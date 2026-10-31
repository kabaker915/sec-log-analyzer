"""检测层：把规则命中变成告警。

分两路，对应安全里的两个基本视角：

  * 内容检测（payload-based）：单条请求里有没有攻击特征。准，但可被编码绕过。
  * 行为检测（behavior-based）：一串请求合起来像不像机器扫描。抗绕过，但容易误报。

真实产品（WAF、SIEM、EDR）都是两路并行取并集，因为两者互补：
只做内容检测，改个语法就绕过；只做行为检测，一次成功的注入看不出来。
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from .config import Config
from .models import Finding, LogEntry, Severity
from .rules import (
    CATEGORY_SEVERITY,
    CRAWLER_UA,
    RULES,
    SCANNER_UA,
    normalize,
)

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Detector:
    def __init__(self, config: Config) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # 对外入口
    # ------------------------------------------------------------------
    def detect(self, entries: list[LogEntry]) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._detect_payload(entries)
        findings += self._detect_scanner_ua(entries)
        findings += self._detect_directory_scan(entries)
        findings += self._detect_ssh_brute(entries)

        findings.sort(
            key=lambda f: (
                _SEVERITY_ORDER.index(f.severity),
                f.score,
                f.ts or datetime.min,
            ),
            reverse=True,
        )
        return findings

    # ------------------------------------------------------------------
    # 1. 内容检测：加权打分
    # ------------------------------------------------------------------
    def _detect_payload(self, entries: list[LogEntry]) -> list[Finding]:
        """同一分类内累加弱特征，强特征直接过线。

        打分而不是布尔，是为了让"多个可疑信号叠加"和"单个铁证"走同一套出口，
        同时让单个弱信号（一个引号）永远够不到阈值。
        """
        findings: list[Finding] = []
        threshold = self.config.alert_score_threshold

        for entry in entries:
            if entry.source != "access":
                continue

            payload = normalize(entry.target)
            # 分类 -> 命中的规则列表
            hits: dict[str, list] = defaultdict(list)

            for rule in RULES:
                if rule.pattern.search(payload):
                    hits[rule.category].append(rule)

            for category, matched in hits.items():
                score = sum(r.weight for r in matched)
                if score < threshold:
                    continue  # 单个弱特征（3 分）在这里被挡掉
                findings.append(
                    Finding(
                        category=category,
                        severity=self._severity_for(category, score),
                        ip=entry.ip,
                        entry=entry,
                        rule_names=[r.name for r in matched],
                        score=score,
                        reason=self._reason(matched, payload),
                    )
                )
        return findings

    @staticmethod
    def _reason(matched: list, payload: str) -> str:
        parts = [f"{r.note}（{r.name}）" for r in matched]
        # 截断展示，避免报告被超长 payload 撑爆；原始日志另有字段完整保留
        shown = payload if len(payload) <= 160 else payload[:160] + "…"
        return "；".join(parts) + f"。归一化后的载荷：{shown}"

    def _severity_for(self, category: str, score: int) -> Severity:
        base = Severity(CATEGORY_SEVERITY.get(category, "medium"))
        if score >= self.config.decisive_weight * 2:
            idx = min(_SEVERITY_ORDER.index(base) + 1, len(_SEVERITY_ORDER) - 1)
            base = _SEVERITY_ORDER[idx]
        return base

    # ------------------------------------------------------------------
    # 2. UA 指纹
    # ------------------------------------------------------------------
    def _detect_scanner_ua(self, entries: list[LogEntry]) -> list[Finding]:
        """按 (IP, 工具名) 去重，一个扫描器只报一条。

        原先是每条请求报一条：gobuster 扫 500 个路径就出 500 条告警，
        直接把分析师淹掉——这正是"告警疲劳"的制造过程。
        同一个 IP 用同一个工具，攻击事实只有一个。
        """
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for entry in entries:
            if entry.source != "access" or not entry.user_agent:
                continue
            m = SCANNER_UA.search(entry.user_agent)
            if not m:
                continue
            tool = m.group(0).lower()
            key = (entry.ip, tool)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    category="扫描器指纹",
                    severity=Severity.MEDIUM,
                    ip=entry.ip,
                    entry=entry,
                    rule_names=["ua_scanner"],
                    score=10,
                    reason=f"User-Agent 暴露自动化工具特征：{m.group(0)}（同类请求已合并）",
                )
            )
        return findings

    # ------------------------------------------------------------------
    # 3. 目录扫描：404 滑动窗口
    # ------------------------------------------------------------------
    def _detect_directory_scan(self, entries: list[LogEntry]) -> list[Finding]:
        """按 IP 分组，用双指针维护滑动窗口统计 404 次数。

        原项目的三个坑在这里一次性修掉：
        a) 用 total_seconds() 而不是 .seconds；
           timedelta.seconds 只取"秒位"，超过 1 天就丢天；负数时更会返回一个巨大的正数。
        b) 先按时间排序。日志不保证有序（多进程写、翻页导出），不排序窗口必错。
        c) 同时看"次数"和"不同路径数"。
           页面真的挂了也会有大量 404，但路径是同一个；
           扫描器的特征是"短时间内大量不同的路径"，这个维度能显著降误报。
        """
        findings: list[Finding] = []
        probes: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.source == "access" and entry.status == 404 and entry.ts is not None:
                probes[entry.ip].append(entry)

        for ip, items in probes.items():
            items.sort(key=lambda e: e.ts)  # 保证窗口单调，见上面 b)

            if self.config.whitelist_crawler_ua and self._looks_like_crawler(items):
                continue

            window = self.config.scan_window_seconds
            key = lambda e: e.path  # noqa: E731

            # 档 A：请求量大（8 次 / 3 个路径）
            hit = self._first_window_hit(
                items,
                window_seconds=window,
                threshold=self.config.scan_404_threshold,
                distinct_field=key,
                distinct_threshold=self.config.scan_distinct_path_threshold,
            )
            profile = "请求量异常"

            # 档 B：次数不算多，但路径高度分散（明显在猜路径）
            if hit is None:
                hit = self._first_window_hit(
                    items,
                    window_seconds=window,
                    threshold=self.config.scan_burst_threshold,
                    distinct_field=key,
                    distinct_threshold=self.config.scan_burst_distinct_threshold,
                )
                profile = "路径分散"

            if hit is None:
                continue

            count, distinct, latest = hit
            findings.append(
                Finding(
                    category="目录扫描",
                    severity=Severity.HIGH if distinct >= 10 else Severity.MEDIUM,
                    ip=ip,
                    entry=latest,
                    rule_names=["behav_404_burst"],
                    score=count,
                    reason=(
                        f"{window} 秒内产生 {count} 次 404，涉及 {distinct} 个不同路径"
                        f"（判定档位：{profile}），符合目录爆破特征"
                    ),
                )
            )
        return findings

    def _looks_like_crawler(self, items: list[LogEntry]) -> bool:
        """爬虫也会刷 404。判断标准：全部请求的 UA 都是爬虫，且没有任何扫描器特征。"""
        uas = [e.user_agent for e in items if e.user_agent]
        if not uas:
            return False
        if any(SCANNER_UA.search(ua) for ua in uas):
            return False  # UA 里混了扫描器，说明是伪装，不能放
        return all(CRAWLER_UA.search(ua) for ua in uas)

    @staticmethod
    def _first_window_hit(
        items: list[LogEntry],
        *,
        window_seconds: int,
        threshold: int,
        distinct_field,
        distinct_threshold: int,
    ):
        """返回首个满足条件的窗口 (事件数, 不同取值数, 窗口末端事件)。"""
        left = 0
        for right, cur in enumerate(items):
            # 关键：total_seconds()。.seconds 在跨天和负差值下都会给出错误结果。
            while (cur.ts - items[left].ts).total_seconds() > window_seconds:
                left += 1
            count = right - left + 1
            if count < threshold:
                continue
            distinct = len({distinct_field(e) for e in items[left : right + 1]})
            if distinct >= distinct_threshold:
                return count, distinct, cur
        return None

    # ------------------------------------------------------------------
    # 4. SSH 爆破
    # ------------------------------------------------------------------
    def _detect_ssh_brute(self, entries: list[LogEntry]) -> list[Finding]:
        """双层窗口 + 成功登录关联。

        快速窗口抓脚本小子（一秒几十次），慢速窗口抓 low & slow——
        攻击者把间隔拉到几分钟，正好绕过常见速率限制，这是 MITRE ATT&CK T1110.003。
        只做单窗口检测的话，慢速爆破永远抓不到。
        """
        findings: list[Finding] = []
        failed: dict[str, list[LogEntry]] = defaultdict(list)
        accepted: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.source != "auth" or entry.ts is None:
                continue
            if entry.message.startswith("failed"):
                failed[entry.ip].append(entry)
            elif entry.message.startswith("accepted"):
                accepted[entry.ip].append(entry)

        for ip, items in failed.items():
            items.sort(key=lambda e: e.ts)
            usernames = {e.username for e in items if e.username}

            hit = self._first_window_hit(
                items,
                window_seconds=self.config.brute_fast_window,
                threshold=self.config.brute_fast_threshold,
                distinct_field=lambda e: e.username,
                distinct_threshold=1,
            )
            label = f"{self.config.brute_fast_window} 秒内"

            if hit is None:
                hit = self._first_window_hit(
                    items,
                    window_seconds=self.config.brute_slow_window,
                    threshold=self.config.brute_slow_threshold,
                    distinct_field=lambda e: e.username,
                    distinct_threshold=1,
                )
                label = f"{self.config.brute_slow_window} 秒内（慢速爆破）"

            if hit is None:
                continue

            count, _, latest = hit
            findings.append(
                Finding(
                    category="SSH爆破",
                    severity=Severity.HIGH,
                    ip=ip,
                    entry=latest,
                    rule_names=["behav_ssh_brute"],
                    score=count,
                    reason=(
                        f"{label}密码失败 {count} 次，尝试用户名 {len(usernames)} 个"
                        f"（{', '.join(sorted(usernames)[:5])}）"
                    ),
                )
            )

        # 爆破之后成功登录 = 极可能已失陷，等级最高
        for ip, acc in accepted.items():
            if ip not in failed:
                continue
            # 只输错一两次密码就登录成功，是正常用户手滑，不是爆破。
            # 不设这道门槛，"1 次失败 + 1 次成功 = 严重事件"会让系统天天谎报军情。
            if len(failed[ip]) < self.config.brute_success_min_failures:
                continue
            first_fail = min(e.ts for e in failed[ip])
            success = next((a for a in acc if a.ts and a.ts >= first_fail), None)
            if success is None:
                continue
            findings.append(
                Finding(
                    category="SSH爆破",
                    severity=Severity.CRITICAL,
                    ip=ip,
                    entry=success,
                    rule_names=["behav_ssh_success_after_fail"],
                    score=99,
                    reason=(
                        f"该 IP 先有 {len(failed[ip])} 次密码失败，"
                        f"随后以用户 {success.username} 登录成功，疑似爆破得手"
                    ),
                )
            )
        return findings
