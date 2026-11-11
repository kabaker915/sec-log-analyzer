"""检测层：把规则命中变成告警。

分两路，对应安全里的两个基本视角：

  * 内容检测（payload-based）：单条请求里有没有攻击特征。准，但可被编码绕过。
  * 行为检测（behavior-based）：一串请求合起来像不像机器扫描。抗绕过，但容易误报。

真实产品（WAF、SIEM、EDR）都是两路并行取并集，因为两者互补：
只做内容检测，改个语法就绕过；只做行为检测，一次成功的注入看不出来。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from .config import Config
from .models import Finding, LogEntry, Severity
from .rules import (
    CATEGORY_SEVERITY,
    CRAWLER_UA,
    RULES,
    SCANNER_UA,
    SCANNER_UA_NOTE,
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
        findings += self._detect_protocol_error_burst(entries)
        findings += self._detect_distributed_scan(entries)
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

    def detect_behavior_only(self, entries: list[LogEntry]) -> list[Finding]:
        """只跑行为检测，跳过内容检测。

        专供实时模式用。实时循环里内容检测已经按条跑过了——
        每条日志进来时立刻判一次，结果已经推送出去。
        在这里对着整段历史再把内容规则跑一遍，产出会被调用方丢掉，
        纯属浪费 CPU。

        实测：缓冲区 20000 条时，完整 detect 约 717ms，
        其中内容检测占 152ms，占比 21%。在 2 核机器上这是每秒都在烧的空转。

        注意这个方法存在的前提是"内容检测是无状态的"。
        一旦某条内容规则需要看历史（比如"同一 payload 在 5 分钟内出现 3 次"），
        它就必须移进这份名单，否则实时模式下会永远不触发。
        """
        findings: list[Finding] = []
        findings += self._detect_scanner_ua(entries)
        findings += self._detect_directory_scan(entries)
        findings += self._detect_protocol_error_burst(entries)
        findings += self._detect_distributed_scan(entries)
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
            note = SCANNER_UA_NOTE.get(tool, "自动化工具特征")
            findings.append(
                Finding(
                    category="扫描器指纹",
                    severity=Severity.MEDIUM,
                    ip=entry.ip,
                    entry=entry,
                    rule_names=["ua_scanner"],
                    score=10,
                    reason=(
                        f"User-Agent 暴露自动化工具特征：{m.group(0)}"
                        f"（{note}；同类请求已合并）"
                    ),
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
    # 4. 协议误用探测：4xx 协议级错误突发
    # ------------------------------------------------------------------
    def _detect_protocol_error_burst(self, entries: list[LogEntry]) -> list[Finding]:
        """抓"发来的根本不是合法 HTTP"的探测。

        为什么必须有这条规则（这条是拿真实数据倒逼出来的）：

        2026-11-10 上线自有 ECS，15 分钟内就收到一条 151.243.11.160 的请求，
        nginx 返回 400。当时工具一条告警都没出。原因不是规则写错了，
        而是这类探测**在内容层根本无迹可寻**：
        请求体是一段 TLS 握手二进制（\\x16\\x03\\x01...），
        没有 union、没有 ../、没有 <script>，RULES 里每一条都命中不了。

        内容检测回答"发的什么"，协议层回答"发的形式对不对"。
        攻击者只要能控制"形式"，就能把整个内容维度绕过去 ——
        这就是为什么 WAF 之外还要有协议解析异常检测。

        统计口径上只认"服务端判定请求本身不合法"的状态码（400/408/414/431/505），
        不掺 401/403 —— 那是鉴权结果，正常业务天天有。
        """
        findings: list[Finding] = []
        groups: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in entries:
            if (
                entry.source == "access"
                and entry.status in self.config.protocol_error_statuses
                and entry.ts is not None
            ):
                groups[entry.ip].append(entry)

        for ip, items in groups.items():
            # 同 _detect_directory_scan：窗口必须建立在有序序列上
            items.sort(key=lambda e: e.ts)

            hit = self._first_window_hit(
                items,
                window_seconds=self.config.protocol_error_window,
                threshold=self.config.protocol_error_threshold,
                # 这里 distinct 用状态码而不是路径：
                # 路径对这种畸形请求没有意义（就是一段乱码），
                # 而"同时出现 400 和 414"说明对方在试探不同长度上限，是更强的信号。
                distinct_field=lambda e: e.status,
                distinct_threshold=1,
            )
            if hit is None:
                continue

            count, _, latest = hit
            # 用 is 而不是 == 定位：dataclass 的 __eq__ 逐字段比较，
            # 两条内容完全相同的日志行会被判成"相等"，
            # list.index() 于是返回前一条，窗口取值就偏了。
            latest_idx = next(i for i, e in enumerate(items) if e is latest)
            window_items = items[: latest_idx + 1]

            sample = latest
            first_line = sample.raw
            # 只取引号内那一段请求行，避免把整行日志（含时间、UA）塞进 reason
            if '"' in first_line:
                seg = first_line.split('"')
                if len(seg) > 1:
                    first_line = seg[1]

            detail = [f"{self.config.protocol_error_window} 秒内 {count} 次"]
            detail.append(f"状态码 {sorted({e.status for e in window_items})}")

            # TLS 握手包打明文端口是最好认的特征：首字节 0x16 是 Handshake 类型，
            # 紧跟 0x03 0x01/0x03 是 TLS 记录层的版本号。
            # 能说出这一句，就把"看到一堆乱码"升级成"知道对方想干什么"。
            #
            # 注意这里必须同时判两种形态 —— 这是踩过的坑：
            # nginx 默认会把不可打印字节转义成字面量 "\x16"（反斜杠 + x + 1 + 6），
            # 落到日志文件里是 4 个可见字符，不是那一个 0x16 字节。
            # 只写 startswith("\x16") 的话，真实 nginx 日志永远匹配不上，
            # 而单元测试里手写字符串又很容易"恰好"通过，于是 bug 被测试掩盖。
            if first_line.startswith(("\x16", "\\x16")):
                detail.append(
                    "首字节 0x16（TLS Handshake），判断为对明文端口发起 HTTPS 请求"
                )
            elif "\\x" in first_line or "\x00" in first_line or any(
                ord(c) < 0x20 for c in first_line
            ):
                detail.append("请求行含不可打印/转义字节，非正常 HTTP 客户端")
            else:
                shown = first_line if len(first_line) <= 80 else first_line[:80] + "…"
                detail.append(f"首行请求：{shown}")

            uas = {e.user_agent for e in window_items if e.user_agent}
            if uas:
                ua_shown = "; ".join(sorted(uas)[:3])
                detail.append(f"UA：{ua_shown}")

            # 等级判定：UA 直接命中扫描器词表才升 high。
            # 光看 400 次数不足以升档 —— 一个配错的客户端重试几次也能凑够 3 次。
            has_scanner_ua = any(SCANNER_UA.search(ua) for ua in uas)

            findings.append(
                Finding(
                    category="协议误用探测",
                    severity=Severity.HIGH if has_scanner_ua else Severity.MEDIUM,
                    ip=ip,
                    entry=latest,
                    rule_names=["behav_http_400_burst"],
                    score=count,
                    reason="；".join(detail),
                )
            )
        return findings

    # ------------------------------------------------------------------
    # 5. 分布式扫描：多 IP 共用同一指纹
    # ------------------------------------------------------------------
    def _detect_distributed_scan(self, entries: list[LogEntry]) -> list[Finding]:
        """按 (UA, 路径) 聚合，看是否有大量不同 IP 在做同一件事。

        为什么需要这条（同样是真实数据倒逼出来的）：

        2026-11-11 的日志里，9 个毫无关联的 IP（分属不同国家、
        不同 ASN）各发了一次 GET /.git/config，UA 全是
        "Mozilla/5.0 (compatible; Scanner/1.0)"。
        同一时刻，没有任何单 IP 触发扫描规则 —— 因为每个 IP 只发了一次。

        这不是规则不够狠，是**视角错了**。按 IP 看，每个源都无辜；
        按指纹看，是一个组织在批量调度。攻防里这叫"横向换源"，
        攻击者用大量肉鸡分摊请求量，专门用来绕开基于单 IP 计数的限速和封禁。

        对应 MITRE ATT&CK T1595.002（主动扫描：漏洞扫描）的分布式变体。
        检测它的唯一办法是不以单个源为单位看，而以"行为指纹"为单位看。

        关键防误报设计：要求命中请求里大部分是错误状态码。
        真实热门页面（/、/index.html）会有大量不同 IP、相同 UA（Chrome 版本号相同）、
        相同路径、但状态 200。不加这道门槛，这条规则上线第一天就会把正常流量
        全判成攻击 —— 而且量级比真攻击大几个数量级。
        """
        findings: list[Finding] = []

        # key = (UA 原文, 规范化后的路径)
        groups: dict[tuple[str, str], list[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.source != "access" or not entry.user_agent or entry.ts is None:
                continue
            if CRAWLER_UA.search(entry.user_agent):
                continue  # 搜索引擎本来就会从多个 IP 抓同一个页面
            groups[(entry.user_agent.strip(), entry.path)].append(entry)

        for (ua, path), items in groups.items():
            if len({e.ip for e in items}) < self.config.distributed_min_ips:
                continue

            errored = sum(1 for e in items if e.status and e.status >= 400)
            if errored / len(items) < self.config.distributed_error_ratio:
                continue  # 状态码正常 → 是正常流量，不是探测

            # 关键：不要要求"整组事件都落在窗口内"。第一版就是这么写的，
            # 结果这 9 个 IP 跨了 3 小时 35 分，直接被过滤掉、规则一声不响。
            # 真实攻击往往就是"挤一段、停一段、再挤一段"，用总跨度判断会漏。
            # 正确做法是在整组里找"密度最高的那个窗口"，窗口内数不同 IP。
            hit = self._densest_ip_window(items, self.config.distributed_window)
            if hit is None:
                continue
            ips, span, latest, distinct_ips = hit

            findings.append(
                Finding(
                    category="分布式扫描",
                    severity=Severity.HIGH if distinct_ips >= 5 else Severity.MEDIUM,
                    ip=latest.ip,
                    entry=latest,
                    rule_names=["behav_distributed_scan"],
                    score=distinct_ips,
                    reason=(
                        f"{distinct_ips} 个不同 IP 在 {int(span)} 秒内请求同一路径 {path}，"
                        f"UA 完全一致（{errored}/{len(items)} 为错误状态码），"
                        f"判断为分布式扫描：各源只发一次，绕开基于单 IP 的限速与封禁。"
                        f"源 IP：{', '.join(sorted(ips)[:8])}"
                        f"{' 等' if len(ips) > 8 else ''}；UA：{ua[:80]}"
                    ),
                )
            )
        return findings

    @staticmethod
    def _densest_ip_window(items: list[LogEntry], window_seconds: int):
        """滑动窗口，返回窗口内不同 IP 数最多的那一段。

        用计数器维护窗口内的 IP 分布，避免每次都重建 set —— 每个右指针移动时
        只在两端做增减，整体 O(n)。日志到几十万行时这个差别很明显。

        返回 (窗口内IP集合, 窗口跨度秒, 窗口末端事件, 不同IP数)，都不够阈值时返回 None。
        """
        items = sorted(items, key=lambda e: e.ts)
        counter: Counter = Counter()
        left = 0
        best = None

        for right, cur in enumerate(items):
            counter[cur.ip] += 1
            while (cur.ts - items[left].ts).total_seconds() > window_seconds:
                left_ip = items[left].ip
                counter[left_ip] -= 1
                if counter[left_ip] == 0:
                    del counter[left_ip]
                left += 1

            if best is None or len(counter) > best[3]:
                span = (cur.ts - items[left].ts).total_seconds()
                best = (set(counter), span, cur, len(counter))

        return best

    # ------------------------------------------------------------------
    # 6. SSH 爆破
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
