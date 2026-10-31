"""大模型研判层。

这一层有四件事是"能跑"和"能上线"的区别，每一件都值得在面试里讲：

1. 去重     —— 同一类攻击只问一次，而不是每条日志问一次（成本）
2. 并发     —— 用线程池同时发，把 N 次串行等待压到 1/N（速度）
3. 重试     —— 指数退避，遇到 429 限流不会越试越死（稳定性）
4. 降级     —— 任何失败都不影响规则结论，AI 只是增强项（可靠性）

最关键的是第 4 条背后的判断：**AI 不在主链路上。**
没有它系统必须依然可用，这句话比"我调了个大模型"值钱得多。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Config
from .models import Finding

API_URL = "https://api.deepseek.com/chat/completions"

# 这类错误重试也没用，直接放弃，省时间也省调用次数
_FATAL_STATUS = {401, 402, 403}


class _FatalAIError(Exception):
    pass


class AIAnalyst:
    def __init__(self, config: Config) -> None:
        self.config = config

    # ------------------------------------------------------------------
    def enrich(self, findings: list[Finding]) -> list[str]:
        """就地填充每条告警的 ai_comment，返回给用户看的备注。"""
        notes: list[str] = []

        if not findings:
            return notes
        if not self.config.ai_enabled:
            notes.append("AI 研判已关闭，仅输出规则检测结果。")
            return notes
        if not self.config.ai_api_key:
            notes.append("未配置 DEEPSEEK_API_KEY，已跳过 AI 研判，规则检测不受影响。")
            return notes

        # --- 去重：按 (攻击类型, 规则组合) 归并 ---
        representatives: dict[tuple, Finding] = {}
        for f in findings:  # findings 已按等级降序，所以先遇到的就是最严重的
            representatives.setdefault(f.dedup_key, f)

        limit = self.config.ai_max_calls
        selected = list(representatives.values())[:limit]
        if len(representatives) > limit:
            notes.append(
                f"共 {len(representatives)} 类告警，受成本上限限制只研判前 {limit} 类，"
                f"其余仍保留规则结论。"
            )

        # --- 并发调用 ---
        with ThreadPoolExecutor(max_workers=self.config.ai_max_workers) as pool:
            future_map = {pool.submit(self._analyze, f): f for f in selected}
            for future in as_completed(future_map):
                finding = future_map[future]
                try:
                    finding.ai_comment = future.result()
                except _FatalAIError as exc:
                    notes.append(f"AI 研判中止：{exc}")
                    break
                except Exception as exc:  # 单条失败不影响其他
                    finding.ai_comment = f"研判失败：{exc}"

        # --- 把结论回填给同类告警 ---
        for f in findings:
            if not f.ai_comment:
                f.ai_comment = representatives.get(f.dedup_key, f).ai_comment

        done = sum(1 for f in selected if f.ai_comment)
        notes.append(
            f"AI 研判完成 {done}/{len(selected)} 类（去重前 {len(findings)} 条告警）。"
        )
        return notes

    # ------------------------------------------------------------------
    def _analyze(self, finding: Finding) -> str:
        prompt = self._build_prompt(finding)
        last_error: Exception | None = None

        for attempt in range(self.config.ai_max_retries + 1):
            try:
                return self._post(prompt)
            except _FatalAIError:
                raise
            except Exception as exc:
                last_error = exc
                if attempt < self.config.ai_max_retries:
                    # 指数退避：0.5s -> 1s -> 2s。直接立刻重试只会加重对方限流。
                    time.sleep(0.5 * (2**attempt))

        return f"研判失败（已重试 {self.config.ai_max_retries} 次）：{last_error}"

    @staticmethod
    def _build_prompt(finding: Finding) -> str:
        raw = finding.entry.raw
        if len(raw) > 600:  # 控制 token 消耗，也避免超长 payload 干扰模型
            raw = raw[:600] + "…"

        return (
            "你是安全运营专家。规则引擎命中了一条可疑 Web 日志，请研判。\n"
            f"攻击类型：{finding.category}\n"
            f"命中规则：{', '.join(finding.rule_names)}\n"
            f"判定依据：{finding.reason}\n"
            f"原始日志：{raw}\n\n"
            "请严格输出三行，每行不超过一句话，不要复述日志：\n"
            "攻击意图：\n"
            "风险影响：\n"
            "处置建议："
        )

    def _post(self, prompt: str) -> str:
        body = {
            "model": self.config.ai_model,
            "messages": [
                {"role": "system", "content": "你是专业的网络安全运营专家，回答简洁、具体、可执行。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,  # 安全研判要稳定结论，不要发散
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.ai_api_key}",
        }
        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(API_URL, data=payload, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.config.ai_timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            if exc.code in _FATAL_STATUS:
                raise _FatalAIError(f"HTTP {exc.code}，请检查 API Key 或余额：{detail}") from exc
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc

        return data["choices"][0]["message"]["content"].strip()
