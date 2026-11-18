"""Agent 循环。

用的是 function calling 的标准形态，不是 ReAct 的文本解析。

为什么不用 ReAct（让模型输出 "Thought: ... Action: ..."）：
  那是 2023 年的做法，需要正则解析模型输出，模型稍微不听话就崩。
  现在模型原生支持结构化工具调用，返回的是 JSON，稳定得多。
  面试如果被问"你怎么实现 agent"，答"原生 function calling + 循环终止条件设计"，
  比答 ReAct 更准确。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from . import tools

MAX_STEPS = 8  # 步数上限：防止模型反复调同一个工具烧钱


@dataclass
class Step:
    """一步 = 一次工具调用 + 它的返回。"""
    n: int
    tool: str
    args: dict
    result: dict
    elapsed_ms: int


@dataclass
class Run:
    """一次完整研判的全部记录。

    trace 是必需的，不是调试用的附加物：
    SOC 分析师不会接受一个"我觉得是攻击"的结论，
    他要知道 agent 看了哪些数据、怎么推出来的。
    """
    alert: dict
    steps: list[Step] = field(default_factory=list)
    verdict: dict | None = None
    stopped_reason: str = ""
    total_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "alert": self.alert,
            "verdict": self.verdict,
            "stopped_reason": self.stopped_reason,
            "total_ms": self.total_ms,
            "trace": [
                {"n": s.n, "tool": s.tool, "args": s.args,
                 "result_preview": _preview(s.result), "ms": s.elapsed_ms}
                for s in self.steps
            ],
        }


def _preview(d: dict, limit: int = 220) -> str:
    s = json.dumps(d, ensure_ascii=False)
    return s if len(s) <= limit else s[:limit] + "…"


SYSTEM_PROMPT = """你是安全运营分析师，负责研判日志告警。

规则：
1. 结论必须基于工具返回的事实，禁止推测工具没提供的信息。
2. 每次只调一个工具，看完结果再决定下一步。
3. 一般需要：看原始日志 → 看该 IP 的全部告警 → 查情报 → 查资产 → 下结论。
4. 如果证据不足以判断，选 needs_investigation，不要硬下结论。
5. 最后必须调用 submit_verdict。

判断标准：
- 扫描器/测绘工具的行为（大量 404、固定 UA、只探测不利用）→ 通常是 true_positive（确实是攻击行为），但资产无价值时处置可以是"记录不封禁"
- 正常业务被规则误伤（如姓名含撇号被判注入）→ false_positive
- 有明确利用尝试（注入 payload、webshell 访问）→ true_positive，高置信度
"""


def run(alert: dict, llm, verbose: bool = True) -> Run:
    """对一个告警做研判。

    alert 至少包含：ip、category、severity、reason、rule_names
    """
    t0 = time.time()
    run_rec = Run(alert=alert)

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"请研判这条告警：\n"
            f"- 来源 IP: {alert.get('ip')}\n"
            f"- 类型: {alert.get('category')}\n"
            f"- 等级: {alert.get('severity')}\n"
            f"- 判定依据: {alert.get('reason')}\n"
            f"- 命中规则: {', '.join(alert.get('rule_names', []))}\n"
        )},
    ]

    for step in range(1, MAX_STEPS + 1):
        msg = llm.chat(messages, tools.TOOL_SCHEMA)

        # 模型直接给了最终结论（没走工具）也要接住
        if msg.get("content") and not msg.get("tool_calls"):
            run_rec.verdict = _parse_verdict_from_text(msg["content"])
            run_rec.stopped_reason = "模型未调用工具，直接给出文本结论"
            break

        calls = msg.get("tool_calls") or []
        if not calls:
            run_rec.stopped_reason = "模型既没调工具也没给内容，终止"
            break

        # 把 assistant 这条（含 tool_calls）原样放回历史，否则下一轮会缺上下文
        messages.append({
            "role": "assistant",
            "content": msg.get("content") or "",
            "tool_calls": calls,
        })

        for c in calls:
            name = c["function"]["name"]
            try:
                args = json.loads(c["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}

            # 终止工具：直接收结论
            if name == "submit_verdict":
                run_rec.verdict = {
                    "verdict": args.get("verdict", "needs_investigation"),
                    "confidence": float(args.get("confidence", 0) or 0),
                    "reason": args.get("reason", ""),
                    "action": args.get("action", ""),
                }
                run_rec.stopped_reason = "模型调用 submit_verdict"
                break

            ts = time.time()
            result = tools.call(name, args)
            elapsed = int((time.time() - ts) * 1000)

            run_rec.steps.append(Step(len(run_rec.steps) + 1, name, args, result, elapsed))
            if verbose:
                print(f"  [{step}] {name}({args}) -> {_preview(result, 120)}")

            messages.append({
                "role": "tool",
                "tool_call_id": c.get("id", f"call_{step}"),
                "content": json.dumps(result, ensure_ascii=False),
            })

        if run_rec.verdict:
            break
    else:
        run_rec.stopped_reason = f"达到步数上限 {MAX_STEPS}，强制终止"

    if run_rec.verdict is None and not run_rec.stopped_reason:
        run_rec.stopped_reason = "未得出结论"

    run_rec.total_ms = int((time.time() - t0) * 1000)
    return run_rec


def _parse_verdict_from_text(text: str) -> dict:
    """兜底：模型直接吐了段文字，尽量捞出来。

    这是**降级路径**，不是主路径。有它 agent 不会空手而归，
    但结论质量无法保证——所以 reason 里要标明来源。
    """
    low = text.lower()
    if "假阳性" in text or "false_positive" in low:
        v = "false_positive"
    elif "真阳性" in text or "true_positive" in low:
        v = "true_positive"
    else:
        v = "needs_investigation"
    return {
        "verdict": v,
        "confidence": 0.5,
        "reason": text.strip()[:500],
        "action": "人工复核",
        "degraded": True,
    }
