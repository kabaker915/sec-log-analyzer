"""对话式研判助手。

和 loop.py 的区别：
  loop.py  = 一次性研判（告警进，结论出）
  chat.py  = 研判完成后可以继续追问

为什么需要追问：
  SOC 分析师拿到「真阳性 0.92」不会立刻照做，他会问：
  「依据是什么」「如果我加白名单会怎样」「把处置步骤写出来」。
  一个不能追问的研判系统，等于只给了结论没给理由。

三个设计约束：
  1. 追问必须能引用前面研判的事实 —— 所以把 trace 压成摘要带进上下文
  2. 不能无限追问 —— 消息历史做滑窗，否则 token 会爆
  3. 每一轮都可以再调工具 —— 追问阶段可能需要新数据
"""

from __future__ import annotations

import json
from typing import Any

from . import tools
from .llm import DeepSeekLLM
from .loop import Run, run

MAX_HISTORY = 12       # 保留最近 12 条消息（6 轮）
MAX_STEPS_PER_TURN = 4  # 追问时最多调 4 次工具

CHAT_SYSTEM = """你是安全运营分析师，正在向同事解释你对一条告警的研判。

已知研判结论：
{verdict}

研判过程（你实际执行的工具调用）：
{trace}

回答要求：
1. 必须基于上面的事实回答，不要引入没查过的信息。
2. 如果同事问的东西你没查过，说明需要查什么，并调用对应工具。
3. 回答简洁，不超过 200 字。用短句，不要客套话。
4. 涉及处置建议时，明确区分「建议」和「已确认的事实」。
"""


class TriageAssistant:
    """一次研判 + 后续追问。"""

    def __init__(self, alert: dict, findings: list[dict], entries: list,
                 llm=None, use_llm: bool = False, verbose: bool = False) -> None:
        tools.bind(findings, entries)
        self.alert = alert
        self.findings = findings
        self.entries = entries
        self.use_llm = use_llm
        self.verbose = verbose
        self.llm = llm or (DeepSeekLLM() if use_llm else _RuleLLM())
        self.result: Run | None = None
        self.history: list[dict] = []

    # ---------------------------------------------------------------- 研判
    def triage(self) -> Run:
        """跑一次完整研判。可重复调用，会重置历史。"""
        if self.use_llm:
            self.result = run(self.alert, self.llm, verbose=self.verbose)
        else:
            # Mock 模式下用 loop 的确定性流程
            self.result = run(self.alert, _LoopMockLLM(), verbose=self.verbose)
        self.history = []
        return self.result

    # ---------------------------------------------------------------- 追问
    def ask(self, question: str) -> dict[str, Any]:
        """追问一轮。返回 {answer, tool_calls}。"""
        if self.result is None:
            self.triage()

        sys_msg = CHAT_SYSTEM.format(
            verdict=json.dumps(self.result.verdict or {}, ensure_ascii=False),
            trace=_trace_digest(self.result),
        )
        messages = [{"role": "system", "content": sys_msg}]
        messages.extend(self.history[-MAX_HISTORY:])
        messages.append({"role": "user", "content": question})

        used: list[str] = []
        for _ in range(MAX_STEPS_PER_TURN + 1):
            msg = self.llm.chat(messages, tools.TOOL_SCHEMA)

            calls = msg.get("tool_calls") or []
            if not calls:
                answer = msg.get("content") or "（没有返回内容）"
                self.history.append({"role": "user", "content": question})
                self.history.append({"role": "assistant", "content": answer})
                self.history = self.history[-MAX_HISTORY:]
                return {"answer": answer, "tool_calls": used}

            # 追问阶段不允许提交结论，只允许查数据
            messages.append({"role": "assistant", "content": msg.get("content") or "",
                             "tool_calls": calls})
            for c in calls:
                name = c["function"]["name"]
                if name == "submit_verdict":
                    messages.append({"role": "tool",
                                     "tool_call_id": c.get("id", "x"),
                                     "content": '{"error": "追问阶段不能重新提交结论"}'})
                    continue
                try:
                    args = json.loads(c["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                res = tools.call(name, args)
                used.append(f"{name}({args})")
                messages.append({"role": "tool",
                                 "tool_call_id": c.get("id", "x"),
                                 "content": json.dumps(res, ensure_ascii=False)})

        return {"answer": "追问步数超限，请缩小问题范围", "tool_calls": used}


def _trace_digest(run_obj: Run, limit: int = 800) -> str:
    """把 trace 压成给模型看的事实摘要。

    不直接塞原始 JSON：工具返回里有整页日志，塞进去会吃掉大量 token，
    而且模型容易从一堆细节里挑错重点。
    """
    lines = []
    for s in run_obj.steps:
        preview = json.dumps(s.result, ensure_ascii=False)
        if len(preview) > 160:
            preview = preview[:160] + "…"
        lines.append(f"- {s.tool}({json.dumps(s.args, ensure_ascii=False)}) -> {preview}")
    text = "\n".join(lines) if lines else "（未调用任何工具）"
    return text[:limit]


# ---------------------------------------------------------------------------
# 无 API Key 时的规则替身
# ---------------------------------------------------------------------------
class _LoopMockLLM:
    """研判阶段用：直接复用 llm.MockLLM 的判定逻辑。"""

    def __init__(self) -> None:
        from .llm import MockLLM
        self._inner = MockLLM()

    def chat(self, messages, schema):
        return self._inner.chat(messages, schema)


class _RuleLLM:
    """追问阶段用：按问题关键词从已知事实里组织回答。

    ⚠️ 这不是 AI。它只是保证「没有 API Key 也能演示完整交互」，
    面试演示时必须说明这一点，不能拿它当模型能力。
    """

    def chat(self, messages, schema):
        from .llm import MockLLM
        q = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        sys_text = messages[0].get("content", "") if messages else ""

        # 从系统消息里捞出结论
        verdict = {}
        try:
            start = sys_text.index("{")
            end = sys_text.index("}", start) + 1
            verdict = json.loads(sys_text[start:end])
        except (ValueError, json.JSONDecodeError):
            pass

        v = verdict.get("verdict", "unknown")
        conf = verdict.get("confidence", "?")
        reason = verdict.get("reason", "")
        action = verdict.get("action", "")

        if any(k in q for k in ("为什么", "依据", "怎么判断")):
            ans = (f"判为 {v}（置信度 {conf}）。依据：{reason}。"
                   f"这个结论来自实际查到的工具返回，不是我推测的。")
        elif any(k in q for k in ("白名单", "不封", "忽略")):
            ans = (f"可以，但要留痕。当前建议处置是：{action}。"
                   f"如果加白名单，风险是这个 IP 后续换行为时不会再告警——"
                   f"建议设置有效期，到期自动失效。")
        elif any(k in q for k in ("步骤", "怎么做", "处置", "怎么办")):
            ans = (f"建议处置：{action}。具体三步："
                   f"① 确认该 IP 是否在已有白名单里；② 按处置建议执行；"
                   f"③ 观察 24 小时是否复现。")
        elif any(k in q for k in ("确定", "风险", "误判", "误报")):
            ans = (f"置信度 {conf}。误判风险主要来自：资产信息不完整时"
                   f"无法判断影响面。判为 {v} 的一部分依据是规则命中，"
                   f"规则本身有漏报可能（比如换写法的绕过）。")
        else:
            ans = (f"当前研判结论是 {v}（置信度 {conf}），依据：{reason[:100]}。"
                   f"你可以问「依据是什么」「处置步骤」「误判风险」。")

        return {"content": ans, "tool_calls": []}
