"""本地大模型适配。

为什么要在本地跑：
  1. **数据不外泄**——把攻击者 IP 和日志发给云端 API，本身是一次数据外泄。
     安全场景下这是实质问题，不是洁癖。
  2. 无速率限制、无费用，可以拿历史日志反复跑、反复调提示词。
  3. 断网可用。

现实问题：小模型的 function calling 不可靠。

  Ollama 0.3+ 支持 tools 参数，但它只是把 schema 塞进提示词，
  模型是否按格式输出完全看模型本事。7B 以下的模型经常：
    - 该调工具时直接编一段话回答
    - 输出半截 JSON
    - 一次调三个工具但格式全错

  所以这里做两个模式：
    ToolsLLM   —— 原生 tools 参数（模型够强时首选）
    TextLLM    —— 文本协议：要求模型输出 ```json {"tool":..,"args":..}```，
                  自己用正则解析。小模型上更稳。

  make_local_llm() 会自动探测：先试 tools 模式，不行就降级。
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

DEFAULT_BASE = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5:7b"

# 访问本机服务必须显式禁用代理。
#
# 机器上开着 HTTP_PROXY 时，urllib 会把 127.0.0.1 的请求也发给代理，
# 表现为 502 Bad Gateway 或超时，看起来像"服务没起来"，
# 实际是请求根本没到本地。这个坑排查起来很费时间，所以模块级统一处理。
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _open(req, timeout: float):
    return _NO_PROXY.open(req, timeout=timeout)


# ---------------------------------------------------------------------------
# 健康检查
# ---------------------------------------------------------------------------
def probe(base: str = DEFAULT_BASE, timeout: float = 3.0) -> dict:
    """检查 Ollama 是否在跑、有哪些模型。

    不抛异常——调用方需要的是「能不能用」，不是异常栈。
    """
    try:
        req = urllib.request.Request(f"{base}/api/tags", method="GET")
        with _open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        models = [m.get("name", "") for m in data.get("models", [])]
        return {"ok": True, "base": base, "models": models}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"ok": False, "base": base, "error": str(exc), "models": []}


# ---------------------------------------------------------------------------
# 模式 A：原生 tools
# ---------------------------------------------------------------------------
class ToolsLLM:
    """走 Ollama 的 OpenAI 兼容接口，带 tools 参数。"""

    mode = "tools"

    def __init__(self, model: str = DEFAULT_MODEL, base: str = DEFAULT_BASE,
                 temperature: float = 0.0, timeout: float = 180.0) -> None:
        self.model = model
        self.base = base.rstrip("/")
        self.temperature = temperature
        # 本地模型慢，超时给足；超时太短会让人以为是提示词问题
        self.timeout = timeout

    def chat(self, messages: list[dict], tool_schema: list) -> dict:
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "tools": tool_schema,
            "temperature": self.temperature,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            f"{self.base}/v1/chat/completions",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _open(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return {"content": f"本地模型 HTTP {exc.code}", "tool_calls": []}
        except (urllib.error.URLError, TimeoutError) as exc:
            return {"content": f"本地模型不可用: {exc}", "tool_calls": []}

        msg = (data.get("choices") or [{}])[0].get("message") or {}
        calls = msg.get("tool_calls") or []
        # 有些实现把参数放在 function.arguments 里但没 id，补上
        for i, c in enumerate(calls):
            c.setdefault("id", f"call_{i}")
        return {"content": msg.get("content") or "", "tool_calls": calls}


# ---------------------------------------------------------------------------
# 模式 B：文本协议（小模型更可靠）
# ---------------------------------------------------------------------------
TEXT_PROTOCOL_HINT = """

你必须用下面两种格式之一回复，不要输出其他内容：

【调用工具】
```json
{"tool": "工具名", "args": {"参数名": "值"}}
```

【给出最终结论】
```json
{"final": {"verdict": "...", "confidence": 0.9, "reason": "...", "action": "..."}}
```

一次只能调用一个工具。看到工具结果后再决定下一步。
"""

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
_BARE_JSON = re.compile(r"(\{[^{}]*\"(?:tool|final)\"[^{}]*\})", re.S)


class TextLLM:
    """文本协议模式。

    把工具说明写进 system prompt，要求模型输出 JSON 代码块，
    再用正则解析。听起来倒退，但在 7B 以下模型上比原生 tools 稳得多——
    因为不需要模型理解 OpenAI 的嵌套 tool_calls 结构，只要会写 JSON。
    """

    mode = "text"

    def __init__(self, model: str = DEFAULT_MODEL, base: str = DEFAULT_BASE,
                 temperature: float = 0.0, timeout: float = 180.0) -> None:
        self.model = model
        self.base = base.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

    def _tool_manual(self, tool_schema: list) -> str:
        lines = ["可用工具："]
        for t in tool_schema:
            fn = t["function"]
            params = ", ".join(fn["parameters"].get("properties", {}).keys())
            lines.append(f"- {fn['name']}({params})：{fn['description']}")
        return "\n".join(lines)

    def chat(self, messages: list[dict], tool_schema: list) -> dict:
        # 把工具说明和协议要求注入 system
        msgs = [dict(m) for m in messages]
        if msgs and msgs[0]["role"] == "system":
            msgs[0]["content"] = (msgs[0]["content"]
                                  + "\n\n" + self._tool_manual(tool_schema)
                                  + TEXT_PROTOCOL_HINT)
        else:
            msgs.insert(0, {"role": "system",
                            "content": self._tool_manual(tool_schema) + TEXT_PROTOCOL_HINT})

        # tool 角色的消息要转成 user，否则某些实现不认
        for m in msgs:
            if m["role"] == "tool":
                m["role"] = "user"
                m["content"] = f"【工具返回】{m['content']}"

        body = json.dumps({
            "model": self.model,
            "messages": msgs,
            "temperature": self.temperature,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            f"{self.base}/v1/chat/completions",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _open(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return {"content": f"本地模型 HTTP {exc.code}", "tool_calls": []}
        except (urllib.error.URLError, TimeoutError) as exc:
            return {"content": f"本地模型不可用: {exc}", "tool_calls": []}

        text = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        return _parse_text_protocol(text)


def _parse_text_protocol(text: str) -> dict:
    """把模型输出解析成和 tool_calls 兼容的结构。

    容错三层：
      1. ```json ... ``` 代码块
      2. 裸 JSON 对象
      3. 都失败 → 当普通文本返回（上层会走降级逻辑）
    """
    for pattern in (_JSON_BLOCK, _BARE_JSON):
        m = pattern.search(text or "")
        if not m:
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue

        if "final" in obj and isinstance(obj["final"], dict):
            return {
                "content": "",
                "tool_calls": [{
                    "id": "call_final",
                    "type": "function",
                    "function": {
                        "name": "submit_verdict",
                        "arguments": json.dumps(obj["final"], ensure_ascii=False),
                    },
                }],
            }
        if "tool" in obj:
            return {
                "content": "",
                "tool_calls": [{
                    "id": "call_0",
                    "type": "function",
                    "function": {
                        "name": obj["tool"],
                        "arguments": json.dumps(obj.get("args") or {}, ensure_ascii=False),
                    },
                }],
            }
    return {"content": text, "tool_calls": []}


# ---------------------------------------------------------------------------
# 自动选择
# ---------------------------------------------------------------------------
def make_local_llm(model: str = DEFAULT_MODEL, base: str = DEFAULT_BASE,
                   prefer: str = "auto") -> tuple[object, str]:
    """返回 (llm, 说明)。

    prefer: "tools" / "text" / "auto"
    auto 的策略：默认走 text 模式。
    理由是实测小模型的原生 tools 命中率明显更低，
    而 text 模式即使模型能力差，至少 JSON 写错还能靠正则补救。
    """
    info = probe(base)
    if not info["ok"]:
        raise RuntimeError(
            f"连不上本地模型服务 {base}。\n"
            f"启动：ollama serve\n"
            f"拉模型：ollama pull {model}"
        )

    if model not in info["models"] and not any(
            m.split(":")[0] == model.split(":")[0] for m in info["models"]):
        raise RuntimeError(
            f"模型 {model} 不存在。已有：{info['models']}\n"
            f"拉取：ollama pull {model}"
        )

    if prefer == "tools":
        return ToolsLLM(model, base), f"tools 模式 · {model}"
    if prefer == "text":
        return TextLLM(model, base), f"text 模式 · {model}"

    return TextLLM(model, base), f"text 模式（auto）· {model}"
