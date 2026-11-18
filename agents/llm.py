"""LLM 适配层。

两个实现：
  MockLLM      —— 不联网，按规则走完同样的工具链。用来演示和单测循环。
  DeepSeekLLM  —— 真调用，OpenAI 兼容格式。

为什么要 Mock：
  1. 循环逻辑的 bug 不该靠"调一次真模型"来发现，太慢太贵
  2. 面试演示不能依赖网络和余额
  3. 评估时需要一个稳定的基线——如果 mock 的结论和真模型差很多，
     说明提示词有问题，而不是模型笨
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class MockLLM:
    """规则驱动的假模型。

    它会**真的读工具返回值**再决定下一步，所以不是一个固定脚本：
    如果工具返回空数据，它会给出 needs_investigation。
    """

    def __init__(self) -> None:
        self.turn = 0
        self.seen: dict[str, dict] = {}

    def chat(self, messages: list[dict], tool_schema: list) -> dict:
        self.turn += 1

        # 记录上一轮工具返回
        for m in messages:
            if m["role"] == "tool":
                try:
                    data = json.loads(m["content"])
                    self.seen[data.get("source", "?")] = data
                except (json.JSONDecodeError, TypeError):
                    pass

        user = messages[1]["content"]
        ip = _extract(user, "来源 IP: ")

        plan = ["get_log_context", "list_alerts_by_ip", "check_ip_intel", "get_asset_info"]

        if self.turn <= len(plan):
            name = plan[self.turn - 1]
            args = {"ip": ip}
            if name == "get_log_context":
                args["limit"] = 15
            return {"content": "", "tool_calls": [_call(name, args, self.turn)]}

        # 四步走完，下结论
        return {"content": "", "tool_calls": [_call("submit_verdict", self._verdict(), 99)]}

    def _verdict(self) -> dict:
        logs = self.seen.get("access_log") or {}
        alerts = self.seen.get("detector") or {}
        intel = self.seen.get("mock_intel") or {}
        asset = self.seen.get("mock_cmdb") or {}

        rows = logs.get("rows") or []
        n_alerts = alerts.get("count", 0)
        rules = alerts.get("rules") or []
        datacenter = bool(intel.get("is_datacenter"))

        # 第一层：明确利用类规则 —— 有 payload，直接定罪
        exploit = {"sqli_union", "sqli_tautology", "sqli_timebased", "cmdi_sep",
                   "cmdi_subshell", "traversal_dotdot", "xss_script", "xss_handler",
                   "xss_proto", "webshell", "log4j_jndi", "ssrf_internal"}
        hit = exploit & set(rules)
        if hit:
            return {
                "verdict": "true_positive",
                "confidence": 0.92,
                "reason": f"命中利用类规则 {sorted(hit)}，日志中有对应 payload，"
                          f"该 IP 共 {logs.get('total', 0)} 次请求",
                "action": "立即封禁并排查是否已被成功利用",
            }

        # 第二层：扫描/探测类规则 —— 确认是自动化行为，但未必有危害
        scan = [r for r in rules
                if r.startswith(("ua_", "behav_", "sens_"))]
        if scan:
            crit = asset.get("criticality", "unknown")
            # 数据中心 IP 更像测绘扫描器，置信度略高；家宽 IP 更像真实攻击者
            conf = 0.80 if datacenter else 0.72
            if crit in ("low", "none"):
                action = "记录并加入观察名单，暂不封禁（资产无业务价值，避免误伤共享 IP）"
            else:
                action = "封禁 IP 并核查是否有后续利用行为"
            return {
                "verdict": "true_positive",
                "confidence": conf,
                "reason": f"该 IP 触发 {n_alerts} 条告警（{', '.join(sorted(scan)[:3])}），"
                          f"共 {logs.get('total', 0)} 次请求；"
                          f"{'来自数据中心，符合测绘扫描特征' if datacenter else '非数据中心 IP'}；"
                          f"资产定级 {crit}",
                "action": action,
            }

        if not rows:
            return {
                "verdict": "needs_investigation",
                "confidence": 0.30,
                "reason": "工具未返回该 IP 的日志记录，可能是日志已轮转或 IP 被过滤",
                "action": "人工核查对应时段的归档日志",
            }

        return {
            "verdict": "needs_investigation",
            "confidence": 0.45,
            "reason": f"共 {n_alerts} 条告警但规则类型无法判断意图，"
                      f"日志 {logs.get('total', 0)} 条请求中没有明显特征",
            "action": "人工复核",
        }


class DeepSeekLLM:
    """DeepSeek 真实调用。用 urllib，不引入 requests——保持零依赖。"""

    def __init__(self, api_key: str | None = None,
                 model: str = "deepseek-chat",
                 base: str = "https://api.deepseek.com") -> None:
        self.key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
        self.model = model
        self.base = base.rstrip("/")
        if not self.key:
            raise RuntimeError("未设置 DEEPSEEK_API_KEY")

    def chat(self, messages: list[dict], tool_schema: list) -> dict:
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "tools": tool_schema,
            "tool_choice": "auto",
            "temperature": 0,   # 研判要可复现，不要创造性
        }).encode()

        req = urllib.request.Request(
            f"{self.base}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return {"content": f"模型调用失败 HTTP {exc.code}", "tool_calls": []}
        except (urllib.error.URLError, TimeoutError) as exc:
            return {"content": f"模型连接失败: {exc}", "tool_calls": []}

        msg = (data.get("choices") or [{}])[0].get("message") or {}
        return {
            "content": msg.get("content") or "",
            "tool_calls": msg.get("tool_calls") or [],
        }


def _call(name: str, args: dict, n: int) -> dict:
    return {
        "id": f"call_{n}",
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args, ensure_ascii=False)},
    }


def _extract(text: str, key: str) -> str:
    for line in text.splitlines():
        if key in line:
            return line.split(key, 1)[1].strip()
    return ""
