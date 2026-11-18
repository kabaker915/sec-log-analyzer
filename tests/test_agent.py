"""Agent 的回归测试。

重点不是"能跑通"，而是"结论稳定"。
Agent 比传统程序更难测：同样的输入，换模型、换温度、换提示词，结论可能变。
所以测的是**边界行为**，不是具体文案。

运行：python tests/test_agent.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents import MockLLM, run_triage          # noqa: E402
from agents import loop as agent_loop           # noqa: E402
from agents import tools                        # noqa: E402
from sec_log_analyzer.config import Config      # noqa: E402
from sec_log_analyzer.pipeline import analyze_file  # noqa: E402
from webapp.state import finding_row            # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def main() -> int:
    log = Path("archive/access-2026-11-13.log")
    if not log.exists():
        print("跳过：缺少测试日志 archive/access-2026-11-13.log")
        return 0

    print("准备数据 ...")
    r = analyze_file(str(log), Config(ai_enabled=False))
    findings = [finding_row(f) for f in r.findings]
    entries = r.entries

    cmdi = next((f for f in findings if f["category"] == "命令注入"), None)
    scan = next((f for f in findings if f["category"] == "分布式扫描"), None)

    print("\n[1] 工具层")
    tools.bind(findings, entries)
    ctx = tools.get_log_context(str(cmdi["ip"]))
    check("get_log_context 返回 source 字段", ctx.get("source") == "access_log")
    check("能查到该 IP 的原始请求", ctx.get("total", 0) > 0)
    al = tools.list_alerts_by_ip(str(cmdi["ip"]))
    check("list_alerts_by_ip 能解析出规则名", bool(al.get("rules")), str(al.get("rules")))
    check("未知工具返回 error 而不是抛异常",
          "error" in tools.call("no_such_tool", {}))
    check("参数错误返回 error", "error" in tools.call("get_log_context", {"bad": 1}))

    print("\n[2] 利用类告警 → 高置信真阳性")
    run1 = run_triage(cmdi, findings, entries, verbose=False)
    v1 = run1.verdict or {}
    check("结论为 true_positive", v1.get("verdict") == "true_positive", str(v1.get("verdict")))
    check("置信度 >= 0.9", float(v1.get("confidence", 0)) >= 0.9)
    check("处置建议含封禁", "封禁" in (v1.get("action") or ""))
    check("走完了 4 个工具", len(run1.steps) == 4, f"实际 {len(run1.steps)}")

    print("\n[3] 扫描类告警 → 真阳性但处置克制")
    run2 = run_triage(scan, findings, entries, verbose=False)
    v2 = run2.verdict or {}
    check("结论为 true_positive", v2.get("verdict") == "true_positive")
    check("置信度低于利用类", float(v2.get("confidence", 1)) < float(v1.get("confidence", 0)))
    check("处置建议含'记录'而非直接封禁",
          "记录" in (v2.get("action") or ""), str(v2.get("action")))

    print("\n[4] 无日志的 IP → 不下硬结论")
    ghost = {"ip": "203.0.113.99", "category": "扫描器指纹", "severity": "medium",
             "reason": "测试用", "uid": "ua_scanner:203.0.113.99"}
    run3 = run_triage(ghost, findings, entries, verbose=False)
    v3 = run3.verdict or {}
    check("结论为 needs_investigation", v3.get("verdict") == "needs_investigation")
    check("置信度 < 0.5", float(v3.get("confidence", 1)) < 0.5)

    print("\n[5] 循环防护")
    check("MAX_STEPS 有上限", agent_loop.MAX_STEPS <= 10)

    class EndlessLLM:
        """永远要调工具、永远不给结论的模型。"""
        def chat(self, messages, schema):
            return {"content": "", "tool_calls": [{
                "id": "x", "type": "function",
                "function": {"name": "get_log_context",
                             "arguments": '{"ip": "1.1.1.1"}'},
            }]}

    run4 = run_triage(cmdi, findings, entries, verbose=False)
    tools.bind(findings, entries)
    run4 = agent_loop.run(cmdi, EndlessLLM(), verbose=False)
    check("死循环被步数上限截断",
          "上限" in run4.stopped_reason, run4.stopped_reason)
    check("截断时没有结论但不崩", run4.verdict is None or isinstance(run4.verdict, dict))

    print("\n[6] trace 完整性")
    back = run1.to_dict()
    check("trace 步数与执行一致", len(back["trace"]) == len(run1.steps))
    check("每步都记录了工具名与参数",
          all(t.get("tool") and "args" in t for t in back["trace"]))
    check("trace 可 JSON 序列化", isinstance(back["trace"], list))

    print(f"\n{'=' * 40}\n通过 {PASS} 项，失败 {FAIL} 项")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
