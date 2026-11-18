"""Agent 包对外入口。

用法见 demo.py：
    from agents import run_triage
    result = run_triage(alert, findings, entries)
"""

from __future__ import annotations

from . import tools
from .llm import DeepSeekLLM, MockLLM
from .loop import Run, run

__all__ = ["run_triage", "Run", "MockLLM", "DeepSeekLLM"]


def run_triage(alert: dict, findings: list[dict], entries: list,
               use_llm: bool = False, verbose: bool = True) -> Run:
    """研判一条告警。

    use_llm=False 时用 MockLLM：不联网、不花钱、结论可复现。
    演示和回归测试都走这条；只有想看真实模型表现时才开。
    """
    tools.bind(findings, entries)
    llm = DeepSeekLLM() if use_llm else MockLLM()
    return run(alert, llm, verbose=verbose)
