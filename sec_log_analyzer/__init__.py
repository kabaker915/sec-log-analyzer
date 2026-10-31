"""sec_log_analyzer —— 基于规则引擎 + 大模型的 Web 日志安全分析。

分层：
    config    可调参数与密钥（不落盘）
    models    数据结构
    parser    文本 -> 结构化日志
    rules     归一化 + 特征规则集
    detector  内容检测 + 行为检测
    ai        大模型研判（去重/并发/降级）
    reporter  多格式报告
    pipeline  编排

命令行走 pipeline，界面走 pipeline，测试也走 pipeline——
三种入口共用一条链路，行为才可能一致。
"""

from .config import Config
from .models import SEVERITY_LABEL, AnalysisResult, Finding, LogEntry, Severity
from .pipeline import analyze_bytes, analyze_file

__all__ = [
    "Config",
    "AnalysisResult",
    "Finding",
    "LogEntry",
    "Severity",
    "SEVERITY_LABEL",
    "analyze_bytes",
    "analyze_file",
]
