"""管道层：把"解析 -> 检测 -> 研判 -> 汇总"串起来。

为什么要有这一层，而不是让 app.py 直接调各模块：
  * 界面只是其中一个消费者。同一套流程要能被 CLI、被定时任务、被 pytest 复用；
  * 编排逻辑集中在一处，加"批量分析多个文件""增量分析"时只改这里；
  * app.py 因此可以保持很薄——界面代码越少，越不容易出诡异的状态问题。
"""

from __future__ import annotations

import time
from pathlib import Path

from .ai_analyst import AIAnalyst
from .config import Config
from .detector import Detector
from .models import AnalysisResult
from .parser import LogParser, decode_bytes


def analyze_bytes(
    data: bytes,
    filename: str,
    config: Config | None = None,
    *,
    use_ai: bool | None = None,
) -> AnalysisResult:
    """主入口。传字节流而不是路径，这样 Streamlit 上传的文件和磁盘文件走同一条路。"""
    config = config or Config.from_env()
    started = time.perf_counter()

    text, used_encoding = decode_bytes(data, config.encoding_candidates)
    parser = LogParser(config)
    entries, errors = parser.parse_text(text)

    detector = Detector(config)
    findings = detector.detect(entries)

    result = AnalysisResult(
        filename=filename,
        entries=entries,
        findings=findings,
        parse_errors=errors,
        skipped_no_ip=parser.skipped_no_ip,
    )
    result.notes.append(f"文本按 {used_encoding} 解码。")
    if parser.skipped_no_ip:
        result.notes.append(
            f"跳过 {parser.skipped_no_ip} 行与来源 IP 无关的日志"
            f"（CRON、systemd-logind、内核等），不计入解析失败。"
        )

    if use_ai is not None:
        config.ai_enabled = use_ai
    result.notes.extend(AIAnalyst(config).enrich(findings))

    result.elapsed_ms = int((time.perf_counter() - started) * 1000)
    return result


def analyze_file(path: str | Path, config: Config | None = None) -> AnalysisResult:
    p = Path(path)
    return analyze_bytes(p.read_bytes(), p.name, config)
