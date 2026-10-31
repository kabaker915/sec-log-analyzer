"""配置层。

为什么单独抽一个 config 而不是在函数里写死常量：
1. 所有"可调参数"集中在一处，改行为不用翻代码；
2. 答辩/面试时可以解释"阈值为什么这么定"——它必须是可配置的，不同站点基线不同；
3. 支持从环境变量覆盖，部署时不用改代码（12-Factor App 的 Config 原则）。

安全要点：API Key 绝不写进源码。源码会被 git 记录、被打包、被截图发到群里。
正确做法是环境变量 + .env（.env 本身要进 .gitignore）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(slots=True)
class Config:
    # ---- 通用 ----
    encoding_candidates: tuple[str, ...] = ("utf-8", "gbk", "latin-1")

    # ---- 行为检测：目录扫描（404 突发）----
    # 两档阈值，任一档满足即告警。单一阈值必然顾此失彼：
    #   档 A：请求量大 —— 8 次 404 + 3 个不同路径（抓常规扫描器，抗"页面资源挂掉"的误报）
    #   档 B：路径分散 —— 5 次 404 + 5 个不同路径（抓小规模但明显在猜路径的探测）
    scan_window_seconds: int = 60
    scan_404_threshold: int = 8
    scan_distinct_path_threshold: int = 3
    scan_burst_threshold: int = 5
    scan_burst_distinct_threshold: int = 5

    # ---- 行为检测：SSH 爆破 ----
    # 双层窗口：快速爆破抓脚本小子，慢速爆破（low & slow）抓绕过速率限制的人
    brute_fast_window: int = 60
    brute_fast_threshold: int = 3
    brute_slow_window: int = 600
    brute_slow_threshold: int = 3
    # "爆破后登录成功"要求之前至少有几次失败。
    # 设成 1 会把"用户手滑输错一次密码"判成严重事件，是典型的严重误报。
    brute_success_min_failures: int = 3

    # ---- 规则打分 ----
    # 强特征（decisive）单独命中即可定罪；弱特征（supportive）只能叠加权重。
    decisive_weight: int = 10
    alert_score_threshold: int = 6

    # ---- 降噪 ----
    # 搜索引擎爬虫也会产生大量 404，误判成扫描。
    # 注意：UA 可以伪造，所以这只是"降噪"不是"放行"，生产环境还要做 rDNS 校验。
    whitelist_crawler_ua: bool = True

    # ---- AI 研判 ----
    ai_enabled: bool = True
    ai_model: str = "deepseek-chat"
    ai_timeout_seconds: float = 20.0
    ai_max_retries: int = 2
    ai_max_calls: int = 12          # 成本闸门：一次分析最多调多少次
    ai_max_workers: int = 4         # 并发度，防止被服务端限流
    ai_api_key: str = field(default="", repr=False)  # repr=False 防止日志里打印出密钥

    # 每个文件最多读多少行，防止有人传个 10GB 的日志把内存打爆
    max_lines: int = 200_000

    @classmethod
    def from_env(cls) -> "Config":
        """从环境变量读取敏感配置。"""
        return cls(
            ai_api_key=os.getenv("DEEPSEEK_API_KEY", ""),
            ai_enabled=os.getenv("AI_ENABLED", "1") != "0",
        )

    def validate(self) -> list[str]:
        """启动时自检，把配置错误提前暴露，而不是跑到一半才崩。"""
        problems: list[str] = []
        if self.scan_window_seconds <= 0:
            problems.append("scan_window_seconds 必须大于 0")
        if self.alert_score_threshold <= 0:
            problems.append("alert_score_threshold 必须大于 0")
        if self.ai_enabled and not self.ai_api_key:
            problems.append("AI 已启用但未提供 DEEPSEEK_API_KEY")
        return problems
