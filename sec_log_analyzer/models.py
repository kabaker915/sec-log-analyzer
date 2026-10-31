"""数据结构层。

为什么把数据结构单独放一个文件：
1. 其他模块都依赖它，但它不依赖任何其他模块——依赖关系是单向的，不会有循环导入；
2. 字段定义集中在一处，改字段时能看清哪些地方会受影响；
3. 用 dataclass 而不是 dict，好处是字段名写错会立刻报错，而不是悄悄返回 None。
   这是"能跑"和"好维护"的分界线之一。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """告警等级。继承 str 是为了能直接序列化成 JSON / 存数据库。"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_LABEL: dict[Severity, str] = {
    Severity.LOW: "低",
    Severity.MEDIUM: "中",
    Severity.HIGH: "高",
    Severity.CRITICAL: "严重",
}


@dataclass(slots=True)
class LogEntry:
    """一条日志。字段按来源分两类：access 用上半部分，auth 用下半部分。"""

    ip: str
    raw: str
    source: str = "access"
    ts: datetime | None = None

    # --- Web 访问日志 ---
    method: str = ""
    path: str = ""
    query: str = ""
    protocol: str = ""
    status: int | None = None
    size: int | None = None
    referer: str = ""
    user_agent: str = ""

    # --- 认证日志 ---
    username: str = ""
    message: str = ""

    @property
    def target(self) -> str:
        """请求目标（路径 + 查询串）。规则匹配用这个，不用整行。

        为什么不用整行：整行含 IP、时间、UA，会让规则误命中——
        比如某个 UA 里恰好含 "select"，整行匹配就会误报。
        """
        if not self.query:
            return self.path
        return f"{self.path}?{self.query}"

    def __repr__(self) -> str:  # 让调试输出可读，又不至于把整行日志刷屏
        return f"LogEntry(ip={self.ip!r}, status={self.status}, path={self.path!r})"


@dataclass(slots=True)
class Finding:
    """一条告警。

    ts 用 property 从 entry 里取，不再单独存一份——
    避免出现"告警时间和日志时间不一致"这种再也不会有人发现的数据矛盾。
    """

    category: str
    severity: Severity
    ip: str
    entry: LogEntry
    rule_names: list[str]
    score: int
    reason: str
    ai_comment: str = ""

    @property
    def ts(self) -> datetime | None:
        return self.entry.ts

    @property
    def dedup_key(self) -> tuple[str, tuple[str, ...]]:
        """AI 研判的去重键：同一类攻击 + 同一组规则 = 同一个问题。

        sqlmap 扫 200 次会产出 200 条 SQL 注入告警，但它们在语义上是同一件事，
        只需要问一次大模型。这一步是成本控制的关键。
        """
        return (self.category, tuple(sorted(self.rule_names)))


@dataclass
class AnalysisResult:
    filename: str
    entries: list[LogEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    elapsed_ms: int = 0

    @property
    def parse_error_rate(self) -> float:
        total = len(self.entries) + len(self.parse_errors)
        return len(self.parse_errors) / total if total else 0.0

    def count_by(self, key) -> Counter:
        """按任意字段分组计数，返回按数量降序排列的 Counter。"""
        counter: Counter = Counter()
        for f in self.findings:
            counter[key(f)] += 1
        return Counter(dict(counter.most_common()))

    def top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        return Counter(f.ip for f in self.findings).most_common(n)
