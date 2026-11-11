"""OCSF 归一化层：把内部结构导出成 SIEM 能直接吃的格式。

为什么要做这一层

    SIEM 之所以能同时处理防火墙、Windows 事件、EDR、云审计的日志，
    靠的不是解析器多，而是**它们最终都收敛到同一个字段模型**。
    没有统一 schema 的系统，数据量再大也只能叫"日志平台"，不叫 SIEM。

    这一层做的就是收敛：不管上游是 nginx access.log 还是 sshd auth.log，
    出去都是同一个形状，字段名和取值域固定。

选 OCSF 而不是自己编一套

    OCSF（Open Cybersecurity Schema Framework）是 AWS、Splunk、CrowdStrike
    等联合推的开放 schema，从 Splunk 的 CIM 演进而来。
    用它的好处不是"更专业"，而是**可对接**：
    字段名一旦定成 src_endpoint.ip，下游任何按 OCSF 写的查询都能直接用，
    不需要再解释"我这个 ip 字段到底指源还是目的"。

    自己编 schema 的项目，三个月后连自己都记不清字段含义，
    这是内部工具最常见的腐化方式。

⚠️ 关于完整度的诚实说明

    这里是 OCSF 的**子集**，只覆盖 HTTP Activity(4002) 与 Authentication(3002)
    两个事件类，字段也做了裁剪。
    刻意不做完整的 200+ 字段：一个日志分析工具填不出 device.owner、
    os.build、actor.process 这些东西，硬填就是造假。

    对外表述应当是"参照 OCSF 建模"，不是"符合 OCSF 规范"——
    两者差别很大，面试官真懂的话会追问 conformance。
"""

from __future__ import annotations

import json
from datetime import datetime

from .models import Finding, LogEntry, Severity

# OCSF 版本。字段实现变化时这里要跟着改，否则下游解析会错位。
OCSF_VERSION = "1.3.0"

PRODUCT = {"name": "sec-log-analyzer", "vendor_name": "self-hosted"}

# ---------------------------------------------------------------------------
# 枚举映射
# ---------------------------------------------------------------------------
# OCSF 的等级是 0-6，我们的 Severity 是 4 档。映射关系不能"平均分配"：
# critical 对 5(Critical) 而不是 6(Fatal) —— Fatal 在 OCSF 里指系统不可用级别的
# 灾难，一次 SQL 注入尝试够不上。等级虚高的告警等于没有等级。
SEVERITY_ID: dict[Severity, int] = {
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

# HTTP Activity 的 activity_id
METHOD_ACTIVITY = {
    "GET": 1,
    "POST": 2,
    "PUT": 3,
    "DELETE": 4,
    "HEAD": 5,
    "OPTIONS": 6,
    "TRACE": 7,
    "CONNECT": 8,
}

# 认证类事件的 status_id：1=成功 2=失败。OCSF 里认证结果不走 severity 表达。
AUTH_STATUS = {"failed": 2, "invalid_user": 2, "accepted": 1}

CLASS_HTTP = 4002
CLASS_AUTH = 3002
CATEGORY_NETWORK = 4
CATEGORY_IAM = 3


def _ts_millis(ts: datetime | None) -> int:
    """OCSF 的 time 字段是「毫秒级 epoch」，不是 ISO 字符串。

    这是最容易踩的一处：写成人能读的时间看着没问题，
    但下游做时间范围过滤时会直接错位。序列化格式必须按规范来。
    """
    if ts is None:
        return 0
    return int(ts.timestamp() * 1000)


def _envelope(class_uid: int, category_uid: int, activity_id: int) -> dict:
    """每种事件都有的公共外壳。

    type_uid = class_uid * 100 + activity_id 是 OCSF 的固定计算方式，
    不是随便定的——下游靠它做单字段路由，不用同时判断两个字段。
    """
    return {
        "class_uid": class_uid,
        "category_uid": category_uid,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "metadata": {"version": OCSF_VERSION, "product": dict(PRODUCT)},
    }


def entry_to_ocsf(entry: LogEntry) -> dict:
    """一条原始日志 -> 一个 OCSF 事件。"""
    if entry.source == "auth":
        return _auth_event(entry)

    activity = METHOD_ACTIVITY.get(entry.method.upper(), 0)
    ev = _envelope(CLASS_HTTP, CATEGORY_NETWORK, activity)
    ev.update(
        {
            "time": _ts_millis(entry.ts),
            # 原始日志没被判成攻击时，等级就是 Informational。
            # 不要因为"这是安全工具的日志"就全部抬成 Medium —— 那指标就没意义了。
            "severity_id": 1,
            "status": "Success" if (entry.status or 0) < 400 else "Failure",
            "src_endpoint": {"ip": entry.ip},
            "http_request": {
                "http_method": entry.method or "UNKNOWN",
                "version": entry.protocol.replace("HTTP/", "") or None,
                "url": {"path": entry.path, "query_string": entry.query or None},
                "user_agent": entry.user_agent or None,
            },
            "http_response": {
                "code": entry.status,
                "length": entry.size,
            },
            # 原文单独留一份：脱敏后的结构化字段会丢信息，
            # 出事复盘时往往还得看原样。OCSF 专门留了 raw_data 给这个用途。
            "raw_data": entry.raw,
        }
    )
    return _drop_none(ev)


def _auth_event(entry: LogEntry) -> dict:
    event = entry.message.split(":", 1)[0]
    activity = 1 if event == "accepted" else 2  # 1=Logon 2=Logoff 之外的失败归到 Logon 尝试
    ev = _envelope(CLASS_AUTH, CATEGORY_IAM, activity)
    ev.update(
        {
            "time": _ts_millis(entry.ts),
            "severity_id": 1,
            "status_id": AUTH_STATUS.get(event, 0),
            "status": "Success" if event == "accepted" else "Failure",
            "src_endpoint": {"ip": entry.ip},
            "user": {"name": entry.username} if entry.username else None,
            "auth_protocol": "SSH",
            "raw_data": entry.raw,
        }
    )
    return _drop_none(ev)


def finding_to_ocsf(finding: Finding) -> dict:
    """告警 -> 一个 OCSF Detections Finding。

    Detections Finding 是 OCSF 里专门表示"检测结果"的类（2001/2004 系列）。
    把告警和原始事件分开成两类对象，是 SIEM 的基本设计：
    事件是"发生了什么"，告警是"我认为这有问题"。混在一起就分不清
    "一条日志"和"一条判断"，后续做误报标注会无从下手。

    这里复用了原始事件的字段，但补上 finding_info 与研究结论。
    """
    base = entry_to_ocsf(finding.entry)
    ev = {
        # Finding 类。activity_id=1 表示 Create（生成了新告警）。
        "class_uid": 2004,
        "category_uid": 2,
        "activity_id": 1,
        "type_uid": 200401,
        "metadata": {"version": OCSF_VERSION, "product": dict(PRODUCT)},
        "time": _ts_millis(finding.ts),
        "severity_id": SEVERITY_ID.get(finding.severity, 3),
        "status": "New",
        "finding_info": {
            "title": finding.category,
            # uid 用规则名 + IP 拼，是为了让"同一类攻击的重复告警"在 SIEM 里
            # 归到同一个 finding，而不是每天新增几百条。这是去重的基础。
            "uid": f"{'+'.join(sorted(finding.rule_names))}:{finding.ip}",
            "types": finding.rule_names,
            "desc": finding.reason,
        },
        "src_endpoint": {"ip": finding.ip},
        "observables": [
            {
                "name": "src_endpoint.ip",
                "type": "IP Address",
                "value": finding.ip,
            }
        ],
        # 把原始事件嵌进去，保留完整上下文。代价是体积变大，
        # 换来的好处是看一条告警不用再回查原始日志。
        "raw_data": finding.entry.raw,
        "unmapped": {
            "score": finding.score,
            "source_class_uid": base.get("class_uid"),
            "ai_comment": finding.ai_comment or None,
        },
    }
    return _drop_none(ev)


def _drop_none(obj):
    """递归去掉 None 值。

    目的不是省字节，是避免 downstream 把 "user_agent": null 当成
    "这个字段存在但值为空"，从而误判为解析成功。
    字段不存在和字段为空是两件事。
    """
    if isinstance(obj, dict):
        return {k: _drop_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_drop_none(v) for v in obj]
    return obj


def to_jsonl(entries: list[LogEntry], findings: list[Finding] | None = None) -> str:
    """按 OCSF 事件流导出 JSONL（一行一个事件）。

    JSONL 而不是一个大 JSON 数组，是因为：
      * 可以流式写入和读取，不用先把整个文件读进内存
      * 单行损坏不影响其他行，容错性好
      * 这是几乎所有日志管道（Filebeat、Fluent Bit、Vector）的默认输入格式
    """
    lines: list[str] = []
    # 先事件后告警：下游按行流式入库时，告警可能引用事件的关联键，
    # 顺序反了会出现"告警指向一条还没入库的事件"。
    for e in entries:
        lines.append(json.dumps(entry_to_ocsf(e), ensure_ascii=False))
    for f in findings or []:
        lines.append(json.dumps(finding_to_ocsf(f), ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")
