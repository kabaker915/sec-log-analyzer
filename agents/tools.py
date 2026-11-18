"""Agent 的工具集。

设计原则：**工具是纯函数，不依赖 LLM，可以单独测。**

为什么这条重要：Agent 出问题时，你永远要能回答"是模型判断错了，
还是工具返回的数据错了"。工具能脱离模型单测，这个问题才有答案。

所有工具返回 dict，且都带 `source` 字段——告诉模型这个数据从哪来。
模型编造结论时最常见的表现是"引用了一个工具没返回的数据"，
有了 source 就能比对。
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

# 这些由外部注入（analyze 结果、告警列表），保持工具无状态
_ctx: dict[str, Any] = {}


def bind(findings: list[dict], entries: list[Any]) -> None:
    """把一次分析的上下文绑给工具集。"""
    _ctx["findings"] = findings
    _ctx["entries"] = entries


# ---------------------------------------------------------------------------
# 工具定义（给 LLM 看的 schema）
# ---------------------------------------------------------------------------
TOOL_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "get_log_context",
            "description": "查看某个 IP 在告警时间点前后的原始请求记录，用于确认它到底做了什么",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "来源 IP"},
                    "limit": {"type": "integer", "description": "最多返回几条，默认 10"},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_alerts_by_ip",
            "description": "列出某个 IP 触发的全部告警，用于判断它是单次探测还是持续攻击",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_ip_intel",
            "description": "查询 IP 的威胁情报归属，返回是否为已知扫描器/云厂商/数据中心",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_asset_info",
            "description": "查询目标资产的归属与重要性，用于判断这次攻击的影响面",
            "parameters": {
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "被攻击的资产 IP"}},
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_verdict",
            "description": "提交最终研判结论。这是最后一步，调用后对话结束",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "enum": ["true_positive", "false_positive", "needs_investigation"],
                        "description": "真阳性=确认是攻击；假阳性=正常行为被误报；需进一步调查",
                    },
                    "confidence": {"type": "number", "description": "0 到 1 之间的置信度"},
                    "reason": {"type": "string", "description": "结论依据，必须引用工具返回的事实"},
                    "action": {"type": "string", "description": "建议处置动作"},
                },
                "required": ["verdict", "confidence", "reason", "action"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# 工具实现
# ---------------------------------------------------------------------------
def get_log_context(ip: str, limit: int = 10) -> dict:
    entries = _ctx.get("entries") or []
    hit = [e for e in entries if getattr(e, "ip", None) == ip]
    # 按时间排序，取最近的
    hit.sort(key=lambda e: getattr(e, "ts", None) or 0)
    rows = [
        {
            "time": e.ts.strftime("%m-%d %H:%M:%S") if getattr(e, "ts", None) else "",
            "method": getattr(e, "method", ""),
            "path": (getattr(e, "path", "") or "")[:80],
            "status": getattr(e, "status", 0),
            "ua": (getattr(e, "user_agent", "") or "-")[:60],
        }
        for e in hit[-limit:]
    ]
    return {
        "source": "access_log",
        "ip": ip,
        "total": len(hit),
        "returned": len(rows),
        "rows": rows,
    }


def list_alerts_by_ip(ip: str) -> dict:
    findings = _ctx.get("findings") or []
    hit = [f for f in findings if f.get("ip") == ip]
    cats = Counter(f.get("category", "?") for f in hit)
    return {
        "source": "detector",
        "ip": ip,
        "count": len(hit),
        "categories": dict(cats),
        "severities": dict(Counter(f.get("severity", "?") for f in hit)),
        "rules": sorted({r for f in hit for r in _rules_of(f)}),
    }


def _rules_of(f: dict) -> list[str]:
    """取出一条告警命中的规则名。

    优先用 rule_names 字段；没有的话从 uid 反解。
    uid 的格式是 "规则1+规则2:IP"，当初设计这个字段只是给前端去重用的，
    没想过会被拿来当数据源——现在补一个显式字段才是正解，
    但为了不改动 Web API 的返回结构，这里先做兼容解析。
    """
    names = f.get("rule_names")
    if names:
        return list(names)
    uid = f.get("uid") or ""
    if ":" in uid:
        return [x for x in uid.split(":", 1)[0].split("+") if x]
    return []


def check_ip_intel(ip: str) -> dict:
    """情报查询。

    ⚠️ 这里是 mock，真实实现应查本地 GeoLite2 / 内部情报库。
    **不要直接调第三方 API**：一是把攻击者 IP 发给别人属于数据外泄，
    二是有速率限制，跑一遍几百条告警就会被封。
    """
    cloud_prefix = ("20.", "13.", "34.", "35.", "104.", "52.", "3.")
    known_scanner = {"censys", "zgrab", "nmap", "masscan"}
    return {
        "source": "mock_intel",
        "ip": ip,
        "is_datacenter": ip.startswith(cloud_prefix),
        "note": "占位数据，非真实情报。真实实现应接本地库",
        "known_scanner_ua": sorted(known_scanner) if ip.startswith(cloud_prefix) else [],
    }


def get_asset_info(ip: str) -> dict:
    """资产归属。真实环境应查 CMDB。"""
    return {
        "source": "mock_cmdb",
        "ip": ip,
        "role": "公网测试机（无业务）" if ip.startswith("127.") else "未知资产",
        "criticality": "low",
        "note": "占位数据，真实实现应接 CMDB",
    }


_DISPATCH = {
    "get_log_context": get_log_context,
    "list_alerts_by_ip": list_alerts_by_ip,
    "check_ip_intel": check_ip_intel,
    "get_asset_info": get_asset_info,
}


def call(name: str, args: dict) -> dict:
    """统一入口。异常必须被捕获并作为观察结果返回——
    工具抛异常直接冒泡到 LLM 会让整个 agent 崩掉。"""
    fn = _DISPATCH.get(name)
    if fn is None:
        return {"error": f"没有这个工具: {name}"}
    try:
        return fn(**args)
    except TypeError as exc:
        return {"error": f"参数不对: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"工具执行失败: {exc.__class__.__name__}: {exc}"}
