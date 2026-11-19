"""IP 地理位置查询。

为什么用离线库而不是在线 API
----------------------------
1. **隐私**：把攻击者 IP 批量发给第三方 API，等于把你的观测数据送给别人。
   这些 IP 虽然是攻击者，但"谁在什么时间攻击哪台机器"本身就是情报。
2. **稳定性**：在线 API 有速率限制，645 个 IP 会被限流甚至封禁。
3. **可复现**：离线库固定，同一份日志每次分析结果一致。

用的是 MaxMind GeoLite2 City。它给到城市级经纬度，比国家级的库有用得多——
国家级只能把点撒在首都，看不出地域分布。

降级策略
--------
库不存在或没装 maxminddb 时，lookup 返回 ok=False，调用方跳过这个点，
而不是报错。地图少几个点比整个页面打不开好。
"""

from __future__ import annotations

import ipaddress
import threading
from pathlib import Path

DEFAULT_DB = Path("data/dbip-city-lite.mmdb")

# 库文件的许可要求展示归属，很多项目会忘
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"

# 港澳台必须按中国特别行政区/省份呈现，不能当成独立国家。
# 地理库返回的是 ISO 代码，这里统一改写显示名。
CN_REGIONS = {
    "HK": "中国香港",
    "MO": "中国澳门",
    "TW": "中国台湾",
}


class GeoLookup:
    """线程安全的懒加载查询器。

    缓存在两个层面：
      - 实例级 dict：同一个 IP 多次出现只查一次库
      - 库对象本身：进程内只打开一次

    为什么要缓存：一次分析 3000 条日志、600 多个 IP，
    每个 IP 可能重复几十次，不缓存就是几千次 B 树查找。
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self._reader = None
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._load_failed = False

    # ------------------------------------------------------------------ 内部
    def _ensure(self) -> None:
        if self._reader is not None or self._load_failed:
            return
        with self._lock:
            if self._reader is not None or self._load_failed:
                return
            if not self.db_path.exists():
                self._load_failed = True
                return
            try:
                import maxminddb

                self._reader = maxminddb.open_database(str(self.db_path))
            except Exception:  # noqa: BLE001
                # 库文件损坏、版本不兼容、依赖没装，都归到"用不了"
                self._load_failed = True

    @property
    def available(self) -> bool:
        self._ensure()
        return self._reader is not None

    # ------------------------------------------------------------------ 查询
    def lookup(self, ip: str) -> dict:
        """返回 {ok, country, country_code, city, lat, lon}。

        私有地址、内网地址直接返回 ok=False —— 它们本来就没有地理位置，
        硬查会得到 None，让调用方多做一次判断。
        """
        if ip in self._cache:
            return self._cache[ip]

        result = self._do_lookup(ip)
        self._cache[ip] = result
        return result

    def _do_lookup(self, ip: str) -> dict:
        # 内网、环回、保留地址：没有地理意义
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return {"ok": False, "reason": "private"}
        except ValueError:
            return {"ok": False, "reason": "bad_ip"}

        self._ensure()
        if self._reader is None:
            return {"ok": False, "reason": "no_db"}

        try:
            rec = self._reader.get(ip)
        except Exception:  # noqa: BLE001
            return {"ok": False, "reason": "lookup_error"}

        if not rec:
            return {"ok": False, "reason": "not_found"}

        loc = rec.get("location") or {}
        lat, lon = loc.get("latitude"), loc.get("longitude")
        if lat is None or lon is None:
            return {"ok": False, "reason": "no_coord"}

        country = rec.get("country") or {}
        city = rec.get("city") or {}
        names = country.get("names") or {}

        code = country.get("iso_code") or ""
        name = CN_REGIONS.get(code) or names.get("zh-CN") or names.get("en") or ""

        return {
            "ok": True,
            "country": name,
            "country_code": code,
            "city": (city.get("names") or {}).get("zh-CN")
                    or (city.get("names") or {}).get("en") or "",
            "lat": round(float(lat), 4),
            "lon": round(float(lon), 4),
        }

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:  # noqa: BLE001
                pass
            self._reader = None


_default: GeoLookup | None = None
_default_lock = threading.Lock()


def get_lookup() -> GeoLookup:
    """进程级单例。地图接口每次请求都新建一个会重复打开 50MB 的库。"""
    global _default
    if _default is None:
        with _default_lock:
            if _default is None:
                _default = GeoLookup()
    return _default


__all__ = ["GeoLookup", "get_lookup", "ATTRIBUTION", "CN_REGIONS"]
