"""控制台的状态与响应动作：告警缓存、封禁表、审计日志。

这一层是 SOAR 的部分 —— 从"发现问题"走到"做出处置"。
和检测层最大的区别是：**这里会改外部世界的状态**。
检测错了只是多一条告警，封禁错了会让业务下线。
所以这里的每条路径都要有回滚和审计。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from sec_log_analyzer.models import Finding, Severity

# 审计日志和数据文件放在 data/，不进版本库（含真实 IP）
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass
class BanRecord:
    ip: str
    reason: str
    created_at: float
    expires_at: float
    operator: str
    dry_run: bool
    finding_uid: str = ""
    revoked_at: float = 0.0

    @property
    def active(self) -> bool:
        return not self.revoked_at and self.expires_at > time.time()

    def to_row(self) -> dict:
        d = asdict(self)
        d["created"] = datetime.fromtimestamp(self.created_at).strftime("%m-%d %H:%M:%S")
        d["expires"] = datetime.fromtimestamp(self.expires_at).strftime("%m-%d %H:%M:%S")
        d["remaining"] = max(0, int(self.expires_at - time.time()))
        d["active"] = self.active
        return d


@dataclass
class AppState:
    """进程内的全部可变状态。

    为什么用一把大锁而不是细分锁：
    这个应用的并发量是"一个人开两个标签页"，锁竞争根本不存在。
    细分锁带来的复杂度（死锁风险、加锁顺序）远大于那点性能收益。
    选型要看真实负载，不是看教科书。
    """

    findings: deque = field(default_factory=lambda: deque(maxlen=2000))
    bans: dict[str, BanRecord] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)
    watcher: object = None           # LogWatcher，由 create_app 注入
    dry_run: bool = True             # 默认不真封，先看效果
    stats: dict = field(default_factory=dict)
    # 单调递增的序号。SSE 推送靠它做增量：
    # 前端记住自己看到的最大 seq，重连时带上 since，只补发新的。
    # 不用时间戳是因为同一秒内的多条告警时间戳相同，会漏发。
    seq: int = 0

    def add_finding(self, f: Finding) -> None:
        row = finding_row(f)
        with self.lock:
            self.seq += 1
            row["seq"] = self.seq
            self.findings.appendleft(row)
        _persist_row(row)

    def load_persisted(self, limit: int = 2000) -> int:
        """把上次运行留下的告警读回内存。

        为什么必须落盘：告警原本只存在 deque 里，进程一重启就全没了。
        而「监控」工具最常被问的问题是「昨天下午那次扫描还在吗」——
        重启一次就查不到，等于没有历史。

        只回填最近 limit 条：更早的属于归档，翻页查全量是数据库的活，
        不该由一个内存展示层承担。
        """
        path = DATA_DIR / "findings.jsonl"
        if not path.exists():
            return 0
        rows: list[dict] = []
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        # 单行损坏不该影响整体。写入过程中断电会留下半行，
                        # 跳过它比整个文件读不出来要好。
                        continue
        except OSError:
            return 0

        rows = rows[-limit:]
        # 老版本落盘的记录没有 epoch 字段（那时还没加），
        # 直接跳过会让热力图和详情少统计一部分数据，而且没有任何提示。
        # 这里按 "月-日 时:分:秒" 反推出来，年份取当前年。
        #
        # 跨年会有歧义：12-31 的记录在 1 月读出来会被算成今年的 12-31（未来）。
        # 用「比现在晚一天以上就减一年」来兜，和解析层处理 syslog 年份是同一个思路。
        now = datetime.now()
        for r in rows:
            if r.get("epoch"):
                continue
            t = r.get("time") or ""
            try:
                dt = datetime.strptime(f"{now.year}-{t}", "%Y-%m-%d %H:%M:%S")
                if (dt - now).days > 1:
                    dt = dt.replace(year=now.year - 1)
                r["epoch"] = dt.timestamp()
            except ValueError:
                r["epoch"] = 0
        with self.lock:
            # appendleft 所以倒序回填，保证最新的在最前面
            for r in reversed(rows):
                self.findings.appendleft(r)
            if rows:
                self.seq = max(int(r.get("seq", 0)) for r in rows)
        return len(rows)

    def since(self, last_seq: int, limit: int = 50) -> list[dict]:
        """取出 seq 大于 last_seq 的告警，按时间正序返回。"""
        with self.lock:
            rows = [r for r in self.findings if r.get("seq", 0) > last_seq]
        rows.sort(key=lambda r: r["seq"])
        return rows[:limit]

    def recent(self, limit: int = 100, min_severity: str | None = None,
               date: str | None = None, sort: str = "time") -> list[dict]:
        """按条件取出告警。

        date   指定某一天（YYYY-MM-DD），None 表示不限
        sort   "time" 按时间倒序（最新在上）；"severity" 先按等级再按时间

        为什么排序在后端做而不是前端：前端的 SSE 流只拿到"新来的那几条"，
        它不知道历史里还有哪些，没法正确排序。要么拉全量到前端排（数据量一大就卡），
        要么让后端排好再给。选后者。
        """
        order = ["low", "medium", "high", "critical"]
        floor = order.index(min_severity) if min_severity in order else 0

        with self.lock:
            items = list(self.findings)

        out = []
        for r in items:
            if order.index(r.get("severity", "low")) < floor:
                continue
            if date and _epoch_date(r.get("epoch")) != date:
                continue
            out.append(r)

        if sort == "severity":
            # 等级优先，同等级内新的在上。
            # 用负的 ord 值让 "critical" 排最前；不能直接 reverse，
            # 那样同等级内的时间顺序也会跟着反过来。
            out.sort(key=lambda r: (-order.index(r.get("severity", "low")),
                                    -(r.get("epoch") or 0)))
        else:
            out.sort(key=lambda r: -(r.get("epoch") or 0))

        return out[:limit]

    def dates(self) -> list[dict]:
        """列出有告警的日期及条数，供日期下拉框使用。

        按日期倒序：看的时候总是先关心最近那天。
        日期用本地时区换算 —— 服务器和浏览器都在东八区时结果一致；
        如果部署在 UTC 机器上，这里的"天"会和用户看到的差几小时，
        所以后端不自己拼日期字符串，统一走 _epoch_date。
        """
        with self.lock:
            items = list(self.findings)
        counter: dict[str, int] = {}
        for r in items:
            d = _epoch_date(r.get("epoch"))
            if d:
                counter[d] = counter.get(d, 0) + 1
        return [
            {"date": d, "count": c}
            for d, c in sorted(counter.items(), reverse=True)
        ]

    # ---------------------------------------------------------------- 聚合
    def heatmap(self, hours: int = 24) -> dict:
        """最近 N 小时 × 严重等级 的告警分布。

        为什么不按「日期 + 小时」做：那样格子数是天数的 24 倍，
        跑三天就是 72 列，屏幕上挤成一团。
        只看「最近 24 小时」，横轴永远是 24 格，一眼能读完。

        时间轴用的是**事件时间**（epoch），不是入库时间。
        否则昨天补跑一次历史日志，所有格子会挤在当前这一小时里，
        看着像「攻击集中在今早」，其实是重放。
        """
        now = time.time()
        order = ["low", "medium", "high", "critical"]
        # matrix[severity][hour_index]
        matrix = {s: [0] * hours for s in order}
        totals = [0] * hours

        with self.lock:
            items = list(self.findings)

        for r in items:
            epoch = r.get("epoch")
            if not epoch:
                continue
            delta = now - float(epoch)
            if delta < 0 or delta >= hours * 3600:
                continue
            # 越新的越靠右：idx = hours-1 是「最近一小时」
            idx = hours - 1 - int(delta // 3600)
            if not (0 <= idx < hours):
                continue
            sev = r.get("severity", "low")
            if sev in matrix:
                matrix[sev][idx] += 1
                totals[idx] += 1

        return {
            "hours": hours,
            "labels": [(int((now - (hours - 1 - i) * 3600) // 3600)) % 24
                       for i in range(hours)],
            "totals": totals,
            "matrix": matrix,
            "max": max(totals) if totals else 0,
        }

    def by_ip(self, ip: str, limit: int = 200) -> dict:
        """某个来源 IP 的完整时间线。

        这是「点开一个来源，看他到底干了什么」的入口。
        比在地图上标个点有用得多 —— 地图只能说明他在哪，
        时间线能说明他试了什么、什么时候来的、来几次。
        """
        with self.lock:
            items = [r for r in self.findings if r.get("ip") == ip]
        # 按时间正序，看起来像一条时间线
        items.sort(key=lambda r: r.get("epoch") or 0)
        cats: dict[str, int] = {}
        for r in items:
            cats[r["category"]] = cats.get(r["category"], 0) + 1
        return {
            "ip": ip,
            "count": len(items),
            "first_seen": items[0].get("time") if items else None,
            "last_seen": items[-1].get("time") if items else None,
            "categories": cats,
            "items": items[-limit:],
        }

    # ---------------------------------------------------------------- 封禁
    def ban(self, ip: str, reason: str, ttl: int, operator: str,
            finding_uid: str = "") -> BanRecord:
        """登记一条封禁。

        注意：真正的"写 nginx 配置"在 apply_deny_file 里做，而且只在
        dry_run=False 时执行。这里只负责状态，好处是测试时不用碰系统文件。
        """
        now = time.time()
        rec = BanRecord(
            ip=ip, reason=reason, created_at=now, expires_at=now + ttl,
            operator=operator, dry_run=self.dry_run, finding_uid=finding_uid,
        )
        with self.lock:
            self.bans[ip] = rec
        audit("ban", ip=ip, reason=reason, ttl=ttl, operator=operator,
              dry_run=self.dry_run, finding_uid=finding_uid)
        return rec

    def revoke(self, ip: str, operator: str) -> bool:
        with self.lock:
            rec = self.bans.get(ip)
            if not rec or not rec.active:
                return False
            rec.revoked_at = time.time()
        audit("revoke", ip=ip, operator=operator)
        return True

    def active_bans(self) -> list[dict]:
        with self.lock:
            return [r.to_row() for r in self.bans.values() if r.active]

    def expire_bans(self) -> int:
        """清理已过期的记录。由后台线程定期调用。

        为什么必须有 TTL：
        不带过期的自动封禁，第一个封掉的往往是运维自己——
        他在外面换了个网络，IP 变了，然后被自己的规则挡在门外。
        这是真实事故，不是假设。
        """
        now = time.time()
        with self.lock:
            expired = [ip for ip, r in self.bans.items()
                       if not r.revoked_at and r.expires_at <= now]
            for ip in expired:
                self.bans.pop(ip, None)
        for ip in expired:
            audit("expire", ip=ip)
        return len(expired)


# ---------------------------------------------------------------------------
# 告警落盘
# ---------------------------------------------------------------------------
_persist_lock = threading.Lock()
_MAX_FILE_BYTES = 4 * 1024 * 1024   # 超过就精简重写


def _persist_row(row: dict) -> None:
    """把一条告警追加到 data/findings.jsonl。

    用 JSONL 而不是 SQLite：这一层的用途只是「重启后能翻到刚才那几条」，
    不是检索。为了翻页引入数据库、schema、迁移，成本远大于收益。

    什么时候该换成 SQLite：需要按任意字段组合查询、或者数据量到几十万条。
    现在一天几百条，JSONL 完全够。
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "findings.jsonl"
    line = json.dumps(row, ensure_ascii=False)
    with _persist_lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                _compact(path)
        except OSError:
            pass


def _compact(path: Path, keep: int = 2000) -> None:
    """文件太大时只保留最近 keep 行。

    同样是原子替换：直接重写会在写到一半时被读到，
    那一刻的历史是空的。审计日志和告警一样，不能有「部分可见」的中间态。
    """
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    tail = lines[-keep:]
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(tail) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _epoch_date(epoch) -> str:
    """epoch 秒 -> 本地日期字符串 YYYY-MM-DD。

    单独抽出来是因为有三处要用（列表筛选、日期下拉、详情页），
    各自写一遍 datetime 换算，早晚会在时区或格式化上不一致。
    """
    try:
        e = float(epoch or 0)
    except (TypeError, ValueError):
        return ""
    if e <= 0:
        return ""
    return datetime.fromtimestamp(e).strftime("%Y-%m-%d")


def finding_row(f: Finding) -> dict:
    """把告警转成前端能直接用的字典。

    这里只做结构化，不做任何 HTML 拼接 —— 前端拿到的是数据，
    渲染成 DOM 时用 textContent。只要有一处用了 innerHTML，
    日志里的 <script> 就会执行，而这个日志本来就是攻击者写的。
    """
    return {
        "uid": f"{'+'.join(sorted(f.rule_names))}:{f.ip}",
        "time": f.ts.strftime("%m-%d %H:%M:%S") if f.ts else "",
        # epoch 单独留一份：前端要算时间轴，用字符串解析日期既慢又容易出错
        # （"11-11 09:15:10" 没有年份，跨年就废了）。
        "epoch": f.ts.timestamp() if f.ts else 0,
        "ip": f.ip,
        "category": f.category,
        "severity": f.severity.value,
        "score": f.score,
        "path": f.entry.path,
        "reason": f.reason,
        # 原文里可能含引号、尖括号、换行，全部原样传给前端，
        # 由前端用 textContent 安全渲染。服务端不做 HTML 转义，
        # 因为服务端转义后前端再显示会变成 &lt; 这种乱码。
        "raw": f.entry.raw,
    }


# ---------------------------------------------------------------------------
# 审计
# ---------------------------------------------------------------------------
_audit_lock = threading.Lock()


def audit(action: str, **fields) -> None:
    """把每一次处置写进审计日志。

    为什么单独记而不是写应用日志里：
    应用日志会被轮转、会被调到 debug 级别之后淹没。
    审计日志的用途是"三个月后有人问谁封了这个 IP"，
    必须独立、只追加、不参与轮转清理。

    没有审计的自动化响应等于没有响应 —— 出了事没人能说清是谁做的、
    依据是什么。这也是 SOAR 产品和"脚本自动封 IP"的根本区别。
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        **fields,
    }
    line = json.dumps(record, ensure_ascii=False)
    with _audit_lock:
        with (DATA_DIR / "audit.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


# ---------------------------------------------------------------------------
# 真正落地封禁
# ---------------------------------------------------------------------------
def apply_deny_file(ips: list[str], *, target: Path | None = None) -> dict:
    """把 IP 列表写进 nginx 的 deny 配置文件，并让 nginx 重载。

    安全要点（这段是整个项目最容易出事故的地方）：

    1. **只用列表参数调用子进程，永远不用 shell=True。**
       shell=True 会把字符串交给 shell 解释，IP 里混进一个 `;` 就是命令执行。
       传列表时参数不经过 shell，注入字符只是普通字符。

    2. **原子替换。** 直接写目标文件时，nginx 可能正好读到写了一半的内容。
       先写临时文件、fsync、再 os.replace —— replace 在同一文件系统内是原子的，
       读到的要么是旧内容要么是新内容，不存在中间态。

    3. **先 `nginx -t` 再 reload。** 配置有语法错误时 reload 会让 nginx
       直接退出，整站 502。先把测试当闸门，测不过就回滚。

    4. **回滚。** 写之前备份原文件，任何一步失败都恢复。
    """
    target = target or DATA_DIR / "deny.conf"
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = target.with_suffix(".conf.bak")

    content_lines = [
        "# 由 sec-log-analyzer 自动生成，请勿手工编辑",
        "# 每行一条，形如 deny 1.2.3.4;",
    ]
    # 这里再校验一次 IP，不信任调用方。
    # 纵深防御的原则：每个关键函数自己负责自己的安全，
    # 不假设上游一定校验过。
    from .security import parse_ip
    safe = [p for ip in ips if (p := parse_ip(ip))]
    content_lines += [f"deny {ip};" for ip in safe]
    content = "\n".join(content_lines) + "\n"

    result = {"ok": False, "written": len(safe), "message": "", "reloaded": False}

    if target.exists():
        shutil.copy2(target, backup)

    # 临时文件必须和目标在同一目录，否则 os.replace 会跨文件系统失败
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, target)
    except OSError as exc:
        result["message"] = f"写入失败：{exc}"
        Path(tmp_name).unlink(missing_ok=True)
        return result

    # nginx 不存在（开发机）就直接返回成功，但要说清楚没有生效
    if not shutil.which("nginx"):
        result.update(ok=True, message="已写入配置（本机无 nginx，未执行重载）")
        return result

    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        if backup.exists():
            os.replace(backup, target)  # 回滚
        result["message"] = f"nginx -t 失败，已回滚：{test.stderr.strip()[:200]}"
        return result

    reload_proc = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
    result.update(
        ok=reload_proc.returncode == 0,
        reloaded=reload_proc.returncode == 0,
        message="已生效" if reload_proc.returncode == 0
        else f"重载失败：{reload_proc.stderr.strip()[:200]}",
    )
    return result
