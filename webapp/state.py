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

    def since(self, last_seq: int, limit: int = 50) -> list[dict]:
        """取出 seq 大于 last_seq 的告警，按时间正序返回。"""
        with self.lock:
            rows = [r for r in self.findings if r.get("seq", 0) > last_seq]
        rows.sort(key=lambda r: r["seq"])
        return rows[:limit]

    def recent(self, limit: int = 100, min_severity: str | None = None) -> list[dict]:
        order = ["low", "medium", "high", "critical"]
        floor = order.index(min_severity) if min_severity in order else 0
        with self.lock:
            items = list(self.findings)
        return [r for r in items if order.index(r["severity"]) >= floor][:limit]

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


def finding_row(f: Finding) -> dict:
    """把告警转成前端能直接用的字典。

    这里只做结构化，不做任何 HTML 拼接 —— 前端拿到的是数据，
    渲染成 DOM 时用 textContent。只要有一处用了 innerHTML，
    日志里的 <script> 就会执行，而这个日志本来就是攻击者写的。
    """
    return {
        "uid": f"{'+'.join(sorted(f.rule_names))}:{f.ip}",
        "time": f.ts.strftime("%m-%d %H:%M:%S") if f.ts else "",
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
