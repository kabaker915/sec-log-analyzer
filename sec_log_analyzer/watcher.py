"""实时监控引擎：把离线分析器变成能长期跑着的监控。

和离线分析的区别不只是"持续读文件"，有四个新问题是离线模式不存在的：

1. 文件会被 logrotate 动过
   两条常见策略，行为完全不同：
     * copytruncate —— 复制一份后把原文件清空。文件没换，大小突然变 0。
     * create       —— 改名后新建一个同名文件。路径没变，inode 变了。
   两种都要处理，否则轮转之后就开始读垃圾或者一整天不再读任何东西。

2. 一行可能只读到一半
   nginx 写日志不是原子操作，读写指针可能正卡在行中间。
   把半行当一个完整行去解析，会得到一条永远解析失败的"幽灵日志"，
   而且下一行也会跟着错位。必须把残行留到下次再拼。

3. 行为检测会被反复触发
   离线只跑一次，实时每秒都在跑。按时间窗口统计的规则（404 突发、
   分布式扫描）会对着同一段历史数据反复得出同一个结论。
   不抑制的话，一个 5 分钟的攻击会在一天里报出上万条相同告警——
   这就是把系统做死的方式。

4. 内存必须有上限
   deque 不设 maxlen 的话，跑满一周就是一个 GB 级泄漏。
   限长之后代价是"太久以前的数据看不见"，这是必须接受的取舍：
   实时检测只关心最近的状态，历史由存储层负责。
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .config import Config
from .detector import Detector
from .models import Finding, LogEntry, Severity
from .parser import LogParser, decode_bytes, is_syslog_shaped


@dataclass
class WatcherStats:
    """对外暴露的运行状态。控制台的顶部数字全部来自这里。"""

    started_at: datetime = field(default_factory=datetime.now)
    lines_read: int = 0
    entries_parsed: int = 0
    parse_errors: int = 0
    # 能识别成 syslog、但压根不含 IP 的行（CRON、systemd-logind、内核消息）。
    # 和 parse_errors 必须分开统计，理由和离线版一样：
    # 一台普通服务器的 auth.log 里这类行占七成以上，
    # 混进"解析失败"会让面板天天报 71% 的失败率，看的人第一反应是工具坏了。
    # 同一个错误在两个地方各犯一次，说明这类问题要从结构上避免 ——
    # 现在两处都调用 parser.is_syslog_shaped()，判断逻辑只有一份。
    skipped_no_ip: int = 0
    findings_total: int = 0
    suppressed_total: int = 0
    last_event_ts: datetime | None = None
    files: dict[str, int] = field(default_factory=dict)  # 路径 -> 已读字节

    def snapshot(self) -> dict:
        uptime = (datetime.now() - self.started_at).total_seconds()
        return {
            "uptime_seconds": int(uptime),
            "started_at": self.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "lines_read": self.lines_read,
            "entries_parsed": self.entries_parsed,
            "parse_errors": self.parse_errors,
            "skipped_no_ip": self.skipped_no_ip,
            "findings_total": self.findings_total,
            "suppressed_total": self.suppressed_total,
            "last_event_ts": (
                self.last_event_ts.strftime("%Y-%m-%d %H:%M:%S")
                if self.last_event_ts
                else None
            ),
            "files": dict(self.files),
        }


class _FileTail:
    """单个文件的增量读取状态。

    把"每个文件的读取进度"独立成一个对象，而不是在 watcher 里塞一堆字典，
    是因为轮转检测需要同时看 inode 和 size 两个量，
    把它们绑在一起才不会出现"读了 A 文件的偏移量去 B 文件找"这种错位。
    """

    def __init__(self, path: Path, from_start: bool = False) -> None:
        self.path = path
        self.offset = 0
        self.inode: int | None = None
        self.partial = b""          # 上一轮读到的残行（无换行结尾）
        self._fh = None
        self._from_start = from_start
        self._open(from_start)

    def _open(self, from_start: bool) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
        try:
            self._fh = open(self.path, "rb")
        except FileNotFoundError:
            # 文件还不存在是**正常情况**，不是错误。
            # 三种常见场景：
            #   1. 服务先于应用启动，日志文件还没被创建
            #   2. logrotate 的 create 策略在旧文件删除和新文件创建之间有间隙
            #   3. 用户传错了路径，但他希望先跑起来再补
            # 原实现在这里直接抛异常，整个应用起不来 ——
            # 一个"日志文件暂时不在"就让监控系统崩溃，是最不该有的失败模式。
            # 改为标记为未就绪，每轮 poll 重试。
            self._fh = None
            self.offset = 0
            self.partial = b""
            return
        st = os.fstat(self._fh.fileno())
        self.inode = st.st_ino
        if from_start:
            self.offset = 0
            self._fh.seek(0)
        else:
            # 默认从文件末尾开始：监控工具重启后如果把历史全部重放一遍，
            # 会瞬间刷出一堆"新"告警，把真正的新事件淹掉。
            self.offset = st.st_size
            self._fh.seek(self.offset)
        self.partial = b""

    def _rotated(self) -> bool:
        """判断文件是否被轮转过。两种策略都要认。"""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            # 文件被删了（logrotate 的 postrotate 还没建新的）。
            # 不能当成"读完了"，否则这个文件就再也不跟了。
            return True
        if st.st_ino != self.inode:
            return True                      # create 策略：换了新文件
        if st.st_size < self.offset:
            return True                      # copytruncate 策略：原文件被清空
        return False

    def read_new(self, max_bytes: int = 4 * 1024 * 1024) -> tuple[list[str], bool]:
        """返回 (完整行列表, 是否发生轮转)。

        max_bytes 是一次读取的上限。日志突然暴涨（比如被 CC 攻击打满）时，
        不限量读取会把内存打爆 —— 而攻击者知道这一点，
        制造海量日志本来就是一种让监控失效的手段。
        """
        # 上一轮没打开（文件当时不存在），这一轮再试一次
        if self._fh is None:
            self._open(self._from_start)
            if self._fh is None:
                return [], False

        rotated = False
        if self._rotated():
            rotated = True
            try:
                self._open(from_start=True)
            except FileNotFoundError:
                return [], True
            if self._fh is None:
                return [], True

        self._fh.seek(self.offset)
        chunk = self._fh.read(max_bytes)
        if not chunk:
            return [], rotated

        self.offset += len(chunk)
        data = self.partial + chunk
        # 只按 \n 切，最后一段如果没换行结尾就是残行，留到下次
        parts = data.split(b"\n")
        self.partial = parts.pop() if parts else b""

        lines: list[str] = []
        if parts:
            # 整块解码再切行。逐行解码会让多字节字符跨行边界时出错，
            # GBK 的中文日志尤其明显。
            text, _ = decode_bytes(b"\n".join(parts), ("utf-8", "gbk", "latin-1"))
            lines = text.split("\n")
        return lines, rotated

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


class _Throttle:
    """告警抑制：同一类告警在 TTL 内只发一次，并记录被压掉了多少条。

    为什么不是"每次命中都发"：
    实时模式下每轮都会重扫最近的缓冲区，一次持续 5 分钟的攻击会被算出几十次。
    原样全部推送的话，真正的新事件会被自己的重复告警埋掉。

    为什么不是"完全丢弃"：
    压制次数要能看见。分析师需要知道"这条告警背后其实有 47 次命中"，
    而不是以为只发生了一次。**抑制不等于忽略**，
    这两者的差别决定了告警是可用的还是有害的。
    """

    def __init__(self, ttl_seconds: int) -> None:
        self.ttl = ttl_seconds
        self._last: dict[tuple, float] = {}
        self._count: dict[tuple, int] = {}

    def check(self, key: tuple, now: float | None = None) -> tuple[bool, int]:
        """返回 (是否应该发出, 自上次发出后被压掉的次数)。"""
        now = now if now is not None else time.monotonic()
        last = self._last.get(key)
        suppressed = self._count.get(key, 0)
        if last is not None and now - last < self.ttl:
            self._count[key] = suppressed + 1
            return False, 0
        self._last[key] = now
        self._count[key] = 0
        return True, suppressed

    def gc(self, older_than: float = 3600.0) -> None:
        """清理长时间没出现的键。

        不做这一步的话，字典会随着不同攻击 IP 的累积无限增长。
        一个被全网扫过的公网 IP，一天能见几千个来源。
        """
        now = time.monotonic()
        stale = [k for k, t in self._last.items() if now - t > older_than]
        for k in stale:
            self._last.pop(k, None)
            self._count.pop(k, None)


class LogWatcher:
    """把日志文件的变化变成告警流。

    用法一：程序内轮询
        w = LogWatcher(["/var/log/nginx/access.log"], config)
        while True:
            for finding in w.poll():
                ...
            time.sleep(0.5)

    用法二：回调 + 线程（Web 控制台用的就是这种）
        w.run(on_finding=queue.put, stop_event=threading.Event())
    """

    def __init__(
        self,
        paths: list[str | Path],
        config: Config | None = None,
        *,
        buffer_size: int = 20_000,
        behavior_interval: float = 5.0,
        throttle_ttl: int = 300,
        from_start: bool = False,
    ) -> None:
        self.config = config or Config.from_env()
        self.detector = Detector(self.config)
        self.parser = LogParser(self.config)

        # 行为检测要看历史，所以必须留一个窗口。
        # 20000 条 ≈ 正常站点几小时到几天的量，内存占用约 20-40MB，
        # 在 4G 的机器上可以接受。
        self.buffer: deque[LogEntry] = deque(maxlen=buffer_size)
        self.behavior_interval = behavior_interval

        self._tails = {str(p): _FileTail(Path(p), from_start=from_start) for p in paths}
        self._throttle = _Throttle(throttle_ttl)
        # 已处理过的「同一条告警」：键是 (抑制键, 事件时间戳)。
        #
        # 为什么需要它：行为检测每 behavior_interval 秒重扫一次窗口，
        # 同一段历史会被反复算出完全相同的告警。这些重复如果计入
        # suppressed_total，这个数字就变成了「扫描次数」而不是
        # 「被压掉的攻击次数」—— 面板上会出现 160 抑制 / 22 推送 这种比例，
        # 看起来像抑制过猛，其实只是同一件事被数了 7 遍。
        # 指标必须反映真实发生的事，不能反映程序内部循环了几次。
        self._emitted: dict[tuple, float] = {}
        self._last_behavior_run = 0.0
        self._lock = threading.RLock()
        self.stats = WatcherStats()

        # 行为检测不可能只跑最新一条，必须回到缓冲区里看上下文；
        # 而缓冲区是无限的，所以限定"只看最近 max_window 秒"。
        # 这个值必须 >= 所有行为规则的窗口，否则规则永远凑不够数据。
        self.max_window = max(
            self.config.scan_window_seconds,
            self.config.brute_slow_window,
            self.config.protocol_error_window,
            self.config.distributed_window,
        )

    # ------------------------------------------------------------------
    def poll(self) -> list[Finding]:
        """读一轮并返回新增告警。非阻塞，调用方自己控制节奏。"""
        with self._lock:
            return self._poll_locked()

    def poll_throttled(self) -> list[Finding]:
        """poll + 抑制。对外推荐用这个。

        直接推原始告警会灌爆上游：行为规则每 5 秒重扫一次缓冲区，
        同一段攻击每分钟就是 12 条重复。抑制必须在锁内完成，
        否则两个线程可能各读到同一批增量、各发一遍。
        """
        with self._lock:
            return self._apply_throttle(self._poll_locked())

    def _poll_locked(self) -> list[Finding]:
        """读所有文件的新增行 -> 解析 -> 入缓冲 -> 两路检测。

        调用方必须已持有 self._lock。名字带 locked 是为了让这件事写在签名上——
        否则半年后有人直接调用它，读到一半缓冲区被另一个线程改掉，很难查。
        """
        new_entries: list[LogEntry] = []

        for key, tail in self._tails.items():
            try:
                lines, rotated = tail.read_new()
            except FileNotFoundError:
                continue
            if rotated:
                self.stats.files[key] = 0
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                self.stats.lines_read += 1
                entry = self.parser.parse_line(line)
                if entry is None:
                    # 和离线版保持同一口径：结构合法但没 IP 的行单独计数，
                    # 只有真正不认识的格式才算解析失败。
                    if is_syslog_shaped(line):
                        self.stats.skipped_no_ip += 1
                    else:
                        self.stats.parse_errors += 1
                    continue
                self.stats.entries_parsed += 1
                if entry.ts and (
                    self.stats.last_event_ts is None
                    or entry.ts > self.stats.last_event_ts
                ):
                    self.stats.last_event_ts = entry.ts
                new_entries.append(entry)
            self.stats.files[key] = tail.offset

        self.buffer.extend(new_entries)

        findings = self._detect_content(new_entries)
        findings += self._detect_behavior()
        return findings

    # ------------------------------------------------------------------
    def _detect_content(self, entries: list[LogEntry]) -> list[Finding]:
        """内容检测只跑新进来的条目。

        这是唯一能"每条日志都跑一遍"的检测方式 —— 它是纯函数，
        一条日志只依赖自己，不依赖历史。所以既准确又不重复。
        行为检测做不到这一点，必须节流。
        """
        if not entries:
            return []
        sub = Detector(self.config)
        return [
            f for f in sub.detect(entries)
            if not f.rule_names[0].startswith("behav_")
        ]

    def _detect_behavior(self) -> list[Finding]:
        """行为检测按节流周期跑一次，每次扫最近一小段缓冲区。"""
        now = time.monotonic()
        if now - self._last_behavior_run < self.behavior_interval:
            return []
        self._last_behavior_run = now

        window = self._recent_entries()
        if len(window) < 2:
            return []

        # 只跑行为检测。内容检测已经按条跑过了，这里重跑一遍再丢掉结果是纯浪费：
        # 实测 20000 条时完整 detect 约 717ms，其中 152ms 是这部分空转。
        return Detector(self.config).detect_behavior_only(window)

    def _recent_entries(self) -> list[LogEntry]:
        """取出最近 max_window 秒内的条目，并受条数上限约束。

        不能按"最近 N 条"取：攻击暴涨时最近 1000 条可能只覆盖 10 秒，
        慢速爆破的 600 秒窗口永远凑不满。
        也不能全量扫：缓冲区跑满 20000 条时一轮要做将近 1 秒，
        2 核机器上更慢，最后读取和检测互相追尾。

        所以两头都限：先按时间取，再按条数截断。
        条数截断取"最新的那批"—— 攻击正在发生时，最新数据最重要。
        """
        if not self.buffer:
            return []
        latest = max((e.ts for e in self.buffer if e.ts), default=None)
        if latest is None:
            return list(self.buffer)[-self.config.behavior_max_window_entries :]

        cutoff = latest.timestamp() - self.max_window
        recent = [e for e in self.buffer if e.ts and e.ts.timestamp() >= cutoff]
        # 兜底：过滤后太少（时钟异常、或条目全无时间戳）就退回整个缓冲区，
        # 宁可慢一点也不能因为一个坏时间戳就什么都不检测。
        if not recent:
            recent = list(self.buffer)
        return recent[-self.config.behavior_max_window_entries :]

    # ------------------------------------------------------------------
    @staticmethod
    def _throttle_key(f: Finding) -> tuple:
        """抑制键的作用范围要拿捏。

        只用规则名 + IP：同一 IP 的持续攻击只报一次 → 合理。
        再加分类：区分"同一 IP 同时触发了 SQLi 和目录扫描" → 必要。
        不加 path：攻击者换个路径是同一件事的继续，
        按路径分开会让一次目录爆破刷出几百条告警。
        不加时间：时间维度由 TTL 负责，键里再塞时间等于取消抑制。
        """
        return (f.rule_names[0], f.category, f.ip)

    def _apply_throttle(self, findings: list[Finding]) -> list[Finding]:
        out: list[Finding] = []
        now = time.monotonic()
        for f in findings:
            # 第一道：完全相同的告警（同规则 + 同 IP + 同事件时间）说明
            # 只是又扫了一遍同一段历史，不是新命中。静默丢掉，**不计数**。
            exact = (self._throttle_key(f), f.ts)
            if exact in self._emitted:
                continue
            self._emitted[exact] = now

            # 第二道：同类告警在 TTL 窗口内只推一条，但这一次是真的新命中，
            # 所以要记进 suppressed_total。
            ok, suppressed = self._throttle.check(self._throttle_key(f), now)
            if not ok:
                self.stats.suppressed_total += 1
                continue
            if suppressed:
                # 把被压掉的次数写进判定依据，让人知道这不是孤立事件
                f.reason += f"（抑制窗口内另有 {suppressed} 次同类命中）"
            out.append(f)
        self.stats.findings_total += len(out)
        return out

    # ------------------------------------------------------------------
    def run(self, on_finding=None, stop_event: threading.Event | None = None,
            interval: float = 0.5) -> None:
        """阻塞式主循环。控制台把它放进后台线程。"""
        stop_event = stop_event or threading.Event()
        last_gc = time.monotonic()
        while not stop_event.is_set():
            try:
                for f in self.poll_throttled():
                    if on_finding:
                        on_finding(f)
            except Exception as exc:  # noqa: BLE001
                # 监控线程绝不能因为单次异常退出。日志格式变了、文件权限没了，
                # 都只该让这一轮失败，下一轮还要继续试。
                # 吞异常是危险的，所以必须让它可见——静默失败的监控等于没有监控。
                print(f"[watcher] 本轮异常，已跳过：{exc!r}", flush=True)

            if time.monotonic() - last_gc > 600:
                self._throttle.gc()
                # _emitted 只按数量裁剪，**不按时间**。
                #
                # 这里踩过一次真实的坑：原本按「超过 3600 秒」清理，
                # 结果在凌晨的安静时段（几个来源之间隔很久）出现了重复告警 ——
                # 同一个扫描器 04:14 报一次，05:18 又报一次，事件时间完全相同。
                #
                # 根因：_recent_entries 的时间基准是「缓冲区里最新事件的时间」，
                # 不是当前时间。安静时段没有新事件，这个基准就不动，
                # 04:14 的事件会一直留在窗口里被反复检测。
                # 而 _emitted 按首次出现时间 3600 秒后清理，
                # 一清理，同一批事件立刻又变成"新告警"。
                #
                # 所以寿命必须由缓冲区容量决定，不能由墙钟时间决定。
                # 键很小（规则+IP+时间戳），留 20 万个也只占几 MB。
                if len(self._emitted) > 200_000:
                    for k in list(self._emitted)[:50_000]:
                        self._emitted.pop(k, None)
                last_gc = time.monotonic()

            stop_event.wait(interval)

    def snapshot(self) -> dict:
        with self._lock:
            return self.stats.snapshot()

    def close(self) -> None:
        for tail in self._tails.values():
            tail.close()


__all__ = ["LogWatcher", "WatcherStats", "Severity"]
