"""日志路径解析：展开通配符、目录，按修改时间排序。

为什么放在引擎层而不是 webapp 层：
  run.py 的无控制台模式也要用，而那个模式**不该依赖 Flask**。
  之前这段逻辑只写在 webapp/create_app 里，结果是
  `run.py --console off --log "archive/*.log"` 直接把带星号的字符串
  丢给 LogWatcher，然后报"文件不存在"——文件明明就在那儿。

  同一件事有两处实现，早晚只修一处。所以抽出来，两边共用。
"""

from __future__ import annotations

import glob as _glob
import os
from pathlib import Path


def expand_log_paths(patterns: list[str], *, skip_gz: bool = True,
                     quiet: bool = False) -> list[str]:
    """把命令行传入的路径展开成实际文件列表，按修改时间旧→新排序。

    三种输入都支持：
      * 普通路径   /var/log/nginx/access.log
      * 通配符     /var/log/nginx/access.log*        （含 .1、.2.gz）
      * 目录       /var/log/nginx                    （目录下所有 .log*）

    **必须自己展开，不能指望 shell**：
      bash 会把 `*.log` 展开再传给程序；PowerShell / cmd **不会**，
      它把 `archive\\access-*.log` 原样传进来。程序如果不展开，
      就会去找一个名字里带星号的文件，然后报"不存在"。

    排序方向很重要：必须旧文件先读。反过来的话，缓冲区里时间最新的
    反而在最后，行为检测的窗口基准会错。

    .gz 默认跳过：压缩文件不能增量跟随（读到底就判断不了有没有新内容），
    历史 .gz 属于离线分析，交给 CLI 单独处理。
    """
    out: list[tuple[float, str]] = []

    for pattern in patterns:
        p = Path(pattern)

        if p.is_dir():
            matches = [str(x) for x in p.glob("*.log*")]
        elif any(c in pattern for c in "*?["):
            matches = _glob.glob(pattern)
        else:
            matches = [pattern]

        # 通配符一个都没匹配到：把原模式传下去，
        # 让上层报"文件不存在：archive\access-*.log"，用户能看懂自己写错了什么
        if not matches:
            out.append((0.0, pattern))
            continue

        for m in matches:
            if skip_gz and m.endswith(".gz"):
                if not quiet:
                    print(f"[跳过] {m} 是压缩文件，历史 .gz 请用 CLI 离线分析", flush=True)
                continue
            if not Path(m).exists():
                continue
            try:
                out.append((os.path.getmtime(m), m))
            except OSError:
                out.append((0.0, m))

    out.sort(key=lambda x: x[0])
    result = [m for _, m in out]
    return result or list(patterns)


__all__ = ["expand_log_paths"]
