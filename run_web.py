"""兼容入口：等价于 `python run.py --console on`。

保留这个文件是因为服务器的 systemd 指向它。
新代码请直接用 run.py，它支持 --console off（只检测、不开端口）。
"""

from __future__ import annotations

import sys

from run import main


if __name__ == "__main__":
    # 强制控制台模式：这个文件存在的意义就是起控制台
    raise SystemExit(main(["--console", "on"] + sys.argv[1:]))
