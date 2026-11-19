"""给 nginx 加蜜罐诱饵的精确匹配放行。

为什么需要这一步
----------------
前面为了加固，加了：
    location ~ /\\.       { deny all; }     # 点文件全拒
    location ~* \\.(zip)$ { deny all; }     # 压缩包全拒

诱饵恰好就是 .env、.aws/credentials、backup.zip —— 全被拒了。

nginx 的 location 优先级：
    = 精确匹配   >  ^~ 前缀   >  ~ 正则   >  普通前缀
所以只要写 location = /.env，它的优先级就高于 location ~ /\\.，
正则那一条根本不会被评估。

这是个真实的设计冲突：**加固和蜜罐在同一个位置上要求相反的行为。**
解法不是"取消防护"，而是"精确开一个小洞，其它一律继续拒"。
"""

import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

TARGET = Path("/etc/nginx/sites-enabled/default")

BLOCK = """
	# ---- 蜜罐诱饵：精确匹配优先于正则 deny，只放行这三条 ----
	# 注意：只对这三个精确路径放行，其它点文件和压缩包仍然 403。
	location = /.env             { }
	location = /.aws/credentials { }
	location = /admin/backup.zip { }
	# ---- 蜜罐诱饵结束 ----
"""


def main() -> int:
    if not TARGET.exists():
        print(f"找不到 {TARGET}", file=sys.stderr)
        return 1

    text = TARGET.read_text(encoding="utf-8")

    if "蜜罐诱饵" in text:
        print("已经加过了，跳过")
        return 0

    backup = Path(f"/root/default.bak.{datetime.now():%Y%m%d-%H%M%S}")
    shutil.copy2(TARGET, backup)
    print(f"已备份到 {backup}")

    # 插在 location / { 之前。这个块一定存在（默认站点的主 location）。
    # 放在它前面纯为了可读性；nginx 不依赖书写顺序，精确匹配天然优先。
    m = re.search(r"^\tlocation / \{", text, re.M)
    if not m:
        print("没找到 location / {，中止", file=sys.stderr)
        return 2

    text = text[:m.start()] + BLOCK.strip("\n") + "\n\n" + text[m.start():]
    TARGET.write_text(text, encoding="utf-8")
    print("配置已写入")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
