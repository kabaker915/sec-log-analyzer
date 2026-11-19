"""给 nginx 默认站点加安全配置。

为什么用脚本改而不是 sed：
  sed 处理多行插入时的转义很容易出错（tab、引号、反斜杠），
  改错了 nginx -t 会报错，但定位是哪一行错了很麻烦。
  用 Python 按行处理，插入位置明确，出错也能看清楚。

做四件事：
  1. 隐藏 nginx 版本号
  2. 加三个安全响应头
  3. 拒绝访问点开头的文件（.env / .git / .htaccess）
  4. 拒绝访问备份和日志类文件

3 和 4 现在还用不上（文档根里只有一个默认页），
但先放上去：将来把应用挂到 nginx 上时，这两个 location 就成了第一道防线。
"""

import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

TARGET = Path("/etc/nginx/sites-enabled/default")

BLOCK = """
	# ---- 安全配置（自动添加）----
	# 隐藏版本号：Server 头暴露 nginx/1.18.0 等于告诉攻击者查哪个 CVE
	server_tokens off;

	add_header X-Frame-Options "SAMEORIGIN" always;
	add_header X-Content-Type-Options "nosniff" always;
	add_header Referrer-Policy "no-referrer" always;

	# 点开头的文件永远不该被访问：.env 有数据库密码，.git 有全部源码
	location ~ /\\. {
		deny all;
	}

	# 备份、日志、SQL 导出：上线时最容易忘在目录里的东西
	location ~* \\.(bak|old|orig|swp|sql|zip|tar|gz|log)$ {
		deny all;
	}
	# ---- 安全配置结束 ----
"""


def main() -> int:
    if not TARGET.exists():
        print(f"找不到 {TARGET}", file=sys.stderr)
        return 1

    text = TARGET.read_text(encoding="utf-8")

    if "安全配置（自动添加）" in text:
        print("已经加过了，跳过")
        return 0

    # 备份。改 nginx 配置前不备份是坏习惯——
    # 配错了站点直接起不来，而这是台跑着服务的机器。
    backup = TARGET.with_suffix(f".bak.{datetime.now():%Y%m%d-%H%M%S}")
    shutil.copy2(TARGET, backup)
    print(f"已备份到 {backup}")

    # 插在 server_name 那一行之后。默认配置里 server_name _; 一定存在，
    # 而它之后、location / 之前是安全配置最合适的位置。
    m = re.search(r"^(\s*server_name\s+[^;]+;)\s*$", text, re.M)
    if not m:
        print("没找到 server_name 行，中止（不改没把握的地方）", file=sys.stderr)
        return 2

    insert_at = m.end()
    new_text = text[:insert_at] + "\n" + BLOCK + text[insert_at:]
    TARGET.write_text(new_text, encoding="utf-8")
    print("配置已写入")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
