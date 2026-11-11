"""生成控制台密码哈希。

密码绝不明文落盘。用法：

    python -m webapp.hashpw

然后按提示把输出的两行环境变量写进部署环境（systemd 的 Environment= 或 .env）。

为什么不在代码里给一个默认密码（比如 admin/admin）

    默认密码是物联网设备被大规模入侵的头号原因，Mimi 僵尸网络靠它拿下了
    几十万台设备。一个安全工具自己留默认口令，是最难解释的事。
    所以没配置时生成随机密码并打印到终端，至少每次启动都不一样。
"""

from __future__ import annotations

import getpass
import sys

from .security import PBKDF2_ITERATIONS, hash_password


def main() -> int:
    pwd = getpass.getpass("设置控制台密码：")
    if len(pwd) < 12:
        print("密码太短。这个后台能看到全部攻击日志、能封禁 IP，"
              "建议至少 12 位并包含大小写数字符号。", file=sys.stderr)
        return 1
    if pwd != getpass.getpass("再输入一次："):
        print("两次输入不一致。", file=sys.stderr)
        return 1

    hashed = hash_password(pwd, iterations=PBKDF2_ITERATIONS)
    print("\n把下面两行写进部署环境（不要提交到版本库）：\n")
    print(f"CONSOLE_USER=admin")
    print(f"CONSOLE_PASSWORD_HASH={hashed}")
    print(
        "\n另外务必设置 CONSOLE_SECRET_KEY（否则每次重启都会让所有人掉线）：\n"
        "  python -c \"import secrets;print(secrets.token_hex(32))\""
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
