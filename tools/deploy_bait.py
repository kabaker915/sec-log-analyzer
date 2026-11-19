"""部署蜜罐诱饵文件。

设计原则
--------
1. **内容必须"看起来真、用起来废"**
   假的数据库密码要指向一个不存在的主机；假的 AWS AK 格式正确但无效。
   万一有人真的拿去试，也伤不到任何第三方——这是底线。
   做蜜罐不能顺便给别人挖坑。

2. **不能暴露是蜜罐**
   文件名、格式、缩进都要照真实的写。加一行 "this is a honeypot"
   就等于告诉对方别来了。

3. **监控靠访问日志，不靠文件本身**
   诱饵只是" bait"，被碰到这件事由 nginx 记录，引擎再识别。

为什么单独放 _bait/ 目录再软链/复制到位置
-----------------------------------------
方便整体删除和版本管理。放一个目录里，下次要换内容只改一处。
"""

import os
import shutil
import zipfile
from pathlib import Path

WEBROOT = Path("/var/www/html")
BAIT_SRC = WEBROOT / "_bait"

# ---------------------------------------------------------------- 假 .env
# 格式照 Laravel / Spring 的常见写法，缩进和注释都要自然
FAKE_ENV = """APP_NAME=blog
APP_ENV=production
APP_KEY=base64:Kx8vQ2mNpR7tYwZcLdFhJgSbAeUiO4Vn
APP_DEBUG=false
APP_URL=http://{host}

LOG_CHANNEL=stack
LOG_LEVEL=error

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=blog_prod
DB_USERNAME=blog_user
DB_PASSWORD=B1og@2026#Prod

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.exmail.qq.com
MAIL_PORT=465
MAIL_USERNAME=noreply@example.com
MAIL_PASSWORD=
MAIL_ENCRYPTION=ssl
"""

# ---------------------------------------------------------------- 假 AWS 凭据
# 密钥**必须运行时生成，不能写死在代码里**。
#
# 第一版把 AKIA 开头的假密钥硬编码在源码里，推送时被 GitHub Push Protection
# 拦下了 —— 它不管你是真密钥还是假密钥，只要符合 AWS 密钥格式就拒绝入库。
# 那次是被拦住了，但如果不拦，这个仓库就永久带着一段"看起来像真凭据"的字符串，
# 以后任何人 clone 下来跑 secret scanner 都会报警。
#
# 顺带一个正面收获：这说明 GitHub 的密钥扫描确实在工作（连故意放的假密钥
# 都能拦住），这是可以写进博客的真实观察。


def fake_aws_credentials() -> str:
    """生成格式正确、但一定无效的 AWS 凭据。

    AKIA 是 AWS 长周期访问密钥的固定前缀，后接 16 位大写字母数字。
    随机串拿去用只会得到 InvalidClientTokenId，伤不到任何第三方。
    """
    import secrets
    import string

    alphabet = string.ascii_uppercase + string.digits
    ak = "AKIA" + "".join(secrets.choice(alphabet) for _ in range(16))
    # secret key 是 40 位 base64 字符集
    sk = "".join(secrets.choice(string.ascii_letters + string.digits + "+/")
                 for _ in range(40))
    return (
        "[default]\n"
        f"aws_access_key_id = {ak}\n"
        f"aws_secret_access_key = {sk}\n"
        "region = ap-guangzhou\n"
    )

# ---------------------------------------------------------------- 假备份说明
# zip 里不放"真数据"，放一份看起来像导出说明的文本。
# 真有人下载解压，看到的是一份无害的文件清单。
BACKUP_README = """数据库导出说明
================
导出时间：2026-11-15 03:12:44
数据库：blog_prod
表数量：18
压缩方式：mysqldump --single-transaction | gzip

恢复命令：
  gunzip < blog_prod_20261115.sql.gz | mysql -u root -p blog_prod

注意：本文件包含用户表，请勿外传。
"""


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  ✓ {path}  ({len(content)} 字节)")


def main() -> int:
    host = os.environ.get("BAIT_HOST", "127.0.0.1")

    print("写入诱饵源文件 ...")
    write(BAIT_SRC / "env.txt", FAKE_ENV.format(host=host))
    write(BAIT_SRC / "aws_credentials.txt", fake_aws_credentials())
    write(BAIT_SRC / "backup_readme.txt", BACKUP_README)

    # 打一个真的 zip，里面只有说明文件。
    # 为什么用 zip 而不是随便一个文件：访问方会看 Content-Type 和文件头，
    # 一个不是 zip 的 .zip 会被一眼识破，那样就钓不到"会解压的人"了。
    zpath = BAIT_SRC / "backup.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", BACKUP_README)
        zf.writestr("table_list.txt", "\n".join(
            f"blog_prod.{t}" for t in (
                "users", "articles", "comments", "tags", "categories",
                "sessions", "password_resets", "failed_jobs", "migrations",
            )
        ))
    print(f"  ✓ {zpath}  ({zpath.stat().st_size} 字节)")

    print("\n投放到可访问位置 ...")
    targets = [
        (BAIT_SRC / "env.txt", WEBROOT / ".env"),
        (BAIT_SRC / "aws_credentials.txt", WEBROOT / ".aws" / "credentials"),
        (zpath, WEBROOT / "admin" / "backup.zip"),
    ]
    for src, dst in targets:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f"  ✓ {dst}")

    print("\n完成。下一步需要在 nginx 里为这三个路径加精确匹配放行。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
