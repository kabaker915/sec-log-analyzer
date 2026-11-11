#!/usr/bin/env bash
# 在公网服务器上部署日志安全控制台。
#
# 设计原则：**不开公网端口**。
# 服务只监听 127.0.0.1，通过 SSH 隧道访问。
# 理由：这个后台能看到全部攻击日志、能封禁 IP，
# 直接暴露到公网而没有一个反向代理做 TLS 和限流，等于自己开一个靶场。
#
# 用法（在服务器上以 root 执行）：
#     bash install.sh
#
# 幂等：重复执行只会更新代码和配置，不会覆盖已生成的密码与密钥。
set -euo pipefail

APP_DIR=/opt/sec-log-analyzer
APP_USER=seclog
REPO=https://github.com/kabaker915/sec-log-analyzer.git
PORT=8080

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
say "1/6 安装系统依赖"
# python3-venv 在 Ubuntu 上默认不装，缺了会报 "ensurepip is not available"
apt-get update -qq
apt-get install -y -qq python3-venv python3-pip git >/dev/null
echo "完成"

# ---------------------------------------------------------------------------
say "2/6 创建运行用户"
# 为什么不直接用 root：
# 控制台要读 /var/log/auth.log，很多人图省事就拿 root 跑。
# 但一旦这个 Web 应用出现 RCE，攻击者直接拿到 root。
# 正确做法是建一个专用用户，只把它加进 adm 组（Ubuntu 上 /var/log 里
# 大部分日志对 adm 组可读），权限刚好够用。
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --create-home --shell /usr/sbin/nologin "$APP_USER"
    echo "已创建用户 $APP_USER"
else
    echo "用户 $APP_USER 已存在"
fi
usermod -aG adm "$APP_USER"
echo "$APP_USER 已加入 adm 组（可读 /var/log/nginx 与 auth.log）"

# ---------------------------------------------------------------------------
say "3/6 准备代码"
# 三条路径，按可靠性排序：
#   1. SKIP_FETCH=1 —— 代码已经用 scp 传上来了，直接用。
#      国内网络下 github.com 和 raw.githubusercontent.com 经常不通，
#      依赖它会让部署在第一步就卡死。这是最可靠的方式。
#   2. 已有 .git —— 从远端更新
#   3. 都没有 —— 尝试克隆（能不能成功看网络）
if [ "${SKIP_FETCH:-0}" = "1" ]; then
    if [ ! -f "$APP_DIR/run_web.py" ]; then
        echo "SKIP_FETCH=1 但 $APP_DIR 里没有代码，请先解压源码包" >&2
        exit 1
    fi
    echo "跳过拉取，使用 $APP_DIR 里已有的代码"
elif [ -d "$APP_DIR/.git" ]; then
    git -C "$APP_DIR" fetch --quiet origin main
    git -C "$APP_DIR" reset --hard --quiet origin/main
    echo "已更新到最新 main"
else
    git clone --quiet "$REPO" "$APP_DIR"
    echo "已克隆到 $APP_DIR"
fi
# 代码仓库永远不属于运行用户以外的人可写，否则运行用户可以改自己的代码
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# data/ 目录必须**提前存在**且权限正确。
# unit 里用了 ProtectSystem=strict，除 ReadWritePaths 列出的路径外全部只读；
# systemd 不会替你创建这个目录，缺了服务就起不来，
# 而且报错信息是"Read-only file system"，看着像权限问题，其实是路径不存在。
install -d -o "$APP_USER" -g "$APP_USER" -m 700 "$APP_DIR/data"

# ---------------------------------------------------------------------------
say "4/6 建立虚拟环境"
if [ ! -d "$APP_DIR/.venv" ]; then
    python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
echo "依赖安装完成"

# ---------------------------------------------------------------------------
say "5/6 生成凭据"
ENV_FILE=/etc/sec-log-analyzer.env
# 六位八进制权限：只有 root 能读。这个文件里是密码哈希和会话密钥。
umask 077

if [ ! -f "$ENV_FILE" ]; then
    SECRET=$("$APP_DIR/.venv/bin/python" -c 'import secrets;print(secrets.token_hex(32))')
    cat > "$ENV_FILE" <<EOF
CONSOLE_USER=admin
CONSOLE_SECRET_KEY=$SECRET
EOF
    echo "已生成 $ENV_FILE"
else
    echo "$ENV_FILE 已存在，保留原有密钥"
fi

# 密码哈希只生成一次。已经存在就不动 —— 重装时把人踢下线是很烦的事。
if ! grep -q '^CONSOLE_PASSWORD_HASH=' "$ENV_FILE"; then
    echo
    echo "设置控制台密码（输入时不会显示，至少 12 位）："
    # 不用 `python -m webapp.hashpw`：它内部用 getpass，
    # getpass 需要真正的终端。在脚本里、或者被管道接走时，
    # getpass 会退化或直接报错，拿到的密码是空的。
    # 所以这里由 shell 负责读，再通过 stdin 交给 Python 算哈希。
    read -rsp "  密码: " P1; echo
    read -rsp "  再输一次: " P2; echo
    if [ "${#P1}" -lt 12 ]; then
        echo "密码太短（少于 12 位），跳过。稍后手动设置：" >&2
        echo "  cd $APP_DIR && .venv/bin/python -m webapp.hashpw" >&2
    elif [ "$P1" != "$P2" ]; then
        echo "两次输入不一致，跳过。稍后手动设置。" >&2
    else
        NEW_HASH=$(cd "$APP_DIR" && printf '%s' "$P1" | \
            .venv/bin/python -c 'import sys;from webapp.security import hash_password;print(hash_password(sys.stdin.read()))')
        unset P1 P2
        echo "CONSOLE_PASSWORD_HASH=$NEW_HASH" >> "$ENV_FILE"
        echo "密码哈希已写入"
    fi
    unset P1 P2 2>/dev/null || true
fi
chmod 600 "$ENV_FILE"

# ---------------------------------------------------------------------------
say "6/6 安装 systemd 服务"
install -m 644 "$APP_DIR/deploy/sec-log-analyzer.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --quiet sec-log-analyzer
systemctl restart sec-log-analyzer
sleep 2

if systemctl is-active --quiet sec-log-analyzer; then
    echo "服务已启动"
else
    echo "服务启动失败，查看日志：" >&2
    journalctl -u sec-log-analyzer -n 30 --no-pager >&2
    exit 1
fi

cat <<EOF

================================================================
部署完成。服务只监听 127.0.0.1:$PORT，公网访问不到 —— 这是故意的。

在你自己的电脑上开一条隧道：

    ssh -N -L $PORT:127.0.0.1:$PORT root@<服务器IP>

保持那个窗口别关，然后用浏览器打开：

    http://127.0.0.1:$PORT

看服务状态：  systemctl status sec-log-analyzer
看实时日志：  journalctl -u sec-log-analyzer -f
重启服务：    systemctl restart sec-log-analyzer
改密码：      cd $APP_DIR && .venv/bin/python -m webapp.hashpw

默认是演练模式：封禁只记录，不写 nginx 配置。
真要让封禁生效，需要额外给 $APP_USER 写 nginx 配置的权限，
不建议在没有反向代理和 HTTPS 的情况下开。
================================================================
EOF
