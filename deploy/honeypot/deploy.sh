#!/usr/bin/env bash
#
# 一键部署：nginx 站点 + 假登录页采集点
#
# 在服务器上以 root 运行：
#   bash deploy.sh
#
# 脚本做的事：
#   1. 检查 Docker 是否可用
#   2. 配置国内镜像加速（不配的话拉镜像会超时）
#   3. 创建日志目录并设置权限
#   4. 启动容器
#   5. 自检：本地 curl 首页和登录页，确认两个都能返回 200/401
#
# 幂等：可以重复执行，已存在的容器会被重建。

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/honeypot}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. 环境检查
# ---------------------------------------------------------------------------
info "检查 Docker"
command -v docker >/dev/null 2>&1 || die "未找到 docker，请先在控制台选择预装 Docker 的镜像"

if ! docker compose version >/dev/null 2>&1; then
    die "未找到 docker compose 插件。尝试：apt update && apt install -y docker-compose-plugin"
fi

if ! docker info >/dev/null 2>&1; then
    die "Docker 守护进程未运行。尝试：systemctl start docker"
fi

info "检查端口 80 是否被占用"
if ss -lntp 2>/dev/null | grep -q ':80 '; then
    warn "端口 80 已被占用，可能是预装的 nginx 或 httpd"
    warn "查看占用进程： ss -lntp | grep :80"
    warn "若确认是系统 nginx，停止它： systemctl disable --now nginx"
    read -r -p "继续部署会启动失败，是否仍然继续？[y/N] " ans
    [[ "${ans,,}" == "y" ]] || exit 1
fi

# ---------------------------------------------------------------------------
# 2. 镜像加速
# 国内拉 Docker Hub 经常超时。用阿里云自己的镜像地址最稳，
# 因为你在阿里云的机器上，内网直连。
# 如果这段地址失效，脚本不会中断，只是拉镜像可能会慢。
# ---------------------------------------------------------------------------
if [[ ! -f /etc/docker/daemon.json ]]; then
    info "配置镜像加速"
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<'JSON'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://dockerproxy.com",
    "https://docker.nju.edu.cn"
  ],
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
JSON
    systemctl restart docker
    sleep 3
fi

# ---------------------------------------------------------------------------
# 3. 部署目录
# 把仓库里的 deploy/honeypot 复制到 /opt/honeypot，之后在那边维护
# ---------------------------------------------------------------------------
info "准备部署目录 $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$REPO_DIR"/. "$APP_DIR"/
mkdir -p "$APP_DIR/logs/nginx" "$APP_DIR/logs/login"

# 日志目录权限：容器内 nginx 以 nginx 用户跑，php 以 www-data 跑
# 这里放宽到 0770，组内可写即可。注意别用 0777。
chown -R 1000:1000 "$APP_DIR/logs" 2>/dev/null || true
chmod -R 0770 "$APP_DIR/logs"

# ---------------------------------------------------------------------------
# 4. 启动
# ---------------------------------------------------------------------------
cd "$APP_DIR"
info "拉取镜像（首次约 1-3 分钟）"
docker compose pull

info "启动容器"
docker compose up -d --remove-orphans

# ---------------------------------------------------------------------------
# 5. 自检
# ---------------------------------------------------------------------------
info "等待服务就绪"
for i in $(seq 1 20); do
    if curl -fsS -o /dev/null "http://127.0.0.1/" 2>/dev/null; then
        break
    fi
    sleep 1
done

echo
info "=== 自检结果 ==="

code_home=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/" || echo "000")
if [[ "$code_home" == "200" ]]; then
    info "首页        HTTP $code_home  ✓"
else
    warn "首页        HTTP $code_home  ✗  查看：docker compose logs web"
fi

# 登录页故意返回 401，所以这里期望 401 而不是 200
code_login=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/admin/login.php" || echo "000")
if [[ "$code_login" == "401" ]]; then
    info "登录页      HTTP $code_login  ✓（401 是预期行为）"
else
    warn "登录页      HTTP $code_login  ✗  期望 401"
fi

# 手动发一条假爆破请求，确认日志真的写进去了
info "写入测试记录"
curl -s -o /dev/null -X POST "http://127.0.0.1/admin/login.php" \
    -d 'username=test_probe&password=probe123' || true
sleep 1

if [[ -s "$APP_DIR/logs/login/credential.log" ]]; then
    info "凭据日志    ✓ 已写入"
    tail -n 1 "$APP_DIR/logs/login/credential.log"
else
    warn "凭据日志    ✗ 为空，检查 PHP 容器日志：docker compose logs login"
fi

echo
info "=== 部署完成 ==="
echo "  站点目录   $APP_DIR/site"
echo "  访问日志   $APP_DIR/logs/nginx/access.log"
echo "  凭据日志   $APP_DIR/logs/login/credential.log"
echo
echo "  浏览器访问： http://$(curl -s --max-time 3 ifconfig.me || echo '你的公网IP')/"
echo
echo "  注意：如果浏览器打不开但 curl 正常，是安全组没放行 80 端口。"
echo
