#!/usr/bin/env bash
# 控制台端到端验证。必须在单次执行内完成：
# 后台进程会随父 shell 退出被回收，所以起服务、发请求、停服务放在同一个脚本里。
set -u
cd /e/sec-log-analyzer

export NO_PROXY="127.0.0.1,localhost"
export no_proxy="127.0.0.1,localhost"
export CONSOLE_USER=admin
export CONSOLE_SECRET_KEY="$(cat reports/web/.secret)"
export CONSOLE_PASSWORD_HASH="$(./.venv/Scripts/python.exe -c \
  'from webapp.security import hash_password;print(hash_password("TestPass!2026",iterations=1000))')"

W=reports/web
mkdir -p "$W"
: > "$W/live.log"

./.venv/Scripts/python.exe run_web.py --log "$W/live.log" --port 8099 > "$W/server.out" 2>&1 &
SRV=$!
sleep 5

rm -f "$W/cj.txt"
TOKEN=$(curl -s --noproxy '*' -c "$W/cj.txt" http://127.0.0.1:8099/login \
  | grep -oE 'name="csrf_token" value="[^"]+"' | sed 's/.*value="//;s/"//')
echo "CSRF token: ${TOKEN:0:10}..."

CODE=$(curl -s --noproxy '*' -b "$W/cj.txt" -c "$W/cj.txt" -o /dev/null -w '%{http_code}' \
  -d "username=admin&password=TestPass!2026&csrf_token=$TOKEN" http://127.0.0.1:8099/login)
echo "登录状态码: $CODE（期望 302）"

echo "--- 未登录访问 API ---"
curl -s --noproxy '*' -o /dev/null -w '  /api/findings 无 Cookie: %{http_code}（期望 401）\n' \
  http://127.0.0.1:8099/api/findings

echo "--- 写入模拟攻击（含 XSS 载荷）---"
cat >> "$W/live.log" <<'EOF'
198.51.100.66 - - [11/Nov/2026:11:00:01 +0800] "GET /?q=<img src=x onerror=alert(document.cookie)> HTTP/1.1" 200 412 "-" "Mozilla/5.0"
198.51.100.67 - - [11/Nov/2026:11:00:02 +0800] "GET /a?id=1%20union%20select%201,2,3 HTTP/1.1" 200 512 "-" "sqlmap/1.7"
198.51.100.68 - - [11/Nov/2026:11:00:03 +0800] "GET /.git/config HTTP/1.1" 404 162 "-" "Scanner/1.0"
198.51.100.69 - - [11/Nov/2026:11:00:04 +0800] "GET /x HTTP/1.1" 404 162 "-" "Mozilla/5.0"
198.51.100.70 - - [11/Nov/2026:11:00:05 +0800] "GET /y HTTP/1.1" 404 162 "-" "Mozilla/5.0"
198.51.100.71 - - [11/Nov/2026:11:00:06 +0800] "GET /z HTTP/1.1" 404 162 "-" "Mozilla/5.0"
198.51.100.72 - - [11/Nov/2026:11:00:07 +0800] "GET /w HTTP/1.1" 404 162 "-" "Mozilla/5.0"
198.51.100.73 - - [11/Nov/2026:11:00:08 +0800] "GET /v HTTP/1.1" 404 162 "-" "Mozilla/5.0"
198.51.100.74 - - [11/Nov/2026:11:00:09 +0800] "GET /u HTTP/1.1" 404 162 "-" "Mozilla/5.0"
EOF
sleep 4

echo "--- 统计 ---"
curl -s --noproxy '*' -b "$W/cj.txt" http://127.0.0.1:8099/api/stats
echo

echo "--- SSE 实时推送 ---"
timeout 3 curl -s --noproxy '*' -N -b "$W/cj.txt" "http://127.0.0.1:8099/api/stream?since=0" \
  | grep '^data:' | head -3 | cut -c1-260

echo "--- 封禁接口（带正确 CSRF）---"
CSRF2=$(curl -s --noproxy '*' -b "$W/cj.txt" http://127.0.0.1:8099/ \
  | grep -oE 'data-csrf="[^"]+"' | head -1 | sed 's/.*="//;s/"//')
echo "  页面内 CSRF: ${CSRF2:0:8}..."
curl -s --noproxy '*' -b "$W/cj.txt" -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF2" -d '{"ip":"203.0.113.77","ttl":600,"reason":"验证"}' \
  http://127.0.0.1:8099/api/ban
echo
echo "  注入型 IP:"
curl -s --noproxy '*' -b "$W/cj.txt" -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF2" -d '{"ip":"1.2.3.4; rm -rf /"}' \
  -w ' (HTTP %{http_code})\n' http://127.0.0.1:8099/api/ban

kill $SRV 2>/dev/null
wait $SRV 2>/dev/null
echo "[已停止]"
