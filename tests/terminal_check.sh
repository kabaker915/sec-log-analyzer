#!/usr/bin/env bash
# 验证终端只显示告警、不刷屏 HTTP 访问日志。
set -u
cd /e/sec-log-analyzer

PORT_SITE=8182
PORT_WEB=8082
LOG=labs/access_terminal.log
AUTH=labs/auth_terminal.log
rm -f "$LOG" "$AUTH" labs/web.out

export CONSOLE_USER=admin
export CONSOLE_SECRET_KEY=test-secret-terminal

python labs/fake_site.py --port "$PORT_SITE" --log "$LOG" > labs/site.out 2>&1 &
SITE=$!
sleep 2

./.venv/Scripts/python.exe run_web.py --log "$LOG" --log "$AUTH" \
  --port "$PORT_WEB" --from-start > labs/web.out 2>&1 &
WEB=$!
sleep 4

python labs/simulate.py --port "$PORT_SITE" --only normal xss sqli distributed malformed \
  --auth-log "$AUTH" 2>&1 | head -8
sleep 3

kill $WEB $SITE 2>/dev/null
wait 2>/dev/null

echo
echo "============ 控制台终端输出（前 25 行）============"
head -25 labs/web.out
echo
echo "============ HTTP 访问日志行数（应为 0）============"
grep -c 'HTTP/1.1" ' labs/web.out || true
