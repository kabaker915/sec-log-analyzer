#!/usr/bin/env bash
# 本机演示验证：直接用脱敏样例日志跑起来，确认打开页面就能看到历史告警。
# 之所以写成脚本而不是一行命令：`cd a && b && python x &` 会把整条链
# 丢进后台子 shell，主 shell 的 cwd 不会变，后面的相对路径全部失效。
set -u
cd /e/sec-log-analyzer

export NO_PROXY="127.0.0.1,localhost"
export no_proxy="127.0.0.1,localhost"
export CONSOLE_USER=admin
export CONSOLE_SECRET_KEY="$(cat reports/web/.secret)"
export CONSOLE_PASSWORD_HASH="$(./.venv/Scripts/python.exe -c \
  'from webapp.security import hash_password;print(hash_password("TestPass!2026",iterations=1000))')"

PORT=${1:-8096}
W=reports/web
mkdir -p "$W"
rm -f "$W/cj_demo.txt"

./.venv/Scripts/python.exe run_web.py \
  --log samples/access_2026-11-11.sample.log \
  --log samples/auth_2026-11-11.sample.log \
  --port "$PORT" --from-start > "$W/demo.out" 2>&1 &
SRV=$!
sleep 6

TOKEN=$(curl -s --noproxy '*' -c "$W/cj_demo.txt" "http://127.0.0.1:$PORT/login" \
  | grep -oE 'name="csrf_token" value="[^"]+"' | sed 's/.*value="//;s/"//')
CODE=$(curl -s --noproxy '*' -b "$W/cj_demo.txt" -c "$W/cj_demo.txt" -o /dev/null -w '%{http_code}' \
  -d "username=admin&password=TestPass!2026&csrf_token=$TOKEN" "http://127.0.0.1:$PORT/login")
echo "登录: $CODE"

echo "历史告警条数: $(curl -s --noproxy '*' -b "$W/cj_demo.txt" \
  "http://127.0.0.1:$PORT/api/findings?limit=300" | grep -o '"uid"' | wc -l)"

echo "--- 统计 ---"
curl -s --noproxy '*' -b "$W/cj_demo.txt" "http://127.0.0.1:$PORT/api/stats"
echo

echo "--- 严重级告警示例 ---"
curl -s --noproxy '*' -b "$W/cj_demo.txt" \
  "http://127.0.0.1:$PORT/api/findings?limit=300&severity=critical" | head -c 500
echo

kill $SRV 2>/dev/null
wait $SRV 2>/dev/null
echo "[已停止]"
