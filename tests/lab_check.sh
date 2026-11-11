#!/usr/bin/env bash
# 靶场自检：起靶场 -> 打一轮 -> 用检测器验结果。
# 写成脚本是因为 `cmd &` 只应作用于最后一条命令，
# 用 `a && b && python x &` 会把整条链丢进后台子 shell。
set -u
cd /e/sec-log-analyzer

PORT=8181
LOG=labs/access.log
AUTH=labs/auth.log
rm -f "$LOG" "$AUTH"

python labs/fake_site.py --port "$PORT" --log "$LOG" > labs/site.out 2>&1 &
SITE=$!
sleep 2

python labs/simulate.py --port "$PORT" --auth-log "$AUTH" 2>&1
RC=$?

sleep 1
kill $SITE 2>/dev/null
wait $SITE 2>/dev/null

echo
echo "================ 检测结果 ================"
./.venv/Scripts/python.exe -m sec_log_analyzer.cli "$LOG" "$AUTH" --out /tmp/lab --no-ai 2>&1 | head -20

echo
echo "================ 日志行数 ================"
wc -l "$LOG" "$AUTH" 2>/dev/null
exit $RC
