#!/usr/bin/env bash
# 上传前的脱敏校验。
#
# 为什么单独写一个脚本：靠肉眼看两遍是最不可靠的做法。
# 之前就发生过一次——排查换行符时用错命令，得出一堆假结论；
# 而这次要防的是"真实 IP 进了公开仓库"，出了事没法撤。
set -u
cd /e/sec-log-analyzer

FAIL=0

check() {
  local label="$1"; shift
  local hits
  hits=$("$@" 2>/dev/null)
  if [ -n "$hits" ]; then
    echo "  ✗ $label"
    echo "$hits" | head -5 | sed 's/^/      /'
    FAIL=1
  else
    echo "  ✓ $label"
  fi
}

echo "=== 服务器与个人标识 ==="
check "真实服务器 IP" grep -rn "8\.138\.184\.167" ENGINEERING.md /e/_blog/journey.md
check "家宽出口 IP"   grep -rn "218\.12\.18\.120" ENGINEERING.md /e/_blog/journey.md
check "云实例主机名"   grep -rn "iZ7xv9vv" ENGINEERING.md /e/_blog/journey.md
check "密码哈希"      grep -rn "pbkdf2_sha256\\$" ENGINEERING.md /e/_blog/journey.md
check "会话密钥"      grep -rn "CONSOLE_SECRET_KEY=" ENGINEERING.md /e/_blog/journey.md

echo
echo "=== 攻击者 IP（可能牵连第三方肉鸡主人）==="
for ip in "175.107.205.100" "66.132.195.90" "147.93.116.71" "167.94.146.56" \
          "36.137.98.30" "36.212.21.211" "118.193.58.125" "85.11.167.204"; do
  check "$ip" grep -rn -- "$ip" ENGINEERING.md /e/_blog/journey.md
done

echo
echo "=== 是否只剩文档保留网段 ==="
echo "  文档网段出现次数（应为正数，说明用了脱敏地址）:"
echo "    203.0.113.x: $(grep -c '203\.0\.113\.' ENGINEERING.md /e/_blog/journey.md 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"
echo "    198.51.100.x: $(grep -c '198\.51\.100\.' ENGINEERING.md /e/_blog/journey.md 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "结论：通过，可以上传"
else
  echo "结论：发现敏感信息，禁止上传"
fi
exit $FAIL
