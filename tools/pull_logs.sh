#!/usr/bin/env bash
# 从服务器拉日志到本地，按日期自动命名。
#
# 用法：
#   bash tools/pull_logs.sh                     # 拉到 archive/，只拉当前日志
#   bash tools/pull_logs.sh /e/mylogs           # 指定目录
#   bash tools/pull_logs.sh --history           # 连轮转归档一起拉（约 9 天）
#   bash tools/pull_logs.sh --history /e/mylogs
#
# 为什么用脚本而不是手敲 scp：
#   1. 文件名要带日期，手敲容易写错，写错了后面按日期筛选就全乱
#   2. 要拉的文件有固定几个，不会漏
#   3. 拉完顺便报大小，能一眼看出对不对（空文件或几字节说明有问题）
set -u

HOST="${LOG_HOST:-root@8.138.184.167}"
STAMP=$(date +%F)          # 2026-11-19
TIME_STAMP=$(date +%H%M)   # 时分，避免同一天多次拉覆盖

DEST=""
HISTORY=0
for arg in "$@"; do
  case "$arg" in
    --history) HISTORY=1 ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) DEST="$arg" ;;
  esac
done
DEST="${DEST:-archive}"

mkdir -p "$DEST" || { echo "建目录失败：$DEST"; exit 1; }

# 连通性先探一下。直接 scp 失败时报错信息很难懂（有时候只是没通网）
if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$HOST" true 2>/dev/null; then
  echo "连不上 $HOST"
  echo "检查："
  echo "  1. ssh -o BatchMode=yes $HOST true"
  echo "  2. 如果是新机器，先确认公钥已配好"
  exit 1
fi

ok=0
fail=0

pull() {
  local remote="$1" local_name="$2"
  if scp -q -o BatchMode=yes "$HOST:$remote" "$DEST/$local_name" 2>/dev/null; then
    # .gz 是二进制，对它跑 wc -l 数的是文件里的 0x0A 字节，得到的"行数"没有意义。
    # 压缩文件只报大小，要看内容得先 zcat。
    case "$local_name" in
      *.gz)
        printf "  ✓ %-34s %6s\n" "$local_name" "$(du -h "$DEST/$local_name" | cut -f1)"
        ;;
      *)
        printf "  ✓ %-34s %6s 行\n" "$local_name" "$(wc -l < "$DEST/$local_name" 2>/dev/null || echo 0)"
        ;;
    esac
    ok=$((ok + 1))
  else
    printf "  ✗ %-34s 拉取失败\n" "$local_name"
    fail=$((fail + 1))
  fi
}

echo "从 $HOST 拉日志 -> $DEST"
echo

echo "当前日志："
pull "/var/log/nginx/access.log" "access-${STAMP}-${TIME_STAMP}.log"
pull "/var/log/auth.log"         "auth-${STAMP}-${TIME_STAMP}.log"

if [ "$HISTORY" -eq 1 ]; then
  echo
  echo "轮转归档（未压缩）："
  pull "/var/log/nginx/access.log.1" "access-${STAMP}-prev.log" || true
  pull "/var/log/auth.log.1"         "auth-${STAMP}-prev.log"   || true

  echo
  echo "轮转归档（压缩，最近 8 份）："
  for i in 2 3 4 5 6 7 8; do
    pull "/var/log/nginx/access.log.${i}.gz" "access-${STAMP}-r${i}.log.gz" || true
  done
fi

echo
echo "完成：成功 $ok 个，失败 $fail 个"
[ "$fail" -gt 0 ] && echo "有失败项，先用 ssh 登上去看文件是否还存在（轮转可能把它删了）"
exit 0
