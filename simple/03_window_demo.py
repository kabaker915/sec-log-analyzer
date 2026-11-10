"""滑动窗口（双指针）演示：把 _first_window_hit 的逻辑画出来看。

运行：
    python simple/03_window_demo.py

场景：8 条日志，时间分别是第 0、10、20、30、40、50、60、70 秒。
判断：60 秒窗口内有没有出现 5 条以上记录。
"""

TIMES = [0, 10, 20, 30, 40, 50, 60, 70]
WINDOW = 60
THRESHOLD = 5

print(f"日志时间点（秒）: {TIMES}")
print(f"窗口长度: {WINDOW} 秒    告警阈值: 窗口内 >= {THRESHOLD} 条\n")
print(f"{'step':<5}{'right':<7}{'cur':<6}{'窗口内的时间点':<28}{'left':<6}{'条数':<6}{'判定'}")
print("-" * 74)

left = 0
left_moves = 0
first_hit = None

for right, cur in enumerate(TIMES):
    # 窗口右端走到 cur，左端一直往前追，直到窗口跨度不超过 WINDOW
    while cur - TIMES[left] > WINDOW:
        left += 1
        left_moves += 1

    window = TIMES[left : right + 1]
    hit = len(window) >= THRESHOLD and first_hit is None
    if hit:
        first_hit = (len(window), cur)

    print(f"{right:<5}{right:<7}{cur:<6}{str(window):<28}{left:<6}{len(window):<6}"
          f"{'← 触发告警' if hit else ''}")

print("-" * 74)
print(f"right 前进了 {len(TIMES)} 次，left 前进了 {left_moves} 次")
print(f"总操作次数 ≈ {len(TIMES) + left_moves}，也就是 O(2n) → 记作 O(n)")
print()
if first_hit:
    print(f"第一次触发：第 {first_hit[1]} 秒时，窗口内有 {first_hit[0]} 条")
else:
    print("没有触发")
