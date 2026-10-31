import re
from datetime import datetime
from collections import deque

WINDOW = 60
THRESHOLD = 2

ip_windows = {}
alerted = set()

with open('auth.log', encoding='utf-8') as f, \
     open('report.txt', 'w', encoding='utf-8') as report:

    report.write(f"=== SSH 暴力检测报告 ===\n")
    report.write(f"窗口: {WINDOW} 秒, 阈值: {THRESHOLD} 次\n")
    report.write("-" * 40 + "\n\n")

    for line in f:
        if 'Failed password' not in line:
            continue

        m_ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if not m_ip:
            continue
        ip = m_ip.group(1)

        ts_str = line[:15]
        t = datetime.strptime(ts_str, '%b %d %H:%M:%S')

        if ip not in ip_windows:
            ip_windows[ip] = deque()

        q = ip_windows[ip]
        q.append(t)

        while q and (t - q[0]).seconds > WINDOW:
            q.popleft()

        if len(q) >= THRESHOLD and ip not in alerted:
            report.write(f"[ALERT] {ip} 在 {WINDOW} 秒内失败 {len(q)} 次\n")
            report.write(f"        窗口起始: {q[0]}\n")
            report.write(f"        最新时间: {q[-1]}\n")
            report.write("-" * 40 + "\n\n")
            alerted.add(ip)

    print('报告写入完毕')