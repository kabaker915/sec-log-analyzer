import re
from datetime import datetime
from collections import deque

sqli = re.compile(r"(union\s+select|or\s+['\"]?1['\"]?=1|--|')", re.IGNORECASE)
xss = re.compile(r"(<script>|alert\(|onerror=)", re.IGNORECASE)

w = 60
th = 3
ip_404 = {}
alerted = set()


def chk(f):
    # 打开报告文件准备写入
    with open('web_report.txt', 'w', encoding='utf-8') as report:
        report.write("=== Web 日志安全分析报告 ===\n\n")

        with open(f, 'r', encoding='utf-8') as file:
            for l in file:
                p = l.split()
                if not p: continue
                ip = p[0]

                if sqli.search(l):
                    report.write(f"[WARN] 发现SQL注入! IP: {ip}\n")
                    report.write(f" 日志: {l.strip()}\n\n")
                    continue
                elif xss.search(l):
                    report.write(f"[WARN] 发现XSS! IP: {ip}\n")
                    report.write(f" 日志: {l.strip()}\n\n")
                    continue

                if " 404 " in l:
                    m_t = re.search(r"\[(.*?)\]", l)
                    if not m_t: continue
                    t = datetime.strptime(m_t.group(1), '%d/%b/%Y:%H:%M:%S')

                    if ip not in ip_404:
                        ip_404[ip] = deque()
                    q = ip_404[ip]
                    q.append(t)

                    while q and (t - q[0]).seconds > w:
                        q.popleft()

                    if len(q) >= th and ip not in alerted:
                        report.write(f"[ALERT] 发现目录扫描! IP: {ip} 在{w}秒内触发了{len(q)}次404\n\n")
                        alerted.add(ip)


if __name__ == "__main__":
    chk('access.log')
    print("分析完毕，结果已写入 web_report.txt")