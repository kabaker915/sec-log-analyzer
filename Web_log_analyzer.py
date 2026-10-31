import re

# 1. 定义标准正则（忽略大小写）
# SQL注入：联合查询、or 1=1、注释符、单引号
sqli = re.compile(r"(union\s+select|or\s+['\"]?1['\"]?=1|--|')", re.IGNORECASE)
# XSS：script标签、alert弹窗、onerror事件
xss = re.compile(r"(<script>|alert\(|onerror=)", re.IGNORECASE)


# 函数名极简为 chk (check)
def chk(f):
    print(f"=== 开始分析: {f} ===\n")

    # 读取文件
    with open(f, 'r', encoding='utf-8') as file:
        for l in file:
            p = l.split()  # p 代表切分后的列表
            if not p:
                continue
            ip = p[0]  # 第一列是IP

            # 开始匹配
            if sqli.search(l):
                print(f"[WARN] 发现SQL注入! IP: {ip}")
                print(f" 日志: {l.strip()}\n")

            elif xss.search(l):
                print(f"[WARN] 发现XSS! IP: {ip}")
                print(f" 日志: {l.strip()}\n")


if __name__ == "__main__":
    chk('access.log')