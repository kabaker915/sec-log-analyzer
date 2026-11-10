import re
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

RULES = [
    (r'UNION\s+SELECT',10,'SQL注入'),
    (r'\s*script',10,'XSS'),
    (r'\.\./',10,'文件路径扫描')
]

THRESHOLD = 6

def analyze(path):
    total = 0
    alerts = []

    with open(path,encoding = 'utf-8') as f:
        for line in f:
            total += 1

            parts = line.split('"')
            payload = parts[1]

            score = 0
            category = ''

            if payload is None:
                continue

            for pattern,weight,rule_category in RULES:
                if re.search(pattern,payload,re.I):
                    score += weight
                    category = rule_category

            if score >= THRESHOLD:
                alerts.append(f'{category},{payload},')

    print(f'{payload},告警{len(alerts)}次')
    for a in alerts:
            print("",a)

if __name__ == "__main__":
    analyze(BASE / "access.log")
