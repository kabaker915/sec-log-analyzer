"""演示 dict -> JSON 字符串 -> bytes 三步，以及为什么需要 encode。

运行：.venv\\Scripts\\python.exe tools\\02_bytes_demo.py
"""

import json

data = {"model": "deepseek-chat", "messages": [{"role": "user", "content": "分析这条日志"}]}

step2 = json.dumps(data)
step3 = step2.encode("utf-8")

print("dict   ->", type(data).__name__)
print("dumps  ->", type(step2).__name__)
print("encode ->", type(step3).__name__)

print("\ndumps 之后的中文变成：")
print(" ", step2[step2.find("content"):][:40])

print("\n长度对比：")
print("  字符串长度 =", len(step2), "（按字符数）")
print("  字节长度   =", len(step3), "（按字节数，中文一个字符占 3 字节）")
