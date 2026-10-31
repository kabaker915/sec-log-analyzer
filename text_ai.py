import json
import os
import urllib.request

# 从环境变量读取，绝不写进源码。
# 源码会被 git 记录、被打包、被截图，密钥一旦进去就再也收不回来。
# 本机临时设置：PowerShell 里 $env:DEEPSEEK_API_KEY = "sk-..."
api_key = os.getenv("DEEPSEEK_API_KEY", "")


def ask_ai(log_line):
    url = "https://api.deepseek.com/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    data = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": "你是一个专业的网络安全运营专家。"},
            {"role": "user",
             "content": f"请分析这条Web日志是否是攻击（注意时间盲注、布尔盲注等变种），并给出处置建议：\n{log_line}"}
        ],
        "temperature": 0.3
    }

    # 把字典转成 JSON 字符串，并编码
    json_data = json.dumps(data).encode('utf-8')

    # 构造请求
    req = urllib.request.Request(url, data=json_data, headers=headers, method='POST')

    try:
        # 发送请求
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result['choices'][0]['message']['content']
    except Exception as e:
        return f"请求失败: {e}"


if __name__ == "__main__":
    print("--- 测试 1：常规 SQL 注入 ---")
    print(ask_ai("10.0.0.5 - - [15/Oct/2026:10:01:01] \"GET /login.php?user=admin' OR '1'='1 HTTP/1.1\""))

    print("\n--- 测试 2：时间盲注（正则很难抓的变种）---")
    print(ask_ai(
        "10.0.0.5 - - [15/Oct/2026:10:02:01] \"GET /login.php?id=1 AND (SELECT 5 FROM (SELECT(SLEEP(5)))xyz) HTTP/1.1\""))