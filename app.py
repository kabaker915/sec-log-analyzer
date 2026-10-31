import streamlit as st
import re
import urllib.request
import json
from datetime import datetime
from collections import deque

# ================= 页面配置 =================
st.set_page_config(page_title="AI 智能安全分析平台", page_icon="🛡️", layout="wide")
st.title("🛡️ 智能 Web 日志安全分析平台")
st.markdown("基于规则引擎粗筛与 AI 大模型精判的安全运营工具")

# ================= 侧边栏配置 =================
st.sidebar.header("⚙️ 参数配置")
api_key = st.sidebar.text_input("DeepSeek API Key", type="password", help="请输入你的 sk- 开头的 API Key")
window = st.sidebar.slider("404 扫描检测窗口 (秒)", 10, 300, 60)
threshold = st.sidebar.slider("404 扫描触发阈值 (次)", 3, 50, 3)


# ================= 核心函数 =================
def ask_ai(log_line, attack_type, key):
    url = "https://api.deepseek.com/chat/completions"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}
    prompt = f"你是一个安全专家。我检测到一条疑似【{attack_type}】的日志，请用一段话简练分析其攻击意图，并给出1条核心处置建议。日志：\n{log_line}"
    data = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3
    }
    try:
        req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result['choices'][0]['message']['content']
    except Exception as e:
        return f"AI 研判失败: {e}"


# ================= 主界面逻辑 =================
uploaded_file = st.file_uploader("请上传 Nginx access.log 日志文件", type=["log", "txt"])

if uploaded_file is not None:
    if st.button("🚀 开始智能研判", type="primary"):
        if not api_key:
            st.error("请先在左侧侧边栏输入 DeepSeek API Key！")
            st.stop()

        sqli = re.compile(r"(union\s+select|or\s+['\"]?1['\"]?=1|--|')", re.IGNORECASE)
        xss = re.compile(r"(<script>|alert\(|onerror=)", re.IGNORECASE)
        ip_404, alerted = {}, set()

        results = []
        lines = uploaded_file.getvalue().decode("utf-8").splitlines()

        progress_bar = st.progress(0)
        status_text = st.empty()

        for i, line in enumerate(lines):
            status_text.text(f"正在分析第 {i + 1}/{len(lines)} 行...")
            progress_bar.progress((i + 1) / len(lines))

            if not line.strip(): continue
            ip = line.split()[0]
            attack_type = None

            # 规则检测
            if sqli.search(line):
                attack_type = "SQL注入"
            elif xss.search(line):
                attack_type = "XSS攻击"

            if " 404 " in line:
                m_t = re.search(r"\[(.*?)\]", line)
                if m_t:
                    t = datetime.strptime(m_t.group(1), '%d/%b/%Y:%H:%M:%S')
                    if ip not in ip_404: ip_404[ip] = deque()
                    q = ip_404[ip]
                    q.append(t)
                    while q and (t - q[0]).seconds > window: q.popleft()
                    if len(q) >= threshold and ip not in alerted:
                        attack_type = "目录扫描"
                        alerted.add(ip)

            # 如果命中规则，调用 AI
            if attack_type:
                ai_advice = ask_ai(line.strip(), attack_type, api_key)
                results.append({
                    "IP": ip,
                    "攻击类型": attack_type,
                    "原始日志": line.strip(),
                    "AI 研判建议": ai_advice
                })

        status_text.success("✅ 分析完成！")

        # 展示结果
        if results:
            st.warning(f"检测到 {len(results)} 条高危行为！")
            for res in results:
                with st.expander(f"🚨 {res['攻击类型']} - 来源 IP: {res['IP']}"):
                    st.code(res['原始日志'], language="text")
                    st.info(f"**AI 研判建议：**\n\n{res['AI 研判建议']}")
        else:
            st.success("🎉 未发现异常行为，系统安全。")