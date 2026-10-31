"""Streamlit 界面 —— 只负责展示，检测逻辑全在 sec_log_analyzer 里。

这个文件刻意写得很薄：界面代码越少，越不容易出状态问题。
"""

import os

import streamlit as st

from sec_log_analyzer import Config
from sec_log_analyzer.pipeline import analyze_bytes
from sec_log_analyzer.reporter import to_csv, to_html, to_markdown

st.set_page_config(page_title="日志安全分析", page_icon="🛡️", layout="wide")
st.title("Web 日志安全分析")
st.caption("规则引擎粗筛 + 行为检测 + 大模型研判")

# ---------------------------------------------------------------- 侧边栏
with st.sidebar:
    st.header("配置")
    api_key = st.text_input(
        "DeepSeek API Key",
        type="password",
        value=os.getenv("DEEPSEEK_API_KEY", ""),
        help="留空则只做规则检测，不调用大模型",
    )
    use_ai = st.checkbox("启用 AI 研判", value=bool(api_key))
    window = st.slider("扫描检测窗口（秒）", 10, 300, 60)
    threshold = st.slider("404 触发阈值（次）", 3, 30, 8)

# ---------------------------------------------------------------- 上传
uploaded = st.file_uploader("上传 nginx access.log 或 Linux auth.log", type=["log", "txt"])

if uploaded and st.button("开始分析", type="primary"):
    config = Config.from_env()
    config.ai_api_key = api_key
    config.ai_enabled = use_ai and bool(api_key)
    config.scan_window_seconds = window
    config.scan_404_threshold = threshold

    with st.spinner("分析中…"):
        result = analyze_bytes(uploaded.getvalue(), uploaded.name, config)

    # 存进 session_state：Streamlit 每次交互都会重跑脚本，不缓存的话结果会丢
    st.session_state["result"] = result

result = st.session_state.get("result")
if result is None:
    st.info("上传日志文件后开始分析。核心引擎零依赖，不配置 API Key 也能正常工作。")
    st.stop()

# ---------------------------------------------------------------- 概览
c1, c2, c3, c4 = st.columns(4)
c1.metric("解析行数", len(result.entries))
c2.metric("告警数", len(result.findings))
c3.metric("解析失败", len(result.parse_errors))
c4.metric("耗时", f"{result.elapsed_ms} ms")

by_category = result.count_by(lambda f: f.category)
if by_category:
    st.subheader("告警分布")
    st.bar_chart(dict(by_category))

# ---------------------------------------------------------------- 明细
if result.findings:
    st.subheader("告警明细")
    st.dataframe(
        [
            {
                "时间": f.ts.strftime("%Y-%m-%d %H:%M:%S") if f.ts else "",
                "来源 IP": f.ip,
                "类型": f.category,
                "等级": f.severity.value,
                "评分": f.score,
                "请求": f.entry.path,
                "判定依据": f.reason,
            }
            for f in result.findings
        ],
        use_container_width=True,
        hide_index=True,
    )

    for f in result.findings[:20]:
        with st.expander(f"{f.category} · {f.ip} · {f.entry.path}"):
            st.code(f.entry.raw, language="text")
            st.write(f"**判定依据**：{f.reason}")
            if f.ai_comment:
                st.info(f.ai_comment)
else:
    st.success("未发现异常行为。")

# ---------------------------------------------------------------- 导出
st.subheader("导出报告")
d1, d2, d3 = st.columns(3)
d1.download_button("Markdown", to_markdown(result), file_name="report.md")
d2.download_button("HTML", to_html(result), file_name="report.html")
d3.download_button("CSV", to_csv(result), file_name="report.csv")

for note in result.notes:
    st.caption(note)
