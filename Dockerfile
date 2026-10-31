# 最小可用部署：一条命令跑起来
# 构建：docker build -t sec-log-analyzer .
# 运行：docker run -d -p 8501:8501 -e DEEPSEEK_API_KEY=sk-xxx sec-log-analyzer

FROM python:3.12-slim

WORKDIR /app

# 先只拷依赖清单，让这层能被缓存 —— 改代码时不用重装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 用非 root 用户运行。容器里跑 root 是常见的安全隐患
RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 8501

# 健康检查：容器编排时用来判断服务是否真的活着
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/healthz', timeout=3)" || exit 1

CMD ["streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0"]
