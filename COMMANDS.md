# 命令使用说明

sec-log-analyzer 的所有入口和参数。按「要做什么」查，不用通读。

---

## 0. 准备

```powershell
cd E:\sec-log-analyzer

# 首次使用：建虚拟环境并装依赖
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

**核心引擎零依赖**，只有 Web 控制台需要 Flask。
如果只做离线分析或实时监控，可以跳过 `pip install`，直接用系统 Python。

```powershell
# 验证环境
.\.venv\Scripts\python.exe -c "import sec_log_analyzer; print('ok')"
```

---

## 1. 离线分析（最常用）

```powershell
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli <日志文件...> [选项]
```

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `files` | 必填 | 日志文件，可传多个（nginx access / Linux auth 混合也行） |
| `--out` | `report` | 输出文件名前缀，不含扩展名 |
| `--no-ai` | 关 | 只做规则检测，不调大模型。**演示和测试一律加这个** |
| `--window` | 配置值 | 404 扫描检测窗口（秒），覆盖 `scan_window_seconds` |
| `--threshold` | 配置值 | 404 触发阈值（次） |
| `--ocsf` | 关 | 额外导出一份 OCSF JSONL，可被其他 SIEM 消费 |
| `--tail` | 关 | 实时模式：持续跟随文件，边读边出告警 |
| `--from-start` | 关 | 配合 `--tail`：从文件开头读，而不是从末尾 |

### 输出

`--out reports/today` 会生成四个文件：

```
reports/today_<日志文件名>.md      Markdown 报告
reports/today_<日志文件名>.html    HTML 报告（可直接发人）
reports/today_<日志文件名>.csv     CSV，给表格用
reports/today_<日志文件名>.jsonl   仅 --ocsf 时生成（OCSF 格式）
```

### 常用组合

```powershell
# 分析单个文件
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli archive\access-2026-11-19.log --no-ai --out reports\today

# 两个文件一起（access + auth）
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli archive\access.log archive\auth.log --no-ai --out reports\both

# 导出 OCSF，给别的 SIEM
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli archive\access.log --no-ai --ocsf --out reports\siem

# 调扫描检测灵敏度（窗口 30 秒、阈 5 次）
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli archive\access.log --no-ai --window 30 --threshold 5
```

---

## 2. 实时监控（终端）

```powershell
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli --tail <日志> --from-start
```

告警按行打到终端，`Ctrl+C` 退出并打印统计。

| 情况 | 加不加 `--from-start` |
|---|---|
| 演示、回放已有日志 | **要加**，否则只等新行，看起来像坏了 |
| 盯着线上日志 | 不加，从文件末尾开始 |

```powershell
# 演示：先把已有告警全打出来
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli --tail archive\access-2026-11-19.log --from-start

# 线上盯梢
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli --tail /var/log/nginx/access.log
```

---

## 3. Web 控制台

统一入口是 `run.py`，`run_web.py` 是兼容别名（等价于 `--console on`）。

```powershell
.\.venv\Scripts\python.exe run.py --log <日志...> [选项]
```

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--log` | 必填 | 可重复。支持通配符 `"path/access.log*"` 和目录 |
| `--console` | 读环境变量 | `on` / `off`。**off = 只检测，不开任何端口** |
| `--host` | `127.0.0.1` | 监听地址。改成 `0.0.0.0` 会打印警告 |
| `--port` | `8080` | 端口 |
| `--live` | 关 | 生效模式：真正写 nginx deny 并重载。不加是演练模式 |
| `--no-watch` | 关 | 不起日志跟随（只看已有数据） |
| `--from-start` | 关 | 从文件开头读 |
| `--access-log` | 关 | 显示每条 HTTP 访问日志（默认关，否则刷屏） |

### 三种用法

```powershell
# ① 控制台 + 检测（默认）
.\.venv\Scripts\python.exe run.py --log "labs\access.log*" --port 8090 --from-start

# ② 只检测，不开端口（告警打到终端 / journald）
.\.venv\Scripts\python.exe run.py --log "labs\access.log*" --console off --from-start

# ③ 用环境变量控制（适合容器和 systemd）
$env:CONSOLE_ENABLED = "0"
.\.venv\Scripts\python.exe run.py --log "labs\access.log*"
```

### 环境变量

| 变量 | 取值 | 说明 |
|---|---|---|
| `CONSOLE_ENABLED` | `1/0`、`on/off`、`true/false` | 控制台开关。优先级低于 `--console` |

> 解析用白名单，不是 `bool()`。`bool("0")` 是 `True`，这是经典陷阱。

### 登录

首次启动会打印临时口令：

```
未设置 CONSOLE_PASSWORD_HASH，已生成临时密码（重启后失效）
    用户名: admin
    密  码: xxxxxxxxxxxxxxxx
```

固定口令要生成哈希写进环境变量：

```powershell
.\.venv\Scripts\python.exe -m webapp.hashpw
# 把输出写进 .env 或 CONSOLE_PASSWORD_HASH
```

---

## 4. Agent 研判

```powershell
.\.venv\Scripts\python.exe -m agents.app <chat|batch> [选项]
```

### 子命令

| 子命令 | 作用 |
|---|---|
| `chat` | 单条研判 + 追问（`为什么` / `处置步骤` / `误判风险` / `加白名单会怎样`） |
| `batch` | 批量研判，**按 IP 聚合后每个 IP 只研判一次** |

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--log` | `archive/access-2026-11-13.log` | 日志路径 |
| `--index` | `0` | `chat` 用：选第几条告警 |
| `--limit` | `10` | `batch` 用：研判前几个 IP |
| `--llm` | 关 | 用云端 DeepSeek（需 `DEEPSEEK_API_KEY`） |
| `--local` | 关 | 用本地 Ollama。**优先于 `--llm`** |
| `--model` | `qwen2.5:7b` | 本地模型名 |
| `--mode` | `auto` | `auto` / `tools` / `text`，本地模型的工具调用方式 |

### 模型选择

```powershell
# 不接模型：规则替身，不联网、不花钱、结论可复现
.\.venv\Scripts\python.exe -m agents.app chat --index 0

# 云端
$env:DEEPSEEK_API_KEY = "sk-xxx"
.\.venv\Scripts\python.exe -m agents.app chat --index 0 --llm

# 本地（需先装 Ollama 并 pull 模型）
.\.venv\Scripts\python.exe -m agents.app chat --index 0 --local

# 强制文本协议模式（小模型更稳）
.\.venv\Scripts\python.exe -m agents.app chat --index 0 --local --mode text
```

### 本地模型前置

```powershell
# 1. 自检：看硬件、看 Ollama、实测工具调用能力
.\.venv\Scripts\python.exe tools\check_local_llm.py

# 2. 拉模型（8GB 显存用 7b）
ollama pull qwen2.5:7b
```

---

## 5. 工具脚本

### 拉日志

```bash
bash tools/pull_logs.sh                        # 拉到 archive/
bash tools/pull_logs.sh E:/我要存的地方         # 指定目录
bash tools/pull_logs.sh --history              # 连轮转归档一起拉（约 9 天）
```

手敲等价的单条命令：

```bash
scp root@<服务器>:/var/log/nginx/access.log E:/目标目录/
```

### 规则调试（改正则时用）

```bash
.\.venv\Scripts\python.exe tools\score.py "/p?id=1' OR '1'='1"
```

输出：

```
载荷    /p?id=1' OR '1'='1
命中
  sqli_tautology   SQL注入  +10  恒真条件，绕过登录或扩大查询结果集
  sqli_quote       SQL注入  +3   引号只是弱特征：O'Brien 这类正常姓名同样带引号
SQL注入 合计 13 分 / 阈值 6 → 告警
```

改完一条规则，先用它验一遍，不用跑整个分析。

```bash
# 一次验多个
.\.venv\Scripts\python.exe tools\score.py "/.env" "/../../etc/passwd" "/?q=<script>"

# 临时换阈值看会不会告警
.\.venv\Scripts\python.exe tools\score.py --threshold 11 "/p?id=1 union select 1"
```

### 封禁建议（只打印，不执行）

```bash
.\.venv\Scripts\python.exe tools\ban_suggest.py archive\access-2026-11-13.log
.\.venv\Scripts\python.exe tools\ban_suggest.py archive\access-2026-11-13.log --min-score 10 --ttl 86400
```

> 只输出命令，不执行。自动化封禁的第一步应该是「建议」，人工确认后再落。

### 日志脱敏（公开前必做）

```bash
.\.venv\Scripts\python.exe tools\anonymize_log.py archive\access-2026-11-13.log -o samples\access-anon.log
```

| 参数 | 说明 |
|---|---|
| `-o/--out` | 输出文件，必填 |
| `--style` | `testnet`（203.0.113.x 等文档网段）或 `10net` |
| `--salt` | 区分批次，避免跨文件假名撞车 |
| `--map-out` | 额外输出映射表。**映射表能反查真实 IP，只能留本地，绝不入库** |

### 上传前检查

```bash
bash tools/precheck_public.sh
```

扫真实 IP、主机名、密码哈希、攻击者 IP。有命中就禁止上传。

### 容量测算

```bash
.\.venv\Scripts\python.exe tools\bench_capacity.py
.\.venv\Scripts\python.exe tools\bench_capacity.py --entries 2000 8000 20000
```

### 新旧版本对比

```bash
.\.venv\Scripts\python.exe tools\compare_old_new.py
```

---

## 6. 场景速查

### 「从服务器拉日志 → 分析 → 出报告」

```bash
bash tools/pull_logs.sh
.\.venv\Scripts\python.exe -m sec_log_analyzer.cli archive/access-2026-11-19-*.log --no-ai --out reports\today
```

### 「只看某个 IP 干了什么」

```bash
grep -F "1.2.3.4" archive/access-2026-11-19.log
```

### 「验证一条规则改得对不对」

```bash
.\.venv\Scripts\python.exe tools\score.py "<你要试的 payload>"
```

### 「演示：让告警一条条跳出来」

```powershell
# 窗口 1：靶场
.\.venv\Scripts\python.exe labs\fake_site.py --port 8081 --log labs\access.log
# 窗口 2：控制台
.\.venv\Scripts\python.exe run.py --log "labs\access.log*" --port 8090 --from-start
# 窗口 3：打攻击
.\.venv\Scripts\python.exe labs\simulate.py --port 8081 --auth-log labs\auth.log
```

### 「服务器上的控制台」

```powershell
ssh -N sec-console          # 开隧道，窗口别关
# 浏览器 http://127.0.0.1:8080
```

```bash
# 服务器上重载
systemctl restart sec-log-analyzer
journalctl -u sec-log-analyzer -f
```

---

## 7. 部署

```bash
# 新机器一键装
SKIP_FETCH=1 bash deploy/install.sh

# 服务管理
systemctl start|stop|restart|status sec-log-analyzer
```

systemd unit 里改控制台开关：

```ini
# 只检测，不开端口
Environment=CONSOLE_ENABLED=0
```

---

## 8. 常见报错

| 报错 | 原因 | 解决 |
|---|---|---|
| `ModuleNotFoundError: flask` | 用了系统 Python 跑控制台 | 用 `.\.venv\Scripts\python.exe` |
| `Address already in use` | 端口被占 | 换 `--port`，或 `netstat -ano \| findstr :8090` 查占用 |
| 控制台能开但页面空白 | 没加 `--from-start` | 加上，或先跑一次离线分析 |
| 拉日志 `Permission denied` | auth.log 是 640 root:adm | 用 `root@` 登录 |
| `CONSOLE_ENABLED=maybe` 被忽略 | 值不在白名单 | 用 `1/0`、`on/off`、`true/false` |
| 本地模型连不上（502） | 请求走了代理 | 代码已绕过代理；若仍报错，检查 `ollama serve` 是否在跑 |
| `nvidia-smi` 报 NVML 错误 | 驱动没加载（50 系需 572.xx+） | 重装驱动，驱动没好前不要拉大模型 |

---

## 9. 退出码

| 码 | 含义 |
|---|---|
| `0` | 正常 |
| `1` | 参数错误或文件不存在 |
| `2` | 本地模型工具调用测试未通过（`check_local_llm.py`） |
