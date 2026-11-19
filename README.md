# sec_log_analyzer

基于**规则引擎 + 大模型**的 Web 日志安全分析工具。输入 nginx 访问日志或 Linux 认证日志，
输出结构化的告警与多格式报告（Markdown / HTML / CSV）。

面向的场景：中小站点没有预算上 SIEM（Splunk / ELK），但仍然需要基础的日志侧检测能力。

---

所有入口和参数的完整说明见 **[COMMANDS.md](COMMANDS.md)**。

## 目录结构

```
sec-log-analyzer/
├── sec_log_analyzer/     核心引擎：解析 / 规则 / 检测 / 实时跟随 / OCSF 导出
│                         零第三方依赖，命令行版只靠标准库
├── webapp/               Web 控制台：Flask 应用、状态管理、鉴权与安全原语
├── agents/               告警研判 Agent：工具集、循环、本地/云端模型适配
├── static/ templates/    前端资源（Flask 默认查找路径，不要移动）
│
├── run_web.py            Web 入口（systemd 引用此路径，不要改名）
│
├── tests/                测试：Web 安全（44 项）、Agent（20 项）、靶场自检
├── tools/                脚本：脱敏、容量测算、评分、公开前检查、本地模型自检
├── bench/                评测：语料生成、误报漏报评估
├── labs/                 靶场：手写 socket 服务器 + 9 类攻击模拟
├── samples/              脱敏后的日志样本（可公开）
├── deploy/               部署：systemd unit、安装脚本、蜜罐环境
├── examples/             早期练习与历史入口（不参与运行）
│
├── archive/              [不入库] 从服务器拉回的真实日志
├── reports/              [不入库] 生成的报告与中间产物
└── data/                 [不入库] 控制台状态：审计日志、封禁记录、告警落盘
```

三条边界：

- **核心引擎零依赖**：删掉 `webapp/`、`static/`、`templates/`、`run_web.py`，
  剩下的仍然是完整的命令行工具。
- **真实数据不入库**：`archive/` `reports/` `data/` 都在 `.gitignore` 里。
  要公开日志必须先跑 `tools/anonymize_log.py` 脱敏到 `samples/`。
- **`examples/` 不参与运行**：里面是早期 Streamlit 入口和练习脚本，
  保留是为了可追溯，删掉不影响任何功能。


## 快速开始

### 方式一：命令行（零依赖）

检测引擎只用 Python 标准库，**不需要 pip install 任何东西**：

```bash
python -m sec_log_analyzer.cli samples/access_2026-10-15.synthetic.log samples/auth_2026-10-15.synthetic.log --no-ai --out reports/demo
```

输出：

```
=== access_2026-10-15.synthetic.log ===
解析 12 行，告警 8 条，耗时 2ms
  - SQL注入: 2
  - 敏感文件探测: 2
  - 扫描器指纹: 2
  - XSS: 1
  - 目录扫描: 1
报告已写入 reports/demo_access.md / .html / .csv
```

### 方式二：Web 控制台

```bash
pip install -r requirements.txt     # 只有控制台需要 Flask
python run_web.py --log samples/access_2026-11-11.sample.log --port 8080 --from-start
```

浏览器打开 <http://127.0.0.1:8080>，首次启动会打印临时口令。

控制台能做：实时告警流（SSE）、按日期/等级筛选、24 小时热力图、点 IP 看时间线、按 IP 封禁（默认演练模式带 TTL）。

### 方式三：告警研判 Agent

```bash
# 单条研判 + 追问（不需要任何模型，走规则替身）
python -m agents.app chat --index 0

# 批量研判（按 IP 聚合）
python -m agents.app batch --limit 10

# 接本地模型（需先装 Ollama，见 agents/README.md）
python -m agents.app chat --index 0 --local
```

Agent 会查日志、查该 IP 全部告警、查情报、查资产，然后给结论 + 完整 trace。
不接模型也能跑——规则替身保证演示不依赖网络。

### 启用 AI 研判

```powershell
# PowerShell
$env:DEEPSEEK_API_KEY = "sk-..."
```

```bash
# bash
export DEEPSEEK_API_KEY="sk-..."
```

未配置 Key 时会自动跳过 AI，只输出规则检测结果——**AI 是增强项，不在主链路上**。

---

## 部署

### 方式一：Docker（推荐）

```bash
docker build -t sec-log-analyzer .
docker run -d --name sla -p 8501:8501 \
  -e DEEPSEEK_API_KEY=sk-xxxx \
  sec-log-analyzer
```

浏览器打开 <http://localhost:8501>。

不用 AI 就不传 `DEEPSEEK_API_KEY`，规则检测照常工作。

### 方式二：云服务器

```bash
# 1. 传代码
scp -r . user@服务器IP:/opt/sec-log-analyzer

# 2. 服务器上构建并启动
cd /opt/sec-log-analyzer
docker build -t sec-log-analyzer .
docker run -d --restart=always -p 8501:8501 \
  -e DEEPSEEK_API_KEY=sk-xxxx \
  sec-log-analyzer
```

注意两点：

- 云服务器安全组要放通 8501
- **公网部署必须加鉴权**。Streamlit 默认无登录，直接把 8501 暴露到公网等于把工具白送人。
  临时方案是用 SSH 隧道：`ssh -L 8501:127.0.0.1:8501 user@服务器IP`，
  然后本地访问 `localhost:8501`。

### 目前没做、也不打算做的

| 没做 | 原因 |
| --- | --- |
| Kubernetes / 微服务 | 单机单容器的量级，上 K8s 是自找麻烦 |
| 用户系统 / 多租户 | 定位是自用工具，不是 SaaS |
| 任务队列 / 异步分析 | 现在单文件分析在秒级，不需要 |
| 数据库 | 结果即时产出，没有历史留存需求 |

**这四条写在这里，是为了回答"为什么不做"，而不是"没想到"。**

---

## 检测能力

### 内容检测（28 条规则，加权打分）

| 类别 | 强特征示例 | 说明 |
| --- | --- | --- |
| SQL 注入 | `union select`、`sleep(`、`information_schema` | 含时间盲注、报错注入、堆叠查询 |
| XSS | `<script`、`onerror=`、`javascript:` | 含事件处理器与伪协议 |
| 命令注入 | `;cat`、`$(`、`\|\|` | 命令分隔符后接系统命令 |
| 路径穿越 | `../`、`/etc/passwd` | 区分"参数里出现"与"请求本身就是" |
| 敏感文件探测 | `/.git`、`/.env`、`wp-config.php` | 版本库、凭据、备份包 |
| WebShell | `eval(`、`system(`、`shell_exec(` | 危险函数出现在参数里 |
| Log4j | `${jndi:ldap` | CVE-2021-44228 |
| SSRF | 参数指向 `127.0.0.1` / `169.254.169.254` | 内网探测与云元数据 |
| 扫描器指纹 | sqlmap / gobuster / nikto 等 UA | 按 (IP, 工具) 去重 |

### 行为检测

| 类型 | 判定方式 |
| --- | --- |
| 目录扫描 | 滑动窗口内 404 次数 + **不同路径数**双阈值 |
| SSH 爆破 | 双层窗口：60s/3 次（快速）+ 600s/3 次（慢速） |
| 爆破成功 | 失败次数达阈值后出现成功登录 → 直接判"严重" |

---

## 三个设计取舍

### 1. 为什么用加权打分，而不是"一条正则命中就告警"

单个弱特征没有区分度。`O'Brien` 里有一个引号，`item--detail` 里有两个连字符，
按布尔判断全都会误报。

所以规则分两级：**强特征 10 分（单独即可定罪）、弱特征 3 分（必须叠加）**，
阈值 6 分。单个弱特征永远过不了线，这就是降误报的核心机制。

实测（12 条自建样本）：误报 1 → 0，召回 1/7 → 7/7。

### 2. 为什么内容检测和行为检测要同时做

- 只做内容检测：改个编码就绕过（`%27`、`UnIoN+SeLeCt`）
- 只做行为检测：一次成功的注入只有一条请求，行为上完全不异常

两者互补：前者准但可绕过，后者抗绕过但误报高。

### 3. 为什么 AI 不在主链路上

规则检测能独立得出结论，AI 只负责把结论翻译成"意图 + 影响 + 处置建议"。
AI 挂了、超时了、欠费了，报告照样出。

配套的四层加固：

| 措施 | 解决的问题 |
| --- | --- |
| 按（攻击类型 + 规则组合）去重 | 成本：200 条同类告警只调用 1 次 |
| 线程池并发（4 线程） | 速度：串行等待压到 1/N |
| 超时 + 指数退避重试 | 限流：失败后 0.5s / 1s 再试 |
| 失败降级 | 可靠性：任何异常都不影响规则结论 |

---

---

## 已知限制（这一节是故意写全的）

- **日志量**：全量读进内存，`max_lines` 默认 20 万行。上 GB 级日志需要改流式处理
- **检测率**：没有标注集，所以谈不上准确率。已有的数字（363 请求 / 67 来源 / 81 条告警）
  是观测值，不是评测结果
- **数据集**：`samples/` 是按攻击特征构造并脱敏的样本；真实流量
  来自自建公网测试机，因含真实 IP 不入库
- **跨源关联**：只做单文件内的行为聚合，不做 nginx 与 auth 的联合分析
- **Agent 评估**：20 项测试测的是边界行为，不是准确率。要说得清好坏需要人工标注集

---

## 环境

- Python 3.10+（用到 `X | None` 语法和 `dataclass(slots=True)`）
- 已在 3.12 / 3.13 上验证核心引擎可运行
- 界面层需要 `flask`（引擎本身不需要）
- 本地模型需要 `ollama`（不在 pip 体系里）
