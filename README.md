# sec_log_analyzer

基于**规则引擎 + 大模型**的 Web 日志安全分析工具。输入 nginx 访问日志或 Linux 认证日志，
输出结构化的告警与多格式报告（Markdown / HTML / CSV）。

面向的场景：中小站点没有预算上 SIEM（Splunk / ELK），但仍然需要基础的日志侧检测能力。

---

## 快速开始

### 方式一：命令行（零依赖）

检测引擎只用 Python 标准库，**不需要 pip install 任何东西**：

```bash
python -m sec_log_analyzer.cli access.log auth.log --no-ai --out reports/demo
```

输出：

```
=== access.log ===
解析 12 行，告警 8 条，耗时 2ms
  - SQL注入: 2
  - 敏感文件探测: 2
  - 扫描器指纹: 2
  - XSS: 1
  - 目录扫描: 1
报告已写入 reports/demo_access.md / .html / .csv
```

### 方式二：网页界面

```bash
pip install -r requirements.txt
streamlit run app.py
```

浏览器打开 <http://localhost:8501>，上传日志文件即可。

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

## 目录结构

```
sec_log_analyzer/
  models.py      数据结构（LogEntry / Finding / AnalysisResult）
  config.py      可调参数，密钥从环境变量读
  parser.py      nginx combined/common + syslog 解析，编码降级
  rules.py       28 条特征规则 + 归一化
  detector.py    内容检测 + 行为检测
  ai_analyst.py  大模型研判（去重/并发/重试/降级）
  reporter.py    Markdown / HTML / CSV
  pipeline.py    编排
  cli.py         命令行入口

tools/compare_old_new.py   新旧版本检测效果对比（复现 README 里的数字）
app.py                     Streamlit 界面
```

---

## 已知限制（这一节是故意写全的）

- **日志量**：目前是全量读进内存，`max_lines` 默认 20 万行。上 GB 级日志需要改成流式处理
- **检测率**：12 条自建样本上的 100% **不具统计意义**，样本天然偏向已实现的规则
- **数据集**：仓库里的 `access.log` / `auth.log` 是**按攻击特征构造的模拟日志**，
  不是真实服务器流量。构造原因是公开的脱敏日志集很难拿到，且需要逐条标注才能算指标
- **部署**：目前只在本地运行，未上云
- **测试**：还没有单元测试（该补的是误报回归与漏报回归两类）
- **告警关联**：不做跨日志源关联，只做单文件内的行为聚合

---

## 环境

- Python 3.10+（用到 `X | None` 语法和 `dataclass(slots=True)`）
- 已在 3.12 / 3.13 上验证核心引擎可运行
- 界面层需要 `streamlit`
