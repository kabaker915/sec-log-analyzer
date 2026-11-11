# 部署

## 一句话

代码在 GitHub，服务器 `git clone` 下来跑，**不开公网端口**，用 SSH 隧道在本地浏览器看。

## 为什么不直接开安全组端口

这个后台能看到全部攻击日志、能封禁 IP。直接暴露到公网意味着：

- 没有 HTTPS → 登录密码明文过网
- 没有反向代理限流 → 登录接口可以被无限爆破
- 没有域名和证书 → 只能裸 IP 访问，`CONSOLE_HTTPS` 也开不了

而 SSH 隧道把这三件事一次解决：流量本来就走 SSH 加密，隧道只对本机开放，关掉窗口即断。

## 步骤

### 一、服务器上执行

```bash
ssh root@<你的服务器IP>
curl -fsSL https://raw.githubusercontent.com/kabaker915/sec-log-analyzer/main/deploy/install.sh -o install.sh
bash install.sh
```

脚本做六件事：装依赖、建 `seclog` 用户（只加进 `adm` 组读日志，**不用 root 跑**）、
克隆代码、建 venv 装 Flask、生成密码哈希与会话密钥到 `/etc/sec-log-analyzer.env`（600 权限）、
装 systemd 服务并启动。

重复执行是安全的：已生成的密码和密钥不会被覆盖。

### 二、本机开隧道

```bash
ssh -N -L 8080:127.0.0.1:8080 root@<你的服务器IP>
```

这个窗口别关。想放后台：

```bash
ssh -f -N -L 8080:127.0.0.1:8080 root@<你的服务器IP>
```

### 三、浏览器打开

```
http://127.0.0.1:8080
```

用 `admin` 和 install.sh 里设的密码登录。

## 常用命令

```bash
systemctl status sec-log-analyzer        # 状态
journalctl -u sec-log-analyzer -f        # 实时日志
systemctl restart sec-log-analyzer       # 重启
```

改密码：

```bash
cd /opt/sec-log-analyzer && .venv/bin/python -m webapp.hashpw
# 把输出的 CONSOLE_PASSWORD_HASH 写进 /etc/sec-log-analyzer.env
systemctl restart sec-log-analyzer
```

## 为什么默认是演练模式

`run_web.py` 默认 `--live` 关闭：封禁只写 `data/audit.jsonl`，不碰 nginx 配置。

要真生效，需要：

1. `apply_deny_file` 写到 nginx 的 `conf.d/` 下，并在 `nginx.conf` 里 include
2. 给 `seclog` 用户对该目录的写权限
3. 让 `nginx -t` 和 `nginx -s reload` 能以 `seclog` 身份执行（sudoers 白名单，不能给全权）

**在没有 HTTPS 和反向代理的前提下不建议开。** 一个能被跨站伪造的封禁接口，
比不封禁危险得多。

## 资源占用

实测（见 `tools/bench_capacity.py`）：

| 项 | 数值 |
|---|---|
| 进程内存 | 约 50 MB（缓冲 2 万条时 47 MB + Flask 开销） |
| 最坏情况 CPU | 单核 5% 左右 |
| 磁盘 | 日志 1 MB/天，审计另计 |

2 核 4G 的机器跑这个，余量很大。

## 一个已知限制

`--live` 模式下写 nginx 配置需要额外授权。当前实现是「先写临时文件 → fsync →
`os.replace` 原子替换 → `nginx -t` → 失败则回滚 → `nginx -s reload`」，
但整个流程要求进程有权限执行 nginx 命令。用 sudoers 给白名单时，
**不要用 `NOPASSWD: ALL`**，只给 `/usr/sbin/nginx -t` 和 `/usr/sbin/nginx -s reload` 两条。
