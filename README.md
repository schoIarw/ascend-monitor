# ascend-monitor v0.1.0 — vLLM Docker 日志监控（Go）

适用于 Ubuntu 和 CentOS 7，支持 Linux amd64/arm64。实时提取 Docker 中 vLLM Engine 的 P（输入吞吐）、G（生成吞吐）、R（执行请求）、W（等待请求）、KV（GPU KV Cache）、PC（前缀缓存）。显示本机 IP 最后两段；终端 W>0 红色高亮，W=0 绿色，重定向时自动关闭颜色。支持 stdout、MySQL 和 both；指标日志由 shell 的 `>`、`>>`、`tee` 处理，程序不在本地自动写指标文件。

## 编译与安装

Go 1.23+，可访问 Go 模块仓库的构建机器执行（生产目标机不需要 Go）：

```bash
git clone git@github.com:schoIarw/ascend-monitor.git
cd ascend-monitor
go mod download
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ascend-monitor ./cmd/ascend-monitor
sudo install -m 0755 ascend-monitor /usr/local/bin/ascend-monitor
ascend-monitor --version
```

ARM64 改为 `GOARCH=arm64`。二进制无 CGO，可以拷贝至 CentOS 7 或 Ubuntu；使用 Docker 日志采集要求本地有 Docker CLI 和容器访问权限（Docker 组通常具有 root 等价权限）。

## 常用命令

```bash
ascend-monitor                                  # 自动查找首个名称/镜像包含 ascen 的容器
ascend-monitor --container my-vllm              # 显式指定容器
ascend-monitor --match another-model            # 自定义容器匹配词
ascend-monitor --ip 192.168.10.25               # 多网卡指定业务 IP
ascend-monitor > /tmp/ascend.log                # 不带颜色的文件输出（覆盖）
ascend-monitor >> /tmp/ascend.log               # 追加输出
ascend-monitor | tee -a /tmp/ascend.log         # 同时显示和记录（无颜色）
ascend-monitor --input sample.log --follow=false
ascend-monitor --input - < sample.log
ascend-monitor --mode mysql                     # 仅写入 MySQL
ascend-monitor --mode both                      # 标准输出 + MySQL
ascend-monitor --mode both > /tmp/ascend.log     # MySQL + 文件
```

`--tail 10` 读取最近 10 行，`--follow` 默认开启；`--color auto|always|never` 可控制颜色。错误写到 stderr，需要记录时添加 `2>> /tmp/ascend-error.log`。默认 `--match ascen` 是兼容原有容器名称的匹配关键词，而非旧程序名。

## MySQL 安全配置（无明文用户名、密码环境变量）

首先由 DBA 执行 `sql/schema.sql`，创建 `ascend_monitor` 数据库及专用账号，授权该库 `SELECT, INSERT, UPDATE, CREATE`。应用首次连接时自动创建 `vllm_metrics` 表，不会自动创建库或用户。生产不要用 MySQL root 账户。

采用 AES-256-GCM：`MYSQL_USER_ENC`、`MYSQL_PASSWORD_ENC` 保存随机 nonce 加密的密文；`MYSQL_CRED_KEY_FILE` 指向本机 0600 权限的独立密钥文件。不要在代码、命令行参数、Git、进程环境中传入明文或原始密钥。密文并非可替代权限控制，同时获得密钥与密文者仍可解密。

```bash
sudo install -d -m 0700 /etc/ascend-monitor /etc/ascend-monitor/key
sudo ascend-monitor keygen --key-file /etc/ascend-monitor/key/credentials.key
sudo install -m 0600 /dev/null /etc/ascend-monitor/mysql.env
sudo sh -c 'cat > /etc/ascend-monitor/mysql.env <<"ENVEOF"
MYSQL_ADDR=db.example.com:3306
MYSQL_DATABASE=ascend_monitor
MYSQL_TLS=required
MYSQL_CRED_KEY_FILE=/etc/ascend-monitor/key/credentials.key
# MYSQL_TLS_CA_FILE=/etc/ascend-monitor/mysql-ca.pem
ENVEOF'
# 推荐在有权限的交互式 root shell 中执行以下两条，输入不回显：
ascend-monitor encrypt --key-file /etc/ascend-monitor/key/credentials.key --field user >> /etc/ascend-monitor/mysql.env
ascend-monitor encrypt --key-file /etc/ascend-monitor/key/credentials.key --field password >> /etc/ascend-monitor/mysql.env
chmod 0600 /etc/ascend-monitor/mysql.env
set -a; . /etc/ascend-monitor/mysql.env; set +a
ascend-monitor --mode both
```

加密凭据时需要有密钥文件读取权限和环境文件写权限；如果当前不是 root，可先进入受控的 root 交互式会话。**不要执行** `echo '明文密码' | ...`：会泄露到 shell 历史。密文与密钥应分开保管并安全备份。密码轮换时应替换旧的 `MYSQL_PASSWORD_ENC` 行，而不是追加同名变量。

默认 MySQL TLS 启用并验证服务端证书与主机名；内部 CA 配置 `MYSQL_TLS_CA_FILE` 指向 PEM 证书。只有明确理解风险时才设置 `MYSQL_TLS=disabled`（会在 stderr 告警）；关闭 TLS 可能泄露解密后的凭据。推荐 `MYSQL_ADDR` 使用与服务器证书匹配的 DNS 名称。

## 数据与边界

表 `ascend_monitor.vllm_metrics` 记录 Docker 日志 UTC 时间、主机名及完整/末两段 IP、容器 ID 和名称、六项指标和去重 `event_hash`。同一条带 Docker 时间戳的日志在重启回放时不会重复插入。历史文件缺少 Docker 时间戳时使用导入时刻，可能不具备跨次导入幂等性。数据库插入最多重试三次，失败将停止采集；**不具备数据库离线期间的本地持久化补偿队列**。

近一小时排队记录示例：

```sql
SELECT event_time_utc, host_ip, container_name, prompt_tps, generation_tps,
       running_reqs, waiting_reqs, gpu_kv_cache_pct, prefix_cache_hit_pct
FROM ascend_monitor.vllm_metrics
WHERE event_time_utc >= UTC_TIMESTAMP() - INTERVAL 1 HOUR
  AND waiting_reqs > 0
ORDER BY event_time_utc DESC LIMIT 100;
```

## CI 与发布

`.github/workflows/ci.yml` 对 `main` 推送、PR 和手动触发运行格式检查、`go test -race -count=1 ./...`、`go vet ./...`、CLI 样例日志验证；成功后无 CGO 交叉编译 Linux amd64/arm64，上传压缩包。首次 `main` CI 全部成功时发布 GitHub Release `v0.1.0`，附两个 tar.gz 和 SHA256SUMS；已存在则不覆盖。发布依赖仓库允许 GitHub Actions 使用 Contents 写权限。CI 编译不等于真实 MySQL 连接/证书/建表集成测试，正式生产部署仍需在有 MySQL 的现场验证。
