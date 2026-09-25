# 拂尘 FlowLens POC 安装指南

> 适用版本：0.7.0
> 部署方式：Docker Compose 单机部署

本文说明如何在一台 Linux 服务器上用 Docker 安装 FlowLens，用于 POC 测试。安装包内含全部镜像，服务器不需要连接互联网。

## 1. 安装包内容

| 文件 | 说明 |
|------|------|
| `flowlens-poc-0.7.0-amd64.tar.gz` | 离线安装包（x86_64）。arm64 服务器使用 `-arm64` 版本 |
| `flowlens-poc-0.7.0-amd64.tar.gz.sha256` | 安装包校验值 |

解压后的目录：

```
flowlens-poc-0.7.0-amd64/
├── install.sh              # 安装脚本
├── flowlens-ctl.sh         # 运维脚本：启停、日志、备份、恢复、升级、卸载
├── docker-compose.yaml     # 服务编排
├── .env.example            # 配置模板，安装时生成 .env
├── conf/
│   ├── agent-config.yaml   # Agent 配置
│   └── demo-traffic.sh     # 演示流量生成器
├── images/
│   └── flowlens-images-0.7.0-amd64.tar.gz   # 全部镜像
├── docs/                   # 本文档、数据库性能说明
├── VERSION
└── SHA256SUMS              # 包内各文件的校验值
```

包含的镜像：

| 镜像 | 说明 |
|------|------|
| `flowlens-platform:0.7.0` | 平台服务（API、检测引擎、账号与审计），以非 root 用户运行 |
| `flowlens-web:0.7.0` | 控制台（nginx），以非 root 用户运行，提供 HTTP/HTTPS |
| `flowlens-agent:0.7.0` | 流量采集 Agent（网关日志模式） |
| `postgres:16-alpine` | 数据库 |

## 2. 环境要求

| 项目 | 最低 | 建议 |
|------|------|------|
| CPU | 2 核 | 4 核 |
| 内存 | 4 GB | 8 GB |
| 磁盘 | 20 GB | 100 GB SSD（审计日志至少保留 180 天） |
| 操作系统 | 64 位 Linux：CentOS 7.9+、RHEL 8+、Ubuntu 20.04+、麒麟 V10、统信 UOS 等 | |
| Docker | Docker Engine 20.10+，带 Compose v2 插件（`docker compose version` 能执行） | Docker 24+ |
| 其他 | bash、tar、gzip；启用 HTTPS 自签名证书时需要 OpenSSL 1.1.1+ | |

默认占用的端口（可在安装时修改）：

| 端口 | 用途 |
|------|------|
| 8080 | 控制台 HTTP；启用 HTTPS 后只做跳转 |
| 8443 | 控制台 HTTPS（启用 HTTPS 时） |

数据库和平台服务不对外暴露端口。外部 Agent 通过控制台端口上报数据（经 nginx 转发到平台）。

## 3. 快速安装

以下命令以 root 身份执行（或使用 docker 组的用户）。

```bash
# 1. 上传安装包到服务器后校验
sha256sum -c flowlens-poc-0.7.0-amd64.tar.gz.sha256

# 2. 解压
tar -xzf flowlens-poc-0.7.0-amd64.tar.gz
cd flowlens-poc-0.7.0-amd64

# 3. 安装并启动（附带演示流量，便于立即看到效果）
./install.sh --demo
```

安装脚本依次完成：

1. 检查 Docker、Compose、内存和磁盘空间。
2. 生成 `.env`：随机生成数据库口令、Agent 令牌和初始管理员口令。
3. 校验并加载镜像。
4. 启动服务，等待平台和控制台就绪。
5. 打印控制台地址、账号和初始口令。

安装完成时输出类似：

```
  FlowLens 0.7.0 已启动

  控制台地址    http://10.0.0.10:8080
  内置账号      sysadmin    系统管理员  -> 系统管理后台
                auditadmin  审计管理员  -> 系统管理后台
                secadmin    安全管理员  -> API 安全管理平台
  初始口令      Fl-3f9a1c0b2d4e-X9   （各账号首次登录须修改口令）
```

### 安装选项

| 选项 | 说明 |
|------|------|
| `--demo` | 启动 Agent 和演示流量生成器，不需要真实网关 |
| `--with-agent` | 启动 Agent，采集真实网关日志（见第 5 节） |
| `--seed-demo` | 向空数据库写入示例资产、告警和采集器 |
| `--https` | 启用 HTTPS，自动生成自签名证书 |
| `--cert 文件 --key 文件` | 启用 HTTPS，使用指定的证书和私钥 |
| `--host 域名或IP` | 自签名证书中包含的域名或 IP，可重复指定 |
| `--http-port 端口` / `--https-port 端口` | 修改对外端口 |
| `-y` | 不询问确认 |

示例：

```bash
# 生产网络中试用：HTTPS + 真实网关日志
./install.sh --https --host flowlens.example.com --host 10.0.0.10 --with-agent

# 80/443 端口
./install.sh --https --http-port 80 --https-port 443
```

重复执行 `install.sh` 是安全的：已有的 `.env`（口令、令牌）保持不变，只更新本次指定的选项。

### 从源码安装

在源码仓库中执行，脚本会自动从源码构建镜像：

```bash
cd deploy/poc
./install.sh --demo
```

构建需要访问 Go、npm 和 Docker Hub 镜像源。

## 4. 首次登录

在浏览器中打开控制台地址。系统没有超级管理员，三个内置账号分别对应三类管理员（三权分立）：

| 账号 | 角色 | 登录后进入 | 职责 |
|------|------|-----------|------|
| `sysadmin` | 系统管理员 | 系统管理后台 | 账号管理、角色分配、安全策略 |
| `auditadmin` | 审计管理员 | 系统管理后台 | 查看、导出、校验审计日志 |
| `secadmin` | 安全管理员 | API 安全管理平台 | 检测规则、告警处置、资产和采集器管理 |

- 三个账号使用同一个初始口令，**首次登录必须修改口令**。
- 新口令至少 8 位，包含大写字母、小写字母、数字、符号中的 3 类，不能与最近 5 次相同。
- 需要分析员（analyst）或只读（viewer）账号时，由 `sysadmin` 在系统管理后台创建。
- 初始口令只在数据库为空时生效，之后修改 `.env` 中的 `FLOWLENS_ADMIN_PASSWORD` 不起作用。

使用 `--demo` 安装时，Agent 启动后几秒内注册到平台，演示流量每秒 5 条持续上报：

- 用 `sysadmin` 登录系统管理后台，在“采集器管理”中可以看到在线的 `poc-agent-01`。
- 用 `secadmin` 登录 API 安全管理平台，在“覆盖率盲区”中可以看到采集器健康状态。

## 5. 接入真实流量

Agent 采用网关日志模式：读取 API 网关的 JSON 格式访问日志，每行一个 JSON 对象。

```json
{"request":{"method":"GET","uri":"/api/v1/users/1","host":"shop.example.com"},
 "response":{"status":200},"client_ip":"10.0.0.8","upstream_addr":"10.0.1.5:8080",
 "request_length":312,"bytes_sent":1024,"request_time":0.012,"route":{"name":"user-svc"}}
```

- 字段格式与 Kong 等网关的 JSON 日志一致。
- nginx 可以用 `log_format ... escape=json` 输出同样的结构。
- Agent 支持日志轮转（按重命名或 copytruncate 方式均可）。
- 身份证号、手机号、银行卡号和凭证类请求头在离开主机前脱敏。

### 5.1 Agent 与平台部署在同一台服务器

1. 在 `.env` 中把 `FLOWLENS_GATEWAY_LOG_DIR` 设为网关日志所在目录（目录中的文件名须为 `access.log`，或修改 `conf/agent-config.yaml` 中的 `path`）。
2. 执行：

   ```bash
   ./install.sh --with-agent
   ```

### 5.2 Agent 部署在网关服务器上

1. 把镜像包复制到网关服务器，执行 `gzip -dc flowlens-images-0.7.0-amd64.tar.gz | docker load`。
2. 复制 `conf/agent-config.yaml` 到网关服务器，修改 `management` 部分：

   ```yaml
   agent:
     id: gw-01                          # 每个 Agent 唯一
   management:
     platform_endpoint: 10.0.0.10:8443  # 控制台地址和 HTTPS 端口
     use_tls: true
     tls_ca_path: /etc/flowlens/ca.crt  # 自签名时即平台的 certs/server.crt
   ```

3. 启动 Agent。令牌取自平台 `.env` 中的 `FLOWLENS_AGENT_TOKEN`：

   ```bash
   docker run -d --name flowlens-agent --restart unless-stopped \
     -e FLOWLENS_AGENT_TOKEN=<平台 .env 中的令牌> \
     -v /path/to/agent-config.yaml:/etc/flowlens/agent-config.yaml:ro \
     -v /path/to/server.crt:/etc/flowlens/ca.crt:ro \
     -v /var/log/gateway:/var/log/gateway:ro \
     flowlens-agent:0.7.0
   ```

注意：

- 自签名证书必须包含 Agent 访问平台时使用的 IP 或域名（安装时用 `--host` 指定）。
- 控制台启用 HTTPS 后，HTTP 端口只做跳转，Agent 必须使用 HTTPS 端口。
- 未启用 HTTPS 时，Agent 可以设置 `platform_endpoint: 10.0.0.10:8080`、`use_tls: false`，但令牌和流量会明文传输，只适合隔离的测试网络。

## 6. HTTPS

- `--https` 生成有效期 825 天的自签名证书，保存在 `certs/` 目录。浏览器会提示证书不受信任，POC 中可以忽略。
- 正式环境请使用 `--cert/--key` 指定由机构 CA 签发的证书。更换证书后执行 `./flowlens-ctl.sh restart`。
- 启用 HTTPS 后：
  - HTTP 请求跳转到 HTTPS。
  - 会话 Cookie 带 Secure 标记。
  - 响应带 HSTS 头。
  - 只允许 TLS 1.2 和 1.3。
- 国密 TLS（SM2/SM4）需要基于铜锁（Tongsuo）的 nginx，例如 Tengine NTLS，本安装包未包含。

## 7. 日常运维

所有命令在安装目录中执行。

| 命令 | 说明 |
|------|------|
| `./flowlens-ctl.sh status` | 查看版本和各服务状态 |
| `./flowlens-ctl.sh logs platform -f` | 持续查看平台日志（也可以是 `web` / `postgres` / `agent`） |
| `./flowlens-ctl.sh stop` / `start` | 停止 / 启动（数据保留） |
| `./flowlens-ctl.sh restart` | 修改 `.env` 后重启使配置生效 |
| `./flowlens-ctl.sh backup` | 备份数据库到 `backups/` |
| `./flowlens-ctl.sh restore backups/xxx.dump` | 从备份恢复，覆盖现有数据 |
| `./flowlens-ctl.sh upgrade flowlens-poc-0.8.0-amd64.tar.gz` | 升级到新版本 |
| `./flowlens-ctl.sh uninstall` | 删除容器，保留数据 |
| `./flowlens-ctl.sh uninstall --purge` | 删除容器和全部数据 |

### 备份与恢复

- 备份文件是 PostgreSQL 自定义格式（`pg_dump -Fc`），包含账号、会话、审计日志、安全策略、资产、告警、检测规则和检测事件。
- 备份文件含有账号口令哈希和审计日志，请妥善保管。
- 恢复后建议用 `auditadmin` 登录，在审计日志页面执行一次完整性校验。

### 升级

`upgrade` 命令依次完成以下步骤：

1. 校验新安装包。
2. 自动备份数据库。
3. 加载新镜像。
4. 更新部署文件，保留 `.env`、`certs/` 和 `conf/agent-config.yaml`。
5. 启动新版本。数据库结构在平台启动时自动升级。

升级失败时，可以执行 `./flowlens-ctl.sh restore <升级前的备份>` 恢复数据，再把 `.env` 中的 `FLOWLENS_VERSION` 改回原版本后执行 `restart`。

## 8. 配置项

配置保存在安装目录的 `.env` 中，修改后执行 `./flowlens-ctl.sh restart`。

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `FLOWLENS_VERSION` | 0.7.0 | 镜像版本，由安装和升级脚本维护 |
| `POSTGRES_PASSWORD` | 随机 | 数据库口令，只能包含字母、数字和 `. _ ~ -`。数据库初始化后修改无效 |
| `FLOWLENS_AGENT_TOKEN` | 随机 | Agent 认证令牌，修改后所有 Agent 须同步修改 |
| `FLOWLENS_ADMIN_PASSWORD` | 随机 | 内置账号初始口令，只在数据库为空时生效 |
| `FLOWLENS_BIND_ADDR` | 0.0.0.0 | 控制台监听地址，例如只允许本机访问时设为 127.0.0.1 |
| `FLOWLENS_HTTP_PORT` / `FLOWLENS_HTTPS_PORT` | 8080 / 8443 | 控制台端口 |
| `FLOWLENS_WEB_HTTPS` | false | 启用 HTTPS，需要 `certs/server.crt` 和 `certs/server.key` |
| `FLOWLENS_COOKIE_SECURE` | false | 会话 Cookie 带 Secure 标记，启用 HTTPS 时须设为 true |
| `FLOWLENS_FRONTEND_SUBNET` | 172.30.10.0/24 | 控制台与平台之间的内部网络。与现有网络冲突时修改，并同步修改 `FLOWLENS_TRUSTED_PROXIES` |
| `FLOWLENS_TRUSTED_PROXIES` | 172.30.10.0/24 | 平台只信任来自该网段的 X-Forwarded-For，用于审计日志和登录限流中记录真实客户端 IP |
| `FLOWLENS_CORS_ORIGINS` | 空 | 允许跨域调用 API 的来源，逗号分隔。自带的控制台不需要 |
| `FLOWLENS_TZ` | Asia/Shanghai | 时区 |
| `FLOWLENS_SEED_DEMO` | false | 向空数据库写入示例数据 |
| `FLOWLENS_GATEWAY_LOG_DIR` | 空 | 同机 Agent 读取的网关日志目录 |
| `FLOWLENS_DEMO_RATE` | 5 | 演示流量每秒请求数 |

## 9. 安全说明

POC 安装包已默认做了以下加固：

- **账号与口令：** 数据库口令、Agent 令牌、初始管理员口令都在安装时随机生成，保存在权限为 600 的 `.env` 中。三个内置账号首次登录必须改口令。
- **网络隔离：** 数据库和平台不对外暴露端口。数据库所在的内部网络无法访问外网。
- **容器权限：** 平台、控制台、Agent 以非 root 用户运行，去掉全部 Linux capabilities，禁止提权。
- **日志：** 容器日志按大小轮转（单个文件 50MB，保留 5 个）。

用于正式环境前还需要：

1. 使用机构 CA 签发的证书启用 HTTPS。
2. 按等保和金融行业要求，把数据库迁移到独立的数据库服务器，开启数据库 TLS（`sslmode=verify-full`）和磁盘加密，并配置定期备份和异地保存。
3. 在防火墙上限制控制台端口的访问来源。
4. 把 `.env` 中的密钥迁移到机构的密钥管理系统。

## 10. 常见问题

**安装时提示端口被占用**

用 `--http-port` / `--https-port` 换一个端口，或停止占用端口的程序。

**提示 `Pool overlaps with other one on this address space`**

`172.30.10.0/24` 与服务器上现有的网络冲突。修改 `.env` 中的 `FLOWLENS_FRONTEND_SUBNET` 和 `FLOWLENS_TRUSTED_PROXIES`（两者保持一致），然后重新执行 `./install.sh`。

**忘记了初始口令**

初始口令在 `.env` 的 `FLOWLENS_ADMIN_PASSWORD` 中。如果内置账号已修改过口令，由 `sysadmin` 在系统管理后台重置其他账号的口令。

**看不到 Agent 或流量**

1. 执行 `./flowlens-ctl.sh logs agent`，确认没有认证失败（401）或连接错误。
2. 确认 Agent 和平台的令牌一致。
3. 确认日志文件路径正确、每行是完整的 JSON。
4. Agent 从日志末尾开始读取，启动前已有的内容不会上报。

**CentOS 7 上执行 `docker compose` 报错**

CentOS 7 自带的 Docker 版本过低。请安装 Docker CE 20.10+ 和 `docker-compose-plugin`。

## 11. 构建安装包（开发人员）

在源码仓库根目录执行：

```bash
scripts/package-poc.sh                          # 构建镜像并生成 dist/flowlens-poc-<版本>-<架构>.tar.gz
scripts/package-poc.sh --platform linux/arm64   # arm64 版本，需要 buildx 和 QEMU
scripts/package-poc.sh --no-images              # 不含镜像的小包，目标机器需能拉取或构建镜像
```

- 版本号取自 `pkg/version/version.go`，并与 `web/package.json` 核对，两者不一致时脚本报错。
- 镜像带 OCI 标签 `org.opencontainers.image.version`。
- 运行阶段镜像构建时不安装任何软件包，内网构建只需要能访问 Go 和 npm 的镜像源。
