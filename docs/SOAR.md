# 拂尘 FlowLens — 联动处置 SOAR (v0.9.0)

> 让告警上的"封禁"真正落到网关、WAF 和自动化平台，而不只是改一个告警状态。

## 一、它做什么

分析员在告警上点"封禁"（或在**联动处置**页手动封禁），平台会：

1. 检查护栏（见下）；
2. 把来源 IP 下发到所有已配置的联动系统；
3. 记录每个系统的执行结果，并写入审计日志（谁、封了谁、结果如何）；
4. 到期后自动解封；平台重启后仍会按期解封（封禁记录已持久化）；
5. 只有封禁**真的生效**，告警才进入"处置中"。全部失败时告警保持原状态，并记录失败原因。

> 之前版本的"封禁/限流"只修改告警状态，并没有对任何系统执行动作。**限流现在返回 501**：当前没有联动系统能做限流，与其谎称已限流，不如明确不支持。

## 二、护栏

封错地址会让真实客户或内部服务断网，所以默认很保守：

| 护栏 | 默认 | 配置 |
|---|---|---|
| 不封内网、回环、链路本地、组播、未指定地址 | 开 | `FLOWLENS_SOAR_ALLOW_PRIVATE=true` 可放开内网 |
| 受保护网段（办公出口、监控、合作方） | 空 | `FLOWLENS_SOAR_PROTECTED_CIDRS=203.0.113.0/24,198.51.100.7` |
| 封禁时长 | 默认 1 小时，最长 24 小时，最短 1 分钟 | `FLOWLENS_SOAR_DEFAULT_TTL` / `_MAX_TTL`（如 `30m`、`48h`） |
| 每小时最多封禁次数 | 30 | `FLOWLENS_SOAR_MAX_BLOCKS_PER_HOUR` |
| 演练模式 | 关 | `FLOWLENS_SOAR_DRY_RUN=true`：只记录，不下发；告警上会标注"演练" |
| 只封单个 IP | — | 不支持网段，避免误伤 |

**建议先开演练模式**跑一段时间，确认哪些告警会触发封禁、封的是不是想封的地址，再关闭它。

演示模式（`--demo`）强制演练，并且**只使用**不产生任何真实动作的模拟连接器，即使环境变量里配置了真实的联动系统也会忽略：演示环境没有登录，不能让任何人碰到真实网关，哪怕只是探测。

权限：查看需要 `security.read`；封禁/解封需要 `alert.handle`（安全管理员、安全分析员）；测试连接需要 `rule.manage`（安全管理员）。系统管理员和审计管理员看不到这些接口。

## 三、联动系统

通过环境变量启用，设置了主变量即启用。密钥只来自环境变量，**不会写入数据库，API 也不会返回**。

### Kong
```
FLOWLENS_SOAR_KONG_URL=http://kong:8001      # Admin API
FLOWLENS_SOAR_KONG_TOKEN=...                 # 可选，Kong-Admin-Token
```
平台维护一个带 `flowlens-block` 标签的全局 `ip-restriction` 插件，`deny` 列表即被封地址。最后一个地址解封时删除该插件（Kong 不允许空列表）。只会改动自己标记的插件。

### APISIX
```
FLOWLENS_SOAR_APISIX_URL=http://apisix:9180
FLOWLENS_SOAR_APISIX_KEY=...                 # X-API-KEY
```
维护全局规则 `flowlens-block` 的 `ip-restriction.blacklist`，兼容 APISIX 2.x/3.x 的响应格式。

### Nginx
```
FLOWLENS_SOAR_NGINX_DENY_FILE=/etc/nginx/flowlens-deny.conf
FLOWLENS_SOAR_NGINX_RELOAD_CMD="nginx -s reload"     # 可省略：只写文件不重载
```
在 nginx 的 `http` 或 `server` 块里加 `include /etc/nginx/flowlens-deny.conf;`。平台原子地重写该文件（只包含 `deny <ip>;` 行），再执行重载命令（按空白拆分后直接执行，不经过 shell）。**重载失败会还原文件**，保证文件与运行配置一致。只写入校验过的 IP，告警内容不可能注入配置。

需要平台进程能写该文件并执行重载命令，所以适合平台与 nginx 同机部署；POC 的容器编排里默认不透传这一项。

### 通用 Webhook（对接 SOAR 平台或自建自动化）
```
FLOWLENS_SOAR_WEBHOOK_URL=https://soar.example.com/hooks/flowlens
FLOWLENS_SOAR_WEBHOOK_SECRET=...             # 必填，请求必须签名
```
向该地址 POST JSON，`action` 为 `block_ip`、`unblock_ip` 或 `ping`：

```json
{"action":"block_ip","ip":"198.51.100.9","reason":"撞库攻击","alert_id":"alt-1","ttl_seconds":3600,"sent_at":1790000000}
```
请求头 `X-FlowLens-Timestamp`（Unix 秒）和 `X-FlowLens-Signature: sha256=<hex>`，其中签名是 `HMAC-SHA256(secret, timestamp + "." + body)`。接收方应校验签名，并拒绝时间戳与本机相差过大的请求（防重放）。返回 2xx 视为成功；不跟随重定向，避免带签名的请求被转发到别处。

### 阿里云 WAF 3.0（**实验性**）
```
FLOWLENS_SOAR_ALIYUN_WAF_ACCESS_KEY_ID=...
FLOWLENS_SOAR_ALIYUN_WAF_ACCESS_KEY_SECRET=...
FLOWLENS_SOAR_ALIYUN_WAF_INSTANCE_ID=waf_v2_public_cn-...
FLOWLENS_SOAR_ALIYUN_WAF_TEMPLATE_ID=...     # 你事先在 WAF 控制台创建的 IP 黑名单防护模板
FLOWLENS_SOAR_ALIYUN_WAF_REGION=cn-hangzhou  # 可选
```
向模板里添加/删除规则，并保存返回的规则 ID 用于解封。

**这个连接器没有在真实 WAF 实例上验证过。** 请求签名（ACS3-HMAC-SHA256）按公开规范实现并有测试覆盖，但规则的具体字段（`CreateDefenseRule` 的 `DefenseScene`、`Rules` 结构）依据官方文档编写，可能与你的实例不一致。控制台会把它标为"实验性"。上线前请：先"测试连接"，再用演练模式，最后真封一个测试地址并到 WAF 控制台核对。规则构造集中在 `platform/internal/soar/aliyun.go` 的 `buildRules`，需要调整时只改这一处。

## 四、API

| 接口 | 权限 | 说明 |
|---|---|---|
| `GET /soar/connectors` | security.read | 联动系统、最近检测结果、生效封禁数，以及当前护栏 |
| `POST /soar/connectors/{name}/test` | rule.manage | 测试连接 |
| `GET /soar/blocks?active=true` | security.read | 封禁记录（新的在前） |
| `POST /soar/block` | alert.handle | `{ip, ttl_minutes, reason, alert_id, connectors[]}` |
| `POST /soar/unblock` | alert.handle | `{ip}` |
| `POST /alerts/{id}/ip_block` | alert.handle | 封禁告警的来源 IP（也可用 `target` 指定），`duration_minutes` 指定时长 |

状态码：`409` 未配置联动系统；`400` 地址/时长/连接器无效；`429` 超过每小时上限；`502` 所有联动系统都失败。封禁部分成功时（例如 Kong 成功、WAF 失败）整体仍为成功，失败的系统在结果里标出；再次封禁同一地址会只重试失败的系统。

## 五、审计

`soar.block`、`soar.unblock`、`soar.test` 都写入防篡改审计链，记录操作人、目标、每个系统的结果。到期自动解封记为 `system` 用户。被拒绝的尝试（内网地址、超限等）同样会记录。

## 六、已知限制

- 只封单个 IP，不支持网段、账号、设备指纹。
- 不做限流（见上）。
- 不做**自动封禁**：告警只是建议，是否封由人决定。误报率没有线上数据验证之前，自动封禁风险太大。
- 封禁记录随业务数据存入 PostgreSQL（未配置数据库、使用内存存储时，重启后记录丢失，已下发的封禁需手动清理）；解封失败会保持"生效中"并每 30 秒重试，直到成功。
- 多个平台副本同时运行时，各自独立到期解封，可能重复下发解封请求（连接器都是幂等的，无副作用）。
