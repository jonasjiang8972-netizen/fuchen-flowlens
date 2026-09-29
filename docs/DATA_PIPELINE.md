# 拂尘 FlowLens — 流式数据管道 (P1-8)

> 打通 `Agent → Kafka → Flink → ClickHouse` 全链路，支撑高吞吐流量的实时聚合与温存储分析。
> 文档版本 V1.0 · 2026-07-23

---

## 一、总体链路

```
┌────────┐   HTTP    ┌──────────┐  publish   ┌────────┐  consume  ┌────────┐
│ Agent  │ ───────▶ │ Platform │ ─────────▶ │ Kafka  │ ────────▶ │ Flink  │
│ (采集) │  /ingest  │ (拂尘)   │  REST代理  │ topic  │           │ (棱镜) │
└────────┘           └────┬─────┘            └────────┘           └───┬────┘
                          │ enrich + write                            │ 1min 窗口聚合
                          ▼                                           ▼
                    ┌──────────────────────────────────────────────────┐
                    │                 ClickHouse (温存储)               │
                    │  api_events (明细)   api_endpoint_stats_1m (聚合) │
                    └──────────────────────────────────────────────────┘
```

- **明细流**：平台在处理每条事件时，把富化后的记录直接写入 ClickHouse `api_events`（即使不部署 Flink 也能查询“API 资产活地图”与风险明细）。
- **聚合流**：平台把归一化后的原始事件旁路发布到 Kafka；Flink 作业按 1 分钟滚动窗口，按接口聚合流量/错误率/时延，写入 `api_endpoint_stats_1m`。

两条流互相独立、互不阻塞，任一后端未配置时自动降级为空操作（no-op），平台仍可在纯内存 / demo 模式下运行。

---

## 二、平台侧实现（`platform/internal/stream`）

仅依赖 Go 标准库，未引入任何原生 Kafka / ClickHouse 客户端，因此 `go.mod` 不变、构建零新增依赖。

| 文件 | 职责 |
|------|------|
| `stream.go` | `Streamer` 门面、`Config`、环境变量解析、no-op 兜底 |
| `kafka_rest.go` | 经 Confluent REST Proxy（HTTP）批量发布事件到 Kafka |
| `clickhouse.go` | 经 ClickHouse HTTP 接口（JSONEachRow）批量写入明细 |

两个 Sink 均为**异步、批量、非阻塞**：内部带缓冲 channel，按 `batch_size` 或 `flush_interval` 刷写；缓冲满时丢弃并计数（`dropped`），绝不阻塞主处理链路。

### 配置（环境变量）

| 变量 | 说明 | 默认 |
|------|------|------|
| `FLOWLENS_KAFKA_REST_URL` | Kafka REST Proxy 地址，为空则禁用 Kafka | — |
| `FLOWLENS_KAFKA_TOPIC` | 目标 topic | `fuchen.api.events` |
| `FLOWLENS_CLICKHOUSE_URL` | ClickHouse HTTP 地址，为空则禁用 | — |
| `FLOWLENS_CLICKHOUSE_DB` | 数据库 | `flowlens` |
| `FLOWLENS_CLICKHOUSE_TABLE` | 明细表 | `api_events` |
| `FLOWLENS_CLICKHOUSE_USER` / `_PASSWORD` | 认证 | — |
| `FLOWLENS_STREAM_BATCH_SIZE` | 刷写批大小 | `500` |
| `FLOWLENS_STREAM_BUFFER_SIZE` | 缓冲区容量 | `20000` |
| `FLOWLENS_STREAM_FLUSH_MS` | 刷写间隔（毫秒） | `2000` |

运行状态可通过 `GET /api/v1/ingest/metrics` 观测，响应新增 `stream_enabled` 与 `stream`（每个 sink 的 `published/failed/dropped/buffered/last_error`）。

---

## 三、Flink 作业（`deploy/flink/api_events_pipeline.sql`）

Flink SQL 作业：Kafka 源 → 1 分钟滚动窗口聚合 → ClickHouse JDBC 汇。

- 源表 `api_events_src`：`connector=kafka`，JSON 格式，`ISO-8601` 时间解析，仅声明聚合所需字段。
- 汇表 `api_endpoint_stats_1m`：`connector=jdbc` + ClickHouse JDBC 驱动。
- 聚合：`TUMBLE(... INTERVAL '1' MINUTE)`，按 `host / path / method` 统计 `request_count / error_count / avg_duration_ms`。

### 依赖 jar

把以下 jar 放入 `deploy/flink/lib/`（构建镜像时 COPY 进 `/opt/flink/lib`）：

- `flink-sql-connector-kafka-*.jar`
- `flink-connector-jdbc-*.jar`
- `clickhouse-jdbc-*-all.jar`

`deploy/flink/submit.sh` 顶部注释给出了对应的 Maven 下载命令。

---

## 四、ClickHouse 表结构（`deploy/clickhouse/init.sql`）

- `api_events`：`MergeTree`，按天分区，30 天 TTL，明细事实表。
- `api_endpoint_stats_1m`：`ReplacingMergeTree`，Flink 写入的分钟级聚合；窗口重发可去重。
- 可选：一个被注释的物化视图，作为“未部署 Flink 时”的原生兜底（切勿与 Flink 同时开启，否则重复计数）。

---

## 五、启动

流式管道是可选组件，叠加在 POC 部署之上（`deploy/poc/docker-compose.stream.yaml`）。这些镜像不在离线安装包内，部署机需能访问镜像仓库。

```bash
cd deploy/poc

# 1. 准备 Flink 连接器 jar（见 ../flink/submit.sh 顶部命令），放入 ../flink/lib/
# 2. 在 .env 里设置 ClickHouse 密码（仅字母和数字）
echo "CLICKHOUSE_PASSWORD=$(openssl rand -hex 16)" >> .env
# 3. 叠加启动
docker compose -f docker-compose.yaml -f docker-compose.stream.yaml up -d --build

# 4. 提交 Flink 作业
../flink/submit.sh

# 5. 查看结果（ClickHouse 只在内部网络，用 exec 查询）
docker compose exec clickhouse clickhouse-client --user flowlens --password "$CLICKHOUSE_PASSWORD" \
  -q "SELECT count() FROM flowlens.api_events"
# 运行状态：登录控制台后访问 GET /api/v1/ingest/metrics（需要会话），看 stream 字段
```

> 数据脱敏：发往 Kafka 和 ClickHouse 的都是**脱敏之后**的事件，且 Kafka 中的事件不带请求/响应体，只含流量元数据。

---

## 六、降级与容错

| 场景 | 行为 |
|------|------|
| 未配置 Kafka / ClickHouse | 对应 sink 为 no-op，平台照常运行（demo 模式） |
| Kafka / ClickHouse 短暂不可用 | 写入失败被计数（`failed`/`last_error`），主链路不阻塞 |
| 突发洪峰超出缓冲 | 超出部分被丢弃并计入 `dropped`，保护平台稳定 |
| 未部署 Flink | 明细仍写入 `api_events`；可选启用 ClickHouse 物化视图做兜底聚合 |
