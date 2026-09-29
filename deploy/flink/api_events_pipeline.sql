-- 拂尘 FlowLens · Flink SQL streaming job (v0.7.0, task P1-8)
--
--   Kafka topic  fuchen.api.events   (raw normalized API events from platform)
--        │
--        ▼   1-minute tumbling window, grouped per endpoint
--   ClickHouse  flowlens.api_endpoint_stats_1m
--
-- Run with the Flink SQL client:
--     deploy/flink/submit.sh
--
-- Prerequisites (see docs/DATA_PIPELINE.md):
--   * flink-sql-connector-kafka jar in /opt/flink/lib
--   * flink-connector-jdbc jar     in /opt/flink/lib
--   * clickhouse-jdbc (all) jar     in /opt/flink/lib

SET 'execution.runtime-mode' = 'streaming';
SET 'pipeline.name' = 'fuchen-api-endpoint-stats-1m';
SET 'parallelism.default' = '2';

-- ─── Source: raw API events on Kafka ──────────────────────────
-- Only the fields needed for traffic aggregation are declared; the JSON
-- format ignores everything else in the event payload.
CREATE TABLE api_events_src (
    event_id      STRING,
    `timestamp`   TIMESTAMP(3),
    agent_id      STRING,
    application ROW<
        method          STRING,
        path_normalized STRING,
        host            STRING,
        status_code     INT,
        duration_ms     DOUBLE
    >,
    WATERMARK FOR `timestamp` AS `timestamp` - INTERVAL '5' SECOND
) WITH (
    'connector'                        = 'kafka',
    'topic'                            = 'fuchen.api.events',
    'properties.bootstrap.servers'     = 'kafka:29092',
    'properties.group.id'              = 'flink-fuchen-agg',
    'scan.startup.mode'                = 'latest-offset',
    'format'                           = 'json',
    'json.ignore-parse-errors'         = 'true',
    'json.timestamp-format.standard'   = 'ISO-8601'
);

-- ─── Sink: per-endpoint per-minute stats in ClickHouse ────────
CREATE TABLE api_endpoint_stats_1m (
    window_start    TIMESTAMP(3),
    host            STRING,
    path            STRING,
    method          STRING,
    request_count   BIGINT,
    error_count     BIGINT,
    avg_duration_ms DOUBLE,
    PRIMARY KEY (host, path, method, window_start) NOT ENFORCED
) WITH (
    'connector'  = 'jdbc',
    'url'        = 'jdbc:clickhouse://clickhouse:8123/flowlens',
    'table-name' = 'api_endpoint_stats_1m',
    'driver'     = 'com.clickhouse.jdbc.ClickHouseDriver',
    'username'   = 'flowlens',
    'password'   = '__CLICKHOUSE_PASSWORD__',
    'sink.buffer-flush.max-rows' = '500',
    'sink.buffer-flush.interval' = '2s'
);

-- ─── Job: 1-minute tumbling aggregation ───────────────────────
INSERT INTO api_endpoint_stats_1m
SELECT
    window_start,
    application.host                                             AS host,
    application.path_normalized                                  AS path,
    application.method                                           AS method,
    COUNT(*)                                                     AS request_count,
    SUM(CASE WHEN application.status_code >= 400 THEN 1 ELSE 0 END) AS error_count,
    AVG(application.duration_ms)                                 AS avg_duration_ms
FROM TABLE(
    TUMBLE(TABLE api_events_src, DESCRIPTOR(`timestamp`), INTERVAL '1' MINUTE)
)
GROUP BY
    window_start,
    window_end,
    application.host,
    application.path_normalized,
    application.method;
