-- 拂尘 FlowLens · ClickHouse warm-storage schema (v0.7.0)
-- Loaded automatically by the clickhouse-server container via
-- /docker-entrypoint-initdb.d. Safe to re-run (all statements are idempotent).

CREATE DATABASE IF NOT EXISTS flowlens;

-- ─────────────────────────────────────────────────────────────
-- Raw enriched events.
-- Written directly by the platform (platform/internal/stream ClickHouse sink)
-- for every processed API event. This is the queryable "活地图" fact table.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS flowlens.api_events
(
    event_time       DateTime64(3),
    event_id         String,
    agent_id         String,
    source           String,
    method           LowCardinality(String),
    path             String,
    host             String,
    status_code      UInt16,
    duration_ms      Float64,
    bytes_in         UInt64,
    bytes_out        UInt64,
    src_ip           String,
    principal        String,
    role             LowCardinality(String),
    risk_score       Int32,
    alert_reason     String,
    sensitive_fields Array(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (host, path, event_time)
TTL toDateTime(event_time) + INTERVAL 30 DAY;

-- ─────────────────────────────────────────────────────────────
-- Per-endpoint, per-minute traffic aggregates.
-- Primary writer is the Flink job (deploy/flink/api_events_pipeline.sql),
-- which consumes the Kafka topic and writes one row per tumbling window.
-- ReplacingMergeTree dedupes if a window is re-emitted after a restart.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS flowlens.api_endpoint_stats_1m
(
    window_start    DateTime,
    host            String,
    path            String,
    method          LowCardinality(String),
    request_count   UInt64,
    error_count     UInt64,
    avg_duration_ms Float64
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (host, path, method, window_start);

-- ─────────────────────────────────────────────────────────────
-- OPTIONAL — Flink-less fallback.
-- If you are NOT running the Flink job, uncomment the materialized view
-- below to have ClickHouse roll api_events into the 1-minute stats table
-- natively. Do NOT enable this at the same time as the Flink job, or the
-- window rows will be double-counted.
-- ─────────────────────────────────────────────────────────────
-- CREATE MATERIALIZED VIEW IF NOT EXISTS flowlens.api_endpoint_stats_1m_mv
-- TO flowlens.api_endpoint_stats_1m AS
-- SELECT
--     toStartOfMinute(event_time)                       AS window_start,
--     host,
--     path,
--     method,
--     count()                                           AS request_count,
--     countIf(status_code >= 400)                       AS error_count,
--     avg(duration_ms)                                  AS avg_duration_ms
-- FROM flowlens.api_events
-- GROUP BY window_start, host, path, method;
