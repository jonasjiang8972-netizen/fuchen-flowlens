// Package stream implements the v0.7.0 streaming backbone for 拂尘 FlowLens.
//
// It connects the ingest pipeline to the "Agent → Kafka → Flink → ClickHouse"
// data path described in docs/ROADMAP.md (task P1-8):
//
//   - Raw API events are published to Kafka (via the Confluent REST Proxy) so a
//     Flink job can perform windowed enrichment / aggregation downstream.
//   - Processed events are also written directly to ClickHouse (warm storage)
//     via the ClickHouse HTTP interface, so analytics work even before a Flink
//     job is deployed.
//
// The whole package depends only on the Go standard library. When neither
// backend is configured the sinks degrade to no-ops, so the platform keeps
// working in pure in-memory / demo mode with no external infrastructure.
package stream

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

// Record is the flattened, enriched view of an API event that is persisted to
// ClickHouse. Field names/tags map 1:1 to the columns declared in
// deploy/clickhouse/init.sql.
type Record struct {
	EventTime       time.Time `json:"event_time"`
	EventID         string    `json:"event_id"`
	AgentID         string    `json:"agent_id"`
	Source          string    `json:"source"`
	Method          string    `json:"method"`
	Path            string    `json:"path"`
	Host            string    `json:"host"`
	StatusCode      uint16    `json:"status_code"`
	DurationMs      float64   `json:"duration_ms"`
	BytesIn         uint64    `json:"bytes_in"`
	BytesOut        uint64    `json:"bytes_out"`
	SrcIP           string    `json:"src_ip"`
	Principal       string    `json:"principal"`
	Role            string    `json:"role"`
	RiskScore       int       `json:"risk_score"`
	AlertReason     string    `json:"alert_reason"`
	SensitiveFields []string  `json:"sensitive_fields"`
}

// SinkStats is a snapshot of a sink's runtime counters, surfaced through the
// ingest metrics endpoint for observability.
type SinkStats struct {
	Enabled   bool   `json:"enabled"`
	Name      string `json:"name"`
	Target    string `json:"target,omitempty"`
	Published uint64 `json:"published"`
	Failed    uint64 `json:"failed"`
	Dropped   uint64 `json:"dropped"`
	Buffered  int    `json:"buffered"`
	LastError string `json:"last_error,omitempty"`
}

// EventSink publishes raw API events onto the streaming backbone.
type EventSink interface {
	Publish(evt shared.APIEvent)
	Stats() SinkStats
	Close() error
}

// RecordSink persists enriched detection records to warm storage.
type RecordSink interface {
	Write(rec Record)
	Stats() SinkStats
	Close() error
}

// Config controls which backends are wired up. Empty URL fields disable the
// corresponding backend.
type Config struct {
	KafkaRESTURL string // e.g. http://kafka-rest:8082
	KafkaTopic   string // e.g. fuchen.api.events

	ClickHouseURL      string // HTTP interface, e.g. http://clickhouse:8123
	ClickHouseDB       string // e.g. flowlens
	ClickHouseTable    string // e.g. api_events
	ClickHouseUser     string
	ClickHousePassword string

	BatchSize     int           // flush when this many items are buffered
	BufferSize    int           // channel capacity before dropping
	FlushInterval time.Duration // flush at least this often
}

// KafkaEnabled reports whether a Kafka target is configured.
func (c Config) KafkaEnabled() bool { return c.KafkaRESTURL != "" && c.KafkaTopic != "" }

// ClickHouseEnabled reports whether a ClickHouse target is configured.
func (c Config) ClickHouseEnabled() bool { return c.ClickHouseURL != "" }

func (c Config) withDefaults() Config {
	if c.KafkaTopic == "" {
		c.KafkaTopic = "fuchen.api.events"
	}
	if c.ClickHouseDB == "" {
		c.ClickHouseDB = "flowlens"
	}
	if c.ClickHouseTable == "" {
		c.ClickHouseTable = "api_events"
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 500
	}
	if c.BufferSize <= 0 {
		c.BufferSize = 20000
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 2 * time.Second
	}
	return c
}

// ConfigFromEnv builds a Config from FLOWLENS_* environment variables. All are
// optional; unset URL fields leave the matching backend disabled.
//
//	FLOWLENS_KAFKA_REST_URL     Confluent REST Proxy base URL
//	FLOWLENS_KAFKA_TOPIC        target topic (default fuchen.api.events)
//	FLOWLENS_CLICKHOUSE_URL     ClickHouse HTTP base URL (e.g. http://clickhouse:8123)
//	FLOWLENS_CLICKHOUSE_DB      database (default flowlens)
//	FLOWLENS_CLICKHOUSE_TABLE   table (default api_events)
//	FLOWLENS_CLICKHOUSE_USER    user
//	FLOWLENS_CLICKHOUSE_PASSWORD password
//	FLOWLENS_STREAM_BATCH_SIZE  flush batch size
//	FLOWLENS_STREAM_BUFFER_SIZE channel capacity
//	FLOWLENS_STREAM_FLUSH_MS    flush interval in milliseconds
func ConfigFromEnv() Config {
	c := Config{
		KafkaRESTURL:       strings.TrimRight(os.Getenv("FLOWLENS_KAFKA_REST_URL"), "/"),
		KafkaTopic:         os.Getenv("FLOWLENS_KAFKA_TOPIC"),
		ClickHouseURL:      strings.TrimRight(os.Getenv("FLOWLENS_CLICKHOUSE_URL"), "/"),
		ClickHouseDB:       os.Getenv("FLOWLENS_CLICKHOUSE_DB"),
		ClickHouseTable:    os.Getenv("FLOWLENS_CLICKHOUSE_TABLE"),
		ClickHouseUser:     os.Getenv("FLOWLENS_CLICKHOUSE_USER"),
		ClickHousePassword: os.Getenv("FLOWLENS_CLICKHOUSE_PASSWORD"),
	}
	if v := os.Getenv("FLOWLENS_STREAM_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.BatchSize = n
		}
	}
	if v := os.Getenv("FLOWLENS_STREAM_BUFFER_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.BufferSize = n
		}
	}
	if v := os.Getenv("FLOWLENS_STREAM_FLUSH_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.FlushInterval = time.Duration(n) * time.Millisecond
		}
	}
	return c
}

// Streamer is the façade the platform uses. It owns one EventSink (Kafka) and
// one RecordSink (ClickHouse); either may be a no-op.
type Streamer struct {
	cfg     Config
	events  EventSink
	records RecordSink
}

// New builds a Streamer from cfg, wiring real sinks where a target is
// configured and no-op sinks otherwise. It never returns nil.
func New(cfg Config) *Streamer {
	cfg = cfg.withDefaults()
	s := &Streamer{cfg: cfg}

	if cfg.KafkaEnabled() {
		s.events = newKafkaRESTSink(cfg)
	} else {
		s.events = noopEventSink{}
	}
	if cfg.ClickHouseEnabled() {
		s.records = newClickHouseSink(cfg)
	} else {
		s.records = noopRecordSink{}
	}
	return s
}

// PublishRaw sends a raw API event to Kafka (no-op if Kafka is disabled).
func (s *Streamer) PublishRaw(evt shared.APIEvent) { s.events.Publish(evt) }

// WriteRecord persists an enriched record to ClickHouse (no-op if disabled).
func (s *Streamer) WriteRecord(rec Record) { s.records.Write(rec) }

// Enabled reports whether at least one real backend is active.
func (s *Streamer) Enabled() bool { return s.cfg.KafkaEnabled() || s.cfg.ClickHouseEnabled() }

// Stats returns a per-sink snapshot for the metrics endpoint.
func (s *Streamer) Stats() map[string]SinkStats {
	return map[string]SinkStats{
		"kafka":      s.events.Stats(),
		"clickhouse": s.records.Stats(),
	}
}

// Close flushes and releases both sinks.
func (s *Streamer) Close() error {
	err1 := s.events.Close()
	err2 := s.records.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// ─── No-op sinks ───────────────────────────────────────────────

type noopEventSink struct{}

func (noopEventSink) Publish(shared.APIEvent) {}
func (noopEventSink) Stats() SinkStats        { return SinkStats{Enabled: false, Name: "kafka-noop"} }
func (noopEventSink) Close() error            { return nil }

type noopRecordSink struct{}

func (noopRecordSink) Write(Record)     {}
func (noopRecordSink) Stats() SinkStats { return SinkStats{Enabled: false, Name: "clickhouse-noop"} }
func (noopRecordSink) Close() error     { return nil }
