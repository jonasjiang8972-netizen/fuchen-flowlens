package stream

import (
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func TestConfigEnabledFlags(t *testing.T) {
	cases := []struct {
		name       string
		cfg        Config
		wantKafka  bool
		wantClickH bool
	}{
		{"empty", Config{}, false, false},
		{"kafka-only", Config{KafkaRESTURL: "http://rest:8082", KafkaTopic: "t"}, true, false},
		{"kafka-missing-topic", Config{KafkaRESTURL: "http://rest:8082"}, false, false},
		{"clickhouse-only", Config{ClickHouseURL: "http://ch:8123"}, false, true},
		{"both", Config{KafkaRESTURL: "http://rest:8082", KafkaTopic: "t", ClickHouseURL: "http://ch:8123"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.KafkaEnabled(); got != tc.wantKafka {
				t.Errorf("KafkaEnabled() = %v, want %v", got, tc.wantKafka)
			}
			if got := tc.cfg.ClickHouseEnabled(); got != tc.wantClickH {
				t.Errorf("ClickHouseEnabled() = %v, want %v", got, tc.wantClickH)
			}
		})
	}
}

func TestWithDefaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.KafkaTopic != "fuchen.api.events" {
		t.Errorf("default topic = %q", c.KafkaTopic)
	}
	if c.ClickHouseDB != "flowlens" || c.ClickHouseTable != "api_events" {
		t.Errorf("default clickhouse db/table = %q/%q", c.ClickHouseDB, c.ClickHouseTable)
	}
	if c.BatchSize <= 0 || c.BufferSize <= 0 || c.FlushInterval <= 0 {
		t.Errorf("non-positive defaults: %+v", c)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("FLOWLENS_KAFKA_REST_URL", "http://rest:8082/")
	t.Setenv("FLOWLENS_KAFKA_TOPIC", "custom.topic")
	t.Setenv("FLOWLENS_CLICKHOUSE_URL", "http://ch:8123/")
	t.Setenv("FLOWLENS_STREAM_BATCH_SIZE", "123")
	t.Setenv("FLOWLENS_STREAM_FLUSH_MS", "750")

	c := ConfigFromEnv()
	if c.KafkaRESTURL != "http://rest:8082" { // trailing slash trimmed
		t.Errorf("KafkaRESTURL = %q", c.KafkaRESTURL)
	}
	if c.ClickHouseURL != "http://ch:8123" {
		t.Errorf("ClickHouseURL = %q", c.ClickHouseURL)
	}
	if c.KafkaTopic != "custom.topic" {
		t.Errorf("KafkaTopic = %q", c.KafkaTopic)
	}
	if c.BatchSize != 123 {
		t.Errorf("BatchSize = %d", c.BatchSize)
	}
	if c.FlushInterval != 750*time.Millisecond {
		t.Errorf("FlushInterval = %v", c.FlushInterval)
	}
}

// A disabled Streamer must accept traffic without panicking and report nothing
// enabled — this is the demo / pure in-memory path.
func TestDisabledStreamerIsNoop(t *testing.T) {
	s := New(Config{})
	if s.Enabled() {
		t.Fatal("expected disabled streamer")
	}
	s.PublishRaw(shared.APIEvent{EventID: "e1"})
	s.WriteRecord(Record{EventID: "e1", EventTime: time.Now()})

	stats := s.Stats()
	if stats["kafka"].Enabled || stats["clickhouse"].Enabled {
		t.Errorf("expected both sinks disabled, got %+v", stats)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestToCHRowFormatsTimestampAndFields(t *testing.T) {
	row := toCHRow(Record{EventID: "e1"}) // zero time → filled with now
	if row.EventTime == "" {
		t.Error("expected non-empty event_time")
	}
	if row.SensitiveFields == nil {
		t.Error("expected non-nil sensitive_fields slice for JSON array output")
	}

	ts := time.Date(2026, 7, 23, 10, 30, 15, int(500*time.Millisecond), time.UTC)
	row2 := toCHRow(Record{EventID: "e2", EventTime: ts})
	if row2.EventTime != "2026-07-23 10:30:15.500" {
		t.Errorf("event_time = %q, want 2026-07-23 10:30:15.500", row2.EventTime)
	}
}
