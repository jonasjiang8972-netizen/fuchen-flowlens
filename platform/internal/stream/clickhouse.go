package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

// clickHouseSink batch-inserts enriched records into ClickHouse via its HTTP
// interface using the JSONEachRow format. Stdlib-only, no native driver.
type clickHouseSink struct {
	insertURL string
	target    string
	user      string
	password  string
	client    *http.Client

	queue  chan Record
	cancel context.CancelFunc
	wg     sync.WaitGroup

	batchSize     int
	flushInterval time.Duration
	inserted      uint64
	failed        uint64
	dropped       uint64

	mu        sync.Mutex
	lastError string
}

// chRow mirrors Record but formats the timestamp the way ClickHouse's
// JSONEachRow parser expects for DateTime64.
type chRow struct {
	EventTime       string   `json:"event_time"`
	EventID         string   `json:"event_id"`
	AgentID         string   `json:"agent_id"`
	Source          string   `json:"source"`
	Method          string   `json:"method"`
	Path            string   `json:"path"`
	Host            string   `json:"host"`
	StatusCode      uint16   `json:"status_code"`
	DurationMs      float64  `json:"duration_ms"`
	BytesIn         uint64   `json:"bytes_in"`
	BytesOut        uint64   `json:"bytes_out"`
	SrcIP           string   `json:"src_ip"`
	Principal       string   `json:"principal"`
	Role            string   `json:"role"`
	RiskScore       int      `json:"risk_score"`
	AlertReason     string   `json:"alert_reason"`
	SensitiveFields []string `json:"sensitive_fields"`
}

func newClickHouseSink(cfg Config) *clickHouseSink {
	query := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", cfg.ClickHouseDB, cfg.ClickHouseTable)
	insertURL := fmt.Sprintf("%s/?query=%s&date_time_input_format=best_effort",
		cfg.ClickHouseURL, url.QueryEscape(query))

	ctx, cancel := context.WithCancel(context.Background())
	s := &clickHouseSink{
		insertURL:     insertURL,
		target:        fmt.Sprintf("%s · %s.%s", cfg.ClickHouseURL, cfg.ClickHouseDB, cfg.ClickHouseTable),
		user:          cfg.ClickHouseUser,
		password:      cfg.ClickHousePassword,
		client:        &http.Client{Timeout: 15 * time.Second},
		queue:         make(chan Record, cfg.BufferSize),
		cancel:        cancel,
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
	}
	s.wg.Add(1)
	go s.loop(ctx)
	logger.L().Infof("stream: ClickHouse sink enabled → %s", s.target)
	return s
}

func (s *clickHouseSink) Write(rec Record) {
	select {
	case s.queue <- rec:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

func (s *clickHouseSink) loop(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	batch := make([]Record, 0, s.batchSize)
	drain := func() {
		if len(batch) == 0 {
			return
		}
		s.send(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case rec := <-s.queue:
					batch = append(batch, rec)
					if len(batch) >= s.batchSize {
						drain()
					}
				default:
					drain()
					return
				}
			}
		case rec := <-s.queue:
			batch = append(batch, rec)
			if len(batch) >= s.batchSize {
				drain()
			}
		case <-ticker.C:
			drain()
		}
	}
}

func (s *clickHouseSink) send(records []Record) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // NDJSON: one JSON object per line
	count := 0
	for i := range records {
		row := toCHRow(records[i])
		if err := enc.Encode(&row); err != nil {
			atomic.AddUint64(&s.failed, 1)
			continue
		}
		count++
	}
	if count == 0 {
		return
	}

	req, err := http.NewRequest(http.MethodPost, s.insertURL, &buf)
	if err != nil {
		s.recordFailure(count, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.user != "" {
		req.Header.Set("X-ClickHouse-User", s.user)
		req.Header.Set("X-ClickHouse-Key", s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.recordFailure(count, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		s.recordFailure(count, fmt.Errorf("clickhouse status %d: %s", resp.StatusCode, string(msg)))
		return
	}
	io.Copy(io.Discard, resp.Body)
	atomic.AddUint64(&s.inserted, uint64(count))
}

func (s *clickHouseSink) recordFailure(n int, err error) {
	atomic.AddUint64(&s.failed, uint64(n))
	s.mu.Lock()
	s.lastError = err.Error()
	s.mu.Unlock()
	logger.L().Warnf("stream: clickhouse insert failed (%d rows): %v", n, err)
}

func (s *clickHouseSink) Stats() SinkStats {
	s.mu.Lock()
	lastErr := s.lastError
	s.mu.Unlock()
	return SinkStats{
		Enabled:   true,
		Name:      "clickhouse-http",
		Target:    s.target,
		Published: atomic.LoadUint64(&s.inserted),
		Failed:    atomic.LoadUint64(&s.failed),
		Dropped:   atomic.LoadUint64(&s.dropped),
		Buffered:  len(s.queue),
		LastError: lastErr,
	}
}

func (s *clickHouseSink) Close() error {
	s.cancel()
	s.wg.Wait()
	return nil
}

func toCHRow(rec Record) chRow {
	fields := rec.SensitiveFields
	if fields == nil {
		fields = []string{}
	}
	ts := rec.EventTime
	if ts.IsZero() {
		ts = time.Now()
	}
	return chRow{
		EventTime:       ts.UTC().Format("2006-01-02 15:04:05.000"),
		EventID:         rec.EventID,
		AgentID:         rec.AgentID,
		Source:          rec.Source,
		Method:          rec.Method,
		Path:            rec.Path,
		Host:            rec.Host,
		StatusCode:      rec.StatusCode,
		DurationMs:      rec.DurationMs,
		BytesIn:         rec.BytesIn,
		BytesOut:        rec.BytesOut,
		SrcIP:           rec.SrcIP,
		Principal:       rec.Principal,
		Role:            rec.Role,
		RiskScore:       rec.RiskScore,
		AlertReason:     rec.AlertReason,
		SensitiveFields: fields,
	}
}
