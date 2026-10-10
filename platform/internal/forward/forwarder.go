package forward

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// SettingsStore persists the configuration.
type SettingsStore interface {
	GetSetting(ctx context.Context, key string) ([]byte, error)
	PutSetting(ctx context.Context, key string, value []byte) error
}

const settingsKey = "forwarding_targets"

// Delivery bounds.
const (
	queueSize      = 2000
	sendTimeout    = 5 * time.Second
	webhookRetries = 3
)

// TargetStats report a target's deliveries since the platform started.
type TargetStats struct {
	Sent        uint64     `json:"sent"`
	Failed      uint64     `json:"failed"`
	Dropped     uint64     `json:"dropped"` // queue full
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	LastSentAt  *time.Time `json:"last_sent_at,omitempty"`
}

// Forwarder delivers events to the configured targets. Each enabled target
// has its own queue and goroutine, so a slow or unreachable destination
// delays and drops only its own events; publishing never blocks.
type Forwarder struct {
	store SettingsStore

	mu      sync.RWMutex
	cfg     Config
	workers map[string]*worker
	stats   map[string]*statsCell
	ctx     context.Context
}

type statsCell struct {
	sent, failed, dropped atomic.Uint64
	mu                    sync.Mutex
	lastError             string
	lastErrorAt, lastSent time.Time
}

type worker struct {
	target Target
	queue  chan Event
	cancel context.CancelFunc
	stats  *statsCell
	conn   net.Conn // syslog over tcp/tls, reused
}

func New(store SettingsStore) *Forwarder {
	return &Forwarder{store: store, workers: map[string]*worker{}, stats: map[string]*statsCell{}}
}

// Start loads the saved configuration and starts delivering. It returns
// once the workers run; they stop when ctx ends.
func (f *Forwarder) Start(ctx context.Context) error {
	cfg := Config{}
	if f.store != nil {
		raw, err := f.store.GetSetting(ctx, settingsKey)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("load forwarding config: %w", err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return fmt.Errorf("decode forwarding config: %w", err)
			}
		}
	}
	f.mu.Lock()
	f.ctx = ctx
	f.cfg = cfg
	f.restartLocked()
	f.mu.Unlock()
	return nil
}

// Config returns the current configuration (with secrets).
func (f *Forwarder) Config() Config {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := Config{Targets: append([]Target(nil), f.cfg.Targets...)}
	return out
}

// Update validates, saves and applies a new configuration. Masked secrets
// keep their stored values.
func (f *Forwarder) Update(ctx context.Context, cfg Config) (Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cfg.keepSecrets(f.cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	raw, _ := json.Marshal(cfg)
	if f.store != nil {
		if err := f.store.PutSetting(ctx, settingsKey, raw); err != nil {
			return Config{}, fmt.Errorf("save forwarding config: %w", err)
		}
	}
	f.cfg = cfg
	f.restartLocked()
	return cfg, nil
}

// restartLocked replaces the workers with ones for the current targets.
func (f *Forwarder) restartLocked() {
	for _, w := range f.workers {
		w.cancel()
	}
	f.workers = map[string]*worker{}
	if f.ctx == nil {
		return
	}
	for _, t := range f.cfg.Targets {
		if !t.Enabled {
			continue
		}
		st := f.stats[t.ID]
		if st == nil {
			st = &statsCell{}
			f.stats[t.ID] = st
		}
		ctx, cancel := context.WithCancel(f.ctx)
		w := &worker{target: t, queue: make(chan Event, queueSize), cancel: cancel, stats: st}
		f.workers[t.ID] = w
		go w.run(ctx)
	}
}

// Publish queues an event for every target that wants it. It never blocks:
// when a target's queue is full the event is dropped for that target and
// counted.
func (f *Forwarder) Publish(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, w := range f.workers {
		if !w.target.wants(e.Type, e.Severity) {
			continue
		}
		select {
		case w.queue <- e:
		default:
			w.stats.dropped.Add(1)
		}
	}
}

// Stats returns delivery statistics per target ID.
func (f *Forwarder) Stats() map[string]TargetStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]TargetStats, len(f.stats))
	for id, s := range f.stats {
		s.mu.Lock()
		ts := TargetStats{Sent: s.sent.Load(), Failed: s.failed.Load(), Dropped: s.dropped.Load(), LastError: s.lastError}
		if !s.lastErrorAt.IsZero() {
			t := s.lastErrorAt
			ts.LastErrorAt = &t
		}
		if !s.lastSent.IsZero() {
			t := s.lastSent
			ts.LastSentAt = &t
		}
		out[id] = ts
		s.mu.Unlock()
	}
	return out
}

// Test sends a test event to t synchronously (t need not be saved; a
// masked secret uses the stored one) and returns the delivery error.
func (f *Forwarder) Test(ctx context.Context, t Target) error {
	cfg := Config{Targets: []Target{t}}
	f.mu.RLock()
	cfg.keepSecrets(f.cfg)
	f.mu.RUnlock()
	if err := cfg.Validate(); err != nil {
		return err
	}
	w := &worker{target: cfg.Targets[0], stats: &statsCell{}}
	defer w.close()
	return w.deliver(ctx, Event{
		Type: EventTest, Time: time.Now(), Severity: "info", Title: "FlowLens 外发测试消息",
		Fields: map[string]string{"target": t.Name},
	})
}

func (w *worker) run(ctx context.Context) {
	defer w.close()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-w.queue:
			err := w.deliver(ctx, e)
			w.stats.record(err)
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.L().Warnf("forwarding to %s failed: %v", w.target.Name, err)
			}
		}
	}
}

func (s *statsCell) record(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.failed.Add(1)
		s.lastError = err.Error()
		s.lastErrorAt = time.Now()
		return
	}
	s.sent.Add(1)
	s.lastSent = time.Now()
}

func (w *worker) deliver(ctx context.Context, e Event) error {
	switch w.target.Type {
	case "syslog":
		return w.sendSyslog(e)
	case "webhook":
		return w.sendWebhook(ctx, e)
	}
	return fmt.Errorf("unknown target type %s", w.target.Type)
}

func (w *worker) close() {
	if w.conn != nil {
		w.conn.Close()
		w.conn = nil
	}
}

// sendSyslog writes one RFC 5424 message. UDP sends a datagram; TCP and TLS
// keep a connection and frame messages with a trailing newline, redialing
// once if the connection broke.
func (w *worker) sendSyslog(e Event) error {
	body := string(e.JSON())
	if w.target.Format == "cef" {
		body = e.CEF()
	}
	msg := e.Syslog(w.target.Facility, body)
	t := w.target
	if t.Protocol == "udp" {
		conn, err := net.DialTimeout("udp", t.Address, sendTimeout)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(sendTimeout))
		_, err = conn.Write([]byte(msg))
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		if w.conn == nil {
			conn, err := w.dial()
			if err != nil {
				return err
			}
			w.conn = conn
		}
		_ = w.conn.SetWriteDeadline(time.Now().Add(sendTimeout))
		if _, err := w.conn.Write([]byte(msg + "\n")); err != nil {
			w.close()
			if attempt == 1 {
				return err
			}
			continue
		}
		return nil
	}
	return nil
}

func (w *worker) dial() (net.Conn, error) {
	d := &net.Dialer{Timeout: sendTimeout}
	if w.target.Protocol == "tls" {
		host, _, _ := net.SplitHostPort(w.target.Address)
		return tls.DialWithDialer(d, "tcp", w.target.Address, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	}
	return d.Dial("tcp", w.target.Address)
}

var webhookClient = &http.Client{Timeout: sendTimeout}

// retryDelays are the waits before webhook retries.
var retryDelays = []time.Duration{time.Second, 3 * time.Second}

// sendWebhook POSTs the JSON envelope. With a secret, the request carries
// X-FlowLens-Timestamp and X-FlowLens-Signature: sha256=<hex HMAC of
// "timestamp.body">, so receivers can check origin and freshness. 5xx and
// network errors are retried; 4xx is not.
func (w *worker) sendWebhook(ctx context.Context, e Event) error {
	body := e.JSON()
	var lastErr error
	for attempt := 0; attempt < webhookRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelays[attempt-1]):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.target.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "FlowLens-Forwarder")
		req.Header.Set("X-FlowLens-Event", e.Type)
		if w.target.Secret != "" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			req.Header.Set("X-FlowLens-Timestamp", ts)
			req.Header.Set("X-FlowLens-Signature", "sha256="+Sign(w.target.Secret, ts, body))
		}
		resp, err := webhookClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		switch {
		case resp.StatusCode < 300:
			return nil
		case resp.StatusCode < 500:
			return fmt.Errorf("webhook returned %d", resp.StatusCode)
		default:
			lastErr = fmt.Errorf("webhook returned %d", resp.StatusCode)
		}
	}
	return lastErr
}

// Sign returns the hex HMAC-SHA256 of "timestamp.body" with secret, as
// sent in X-FlowLens-Signature.
func Sign(secret, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp + "."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}
