package forward

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

type memSettings struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memSettings) GetSetting(_ context.Context, k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return nil, storage.ErrNotFound // as the real stores do
	}
	return v, nil
}

func (s *memSettings) PutSetting(_ context.Context, k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[k] = v
	return nil
}

func init() { _ = logger.Init(false) }

func TestValidate(t *testing.T) {
	bad := []Target{
		{Name: "", Type: "syslog", Address: "1.2.3.4:514", Events: []string{EventAudit}},
		{Name: "a", Type: "syslog", Address: "no-port", Events: []string{EventAudit}},
		{Name: "a", Type: "syslog", Address: "1.2.3.4:514", Protocol: "smtp", Events: []string{EventAudit}},
		{Name: "a", Type: "webhook", URL: "ftp://x", Events: []string{EventAudit}},
		{Name: "a", Type: "webhook", URL: "https://x", Events: nil},
		{Name: "a", Type: "webhook", URL: "https://x", Events: []string{"everything"}},
		{Name: "a", Type: "webhook", URL: "https://x", Events: []string{EventAlertCreated}, MinSeverity: "urgent"},
		{Name: "a", Type: "mail", Events: []string{EventAudit}},
	}
	for i, tg := range bad {
		c := Config{Targets: []Target{tg}}
		if err := c.Validate(); err == nil {
			t.Errorf("case %d accepted: %+v", i, tg)
		}
	}
	c := Config{Targets: []Target{{Name: "siem", Type: "syslog", Address: "10.0.0.5:514", Events: []string{EventAudit}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	got := c.Targets[0]
	if got.ID == "" || got.Protocol != "udp" || got.Format != "json" || got.Facility != 13 || got.MinSeverity != "low" {
		t.Fatalf("defaults: %+v", got)
	}
}

func TestFormats(t *testing.T) {
	e := Event{Type: EventAlertCreated, Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Severity: "critical",
		Title: "SSRF | 告警", Fields: map[string]string{"source_ip": "198.51.100.1", "requirement": "FR-DET-007", "reason": "a=b", "alert_id": "alt-1", "rule": "R-SSRF-001"}}
	var env map[string]any
	if err := json.Unmarshal(e.JSON(), &env); err != nil || env["type"] != EventAlertCreated || env["product"] != "FlowLens" {
		t.Fatalf("json: %s", e.JSON())
	}
	cef := e.CEF()
	for _, want := range []string{"CEF:0|FlowLens|FlowLens API Security|", "|FR-DET-007|SSRF \\| 告警|10|", "src=198.51.100.1", `reason=a\=b`, "externalId=alt-1", `msg=requirement\=FR-DET-007 rule\=R-SSRF-001`} {
		if !strings.Contains(cef, want) {
			t.Errorf("cef %q missing %q", cef, want)
		}
	}
	sl := e.Syslog(13, "body")
	if !strings.HasPrefix(sl, "<106>1 2026-01-02T03:04:05Z ") || !strings.HasSuffix(sl, " flowlens - alert_created - body") {
		t.Fatalf("syslog: %q", sl)
	}
}

func TestWebhookDeliverySignatureAndRetry(t *testing.T) {
	retryDelays = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	var mu sync.Mutex
	calls := 0
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 { // first attempt fails, retried
			w.WriteHeader(503)
			return
		}
		want := "sha256=" + Sign("k3y", r.Header.Get("X-FlowLens-Timestamp"), body)
		if r.Header.Get("X-FlowLens-Signature") != want || r.Header.Get("X-FlowLens-Event") == "" {
			w.WriteHeader(401)
			return
		}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		got = append(got, m)
	}))
	defer srv.Close()

	f := New(&memSettings{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := f.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Update(ctx, Config{Targets: []Target{{ID: "w1", Name: "soar", Type: "webhook", Enabled: true, URL: srv.URL,
		Secret: "k3y", Events: []string{EventAlertHandled, EventAlertCreated}, MinSeverity: "high"}}}); err != nil {
		t.Fatal(err)
	}
	f.Publish(Event{Type: EventAlertCreated, Severity: "medium", Title: "filtered by severity"})
	f.Publish(Event{Type: EventAudit, Severity: "info", Title: "not subscribed"})
	f.Publish(Event{Type: EventAlertHandled, Severity: "high", Title: "block", Fields: map[string]string{"action": "ip_block"}})

	deadline := time.Now().Add(3 * time.Second)
	for {
		if st := f.Stats()["w1"]; st.Sent == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not delivered: %+v calls=%d", f.Stats()["w1"], calls)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0]["title"] != "block" || calls != 2 {
		t.Fatalf("got=%v calls=%d", got, calls)
	}
}

func TestWebhookClientErrorIsNotRetried(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(400)
	}))
	defer srv.Close()
	f := New(nil)
	err := f.Test(context.Background(), Target{Name: "t", Type: "webhook", URL: srv.URL, Events: []string{EventAudit}})
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestSyslogUDPAndTCP(t *testing.T) {
	// UDP
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	f := New(nil)
	if err := f.Test(context.Background(), Target{Name: "udp", Type: "syslog", Address: pc.LocalAddr().String(), Format: "cef", Events: []string{EventAudit}}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "CEF:0|FlowLens|") || !strings.HasPrefix(string(buf[:n]), "<110>1 ") {
		t.Fatalf("udp got %q err=%v", buf[:n], err)
	}

	// TCP through a running worker: two messages over one connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f2 := New(&memSettings{})
	_ = f2.Start(ctx)
	if _, err := f2.Update(ctx, Config{Targets: []Target{{ID: "s1", Name: "soc", Type: "syslog", Enabled: true, Address: ln.Addr().String(), Protocol: "tcp", Events: []string{EventAudit}}}}); err != nil {
		t.Fatal(err)
	}
	f2.Publish(Event{Type: EventAudit, Severity: "info", Title: "auth.login", Fields: map[string]string{"event_type": "auth.login"}})
	f2.Publish(Event{Type: EventAudit, Severity: "info", Title: "user.create"})
	for i, want := range []string{"auth.login", "user.create"} {
		select {
		case l := <-lines:
			if !strings.Contains(l, want) || !strings.Contains(l, `"product":"FlowLens"`) {
				t.Fatalf("line %d: %q", i, l)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("tcp message %d not received", i)
		}
	}
}

func TestSecretsMaskedAndKept(t *testing.T) {
	st := &memSettings{}
	f := New(st)
	ctx := context.Background()
	_ = f.Start(ctx)
	if _, err := f.Update(ctx, Config{Targets: []Target{{ID: "w", Name: "w", Type: "webhook", URL: "https://soar.example/hook", Secret: "s3cret", Events: []string{EventAudit}}}}); err != nil {
		t.Fatal(err)
	}
	masked := f.Config().Masked()
	if masked.Targets[0].Secret != maskedSecret {
		t.Fatalf("secret not masked: %+v", masked.Targets[0])
	}
	// Sending the masked config back keeps the secret.
	if _, err := f.Update(ctx, masked); err != nil {
		t.Fatal(err)
	}
	if f.Config().Targets[0].Secret != "s3cret" {
		t.Fatalf("secret lost: %q", f.Config().Targets[0].Secret)
	}
	// Reload from storage.
	f2 := New(st)
	_ = f2.Start(ctx)
	if got := f2.Config(); len(got.Targets) != 1 || got.Targets[0].Secret != "s3cret" {
		t.Fatalf("reload: %+v", got)
	}
}

func TestPublishNeverBlocks(t *testing.T) {
	// A target that never accepts: its queue fills and further events drop.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	f := New(&memSettings{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = f.Start(ctx)
	_, _ = f.Update(ctx, Config{Targets: []Target{{ID: "x", Name: "x", Type: "webhook", Enabled: true, URL: "http://" + ln.Addr().String(), Events: []string{EventAudit}}}})
	start := time.Now()
	for i := 0; i < queueSize*2; i++ {
		f.Publish(Event{Type: EventAudit, Severity: "info"})
	}
	if time.Since(start) > time.Second {
		t.Fatal("Publish blocked")
	}
	if f.Stats()["x"].Dropped == 0 {
		t.Fatal("overflow not counted")
	}
}
