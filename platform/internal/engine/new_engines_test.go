package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// ─── Bot ───────────────────────────────────────────────────────

func newBot() (*BotEngine, storage.Store, *fakeClock) {
	store := storage.NewMemStore()
	e := NewBotEngine(store)
	clk := newFakeClock()
	e.now = clk.Now
	return e, store, clk
}

func TestBotBurst(t *testing.T) {
	e, store, clk := newBot()
	var score int
	var reason string
	for i := 0; i < 120; i++ {
		// Irregular gaps: only the burst can trigger.
		clk.Advance(time.Duration(50+(i*37)%400) * time.Millisecond)
		score, reason = e.Evaluate("ip:1.2.3.4", "1.2.3.4", time.Time{})
		if i < 119 && score != 0 {
			t.Fatalf("request %d scored %d before the burst threshold", i+1, score)
		}
	}
	if score != 70 || !strings.Contains(reason, "请求爆发") {
		t.Fatalf("120 requests in under a minute: score=%d reason=%q", score, reason)
	}
	if n := len(detectionEvents(t, store, "BOT")); n != 1 {
		t.Fatalf("stored %d bot events, want 1", n)
	}
}

func TestBotRegularRhythm(t *testing.T) {
	e, _, clk := newBot()
	var score int
	var reason string
	for i := 0; i < 31; i++ { // 30 intervals of exactly 2s
		clk.Advance(2 * time.Second)
		score, reason = e.Evaluate("partner:abcd", "", time.Time{})
	}
	if score != 70 || !strings.Contains(reason, "请求间隔规律") {
		t.Fatalf("metronomic requests: score=%d reason=%q", score, reason)
	}
}

func TestBotHumanTrafficIsClean(t *testing.T) {
	e, _, clk := newBot()
	gaps := []time.Duration{3 * time.Second, 800 * time.Millisecond, 12 * time.Second, 1500 * time.Millisecond, 6 * time.Second}
	for i := 0; i < 100; i++ {
		clk.Advance(gaps[i%len(gaps)])
		if score, reason := e.Evaluate("alice", "", time.Time{}); score != 0 {
			t.Fatalf("human-like traffic scored %d: %s", score, reason)
		}
	}
}

func TestBotMachineSpeedGapsAreNotRhythm(t *testing.T) {
	e, _, clk := newBot()
	for i := 0; i < 60; i++ { // 1ms apart: a batch, below the burst threshold
		clk.Advance(time.Millisecond)
		if score, _ := e.Evaluate("svc:batch", "", time.Time{}); score != 0 {
			t.Fatalf("batched requests scored %d", score)
		}
	}
}

func TestBotUsesEventTimestamps(t *testing.T) {
	e, _, clk := newBot()
	// Events arrive together (one flush) but carry 2s-spaced timestamps.
	base := clk.Now().Add(-2 * time.Minute)
	var score int
	for i := 0; i < 31; i++ {
		score, _ = e.Evaluate("crawler", "", base.Add(time.Duration(i)*2*time.Second))
	}
	if score != 70 {
		t.Fatalf("spaced event timestamps scored %d, want 70", score)
	}
	// A timestamp far from the clock is not trusted.
	e2, _, _ := newBot()
	for i := 0; i < 31; i++ {
		score, _ = e2.Evaluate("old", "", base.Add(-time.Hour+time.Duration(i)*2*time.Second))
	}
	if score != 0 {
		t.Fatalf("skewed timestamps scored %d", score)
	}
}

func TestBotConfigure(t *testing.T) {
	e, _, clk := newBot()
	e.Configure(Params{"burst_threshold": 10.0})
	var score int
	for i := 0; i < 10; i++ {
		clk.Advance(time.Duration(200+i*90) * time.Millisecond)
		score, _ = e.Evaluate("x", "", time.Time{})
	}
	if score != 70 {
		t.Fatalf("burst threshold 10 not applied: %d", score)
	}
}

// ─── Rate ──────────────────────────────────────────────────────

func newRate() (*RateEngine, storage.Store, *fakeClock) {
	store := storage.NewMemStore()
	e := NewRateEngine(store)
	clk := newFakeClock()
	e.now = clk.Now
	return e, store, clk
}

// window sends n requests spread over one minute and returns the last
// result.
func rateWindow(e *RateEngine, clk *fakeClock, endpoint string, n int) (int, string, string) {
	var score int
	var reason, top string
	step := time.Minute / time.Duration(n+1)
	for i := 0; i < n; i++ {
		clk.Advance(step)
		ip := fmt.Sprintf("10.0.0.%d", i%3)
		if i%2 == 0 {
			ip = "203.0.113.7"
		}
		score, reason, top = e.Evaluate(endpoint, ip, time.Time{})
	}
	clk.Advance(step)
	return score, reason, top
}

func TestRateNeedsBaseline(t *testing.T) {
	e, _, clk := newRate()
	// A busy endpoint with no history is not a surge.
	if score, _, _ := rateWindow(e, clk, "GET /api/a", 2000); score != 0 {
		t.Fatalf("first window scored %d", score)
	}
}

func TestRateSurge(t *testing.T) {
	e, store, clk := newRate()
	for w := 0; w < 4; w++ {
		if score, _, _ := rateWindow(e, clk, "GET /api/orders", 100); score != 0 {
			t.Fatalf("baseline window %d scored %d", w, score)
		}
	}
	score, reason, top := rateWindow(e, clk, "GET /api/orders", 1000)
	if score < 70 || !strings.Contains(reason, "流量突增") || top != "203.0.113.7" {
		t.Fatalf("10x surge: score=%d top=%q reason=%q", score, top, reason)
	}
	if n := len(detectionEvents(t, store, "RATE_ANOMALY")); n != 1 {
		t.Fatalf("stored %d rate events, want 1", n)
	}
	// The surge window is not folded into the baseline.
	if b := e.endpoints["GET /api/orders"].baseline; b > 150 {
		t.Fatalf("baseline rose to %.0f during a surge", b)
	}
}

func TestRateMinRequests(t *testing.T) {
	e, _, clk := newRate()
	for w := 0; w < 4; w++ {
		rateWindow(e, clk, "GET /api/rare", 5)
	}
	// 20x the baseline, but under 300 requests.
	if score, _, _ := rateWindow(e, clk, "GET /api/rare", 100); score != 0 {
		t.Fatalf("low-volume spike scored %d", score)
	}
}

func TestRateIdleGapLowersBaseline(t *testing.T) {
	e, _, clk := newRate()
	for w := 0; w < 4; w++ {
		rateWindow(e, clk, "GET /api/b", 1000)
	}
	clk.Advance(30 * time.Minute)
	rateWindow(e, clk, "GET /api/b", 10)
	if b := e.endpoints["GET /api/b"].baseline; b > 100 {
		t.Fatalf("baseline %.0f ignores 30 idle minutes", b)
	}
}

func TestRateConfigureResetsOnWindowChange(t *testing.T) {
	e, _, clk := newRate()
	for w := 0; w < 4; w++ {
		rateWindow(e, clk, "GET /api/c", 100)
	}
	e.Configure(Params{"window_minutes": 1.0, "multiplier": 2.0, "min_requests": 50.0})
	if len(e.endpoints) != 1 {
		t.Fatalf("same window must keep baselines")
	}
	if score, _, _ := rateWindow(e, clk, "GET /api/c", 250); score < 70 {
		t.Fatalf("2.5x with multiplier 2 scored %d", score)
	}
	e.Configure(Params{"window_minutes": 5.0})
	if len(e.endpoints) != 0 {
		t.Fatalf("window change kept %d baselines", len(e.endpoints))
	}
}

// ─── SSRF ──────────────────────────────────────────────────────

func TestSSRFClassification(t *testing.T) {
	e := NewSSRFEngine(storage.NewMemStore())
	cases := []struct {
		name, value string
		want        int
	}{
		{"url", "http://169.254.169.254/latest/meta-data/", 95},
		{"q", "http://100.100.100.200/latest/meta-data", 95},
		{"callback", "https://metadata.google.internal/computeMetadata/v1/", 95},
		{"src", "file:///etc/passwd", 85},
		{"anything", "gopher://example.com:70/_x", 85},
		{"url", "http://10.1.2.3:8080/admin", 75},
		{"url", "http://127.0.0.1/", 75},
		{"url", "http://2130706433/", 75}, // decimal 127.0.0.1
		{"url", "http://0x7f000001/", 75}, // hex 127.0.0.1
		{"url", "http://[::1]/", 75},
		{"url", "http://localhost:6379/", 75},
		{"url", "http://user@192.168.1.1/", 75},
		{"target", "192.168.0.10:22", 75}, // bare address in a target param
		{"client_ip", "10.1.2.3", 0},      // bare address elsewhere is data
		{"app_version", "10.2.3.4", 0},
		{"order_id", "2130706433", 0}, // a number is not a host
		{"url", "https://www.example.com/a?b=c", 0},
		{"next", "/dashboard", 0},
		{"q", "how to use http", 0},
	}
	for _, c := range cases {
		got, why := e.classify(c.name, c.value)
		if got != c.want {
			t.Errorf("%s=%q scored %d (%s), want %d", c.name, c.value, got, why, c.want)
		}
	}
}

func TestSSRFEvaluateQueryAndBody(t *testing.T) {
	store := storage.NewMemStore()
	e := NewSSRFEngine(store)
	score, reason := e.Evaluate("/api/v1/preview", "198.51.100.4",
		map[string]string{"page": "1", "url": "http://10.0.0.5/"},
		[]byte(`{"hook":{"webhook":"http://169.254.169.254/latest/"}}`))
	if score != 95 || !strings.Contains(reason, "webhook") {
		t.Fatalf("score=%d reason=%q, want the metadata URL from the body", score, reason)
	}
	if evts := detectionEvents(t, store, "SSRF"); len(evts) != 1 || evts[0].Severity != "critical" {
		t.Fatalf("events: %+v", evts)
	}
	if score, _ := e.Evaluate("/api/v1/search", "", map[string]string{"q": "phone"}, nil); score != 0 {
		t.Fatalf("plain query scored %d", score)
	}
}

func TestSSRFConfigure(t *testing.T) {
	e := NewSSRFEngine(storage.NewMemStore())
	e.Configure(Params{"internal_nets": "100.64.0.0/10, not-a-cidr", "metadata_hosts": "meta.internal", "blocked_schemes": "ftp"})
	if s, _ := e.classify("url", "http://100.64.1.1/"); s != 75 {
		t.Errorf("custom internal net: %d", s)
	}
	if s, _ := e.classify("url", "http://10.0.0.1/"); s != 0 {
		t.Errorf("replaced internal nets still match 10/8: %d", s)
	}
	if s, _ := e.classify("url", "http://META.internal/x"); s != 95 {
		t.Errorf("custom metadata host: %d", s)
	}
	if s, _ := e.classify("url", "file:///etc/passwd"); s != 0 {
		t.Errorf("file scheme no longer blocked: %d", s)
	}
}
