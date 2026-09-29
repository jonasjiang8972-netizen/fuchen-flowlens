package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/sensitive"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// ─── DLP ───────────────────────────────────────────────────────

func TestDLPMaskingDefect(t *testing.T) {
	store := storage.NewMemStore()
	e := NewDLPEngine(store, 5)
	f := sensitive.ScanText(`{"id":"11010519491231002X","phone":"13812345678"}`)

	res := e.Evaluate("/api/v1/users/{id}", "alice", "10.0.0.1", f)
	if !res.MaskingDefect || res.Score < 80 {
		t.Fatalf("two unmasked types scored %d, defect=%v", res.Score, res.MaskingDefect)
	}
	if !strings.Contains(res.Reason, "身份证号") || !strings.Contains(res.Reason, "手机号") {
		t.Fatalf("reason lacks types: %s", res.Reason)
	}
	if strings.Contains(res.Reason, "11010519491231002X") {
		t.Fatal("value leaked into reason")
	}
	// Cooldown: the second hit still scores but stores no second event.
	e.Evaluate("/api/v1/users/{id}", "alice", "10.0.0.1", f)
	if n := len(detectionEvents(t, store, "DLP")); n != 1 {
		t.Fatalf("stored %d DLP events, want 1", n)
	}
}

func TestDLPProperlyMaskedIsQuiet(t *testing.T) {
	e := NewDLPEngine(storage.NewMemStore(), 5)
	f := sensitive.ScanText(`{"phone":"138****5678","card":"622202******1234"}`)
	if res := e.Evaluate("/api/x", "a", "1.1.1.1", f); res.Score != 0 {
		t.Fatalf("masked data scored %d", res.Score)
	}
}

func TestDLPBulkExposureEvenWhenMasked(t *testing.T) {
	e := NewDLPEngine(storage.NewMemStore(), 5)
	f := sensitive.ScanText(strings.Repeat(`"138****5678",`, 6))
	res := e.Evaluate("/api/export", "a", "1.1.1.1", f)
	if res.Score != 70 || res.MaskingDefect {
		t.Fatalf("bulk masked: score %d defect %v", res.Score, res.MaskingDefect)
	}
}

func TestDLPEmailAloneIsNotADefect(t *testing.T) {
	e := NewDLPEngine(storage.NewMemStore(), 5)
	f := sensitive.ScanText(`{"email":"a@example.com"}`)
	if res := e.Evaluate("/api/x", "a", "1.1.1.1", f); res.Score != 0 {
		t.Fatalf("email scored %d", res.Score)
	}
}

// ─── Bot ───────────────────────────────────────────────────────

func newBot() (*BotEngine, storage.Store, *fakeClock) {
	store := storage.NewMemStore()
	e := NewBotEngine(store)
	clk := newFakeClock()
	e.now = clk.Now
	return e, store, clk
}

const chrome = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"

func TestBotHumanBrowsingIsNotFlagged(t *testing.T) {
	e, store, clk := newBot()
	// Irregular gaps, browser headers, ordinary UA.
	gaps := []int{3, 11, 2, 27, 5, 8, 19, 4, 13, 6, 9, 31}
	for _, g := range gaps {
		clk.Advance(time.Duration(g) * time.Second)
		if score, _ := e.Observe(BotRequest{SourceIP: "10.0.0.5", UserAgent: chrome, Browserlike: true}); score != 0 {
			t.Fatalf("human scored %d", score)
		}
	}
	if n := len(detectionEvents(t, store, "BOT")); n != 0 {
		t.Fatalf("stored %d BOT events", n)
	}
}

func TestBotScriptedClientIsFlagged(t *testing.T) {
	e, store, clk := newBot()
	var score int
	var reason string
	for i := 0; i < 20; i++ {
		clk.Advance(500 * time.Millisecond)
		score, reason = e.Observe(BotRequest{SourceIP: "10.0.0.9", UserAgent: "python-requests/2.31"})
	}
	// UA 30 + regular interval 40 + no browser headers 10.
	if score != 80 {
		t.Fatalf("scripted client scored %d (%s), want 80", score, reason)
	}
	if n := len(detectionEvents(t, store, "BOT")); n != 1 {
		t.Fatalf("stored %d BOT events, want 1 (cooldown)", n)
	}
}

func TestBotRegularIntervalWithBrowserUAStillFlagged(t *testing.T) {
	e, _, clk := newBot()
	var score int
	for i := 0; i < 15; i++ {
		clk.Advance(2 * time.Second)
		score, _ = e.Observe(BotRequest{SourceIP: "10.0.0.7", UserAgent: chrome, Browserlike: true})
	}
	if score != 40 {
		t.Fatalf("spoofed-UA script scored %d, want 40 (interval only)", score)
	}
}

func TestBotBurst(t *testing.T) {
	e, _, clk := newBot()
	var score int
	for i := 0; i < 150; i++ {
		clk.Advance(time.Duration(200+(i%7)*90) * time.Millisecond) // irregular but fast
		score, _ = e.Observe(BotRequest{SourceIP: "10.0.0.8", UserAgent: chrome, Browserlike: true})
	}
	if score < 30 {
		t.Fatalf("burst scored %d, want >= 30", score)
	}
}

func TestBotJA3KeysTheClientAcrossIPs(t *testing.T) {
	e, _, clk := newBot()
	e.SetKnownJA3([]string{"AAAA"})
	score, reason := e.Observe(BotRequest{SourceIP: "1.1.1.1", UserAgent: chrome, JA3: "aaaa", Browserlike: true})
	if score != 40 || !strings.Contains(reason, "TLS 指纹") {
		t.Fatalf("deny-listed JA3: %d %s", score, reason)
	}
	// Same fingerprint from many IPs shares one history.
	for i := 0; i < 12; i++ {
		clk.Advance(time.Second)
		score, _ = e.Observe(BotRequest{SourceIP: fmt.Sprintf("2.2.2.%d", i), UserAgent: chrome, JA3: "bbbb", Browserlike: true})
	}
	if score != 40 {
		t.Fatalf("rotating IPs behind one JA3 scored %d, want 40", score)
	}
}

func TestBotClientTableIsBounded(t *testing.T) {
	e, _, _ := newBot()
	for i := 0; i < maxBotClients+500; i++ {
		e.Observe(BotRequest{SourceIP: fmt.Sprintf("ip-%d", i), UserAgent: chrome, Browserlike: true})
	}
	if len(e.clients) > maxBotClients {
		t.Fatalf("%d clients tracked, cap %d", len(e.clients), maxBotClients)
	}
}
