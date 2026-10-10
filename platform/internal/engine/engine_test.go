package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// fakeClock is a manually advanced clock shared by the engine under test.
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock               { return &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func detectionEvents(t *testing.T, store storage.Store, typ string) []storage.AlertEvent {
	t.Helper()
	all, err := store.ListRecentAlerts(context.Background(), time.Time{}, 100000)
	if err != nil {
		t.Fatal(err)
	}
	var out []storage.AlertEvent
	for _, e := range all {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// ─── BOLA ──────────────────────────────────────────────────────

func newBOLA() (*BOLAEngine, storage.Store, *fakeClock) {
	store := storage.NewMemStore()
	e := NewBOLAEngine(store)
	clk := newFakeClock()
	e.now = clk.Now
	return e, store, clk
}

// traverse has the account access n distinct objects, one second apart,
// and returns the last score and reason.
func traverse(e *BOLAEngine, clk *fakeClock, account string, start, n int) (int, string) {
	var score int
	var reason string
	for i := start; i < start+n; i++ {
		score, reason = e.Evaluate(account, fmt.Sprintf("order-%d", i), "/api/orders/{id}", "10.0.0.1")
		clk.Advance(time.Second)
	}
	return score, reason
}

func TestBOLANormalUsageIsNotFlagged(t *testing.T) {
	e, store, clk := newBOLA()
	if score, _ := traverse(e, clk, "alice", 0, 10); score != 0 {
		t.Fatalf("10 objects scored %d, want 0", score)
	}
	// Re-reading the same object many times is not traversal.
	for i := 0; i < 200; i++ {
		if score, _ := e.Evaluate("alice", "order-1", "/api/orders/{id}", "10.0.0.1"); score != 0 {
			t.Fatalf("repeated access to one object scored %d", score)
		}
	}
	if n := len(detectionEvents(t, store, "BOLA")); n != 0 {
		t.Fatalf("stored %d BOLA events, want 0", n)
	}
}

func TestBOLAThresholdTriggers(t *testing.T) {
	e, store, clk := newBOLA()
	if score, _ := traverse(e, clk, "bob", 0, 19); score != 0 {
		t.Fatalf("19 objects scored %d, want 0 (threshold 20)", score)
	}
	score, reason := traverse(e, clk, "bob", 19, 1)
	if score != 70 || !strings.Contains(reason, "对象遍历") || !strings.Contains(reason, "阈值 20") {
		t.Fatalf("20 objects: score=%d reason=%q, want 70 at the threshold", score, reason)
	}
	if n := len(detectionEvents(t, store, "BOLA")); n != 1 {
		t.Fatalf("stored %d BOLA events, want 1", n)
	}
}

func TestBOLAScoreRisesWithTraversal(t *testing.T) {
	e, store, clk := newBOLA()
	// Twice the threshold: 70 + 30*(2-1)/2 = 85.
	if score, _ := traverse(e, clk, "mallory", 0, 40); score != 85 {
		t.Fatalf("40 objects scored %d, want 85", score)
	}
	evts := detectionEvents(t, store, "BOLA")
	if len(evts) == 0 || evts[len(evts)-1].AccountID != "mallory" || evts[len(evts)-1].SourceIP != "10.0.0.1" {
		t.Fatalf("missing or wrong BOLA event: %+v", evts)
	}
	// Capped at 100 from three times the threshold.
	if score, _ := traverse(e, clk, "mallory", 40, 200); score != 100 {
		t.Fatalf("heavy traversal scored %d, want 100", score)
	}
}

func TestBOLASlidingWindowExpires(t *testing.T) {
	e, _, clk := newBOLA()
	traverse(e, clk, "carol", 0, 30)
	clk.Advance(6 * time.Minute)
	if score, _ := traverse(e, clk, "carol", 30, 1); score != 0 {
		t.Fatalf("after window expiry scored %d, want 0", score)
	}
	if got := len(e.accountBase["carol"].WindowAccess); got != 1 {
		t.Fatalf("window holds %d accesses, want 1 after pruning", got)
	}
}

func TestBOLAConfigure(t *testing.T) {
	e, _, clk := newBOLA()
	e.Configure(Params{"window_minutes": 1.0, "traverse_threshold": 5.0})
	if score, _ := traverse(e, clk, "dave", 0, 5); score != 70 {
		t.Fatalf("5 objects with threshold 5 scored %d, want 70", score)
	}
	// One object every 20s: at most 3 in a one-minute window.
	e2, _, clk2 := newBOLA()
	e2.Configure(Params{"window_minutes": 1.0, "traverse_threshold": 5.0})
	for i := 0; i < 20; i++ {
		if score, _ := e2.Evaluate("erin", fmt.Sprintf("doc-%d", i), "/api/docs/{id}", "10.0.0.2"); score != 0 {
			t.Fatalf("slow access scored %d with a one-minute window", score)
		}
		clk2.Advance(20 * time.Second)
	}
	// Invalid values fall back to the defaults.
	e.Configure(Params{"window_minutes": 0.0, "traverse_threshold": -3.0})
	if e.window != 5*time.Minute || e.threshold != 20 {
		t.Fatalf("invalid config gave window=%v threshold=%d", e.window, e.threshold)
	}
}

func TestBOLAAccountsAreIsolated(t *testing.T) {
	e, _, clk := newBOLA()
	traverse(e, clk, "mallory", 0, 60)
	if score, _ := traverse(e, clk, "alice", 0, 5); score != 0 {
		t.Fatalf("alice scored %d because of mallory's traffic", score)
	}
}

// ─── Auth failure / credential stuffing ────────────────────────

func newAuth() (*AuthFailureEngine, storage.Store, *fakeClock) {
	store := storage.NewMemStore()
	e := NewAuthFailureEngine(store)
	clk := newFakeClock()
	e.now = clk.Now
	return e, store, clk
}

func fail(e *AuthFailureEngine, ip string, attempts, users int) {
	for i := 0; i < attempts; i++ {
		e.RecordFailure(ip, fmt.Sprintf("user-%d", i%users))
	}
}

func TestAuthUnknownIPIsClean(t *testing.T) {
	e, _, _ := newAuth()
	if score, _ := e.Evaluate("1.1.1.1"); score != 0 {
		t.Fatalf("unknown IP scored %d", score)
	}
}

func TestAuthCredentialStuffing(t *testing.T) {
	e, store, _ := newAuth()
	fail(e, "6.6.6.6", 20, 6) // threshold reached over 6 accounts
	score, reason := e.Evaluate("6.6.6.6")
	if score != 85 || !strings.Contains(reason, "撞库特征") || !strings.Contains(reason, "6 个不同账号") {
		t.Fatalf("score=%d reason=%q, want 85 credential stuffing", score, reason)
	}
	evts := detectionEvents(t, store, "CREDENTIAL_STUFFING")
	if len(evts) != 1 || evts[0].SourceIP != "6.6.6.6" || evts[0].Severity != "high" {
		t.Fatalf("unexpected events: %+v", evts)
	}
}

func TestAuthHeavyStuffingIsCritical(t *testing.T) {
	e, store, _ := newAuth()
	fail(e, "6.6.6.7", 100, 10) // five times the threshold
	if score, _ := e.Evaluate("6.6.6.7"); score != 100 {
		t.Fatalf("score=%d, want 100", score)
	}
	if evts := detectionEvents(t, store, "CREDENTIAL_STUFFING"); len(evts) != 1 || evts[0].Severity != "critical" {
		t.Fatalf("unexpected events: %+v", evts)
	}
}

func TestAuthBruteForceOnOneAccount(t *testing.T) {
	e, store, _ := newAuth()
	fail(e, "7.7.7.7", 25, 1)
	score, reason := e.Evaluate("7.7.7.7")
	if score != 75 || !strings.Contains(reason, "暴力破解") {
		t.Fatalf("score=%d reason=%q, want 75 brute force", score, reason)
	}
	if n := len(detectionEvents(t, store, "BRUTE_FORCE")); n != 1 {
		t.Fatalf("stored %d brute-force events, want 1", n)
	}
}

func TestAuthBelowThresholdIsClean(t *testing.T) {
	e, _, _ := newAuth()
	fail(e, "8.8.8.8", 19, 6)
	if score, _ := e.Evaluate("8.8.8.8"); score != 0 {
		t.Fatalf("19 failures scored %d, want 0 (threshold 20)", score)
	}
	fail(e, "8.8.8.9", 10, 1) // a user mistyping a few times
	if score, _ := e.Evaluate("8.8.8.9"); score != 0 {
		t.Fatalf("10 failures on one account scored %d", score)
	}
}

func TestAuthWindowSlides(t *testing.T) {
	e, _, clk := newAuth()
	fail(e, "9.9.9.9", 20, 6)
	clk.Advance(11 * time.Minute) // all failures fall out of the 10-minute window
	if score, _ := e.Evaluate("9.9.9.9"); score != 0 {
		t.Fatalf("expired failures scored %d, want 0", score)
	}
	fail(e, "9.9.9.9", 1, 1)
	if n := len(e.failTracker["9.9.9.9"].Failures); n != 1 {
		t.Fatalf("tracker holds %d failures, want 1 after pruning", n)
	}
}

func TestAuthConfigure(t *testing.T) {
	e, _, _ := newAuth()
	e.Configure(Params{"window_minutes": 1.0, "fail_count": 5.0, "unique_accounts": 2.0})
	fail(e, "4.4.4.4", 5, 2)
	if score, reason := e.Evaluate("4.4.4.4"); score != 85 || !strings.Contains(reason, "1 分钟") {
		t.Fatalf("score=%d reason=%q, want 85 with a one-minute window", score, reason)
	}
}

func TestAuthConcurrentRecordAndEvaluate(t *testing.T) {
	e, _, _ := newAuth()
	e.now = time.Now // the fake clock is not goroutine-safe
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				e.RecordFailure("5.5.5.5", fmt.Sprintf("u%d", i%20))
				e.Evaluate("5.5.5.5")
			}
		}()
	}
	wg.Wait()
}

// ─── BFLA ──────────────────────────────────────────────────────

func newBFLA() (*BFLAEngine, storage.Store) {
	store := storage.NewMemStore()
	return NewBFLAEngine(store), store
}

func TestBFLAIgnoresNonAdminEndpoints(t *testing.T) {
	e, _ := newBFLA()
	e.RecordAccess("u1", "user", "/api/orders")
	if score, _ := e.Evaluate("u1", "user", "/api/orders"); score != 0 {
		t.Fatalf("non-admin endpoint scored %d", score)
	}
}

func TestBFLAUnseenEndpointIsNotScored(t *testing.T) {
	e, _ := newBFLA()
	if score, _ := e.Evaluate("u1", "user", "/admin/users"); score != 0 {
		t.Fatalf("admin endpoint with no history scored %d", score)
	}
}

func TestBFLARareRoleOnAdminEndpoint(t *testing.T) {
	e, store := newBFLA()
	for i := 0; i < 100; i++ {
		e.RecordAccess("root", "admin", "/api/v1/admin/users")
	}
	if score, _ := e.Evaluate("root", "admin", "/api/v1/admin/users"); score != 0 {
		t.Fatalf("usual admin role scored %d", score)
	}

	e.RecordAccess("eve", "user", "/api/v1/admin/users") // 1 of 101 < 5%
	score, reason := e.Evaluate("eve", "user", "/api/v1/admin/users")
	if score != 75 || !strings.Contains(reason, "user") {
		t.Fatalf("rare role: score=%d reason=%q, want 75", score, reason)
	}
	evts := detectionEvents(t, store, "BFLA")
	if len(evts) != 1 || evts[0].AccountID != "eve" {
		t.Fatalf("unexpected BFLA events: %+v", evts)
	}
}

func TestBOLAStoredEventsAreThrottled(t *testing.T) {
	e, store, clk := newBOLA()
	traverse(e, clk, "mallory", 0, 120) // over 2 minutes, score >= 70 from object 21 on
	if n := len(detectionEvents(t, store, "BOLA")); n != 1 {
		t.Fatalf("stored %d BOLA events during one burst, want 1", n)
	}
	clk.Advance(eventCooldown)
	traverse(e, clk, "mallory", 1000, 60)
	if n := len(detectionEvents(t, store, "BOLA")); n != 2 {
		t.Fatalf("stored %d BOLA events after cooldown, want 2", n)
	}
}

func TestAuthStoredEventsAreThrottled(t *testing.T) {
	e, store, _ := newAuth()
	fail(e, "6.6.6.6", 30, 6)
	for i := 0; i < 5; i++ {
		if score, _ := e.Evaluate("6.6.6.6"); score < 70 {
			t.Fatalf("score %d, want >= 70 on every evaluation", score)
		}
	}
	if n := len(detectionEvents(t, store, "CREDENTIAL_STUFFING")); n != 1 {
		t.Fatalf("stored %d events, want 1", n)
	}
}

func TestBFLAPrivilegedRolesAreNotFlagged(t *testing.T) {
	e, store := newBFLA()
	for _, role := range []string{"admin", "Super_Admin", "security_admin"} {
		e.RecordAccess("ops", role, "/admin/users")
		if score, _ := e.Evaluate("ops", role, "/admin/users"); score != 0 {
			t.Fatalf("privileged role %q scored %d", role, score)
		}
	}
	if n := len(detectionEvents(t, store, "BFLA")); n != 0 {
		t.Fatalf("stored %d BFLA events for privileged roles", n)
	}
}

func TestBFLAColdStartFlagsOrdinaryRoles(t *testing.T) {
	e, _ := newBFLA()
	e.RecordAccess("eve", "user", "/actuator/env")
	score, reason := e.Evaluate("eve", "user", "/actuator/env")
	if score != 75 || !strings.Contains(reason, "基线不足") {
		t.Fatalf("score=%d reason=%q, want 75 with cold-start reason", score, reason)
	}
}

func TestBFLACommonRoleIsNotFlagged(t *testing.T) {
	e, _ := newBFLA()
	for i := 0; i < 20; i++ {
		e.RecordAccess(fmt.Sprintf("svc-%d", i), "service", "/actuator/health")
	}
	if score, _ := e.Evaluate("svc-1", "service", "/actuator/health"); score != 0 {
		t.Fatalf("role with 100%% share scored %d", score)
	}
}

func TestBFLAAdminPrefixMatchesWholeSegments(t *testing.T) {
	for path, want := range map[string]bool{
		"/admin":               true,
		"/admin/users":         true,
		"/api/v1/admin/config": true,
		"/administrator-guide": false,
		"/adminx":              false,
		"/api/orders":          false,
	} {
		if got := NewBFLAEngine(storage.NewMemStore()).IsAdminEndpoint(path); got != want {
			t.Errorf("IsAdminEndpoint(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestBFLAConfigure(t *testing.T) {
	e, _ := newBFLA()
	e.Configure(Params{"admin_endpoints": "/ops/", "privileged_roles": "ops_admin"})
	if e.IsAdminEndpoint("/admin/users") || !e.IsAdminEndpoint("/ops/restart") {
		t.Fatalf("custom management prefixes not applied")
	}
	e.RecordAccess("o", "ops_admin", "/ops/restart")
	if score, _ := e.Evaluate("o", "ops_admin", "/ops/restart"); score != 0 {
		t.Fatalf("configured privileged role scored %d", score)
	}
	// "admin" is no longer privileged once the list is replaced.
	e.RecordAccess("a", "admin", "/ops/restart")
	if score, _ := e.Evaluate("a", "admin", "/ops/restart"); score != 75 {
		t.Fatalf("admin outside the configured list scored %d, want 75", score)
	}
}

func TestBFLABaselineAndShare(t *testing.T) {
	e, _ := newBFLA()
	e.Configure(Params{"min_baseline": 3.0, "rare_share": 0.3})
	for i := 0; i < 7; i++ {
		e.RecordAccess("root", "admin", "/admin/users")
	}
	for i := 0; i < 3; i++ {
		e.RecordAccess("ops", "operator", "/admin/users")
	}
	// operator is 3 of 10 = 30%, not under the 30% threshold.
	if score, _ := e.Evaluate("ops", "operator", "/admin/users"); score != 0 {
		t.Fatalf("30%% share scored %d with rare_share 0.3", score)
	}
	e.Configure(Params{"min_baseline": 3.0, "rare_share": 0.31})
	if score, _ := e.Evaluate("ops", "operator", "/admin/users"); score != 75 {
		t.Fatalf("30%% share scored %d with rare_share 0.31, want 75", score)
	}
}

func TestBFLAStrictMode(t *testing.T) {
	e, _ := newBFLA()
	for i := 0; i < 20; i++ {
		e.RecordAccess(fmt.Sprintf("svc-%d", i), "service", "/actuator/health")
	}
	if score, _ := e.Evaluate("svc-1", "service", "/actuator/health"); score != 0 {
		t.Fatalf("common role scored %d without strict mode", score)
	}
	e.Configure(Params{"strict_mode": true})
	score, reason := e.Evaluate("svc-1", "service", "/actuator/health")
	if score != 75 || !strings.Contains(reason, "严格模式") {
		t.Fatalf("strict mode: score=%d reason=%q", score, reason)
	}
}

func TestBFLAStoredEventsAreThrottled(t *testing.T) {
	e, store := newBFLA()
	for i := 0; i < 5; i++ {
		e.RecordAccess("eve", "user", "/admin/users")
		e.Evaluate("eve", "user", "/admin/users")
	}
	if n := len(detectionEvents(t, store, "BFLA")); n != 1 {
		t.Fatalf("stored %d BFLA events, want 1", n)
	}
}
