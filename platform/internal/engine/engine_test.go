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
	all, err := store.ListRecentAlerts(context.Background(), time.Time{})
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

func TestBOLAMediumTraversal(t *testing.T) {
	e, store, clk := newBOLA()
	if score, _ := traverse(e, clk, "bob", 0, 20); score != 0 {
		t.Fatalf("20 objects scored %d, want 0 (threshold is > 20)", score)
	}
	// 21 unique objects in 5 min: rate 4.2/min -> 60 + int(2.2*5) = 71
	score, reason := traverse(e, clk, "bob", 20, 1)
	if score != 71 || !strings.Contains(reason, "中等遍历") {
		t.Fatalf("21 objects: score=%d reason=%q, want 71 medium traversal", score, reason)
	}
	if n := len(detectionEvents(t, store, "BOLA")); n != 1 {
		t.Fatalf("stored %d BOLA events, want 1", n)
	}
}

func TestBOLAHighTraversal(t *testing.T) {
	e, store, clk := newBOLA()
	// 51 unique objects in 5 min: rate 10.2/min -> 80 + int(5.2*2) = 90
	score, reason := traverse(e, clk, "mallory", 0, 51)
	if score != 90 || !strings.Contains(reason, "高遍历速率") {
		t.Fatalf("51 objects: score=%d reason=%q, want 90 high traversal", score, reason)
	}
	evts := detectionEvents(t, store, "BOLA")
	if len(evts) == 0 || evts[len(evts)-1].AccountID != "mallory" || evts[len(evts)-1].SourceIP != "10.0.0.1" {
		t.Fatalf("missing or wrong BOLA event: %+v", evts)
	}
	// Score is capped at 100.
	if score, _ := traverse(e, clk, "mallory", 51, 200); score != 100 {
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

func TestBOLACumulativeObjectsAcrossWindows(t *testing.T) {
	e, _, clk := newBOLA()
	// 101 objects spread slowly (one every 20s = 15 per window): never a
	// traversal burst, but the cumulative total crosses 100.
	var score int
	var reason string
	for i := 0; i < 101; i++ {
		score, reason = e.Evaluate("dave", fmt.Sprintf("doc-%d", i), "/api/docs/{id}", "10.0.0.2")
		clk.Advance(20 * time.Second)
	}
	if score != 50 || !strings.Contains(reason, "累计 101") {
		t.Fatalf("score=%d reason=%q, want 50 cumulative", score, reason)
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
	fail(e, "6.6.6.6", 12, 6) // 12/min over 6 accounts -> 80 + int(2*2) = 84
	score, reason := e.Evaluate("6.6.6.6")
	if score != 84 || !strings.Contains(reason, "撞库特征") || !strings.Contains(reason, "/min") {
		t.Fatalf("score=%d reason=%q, want 84 credential stuffing in /min", score, reason)
	}
	evts := detectionEvents(t, store, "CREDENTIAL_STUFFING")
	if len(evts) != 1 || evts[0].SourceIP != "6.6.6.6" || evts[0].Severity != "critical" {
		t.Fatalf("unexpected events: %+v", evts)
	}
}

func TestAuthHighFrequencyFailures(t *testing.T) {
	e, store, _ := newAuth()
	fail(e, "7.7.7.7", 6, 4) // 6/min over 4 accounts -> medium, not stored
	if score, reason := e.Evaluate("7.7.7.7"); score != 60 || !strings.Contains(reason, "高频失败登录") {
		t.Fatalf("score=%d reason=%q, want 60", score, reason)
	}
	if n := len(detectionEvents(t, store, "CREDENTIAL_STUFFING")); n != 0 {
		t.Fatalf("stored %d events for a score below 70", n)
	}
}

func TestAuthSingleAccountTyposAreNotStuffing(t *testing.T) {
	e, _, _ := newAuth()
	fail(e, "8.8.8.8", 50, 1)
	if score, _ := e.Evaluate("8.8.8.8"); score != 0 {
		t.Fatalf("one user failing repeatedly scored %d", score)
	}
}

func TestAuthRateUsesElapsedTime(t *testing.T) {
	e, _, clk := newAuth()
	fail(e, "9.9.9.9", 12, 6)
	clk.Advance(10 * time.Minute) // 12 failures over 10 min = 1.2/min
	if score, _ := e.Evaluate("9.9.9.9"); score != 0 {
		t.Fatalf("slow failures scored %d, want 0", score)
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
	fail(e, "6.6.6.6", 12, 6)
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
		if got := isAdminEndpoint(path); got != want {
			t.Errorf("isAdminEndpoint(%q) = %v, want %v", path, got, want)
		}
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
