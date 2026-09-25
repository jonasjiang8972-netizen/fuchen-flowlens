package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// memRepo is an in-memory Repository whose writes can be made to fail.
type memRepo struct {
	mu    sync.Mutex
	docs  map[string]map[string][]byte
	fail  bool
	saves int
}

func newMemRepo() *memRepo { return &memRepo{docs: map[string]map[string][]byte{}} }

func (r *memRepo) LoadDocuments(_ context.Context, kind string) (map[string][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string][]byte{}
	for id, v := range r.docs[kind] {
		out[id] = append([]byte(nil), v...)
	}
	return out, nil
}

func (r *memRepo) SaveDocuments(_ context.Context, kind string, docs map[string][]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("database unavailable")
	}
	if r.docs[kind] == nil {
		r.docs[kind] = map[string][]byte{}
	}
	for id, v := range docs {
		r.docs[kind][id] = append([]byte(nil), v...)
	}
	r.saves++
	return nil
}

func (r *memRepo) setFail(v bool) { r.mu.Lock(); r.fail = v; r.mu.Unlock() }

func (r *memRepo) count(kind string) int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.docs[kind]) }

var ctx = context.Background()

// ─── Rules ─────────────────────────────────────────────────────

func TestRulesDefaultsSavedAndChangesSurviveReload(t *testing.T) {
	repo := newMemRepo()
	s, err := NewRuleServiceFrom(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	defaults := len(NewRuleService().rules)
	if repo.count(KindRule) != defaults {
		t.Fatalf("saved %d rules, want %d defaults", repo.count(KindRule), defaults)
	}
	if _, err := s.UpdateEnabled("R-BOLA-001", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateConfig("R-BOLA-001", map[string]interface{}{"traverse_threshold": 42}, nil); err != nil {
		t.Fatal(err)
	}

	again, _ := NewRuleServiceFrom(ctx, repo)
	r, _ := again.Get("R-BOLA-001")
	if r.Enabled || fmt.Sprint(r.Config["traverse_threshold"]) != "42" {
		t.Fatalf("change lost on reload: enabled=%v config=%v", r.Enabled, r.Config)
	}
}

func TestRulesMissingDefaultIsAddedStoredOneKept(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewRuleServiceFrom(ctx, repo)
	s.UpdateEnabled("R-AUTH-001", false)
	// Simulate an older database without one of the default rules.
	delete(repo.docs[KindRule], "R-SSRF-001")

	again, _ := NewRuleServiceFrom(ctx, repo)
	if _, err := again.Get("R-SSRF-001"); err != nil {
		t.Fatal("missing default rule was not added")
	}
	if r, _ := again.Get("R-AUTH-001"); r.Enabled {
		t.Fatal("stored rule was overwritten by the default")
	}
}

func TestRuleUpdateRollsBackWhenSaveFails(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewRuleServiceFrom(ctx, repo)
	repo.setFail(true)
	if _, err := s.UpdateEnabled("R-BOLA-001", false); err == nil {
		t.Fatal("update reported success although saving failed")
	}
	if r, _ := s.Get("R-BOLA-001"); !r.Enabled {
		t.Fatal("unsaved change left in memory")
	}
}

func TestRuleHitsAreFlushed(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewRuleServiceFrom(ctx, repo)
	for i := 0; i < 3; i++ {
		s.IncrementHit("R-BOLA-001")
	}
	var stored Rule
	_ = json.Unmarshal(repo.docs[KindRule]["R-BOLA-001"], &stored)
	before := stored.HitCount
	if n, err := s.Flush(ctx); err != nil || n != 1 {
		t.Fatalf("flush wrote %d, err %v; want 1", n, err)
	}
	_ = json.Unmarshal(repo.docs[KindRule]["R-BOLA-001"], &stored)
	if stored.HitCount != before+3 {
		t.Fatalf("stored hit count %d, want %d", stored.HitCount, before+3)
	}
	if n, _ := s.Flush(ctx); n != 0 {
		t.Fatalf("second flush wrote %d, want 0", n)
	}
}

// ─── Alerts ────────────────────────────────────────────────────

func TestAlertsStartEmptyWithoutSeed(t *testing.T) {
	s, _ := NewAlertServiceFrom(ctx, newMemRepo(), false)
	if n := len(s.List()); n != 0 {
		t.Fatalf("%d alerts without seeding, want 0", n)
	}
	repo := newMemRepo()
	seeded, _ := NewAlertServiceFrom(ctx, repo, true)
	if len(seeded.List()) == 0 || repo.count(KindAlert) != len(seeded.List()) {
		t.Fatal("seeded alerts not saved")
	}
}

func TestDetectionAlertsPersistAndKeepMergingAfterReload(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAlertServiceFrom(ctx, repo, false)
	first := s.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "d1", "1.2.3.4", "acct", 80, 0.9)
	s.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "d2", "1.2.3.4", "acct", 85, 0.9)
	if _, err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	again, _ := NewAlertServiceFrom(ctx, repo, false)
	a, err := again.Get(first.ID)
	if err != nil || a.OccurrenceCount != 2 || a.RiskScore != 85 {
		t.Fatalf("reloaded alert: %+v %v", a, err)
	}
	merged := again.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "d3", "1.2.3.4", "acct", 70, 0.9)
	if merged.ID != first.ID || merged.OccurrenceCount != 3 {
		t.Fatalf("repeat after reload created %s (count %d), want merge into %s", merged.ID, merged.OccurrenceCount, first.ID)
	}
}

func TestAlertActionRollsBackWhenSaveFails(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAlertServiceFrom(ctx, repo, true)
	repo.setFail(true)
	if err := s.ExecuteAction("alt-001", "ip_block", "", 0); err == nil {
		t.Fatal("action reported success although saving failed")
	}
	if a, _ := s.Get("alt-001"); a.Status != "open" || a.Disposal != nil {
		t.Fatalf("unsaved disposal left in memory: %+v", a)
	}
	repo.setFail(false)
	if err := s.ExecuteAction("alt-001", "ip_block", "", 0); err != nil {
		t.Fatal(err)
	}
	again, _ := NewAlertServiceFrom(ctx, repo, false)
	if a, _ := again.Get("alt-001"); a.Status != "in_progress" || a.Disposal == nil || a.Disposal.Action != "ip_block" {
		t.Fatalf("disposal lost on reload: %+v", a)
	}
}

func TestFailedFlushIsRetried(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAlertServiceFrom(ctx, repo, false)
	a := s.CreateDetectionAlert("FR-DET-002", "critical", "撞库", "d", "6.6.6.6", "", 90, 0.9)
	repo.setFail(true)
	if _, err := s.Flush(ctx); err == nil {
		t.Fatal("flush reported success although saving failed")
	}
	repo.setFail(false)
	if n, err := s.Flush(ctx); err != nil || n != 1 {
		t.Fatalf("retry flush wrote %d, err %v; want 1", n, err)
	}
	if _, ok := repo.docs[KindAlert][a.ID]; !ok {
		t.Fatal("alert not stored after retry")
	}
}

// ─── Assets ────────────────────────────────────────────────────

func TestAssetStatisticsContinueAfterReload(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAssetServiceFrom(ctx, repo, false)
	var a Asset
	for i := 1; i <= 100; i++ {
		a = s.ObserveEvent(apiEvent("/api/orders/{id}", "/api/orders/1", fmt.Sprintf("10.0.0.%d", i%7), 200, float64(i)), []string{"phone"})
	}
	if _, err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	again, _ := NewAssetServiceFrom(ctx, repo, false)
	got, err := again.Get(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestStats.TotalCalls24h != 100 || got.RequestStats.UniqueCallers24h != 7 || got.RequestStats.P95LatencyMs != 95 {
		t.Fatalf("reloaded stats: calls=%d unique=%d p95=%v", got.RequestStats.TotalCalls24h, got.RequestStats.UniqueCallers24h, got.RequestStats.P95LatencyMs)
	}
	// New traffic continues from the restored state instead of restarting.
	next := again.ObserveEvent(apiEvent("/api/orders/{id}", "/api/orders/2", "10.0.0.1", 200, 50), nil)
	if next.RequestStats.TotalCalls24h != 101 || next.RequestStats.UniqueCallers24h != 7 || next.RequestStats.TopCallers[0].Calls < 15 {
		t.Fatalf("stats restarted after reload: %+v", next.RequestStats)
	}
	if avg := next.RequestStats.AvgLatencyMs; avg < 50 || avg > 51 {
		t.Fatalf("average latency %v, want about 50.5 (mean of 1..100 and 50)", avg)
	}
	if len(next.SensitiveFields) != 1 {
		t.Fatalf("sensitive fields lost: %v", next.SensitiveFields)
	}
}

func TestAssetClaimRollsBackWhenSaveFails(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAssetServiceFrom(ctx, repo, false)
	a := s.ObserveEvent(apiEvent("/api/pay", "", "10.0.0.1", 200, 0), nil)
	s.Flush(ctx)
	repo.setFail(true)
	if err := s.Claim(a.ID, "alice"); err == nil {
		t.Fatal("claim reported success although saving failed")
	}
	if got, _ := s.Get(a.ID); got.ClaimStatus != "unclaimed" || got.Owner != "" {
		t.Fatalf("unsaved claim left in memory: %s/%s", got.ClaimStatus, got.Owner)
	}
	repo.setFail(false)
	if err := s.Claim(a.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	again, _ := NewAssetServiceFrom(ctx, repo, false)
	if got, _ := again.Get(a.ID); got.Owner != "alice" {
		t.Fatalf("claim lost on reload: owner=%q", got.Owner)
	}
	if err := s.Claim("missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing asset: %v, want ErrNotFound", err)
	}
}

// ─── Collectors ────────────────────────────────────────────────

func TestAgentStatusFollowsHeartbeatAge(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAgentServiceFrom(ctx, repo, false)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	id, err := s.RegisterWithID("agent-1", "host", "ebpf", "prod", "0.7.0", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := s.Get(id); a.AgentVersion != "0.7.0" || a.OS != "linux" {
		t.Fatalf("reported version/os not kept: %q %q", a.AgentVersion, a.OS)
	}
	status := func() string { a, _ := s.Get(id); return a.Status }
	if status() != "online" {
		t.Fatalf("fresh agent %s", status())
	}
	now = now.Add(2 * time.Minute)
	if status() != "degraded" || s.DegradedCount() != 1 {
		t.Fatalf("after 2 min without heartbeat: %s", status())
	}
	now = now.Add(10 * time.Minute)
	if status() != "offline" || s.OfflineCount() != 1 || s.OnlineCount() != 0 {
		t.Fatalf("after 12 min without heartbeat: %s", status())
	}
	s.UpdateHeartbeat(id)
	if status() != "online" {
		t.Fatalf("after heartbeat: %s", status())
	}
	s.Flush(ctx)
	again, _ := NewAgentServiceFrom(ctx, repo, false)
	again.now = s.now
	if a, err := again.Get(id); err != nil || a.Status != "online" || a.Hostname != "host" {
		t.Fatalf("reloaded agent: %+v %v", a, err)
	}
}

func TestAgentRegisterRollsBackWhenSaveFails(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAgentServiceFrom(ctx, repo, false)
	repo.setFail(true)
	if _, err := s.RegisterWithID("agent-x", "h", "ebpf", "c", "0.7.0", "linux"); err == nil {
		t.Fatal("register reported success although saving failed")
	}
	if _, err := s.Get("agent-x"); err == nil {
		t.Fatal("unsaved agent left in memory")
	}
}

func TestConcurrentTrafficAndFlushes(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAssetServiceFrom(ctx, repo, false)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				s.ObserveEvent(apiEvent(fmt.Sprintf("/api/r%d", i%5), "", fmt.Sprintf("10.0.%d.1", w), 200, 3), nil)
			}
		}(w)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				s.Flush(ctx)
			}
		}
	}()
	wg.Wait()
	close(stop)
	s.Flush(ctx)
	again, _ := NewAssetServiceFrom(ctx, repo, false)
	total := 0
	for _, a := range again.List() {
		total += a.RequestStats.TotalCalls24h
	}
	if total != 1200 {
		t.Fatalf("persisted %d calls, want 1200", total)
	}
}
