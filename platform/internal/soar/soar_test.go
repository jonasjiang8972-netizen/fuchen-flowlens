package soar

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// fake is an in-memory connector that can be told to fail.
type fake struct {
	name      string
	mu        sync.Mutex
	blocked   map[string]bool
	blockErr  error
	unblkErr  error
	blockCall int
}

func newFake(name string) *fake { return &fake{name: name, blocked: map[string]bool{}} }

func (f *fake) Name() string  { return f.name }
func (f *fake) Label() string { return f.name }
func (f *fake) Block(_ context.Context, r Request) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blockCall++
	if f.blockErr != nil {
		return "", f.blockErr
	}
	f.blocked[r.IP] = true
	return "ref-" + r.IP, nil
}
func (f *fake) Unblock(_ context.Context, ip, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unblkErr != nil {
		return f.unblkErr
	}
	if ref != "ref-"+ip {
		return errors.New("wrong ref " + ref)
	}
	delete(f.blocked, ip)
	return nil
}
func (f *fake) Check(context.Context) error { return f.blockErr }
func (f *fake) has(ip string) bool          { f.mu.Lock(); defer f.mu.Unlock(); return f.blocked[ip] }

func testManager(t *testing.T, p Policy, store storage.DocumentStore, ads ...Adapter) (*Manager, *time.Time) {
	t.Helper()
	m := NewManager(p, ads, store, nil)
	clock := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	return m, &clock
}

func TestValidateTarget(t *testing.T) {
	_, n, _ := parseCIDR("203.0.113.0/24")
	m, _ := testManager(t, Policy{ProtectedNets: n}, nil, newFake("a"))
	bad := []string{"", "not-an-ip", "0.0.0.0", "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.9", "169.254.1.1", "224.0.0.1", "::1", "fe80::1", "203.0.113.7"}
	for _, ip := range bad {
		if _, err := m.ValidateTarget(ip); !errors.Is(err, ErrBadTarget) {
			t.Errorf("ValidateTarget(%q) = %v, want ErrBadTarget", ip, err)
		}
	}
	if ip, err := m.ValidateTarget(" 198.51.100.9 "); err != nil || ip != "198.51.100.9" {
		t.Errorf("public address rejected: %q %v", ip, err)
	}
	m2, _ := testManager(t, Policy{AllowPrivate: true}, nil, newFake("a"))
	if _, err := m2.ValidateTarget("10.1.2.3"); err != nil {
		t.Errorf("AllowPrivate should permit private addresses: %v", err)
	}
	if _, err := m2.ValidateTarget("0.0.0.0"); err == nil {
		t.Error("AllowPrivate must not permit unspecified addresses")
	}
}

func TestBlockGuardrails(t *testing.T) {
	f := newFake("a")
	m, _ := testManager(t, Policy{MaxBlocksPerHour: 2, MaxTTL: 2 * time.Hour}, nil, f)

	if _, err := NewManager(Policy{}, nil, nil, nil).Block(context.Background(), BlockInput{IP: "198.51.100.1"}); !errors.Is(err, ErrNoConnectors) {
		t.Errorf("no connectors: %v", err)
	}
	if _, err := m.Block(context.Background(), BlockInput{IP: "10.0.0.1"}); !errors.Is(err, ErrBadTarget) {
		t.Errorf("private: %v", err)
	}
	for _, ttl := range []time.Duration{30 * time.Second, 3 * time.Hour, -time.Minute} {
		if _, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.1", TTL: ttl}); !errors.Is(err, ErrBadTTL) {
			t.Errorf("ttl %v: %v", ttl, err)
		}
	}
	if _, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.1", Connectors: []string{"nope"}}); !errors.Is(err, ErrUnknownConn) {
		t.Errorf("unknown connector: %v", err)
	}
	if f.blockCall != 0 {
		t.Fatalf("connector was called %d times by rejected requests", f.blockCall)
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if _, err := m.Block(context.Background(), BlockInput{IP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.3"}); !errors.Is(err, ErrRateLimited) {
		t.Errorf("third block in an hour: %v, want ErrRateLimited", err)
	}
}

func TestRateLimitWindowSlides(t *testing.T) {
	m, clock := testManager(t, Policy{MaxBlocksPerHour: 1}, nil, newFake("a"))
	if _, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.1"}); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(61 * time.Minute)
	if _, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.2"}); err != nil {
		t.Errorf("after the window: %v", err)
	}
}

func TestBlockLifecycleAndExpiry(t *testing.T) {
	f := newFake("a")
	m, clock := testManager(t, Policy{}, nil, f)
	b, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.5", TTL: 10 * time.Minute, Reason: "stuffing", AlertID: "alt-1", Operator: "sec"})
	if err != nil || b.State != StateActive || !f.has("198.51.100.5") {
		t.Fatalf("block: %+v %v", b, err)
	}
	if !b.ExpiresAt.Equal(clock.Add(10 * time.Minute)) {
		t.Errorf("expiry = %v", b.ExpiresAt)
	}
	if n := m.ExpireDue(context.Background()); n != 0 {
		t.Errorf("nothing is due yet, processed %d", n)
	}
	*clock = clock.Add(11 * time.Minute)
	if n := m.ExpireDue(context.Background()); n != 1 {
		t.Fatalf("expired %d blocks, want 1", n)
	}
	if f.has("198.51.100.5") {
		t.Error("expired block still enforced")
	}
	got := m.Blocks(false, 10)
	if len(got) != 1 || got[0].State != StateReleased || got[0].ReleasedBy != "system" || got[0].ReleasedAt == nil {
		t.Errorf("after expiry: %+v", got)
	}
	if len(m.Blocks(true, 10)) != 0 {
		t.Error("released block listed as active")
	}
}

func TestReblockExtendsExistingBlock(t *testing.T) {
	f := newFake("a")
	m, clock := testManager(t, Policy{}, nil, f)
	first, _ := m.Block(context.Background(), BlockInput{IP: "198.51.100.5", TTL: 10 * time.Minute})
	*clock = clock.Add(5 * time.Minute)
	second, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.5", TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || len(m.Blocks(false, 10)) != 1 {
		t.Errorf("re-block created a second record: %s vs %s", second.ID, first.ID)
	}
	if !second.ExpiresAt.Equal(clock.Add(30 * time.Minute)) {
		t.Errorf("expiry not extended: %v", second.ExpiresAt)
	}
}

func TestPartialAndTotalFailure(t *testing.T) {
	good, bad := newFake("good"), newFake("bad")
	bad.blockErr = errors.New("boom")
	m, _ := testManager(t, Policy{}, nil, good, bad)

	b, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.5"})
	if err != nil || b.State != StateActive {
		t.Fatalf("partial success should still be active: %+v %v", b, err)
	}
	var sawErr bool
	for _, r := range b.Results {
		if r.Connector == "bad" && !r.OK && r.Error == "boom" {
			sawErr = true
		}
	}
	if !sawErr {
		t.Errorf("failed connector not reported: %+v", b.Results)
	}

	// Retrying after the bad connector recovers must not disturb the good one.
	bad.mu.Lock()
	bad.blockErr = nil
	bad.mu.Unlock()
	b, _ = m.Block(context.Background(), BlockInput{IP: "198.51.100.5"})
	for _, r := range b.Results {
		if !r.OK {
			t.Errorf("connector %s still failing after retry: %+v", r.Connector, r)
		}
	}

	allBad := newFake("x")
	allBad.blockErr = errors.New("down")
	m2, _ := testManager(t, Policy{}, nil, allBad)
	b, err = m2.Block(context.Background(), BlockInput{IP: "198.51.100.6"})
	if err != nil || b.State != StateFailed {
		t.Errorf("all connectors failing: state=%s err=%v", b.State, err)
	}
	if len(m2.Blocks(true, 10)) != 0 {
		t.Error("a failed block must not count as active")
	}
}

func TestRetryDoesNotDropWorkingBlock(t *testing.T) {
	f := newFake("a")
	m, _ := testManager(t, Policy{}, nil, f)
	if _, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.5"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.blockErr = errors.New("transient")
	f.mu.Unlock()
	b, _ := m.Block(context.Background(), BlockInput{IP: "198.51.100.5"})
	if b.State != StateActive || !b.Results[0].OK {
		t.Errorf("a failed retry erased the working block: %+v", b)
	}
	f.mu.Lock()
	f.blockErr = nil
	f.mu.Unlock()
	if _, err := m.Unblock(context.Background(), "198.51.100.5", "op"); err != nil || f.has("198.51.100.5") {
		t.Errorf("unblock after failed retry: %v", err)
	}
}

func TestUnblock(t *testing.T) {
	f := newFake("a")
	m, _ := testManager(t, Policy{}, nil, f)
	if _, err := m.Unblock(context.Background(), "198.51.100.5", "op"); !errors.Is(err, ErrNotBlocked) {
		t.Errorf("unblocking an unblocked address: %v", err)
	}
	if _, err := m.Unblock(context.Background(), "junk", "op"); !errors.Is(err, ErrBadTarget) {
		t.Errorf("bad address: %v", err)
	}
	m.Block(context.Background(), BlockInput{IP: "198.51.100.5"})
	b, err := m.Unblock(context.Background(), "198.51.100.5", "alice")
	if err != nil || b.State != StateReleased || b.ReleasedBy != "alice" || f.has("198.51.100.5") {
		t.Fatalf("unblock: %+v %v", b, err)
	}
}

func TestFailedUnblockStaysActiveAndRetries(t *testing.T) {
	f := newFake("a")
	m, clock := testManager(t, Policy{}, nil, f)
	m.Block(context.Background(), BlockInput{IP: "198.51.100.5", TTL: time.Minute})
	f.mu.Lock()
	f.unblkErr = errors.New("gateway unreachable")
	f.mu.Unlock()
	*clock = clock.Add(2 * time.Minute)
	m.ExpireDue(context.Background())
	act := m.Blocks(true, 10)
	if len(act) != 1 || !strings.Contains(act[0].Results[0].Error, "gateway unreachable") {
		t.Fatalf("failed unblock should leave the block active with the error: %+v", act)
	}
	f.mu.Lock()
	f.unblkErr = nil
	f.mu.Unlock()
	m.ExpireDue(context.Background())
	if len(m.Blocks(true, 10)) != 0 || f.has("198.51.100.5") {
		t.Error("retry did not lift the block")
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	f := newFake("a")
	m, clock := testManager(t, Policy{DryRun: true}, nil, f)
	b, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.5", TTL: time.Minute})
	if err != nil || b.State != StateDryRun {
		t.Fatalf("%+v %v", b, err)
	}
	if f.blockCall != 0 || f.has("198.51.100.5") {
		t.Error("dry run reached the connector")
	}
	*clock = clock.Add(2 * time.Minute)
	m.ExpireDue(context.Background())
	if got := m.Blocks(false, 1); got[0].State != StateReleased {
		t.Errorf("dry-run block should still expire: %+v", got)
	}
}

func TestPersistenceSurvivesRestart(t *testing.T) {
	store := storage.NewMemStore()
	f := newFake("a")
	m, clock := testManager(t, Policy{}, store, f)
	if _, err := m.Block(context.Background(), BlockInput{IP: "198.51.100.5", TTL: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}

	// A new process: same store and connector state, fresh manager.
	m2, _ := testManager(t, Policy{}, store, f)
	m2.now = func() time.Time { return clock.Add(11 * time.Minute) }
	if err := m2.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(m2.Blocks(true, 10)) != 1 {
		t.Fatal("active block not restored")
	}
	m2.ExpireDue(context.Background())
	if f.has("198.51.100.5") {
		t.Error("block restored after restart was not lifted on schedule")
	}
	// And the release is persisted too.
	m3, _ := testManager(t, Policy{}, store, f)
	m3.Load(context.Background())
	if got := m3.Blocks(false, 10); len(got) != 1 || got[0].State != StateReleased {
		t.Errorf("release not persisted: %+v", got)
	}
}

func TestConnectorsAndCheck(t *testing.T) {
	ok, bad := newFake("ok"), newFake("bad")
	bad.blockErr = errors.New("unauthorised")
	m, _ := testManager(t, Policy{}, nil, ok, bad)
	m.Block(context.Background(), BlockInput{IP: "198.51.100.5", Connectors: []string{"ok"}})

	for _, c := range m.Connectors() {
		if c.Status != "unchecked" {
			t.Errorf("%s status before check = %s", c.Name, c.Status)
		}
	}
	if st, err := m.Check(context.Background(), "ok"); err != nil || st.Status != "ok" || st.ActiveBlocks != 1 || st.LastChecked == nil {
		t.Errorf("ok connector: %+v %v", st, err)
	}
	if st, _ := m.Check(context.Background(), "bad"); st.Status != "error" || st.Error != "unauthorised" {
		t.Errorf("bad connector: %+v", st)
	}
	if _, err := m.Check(context.Background(), "nope"); !errors.Is(err, ErrUnknownConn) {
		t.Errorf("unknown connector: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	env := map[string]string{
		"FLOWLENS_SOAR_KONG_URL": "http://kong:8001", "FLOWLENS_SOAR_NGINX_DENY_FILE": "/tmp/x.conf",
		"FLOWLENS_SOAR_WEBHOOK_URL": "https://soar/hook", "FLOWLENS_SOAR_WEBHOOK_SECRET": "s",
		"FLOWLENS_SOAR_PROTECTED_CIDRS": "203.0.113.0/24, 198.51.100.7", "FLOWLENS_SOAR_MAX_TTL": "48h",
		"FLOWLENS_SOAR_DEFAULT_TTL": "30m", "FLOWLENS_SOAR_MAX_BLOCKS_PER_HOUR": "5", "FLOWLENS_SOAR_DRY_RUN": "true",
	}
	p, ads, err := FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range ads {
		names = append(names, a.Name())
	}
	if strings.Join(names, ",") != "kong,nginx,webhook" {
		t.Errorf("connectors = %v", names)
	}
	if !p.DryRun || p.MaxTTL != 48*time.Hour || p.DefaultTTL != 30*time.Minute || p.MaxBlocksPerHour != 5 || len(p.ProtectedNets) != 2 {
		t.Errorf("policy = %+v", p)
	}

	for name, env := range map[string]map[string]string{
		"apisix without key":     {"FLOWLENS_SOAR_APISIX_URL": "http://a"},
		"webhook without secret": {"FLOWLENS_SOAR_WEBHOOK_URL": "http://a"},
		"aliyun incomplete":      {"FLOWLENS_SOAR_ALIYUN_WAF_ACCESS_KEY_ID": "id"},
		"bad ttl":                {"FLOWLENS_SOAR_MAX_TTL": "soon"},
		"bad cidr":               {"FLOWLENS_SOAR_PROTECTED_CIDRS": "300.1.1.1/8"},
		"default over max":       {"FLOWLENS_SOAR_DEFAULT_TTL": "48h"},
		"bad rate":               {"FLOWLENS_SOAR_MAX_BLOCKS_PER_HOUR": "0"},
	} {
		if _, _, err := FromEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("%s: expected a configuration error", name)
		}
	}
	_, ads, err = FromEnv(func(string) string { return "" })
	if err != nil || len(ads) != 0 {
		t.Errorf("empty environment: %v %v", ads, err)
	}
}

func parseCIDR(s string) (any, []*net.IPNet, error) {
	_, n, err := net.ParseCIDR(s)
	return nil, []*net.IPNet{n}, err
}
