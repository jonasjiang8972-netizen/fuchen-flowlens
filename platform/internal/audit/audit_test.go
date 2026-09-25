package audit

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// sliceStore is an AuditStore whose records tests can tamper with.
type sliceStore struct {
	recs []storage.AuditRecord
	seq  int64
}

func (s *sliceStore) AppendAudit(_ context.Context, rec *storage.AuditRecord, chain func(string) string) error {
	prev := ""
	if n := len(s.recs); n > 0 {
		prev = s.recs[n-1].Hash
	}
	s.seq++
	rec.Seq = s.seq
	rec.PrevHash = prev
	rec.Hash = chain(prev)
	s.recs = append(s.recs, *rec)
	return nil
}

func (s *sliceStore) ListAudit(context.Context, storage.AuditQuery) ([]storage.AuditRecord, int, error) {
	return s.recs, len(s.recs), nil
}

func (s *sliceStore) WalkAudit(ctx context.Context, fn func(storage.AuditRecord) error) error {
	return s.WalkAuditFrom(ctx, 0, fn)
}

func (s *sliceStore) WalkAuditFrom(_ context.Context, from int64, fn func(storage.AuditRecord) error) error {
	for _, r := range s.recs {
		if r.Seq < from {
			continue
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

func (s *sliceStore) DeleteAuditBefore(_ context.Context, t time.Time) (int64, error) {
	i := 0
	for i < len(s.recs) && s.recs[i].Time.Before(t) {
		i++
	}
	s.recs = s.recs[i:]
	return int64(i), nil
}

func seeded(t *testing.T, n int) (*Service, *sliceStore) {
	t.Helper()
	st := &sliceStore{}
	svc := New(st)
	base := time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.UTC)
	for i := 0; i < n; i++ {
		ts := base.Add(time.Duration(i) * 24 * time.Hour)
		svc.now = func() time.Time { return ts }
		if err := svc.Record(context.Background(), storage.AuditRecord{Username: "u", EventType: "user.create", Target: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	return svc, st
}

func TestChainVerifies(t *testing.T) {
	svc, st := seeded(t, 5)
	res, err := svc.Verify(context.Background())
	if err != nil || !res.OK || res.Checked != 5 {
		t.Fatalf("verify: %+v %v", res, err)
	}
	if st.recs[0].Time.Nanosecond()%1000 != 0 {
		t.Fatal("time not truncated to microseconds before hashing")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]func(st *sliceStore){
		"modified field":  func(st *sliceStore) { st.recs[2].Username = "someone-else" },
		"modified result": func(st *sliceStore) { st.recs[3].Result = ResultFailure },
		"deleted middle":  func(st *sliceStore) { st.recs = append(st.recs[:2], st.recs[3:]...) },
		"swapped order":   func(st *sliceStore) { st.recs[1], st.recs[2] = st.recs[2], st.recs[1] },
		"rehashed but unlinked": func(st *sliceStore) {
			st.recs[2].Detail = "forged"
			st.recs[2].Hash = Hash(st.recs[2])
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			svc, st := seeded(t, 5)
			tamper(st)
			res, _ := svc.Verify(context.Background())
			if res.OK || res.BrokenAt == 0 || res.Reason == "" {
				t.Fatalf("tampering not detected: %+v", res)
			}
		})
	}
}

func TestPurgeKeepsChainVerifiableAndHonoursMinimum(t *testing.T) {
	svc, st := seeded(t, 200) // one record per day
	svc.now = func() time.Time { return st.recs[len(st.recs)-1].Time }

	n, err := svc.Purge(context.Background(), 7*24*time.Hour) // below minimum: 180 days used
	if err != nil {
		t.Fatal(err)
	}
	if n != 19 || len(st.recs) != 181 {
		t.Fatalf("purged %d, kept %d; want 19 purged, 181 kept", n, len(st.recs))
	}
	res, _ := svc.Verify(context.Background())
	if !res.OK || res.FirstSeq != 20 {
		t.Fatalf("chain after purge: %+v", res)
	}
}

func TestHashDependsOnEveryField(t *testing.T) {
	base := storage.AuditRecord{Seq: 1, Time: time.Unix(0, 0), UserID: "a", Username: "b", Role: "c", SourceIP: "d",
		Console: "e", EventType: "f", Target: "g", Result: "h", Reason: "i", Detail: "j", Method: "k", Path: "l", PrevHash: "m"}
	h := Hash(base)
	mutations := []func(*storage.AuditRecord){
		func(r *storage.AuditRecord) { r.Seq = 2 },
		func(r *storage.AuditRecord) { r.Time = r.Time.Add(time.Microsecond) },
		func(r *storage.AuditRecord) { r.UserID += "x" },
		func(r *storage.AuditRecord) { r.Username += "x" },
		func(r *storage.AuditRecord) { r.Role += "x" },
		func(r *storage.AuditRecord) { r.SourceIP += "x" },
		func(r *storage.AuditRecord) { r.Console += "x" },
		func(r *storage.AuditRecord) { r.EventType += "x" },
		func(r *storage.AuditRecord) { r.Target += "x" },
		func(r *storage.AuditRecord) { r.Result += "x" },
		func(r *storage.AuditRecord) { r.Reason += "x" },
		func(r *storage.AuditRecord) { r.Detail += "x" },
		func(r *storage.AuditRecord) { r.Method += "x" },
		func(r *storage.AuditRecord) { r.Path += "x" },
		func(r *storage.AuditRecord) { r.PrevHash += "x" },
	}
	for i, m := range mutations {
		r := base
		m(&r)
		if Hash(r) == h {
			t.Errorf("mutation %d did not change the hash", i)
		}
	}
	if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Fatalf("hash %q is not 64 hex chars (SM3)", h)
	}
}

// memSettings is a goroutine-safe in-memory SettingsStore.
type memSettings struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newSettings() *memSettings { return &memSettings{m: map[string][]byte{}} }

func (s *memSettings) GetSetting(_ context.Context, k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return v, nil
}

func (s *memSettings) PutSetting(_ context.Context, k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

// countingStore records how many records a walk visited.
type countingStore struct {
	*sliceStore
	visited int
}

func (c *countingStore) WalkAuditFrom(ctx context.Context, from int64, fn func(storage.AuditRecord) error) error {
	return c.sliceStore.WalkAuditFrom(ctx, from, func(r storage.AuditRecord) error {
		c.visited++
		return fn(r)
	})
}

func addRecords(t *testing.T, svc *Service, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := svc.Record(context.Background(), storage.AuditRecord{Username: "u", EventType: "user.create"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIncrementalVerifyChecksOnlyNewRecords(t *testing.T) {
	cs := &countingStore{sliceStore: &sliceStore{}}
	svc := New(cs)
	svc.SetSettings(newSettings())
	addRecords(t, svc, 1000)

	res, err := svc.VerifyIncremental(context.Background())
	if err != nil || !res.OK || res.Mode != "full" || res.Checked != 1000 {
		t.Fatalf("first run (no checkpoint): %+v %v", res, err)
	}
	addRecords(t, svc, 10)
	cs.visited = 0
	res, err = svc.VerifyIncremental(context.Background())
	if err != nil || !res.OK || res.Mode != "incremental" || res.Checked != 11 || res.FirstSeq != 1000 {
		t.Fatalf("incremental run: %+v %v", res, err)
	}
	if cs.visited > 20 {
		t.Fatalf("incremental run visited %d records, want about 11", cs.visited)
	}
}

func TestIncrementalVerifyDetectsTampering(t *testing.T) {
	for name, tamper := range map[string]func(st *sliceStore){
		"checkpoint record modified": func(st *sliceStore) { st.recs[99].Detail = "forged"; st.recs[99].Hash = Hash(st.recs[99]) },
		"new record modified":        func(st *sliceStore) { st.recs[103].Username = "x" },
		"new record deleted":         func(st *sliceStore) { st.recs = append(st.recs[:102], st.recs[103:]...) },
		"checkpoint record deleted":  func(st *sliceStore) { st.recs = append(st.recs[:99], st.recs[100:]...) },
	} {
		t.Run(name, func(t *testing.T) {
			st := &sliceStore{}
			svc := New(st)
			svc.SetSettings(newSettings())
			addRecords(t, svc, 100)
			if res, _ := svc.VerifyIncremental(context.Background()); !res.OK {
				t.Fatal("baseline not OK")
			}
			addRecords(t, svc, 5)
			tamper(st)
			res, err := svc.VerifyIncremental(context.Background())
			if err != nil || res.OK || res.Reason == "" {
				t.Fatalf("tampering not detected: %+v %v", res, err)
			}
		})
	}
}

func TestIncrementalVerifyAfterRetentionFallsBackToFull(t *testing.T) {
	st := &sliceStore{}
	svc := New(st)
	svc.SetSettings(newSettings())
	addRecords(t, svc, 50)
	svc.VerifyIncremental(context.Background()) // checkpoint at seq 50
	addRecords(t, svc, 10)
	st.recs = st.recs[55:] // retention purged everything up to seq 55
	res, err := svc.VerifyIncremental(context.Background())
	if err != nil || !res.OK || res.Mode != "full" || res.FirstSeq != 56 {
		t.Fatalf("after purge: %+v %v", res, err)
	}
}

func TestBackgroundFullVerify(t *testing.T) {
	st := &sliceStore{}
	svc := New(st)
	settings := newSettings()
	svc.SetSettings(settings)
	addRecords(t, svc, 200)
	if !svc.StartFullVerify() {
		t.Fatal("full verify did not start")
	}
	deadline := time.Now().Add(5 * time.Second)
	for svc.FullVerifyStatus(context.Background()).Running {
		if time.Now().After(deadline) {
			t.Fatal("full verify did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	st2 := svc.FullVerifyStatus(context.Background())
	if st2.Last == nil || !st2.Last.OK || st2.Last.Checked != 200 {
		t.Fatalf("status: %+v", st2)
	}
	// The result is persisted for a restarted service.
	fresh := New(st)
	fresh.SetSettings(settings)
	if last := fresh.FullVerifyStatus(context.Background()).Last; last == nil || last.Checked != 200 {
		t.Fatalf("persisted result: %+v", last)
	}
}
