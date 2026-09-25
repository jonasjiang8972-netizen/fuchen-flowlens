package audit

import (
	"context"
	"strings"
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

func (s *sliceStore) WalkAudit(_ context.Context, fn func(storage.AuditRecord) error) error {
	for _, r := range s.recs {
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
