package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// stores returns every Store implementation to run the contract against.
// PostgreSQL runs when FLOWLENS_TEST_PG_DSN points at a disposable database.
func stores(t *testing.T) map[string]Store {
	t.Helper()
	out := map[string]Store{"memory": NewMemStore()}
	if dsn := os.Getenv("FLOWLENS_TEST_PG_DSN"); dsn != "" {
		pg, err := NewPGStore(context.Background(), dsn)
		if err != nil {
			t.Fatalf("postgres: %v", err)
		}
		for _, table := range []string{"fl_sessions", "fl_users", "fl_settings", "fl_detection_events", "fl_documents"} {
			if _, err := pg.pool.Exec(context.Background(), "DELETE FROM "+table); err != nil {
				t.Fatal(err)
			}
		}
		// Truncate is allowed for tests only; the trigger blocks UPDATE, not TRUNCATE.
		if _, err := pg.pool.Exec(context.Background(), "TRUNCATE fl_audit_logs RESTART IDENTITY"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pg.Close() })
		out["postgres"] = pg
	} else {
		t.Log("FLOWLENS_TEST_PG_DSN not set: PostgreSQL contract tests skipped")
	}
	return out
}

func ts(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func TestUserContract(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := ts("2026-03-01T09:00:00Z")
			exp := now.Add(24 * time.Hour)
			u := &User{ID: "usr-1", Username: "Alice", DisplayName: "爱丽丝", Email: "a@example.com",
				PasswordHash: "h1", PasswordHistory: []string{"h0"}, PasswordChangedAt: now, MustChangePassword: true,
				Role: "sec_admin", Status: "active", ExpiresAt: &exp, CreatedBy: "sysadmin", CreatedAt: now, UpdatedAt: now}
			if err := st.CreateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			dup := *u
			dup.ID = "usr-2"
			dup.Username = "alice"
			if err := st.CreateUser(ctx, &dup); err == nil {
				t.Fatal("case-insensitive duplicate username accepted")
			}

			got, err := st.GetUserByUsername(ctx, "ALICE")
			if err != nil {
				t.Fatal(err)
			}
			if got.DisplayName != "爱丽丝" || len(got.PasswordHistory) != 1 || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || !got.MustChangePassword {
				t.Fatalf("round trip mismatch: %+v", got)
			}

			lock := now.Add(time.Hour)
			got.FailedAttempts, got.LockedUntil, got.Role = 3, &lock, "viewer"
			if err := st.UpdateUser(ctx, got); err != nil {
				t.Fatal(err)
			}
			again, _ := st.GetUserByID(ctx, "usr-1")
			if again.FailedAttempts != 3 || again.LockedUntil == nil || again.Role != "viewer" {
				t.Fatalf("update not persisted: %+v", again)
			}
			if n, _ := st.CountUsers(ctx); n != 1 {
				t.Fatalf("count %d", n)
			}
			if err := st.DeleteUser(ctx, "usr-1"); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetUserByID(ctx, "usr-1"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("after delete: %v", err)
			}
			if err := st.UpdateUser(ctx, got); !errors.Is(err, ErrNotFound) {
				t.Fatalf("update missing user: %v", err)
			}
		})
	}
}

func TestSessionContract(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := ts("2026-03-01T09:00:00Z")
			_ = st.CreateUser(ctx, &User{ID: "usr-1", Username: "bob", PasswordHash: "h", PasswordChangedAt: now,
				Role: "viewer", Status: "active", CreatedAt: now, UpdatedAt: now})
			for i, h := range []string{"s1", "s2", "s3"} {
				if err := st.CreateSession(ctx, &Session{TokenHash: h, UserID: "usr-1", CreatedAt: now,
					LastSeenAt: now.Add(time.Duration(i) * time.Minute), ExpiresAt: now.Add(8 * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.TouchSession(ctx, "s1", now.Add(20*time.Minute)); err != nil {
				t.Fatal(err)
			}
			s1, _ := st.GetSession(ctx, "s1")
			if !s1.LastSeenAt.Equal(now.Add(20 * time.Minute)) {
				t.Fatalf("touch not applied: %v", s1.LastSeenAt)
			}
			// idle before now+10m removes s2 (at +1m) and s3 (at +2m), keeps s1 (+20m)
			if err := st.DeleteExpiredSessions(ctx, now.Add(10*time.Minute), now.Add(30*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetSession(ctx, "s2"); !errors.Is(err, ErrNotFound) {
				t.Fatal("idle session kept")
			}
			_ = st.CreateSession(ctx, &Session{TokenHash: "s4", UserID: "usr-1", CreatedAt: now, LastSeenAt: now.Add(20 * time.Minute), ExpiresAt: now.Add(8 * time.Hour)})
			if err := st.DeleteUserSessions(ctx, "usr-1", "s4"); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetSession(ctx, "s1"); !errors.Is(err, ErrNotFound) {
				t.Fatal("other session kept")
			}
			if _, err := st.GetSession(ctx, "s4"); err != nil {
				t.Fatal("kept session removed")
			}
			// Deleting the user removes its sessions.
			_ = st.DeleteUser(ctx, "usr-1")
			if _, err := st.GetSession(ctx, "s4"); !errors.Is(err, ErrNotFound) {
				t.Fatal("session survived user deletion")
			}
		})
	}
}

func TestSettingsContract(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if _, err := st.GetSetting(ctx, "k"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("missing setting: %v", err)
			}
			_ = st.PutSetting(ctx, "k", []byte(`{"a":1}`))
			_ = st.PutSetting(ctx, "k", []byte(`{"a":2}`))
			v, err := st.GetSetting(ctx, "k")
			if err != nil || string(v) != `{"a": 2}` && string(v) != `{"a":2}` {
				t.Fatalf("setting = %s, %v", v, err)
			}
		})
	}
}

func TestAuditContract(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			chain := func(r *AuditRecord) func(string) string {
				return func(prev string) string { return fmt.Sprintf("h(%d,%s)", r.Seq, prev) }
			}
			for i := 0; i < 5; i++ {
				r := &AuditRecord{Time: ts("2026-03-01T09:00:00Z").Add(time.Duration(i) * time.Hour),
					Username: []string{"alice", "bob"}[i%2], EventType: []string{"auth.login", "user.create"}[i%2],
					Result: "success", Console: "admin"}
				if err := st.AppendAudit(ctx, r, chain(r)); err != nil {
					t.Fatal(err)
				}
				if r.Seq != int64(i+1) {
					t.Fatalf("seq %d, want %d", r.Seq, i+1)
				}
			}
			recs, total, err := st.ListAudit(ctx, AuditQuery{Username: "ALICE", EventType: "auth.", Limit: 2})
			if err != nil || total != 3 || len(recs) != 2 || recs[0].Seq != 5 {
				t.Fatalf("filtered list: total=%d len=%d first=%v err=%v", total, len(recs), recs, err)
			}
			recs, _, _ = st.ListAudit(ctx, AuditQuery{From: ts("2026-03-01T10:00:00Z"), To: ts("2026-03-01T12:00:00Z")})
			if len(recs) != 2 {
				t.Fatalf("time range: %d records", len(recs))
			}
			var walked []int64
			_ = st.WalkAudit(ctx, func(r AuditRecord) error {
				walked = append(walked, r.Seq)
				if r.Seq > 1 && r.PrevHash != fmt.Sprintf("h(%d,%s)", r.Seq-1, "") && r.PrevHash == "" {
					t.Errorf("record %d not linked", r.Seq)
				}
				return nil
			})
			if fmt.Sprint(walked) != "[1 2 3 4 5]" {
				t.Fatalf("walk order %v", walked)
			}
			n, _ := st.DeleteAuditBefore(ctx, ts("2026-03-01T11:00:00Z"))
			if n != 2 {
				t.Fatalf("purged %d, want 2", n)
			}
		})
	}
}

func TestAuditAppendsAreSerialised(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var wg sync.WaitGroup
			for w := 0; w < 8; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < 25; i++ {
						r := &AuditRecord{Time: time.Now(), EventType: "x", Result: "success"}
						_ = st.AppendAudit(ctx, r, func(prev string) string { return fmt.Sprintf("%d<-%s", r.Seq, prev) })
					}
				}()
			}
			wg.Wait()
			var prev *AuditRecord
			count := 0
			_ = st.WalkAudit(ctx, func(r AuditRecord) error {
				if prev != nil && r.PrevHash != prev.Hash {
					t.Errorf("chain forked at %d", r.Seq)
				}
				rc := r
				prev = &rc
				count++
				return nil
			})
			if count < 200 {
				t.Fatalf("only %d records", count)
			}
		})
	}
}

func TestPostgresAuditIsAppendOnly(t *testing.T) {
	st, ok := stores(t)["postgres"]
	if !ok {
		t.Skip("FLOWLENS_TEST_PG_DSN not set")
	}
	pg := st.(*PGStore)
	ctx := context.Background()
	r := &AuditRecord{Time: time.Now(), EventType: "x", Result: "success"}
	_ = pg.AppendAudit(ctx, r, func(string) string { return "h" })
	if _, err := pg.pool.Exec(ctx, "UPDATE fl_audit_logs SET username='forged'"); err == nil {
		t.Fatal("UPDATE on audit table succeeded")
	}
}

func TestDocumentContract(t *testing.T) {
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if docs, err := st.LoadDocuments(ctx, "asset"); err != nil || len(docs) != 0 {
				t.Fatalf("empty load: %v %v", docs, err)
			}
			if err := st.SaveDocuments(ctx, "asset", map[string][]byte{
				"a1": []byte(`{"owner":"alice","n":1}`),
				"a2": []byte(`{"owner":"bob","n":2}`),
			}); err != nil {
				t.Fatal(err)
			}
			_ = st.SaveDocuments(ctx, "alert", map[string][]byte{"a1": []byte(`{"kind":"alert"}`)})
			// Upsert replaces the whole document.
			if err := st.SaveDocuments(ctx, "asset", map[string][]byte{"a1": []byte(`{"owner":"carol"}`)}); err != nil {
				t.Fatal(err)
			}
			docs, err := st.LoadDocuments(ctx, "asset")
			if err != nil || len(docs) != 2 {
				t.Fatalf("load: %d docs, %v", len(docs), err)
			}
			var a1 map[string]any
			_ = json.Unmarshal(docs["a1"], &a1)
			if a1["owner"] != "carol" || a1["n"] != nil {
				t.Fatalf("upsert did not replace document: %s", docs["a1"])
			}
			if alerts, _ := st.LoadDocuments(ctx, "alert"); len(alerts) != 1 {
				t.Fatalf("kinds not separated: %d alerts", len(alerts))
			}
			if err := st.SaveDocuments(ctx, "asset", nil); err != nil {
				t.Fatalf("empty save: %v", err)
			}
		})
	}
}
