package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/forward"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

func TestAlertsAndAuditAreForwarded(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}))
	defer hook.Close()

	srv := NewPlatformServer(storage.NewMemStore())
	ctx := t.Context()
	if err := srv.forwarder.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.forwarder.Update(ctx, forward.Config{Targets: []forward.Target{{
		Name: "soar", Type: "webhook", Enabled: true, URL: hook.URL,
		Events: []string{forward.EventAlertCreated, forward.EventAlertHandled, forward.EventAudit},
	}}}); err != nil {
		t.Fatal(err)
	}

	// A traversal raises one alert; later merges are not re-sent.
	d := traverseObjects(srv, "fwd-acct", 25)
	if d.RuleID != ruleBOLA {
		t.Fatalf("no detection: %+v", d)
	}
	alert := alertsFor(srv, "fwd-acct")[0]
	if _, err := srv.alertService.ExecuteAction(alert.ID, "ip_block", "secadmin", "SOAR"); err != nil {
		t.Fatal(err)
	}
	a, _ := srv.alertService.Get(alert.ID)
	srv.publishAlertHandled(a, "ip_block", "secadmin", "SOAR")
	_ = srv.audit.Record(ctx, storage.AuditRecord{Username: "sysadmin", EventType: "user.create", Target: "ana"})

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("received %d events: %v", n, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // anything extra would arrive now
	mu.Lock()
	defer mu.Unlock()
	types := map[string]int{}
	for _, m := range got {
		types[m["type"].(string)]++
	}
	if types[forward.EventAlertCreated] != 1 || types[forward.EventAlertHandled] != 1 || types[forward.EventAudit] != 1 {
		t.Fatalf("event types: %v", types)
	}
	for _, m := range got {
		if m["type"] == forward.EventAlertHandled {
			data := m["data"].(map[string]any)
			if data["action"] != "ip_block" || data["source_ip"] != "10.1.1.1" || data["actor"] != "secadmin" {
				t.Fatalf("handled event data: %v", data)
			}
		}
	}
}
