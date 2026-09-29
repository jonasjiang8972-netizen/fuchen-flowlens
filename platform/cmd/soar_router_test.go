package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/server"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/soar"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

type okConnector struct{ blocked map[string]bool }

func (okConnector) Name() string  { return "stub" }
func (okConnector) Label() string { return "stub" }
func (c okConnector) Block(_ context.Context, r soar.Request) (string, error) {
	c.blocked[r.IP] = true
	return "", nil
}
func (c okConnector) Unblock(_ context.Context, ip, _ string) error {
	delete(c.blocked, ip)
	return nil
}
func (okConnector) Check(context.Context) error { return nil }

func newSOARHarness(t *testing.T) (*harness, okConnector) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := storage.NewMemStore()
	srv := server.NewPlatformServer(store)
	if _, err := srv.IAM().Bootstrap(context.Background(), initialPassword); err != nil {
		t.Fatal(err)
	}
	c := okConnector{blocked: map[string]bool{}}
	srv.SetSOAR(soar.NewManager(soar.DefaultPolicy(), []soar.Adapter{c}, store, srv.Audit()))
	return &harness{t: t, r: setupRouter(srv, config{})}, c
}

func TestSOAREndpointPermissions(t *testing.T) {
	h, conn := newSOARHarness(t)
	tok := h.tokens()
	const block = `{"ip":"198.51.100.20","ttl_minutes":10}`

	// Unauthenticated callers get nothing.
	for _, call := range [][3]string{
		{"GET", "/api/v1/soar/connectors", ""}, {"GET", "/api/v1/soar/blocks", ""},
		{"POST", "/api/v1/soar/block", block}, {"POST", "/api/v1/soar/unblock", block},
		{"POST", "/api/v1/soar/connectors/stub/test", ""},
	} {
		if w := h.do(call[0], call[1], "", call[2]); w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s: %d, want 401", call[0], call[1], w.Code)
		}
	}
	if len(conn.blocked) != 0 {
		t.Fatal("an unauthenticated request reached the connector")
	}

	// The management console's roles have no business with enforcement.
	for _, role := range []string{"sys_admin", "audit_admin"} {
		for _, call := range [][3]string{{"GET", "/api/v1/soar/connectors", ""}, {"POST", "/api/v1/soar/block", block}} {
			if w := h.do(call[0], call[1], tok[role], call[2]); w.Code != http.StatusForbidden {
				t.Errorf("%s %s %s: %d, want 403", role, call[0], call[1], w.Code)
			}
		}
	}

	// A viewer can look but not act.
	if w := h.do("GET", "/api/v1/soar/connectors", tok["viewer"], ""); w.Code != http.StatusOK {
		t.Errorf("viewer read: %d", w.Code)
	}
	for _, call := range [][3]string{{"POST", "/api/v1/soar/block", block}, {"POST", "/api/v1/soar/unblock", block}, {"POST", "/api/v1/soar/connectors/stub/test", ""}} {
		if w := h.do(call[0], call[1], tok["viewer"], call[2]); w.Code != http.StatusForbidden {
			t.Errorf("viewer %s %s: %d, want 403", call[0], call[1], w.Code)
		}
	}
	if len(conn.blocked) != 0 {
		t.Fatal("a viewer managed to block an address")
	}

	// An analyst handles alerts, so may block, but changing the connector
	// setup (testing it) is policy work for the security admin.
	if w := h.do("POST", "/api/v1/soar/connectors/stub/test", tok["analyst"], ""); w.Code != http.StatusForbidden {
		t.Errorf("analyst testing a connector: %d, want 403", w.Code)
	}
	if w := h.do("POST", "/api/v1/soar/block", tok["analyst"], block); w.Code != http.StatusOK || !conn.blocked["198.51.100.20"] {
		t.Fatalf("analyst block: %d %s", w.Code, w.Body.String())
	}
	if w := h.do("POST", "/api/v1/soar/connectors/stub/test", tok["sec_admin"], ""); w.Code != http.StatusOK {
		t.Errorf("sec_admin test: %d", w.Code)
	}
	if w := h.do("POST", "/api/v1/soar/unblock", tok["sec_admin"], block); w.Code != http.StatusOK || conn.blocked["198.51.100.20"] {
		t.Errorf("sec_admin unblock: %d", w.Code)
	}

	// The audit trail names who blocked and lifted it.
	w := h.do("GET", "/api/v1/admin/audit-logs?event_type=soar.", tok["audit_admin"], "")
	if w.Code != http.StatusOK {
		t.Fatalf("audit query: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"soar.block", "soar.unblock", `"username":"ana"`, "198.51.100.20"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit trail missing %s: %s", want, body)
		}
	}
}
