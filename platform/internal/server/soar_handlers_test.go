package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/soar"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

type stubConnector struct {
	mu      sync.Mutex
	err     error
	blocked map[string]bool
}

func (c *stubConnector) Name() string  { return "stub" }
func (c *stubConnector) Label() string { return "stub" }
func (c *stubConnector) Block(_ context.Context, r soar.Request) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return "", c.err
	}
	if c.blocked == nil {
		c.blocked = map[string]bool{}
	}
	c.blocked[r.IP] = true
	return "", nil
}
func (c *stubConnector) Unblock(_ context.Context, ip, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.blocked, ip)
	return nil
}
func (c *stubConnector) Check(context.Context) error { return c.err }

func soarServer(t *testing.T, policy soar.Policy, ads ...soar.Adapter) (*PlatformServer, *gin.Engine, *storage.MemStore) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := storage.NewMemStore()
	srv := NewPlatformServer(store)
	srv.SetSOAR(soar.NewManager(policy, ads, store, srv.Audit()))
	r := gin.New()
	r.POST("/alerts/:id/:action", srv.AlertActionHandler)
	r.GET("/soar/connectors", srv.SOARConnectorsHandler)
	r.POST("/soar/connectors/:name/test", srv.SOARTestHandler)
	r.GET("/soar/blocks", srv.SOARBlocksHandler)
	r.POST("/soar/block", srv.SOARBlockHandler)
	r.POST("/soar/unblock", srv.SOARUnblockHandler)
	return srv, r, store
}

func post(t *testing.T, r http.Handler, url string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, url, bytes.NewReader(raw)))
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func alertByID(srv *PlatformServer, id string) (status, disposal string) {
	for _, a := range srv.alertService.List() {
		if a.ID == id {
			if a.Disposal != nil {
				disposal = a.Disposal.Status
			}
			return a.Status, disposal
		}
	}
	return "", ""
}

func newAlert(srv *PlatformServer, ip string) string {
	return srv.alertService.CreateDetectionAlert("FR-DET-002", "high", "撞库", "desc", ip, "acct", 90, 0.9).ID
}

func auditEvents(t *testing.T, store *storage.MemStore, prefix string) []storage.AuditRecord {
	t.Helper()
	recs, _, err := store.ListAudit(context.Background(), storage.AuditQuery{EventType: prefix, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestAlertBlockWithoutConnectorsChangesNothing(t *testing.T) {
	srv, r, store := soarServer(t, soar.DefaultPolicy())
	id := newAlert(srv, "198.51.100.7")
	code, body := post(t, r, "/alerts/"+id+"/ip_block", map[string]any{})
	if code != 409 || body["code"] != "no_connectors" {
		t.Fatalf("status %d body %v, want 409 no_connectors", code, body)
	}
	if st, disp := alertByID(srv, id); st != "open" || disp != "" {
		t.Errorf("alert must stay untouched, got status=%s disposal=%s", st, disp)
	}
	if evs := auditEvents(t, store, "soar.block"); len(evs) != 1 || evs[0].Result != "failure" {
		t.Errorf("the refused attempt should be audited: %+v", evs)
	}
}

func TestAlertBlockEnforcesAndRecords(t *testing.T) {
	c := &stubConnector{}
	srv, r, store := soarServer(t, soar.DefaultPolicy(), c)
	id := newAlert(srv, "198.51.100.7")

	code, body := post(t, r, "/alerts/"+id+"/ip_block", map[string]any{"duration_minutes": 30})
	if code != 200 {
		t.Fatalf("status %d body %v", code, body)
	}
	if !c.blocked["198.51.100.7"] {
		t.Fatal("the connector was never asked to block")
	}
	if st, disp := alertByID(srv, id); st != "in_progress" || disp != "success" {
		t.Errorf("alert status=%s disposal=%s", st, disp)
	}
	evs := auditEvents(t, store, "soar.block")
	if len(evs) != 1 || evs[0].Result != "success" || evs[0].Target != "198.51.100.7" || !strings.Contains(evs[0].Detail, "stub:ok") || !strings.Contains(evs[0].Detail, "ttl=30m") {
		t.Errorf("audit = %+v", evs)
	}
	// The alert action must not also produce the generic, less specific record.
	if n := len(auditEvents(t, store, "")); n != 1 {
		t.Errorf("expected exactly one audit record, got %d", n)
	}
}

func TestAlertBlockRefusesPrivateAndMissingIP(t *testing.T) {
	c := &stubConnector{}
	srv, r, _ := soarServer(t, soar.DefaultPolicy(), c)
	priv := newAlert(srv, "10.1.2.3")
	if code, _ := post(t, r, "/alerts/"+priv+"/ip_block", map[string]any{}); code != 400 {
		t.Errorf("private source: status %d, want 400", code)
	}
	noIP := srv.alertService.CreateDetectionAlert("FR-DET-001", "high", "t", "d", "", "acct-only", 80, 0.9).ID
	if code, _ := post(t, r, "/alerts/"+noIP+"/ip_block", map[string]any{}); code != 400 {
		t.Errorf("alert without an IP: status %d, want 400", code)
	}
	if code, _ := post(t, r, "/alerts/missing/ip_block", map[string]any{}); code != 404 {
		t.Errorf("unknown alert: status %d, want 404", code)
	}
	if len(c.blocked) != 0 {
		t.Errorf("connector was called: %v", c.blocked)
	}
	// An operator can name a public target explicitly.
	if code, _ := post(t, r, "/alerts/"+priv+"/ip_block", map[string]any{"target": "198.51.100.9"}); code != 200 || !c.blocked["198.51.100.9"] {
		t.Errorf("explicit target: status %d blocked=%v", code, c.blocked)
	}
}

func TestAlertBlockFailureIsReportedNotHidden(t *testing.T) {
	c := &stubConnector{err: errors.New("gateway down")}
	srv, r, _ := soarServer(t, soar.DefaultPolicy(), c)
	id := newAlert(srv, "198.51.100.7")
	code, body := post(t, r, "/alerts/"+id+"/ip_block", map[string]any{})
	if code != 502 {
		t.Fatalf("status %d body %v, want 502", code, body)
	}
	if st, disp := alertByID(srv, id); st != "open" || disp != "failed" {
		t.Errorf("a failed block must leave the alert open and record the failure: status=%s disposal=%s", st, disp)
	}
	if active := srv.soar.Blocks(true, 10); len(active) != 0 {
		t.Errorf("failed block counted as active: %+v", active)
	}
}

func TestAlertDryRunIsLabelled(t *testing.T) {
	c := &stubConnector{}
	srv, r, _ := soarServer(t, soar.Policy{DryRun: true}, c)
	id := newAlert(srv, "198.51.100.7")
	if code, _ := post(t, r, "/alerts/"+id+"/ip_block", map[string]any{}); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(c.blocked) != 0 {
		t.Error("dry run must not reach the connector")
	}
	if _, disp := alertByID(srv, id); disp != "dry_run" {
		t.Errorf("disposal = %q, want dry_run so nobody believes the attacker was blocked", disp)
	}
}

func TestRateLimitActionIsNotFaked(t *testing.T) {
	srv, r, _ := soarServer(t, soar.DefaultPolicy(), &stubConnector{})
	id := newAlert(srv, "198.51.100.7")
	if code, _ := post(t, r, "/alerts/"+id+"/rate_limit", map[string]any{}); code != 501 {
		t.Errorf("status %d, want 501", code)
	}
	if st, _ := alertByID(srv, id); st != "open" {
		t.Errorf("alert status = %s", st)
	}
	// Ordinary status actions still work.
	if code, _ := post(t, r, "/alerts/"+id+"/acknowledge", map[string]any{}); code != 200 {
		t.Errorf("acknowledge: status %d", code)
	}
}

func TestManualBlockUnblockAndListing(t *testing.T) {
	c := &stubConnector{}
	_, r, store := soarServer(t, soar.DefaultPolicy(), c)

	for name, body := range map[string]map[string]any{
		"bad ip":       {"ip": "nope"},
		"private":      {"ip": "192.168.0.1"},
		"ttl too long": {"ip": "198.51.100.1", "ttl_minutes": 100000},
		"bad ttl":      {"ip": "198.51.100.1", "ttl_minutes": -5},
		"unknown conn": {"ip": "198.51.100.1", "connectors": []string{"nope"}},
	} {
		if code, _ := post(t, r, "/soar/block", body); code != 400 {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
	if code, b := post(t, r, "/soar/block", map[string]any{"ip": "198.51.100.1", "ttl_minutes": 15, "reason": "manual"}); code != 200 || b["state"] != "active" {
		t.Fatalf("block: %d %v", code, b)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/soar/blocks?active=true", nil))
	var list struct {
		Items []map[string]any `json:"items"`
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0]["ip"] != "198.51.100.1" {
		t.Errorf("listing = %+v", list)
	}
	if code, _ := post(t, r, "/soar/unblock", map[string]any{"ip": "198.51.100.99"}); code != 404 {
		t.Errorf("unblock unknown: %d", code)
	}
	if code, _ := post(t, r, "/soar/unblock", map[string]any{}); code != 400 {
		t.Errorf("unblock without ip: %d", code)
	}
	if code, b := post(t, r, "/soar/unblock", map[string]any{"ip": "198.51.100.1"}); code != 200 || b["state"] != "released" || c.blocked["198.51.100.1"] {
		t.Errorf("unblock: %d %v", code, b)
	}
	if evs := auditEvents(t, store, "soar.unblock"); len(evs) != 2 {
		t.Errorf("both unblock attempts should be audited, got %d", len(evs))
	}
}

func TestConnectorsEndpointHidesSecretsAndTests(t *testing.T) {
	c := &stubConnector{}
	_, r, store := soarServer(t, soar.Policy{DryRun: true, MaxBlocksPerHour: 7}, c)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/soar/connectors", nil))
	var got struct {
		Enabled    bool `json:"enabled"`
		Connectors []struct {
			Name, Status string
		} `json:"connectors"`
		Policy map[string]any `json:"policy"`
	}
	json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Enabled || len(got.Connectors) != 1 || got.Connectors[0].Status != "unchecked" || got.Policy["dry_run"] != true || got.Policy["max_blocks_per_hour"].(float64) != 7 {
		t.Errorf("connectors = %s", w.Body.String())
	}
	if code, st := post(t, r, "/soar/connectors/stub/test", nil); code != 200 || st["status"] != "ok" {
		t.Errorf("test: %d %v", code, st)
	}
	if code, _ := post(t, r, "/soar/connectors/nope/test", nil); code != 400 {
		t.Errorf("unknown connector: %d", code)
	}
	if evs := auditEvents(t, store, "soar.test"); len(evs) != 1 {
		t.Errorf("connector tests should be audited: %d", len(evs))
	}
}
