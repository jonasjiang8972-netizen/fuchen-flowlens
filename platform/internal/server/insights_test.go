package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func call(t *testing.T, h gin.HandlerFunc, target string) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", target, nil)
	h(c)
	if w.Code != 200 {
		t.Fatalf("%s: %d %s", target, w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

// emptyServer has no sample data: a fresh installation.
func emptyServer(t *testing.T) *PlatformServer {
	t.Helper()
	srv, err := NewPlatformServerFrom(t.Context(), storage.NewMemStore(), false)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func ingestRequest(srv *PlatformServer, path string, headers map[string]string, status uint16) {
	var evt shared.APIEvent
	evt.Application.Method = "GET"
	evt.Application.Host = "shop.example"
	evt.Application.PathRaw = path
	evt.Application.StatusCode = status
	evt.Network.SrcIP = "10.8.0.1"
	evt.Content.RequestHeaders = headers
	srv.processIngestEvent(context.Background(), evt)
}

func TestCoverageSummaryOnFreshInstall(t *testing.T) {
	srv := emptyServer(t)
	out := call(t, srv.CoverageSummaryHandler, "/coverage/summary")
	spots := out["blind_spots"].([]any)
	if len(spots) != 1 || spots[0].(map[string]any)["type"] != "未部署采集器" {
		t.Fatalf("fresh install blind spots: %v", spots)
	}
}

func TestCoverageSummaryDerivesBlindSpots(t *testing.T) {
	srv := emptyServer(t)
	if _, err := srv.agentService.RegisterAgent(service.Registration{ID: "gw-1", Hostname: "gw", CollectMode: "gateway_log"}); err != nil {
		t.Fatal(err)
	}
	// Anonymous traffic without response bodies to a sensitive endpoint.
	for i := 0; i < 4; i++ {
		ingestRequest(srv, "/api/v1/users/7?phone=138****0000", nil, 200)
	}
	ingestRequest(srv, "/api/v1/orders", map[string]string{"x-user-id": "u1"}, 200)

	out := call(t, srv.CoverageSummaryHandler, "/coverage/summary")
	traffic := out["traffic"].(map[string]any)
	if traffic["events"].(float64) != 5 || traffic["identified_share"].(float64) != 0.2 || traffic["body_share"].(float64) != 0 {
		t.Fatalf("traffic: %v", traffic)
	}
	types := map[string]string{}
	for _, s := range out["blind_spots"].([]any) {
		m := s.(map[string]any)
		types[m["type"].(string)] = m["severity"].(string)
	}
	for typ, sev := range map[string]string{"敏感接口无责任人": "high", "接口无责任人": "medium", "调用方无法识别": "medium", "未采集响应体": "medium"} {
		if types[typ] != sev {
			t.Errorf("blind spot %s = %q, want %q (all: %v)", typ, types[typ], sev, types)
		}
	}
	if _, ok := types["未部署采集器"]; ok {
		t.Errorf("collector registered but reported missing")
	}
}

func TestCallersHandler(t *testing.T) {
	srv := emptyServer(t)
	for i := 0; i < 3; i++ {
		ingestRequest(srv, "/api/v1/orders", map[string]string{"x-user-id": "u-77"}, 200)
	}
	ingestRequest(srv, "/api/v1/orders", map[string]string{"x-api-key": "abcdefghijkl"}, 403)
	srv.alertService.CreateDetectionAlert("FR-DET-001", "high", "t", "d", "10.8.0.1", "u-77", 80, 0.9)

	out := call(t, srv.ListCallersHandler, "/callers")
	items := out["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("items: %v", items)
	}
	top := items[0].(map[string]any)
	if top["caller_id"] != "u-77" || top["requests"].(float64) != 3 || top["open_alerts"].(float64) != 1 || top["type"] != "external_user" {
		t.Fatalf("top caller: %v", top)
	}
	partner := items[1].(map[string]any)
	// The key is fingerprinted by redaction before it identifies the caller.
	id, _ := partner["caller_id"].(string)
	if !strings.HasPrefix(id, "partner:sm3:") || len(id) != len("partner:sm3:")+12 || strings.Contains(id, "abcdefghijkl") || partner["errors"].(float64) != 1 {
		t.Fatalf("partner caller: %v", partner)
	}
	if rules := out["rules"].([]any); len(rules) != 5 {
		t.Fatalf("rules: %v", rules)
	}
	filtered := call(t, srv.ListCallersHandler, "/callers?type=partner")["items"].([]any)
	if len(filtered) != 1 {
		t.Fatalf("type filter: %v", filtered)
	}
}

func TestAlertTrendHandlerValidatesDays(t *testing.T) {
	srv := emptyServer(t)
	if items := call(t, srv.AlertTrendHandler, "/alerts/trend?days=14")["items"].([]any); len(items) != 14 {
		t.Fatalf("14 days: %d", len(items))
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/alerts/trend?days=0", nil)
	srv.AlertTrendHandler(c)
	if w.Code != 400 {
		t.Fatalf("days=0: %d", w.Code)
	}
}
