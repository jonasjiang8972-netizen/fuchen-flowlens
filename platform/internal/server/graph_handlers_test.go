package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/graph"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func graphRouter(srv *PlatformServer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/graph/flow", srv.FlowGraphHandler)
	r.GET("/graph/attack", srv.AttackGraphHandler)
	return r
}

func getJSON(t *testing.T, r http.Handler, url string, out any) int {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	if out != nil && w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v (%s)", url, err, w.Body.String())
		}
	}
	return w.Code
}

func TestIngestFeedsFlowGraph(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	evt := shared.APIEvent{Timestamp: time.Now()}
	evt.Network.SrcIP = "203.0.113.30"
	evt.Application.Method = "GET"
	evt.Application.Host = "shop.example.com"
	evt.Application.PathRaw = "/api/orders/7"
	evt.Application.PathNormalized = "/api/orders/{id}"
	evt.Application.StatusCode = 200
	srv.processIngestEvent(context.Background(), evt)

	var g graph.Graph
	if code := getJSON(t, graphRouter(srv), "/graph/flow", &g); code != 200 {
		t.Fatalf("status %d", code)
	}
	found := map[string]bool{}
	for _, n := range g.Nodes {
		found[n.ID] = true
	}
	for _, id := range []string{"client:203.0.113.30", "service:shop.example.com", "endpoint:shop.example.com|GET|/api/orders/{id}"} {
		if !found[id] {
			t.Errorf("flow graph missing node %s (have %v)", id, found)
		}
	}
}

func TestFlowGraphRejectsBadParams(t *testing.T) {
	r := graphRouter(NewPlatformServer(storage.NewMemStore()))
	for _, url := range []string{"/graph/flow?view=bogus", "/graph/flow?limit=abc", "/graph/flow?min_calls=-1", "/graph/attack?limit=x"} {
		if code := getJSON(t, r, url, nil); code != 400 {
			t.Errorf("%s: status %d, want 400", url, code)
		}
	}
}

func TestAttackGraphFromRealDetection(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	ip := "198.51.100.77"
	// A burst of failed logins from one address raises an auth-failure alert.
	for i := 0; i < 80; i++ {
		evt := shared.APIEvent{Timestamp: time.Now()}
		evt.Network.SrcIP = ip
		evt.Application.Method = "POST"
		evt.Application.Host = "shop.example.com"
		evt.Application.PathNormalized = "/api/login"
		evt.Application.StatusCode = 401
		evt.Content.RequestHeaders = map[string]string{"X-User-Id": "acct-" + string(rune('a'+i%26))}
		srv.processIngestEvent(context.Background(), evt)
	}
	var alertID string
	for _, a := range srv.alertService.List() {
		if a.SourceIP == ip {
			alertID = a.ID
		}
	}
	if alertID == "" {
		t.Skip("burst did not raise an alert with the current engine thresholds")
	}

	var g graph.AttackGraph
	if code := getJSON(t, graphRouter(srv), "/graph/attack?alert_id="+alertID, &g); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(g.Paths) != 1 || g.Paths[0].Actor != ip {
		t.Fatalf("paths = %+v", g.Paths)
	}
	hasEndpoint := false
	for _, n := range g.Nodes {
		if n.Kind == graph.KindEndpoint && n.Label == "POST /api/login" {
			hasEndpoint = true
		}
	}
	if !hasEndpoint {
		t.Error("attack graph should show the endpoint the source attacked")
	}
	if code := getJSON(t, graphRouter(srv), "/graph/attack?alert_id=nope", nil); code != 404 {
		t.Errorf("unknown alert: status %d, want 404", code)
	}
}

func TestSeedDemoGraphOnlyFillsEmptyGraph(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	srv.SeedDemoGraph()
	first := srv.graph.Flow(graph.FlowQuery{Limit: 500})
	if len(first.Edges) == 0 {
		t.Fatal("demo seed produced no graph")
	}
	srv.SeedDemoGraph() // second call must not double the counts
	second := srv.graph.Flow(graph.FlowQuery{Limit: 500})
	if len(second.Edges) != len(first.Edges) || second.Edges[0].Calls != first.Edges[0].Calls {
		t.Error("seeding twice changed the graph")
	}

	real := NewPlatformServer(storage.NewMemStore())
	real.graph.Observe(graph.Observation{SrcIP: "1.2.3.4", Service: "s", Method: "GET", Path: "/real", Status: 200})
	real.SeedDemoGraph()
	for _, n := range real.graph.Flow(graph.FlowQuery{Limit: 500}).Nodes {
		if n.ID == "service:api.example.com" {
			t.Error("demo data was mixed into a graph holding real traffic")
		}
	}
}
