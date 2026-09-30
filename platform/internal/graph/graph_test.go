package graph

import (
	"fmt"
	"testing"
	"time"
)

func obs(ip, acct, svc, method, path string, status int, fields ...string) Observation {
	return Observation{Time: time.Now(), SrcIP: ip, Account: acct, Service: svc, Method: method, Path: path, Status: status, BytesOut: 100, Fields: fields}
}

func findNode(g Graph, id string) (Node, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

func findEdge(g Graph, src, dst string) (Edge, bool) {
	for _, e := range g.Edges {
		if e.Source == src && e.Target == dst {
			return e, true
		}
	}
	return Edge{}, false
}

func TestFlowAggregatesLayers(t *testing.T) {
	s := NewStore()
	for i := 0; i < 3; i++ {
		s.Observe(obs("203.0.113.5", "u1", "api.example.com", "get", "/api/v1/user/{id}", 200, "phone"))
	}
	s.Observe(obs("203.0.113.5", "u1", "api.example.com", "GET", "/api/v1/user/{id}", 500, "phone"))

	g := s.Flow(FlowQuery{})
	e, ok := findEdge(g, "client:203.0.113.5", "service:api.example.com")
	if !ok || e.Calls != 4 || e.Errors != 1 {
		t.Fatalf("client→service edge = %+v ok=%v, want 4 calls 1 error", e, ok)
	}
	ep := "endpoint:api.example.com|GET|/api/v1/user/{id}"
	if _, ok := findEdge(g, "service:api.example.com", ep); !ok {
		t.Fatal("missing service→endpoint edge (method should be upper-cased)")
	}
	if e, ok := findEdge(g, ep, "field:phone"); !ok || e.Calls != 4 {
		t.Fatalf("endpoint→field edge = %+v ok=%v", e, ok)
	}
	if n, _ := findNode(g, ep); n.Risk != "high" {
		t.Errorf("endpoint exposing a sensitive field: risk = %q, want high", n.Risk)
	}
	if n, _ := findNode(g, "client:203.0.113.5"); n.Zone != "external" {
		t.Errorf("public source zone = %q, want external", n.Zone)
	}
}

func TestFlowViews(t *testing.T) {
	s := NewStore()
	s.Observe(obs("10.0.0.7", "", "svc-a", "GET", "/plain", 200))
	s.Observe(obs("10.0.0.7", "", "svc-a", "GET", "/pii", 200, "id_card"))

	svc := s.Flow(FlowQuery{View: ViewService})
	for _, n := range svc.Nodes {
		if n.Kind == KindClient || n.Kind == KindField {
			t.Errorf("service view contains %s node %s", n.Kind, n.ID)
		}
	}
	data := s.Flow(FlowQuery{View: ViewData})
	if _, ok := findNode(data, "endpoint:svc-a|GET|/plain"); ok {
		t.Error("data view should only include endpoints exposing sensitive fields")
	}
	if _, ok := findNode(data, "endpoint:svc-a|GET|/pii"); !ok {
		t.Error("data view is missing the sensitive endpoint")
	}
	if n, _ := findNode(s.Flow(FlowQuery{}), "client:10.0.0.7"); n.Zone != "internal" {
		t.Errorf("private source zone = %q, want internal", n.Zone)
	}
}

func TestFlowKeywordLimitAndOrder(t *testing.T) {
	s := NewStore()
	for i := 0; i < 5; i++ {
		s.Observe(obs("1.1.1.1", "", "svc", "GET", "/busy", 200))
	}
	s.Observe(obs("1.1.1.1", "", "svc", "GET", "/quiet", 200))

	g := s.Flow(FlowQuery{Keyword: "QUIET"})
	if _, ok := findNode(g, "endpoint:svc|GET|/quiet"); !ok {
		t.Error("keyword match (case-insensitive) missing")
	}
	if _, ok := findNode(g, "endpoint:svc|GET|/busy"); ok {
		t.Error("non-matching endpoint should be excluded by keyword")
	}

	g = s.Flow(FlowQuery{Limit: 1})
	if !g.Stats.Truncated || len(g.Edges) != 1 {
		t.Fatalf("limit 1: truncated=%v edges=%d", g.Stats.Truncated, len(g.Edges))
	}
	if g.Edges[0].Calls != 6 {
		t.Errorf("busiest edge should win, got %d calls", g.Edges[0].Calls)
	}
}

func TestFlowMedianErrorRisk(t *testing.T) {
	s := NewStore()
	for i := 0; i < 30; i++ {
		s.Observe(obs("9.9.9.9", "", "svc", "POST", "/login", 401))
	}
	if n, _ := findNode(s.Flow(FlowQuery{}), "endpoint:svc|POST|/login"); n.Risk != "medium" {
		t.Errorf("endpoint failing most calls: risk = %q, want medium", n.Risk)
	}
}

func TestCapsBoundGrowth(t *testing.T) {
	s := NewStore()
	for i := 0; i < maxNodes+500; i++ {
		s.Observe(obs(fmt.Sprintf("8.8.%d.%d", i/250, i%250), "", "svc", "GET", fmt.Sprintf("/p%d", i), 200))
	}
	s.mu.RLock()
	nodes, edges := len(s.nodes), len(s.edges)
	dropped := s.dropped
	s.mu.RUnlock()
	if nodes > maxNodes || edges > maxEdges {
		t.Fatalf("caps exceeded: nodes=%d edges=%d", nodes, edges)
	}
	if dropped == 0 {
		t.Error("dropped counter should record observations refused at the cap")
	}
}

func TestPruneRemovesStale(t *testing.T) {
	s := NewStore()
	old := obs("2.2.2.2", "u", "svc", "GET", "/old", 200)
	old.Time = time.Now().Add(-48 * time.Hour)
	s.Observe(old)
	s.Observe(obs("3.3.3.3", "u", "svc", "GET", "/new", 200))

	s.prune(time.Now().Add(-24 * time.Hour))
	g := s.Flow(FlowQuery{})
	if _, ok := findNode(g, "endpoint:svc|GET|/old"); ok {
		t.Error("stale endpoint survived prune")
	}
	if _, ok := findNode(g, "endpoint:svc|GET|/new"); !ok {
		t.Error("fresh endpoint was pruned")
	}
	if _, ok := s.byIP["2.2.2.2"]; ok {
		t.Error("stale actor still indexed")
	}
}

func TestStageOf(t *testing.T) {
	cases := map[string]string{
		"FR-RISK-002": "侦察探测", "FR-DET-002": "凭据攻击", "FR-DET-001": "对象枚举",
		"FR-DET-005": "权限提升", "FR-DLP-003": "数据外泄", "FR-ALT-001": "异常访问",
	}
	for req, want := range cases {
		if got := StageOf(req).Name; got != want {
			t.Errorf("StageOf(%s) = %s, want %s", req, got, want)
		}
	}
}

func TestAttackGraphChainsAlertsBySource(t *testing.T) {
	s := NewStore()
	ip := "198.51.100.9"
	s.Observe(obs(ip, "", "svc", "POST", "/login", 401))
	s.Observe(obs(ip, "victim", "svc", "GET", "/api/order/{id}", 200, "phone"))
	s.Observe(obs(ip, "victim", "svc", "GET", "/admin/export", 200, "id_card"))
	s.Observe(obs("192.0.2.1", "other", "svc", "GET", "/health", 200))

	now := time.Now()
	alerts := []AlertRef{
		{ID: "a2", Title: "export", Severity: "critical", Requirement: "FR-DLP-003", SourceIP: ip, AccountID: "victim", Time: now.Add(time.Minute), RiskScore: 95},
		{ID: "a1", Title: "stuffing", Severity: "high", Requirement: "FR-DET-002", SourceIP: ip, Time: now, RiskScore: 80},
		{ID: "a3", Title: "unrelated", Severity: "medium", Requirement: "FR-RISK-002", SourceIP: "192.0.2.1", Time: now, RiskScore: 50},
	}
	g := s.Attack(alerts, AttackQuery{})
	if len(g.Paths) != 2 {
		t.Fatalf("paths = %d, want 2 sources", len(g.Paths))
	}
	p := g.Paths[0] // most severe first
	if p.Actor != ip || p.Severity != "critical" {
		t.Fatalf("first path = %+v", p)
	}
	if len(p.Steps) != 2 || p.Steps[0].AlertID != "a1" || p.Steps[1].AlertID != "a2" {
		t.Fatalf("steps not in time order: %+v", p.Steps)
	}
	if !p.Escalating {
		t.Error("credential attack followed by exfiltration should be escalating")
	}
	if len(p.Accounts) != 1 || p.Accounts[0] != "victim" {
		t.Errorf("accounts = %v", p.Accounts)
	}
	if _, ok := findEdge(g.Graph, "alert:a1", "alert:a2"); !ok {
		t.Error("missing sequence edge between consecutive alerts")
	}
	if _, ok := findEdge(g.Graph, "account:victim", "endpoint:svc|GET|/admin/export"); !ok {
		t.Error("account→endpoint edge missing")
	}
	if _, ok := findEdge(g.Graph, "endpoint:svc|GET|/admin/export", "field:id_card"); !ok {
		t.Error("endpoint→field edge missing")
	}
	if _, ok := findNode(g.Graph, "endpoint:svc|GET|/health"); !ok {
		t.Error("second source's endpoint missing from the unfiltered graph")
	}
	only := s.Attack(alerts, AttackQuery{AlertID: "a1"})
	if _, ok := findNode(only.Graph, "endpoint:svc|GET|/health"); ok {
		t.Error("another source's endpoint leaked into an alert-filtered graph")
	}
	if len(only.Paths) != 1 || len(only.Paths[0].Steps) != 2 {
		t.Errorf("filtered graph should keep the whole chain of the alert's source: %+v", only.Paths)
	}
}

func TestAttackGraphSingleAlertAndUntrackedSource(t *testing.T) {
	s := NewStore()
	ip := "198.51.100.9"
	s.Observe(obs(ip, "", "svc", "GET", "/x", 200))
	alerts := []AlertRef{
		{ID: "a1", Title: "t1", Severity: "high", Requirement: "FR-DET-001", SourceIP: ip, Time: time.Now()},
		{ID: "a9", Title: "seed", Severity: "low", Requirement: "FR-AST-002", Time: time.Now()},
	}
	g := s.Attack(alerts, AttackQuery{AlertID: "a1"})
	if len(g.Paths) != 1 || g.Paths[0].Actor != ip {
		t.Fatalf("alert filter: paths = %+v", g.Paths)
	}
	// An alert with no source and no account still gets a node.
	g = s.Attack(alerts, AttackQuery{AlertID: "a9"})
	if len(g.Paths) != 1 || len(g.Nodes) < 2 {
		t.Fatalf("untracked alert: paths=%d nodes=%d", len(g.Paths), len(g.Nodes))
	}
	if empty := s.Attack(nil, AttackQuery{}); empty.Nodes == nil || empty.Paths == nil {
		t.Error("empty result must serialise as [] not null")
	}
}

func TestAttackGraphSourceLimit(t *testing.T) {
	s := NewStore()
	var alerts []AlertRef
	for i := 0; i < 5; i++ {
		alerts = append(alerts, AlertRef{ID: fmt.Sprintf("a%d", i), Severity: "high", Requirement: "FR-DET-001", SourceIP: fmt.Sprintf("7.7.7.%d", i), Time: time.Now(), RiskScore: 70 + i})
	}
	g := s.Attack(alerts, AttackQuery{Limit: 2})
	if len(g.Paths) != 2 || !g.Stats.Truncated {
		t.Fatalf("limit: paths=%d truncated=%v", len(g.Paths), g.Stats.Truncated)
	}
	if g.Paths[0].Actor != "7.7.7.4" {
		t.Errorf("highest risk score should lead among equal severities, got %s", g.Paths[0].Actor)
	}
}
