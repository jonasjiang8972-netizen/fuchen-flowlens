package server

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/graph"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

// graphService names the service an event belongs to: the collector's
// service name when it has one, otherwise the host that was called.
func graphService(evt shared.APIEvent) string {
	if evt.Metadata.ServiceName != "" {
		return evt.Metadata.ServiceName
	}
	return evt.Application.Host
}

// FlowGraphHandler serves the traffic-driven data-flow map.
//
//	GET /graph/flow?view=business|service|data&q=<keyword>&limit=<edges>&min_calls=<n>
func (s *PlatformServer) FlowGraphHandler(c *gin.Context) {
	view := c.DefaultQuery("view", graph.ViewBusiness)
	switch view {
	case graph.ViewBusiness, graph.ViewService, graph.ViewData:
	default:
		c.JSON(400, gin.H{"error": "view 必须是 business、service 或 data"})
		return
	}
	limit, ok := intQuery(c, "limit", 0)
	if !ok {
		return
	}
	minCalls, ok := intQuery(c, "min_calls", 0)
	if !ok {
		return
	}
	c.JSON(200, s.graph.Flow(graph.FlowQuery{View: view, Keyword: c.Query("q"), Limit: limit, MinCalls: uint64(minCalls)}))
}

// AttackGraphHandler serves the attack-path graph built from alerts and the
// activity recorded for their sources.
//
//	GET /graph/attack?alert_id=<id>&limit=<sources>
func (s *PlatformServer) AttackGraphHandler(c *gin.Context) {
	limit, ok := intQuery(c, "limit", 0)
	if !ok {
		return
	}
	alertID := c.Query("alert_id")
	alerts := s.alertService.List()
	refs := make([]graph.AlertRef, 0, len(alerts))
	found := alertID == ""
	for _, a := range alerts {
		if a.ID == alertID {
			found = true
		}
		// Closed alerts no longer describe a live attack.
		if a.Status == "closed" && a.ID != alertID {
			continue
		}
		refs = append(refs, graph.AlertRef{
			ID: a.ID, Title: a.Title, Severity: a.Severity, Requirement: a.SourceRequirement,
			SourceIP: a.SourceIP, AccountID: a.AccountID, Time: a.Timestamp, RiskScore: a.RiskScore, Status: a.Status,
		})
	}
	if !found {
		c.JSON(404, gin.H{"error": "告警不存在"})
		return
	}
	c.JSON(200, s.graph.Attack(refs, graph.AttackQuery{AlertID: alertID, Limit: limit}))
}

// intQuery reads a non-negative integer query parameter, answering 400 itself
// when the value is malformed.
func intQuery(c *gin.Context, name string, def int) (int, bool) {
	raw := c.Query(name)
	if raw == "" {
		return def, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		c.JSON(400, gin.H{"error": fmt.Sprintf("%s 必须是非负整数", name)})
		return 0, false
	}
	return v, true
}

// SeedDemoGraph fills an empty graph with sample traffic that matches the
// sample alerts, so the demo consoles show a populated map. It never runs
// against a graph that already holds real traffic.
func (s *PlatformServer) SeedDemoGraph() {
	if len(s.graph.Flow(graph.FlowQuery{Limit: 1}).Edges) > 0 {
		return
	}
	now := time.Now()
	host := "api.example.com"
	obs := func(ago time.Duration, ip, acct, role, method, path string, status int, n int, fields ...string) {
		for i := 0; i < n; i++ {
			s.graph.Observe(graph.Observation{
				Time: now.Add(-ago + time.Duration(i)*time.Second), SrcIP: ip, Account: acct, Role: role,
				Service: host, Method: method, Path: path, Status: status, BytesOut: 2048, Fields: fields,
			})
		}
	}
	// Ordinary traffic.
	obs(2*time.Hour, "10.20.1.15", "web-bff", "service", "GET", "/api/v1/user/{id}", 200, 240, "phone", "email")
	obs(2*time.Hour, "10.20.1.15", "web-bff", "service", "GET", "/api/v1/order/{id}", 200, 180, "recipient_phone")
	obs(2*time.Hour, "10.20.1.16", "app-bff", "service", "POST", "/api/v1/payment/checkout", 200, 90, "card_number")
	obs(2*time.Hour, "10.20.1.16", "app-bff", "service", "POST", "/graphql", 200, 120)
	obs(90*time.Minute, "118.24.3.7", "usr-10021", "user", "GET", "/api/v1/order/{id}", 200, 25, "recipient_phone")
	obs(90*time.Minute, "118.24.3.7", "usr-10021", "user", "GET", "/api/v1/user/{id}/orders", 200, 12)
	// Credential stuffing, then a takeover of one account.
	obs(30*time.Minute, "198.51.100.22", "", "", "POST", "/api/v1/auth/login", 401, 68)
	obs(20*time.Minute, "198.51.100.22", "usr-30177", "user", "POST", "/api/v1/auth/login", 200, 1)
	obs(19*time.Minute, "198.51.100.22", "usr-30177", "user", "GET", "/api/v1/user/{id}", 200, 3, "phone", "email")
	// Object enumeration by a signed-in account.
	obs(15*time.Minute, "203.0.113.18", "usr-88213", "user", "GET", "/api/v1/order/{id}", 200, 140, "recipient_phone")
	obs(14*time.Minute, "203.0.113.18", "usr-88213", "user", "GET", "/api/v1/admin/users", 403, 6)
	// Payment card testing and a legacy export.
	obs(25*time.Minute, "45.33.22.11", "", "", "POST", "/api/v1/payment/checkout", 400, 120, "card_number")
	obs(50*time.Minute, "10.20.9.4", "svc-batch", "service", "GET", "/api/v1/legacy/export", 200, 4, "full_name", "id_card", "phone")
}
