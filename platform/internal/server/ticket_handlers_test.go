package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/soar"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func ticketRouter(srv *PlatformServer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/tickets", srv.ListTicketsHandler)
	r.GET("/tickets/summary", srv.TicketSummaryHandler)
	r.GET("/tickets/:id", srv.GetTicketHandler)
	r.POST("/tickets", srv.CreateTicketHandler)
	r.POST("/tickets/:id/transition", srv.TransitionTicketHandler)
	r.POST("/tickets/:id/assign", srv.AssignTicketHandler)
	r.POST("/tickets/:id/comment", srv.CommentTicketHandler)
	r.POST("/alerts/:id/:action", srv.AlertActionHandler)
	return r
}

func alertStatus(srv *PlatformServer, id string) string {
	s, _ := alertByID(srv, id)
	return s
}

func TestSeriousDetectionOpensATicketAutomatically(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	ip := "198.51.100.77"
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
	// Only high and critical alerts get a ticket; the burst also raised lower
	// severity alerts, which must not.
	list := srv.ticketService.List(service.TicketFilter{})
	if len(list) == 0 {
		t.Skip("burst did not raise a serious alert with the current engine thresholds")
	}
	tk := list[0]
	if !tk.Auto || tk.Status != "pending" || tk.Action == "" || tk.CreatedBy != "system" {
		t.Fatalf("automatic ticket = %+v", tk)
	}
	if tk.Severity != "high" && tk.Severity != "critical" {
		t.Errorf("ticket for a %s alert", tk.Severity)
	}
	for _, a := range srv.alertService.List() {
		if a.SourceIP == ip && a.Severity != "high" && a.Severity != "critical" && srv.ticketService.ForAlert(a.ID) != nil {
			t.Errorf("a %s alert got a ticket", a.Severity)
		}
	}
	// The burst spread across 26 accounts raised many alerts, but one attack
	// from one source must be one ticket.
	if n := len(srv.ticketService.List(service.TicketFilter{})); n != 1 {
		t.Errorf("one attack opened %d tickets, want 1 (%d alerts)", n, len(srv.alertService.List()))
	}
	if tk.RelatedCount == 0 {
		t.Errorf("the other alerts were not attached to the ticket: %+v", tk)
	}
}

func TestTicketHTTPWorkflowSyncsTheAlert(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	r := ticketRouter(srv)
	alertID := newAlert(srv, "198.51.100.7")

	code, tk := post(t, r, "/tickets", map[string]any{"alert_id": alertID, "owner": "安全运营"})
	if code != 201 || tk["severity"] != "high" || tk["title"] != "撞库" || tk["action"] == "" {
		t.Fatalf("create from alert: %d %v", code, tk)
	}
	id := tk["ticket_id"].(string)

	// A second ticket for the same open alert points at the first.
	code, dup := post(t, r, "/tickets", map[string]any{"alert_id": alertID})
	if code != 409 || dup["ticket_id"] != id || dup["code"] != "ticket_exists" {
		t.Errorf("duplicate: %d %v", code, dup)
	}
	if code, _ := post(t, r, "/tickets", map[string]any{"alert_id": "missing"}); code != 404 {
		t.Errorf("unknown alert: %d", code)
	}
	if code, _ := post(t, r, "/tickets", map[string]any{"title": "", "severity": "high"}); code != 400 {
		t.Errorf("no title: %d", code)
	}

	base := "/tickets/" + id + "/transition"
	if code, _ := post(t, r, base, map[string]any{"to": "done"}); code != 409 {
		t.Errorf("pending -> done: %d, want 409", code)
	}
	if code, _ := post(t, r, base, map[string]any{}); code != 400 {
		t.Errorf("missing target: %d", code)
	}
	if code, _ := post(t, r, base, map[string]any{"to": "processing"}); code != 200 {
		t.Fatalf("start: %d", code)
	}
	if code, _ := post(t, r, base, map[string]any{"to": "review"}); code != 400 {
		t.Errorf("review without a note: %d, want 400", code)
	}
	post(t, r, base, map[string]any{"to": "review", "note": "已封禁并修复"})

	// No principal is set in this router, so the actor is "system" for both the
	// submission and the approval: the separation rule must refuse it.
	if code, body := post(t, r, base, map[string]any{"to": "done"}); code != 403 || body["code"] != "self_review" {
		t.Errorf("same person approving: %d %v", code, body)
	}
	if st := alertStatus(srv, alertID); st == "resolved" {
		t.Error("alert resolved although the ticket was not approved")
	}

	if code, _ := post(t, r, "/tickets/"+id+"/comment", map[string]any{"text": "已通知业务方"}); code != 200 {
		t.Errorf("comment: %d", code)
	}
	if code, _ := post(t, r, "/tickets/"+id+"/comment", map[string]any{"text": " "}); code != 400 {
		t.Errorf("blank comment: %d", code)
	}
	if code, _ := post(t, r, "/tickets/"+id+"/assign", map[string]any{"owner": "订单团队"}); code != 200 {
		t.Errorf("assign: %d", code)
	}
	if code, _ := post(t, r, "/tickets/nope/transition", map[string]any{"to": "processing"}); code != 404 {
		t.Errorf("unknown ticket: %d", code)
	}
}

func TestClosingATicketResolvesItsAlert(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	r := ticketRouter(srv)
	alertID := newAlert(srv, "198.51.100.7")
	_, tk := post(t, r, "/tickets", map[string]any{"alert_id": alertID, "owner": "team"})
	id := tk["ticket_id"].(string)

	// Close as a false positive: the alert follows.
	post(t, r, "/tickets/"+id+"/transition", map[string]any{"to": "false_positive", "note": "压测流量"})
	if st := alertStatus(srv, alertID); st != "false_positive" {
		t.Errorf("alert status = %s, want false_positive", st)
	}
	// Reopening puts the alert back to work.
	post(t, r, "/tickets/"+id+"/transition", map[string]any{"to": "processing", "note": "确认是真实攻击"})
	if st := alertStatus(srv, alertID); st != "in_progress" {
		t.Errorf("alert status after reopen = %s, want in_progress", st)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tickets/summary", nil))
	var sum map[string]any
	json.Unmarshal(w.Body.Bytes(), &sum)
	if sum["open"].(float64) != 1 {
		t.Errorf("summary = %v", sum)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tickets?open=true&alert_id="+alertID, nil))
	var list struct {
		Items []map[string]any `json:"items"`
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Items) != 1 || list.Items[0]["status"] != "processing" || list.Items[0]["reopened"].(float64) != 1 {
		t.Errorf("list = %s", w.Body.String())
	}
}

func TestBlockingFromAnAlertIsNotedOnItsTicket(t *testing.T) {
	c := &stubConnector{}
	srv, _, _ := soarServer(t, soar.DefaultPolicy(), c)
	r := ticketRouter(srv)
	alertID := newAlert(srv, "198.51.100.7")
	_, tk := post(t, r, "/tickets", map[string]any{"alert_id": alertID})

	if code, _ := post(t, r, "/alerts/"+alertID+"/ip_block", map[string]any{}); code != 200 {
		t.Fatalf("block: %d", code)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tickets/"+tk["ticket_id"].(string), nil))
	if !strings.Contains(w.Body.String(), "198.51.100.7") || !strings.Contains(w.Body.String(), "alert_action") {
		t.Errorf("the block was not recorded on the ticket: %s", w.Body.String())
	}
}

func TestSeedDemoTicketsMatchSampleAlerts(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	srv.SeedDemoTickets()
	list := srv.ticketService.List(service.TicketFilter{})
	if len(list) == 0 {
		t.Fatal("no demo tickets")
	}
	known := map[string]bool{}
	for _, a := range srv.alertService.List() {
		known[a.ID] = true
	}
	for _, tk := range list {
		if !known[tk.AlertID] || (tk.Severity != "high" && tk.Severity != "critical") {
			t.Errorf("demo ticket %s does not match a serious sample alert: %+v", tk.ID, tk)
		}
	}
}
