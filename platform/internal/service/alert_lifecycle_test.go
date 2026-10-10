package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func TestAlertLifecycleAndHistory(t *testing.T) {
	s := NewAlertService()
	s.now = func() time.Time { return time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC) }
	a := s.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "遍历 30 个对象", "203.0.113.5", "acct-1", 80, 0.9)

	steps := []struct{ action, status string }{
		{"acknowledge", "acknowledged"},
		{"ip_block", "in_progress"},
		{"resolve", "resolved"},
		{"reopen", "open"},
		{"false_positive", "false_positive"},
	}
	for _, st := range steps {
		got, err := s.ExecuteAction(a.ID, st.action, "secadmin", "备注 "+st.action)
		if err != nil {
			t.Fatalf("%s: %v", st.action, err)
		}
		if got.Status != st.status {
			t.Fatalf("%s: status %q, want %q", st.action, got.Status, st.status)
		}
	}
	if _, err := s.ExecuteAction(a.ID, "delete_everything", "secadmin", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown action: %v", err)
	}
	d, _ := s.GetDetail(a.ID)
	if len(d.History) != len(steps) || d.History[1].Action != "ip_block" || d.Disposal == nil || d.Disposal.Status != "recorded" {
		t.Fatalf("history/disposal: %+v %+v", d.History, d.Disposal)
	}
	var tl []string
	for _, e := range d.Timeline {
		tl = append(tl, e.Event+":"+e.Detail)
	}
	joined := strings.Join(tl, " | ")
	if !strings.Contains(joined, "告警产生") || !strings.Contains(joined, "secadmin：封禁来源 IP，备注 ip_block") {
		t.Fatalf("timeline: %s", joined)
	}
}

func TestAlertEvidenceAndRelatedAreReal(t *testing.T) {
	s := NewAlertService()
	now := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	a := s.CreateDetectionAlert("FR-DET-002", "high", "撞库", "失败 20 次", "198.51.100.9", "ip:198.51.100.9", 85, 0.6)
	now = now.Add(3 * time.Minute)
	s.CreateDetectionAlert("FR-DET-002", "high", "撞库", "失败 40 次", "198.51.100.9", "ip:198.51.100.9", 88, 0.6)
	other := s.CreateDetectionAlert("FR-DET-007", "critical", "SSRF", "元数据", "198.51.100.9", "ip:198.51.100.9", 95, 0.6)
	unrelated := s.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "x", "10.0.0.1", "acct-z", 75, 0.9)

	d, _ := s.GetDetail(a.ID)
	if d.RawData["occurrences"] != "2" || d.RawData["duration"] != "3m0s" || d.RawData["source_ip"] != "198.51.100.9" {
		t.Fatalf("evidence: %v", d.RawData)
	}
	for _, fake := range []string{"user_agent", "ja3_fingerprint", "success_rate"} {
		if _, ok := d.RawData[fake]; ok {
			t.Fatalf("evidence still has made-up %s", fake)
		}
	}
	if len(d.RelatedAlerts) == 0 || d.RelatedAlerts[0] != other.ID {
		t.Fatalf("related: %v, want %s first", d.RelatedAlerts, other.ID)
	}
	for _, id := range d.RelatedAlerts {
		if id == unrelated.ID {
			t.Fatalf("unrelated alert listed")
		}
	}
}

func TestDetectionsMergeWhileAlertIsBeingHandled(t *testing.T) {
	s := NewAlertService()
	a := s.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "x", "1.1.1.1", "acct", 80, 0.9)
	if _, err := s.ExecuteAction(a.ID, "rate_limit", "secadmin", ""); err != nil {
		t.Fatal(err)
	}
	b := s.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "y", "1.1.1.1", "acct", 82, 0.9)
	if b.ID != a.ID || b.OccurrenceCount != 2 {
		t.Fatalf("ongoing attack during handling opened %s (count %d)", b.ID, b.OccurrenceCount)
	}
	_, _ = s.ExecuteAction(a.ID, "resolve", "secadmin", "")
	c := s.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "z", "1.1.1.1", "acct", 82, 0.9)
	if c.ID == a.ID {
		t.Fatalf("recurrence after resolution merged into the resolved alert")
	}
}

func TestAlertTrend(t *testing.T) {
	s := &AlertService{alerts: map[string]*Alert{}, activeDetections: map[string]string{}}
	now := time.Date(2026, 3, 10, 15, 0, 0, 0, time.Local)
	s.now = func() time.Time { return now }
	add := func(daysAgo int, sev string) *Alert {
		a := &Alert{ID: fmt.Sprintf("a-%d-%s-%d", daysAgo, sev, len(s.alerts)), Severity: sev, Timestamp: now.AddDate(0, 0, -daysAgo)}
		s.alerts[a.ID] = a
		return a
	}
	add(0, "critical")
	add(0, "high")
	add(2, "medium")
	add(6, "low")
	add(7, "critical") // outside a 7-day window
	closed := add(3, "high")
	closed.History = []AlertHistory{{Time: now.AddDate(0, 0, -1), Status: "resolved"}}

	tr := s.Trend(7)
	if len(tr) != 7 || tr[0].Date != "2026-03-04" || tr[6].Date != "2026-03-10" {
		t.Fatalf("days: %+v", tr)
	}
	if tr[6].Critical != 1 || tr[6].High != 1 || tr[4].Medium != 1 || tr[0].Low != 1 || tr[3].High != 1 || tr[5].Closed != 1 {
		t.Fatalf("counts: %+v", tr)
	}
	total := 0
	for _, d := range tr {
		total += d.Critical + d.High + d.Medium + d.Low
	}
	if total != 5 {
		t.Fatalf("counted %d alerts in the window, want 5", total)
	}
}

func TestDiscoveredAssetIsShadowUntilClaimed(t *testing.T) {
	s := NewAssetService()
	var evt shared.APIEvent
	evt.Application.Method = "GET"
	evt.Application.Host = "new.example"
	evt.Application.PathNormalized = "/api/v9/things"
	a := s.ObserveEvent(evt, nil)
	if a.Status != "shadow" || a.ClaimStatus != "unclaimed" {
		t.Fatalf("discovered asset: status=%s claim=%s", a.Status, a.ClaimStatus)
	}
	if err := s.Claim(a.ID, "team-x"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(a.ID)
	if got.Status != "active" || got.Owner != "team-x" {
		t.Fatalf("after claim: %+v", got)
	}
}

func TestAssetChangesAndRelated(t *testing.T) {
	s := NewAssetService()
	obs := func(path string, fields ...string) Asset {
		var evt shared.APIEvent
		evt.Application.Method = "GET"
		evt.Application.Host = "bank.example"
		evt.Application.PathNormalized = path
		return s.ObserveEvent(evt, fields)
	}
	a := obs("/api/v2/cards/{id}", "card_number")
	obs("/api/v2/cards/{id}", "card_number")        // no change
	obs("/api/v2/cards/{id}", "card_number", "cvv") // new field
	obs("/api/v2/cards/{id}/limits")
	obs("/api/v3/other")
	if err := s.Claim(a.ID, "cards-team"); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetDetail(a.ID)
	var types []string
	for _, c := range d.ChangeHistory {
		types = append(types, c.ChangeType)
	}
	// Newest first: claim, new field, discovery (the creation event's
	// fields are part of the discovery, not a change).
	if strings.Join(types, ",") != "owner_changed,sensitive_field_added,discovered" {
		t.Fatalf("changes: %v", types)
	}
	if len(d.RelatedAssets) != 1 {
		t.Fatalf("related: %v", d.RelatedAssets)
	}
	if fmt.Sprint(d.Alerts) != "[]" {
		t.Fatalf("asset service must not make up alerts: %v", d.Alerts)
	}
}

func TestAlertsForEndpoint(t *testing.T) {
	s := NewAlertService()
	a := s.CreateDetectionAlert("FR-DET-001", "high", "BOLA", "x", "1.1.1.1", "acct-e", 80, 0.9)
	s.AddEndpoint(a.ID, "GET /api/v1/things/{id}")
	s.AddEndpoint(a.ID, "GET /api/v1/things/{id}") // once
	if got := s.ForEndpoint("GET /api/v1/things/{id}"); len(got) != 1 || got[0].ID != a.ID {
		t.Fatalf("ForEndpoint: %+v", got)
	}
	if got, _ := s.Get(a.ID); len(got.Endpoints) != 1 {
		t.Fatalf("endpoints: %v", got.Endpoints)
	}
	if got := s.ForEndpoint("GET /nothing"); len(got) != 0 {
		t.Fatalf("unrelated endpoint: %+v", got)
	}
}
