package server

import (
	"fmt"
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

// alertsFor returns the alerts raised for account (sample alerts excluded).
func alertsFor(srv *PlatformServer, account string) []service.Alert {
	var out []service.Alert
	for _, a := range srv.alertService.List() {
		if a.AccountID == account {
			out = append(out, a)
		}
	}
	return out
}

// traverseObjects sends n accesses by account to distinct objects.
func traverseObjects(srv *PlatformServer, account string, n int) detection {
	var d detection
	for i := 0; i < n; i++ {
		req := accessDetectionRequest{AccountID: account, Role: "user", Endpoint: "/api/v1/orders/{id}",
			ObjectID: fmt.Sprintf("o-%d", i), SourceIP: "10.1.1.1", Status: 200}
		d = srv.evaluate(detectInput{req: req})
		srv.raise(d, req, 0.9)
	}
	return d
}

func TestDisabledRuleDoesNotDetect(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	if _, err := srv.ruleService.UpdateEnabled(ruleBOLA, false); err != nil {
		t.Fatal(err)
	}
	if d := traverseObjects(srv, "acct-off", 60); d.Score != 0 {
		t.Fatalf("disabled BOLA rule scored %d", d.Score)
	}
	if n := len(alertsFor(srv, "acct-off")); n != 0 {
		t.Fatalf("disabled rule raised %d alerts", n)
	}

	if _, err := srv.ruleService.UpdateEnabled(ruleBOLA, true); err != nil {
		t.Fatal(err)
	}
	if d := traverseObjects(srv, "acct-on", 20); d.RuleID != ruleBOLA || d.Score < alertThreshold {
		t.Fatalf("enabled rule: %+v", d)
	}
	alerts := alertsFor(srv, "acct-on")
	if len(alerts) != 1 || alerts[0].SourceRequirement != "FR-DET-001" {
		t.Fatalf("enabled rule alerts: %+v", alerts)
	}
	if r, _ := srv.ruleService.Get(ruleBOLA); r.HitCount == 0 {
		t.Fatalf("hit not counted")
	}
}

func TestRuleParameterChangeAppliesImmediately(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	if d := traverseObjects(srv, "acct-a", 10); d.Score != 0 {
		t.Fatalf("10 objects scored %d with the default threshold 20", d.Score)
	}
	if _, err := srv.ruleService.UpdateConfig(ruleBOLA, map[string]interface{}{"traverse_threshold": 5.0}); err != nil {
		t.Fatal(err)
	}
	srv.applyRuleConfig(ruleBOLA)
	if d := traverseObjects(srv, "acct-b", 5); d.Score != alertThreshold {
		t.Fatalf("5 objects scored %d after lowering the threshold to 5", d.Score)
	}
}

// A 401 that also completes an object traversal is attributed to the engine
// that scored it, not guessed from the status code.
func TestAlertAttributedToScoringRule(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	traverseObjects(srv, "acct-x", 19)
	req := accessDetectionRequest{AccountID: "acct-x", Role: "user", Endpoint: "/api/v1/orders/{id}",
		ObjectID: "o-final", SourceIP: "10.1.1.1", Status: 401}
	d := srv.evaluate(detectInput{req: req})
	if d.RuleID != ruleBOLA {
		t.Fatalf("finding attributed to %q, want %s", d.RuleID, ruleBOLA)
	}
	if a := srv.raise(d, req, 0.9); a == nil || a.SourceRequirement != "FR-DET-001" {
		t.Fatalf("alert: %+v", a)
	}
}

func TestAuthFailuresBuildWhileRuleIsOff(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	if _, err := srv.ruleService.UpdateEnabled(ruleAuth, false); err != nil {
		t.Fatal(err)
	}
	fail := func(i int) detection {
		req := accessDetectionRequest{AccountID: fmt.Sprintf("victim-%d", i%6), Endpoint: "/api/v1/login",
			SourceIP: "203.0.113.9", Status: 401}
		return srv.evaluate(detectInput{req: req})
	}
	for i := 0; i < 25; i++ {
		if d := fail(i); d.Score != 0 {
			t.Fatalf("disabled auth rule scored %d", d.Score)
		}
	}
	if _, err := srv.ruleService.UpdateEnabled(ruleAuth, true); err != nil {
		t.Fatal(err)
	}
	if d := fail(25); d.RuleID != ruleAuth || d.Score < 85 {
		t.Fatalf("after enabling: %+v", d)
	}
}

func TestExposedSensitiveFieldsIgnoreRequestHeaders(t *testing.T) {
	evt := shared.APIEvent{}
	evt.Content.RequestHeaders = map[string]string{"Authorization": "x", "X-Auth-Token": "y"}
	evt.Content.QueryParams = map[string]string{"mobile": "138****0000"}
	evt.Content.ResponseBody = []byte(`{"data":[{"id_card":"110***","name":"a","items":[{"card_number":"6222***"}]}]}`)
	got := exposedSensitiveFields(evt)
	want := []string{"card_number", "id_card", "mobile"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("exposed = %v, want %v", got, want)
	}
	// The asset inventory still records the token header.
	all := classifySensitiveFields(evt)
	if fmt.Sprint(all) != fmt.Sprint([]string{"X-Auth-Token", "card_number", "id_card", "mobile"}) {
		t.Fatalf("classified = %v", all)
	}
}

func TestIngestedExportRaisesDLPAlert(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	evt := shared.APIEvent{}
	evt.Application.Method = "GET"
	evt.Application.PathRaw = "/api/v1/customers/export"
	evt.Application.StatusCode = 200
	evt.Network.SrcIP = "10.9.9.9"
	evt.Content.RequestHeaders = map[string]string{"x-user-id": "analyst-1"}
	evt.Content.ResponseBody = []byte(`[{"name":"a","phone":"138****0000"}]`)
	srv.processIngestEvent(t.Context(), evt)
	alerts := alertsFor(srv, "analyst-1")
	if len(alerts) != 1 || alerts[0].SourceRequirement != "FR-DLP-001" {
		t.Fatalf("alerts: %+v", alerts)
	}
}

func TestIngestedSSRFQueryRaisesAlert(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	evt := shared.APIEvent{}
	evt.Application.Method = "GET"
	// Query string still on the path, as a gateway log delivers it.
	evt.Application.PathRaw = "/api/v1/preview?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
	evt.Network.SrcIP = "198.51.100.23"
	evt.Content.RequestHeaders = map[string]string{"x-user-id": "attacker-1"}
	srv.processIngestEvent(t.Context(), evt)
	alerts := alertsFor(srv, "attacker-1")
	if len(alerts) != 1 || alerts[0].SourceRequirement != "FR-DET-007" || alerts[0].Severity != "critical" {
		t.Fatalf("alerts: %+v", alerts)
	}
}

func TestRateAlertIsFiledPerEndpoint(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	d := detection{RuleID: ruleRate, Score: 75, Reason: "surge", Subject: "endpoint:GET /api/x", SubjectIP: "203.0.113.1", override: true}
	for i := 0; i < 3; i++ {
		req := accessDetectionRequest{AccountID: fmt.Sprintf("caller-%d", i), SourceIP: fmt.Sprintf("10.0.0.%d", i)}
		srv.raise(d, req, 0.8)
	}
	alerts := alertsFor(srv, "endpoint:GET /api/x")
	if len(alerts) != 1 || alerts[0].OccurrenceCount != 3 || alerts[0].SourceIP != "203.0.113.1" {
		t.Fatalf("alerts: %+v", alerts)
	}
}
