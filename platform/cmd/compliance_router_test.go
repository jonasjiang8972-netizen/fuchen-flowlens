package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDSNSSLMode(t *testing.T) {
	for dsn, want := range map[string]string{
		"": "",
		"postgres://u:p@h:5432/db?sslmode=disable":      "disable",
		"postgresql://u:p@h/db?sslmode=verify-full&x=1": "verify-full",
		"postgres://u:p@h/db":                           "",
		"host=h user=u sslmode=require dbname=d":        "require",
		"host=h user=u sslmode='verify-ca'":             "verify-ca",
		"host=h user=u":                                 "",
		"not a dsn":                                     "",
	} {
		if got := dsnSSLMode(dsn); got != want {
			t.Errorf("dsnSSLMode(%q) = %q, want %q", dsn, got, want)
		}
	}
}

func TestComplianceReportPermissionsAndAudit(t *testing.T) {
	h := newHarness(t, "")
	tok := h.tokens()
	const url = "/api/v1/reports/compliance?template=mlps3"

	if w := h.do("GET", url, "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d, want 401", w.Code)
	}
	// The report summarises the whole platform's posture: only the security
	// administrator may generate it. Not even a read-only or analyst account.
	for _, role := range []string{"viewer", "analyst", "sys_admin", "audit_admin"} {
		for _, path := range []string{url, "/api/v1/reports/compliance/templates", "/api/v1/reports/compliance/export?template=mlps3"} {
			if w := h.do("GET", path, tok[role], ""); w.Code != http.StatusForbidden {
				t.Errorf("%s GET %s: %d, want 403", role, path, w.Code)
			}
		}
	}

	w := h.do("GET", url, tok["sec_admin"], "")
	if w.Code != http.StatusOK {
		t.Fatalf("sec_admin: %d %s", w.Code, w.Body.String())
	}
	var rep struct {
		Template string `json:"template"`
		Summary  struct{ Total, Pass, Fail int }
		Sections []struct {
			Category string
			Checks   []struct{ ID, Status, Basis string }
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Template != "mlps3" || rep.Summary.Total < 20 || len(rep.Sections) < 5 {
		t.Fatalf("report = %+v", rep.Summary)
	}
	status := map[string]string{}
	for _, s := range rep.Sections {
		for _, c := range s.Checks {
			status[c.ID] = c.Status
		}
	}
	// This harness runs in memory, over plain HTTP, with no client certs and
	// no connectors: the report must say so rather than pass those checks.
	for id, want := range map[string]string{"AU-2": "fail", "TR-1": "fail", "IR-4": "fail", "ID-5": "fail", "AU-3": "pass", "AC-1": "pass"} {
		if status[id] != want {
			t.Errorf("%s = %q, want %q", id, status[id], want)
		}
	}
	// Freshly bootstrapped accounts have all changed their passwords in tokens().
	if status["ID-4"] != "pass" {
		t.Errorf("ID-4 = %q, want pass after every account changed its initial password", status["ID-4"])
	}

	if w := h.do("GET", "/api/v1/reports/compliance?template=nope", tok["sec_admin"], ""); w.Code != http.StatusBadRequest {
		t.Errorf("unknown template: %d", w.Code)
	}
	if w := h.do("GET", "/api/v1/reports/compliance/export?format=pdf", tok["sec_admin"], ""); w.Code != http.StatusBadRequest {
		t.Errorf("unknown format: %d", w.Code)
	}
	html := h.do("GET", "/api/v1/reports/compliance/export?template=finance&format=html", tok["sec_admin"], "")
	if html.Code != http.StatusOK || !strings.HasPrefix(html.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(html.Header().Get("Content-Disposition"), "attachment") || html.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(html.Body.String(), "金融行业自查") {
		t.Errorf("html export: %d %v", html.Code, html.Header())
	}
	csv := h.do("GET", "/api/v1/reports/compliance/export?template=finance&format=csv", tok["sec_admin"], "")
	if csv.Code != http.StatusOK || !strings.HasPrefix(csv.Header().Get("Content-Type"), "text/csv") || !strings.HasPrefix(csv.Body.String(), "\xEF\xBB\xBF") {
		t.Errorf("csv export: %d %v", csv.Code, csv.Header())
	}

	// Generating and taking a report is auditable, and names who did it.
	audit := h.do("GET", "/api/v1/admin/audit-logs?event_type=report.", tok["audit_admin"], "").Body.String()
	for _, want := range []string{"report.generate", "report.export", `"username":"secadmin"`, "format=csv", "format=html"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit trail missing %s", want)
		}
	}
}
