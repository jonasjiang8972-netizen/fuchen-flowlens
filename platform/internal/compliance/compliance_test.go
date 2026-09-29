package compliance

import (
	"strings"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/iam"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
)

var now = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func healthy() Snapshot {
	last := now.Add(-time.Hour)
	return Snapshot{
		Now:    now,
		Policy: iam.DefaultPolicy(),
		Users: []iam.UserView{
			{Username: "sysadmin", Role: iam.RoleSysAdmin, Status: "active", LastLoginAt: &last, CreatedAt: now.AddDate(0, -1, 0)},
			{Username: "auditadmin", Role: iam.RoleAuditAdmin, Status: "active", LastLoginAt: &last, CreatedAt: now.AddDate(0, -1, 0)},
			{Username: "secadmin", Role: iam.RoleSecAdmin, Status: "active", LastLoginAt: &last, CreatedAt: now.AddDate(0, -1, 0)},
		},
		AuditCheck: &audit.VerifyResult{OK: true, Checked: 1200, FirstSeq: 1, LastSeq: 1200},
		Deploy: Deployment{DBPersistent: true, DBSSLMode: "verify-full", TLS: true, ClientCertRequired: true, AgentTokenSet: true,
			SOARConnectors: 2, BOLAModelEnabled: true, BOLAModelTrained: true},
		Assets: []service.Asset{
			{ID: "a1", Status: "active", ClaimStatus: "claimed", SensitivityHint: "high", SensitiveFields: []string{"phone"}},
			{ID: "a2", Status: "active", ClaimStatus: "claimed"},
		},
		Agents: []service.Agent{{Status: "online"}, {Status: "online"}},
		Rules:  []service.Rule{{Name: "BOLA", Enabled: true}, {Name: "认证失效", Enabled: true}},
	}
}

func find(r Report, id string) Check {
	for _, s := range r.Sections {
		for _, c := range s.Checks {
			if c.ID == id {
				return c
			}
		}
	}
	return Check{}
}

func TestUnknownTemplate(t *testing.T) {
	if _, err := Build("nope", healthy()); err == nil {
		t.Error("unknown template accepted")
	}
}

func TestHealthyPlatformPassesLiveChecks(t *testing.T) {
	r, err := Build(TemplateMLPS3, healthy())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ID-1", "ID-2", "ID-3", "ID-4", "ID-6", "AC-1", "AU-1", "AU-2", "AU-3", "TR-1", "TR-2", "TR-4", "DA-2", "DA-3", "AS-1", "AS-2", "AS-3", "IR-1", "IR-2", "IR-3", "IR-4", "IR-5"} {
		if c := find(r, id); c.Status != Pass {
			t.Errorf("%s = %s (%s), want pass", id, c.Status, c.Evidence)
		}
	}
	if r.Summary.Total == 0 || r.Summary.Pass+r.Summary.Partial+r.Summary.Fail+r.Summary.Manual != r.Summary.Total {
		t.Errorf("summary does not add up: %+v", r.Summary)
	}
}

func TestUnimplementedCapabilitiesNeverPass(t *testing.T) {
	// Even a perfectly configured platform cannot pass what it does not do.
	r, _ := Build(TemplateFinance, healthy())
	for id, want := range map[string]string{"ID-5": Fail, "AU-4": Fail, "TR-3": Partial, "DA-4": Fail, "DA-5": Partial} {
		c := find(r, id)
		if c.Status != want || c.Basis != BasisCapability {
			t.Errorf("%s = %s/%s, want %s/capability", id, c.Status, c.Basis, want)
		}
		if c.Remediation == "" {
			t.Errorf("%s has no remediation", id)
		}
	}
	for _, id := range []string{"MG-1", "MG-2", "MG-3", "MG-4", "MG-5"} {
		if c := find(r, id); c.Status != Manual || c.Basis != BasisManual {
			t.Errorf("%s = %s/%s, want manual", id, c.Status, c.Basis)
		}
	}
}

func TestPolicyWeaknessesAreReported(t *testing.T) {
	s := healthy()
	s.Policy.PasswordMinLength = 6
	s.Policy.LockoutThreshold = 0
	s.Policy.SessionIdleMinutes = 120
	s.Policy.AuditRetentionDays = 30
	r, _ := Build(TemplateMLPS3, s)
	for _, id := range []string{"ID-1", "ID-2", "ID-3", "AU-1"} {
		if c := find(r, id); c.Status != Fail || c.Remediation == "" {
			t.Errorf("%s = %s, want fail with a remediation", id, c.Status)
		}
	}
}

func TestAccountChecks(t *testing.T) {
	s := healthy()
	old := now.AddDate(0, -6, 0)
	s.Users = append(s.Users,
		iam.UserView{Username: "newbie", Role: iam.RoleAnalyst, Status: "active", MustChangePassword: true, CreatedAt: now},
		iam.UserView{Username: "gone", Role: iam.RoleAnalyst, Status: "active", LastLoginAt: &old, CreatedAt: old},
		iam.UserView{Username: "off", Role: iam.RoleAnalyst, Status: "disabled", MustChangePassword: true, LastLoginAt: &old, CreatedAt: old},
	)
	r, _ := Build(TemplateMLPS3, s)
	if c := find(r, "ID-4"); c.Status != Fail || !strings.Contains(c.Evidence, "1 个启用账号") {
		t.Errorf("initial password: %s %q (a disabled account must not count)", c.Status, c.Evidence)
	}
	if c := find(r, "ID-6"); c.Status != Fail || !strings.Contains(c.Evidence, "1 个启用账号超过") {
		t.Errorf("stale accounts: %s %q (a disabled account must not count)", c.Status, c.Evidence)
	}
	// The report must not name accounts: the security console may not see them.
	for _, sec := range r.Sections {
		for _, c := range sec.Checks {
			for _, name := range []string{"newbie", "gone", "sysadmin", "secadmin"} {
				if strings.Contains(c.Evidence, name) {
					t.Errorf("%s evidence names account %q", c.ID, name)
				}
			}
		}
	}
}

func TestSeparationOfDutiesNeedsAllThreeRoles(t *testing.T) {
	s := healthy()
	s.Users = s.Users[:2] // no security administrator
	r, _ := Build(TemplateMLPS3, s)
	if c := find(r, "AC-1"); c.Status != Fail || !strings.Contains(c.Evidence, "安全管理员") {
		t.Errorf("AC-1 = %s %q", c.Status, c.Evidence)
	}
	s.Users[0].Status = "disabled" // a disabled account does not count
	r, _ = Build(TemplateMLPS3, s)
	if c := find(r, "AC-1"); c.Status != Fail || !strings.Contains(c.Evidence, "系统管理员") {
		t.Errorf("disabled sysadmin counted: %s %q", c.Status, c.Evidence)
	}
}

func TestAuditIntegrityStates(t *testing.T) {
	s := healthy()
	s.AuditCheck = &audit.VerifyResult{OK: false, BrokenAt: 77, Reason: "hash mismatch"}
	if c := find(mustBuild(t, s), "AU-3"); c.Status != Fail || !strings.Contains(c.Evidence, "77") {
		t.Errorf("broken chain: %s %q", c.Status, c.Evidence)
	}
	s.AuditCheck, s.AuditErr = nil, "database unavailable"
	if c := find(mustBuild(t, s), "AU-3"); c.Status != Manual || !strings.Contains(c.Evidence, "database unavailable") {
		t.Errorf("could not verify: %s %q (an unverified trail must not pass)", c.Status, c.Evidence)
	}
	s.Deploy.DBPersistent = false
	if c := find(mustBuild(t, s), "AU-2"); c.Status != Fail {
		t.Errorf("in-memory audit trail = %s, want fail", c.Status)
	}
}

func TestTransportStates(t *testing.T) {
	cases := []struct {
		name string
		d    Deployment
		tr1  string
		tr2  string
		tr4  string
	}{
		{"nothing configured", Deployment{DBPersistent: true, DBSSLMode: "disable"}, Fail, Fail, Partial},
		{"behind an https proxy", Deployment{DBPersistent: true, SecureCookies: true, AgentTokenSet: true, DBSSLMode: "require"}, Partial, Partial, Partial},
		{"fully configured", Deployment{DBPersistent: true, TLS: true, ClientCertRequired: true, DBSSLMode: "verify-ca"}, Pass, Pass, Pass},
		{"unknown db mode", Deployment{DBPersistent: true, TLS: true, AgentTokenSet: true}, Pass, Partial, Manual},
		{"no database", Deployment{}, Fail, Fail, Manual},
	}
	for _, tc := range cases {
		s := healthy()
		s.Deploy = tc.d
		r := mustBuild(t, s)
		for id, want := range map[string]string{"TR-1": tc.tr1, "TR-2": tc.tr2, "TR-4": tc.tr4} {
			if got := find(r, id).Status; got != want {
				t.Errorf("%s: %s = %s, want %s", tc.name, id, got, want)
			}
		}
	}
}

func TestDataAndAssetChecks(t *testing.T) {
	s := healthy()
	s.Assets = []service.Asset{
		{ID: "1", Status: "active", ClaimStatus: "unclaimed", SensitivityHint: "high", SensitiveFields: []string{"id_card(未脱敏)"}},
		{ID: "2", Status: "shadow", ClaimStatus: "claimed"},
		{ID: "3", Status: "zombie", ClaimStatus: "claimed"},
		{ID: "4", Status: "active", ClaimStatus: "claimed"},
	}
	s.Alerts = []service.Alert{{SourceRequirement: "FR-DLP-001", Status: "open"}, {SourceRequirement: "FR-DLP-001", Status: "resolved"}}
	r := mustBuild(t, s)
	if c := find(r, "DA-2"); c.Status != Fail || !strings.Contains(c.Evidence, "1 个接口") || !strings.Contains(c.Evidence, "1 条脱敏缺陷告警") {
		t.Errorf("DA-2 = %s %q", c.Status, c.Evidence)
	}
	if c := find(r, "DA-3"); c.Status != Fail || !strings.Contains(c.Evidence, "1 个还没有责任人") {
		t.Errorf("DA-3 = %s %q", c.Status, c.Evidence)
	}
	if c := find(r, "AS-1"); c.Status != Fail { // 2 of 4 is over the 10% line
		t.Errorf("AS-1 = %s %q", c.Status, c.Evidence)
	}
	if c := find(r, "AS-2"); c.Status != Fail { // 1 of 4 = 25% unclaimed
		t.Errorf("AS-2 = %s %q", c.Status, c.Evidence)
	}
	// No assets at all is "cannot tell", never a pass.
	s.Assets = nil
	r = mustBuild(t, s)
	for _, id := range []string{"AS-1", "AS-2", "DA-3"} {
		if c := find(r, id); c.Status != Manual {
			t.Errorf("%s with no assets = %s, want manual", id, c.Status)
		}
	}
}

func TestCoverageAndResponseChecks(t *testing.T) {
	s := healthy()
	s.Agents = nil
	if c := find(mustBuild(t, s), "AS-3"); c.Status != Fail {
		t.Errorf("no agents = %s", c.Status)
	}
	s.Agents = []service.Agent{{Status: "online"}, {Status: "online"}, {Status: "online"}, {Status: "online"}, {Status: "online"},
		{Status: "online"}, {Status: "online"}, {Status: "online"}, {Status: "online"}, {Status: "offline"}}
	if c := find(mustBuild(t, s), "AS-3"); c.Status != Partial {
		t.Errorf("90%% online = %s", c.Status)
	}
	s.Agents = []service.Agent{{Status: "online"}, {Status: "offline"}}
	if c := find(mustBuild(t, s), "AS-3"); c.Status != Fail {
		t.Errorf("50%% online = %s", c.Status)
	}

	s = healthy()
	s.Rules = []service.Rule{{Name: "a", Enabled: true}, {Name: "b", Enabled: false}, {Name: "c", Enabled: false}}
	if c := find(mustBuild(t, s), "IR-1"); c.Status != Fail || !strings.Contains(c.Evidence, "b、c") {
		t.Errorf("IR-1 = %s %q", c.Status, c.Evidence)
	}
	s.Tickets = service.TicketSummary{Open: 3, Overdue: 1}
	if c := find(mustBuild(t, s), "IR-2"); c.Status != Fail {
		t.Errorf("overdue ticket: IR-2 = %s", c.Status)
	}
	s.Tickets = service.TicketSummary{Open: 3, Unassigned: 1}
	if c := find(mustBuild(t, s), "IR-2"); c.Status != Partial {
		t.Errorf("unassigned ticket: IR-2 = %s", c.Status)
	}
	s.SeriousAlertsWithoutTicket = 4
	if c := find(mustBuild(t, s), "IR-3"); c.Status != Fail || !strings.Contains(c.Evidence, "4 条") {
		t.Errorf("IR-3 = %s %q", c.Status, c.Evidence)
	}

	s = healthy()
	s.Deploy.SOARConnectors, s.Deploy.SOARDryRun = 0, false
	if c := find(mustBuild(t, s), "IR-4"); c.Status != Fail {
		t.Errorf("no connectors: IR-4 = %s", c.Status)
	}
	s.Deploy.SOARConnectors, s.Deploy.SOARDryRun = 1, true
	if c := find(mustBuild(t, s), "IR-4"); c.Status != Partial {
		t.Errorf("dry run: IR-4 = %s", c.Status)
	}
	s.Deploy.BOLAModelTrained = false
	if c := find(mustBuild(t, s), "IR-5"); c.Status != Partial {
		t.Errorf("untrained model: IR-5 = %s", c.Status)
	}
	s.Deploy.BOLAModelEnabled = false
	if c := find(mustBuild(t, s), "IR-5"); c.Status != Partial || !strings.Contains(c.Evidence, "已关闭") {
		t.Errorf("model off: IR-5 = %s %q", c.Status, c.Evidence)
	}
}

func TestTemplatesDifferAndOrderIsStable(t *testing.T) {
	m, _ := Build(TemplateMLPS3, healthy())
	f, _ := Build(TemplateFinance, healthy())
	if m.Summary.Total >= f.Summary.Total {
		t.Errorf("the finance template adds data-security items: mlps3=%d finance=%d", m.Summary.Total, f.Summary.Total)
	}
	if find(m, "DA-4").ID != "" {
		t.Error("data classification (JR/T 0197) belongs only in the finance template")
	}
	if find(f, "DA-4").ID == "" {
		t.Error("finance template is missing data classification")
	}
	if m.Sections[0].Category != CatIdentity || m.Sections[len(m.Sections)-1].Category != CatManual {
		t.Errorf("section order: first %s, last %s", m.Sections[0].Category, m.Sections[len(m.Sections)-1].Category)
	}
	for _, r := range []Report{m, f} {
		for _, sec := range r.Sections {
			for _, c := range sec.Checks {
				if c.Ref == "" || c.Evidence == "" || c.Title == "" || c.Status == "" || c.Basis == "" {
					t.Errorf("%s/%s is incomplete: %+v", r.Template, c.ID, c)
				}
			}
		}
		if !strings.Contains(r.Disclaimer, "不是等保测评结论") {
			t.Error("the disclaimer must say this is not a formal assessment")
		}
	}
}

func TestExports(t *testing.T) {
	s := healthy()
	s.Assets = []service.Asset{{ID: "x", Status: "active", ClaimStatus: "claimed"}}
	r := mustBuild(t, s)
	// Untrusted text must be escaped in HTML and neutralised in CSV.
	c := &r.Sections[0].Checks[0]
	c.Evidence = `<script>alert(1)</script>`
	c.Remediation = `=HYPERLINK("http://evil","x")`

	html, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	h := string(html)
	if strings.Contains(h, "<script>alert(1)") || !strings.Contains(h, "&lt;script&gt;") {
		t.Error("HTML output does not escape check text")
	}
	for _, want := range []string{r.Title, "不是等保测评结论", "符合", "需人工核查", "身份鉴别"} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML missing %q", want)
		}
	}

	raw, err := CSV(r)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	if !strings.HasPrefix(out, "\xEF\xBB\xBF") {
		t.Error("CSV needs a BOM for Excel")
	}
	if strings.Contains(out, ",=HYPERLINK") || !strings.Contains(out, "'=HYPERLINK") {
		t.Errorf("CSV cell starting with = was not neutralised")
	}
	if n := strings.Count(out, "\n"); n != r.Summary.Total+1 {
		t.Errorf("CSV has %d lines, want %d (header + checks)", n, r.Summary.Total+1)
	}
}

func TestDemoReportIsLabelled(t *testing.T) {
	s := healthy()
	s.Deploy.DemoMode = true
	r := mustBuild(t, s)
	if !r.Demo {
		t.Fatal("demo report not marked")
	}
	html, _ := HTML(r)
	if !strings.Contains(string(html), "演示数据") {
		t.Error("the printed demo report must say it is sample data")
	}
}

func mustBuild(t *testing.T, s Snapshot) Report {
	t.Helper()
	r, err := Build(TemplateFinance, s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
