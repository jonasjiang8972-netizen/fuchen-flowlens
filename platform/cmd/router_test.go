package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/server"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

const (
	initialPassword = "Init#Pass2026"
	newPassword     = "N3w!Secure-Pass"
)

type harness struct {
	t *testing.T
	r *gin.Engine
}

func newHarness(t *testing.T, agentToken string) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	srv := server.NewPlatformServer(storage.NewMemStore())
	if _, err := srv.IAM().Bootstrap(context.Background(), initialPassword); err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, r: setupRouter(srv, config{agentToken: agentToken})}
}

// do sends a request with a bearer token (may be empty) and JSON body.
func (h *harness) do(method, path, token, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.r.ServeHTTP(w, req)
	return w
}

func (h *harness) login(username, password string) (string, map[string]any) {
	h.t.Helper()
	w := h.do(http.MethodPost, "/api/v1/auth/login", "", `{"username":"`+username+`","password":"`+password+`"}`)
	if w.Code != http.StatusOK {
		h.t.Fatalf("login %s: %d %s", username, w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body["token"].(string), body
}

// ready logs in with the initial password and completes the forced change.
func (h *harness) ready(username string) string {
	h.t.Helper()
	token, _ := h.login(username, initialPassword)
	w := h.do(http.MethodPost, "/api/v1/auth/password", token, `{"old_password":"`+initialPassword+`","new_password":"`+newPassword+`"}`)
	if w.Code != http.StatusOK {
		h.t.Fatalf("change password %s: %d %s", username, w.Code, w.Body.String())
	}
	return token
}

// tokens returns a ready session for every role; analyst and viewer
// accounts are created by the system administrator through the API.
func (h *harness) tokens() map[string]string {
	h.t.Helper()
	tok := map[string]string{
		"sys_admin":   h.ready("sysadmin"),
		"audit_admin": h.ready("auditadmin"),
		"sec_admin":   h.ready("secadmin"),
	}
	for _, u := range []struct{ name, role string }{{"ana", "analyst"}, {"view", "viewer"}} {
		w := h.do(http.MethodPost, "/api/v1/admin/users", tok["sys_admin"],
			`{"username":"`+u.name+`","role":"`+u.role+`","password":"`+initialPassword+`"}`)
		if w.Code != http.StatusCreated {
			h.t.Fatalf("create %s: %d %s", u.name, w.Code, w.Body.String())
		}
		tok[u.role] = h.ready(u.name)
	}
	return tok
}

func agentPost(r *gin.Engine, path, token string) int {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"agent_id":"a1","hostname":"h","events":[{"event_id":"e1"}]}`))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(auth.AgentTokenHeader, token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestAgentEndpointsRequireAgentToken(t *testing.T) {
	h := newHarness(t, "s3cret")
	for _, p := range []string{"/api/v1/agents/register", "/api/v1/agents/a1/heartbeat", "/api/v1/ingest/batch"} {
		if code := agentPost(h.r, p, ""); code != http.StatusUnauthorized {
			t.Errorf("%s without token: got %d, want 401", p, code)
		}
		if code := agentPost(h.r, p, "wrong"); code != http.StatusUnauthorized {
			t.Errorf("%s with wrong token: got %d, want 401", p, code)
		}
		if code := agentPost(h.r, p, "s3cret"); code == http.StatusUnauthorized {
			t.Errorf("%s with valid token: got 401", p)
		}
	}
}

func TestAgentEndpointsFailClosedWithoutConfiguredToken(t *testing.T) {
	h := newHarness(t, "")
	if code := agentPost(h.r, "/api/v1/ingest/batch", "anything"); code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 when platform has no agent token", code)
	}
}

func TestAgentTokenDoesNotGrantOperatorAPIs(t *testing.T) {
	h := newHarness(t, "s3cret")
	for _, p := range []string{"/api/v1/assets", "/api/v1/admin/users"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set(auth.AgentTokenHeader, "s3cret")
		w := httptest.NewRecorder()
		h.r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("agent token on %s: got %d, want 401", p, w.Code)
		}
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	h := newHarness(t, "")
	for _, p := range []string{"/api/v1/assets", "/api/v1/admin/users", "/api/v1/admin/audit-logs", "/api/v1/auth/me"} {
		if w := h.do(http.MethodGet, p, "", ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", p, w.Code)
		}
	}
}

func TestInitialPasswordMustBeChangedFirst(t *testing.T) {
	h := newHarness(t, "")
	token, body := h.login("secadmin", initialPassword)
	if body["must_change_password"] != true || body["console"] != "security" {
		t.Fatalf("login body %v", body)
	}
	w := h.do(http.MethodGet, "/api/v1/assets", token, "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "password_change_required") {
		t.Fatalf("before password change: %d %s", w.Code, w.Body.String())
	}
	if w := h.do(http.MethodGet, "/api/v1/auth/me", token, ""); w.Code != http.StatusOK {
		t.Fatalf("/auth/me must work before password change, got %d", w.Code)
	}
	// Weak new password is rejected.
	w = h.do(http.MethodPost, "/api/v1/auth/password", token, `{"old_password":"`+initialPassword+`","new_password":"short"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("weak password: got %d", w.Code)
	}
	w = h.do(http.MethodPost, "/api/v1/auth/password", token, `{"old_password":"`+initialPassword+`","new_password":"`+newPassword+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("change password: %d %s", w.Code, w.Body.String())
	}
	// Same session continues without re-login.
	if w := h.do(http.MethodGet, "/api/v1/assets", token, ""); w.Code != http.StatusOK {
		t.Fatalf("after password change: got %d", w.Code)
	}
}

func TestSeparationOfDuties(t *testing.T) {
	h := newHarness(t, "")
	tok := h.tokens()

	cases := []struct {
		method, path, body string
		allowed            []string
	}{
		// API security platform
		{"GET", "/api/v1/assets", "", []string{"sec_admin", "analyst", "viewer"}},
		{"GET", "/api/v1/alerts", "", []string{"sec_admin", "analyst", "viewer"}},
		{"PUT", "/api/v1/rules/R-BOLA-001", `{"enabled":false}`, []string{"sec_admin"}},
		{"POST", "/api/v1/alerts/alt-001/block_ip", `{}`, []string{"sec_admin", "analyst"}},
		{"POST", "/api/v1/assets/ast-001/claim", `{"owner":"team"}`, []string{"sec_admin", "analyst"}},
		{"GET", "/api/v1/coverage/agents", "", []string{"sec_admin", "analyst", "viewer"}},
		// Management console
		{"GET", "/api/v1/admin/users", "", []string{"sys_admin"}},
		{"GET", "/api/v1/admin/roles", "", []string{"sys_admin"}},
		{"GET", "/api/v1/admin/security-policy", "", []string{"sys_admin"}},
		{"GET", "/api/v1/admin/agents", "", []string{"sys_admin"}},
		{"GET", "/api/v1/admin/system/info", "", []string{"sys_admin"}},
		{"GET", "/api/v1/admin/audit-logs", "", []string{"audit_admin"}},
		{"GET", "/api/v1/admin/audit-logs/verify", "", []string{"audit_admin"}},
	}
	for _, tc := range cases {
		for role, token := range tok {
			allowed := false
			for _, a := range tc.allowed {
				allowed = allowed || a == role
			}
			w := h.do(tc.method, tc.path, token, tc.body)
			if allowed && w.Code == http.StatusForbidden {
				t.Errorf("%s %s as %s: got 403, want allowed", tc.method, tc.path, role)
			}
			if !allowed && w.Code != http.StatusForbidden {
				t.Errorf("%s %s as %s: got %d, want 403", tc.method, tc.path, role, w.Code)
			}
		}
	}
}

func TestDeniedAccessIsAudited(t *testing.T) {
	h := newHarness(t, "")
	tok := h.tokens()
	h.do(http.MethodGet, "/api/v1/admin/audit-logs", tok["sys_admin"], "") // sysadmin may not read the audit trail

	w := h.do(http.MethodGet, "/api/v1/admin/audit-logs?event_type=access.denied", tok["audit_admin"], "")
	var body struct {
		Items []storage.AuditRecord `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	found := false
	for _, r := range body.Items {
		found = found || (r.Username == "sysadmin" && r.Result == "failure")
	}
	if !found {
		t.Fatalf("denied audit read by sysadmin not recorded: %s", w.Body.String())
	}
}

func TestLoginAndAdminActionsAreAuditedWithHashChain(t *testing.T) {
	h := newHarness(t, "")
	tok := h.tokens()
	h.do(http.MethodPost, "/api/v1/auth/login", "", `{"username":"secadmin","password":"wrong"}`)

	w := h.do(http.MethodGet, "/api/v1/admin/audit-logs?limit=500", tok["audit_admin"], "")
	var body struct {
		Items []storage.AuditRecord `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	seen := map[string]bool{}
	for _, r := range body.Items {
		seen[r.EventType+"/"+r.Result] = true
		if r.Hash == "" || (r.Seq > 1 && r.PrevHash == "") {
			t.Fatalf("record %d missing chain hashes", r.Seq)
		}
	}
	for _, want := range []string{"auth.login/success", "auth.login/failure", "auth.password_change/success", "user.create/success", "user.bootstrap/success"} {
		if !seen[want] {
			t.Errorf("audit trail lacks %s", want)
		}
	}
	w = h.do(http.MethodGet, "/api/v1/admin/audit-logs/verify", tok["audit_admin"], "")
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("verify: %s", w.Body.String())
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	h := newHarness(t, "")
	token := h.ready("secadmin")
	if w := h.do(http.MethodPost, "/api/v1/auth/logout", token, ""); w.Code != http.StatusOK {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := h.do(http.MethodGet, "/api/v1/assets", token, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("token after logout: got %d, want 401", w.Code)
	}
}

func TestCookieSessionRequiresCSRFHeader(t *testing.T) {
	h := newHarness(t, "")
	h.ready("secadmin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"secadmin","password":"`+newPassword+`"}`))
	w := httptest.NewRecorder()
	h.r.ServeHTTP(w, req)
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.CookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie missing or not HttpOnly/SameSite=Strict: %+v", cookie)
	}

	send := func(withHeader bool) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/ast-001/claim", strings.NewReader(`{"owner":"x"}`))
		req.AddCookie(cookie)
		if withHeader {
			req.Header.Set(auth.CSRFHeader, auth.CSRFValue)
		}
		w := httptest.NewRecorder()
		h.r.ServeHTTP(w, req)
		return w.Code
	}
	if code := send(false); code != http.StatusForbidden {
		t.Fatalf("cookie POST without CSRF header: got %d, want 403", code)
	}
	if code := send(true); code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Fatalf("cookie POST with CSRF header: got %d", code)
	}
	// Reads with the cookie need no header.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("cookie GET: got %d", w.Code)
	}
}

func TestCORSOnlyAllowsConfiguredOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(corsMiddleware(parseOrigins(" https://console.example.com/ , ")))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	cases := []struct {
		origin string
		want   string
	}{
		{"https://console.example.com", "https://console.example.com"},
		{"https://evil.example.com", ""},
		{"", ""},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != tc.want {
			t.Errorf("origin %q: Allow-Origin = %q, want %q", tc.origin, got, tc.want)
		}
	}
}

func TestAgentRoutesRequireClientCertWhenCAConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := server.NewPlatformServer(storage.NewMemStore())
	r := setupRouter(srv, config{agentToken: "s3cret", tlsClientCA: "/etc/flowlens/agent-ca.pem"})
	if code := agentPost(r, "/api/v1/ingest/batch", "s3cret"); code != http.StatusUnauthorized {
		t.Fatalf("valid token without client certificate: got %d, want 401", code)
	}
}
