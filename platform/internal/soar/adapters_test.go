package soar

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── Kong ──────────────────────────────────────────────────────

// fakeKong emulates the slice of Kong's Admin API the connector uses.
type fakeKong struct {
	mu      sync.Mutex
	plugin  map[string]any // nil = none
	token   string
	deletes int
}

func (k *fakeKong) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if r.Header.Get("Kong-Admin-Token") != k.token {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == "GET" && r.URL.Path == "/":
		w.Write([]byte(`{"version":"3.6"}`))
	case r.Method == "GET" && r.URL.Path == "/plugins":
		if r.URL.Query().Get("tags") != kongTag {
			w.Write([]byte(`{"data":[]}`))
			return
		}
		data := []any{}
		if k.plugin != nil {
			data = append(data, k.plugin)
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	case r.Method == "POST" && r.URL.Path == "/plugins":
		var p map[string]any
		json.Unmarshal(body, &p)
		p["id"] = "plug-1"
		k.plugin = p
		w.WriteHeader(201)
	case r.Method == "PATCH" && r.URL.Path == "/plugins/plug-1":
		var p map[string]any
		json.Unmarshal(body, &p)
		k.plugin["config"] = p["config"]
	case r.Method == "DELETE" && r.URL.Path == "/plugins/plug-1":
		k.plugin = nil
		k.deletes++
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

func (k *fakeKong) deny() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.plugin == nil {
		return nil
	}
	var out []string
	for _, v := range k.plugin["config"].(map[string]any)["deny"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

func TestKongBlockAndUnblock(t *testing.T) {
	fk := &fakeKong{token: "tok"}
	srv := httptest.NewServer(fk)
	defer srv.Close()
	k := NewKong(srv.URL+"/", "tok")
	ctx := context.Background()

	if err := k.Check(ctx); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := NewKong(srv.URL, "wrong").Check(ctx); err == nil {
		t.Error("wrong admin token should fail the check")
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.1"} { // repeat is idempotent
		if _, err := k.Block(ctx, Request{IP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(fk.deny(), ","); got != "198.51.100.1,198.51.100.2" {
		t.Fatalf("deny list = %s", got)
	}
	if fk.plugin["name"] != "ip-restriction" {
		t.Errorf("plugin = %v", fk.plugin["name"])
	}
	if tags := fk.plugin["tags"].([]any); len(tags) != 1 || tags[0] != kongTag {
		t.Errorf("plugin must be tagged so only FlowLens' own is touched: %v", tags)
	}
	if err := k.Unblock(ctx, "198.51.100.1", ""); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fk.deny(), ","); got != "198.51.100.2" {
		t.Errorf("after unblock = %s", got)
	}
	if err := k.Unblock(ctx, "203.0.113.99", ""); err != nil { // never blocked
		t.Errorf("unblocking an unknown address: %v", err)
	}
	// Kong rejects an empty deny list, so the last address removes the plugin.
	if err := k.Unblock(ctx, "198.51.100.2", ""); err != nil || fk.plugin != nil || fk.deletes != 1 {
		t.Errorf("last unblock: plugin=%v deletes=%d err=%v", fk.plugin, fk.deletes, err)
	}
	if err := k.Unblock(ctx, "198.51.100.2", ""); err != nil {
		t.Errorf("unblock with no plugin: %v", err)
	}
}

// ─── APISIX ────────────────────────────────────────────────────

type fakeAPISIX struct {
	mu   sync.Mutex
	rule map[string]any
	v2   bool // wrap responses the APISIX 2.x way
}

func (a *fakeAPISIX) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.Header.Get("X-API-KEY") != "key" {
		w.WriteHeader(401)
		return
	}
	const path = "/apisix/admin/global_rules/flowlens-block"
	switch {
	case r.Method == "GET" && r.URL.Path == "/apisix/admin/global_rules":
		w.Write([]byte(`{"total":0}`))
	case r.Method == "GET" && r.URL.Path == path:
		if a.rule == nil {
			w.WriteHeader(404)
			return
		}
		if a.v2 {
			json.NewEncoder(w).Encode(map[string]any{"node": map[string]any{"value": a.rule}})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"value": a.rule})
		}
	case r.Method == "PUT" && r.URL.Path == path:
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		a.rule = b
	case r.Method == "DELETE" && r.URL.Path == path:
		if a.rule == nil {
			w.WriteHeader(404)
			return
		}
		a.rule = nil
	default:
		w.WriteHeader(404)
	}
}

func (a *fakeAPISIX) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rule == nil {
		return nil
	}
	var out []string
	for _, v := range a.rule["plugins"].(map[string]any)["ip-restriction"].(map[string]any)["blacklist"].([]any) {
		out = append(out, v.(string))
	}
	return out
}

func TestAPISIXBlockAndUnblock(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		fa := &fakeAPISIX{v2: v2}
		srv := httptest.NewServer(fa)
		a := NewAPISIX(srv.URL, "key")
		ctx := context.Background()
		if err := a.Check(ctx); err != nil {
			t.Fatalf("v2=%v check: %v", v2, err)
		}
		if err := NewAPISIX(srv.URL, "bad").Check(ctx); err == nil {
			t.Error("wrong key should fail")
		}
		for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.2"} {
			if _, err := a.Block(ctx, Request{IP: ip}); err != nil {
				t.Fatalf("v2=%v: %v", v2, err)
			}
		}
		if got := strings.Join(fa.list(), ","); got != "198.51.100.1,198.51.100.2" {
			t.Fatalf("v2=%v blacklist = %s", v2, got)
		}
		a.Unblock(ctx, "198.51.100.1", "")
		if got := strings.Join(fa.list(), ","); got != "198.51.100.2" {
			t.Errorf("v2=%v after unblock = %s", v2, got)
		}
		if err := a.Unblock(ctx, "198.51.100.2", ""); err != nil || fa.rule != nil {
			t.Errorf("v2=%v last unblock should delete the rule: %v %v", v2, fa.rule, err)
		}
		if err := a.Unblock(ctx, "198.51.100.2", ""); err != nil {
			t.Errorf("v2=%v unblock with no rule: %v", v2, err)
		}
		srv.Close()
	}
}

// ─── Nginx ─────────────────────────────────────────────────────

func TestNginxDenyFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "deny.conf")
	n := NewNginx(file, "true") // "true" stands in for a reload that succeeds
	ctx := context.Background()

	if err := n.Check(ctx); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"198.51.100.2", "198.51.100.1", "2001:db8::5", "198.51.100.1"} {
		if _, err := n.Block(ctx, Request{IP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(file)
	want := "# Managed by FlowLens. Do not edit: changes are overwritten.\ndeny 198.51.100.1;\ndeny 198.51.100.2;\ndeny 2001:db8::5;\n"
	if string(raw) != want {
		t.Fatalf("file =\n%s\nwant\n%s", raw, want)
	}
	if err := n.Unblock(ctx, "198.51.100.1", ""); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(file)
	if strings.Contains(string(raw), "198.51.100.1;") || !strings.Contains(string(raw), "198.51.100.2;") {
		t.Errorf("after unblock:\n%s", raw)
	}
	if err := n.Unblock(ctx, "203.0.113.50", ""); err != nil {
		t.Errorf("unknown address: %v", err)
	}
	// Manual edits to the file are preserved for addresses FlowLens knows,
	// and only valid IP literals are ever parsed back.
	os.WriteFile(file, []byte("# hand edit\ndeny 198.51.100.9;\ndeny all;\nallow 10.0.0.0/8;\n"), 0o644)
	if _, err := n.Block(ctx, Request{IP: "198.51.100.10"}); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(file)
	if strings.Contains(string(raw), "deny all") || strings.Contains(string(raw), "allow") {
		t.Errorf("only deny <ip> lines belong in a managed file:\n%s", raw)
	}
}

func TestNginxRejectsInjection(t *testing.T) {
	file := filepath.Join(t.TempDir(), "deny.conf")
	n := NewNginx(file, "")
	for _, bad := range []string{"1.2.3.4; allow all", "1.2.3.4\ndeny all", "$(id)", "example.com", ""} {
		if _, err := n.Block(context.Background(), Request{IP: bad}); err == nil {
			t.Errorf("Block(%q) accepted", bad)
		}
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("nothing should have been written")
	}
}

func TestNginxRollsBackWhenReloadFails(t *testing.T) {
	file := filepath.Join(t.TempDir(), "deny.conf")
	if err := NewNginx(file, "true").Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	good := NewNginx(file, "true")
	good.Block(context.Background(), Request{IP: "198.51.100.1"})
	before, _ := os.ReadFile(file)

	broken := NewNginx(file, "false") // reload exits non-zero
	if _, err := broken.Block(context.Background(), Request{IP: "198.51.100.2"}); err == nil || !strings.Contains(err.Error(), "重载 nginx 失败") {
		t.Fatalf("expected a reload error, got %v", err)
	}
	after, _ := os.ReadFile(file)
	if string(after) != string(before) {
		t.Errorf("file not restored after failed reload:\n%s", after)
	}
	if err := broken.Unblock(context.Background(), "198.51.100.1", ""); err == nil {
		t.Error("failed reload on unblock must be reported")
	}
	if again, _ := os.ReadFile(file); string(again) != string(before) {
		t.Error("file not restored after failed unblock reload")
	}

	// A first-ever block whose reload fails must not leave a file behind.
	fresh := filepath.Join(t.TempDir(), "new.conf")
	if _, err := NewNginx(fresh, "false").Block(context.Background(), Request{IP: "198.51.100.3"}); err == nil {
		t.Fatal("want error")
	}
	if _, err := os.Stat(fresh); err == nil {
		t.Error("stale file left after failed first block")
	}
}

func TestNginxCheckFailsForMissingDir(t *testing.T) {
	if err := NewNginx("/nonexistent-dir/x.conf", "").Check(context.Background()); err == nil {
		t.Error("check should fail when the directory does not exist")
	}
}

// ─── Webhook ───────────────────────────────────────────────────

func TestWebhookSignsRequests(t *testing.T) {
	var got []map[string]any
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-FlowLens-Timestamp")
		if want := Sign([]byte("shh"), ts, body); r.Header.Get("X-FlowLens-Signature") != want {
			w.WriteHeader(401)
			return
		}
		var m map[string]any
		json.Unmarshal(body, &m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}))
	defer srv.Close()

	w := NewWebhook(srv.URL, "shh")
	ctx := context.Background()
	if err := w.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Block(ctx, Request{IP: "198.51.100.1", Reason: "stuffing", AlertID: "alt-9", TTL: 90 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := w.Unblock(ctx, "198.51.100.1", ""); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0]["action"] != "ping" || got[1]["action"] != "block_ip" || got[2]["action"] != "unblock_ip" {
		t.Fatalf("payloads = %v", got)
	}
	if got[1]["ip"] != "198.51.100.1" || got[1]["ttl_seconds"].(float64) != 5400 || got[1]["alert_id"] != "alt-9" {
		t.Errorf("block payload = %v", got[1])
	}
	if err := NewWebhook(srv.URL, "wrong-secret").Check(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a receiver rejecting the signature must surface as an error: %v", err)
	}
}

func TestWebhookSignatureCoversTimestampAndBody(t *testing.T) {
	base := Sign([]byte("k"), "100", []byte(`{"a":1}`))
	for name, other := range map[string]string{
		"body": Sign([]byte("k"), "100", []byte(`{"a":2}`)), "timestamp": Sign([]byte("k"), "101", []byte(`{"a":1}`)),
		"secret": Sign([]byte("z"), "100", []byte(`{"a":1}`)),
	} {
		if other == base {
			t.Errorf("signature does not depend on %s", name)
		}
	}
	if !strings.HasPrefix(base, "sha256=") {
		t.Errorf("format: %s", base)
	}
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	if err := NewWebhook(redir.URL, "s").Check(context.Background()); err == nil {
		t.Error("a redirect is not success")
	}
	if hit {
		t.Error("the signed request was forwarded to the redirect target")
	}
}

// ─── Aliyun WAF ────────────────────────────────────────────────

func TestPercentEncode(t *testing.T) {
	cases := map[string]string{
		"abc-_.~09": "abc-_.~09", "a b": "a%20b", "a/b": "a%2Fb", "*": "%2A", "+": "%2B", "中": "%E4%B8%AD",
		`[{"k":"v"}]`: "%5B%7B%22k%22%3A%22v%22%7D%5D",
	}
	for in, want := range cases {
		if got := percentEncode(in); got != want {
			t.Errorf("percentEncode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := canonicalQuery(map[string]string{"b": "2", "a": "1 x"}); got != "a=1%20x&b=2" {
		t.Errorf("canonicalQuery = %s", got)
	}
}

func TestAliyunSignatureProperties(t *testing.T) {
	at := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	params := map[string]string{"InstanceId": "waf-1", "Rules": "[]"}
	base := signRequest("AK", "SK", "POST", "wafopenapi.cn-hangzhou.aliyuncs.com", "CreateDefenseRule", "2021-10-01", params, at, "n1")

	auth := base["Authorization"]
	if !strings.HasPrefix(auth, "ACS3-HMAC-SHA256 Credential=AK,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature=") {
		t.Fatalf("authorization = %s", auth)
	}
	if base["x-acs-date"] != "2026-09-29T08:00:00Z" || base["x-acs-content-sha256"] != sha256Hex(nil) {
		t.Errorf("headers = %v", base)
	}
	again := signRequest("AK", "SK", "POST", "wafopenapi.cn-hangzhou.aliyuncs.com", "CreateDefenseRule", "2021-10-01", params, at, "n1")
	if again["Authorization"] != auth {
		t.Error("signing is not deterministic")
	}
	vary := map[string]map[string]string{
		"secret": signRequest("AK", "OTHER", "POST", "h", "CreateDefenseRule", "2021-10-01", params, at, "n1"),
		"action": signRequest("AK", "SK", "POST", "wafopenapi.cn-hangzhou.aliyuncs.com", "DeleteDefenseRule", "2021-10-01", params, at, "n1"),
		"param":  signRequest("AK", "SK", "POST", "wafopenapi.cn-hangzhou.aliyuncs.com", "CreateDefenseRule", "2021-10-01", map[string]string{"InstanceId": "waf-2", "Rules": "[]"}, at, "n1"),
		"nonce":  signRequest("AK", "SK", "POST", "wafopenapi.cn-hangzhou.aliyuncs.com", "CreateDefenseRule", "2021-10-01", params, at, "n2"),
		"time":   signRequest("AK", "SK", "POST", "wafopenapi.cn-hangzhou.aliyuncs.com", "CreateDefenseRule", "2021-10-01", params, at.Add(time.Second), "n1"),
	}
	for name, h := range vary {
		if h["Authorization"] == auth {
			t.Errorf("signature ignores %s", name)
		}
	}
	if strings.Contains(auth, "SK") {
		t.Error("the secret must never appear in the header")
	}
}

func TestAliyunBlockUnblockRequests(t *testing.T) {
	type call struct {
		action string
		query  map[string]string
		auth   string
	}
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := map[string]string{}
		for k, v := range r.URL.Query() {
			q[k] = v[0]
		}
		calls = append(calls, call{r.Header.Get("x-acs-action"), q, r.Header.Get("Authorization")})
		switch r.Header.Get("x-acs-action") {
		case "CreateDefenseRule":
			w.Write([]byte(`{"RequestId":"r1","RuleIds":"7788"}`))
		case "DescribeInstance":
			w.WriteHeader(403)
			w.Write([]byte(`{"Code":"Forbidden.RAM","Message":"no permission","RequestId":"r2"}`))
		default:
			w.Write([]byte(`{"RequestId":"r3"}`))
		}
	}))
	defer srv.Close()

	a := NewAliyunWAF(AliyunConfig{AccessKeyID: "AK", AccessKeySecret: "SK", InstanceID: "waf-1", TemplateID: "42", Endpoint: srv.URL})
	ctx := context.Background()
	ref, err := a.Block(ctx, Request{IP: "198.51.100.1", AlertID: "alt-1"})
	if err != nil || ref != "7788" {
		t.Fatalf("block: ref=%q err=%v", ref, err)
	}
	c := calls[0]
	if c.action != "CreateDefenseRule" || c.query["InstanceId"] != "waf-1" || c.query["TemplateId"] != "42" || !strings.Contains(c.query["Rules"], "198.51.100.1") {
		t.Errorf("create call = %+v", c)
	}
	if !strings.HasPrefix(c.auth, "ACS3-HMAC-SHA256 Credential=AK,") {
		t.Errorf("unsigned call: %s", c.auth)
	}
	if err := a.Unblock(ctx, "198.51.100.1", ref); err != nil {
		t.Fatal(err)
	}
	if c := calls[1]; c.action != "DeleteDefenseRule" || c.query["RuleIds"] != "7788" {
		t.Errorf("delete call = %+v", c)
	}
	if err := a.Unblock(ctx, "198.51.100.1", ""); err == nil {
		t.Error("unblocking without a rule id must fail loudly, not silently succeed")
	}
	err = a.Check(ctx)
	if err == nil || !strings.Contains(err.Error(), "Forbidden.RAM") || !strings.Contains(err.Error(), "r2") {
		t.Errorf("API errors should carry code and request id: %v", err)
	}
	if !a.Experimental() {
		t.Error("the WAF connector is untested against a live instance and must say so")
	}
}

func TestAliyunRuleIDForms(t *testing.T) {
	for in, want := range map[string]string{`"1,2"`: "1,2", `[11,22]`: "11,22", `null`: "", `{}`: ""} {
		if got := ruleRef(json.RawMessage(in)); got != want {
			t.Errorf("ruleRef(%s) = %q, want %q", in, got, want)
		}
	}
}
