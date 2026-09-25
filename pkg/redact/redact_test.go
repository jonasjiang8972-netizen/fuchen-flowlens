package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func TestMaskText(t *testing.T) {
	cases := map[string]string{
		"身份证 110101199003074514 已核验": "身份证 110***********4514 已核验",
		"手机 13800138000":             "手机 138****8000",
		"卡号 6222021234567890128":     "卡号 622202*********0128",
		"卡号 6222 0212 3456 7890 128": "卡号 622202*********0128",
		"订单 1234567890123 不是卡号":      "订单 1234567890123 不是卡号", // fails Luhn
		"普通数字 42 和 2026-09-25":       "普通数字 42 和 2026-09-25",
	}
	for in, want := range cases {
		if got := MaskText(in); got != want {
			t.Errorf("MaskText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCredentialHeadersBecomeStableFingerprints(t *testing.T) {
	r := New("deploy-key")
	evt := shared.APIEvent{}
	evt.Content.RequestHeaders = map[string]string{
		"Authorization": "Bearer eyJhbGciOi.secret.sig",
		"Cookie":        "SESSION=abc123",
		"X-Api-Key":     "pk_live_123",
		"X-User-Id":     "u-1001",
		"X-Mobile":      "13800138000",
	}
	r.Event(&evt)
	h := evt.Content.RequestHeaders
	for _, k := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if !strings.HasPrefix(h[k], "sm3:") || strings.Contains(h[k], "secret") || strings.Contains(h[k], "abc123") {
			t.Errorf("%s = %q, want sm3 fingerprint", k, h[k])
		}
	}
	if h["X-User-Id"] != "u-1001" {
		t.Errorf("non-sensitive header changed: %q", h["X-User-Id"])
	}
	if h["X-Mobile"] != "138****8000" {
		t.Errorf("phone in header not masked: %q", h["X-Mobile"])
	}
	if r.Fingerprint("pk_live_123") != h["X-Api-Key"] {
		t.Error("fingerprint not stable")
	}
	if New("other-key").Fingerprint("pk_live_123") == h["X-Api-Key"] {
		t.Error("fingerprint not keyed")
	}
}

func TestJSONBodyRedaction(t *testing.T) {
	r := New("k")
	evt := shared.APIEvent{}
	evt.Content.RequestBody = []byte(`{"username":"alice","password":"P@ssw0rd!","card":{"number":"6222021234567890128","cvv":"123"},"pay_pin":123456}`)
	evt.Content.ResponseBody = []byte(`{"data":[{"name":"张三","id_card":"110101199003074514","mobile":13800138000,"email":"a@b.com"}],"access_token":"tok"}`)
	r.Event(&evt)

	var req, resp map[string]any
	if err := json.Unmarshal(evt.Content.RequestBody, &req); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(evt.Content.ResponseBody, &resp); err != nil {
		t.Fatal(err)
	}
	card := req["card"].(map[string]any)
	if req["password"] != Removed || card["cvv"] != Removed || req["pay_pin"] != Removed {
		t.Errorf("secrets kept: %s", evt.Content.RequestBody)
	}
	if card["number"] != "622202*********0128" || req["username"] != "alice" {
		t.Errorf("card/username wrong: %s", evt.Content.RequestBody)
	}
	row := resp["data"].([]any)[0].(map[string]any)
	if row["id_card"] != "110***********4514" || row["mobile"] != "138****8000" || resp["access_token"] != Removed {
		t.Errorf("response not masked: %s", evt.Content.ResponseBody)
	}
	// Field names survive for classification.
	for _, key := range []string{`"id_card"`, `"mobile"`, `"password"`} {
		if !strings.Contains(string(evt.Content.ResponseBody)+string(evt.Content.RequestBody), key) {
			t.Errorf("field name %s lost", key)
		}
	}
}

func TestFormTruncatedBodiesQueryAndPath(t *testing.T) {
	r := New("k")
	evt := shared.APIEvent{}
	evt.Content.ContentType = "application/x-www-form-urlencoded"
	evt.Content.RequestBody = []byte("user=bob&password=hunter2&phone=13912345678")
	evt.Content.ResponseBody = []byte(`{"token":"abc","phone":"13800138000","trunc`) // truncated JSON
	evt.Content.QueryParams = map[string]string{"access_token": "t", "mobile": "13800138000", "page": "2"}
	evt.Application.PathRaw = "/api/users/13800138000/cards/6222021234567890128"
	r.Event(&evt)

	if got := string(evt.Content.RequestBody); strings.Contains(got, "hunter2") || !strings.Contains(got, "139%2A%2A%2A%2A5678") {
		t.Errorf("form body = %q", got)
	}
	if got := string(evt.Content.ResponseBody); strings.Contains(got, `"abc"`) || strings.Contains(got, "13800138000") {
		t.Errorf("truncated body = %q", got)
	}
	q := evt.Content.QueryParams
	if q["access_token"] != Removed || q["mobile"] != "138****8000" || q["page"] != "2" {
		t.Errorf("query = %v", q)
	}
	if evt.Application.PathRaw != "/api/users/138****8000/cards/622202*********0128" {
		t.Errorf("path = %q", evt.Application.PathRaw)
	}
}

func TestRedactionIsIdempotent(t *testing.T) {
	r := New("k")
	evt := shared.APIEvent{}
	evt.Content.RequestHeaders = map[string]string{"Authorization": "Bearer x", "X-Phone": "13800138000"}
	evt.Content.QueryParams = map[string]string{"token": "t", "id": "110101199003074514"}
	evt.Content.ResponseBody = []byte(`{"mobile":"13800138000","password":"x","card":"6222021234567890128"}`)
	evt.Application.PathRaw = "/u/13800138000"
	r.Event(&evt)
	first, _ := json.Marshal(evt)

	// The platform re-applies redaction on ingest; a second pass must be a no-op.
	New("platform-key").Event(&evt)
	second, _ := json.Marshal(evt)
	if string(first) != string(second) {
		t.Errorf("second pass changed the event:\n%s\n%s", first, second)
	}
}
