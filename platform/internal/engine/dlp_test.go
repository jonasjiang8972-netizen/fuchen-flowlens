package engine

import (
	"strings"
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

func TestSensitiveType(t *testing.T) {
	for field, want := range map[string]string{
		"id_card_no":      SensitiveIDCard,
		"IDCard":          SensitiveIDCard,
		"card_number":     SensitiveBankCard,
		"bank_account":    SensitiveBankCard,
		"recipient_phone": SensitivePhone,
		"mobile":          SensitivePhone,
		"access_token":    SensitiveCredential,
		"x_api_key":       SensitiveCredential,
		"email":           SensitiveContact,
		"hotel_name":      "", // "tel" inside a word is not a phone
		"order_id":        "",
	} {
		if got := SensitiveType(field); got != want {
			t.Errorf("SensitiveType(%q) = %q, want %q", field, got, want)
		}
	}
}

func TestDLPExportEndpoint(t *testing.T) {
	store := storage.NewMemStore()
	e := NewDLPEngine(store)
	score, reason := e.Evaluate("/api/v1/customers/export", "10.0.0.5", []string{"phone", "name"})
	if score != 75 || !strings.Contains(reason, "敏感数据导出") || !strings.Contains(reason, "手机号") {
		t.Fatalf("score=%d reason=%q", score, reason)
	}
	if n := len(detectionEvents(t, store, "SENSITIVE_DATA")); n != 1 {
		t.Fatalf("stored %d events, want 1", n)
	}
	// Same endpoint again: alert-worthy, but the stored event is throttled.
	e.Evaluate("/api/v1/customers/export", "10.0.0.5", []string{"phone"})
	if n := len(detectionEvents(t, store, "SENSITIVE_DATA")); n != 1 {
		t.Fatalf("stored %d events after a repeat, want 1", n)
	}
}

func TestDLPManyFieldsAndCredentials(t *testing.T) {
	e := NewDLPEngine(storage.NewMemStore())
	if score, _ := e.Evaluate("/api/v1/users/{id}", "", []string{"phone", "id_card"}); score != 0 {
		t.Fatalf("2 fields under the threshold of 3 scored %d", score)
	}
	score, reason := e.Evaluate("/api/v1/users/{id}", "", []string{"phone", "id_card", "card_number"})
	if score != 75 || !strings.Contains(reason, "3 个敏感字段") {
		t.Fatalf("3 fields: score=%d reason=%q", score, reason)
	}
	if score, _ := e.Evaluate("/api/v1/export", "", []string{"password"}); score != 85 {
		t.Fatalf("credential in export scored %d, want 85", score)
	}
}

func TestDLPConfigure(t *testing.T) {
	e := NewDLPEngine(storage.NewMemStore())
	// Contact data is off by default.
	if score, _ := e.Evaluate("/api/export", "", []string{"email"}); score != 0 {
		t.Fatalf("contact field scored %d while disabled", score)
	}
	e.Configure(Params{"contact": true, "phone": false, "export_keywords": "report", "max_fields": 2.0})
	if score, _ := e.Evaluate("/api/report/daily", "", []string{"email"}); score != 75 {
		t.Fatalf("enabled contact on a custom export keyword scored %d", score)
	}
	if score, _ := e.Evaluate("/api/report/daily", "", []string{"phone"}); score != 0 {
		t.Fatalf("disabled phone type scored %d", score)
	}
	if score, _ := e.Evaluate("/api/export", "", []string{"email"}); score != 0 {
		t.Fatalf("old export keyword still applies: %d", score)
	}
	if score, _ := e.Evaluate("/api/users", "", []string{"email", "id_card"}); score != 75 {
		t.Fatalf("max_fields 2 not applied: %d", score)
	}
}

func TestParamsAccessors(t *testing.T) {
	p := Params{"f": 2.5, "s": "3", "b": "true", "l": " a, ,b ,", "bad": []int{1}}
	if p.Float("f", 0) != 2.5 || p.Int("s", 0) != 3 || !p.Bool("b", false) {
		t.Fatalf("accessors: %v %v %v", p.Float("f", 0), p.Int("s", 0), p.Bool("b", false))
	}
	if got := p.List("l", ""); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("List = %q", got)
	}
	if p.Int("bad", 7) != 7 || p.Int("missing", 9) != 9 || p.String("missing", "d") != "d" {
		t.Fatalf("fallbacks not used")
	}
	var nilParams Params
	if nilParams.Int("x", 4) != 4 {
		t.Fatalf("nil params must give defaults")
	}
}
