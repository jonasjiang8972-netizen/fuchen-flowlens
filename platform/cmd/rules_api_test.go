package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRuleConfigAPI(t *testing.T) {
	h := newHarness(t, "")
	tok := h.ready("secadmin")

	for _, body := range []string{
		`{"config":{"traverse_threshold":2}}`,
		`{"config":{"traverse_threshold":"abc"}}`,
		`{"config":{"no_such":1}}`,
		`{"config":{}}`,
	} {
		w := h.do(http.MethodPut, "/api/v1/rules/R-BOLA-001", tok, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d %s, want 400", body, w.Code, w.Body.String())
		}
	}
	w := h.do(http.MethodPut, "/api/v1/rules/R-BOLA-001", tok, `{"config":{"traverse_threshold":2}}`)
	if !strings.Contains(w.Body.String(), "取值范围") {
		t.Errorf("400 body does not explain the range: %s", w.Body.String())
	}

	w = h.do(http.MethodPut, "/api/v1/rules/R-BOLA-001", tok, `{"config":{"traverse_threshold":30}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("valid update: %d %s", w.Code, w.Body.String())
	}
	w = h.do(http.MethodGet, "/api/v1/rules/R-BOLA-001", tok, "")
	var rule struct {
		Params []struct {
			Key   string  `json:"key"`
			Value float64 `json:"value"`
		} `json:"params"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &rule)
	found := false
	for _, p := range rule.Params {
		if p.Key == "traverse_threshold" {
			found = true
			if p.Value != 30 {
				t.Fatalf("value after update = %v, want 30", p.Value)
			}
		}
	}
	if !found {
		t.Fatalf("traverse_threshold missing: %s", w.Body.String())
	}

	// Detection through the API uses the new threshold.
	for i := 0; i < 29; i++ {
		h.do(http.MethodPost, "/api/v1/detect/access", tok,
			`{"account_id":"api-acct","role":"user","endpoint":"/api/v1/orders/{id}","object_id":"o-`+string(rune('a'+i%26))+string(rune('a'+i/26))+`","source_ip":"10.2.2.2","status_code":200}`)
	}
	w = h.do(http.MethodPost, "/api/v1/detect/access", tok,
		`{"account_id":"api-acct","role":"user","endpoint":"/api/v1/orders/{id}","object_id":"o-last","source_ip":"10.2.2.2","status_code":200}`)
	var res struct {
		Score  int    `json:"risk_score"`
		RuleID string `json:"rule_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.Score != 70 || res.RuleID != "R-BOLA-001" {
		t.Fatalf("30th object with threshold 30: %s", w.Body.String())
	}
}
