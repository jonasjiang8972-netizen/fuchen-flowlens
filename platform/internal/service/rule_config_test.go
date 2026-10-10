package service

import (
	"encoding/json"
	"errors"
	"testing"
)

func paramValue(t *testing.T, r *Rule, key string) interface{} {
	t.Helper()
	for _, p := range r.Params {
		if p.Key == key {
			return p.Value
		}
	}
	t.Fatalf("rule %s has no param %s", r.ID, key)
	return nil
}

func TestRuleParamValueIsSavedOrDefault(t *testing.T) {
	s := NewRuleService()
	r, _ := s.Get("R-BOLA-001")
	if v := paramValue(t, r, "traverse_threshold"); v != 20 {
		t.Fatalf("default value = %v", v)
	}
	r, err := s.UpdateConfig("R-BOLA-001", map[string]interface{}{"traverse_threshold": 42.0})
	if err != nil {
		t.Fatal(err)
	}
	if v := paramValue(t, r, "traverse_threshold"); v != 42.0 {
		t.Fatalf("saved value = %v", v)
	}
	if got := s.Values("R-BOLA-001"); got["traverse_threshold"] != 42.0 || got["window_minutes"] != 5 {
		t.Fatalf("values = %v", got)
	}
}

func TestRuleConfigValidation(t *testing.T) {
	s := NewRuleService()
	cases := []map[string]interface{}{
		{"no_such_param": 1.0},
		{"traverse_threshold": 2.0},            // below min 5
		{"traverse_threshold": 20.5},           // not an integer
		{"traverse_threshold": "20"},           // wrong type
		{"window_minutes": 999.0},              // above max 60
		{"traverse_threshold": 30.0, "x": 1.0}, // one bad key rejects all
	}
	for _, cfg := range cases {
		if _, err := s.UpdateConfig("R-BOLA-001", cfg); !errors.Is(err, ErrInvalid) {
			t.Errorf("config %v: err = %v, want ErrInvalid", cfg, err)
		}
	}
	if v := s.Values("R-BOLA-001")["traverse_threshold"]; v != 20 {
		t.Fatalf("rejected update changed the rule: %v", v)
	}
	if _, err := s.UpdateConfig("R-BFLA-001", map[string]interface{}{"strict_mode": "yes"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bool given a string: %v", err)
	}
	if _, err := s.UpdateConfig("R-BFLA-001", map[string]interface{}{"admin_endpoints": "   "}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty string accepted: %v", err)
	}
	if _, err := s.UpdateConfig("R-BFLA-001", map[string]interface{}{"rare_share": 0.2, "strict_mode": true}); err != nil {
		t.Errorf("valid update rejected: %v", err)
	}
}

func TestRuleDefaultsHaveNoFakeHits(t *testing.T) {
	for _, r := range NewRuleService().List() {
		if r.HitCount != 0 || r.LastHitAt != nil {
			t.Errorf("%s ships with hit_count=%d last_hit=%v", r.ID, r.HitCount, r.LastHitAt)
		}
	}
}

// A rule stored by an older version keeps its switch, hits and valid values,
// takes the current definitions and drops values that no longer fit.
func TestStoredRuleMigratesToCurrentDefinitions(t *testing.T) {
	repo := newMemRepo()
	old := Rule{
		ID: "R-BOLA-001", Name: "旧名称", Enabled: false, HitCount: 9,
		Config: map[string]interface{}{
			"traverse_threshold": 50.0,  // still valid
			"rate_threshold":     2.0,   // parameter removed
			"window_minutes":     500.0, // out of range now
			"baseline_window":    "5m",  // descriptive leftovers
		},
		Params: []RuleParam{{Key: "rate_threshold", Type: "float"}},
	}
	raw, _ := json.Marshal(old)
	if err := repo.SaveDocuments(ctx, KindRule, map[string][]byte{"R-BOLA-001": raw}); err != nil {
		t.Fatal(err)
	}
	s, err := NewRuleServiceFrom(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := s.Get("R-BOLA-001")
	if r.Enabled || r.HitCount != 9 || r.Name != "BOLA 对象遍历检测" {
		t.Fatalf("switch/hits/definition: enabled=%v hits=%d name=%q", r.Enabled, r.HitCount, r.Name)
	}
	if len(r.Config) != 1 || r.Config["traverse_threshold"] != 50.0 {
		t.Fatalf("config after migration = %v", r.Config)
	}
	if len(r.Params) != 2 {
		t.Fatalf("params not replaced by current definitions: %+v", r.Params)
	}
	// The migrated rule was written back.
	again, _ := NewRuleServiceFrom(ctx, repo)
	if r2, _ := again.Get("R-BOLA-001"); r2.Name != "BOLA 对象遍历检测" || len(r2.Config) != 1 {
		t.Fatalf("migration not saved: %+v", r2)
	}
}

func TestStoredRulesDoNotPersistComputedValues(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewRuleServiceFrom(ctx, repo)
	if _, err := s.UpdateConfig("R-BOLA-001", map[string]interface{}{"traverse_threshold": 30.0}); err != nil {
		t.Fatal(err)
	}
	// Reloading migrates the stored rule; the rewrite must not store values
	// either.
	if _, err := NewRuleServiceFrom(ctx, repo); err != nil {
		t.Fatal(err)
	}
	docs, _ := repo.LoadDocuments(ctx, KindRule)
	for id, raw := range docs {
		var stored Rule
		_ = json.Unmarshal(raw, &stored)
		for _, p := range stored.Params {
			if p.Value != nil {
				t.Fatalf("%s param %s stored with value %v", id, p.Key, p.Value)
			}
		}
	}
}
