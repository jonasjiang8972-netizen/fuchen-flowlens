package main

import (
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/server"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

func TestConfigureBOLAML(t *testing.T) {
	srv := server.NewPlatformServer(storage.NewMemStore())
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	if err := configureBOLAML(srv, env(nil)); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if err := configureBOLAML(srv, env(map[string]string{"FLOWLENS_BOLA_ML": "off", "FLOWLENS_BOLA_ML_THRESHOLD": "0.7"})); err != nil {
		t.Fatalf("off: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"not a number": {"FLOWLENS_BOLA_ML_THRESHOLD": "high"},
		"too low":      {"FLOWLENS_BOLA_ML_THRESHOLD": "0.4"},
		"never flags":  {"FLOWLENS_BOLA_ML_THRESHOLD": "1"},
	} {
		if err := configureBOLAML(srv, env(m)); err == nil {
			t.Errorf("%s: expected a configuration error", name)
		}
	}
}
