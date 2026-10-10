package main

import (
	"strings"
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/detector"
)

func TestResolveMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Collector.Mode = "auto"

	// Nothing configured or found: a clear error, not a silent collector.
	if _, err := resolveMode(cfg, &detector.Environment{}); err == nil || !strings.Contains(err.Error(), "gateway_log") {
		t.Fatalf("auto without a log: %v", err)
	}
	// A log found at a well-known path is used, with its format.
	m, err := resolveMode(cfg, &detector.Environment{GWLogPath: "/var/log/nginx/access.log", GWLogFormat: "nginx"})
	if err != nil || m != detector.ModeGatewayLog || cfg.Collector.GWLog.Path != "/var/log/nginx/access.log" || cfg.Collector.GWLog.Format != "nginx" {
		t.Fatalf("auto with nginx log: mode=%v err=%v cfg=%+v", m, err, cfg.Collector.GWLog)
	}
	// Modes not implemented in this version are refused.
	for _, mode := range []string{"ebpf", "pcap", "dpdk", "vpc_flow"} {
		c := config.DefaultConfig()
		c.Collector.Mode = mode
		if _, err := resolveMode(c, &detector.Environment{}); err == nil {
			t.Errorf("mode %s accepted", mode)
		}
	}
	c := config.DefaultConfig()
	c.Collector.Mode = "gateway_log"
	if m, err := resolveMode(c, &detector.Environment{}); err != nil || m != detector.ModeGatewayLog {
		t.Fatalf("explicit gateway_log: %v %v", m, err)
	}
}
