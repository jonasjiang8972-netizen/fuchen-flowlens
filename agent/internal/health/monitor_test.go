package health

import (
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

func TestParseStatCPU(t *testing.T) {
	// The command name contains spaces and a parenthesis.
	line := "1234 (my (agent) x) S 1 1234 1234 0 -1 4194560 100 0 0 0 250 75 0 0 20 0 8 0 100 0 0"
	got, err := parseStatCPU(line)
	if err != nil || got != 325 {
		t.Fatalf("parseStatCPU = %d, %v; want 325", got, err)
	}
	if _, err := parseStatCPU("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestProcSampleOnLinux(t *testing.T) {
	if _, rss, err := procSample(); err == nil && rss == 0 {
		t.Fatal("resident memory read as 0")
	}
}

func TestObserveComputesIntervalRates(t *testing.T) {
	_ = logger.Init(false)
	m := NewMonitor("a1", config.ManagementConfig{})
	cpu := uint64(1000)
	m.procSample = func() (uint64, uint64, error) { return cpu, 64 << 20, nil }

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.Observe(5000, 0, t0) // first sample: baseline only
	if got := m.GetMetrics(); got.QPS != 0 || got.MemoryMB != 64 {
		t.Fatalf("first sample: %+v", got)
	}
	cpu += 150 // 1.5 s of CPU over 10 s
	m.Observe(6000, 0, t0.Add(10*time.Second))
	got := m.GetMetrics()
	if got.QPS != 100 || got.DropRate != 0 || got.CPUPercent != 15 {
		t.Fatalf("interval metrics: %+v", got)
	}
	if m.GetStatus() != "running" {
		t.Fatalf("status %q, want running", m.GetStatus())
	}
	// 50 dropped of 1050 offered: degraded.
	m.Observe(7000, 50, t0.Add(20*time.Second))
	if got := m.GetMetrics(); got.DropRate < 0.04 || got.DropRate > 0.05 || m.GetStatus() != "degraded" {
		t.Fatalf("drop rate %.4f status %q", got.DropRate, m.GetStatus())
	}
	// QPS is per interval, not cumulative.
	m.Observe(7100, 50, t0.Add(30*time.Second))
	if got := m.GetMetrics(); got.QPS != 10 || m.GetStatus() != "running" {
		t.Fatalf("after recovery: qps=%v status=%q", got.QPS, m.GetStatus())
	}
}
