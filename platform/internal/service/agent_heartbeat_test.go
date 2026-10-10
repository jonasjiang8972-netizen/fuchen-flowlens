package service

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHeartbeatStoresMetricsHistoryAndLogs(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewAgentServiceFrom(ctx, repo, false)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	cfg := &AgentConfig{Mode: "gateway_log", GatewayLogPath: "/var/log/gateway/access.log", CaptureBody: true}
	if _, err := s.RegisterAgent(Registration{ID: "gw-1", Hostname: "h", CollectMode: "gateway_log", Version: "0.7.0", Arch: "arm64", Config: cfg}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxHeartbeatSamples+5; i++ {
		now = now.Add(10 * time.Second)
		if err := s.Heartbeat("gw-1", HeartbeatReport{Status: "running", QPS: float64(i), CPUPercent: 3.5, MemoryMB: 40}); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := s.Get("gw-1")
	if a.QPS != float64(maxHeartbeatSamples+4) || a.CPUPercent != 3.5 || a.MemoryMB != 40 || a.Arch != "arm64" || a.Status != "online" {
		t.Fatalf("latest metrics not kept: %+v", a)
	}
	d, _ := s.GetDetail("gw-1")
	if len(d.Metrics.QPSHistory) != maxHeartbeatSamples || len(d.Metrics.SampleTimes) != maxHeartbeatSamples {
		t.Fatalf("history length %d, want %d", len(d.Metrics.QPSHistory), maxHeartbeatSamples)
	}
	if d.Metrics.QPSHistory[0] != 5 || d.Metrics.UptimeSeconds != int64((maxHeartbeatSamples+5)*10) {
		t.Fatalf("history start %v uptime %d", d.Metrics.QPSHistory[0], d.Metrics.UptimeSeconds)
	}
	if d.Config == nil || d.Config.GatewayLogPath != "/var/log/gateway/access.log" {
		t.Fatalf("reported config lost: %+v", d.Config)
	}
	if len(d.RecentLogs) != 1 || !strings.Contains(d.RecentLogs[0].Message, "采集器注册") {
		t.Fatalf("logs: %+v", d.RecentLogs)
	}

	// Reported degradation and recovery are logged once each, newest first.
	_ = s.Heartbeat("gw-1", HeartbeatReport{Status: "degraded", DropRate: 0.03})
	_ = s.Heartbeat("gw-1", HeartbeatReport{Status: "degraded", DropRate: 0.04})
	if a, _ := s.Get("gw-1"); a.Status != "degraded" {
		t.Fatalf("reported degraded shown as %s", a.Status)
	}
	// Traffic keeps the collector alive without hiding its degradation.
	s.SeenTraffic("gw-1", "GET /api/a")
	s.SeenTraffic("gw-1", "GET /api/a")
	s.SeenTraffic("gw-1", "POST /api/b")
	if a, _ := s.Get("gw-1"); a.Status != "degraded" {
		t.Fatalf("traffic overrode reported status: %s", a.Status)
	}
	_ = s.Heartbeat("gw-1", HeartbeatReport{Status: "running"})
	now = now.Add(20 * time.Minute) // goes offline
	_ = s.Heartbeat("gw-1", HeartbeatReport{Status: "running"})
	d, _ = s.GetDetail("gw-1")
	var msgs []string
	for _, l := range d.RecentLogs {
		msgs = append(msgs, l.Message)
	}
	joined := strings.Join(msgs, " | ")
	if len(msgs) != 4 || !strings.HasPrefix(msgs[0], "离线 20m0s 后恢复心跳") ||
		!strings.Contains(joined, "恢复正常") || !strings.Contains(joined, "丢弃率 3.00%") {
		t.Fatalf("logs: %s", joined)
	}
	if d.CollectedAPIs != 2 {
		t.Fatalf("collected APIs = %d, want 2", d.CollectedAPIs)
	}

	// Latest metrics are persisted on flush.
	if _, err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	again, _ := NewAgentServiceFrom(ctx, repo, false)
	if a, _ := again.Get("gw-1"); a.Config == nil || a.Arch != "arm64" || a.RegisteredAt.IsZero() {
		t.Fatalf("not persisted: %+v", a)
	}
}

func TestHeartbeatFromUnknownAgent(t *testing.T) {
	s := NewAgentService()
	if err := s.Heartbeat("nobody", HeartbeatReport{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	s.SeenTraffic("nobody", "GET /x") // ignored, no panic
}

func TestReregistrationIsLoggedAndResetsHistory(t *testing.T) {
	s := NewAgentService()
	_, _ = s.RegisterAgent(Registration{ID: "a", Hostname: "h", CollectMode: "gateway_log"})
	_ = s.Heartbeat("a", HeartbeatReport{QPS: 9})
	_, _ = s.RegisterAgent(Registration{ID: "a", Hostname: "h", CollectMode: "gateway_log"})
	d, _ := s.GetDetail("a")
	if len(d.Metrics.QPSHistory) != 0 || !strings.Contains(d.RecentLogs[0].Message, "重新注册") {
		t.Fatalf("after re-registration: history=%v logs=%+v", d.Metrics.QPSHistory, d.RecentLogs)
	}
}
