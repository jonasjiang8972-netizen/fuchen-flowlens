package gwlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

func TestTailWaitsForLogFile(t *testing.T) {
	_ = logger.Init(false)
	openRetryInterval = 20 * time.Millisecond

	path := filepath.Join(t.TempDir(), "access.log")
	g := New().(*GatewayLogCollector)
	if err := g.Initialize(collector.CollectorConfig{GWLogPath: path}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := g.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	// The file appears after the collector started; lines appended after it
	// is opened must be collected.
	time.Sleep(60 * time.Millisecond)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	time.Sleep(60 * time.Millisecond)
	line := `{"request":{"method":"GET","uri":"/api/v1/users/1","host":"shop"},"response":{"status":200},"client_ip":"10.0.0.8"}` + "\n"
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}

	select {
	case evt := <-g.Events():
		if evt.Application.Method != "GET" || evt.Application.PathRaw != "/api/v1/users/1" || evt.Network.SrcIP != "10.0.0.8" {
			t.Fatalf("unexpected event: %+v", evt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event collected from a log file created after start")
	}
}

func TestStopWhileWaitingForLogFile(t *testing.T) {
	_ = logger.Init(false)
	openRetryInterval = 20 * time.Millisecond
	g := New().(*GatewayLogCollector)
	_ = g.Initialize(collector.CollectorConfig{GWLogPath: filepath.Join(t.TempDir(), "missing.log")})
	if err := g.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = g.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked while waiting for the log file")
	}
}

func startCollector(t *testing.T, path string) *GatewayLogCollector {
	t.Helper()
	_ = logger.Init(false)
	openRetryInterval = 20 * time.Millisecond
	g := New().(*GatewayLogCollector)
	_ = g.Initialize(collector.CollectorConfig{GWLogPath: path})
	ctx, cancel := context.WithCancel(context.Background())
	if err := g.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = g.Stop() })
	time.Sleep(150 * time.Millisecond) // opened and positioned at the end
	return g
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func logLine(uri string) string {
	return `{"request":{"method":"GET","uri":"` + uri + `"},"response":{"status":200}}` + "\n"
}

func expectURI(t *testing.T, g *GatewayLogCollector, uri string) {
	t.Helper()
	select {
	case evt := <-g.Events():
		if evt.Application.PathRaw != uri {
			t.Fatalf("got %q, want %q", evt.Application.PathRaw, uri)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no event for %s", uri)
	}
}

func TestTailSkipsExistingContentAndJoinsPartialLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	appendTo(t, path, logLine("/old"))
	g := startCollector(t, path)

	full := logLine("/split")
	appendTo(t, path, full[:20])
	time.Sleep(250 * time.Millisecond) // several ticks see only the first half
	appendTo(t, path, full[20:])
	expectURI(t, g, "/split")
}

func TestTailFollowsTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	appendTo(t, path, logLine("/before-1")+logLine("/before-2"))
	g := startCollector(t, path)

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	appendTo(t, path, logLine("/after"))
	expectURI(t, g, "/after")
}

func TestTailFollowsRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	appendTo(t, path, logLine("/old"))
	g := startCollector(t, path)

	appendTo(t, path, logLine("/last-in-old"))
	if err := os.Rename(path, filepath.Join(dir, "access.log.1")); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, logLine("/first-in-new"))
	expectURI(t, g, "/last-in-old")
	expectURI(t, g, "/first-in-new")
}

func TestEventIDsUniqueWithinSameInstant(t *testing.T) {
	now := time.Now()
	seen := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		id := newEventID(now)
		if seen[id] {
			t.Fatalf("duplicate event ID %s after %d IDs", id, i)
		}
		seen[id] = true
	}
}
