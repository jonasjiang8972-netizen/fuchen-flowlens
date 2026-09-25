package gwlog

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

type GatewayLogCollector struct {
	collector.BaseCollector
	config collector.CollectorConfig
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New() collector.Collector {
	return &GatewayLogCollector{
		BaseCollector: collector.NewBaseCollector(10000),
	}
}

func (g *GatewayLogCollector) Name() string {
	return "gateway_log"
}

func (g *GatewayLogCollector) Initialize(cfg collector.CollectorConfig) error {
	g.config = cfg
	return nil
}

func (g *GatewayLogCollector) Start(ctx context.Context) error {
	if g.config.GWLogPath == "" {
		return fmt.Errorf("gateway log path not configured")
	}

	ctx, g.cancel = context.WithCancel(ctx)
	g.wg.Add(1)

	go func() {
		defer g.wg.Done()
		g.tailLoop(ctx)
	}()

	logger.L().Infof("Gateway log collector started: %s (format: %s)", g.config.GWLogPath, g.config.GWLogFormat)
	return nil
}

func (g *GatewayLogCollector) Stop() error {
	if g.cancel != nil {
		g.cancel()
	}
	g.wg.Wait()
	return nil
}

func (g *GatewayLogCollector) HealthCheck() error {
	if _, err := os.Stat(g.config.GWLogPath); err != nil {
		return err
	}
	return nil
}

// openRetryInterval is how often a missing gateway log is re-checked.
var openRetryInterval = time.Second

// openLog waits until the gateway log can be opened, so the agent may start
// before the gateway writes its first line. It returns nil when ctx ends.
func (g *GatewayLogCollector) openLog(ctx context.Context) *os.File {
	warned := false
	for {
		file, err := os.Open(g.config.GWLogPath)
		if err == nil {
			if warned {
				logger.L().Infof("Gateway log %s is now available", g.config.GWLogPath)
			}
			return file
		}
		if !warned {
			logger.L().Warnf("Gateway log not readable yet, retrying: %v", err)
			warned = true
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(openRetryInterval):
		}
	}
}

// tailLoop follows the gateway log from its current end. It keeps an
// incomplete last line until the rest is written, starts over when the file
// is truncated (copytruncate rotation) and reopens it when it is replaced
// (rename rotation).
func (g *GatewayLogCollector) tailLoop(ctx context.Context) {
	file := g.openLog(ctx)
	if file == nil {
		return
	}
	defer func() { file.Close() }()

	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		logger.L().Errorf("Failed to seek log file: %v", err)
		return
	}

	reader := bufio.NewReader(file)
	var partial strings.Builder
	drain := func() {
		for {
			chunk, err := reader.ReadString('\n')
			offset += int64(len(chunk))
			if err != nil {
				partial.WriteString(chunk)
				return
			}
			line := chunk
			if partial.Len() > 0 {
				partial.WriteString(chunk)
				line = partial.String()
				partial.Reset()
			}
			g.handleLine(line)
		}
	}
	restart := func(f *os.File) {
		file = f
		offset = 0
		reader.Reset(f)
		partial.Reset()
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		drain()

		cur, err := os.Stat(g.config.GWLogPath)
		if err != nil {
			continue // rotated away and not recreated yet: keep the old file
		}
		open, err := file.Stat()
		if err != nil {
			continue
		}
		switch {
		case !os.SameFile(cur, open):
			drain() // lines written to the old file before the switch
			nf, err := os.Open(g.config.GWLogPath)
			if err != nil {
				continue
			}
			logger.L().Infof("Gateway log %s was rotated, reopening", g.config.GWLogPath)
			file.Close()
			restart(nf)
		case cur.Size() < offset:
			logger.L().Infof("Gateway log %s was truncated, reading from the start", g.config.GWLogPath)
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				logger.L().Errorf("Failed to seek log file: %v", err)
				return
			}
			restart(file)
		}
	}
}

func (g *GatewayLogCollector) handleLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if evt := g.parseLine(line); evt != nil {
		g.Emit(evt)
	}
}

func (g *GatewayLogCollector) parseLine(line string) *shared.APIEvent {
	format := g.config.GWLogFormat
	if format == "" {
		format = "json"
	}
	return g.parseJSON(line)
}

// newEventID returns an ID unique per event. The platform drops events whose
// ID it has already seen, so IDs must not repeat even for lines read in the
// same instant.
func newEventID(now time.Time) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("gw-%d-%d", now.UnixNano(), eventSeq.Add(1))
	}
	return fmt.Sprintf("gw-%d-%s", now.UnixNano(), hex.EncodeToString(b[:]))
}

var eventSeq atomic.Uint64

func (g *GatewayLogCollector) parseJSON(line string) *shared.APIEvent {
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil
	}

	now := time.Now()
	evt := &shared.APIEvent{
		EventID:   newEventID(now),
		Timestamp: now,
		Source:    "gateway_log",
		Application: shared.ApplicationLayer{
			ProtocolType: "REST",
		},
	}

	if v, ok := entry["request"].(map[string]interface{}); ok {
		if method, ok := v["method"].(string); ok {
			evt.Application.Method = method
		}
		if uri, ok := v["uri"].(string); ok {
			evt.Application.PathRaw = uri
		}
		if host, ok := v["host"].(string); ok {
			evt.Application.Host = host
		}
	}

	if v, ok := entry["response"].(map[string]interface{}); ok {
		if status, ok := v["status"].(float64); ok {
			evt.Application.StatusCode = uint16(status)
		}
	}

	if v, ok := entry["client_ip"].(string); ok {
		evt.Network.SrcIP = v
	}
	if v, ok := entry["upstream_addr"].(string); ok {
		evt.Network.DstIP = strings.Split(v, ":")[0]
	}
	if v, ok := entry["request_length"].(float64); ok {
		evt.Application.BytesIn = uint64(v)
	}
	if v, ok := entry["bytes_sent"].(float64); ok {
		evt.Application.BytesOut = uint64(v)
	}
	if v, ok := entry["request_time"].(float64); ok {
		evt.Application.DurationMs = v * 1000
	}
	if v, ok := entry["route"].(map[string]interface{}); ok {
		if name, ok := v["name"].(string); ok {
			evt.Metadata.ServiceName = name
		}
	}

	return evt
}
