package gwlog

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

type GatewayLogCollector struct {
	baseCollector
	config     collector.CollectorConfig
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func New() collector.Collector {
	return &GatewayLogCollector{
		baseCollector: newBaseCollector(10000),
	}
}

func (g *GatewayLogCollector) Name() string {
	return "gateway_log"
}

func (g *GatewayLogCollector) Initialize(cfg collector.CollectorConfig) error {
	g.config = cfg
	if g.config.GWLogPath == "" {
		return nil
	}
	return nil
}

func (g *GatewayLogCollector) Start(ctx context.Context) error {
	log := logger.L()
	if g.config.GWLogPath == "" {
		return log.Error("gateway log path not configured")
	}

	ctx, g.cancel = context.WithCancel(ctx)
	g.wg.Add(1)

	go func() {
		defer g.wg.Done()
		g.tailLoop(ctx)
	}()

	log.Infof("Gateway log collector started: %s (format: %s)", g.config.GWLogPath, g.config.GWLogFormat)
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
	if g.config.GWLogPath == "" {
		return nil
	}
	if _, err := os.Stat(g.config.GWLogPath); err != nil {
		return err
	}
	return nil
}

func (g *GatewayLogCollector) tailLoop(ctx context.Context) {
	log := logger.L()

	file, err := os.Open(g.config.GWLogPath)
	if err != nil {
		log.Errorf("Failed to open gateway log: %v", err)
		return
	}
	defer file.Close()

	_, err = file.Seek(0, 2)
	if err != nil {
		log.Errorf("Failed to seek log file: %v", err)
		return
	}

	reader := bufio.NewReader(file)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				evt := g.parseLine(line)
				if evt != nil {
					g.emit(evt)
				}
			}
		}
	}
}

func (g *GatewayLogCollector) parseLine(line string) *shared.APIEvent {
	switch g.config.GWLogFormat {
	case "json":
		return g.parseJSON(line)
	case "nginx":
		return g.parseNginx(line)
	case "envoy":
		return g.parseEnvoy(line)
	default:
		return g.parseJSON(line)
	}
}

func (g *GatewayLogCollector) parseJSON(line string) *shared.APIEvent {
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil
	}

	now := time.Now()
	evt := &shared.APIEvent{
		EventID:   generateID(),
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

func (g *GatewayLogCollector) parseNginx(line string) *shared.APIEvent {
	now := time.Now()
	evt := &shared.APIEvent{
		EventID:   generateID(),
		Timestamp: now,
		Source:    "gateway_log",
		Application: shared.ApplicationLayer{
			ProtocolType: "REST",
		},
	}
	evt.Network.SrcIP = "0.0.0.0"
	evt.Application.Method = "GET"
	evt.Application.StatusCode = 200
	return evt
}

func (g *GatewayLogCollector) parseEnvoy(line string) *shared.APIEvent {
	return g.parseNginx(line)
}

func generateID() string {
	return time.Now().Format("20060102") + "-" + randomStr(8)
}

func randomStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}
