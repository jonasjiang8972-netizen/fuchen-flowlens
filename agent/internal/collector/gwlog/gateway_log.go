package gwlog

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

type GatewayLogCollector struct {
	collector.BaseCollector
	config     collector.CollectorConfig
	cancel     context.CancelFunc
	wg         sync.WaitGroup
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

func (g *GatewayLogCollector) tailLoop(ctx context.Context) {
	file, err := os.Open(g.config.GWLogPath)
	if err != nil {
		logger.L().Errorf("Failed to open gateway log: %v", err)
		return
	}
	defer file.Close()

	_, err = file.Seek(0, 2)
	if err != nil {
		logger.L().Errorf("Failed to seek log file: %v", err)
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
					g.Emit(evt)
				}
			}
		}
	}
}

func (g *GatewayLogCollector) parseLine(line string) *shared.APIEvent {
	format := g.config.GWLogFormat
	if format == "" {
		format = "json"
	}
	return g.parseJSON(line)
}

func (g *GatewayLogCollector) parseJSON(line string) *shared.APIEvent {
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil
	}

	now := time.Now()
	evt := &shared.APIEvent{
		EventID:   fmt.Sprintf("%d-%d", now.Unix(), now.UnixMilli()%100000),
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
