package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector/gwlog"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector/ebpf"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/detector"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/health"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/normalizer"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
)

func main() {
	var configPath string
	var debug bool
	flag.StringVar(&configPath, "config", "agent-config.yaml", "path to config file")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.Parse()

	if err := logger.Init(debug); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	log := logger.L()
	log.Infof("Starting %s Agent v%s", version.Name, version.AgentVersion)

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Warnf("Using default config: %v", err)
		cfg = config.DefaultConfig()
	}

	env := detector.DetectEnvironment()
	log.Infof("Environment: %s", env.String())

	collectMode := detector.CollectMode(cfg.Collector.Mode)
	if collectMode == detector.ModeAuto {
		collectMode = detector.AutoDetect(env)
		log.Infof("Auto-detected mode: %s", collectMode)
	}

	coll, err := createCollector(collectMode)
	if err != nil {
		log.Fatalf("Failed to create collector: %v", err)
	}

	collectorCfg := collector.CollectorConfig{
		Interface:     cfg.Collector.Interface,
		FilterPorts:   cfg.Collector.FilterPorts,
		CaptureHeaders: cfg.Collector.CaptureHeaders,
		CaptureBody:    cfg.Collector.CaptureBody,
		MaxBodySize:    cfg.Collector.MaxBodySizeKB * 1024,
		BufferSize:    10000,
		Workers:        cfg.Collector.Workers,
		GWLogPath:     cfg.Collector.GWLog.Path,
		GWLogFormat:   cfg.Collector.GWLog.Format,
	}

	if err := coll.Initialize(collectorCfg); err != nil {
		log.Fatalf("Failed to initialize collector: %v", err)
	}

	norm := normalizer.New()
	monitor := health.NewMonitor(cfg.Agent.ID, cfg.Management)
	monitor.SetCollectMode(string(collectMode))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := coll.Start(ctx); err != nil {
		log.Fatalf("Failed to start collector: %v", err)
	}

	go monitor.Start(ctx)

	go processEvents(ctx, coll, norm, monitor)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := coll.Stats()
				log.Debugf("Collector stats: events=%d, dropped=%d, errors=%d",
					stats.EventsTotal, stats.DroppedTotal, stats.ErrorsTotal)
				monitor.UpdateMetrics(func(m *health.Metrics) {
					m.QPS = float64(stats.EventsTotal) / 10
				})
			}
		}
	}()

	log.Infof("Agent %s started successfully in %s mode", cfg.Agent.ID, collectMode)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Infof("Received signal %v, shutting down...", sig)

	cancel()
	coll.Stop()
	monitor.Stop()
	time.Sleep(500 * time.Millisecond)
	log.Info("Agent stopped gracefully")
}

func createCollector(mode detector.CollectMode) (collector.Collector, error) {
	switch mode {
	case detector.ModeEBPF:
		return ebpf.New(), nil
	case detector.ModeGatewayLog:
		return gwlog.New(), nil
	case detector.ModeDPDK:
		return nil, fmt.Errorf("DPDK collector not yet implemented")
	case detector.ModeVPCFlow:
		return nil, fmt.Errorf("VPC Flow collector not yet implemented")
	case detector.ModePcap:
		return nil, fmt.Errorf("pcap collector not yet implemented")
	default:
		return gwlog.New(), nil
	}
}

func processEvents(ctx context.Context, coll collector.Collector, norm *normalizer.Normalizer, mon *health.Monitor) {
	log := logger.L()
	events := coll.Events()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				log.Warn("Collector events channel closed")
				return
			}
			normalized := norm.NormalizeEvent(evt)
			if normalized.Application.PathNormalized == "" {
				normalized.Application.PathNormalized = normalized.Application.PathRaw
			}
		}
	}
}
