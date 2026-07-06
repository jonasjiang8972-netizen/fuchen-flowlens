package ebpf

import (
	"context"
	"fmt"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

type EBPFCollector struct {
	baseCollector
	config collector.CollectorConfig
	cancel context.CancelFunc
}

func New() collector.Collector {
	return &EBPFCollector{
		baseCollector: newBaseCollector(10000),
	}
}

func (e *EBPFCollector) Name() string {
	return "ebpf"
}

func (e *EBPFCollector) Initialize(cfg collector.CollectorConfig) error {
	e.config = cfg
	return nil
}

func (e *EBPFCollector) Start(ctx context.Context) error {
	logger.L().Warn("eBPF collector: using simulation mode (actual eBPF requires compiled C programs)")
	ctx, e.cancel = context.WithCancel(ctx)
	go e.simulate(ctx)
	return nil
}

func (e *EBPFCollector) Stop() error {
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}

func (e *EBPFCollector) HealthCheck() error {
	return nil
}

func (e *EBPFCollector) simulate(ctx context.Context) {
	<-ctx.Done()
}
