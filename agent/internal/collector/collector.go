package collector

import (
	"context"
	"io"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

type CollectMode string

type Collector interface {
	Name() string
	Initialize(cfg CollectorConfig) error
	Start(ctx context.Context) error
	Stop() error
	Events() <-chan *shared.APIEvent
	Stats() CollectorStats
	HealthCheck() error
}

type CollectorConfig struct {
	Interface     string
	FilterPorts   []string
	CaptureHeaders bool
	CaptureBody    bool
	MaxBodySize   int
	BufferSize    int
	Workers       int
	GWLogPath     string
	GWLogFormat   string
}

type CollectorStats struct {
	EventsTotal   uint64
	PacketsTotal  uint64
	BytesTotal    uint64
	DroppedTotal  uint64
	ErrorsTotal   uint64
	LastEventTime int64
}

var _ io.Closer = (*BaseCollector)(nil)

type BaseCollector struct {
	events chan *shared.APIEvent
	stats  CollectorStats
}

func NewBaseCollector(bufferSize int) BaseCollector {
	return BaseCollector{
		events: make(chan *shared.APIEvent, bufferSize),
	}
}

func (b *BaseCollector) Events() <-chan *shared.APIEvent {
	return b.events
}

func (b *BaseCollector) Stats() CollectorStats {
	return b.stats
}

func (b *BaseCollector) Emit(evt *shared.APIEvent) {
	select {
	case b.events <- evt:
		b.stats.EventsTotal++
		b.stats.LastEventTime = evt.Timestamp.UnixMilli()
	default:
		b.stats.DroppedTotal++
	}
}

func (b *BaseCollector) Close() error {
	close(b.events)
	return nil
}
