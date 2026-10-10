package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

type Monitor struct {
	mu            sync.RWMutex
	agentID       string
	config        config.ManagementConfig
	status        string
	metrics       Metrics
	lastHeartbeat time.Time
	handlers      []StatusHandler

	// Previous Observe sample, for per-interval rates.
	prevAt      time.Time
	prevEvents  uint64
	prevDropped uint64
	prevCPU     uint64
	procSample  func() (uint64, uint64, error)
}

// degradedDropRate is the share of dropped events from which the agent
// reports itself degraded.
const degradedDropRate = 0.01

type Metrics struct {
	QPS            float64 `json:"qps"`
	PacketsPerSec  float64 `json:"packets_per_sec"`
	DropRate       float64 `json:"drop_rate"`
	BytesProcessed uint64  `json:"bytes_processed"`
	CPUPercent     float64 `json:"cpu_percent"`
	MemoryMB       uint64  `json:"memory_mb"`
	KafkaLatencyMS int64   `json:"kafka_produce_latency_ms"`
	KafkaPending   uint64  `json:"kafka_pending_messages"`
	CollectMode    string  `json:"collect_mode"`
}

type StatusHandler func(status string, message string)

func NewMonitor(agentID string, cfg config.ManagementConfig) *Monitor {
	return &Monitor{
		agentID:    agentID,
		config:     cfg,
		status:     "initializing",
		handlers:   make([]StatusHandler, 0),
		procSample: procSample,
	}
}

// Observe takes the collector's cumulative counters and updates the
// metrics for the interval since the previous call: QPS and drop rate from
// the counter deltas, CPU share and resident memory of this process, and
// the status (degraded while the drop rate is at least 1%, else running).
func (m *Monitor) Observe(eventsTotal, droppedTotal uint64, now time.Time) {
	cpuTicks, rss, procErr := m.procSample()

	m.mu.Lock()
	first := m.prevAt.IsZero()
	elapsed := now.Sub(m.prevAt).Seconds()
	if !first && elapsed > 0 && eventsTotal >= m.prevEvents && droppedTotal >= m.prevDropped {
		events := float64(eventsTotal - m.prevEvents)
		dropped := float64(droppedTotal - m.prevDropped)
		m.metrics.QPS = events / elapsed
		m.metrics.DropRate = 0
		if events+dropped > 0 {
			m.metrics.DropRate = dropped / (events + dropped)
		}
		if procErr == nil && cpuTicks >= m.prevCPU {
			m.metrics.CPUPercent = float64(cpuTicks-m.prevCPU) / clockTicks / elapsed * 100
		}
	}
	if procErr == nil {
		m.metrics.MemoryMB = rss / (1 << 20)
		m.prevCPU = cpuTicks
	}
	m.prevAt, m.prevEvents, m.prevDropped = now, eventsTotal, droppedTotal
	status := "running"
	if m.metrics.DropRate >= degradedDropRate {
		status = "degraded"
	}
	changed := status != m.status
	m.mu.Unlock()

	if changed {
		m.setStatus(status, fmt.Sprintf("drop rate %.2f%%", m.metrics.DropRate*100))
	}
}

func (m *Monitor) Start(ctx context.Context) {
	logger.L().Infof("Health monitor started for agent %s", m.agentID)
	ticker := time.NewTicker(m.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.setStatus("stopping", "agent shutting down")
			return
		case <-ticker.C:
			m.mu.Lock()
			m.lastHeartbeat = time.Now()
			m.mu.Unlock()
		}
	}
}

func (m *Monitor) Stop() {
	m.setStatus("stopped", "monitor stopped")
}

func (m *Monitor) GetStatus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Monitor) GetMetrics() Metrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics
}

func (m *Monitor) UpdateMetrics(fn func(*Metrics)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(&m.metrics)
}

func (m *Monitor) SetCollectMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics.CollectMode = mode
}

func (m *Monitor) setStatus(status, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldStatus := m.status
	m.status = status
	logger.L().Infof("Agent status changed: %s -> %s (%s)", oldStatus, status, message)
	for _, h := range m.handlers {
		h(status, message)
	}
}

func (m *Monitor) OnStatusChange(handler StatusHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

func (m *Monitor) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status == "running"
}

func (m *Monitor) TimeSinceHeartbeat() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return time.Since(m.lastHeartbeat)
}
