package health

import (
	"context"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
)

type Monitor struct {
	mu          sync.RWMutex
	agentID     string
	config      config.ManagementConfig
	status      string
	metrics     Metrics
	lastHeartbeat time.Time
	handlers    []StatusHandler
}

type Metrics struct {
	QPS               float64   `json:"qps"`
	PacketsPerSec     float64   `json:"packets_per_sec"`
	DropRate          float64   `json:"drop_rate"`
	BytesProcessed    uint64    `json:"bytes_processed"`
	CPUPercent        float64   `json:"cpu_percent"`
	MemoryMB          uint64    `json:"memory_mb"`
	KafkaLatencyMS    int64     `json:"kafka_produce_latency_ms"`
	KafkaPending      uint64    `json:"kafka_pending_messages"`
	CollectMode       string    `json:"collect_mode"`
}

type StatusHandler func(status string, message string)

func NewMonitor(agentID string, cfg config.ManagementConfig) *Monitor {
	return &Monitor{
		agentID:  agentID,
		config:   cfg,
		status:   "initializing",
		handlers: make([]StatusHandler, 0),
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
			m.lastHeartbeat = time.Now()
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
