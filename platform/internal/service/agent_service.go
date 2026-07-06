package service

import (
	"fmt"
	"sync"
	"time"
)

type Agent struct {
	ID             string    `json:"agent_id"`
	Hostname       string    `json:"hostname"`
	Status         string    `json:"status"`
	CollectMode    string    `json:"collect_mode"`
	Cluster        string    `json:"cluster"`
	QPS            float64   `json:"qps"`
	LastHeartbeat  time.Time `json:"last_heartbeat"`
	AgentVersion   string    `json:"agent_version"`
	OS             string    `json:"os"`
	Arch           string    `json:"arch"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemoryMB       uint64    `json:"memory_mb_used"`
	DropRate       float64   `json:"drop_rate"`
	KernelVersion  string    `json:"kernel_version"`
	Interface      string    `json:"interface"`
	Namespace      string    `json:"namespace"`
	ServiceName    string    `json:"service_name"`
	CloudProvider  string    `json:"cloud_provider"`
	Region         string    `json:"region"`
}

type AgentDetail struct {
	Agent
	Metrics       *AgentMetrics   `json:"metrics"`
	Config        *AgentConfig    `json:"config"`
	RecentLogs    []LogEntry      `json:"recent_logs"`
	CollectedAPIs int             `json:"collected_apis"`
}

type AgentMetrics struct {
	QPSHistory       []float64         `json:"qps_history"`
	DropRateHistory  []float64         `json:"drop_rate_history"`
	CPUHistory       []float64         `json:"cpu_history"`
	MemoryHistory    []uint64          `json:"memory_history"`
	KafkaLag         int64             `json:"kafka_lag"`
	BytesProcessed   uint64            `json:"bytes_processed"`
	PacketsProcessed uint64            `json:"packets_processed"`
	UptimeSeconds    int64             `json:"uptime_seconds"`
}

type AgentConfig struct {
	Mode           string   `json:"mode"`
	FilterPorts    []string `json:"filter_ports"`
	CaptureHeaders bool     `json:"capture_headers"`
	CaptureBody    bool     `json:"capture_body"`
	MaxBodySizeKB  int      `json:"max_body_size_kb"`
	KafkaBrokers   []string `json:"kafka_brokers"`
	KafkaTopic     string   `json:"kafka_topic"`
}

type LogEntry struct {
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type AgentService struct {
	mu     sync.RWMutex
	agents map[string]*Agent
}

func NewAgentService() *AgentService {
	s := &AgentService{
		agents: make(map[string]*Agent),
	}
	s.seedAgents()
	return s
}

func (s *AgentService) seedAgents() {
	now := time.Now()
	s.agents["agent-prod-k8s-01"] = &Agent{
		ID: "agent-prod-k8s-01", Hostname: "k8s-node-sh-prod-01", Status: "online",
		CollectMode: "ebpf", Cluster: "shanghai-prod", QPS: 15230,
		LastHeartbeat: now.Add(-5 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", Arch: "amd64", CPUPercent: 12.3, MemoryMB: 512, DropRate: 0.001,
		KernelVersion: "5.15.0-91", Interface: "eth0", Namespace: "order-system",
		ServiceName: "order-api", CloudProvider: "aliyun", Region: "cn-shanghai",
	}
	s.agents["agent-prod-k8s-02"] = &Agent{
		ID: "agent-prod-k8s-02", Hostname: "k8s-node-sh-prod-02", Status: "online",
		CollectMode: "ebpf", Cluster: "shanghai-prod", QPS: 14800,
		LastHeartbeat: now.Add(-3 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", Arch: "amd64", CPUPercent: 15.1, MemoryMB: 498, DropRate: 0.002,
		KernelVersion: "5.15.0-91", Interface: "eth0", Namespace: "payment-system",
		ServiceName: "payment-api", CloudProvider: "aliyun", Region: "cn-shanghai",
	}
	s.agents["agent-prod-k8s-03"] = &Agent{
		ID: "agent-prod-k8s-03", Hostname: "k8s-node-sh-prod-03", Status: "online",
		CollectMode: "ebpf", Cluster: "shanghai-prod", QPS: 8900,
		LastHeartbeat: now.Add(-7 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", Arch: "amd64", CPUPercent: 8.7, MemoryMB: 380, DropRate: 0.000,
		KernelVersion: "5.15.0-91", Interface: "eth0", Namespace: "user-system",
		ServiceName: "user-api", CloudProvider: "aliyun", Region: "cn-shanghai",
	}
	s.agents["agent-staging-01"] = &Agent{
		ID: "agent-staging-01", Hostname: "k8s-node-stg-01", Status: "online",
		CollectMode: "ebpf", Cluster: "shanghai-staging", QPS: 3200,
		LastHeartbeat: now.Add(-12 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", Arch: "amd64", CPUPercent: 5.2, MemoryMB: 256, DropRate: 0.000,
		KernelVersion: "5.15.0-91", Interface: "eth0", Namespace: "default",
		ServiceName: "all-services", CloudProvider: "aliyun", Region: "cn-shanghai",
	}
	s.agents["agent-vm-dmz-01"] = &Agent{
		ID: "agent-vm-dmz-01", Hostname: "vm-dmz-01", Status: "online",
		CollectMode: "dpdk", Cluster: "beijing-prod", QPS: 28700,
		LastHeartbeat: now.Add(-4 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", Arch: "amd64", CPUPercent: 22.5, MemoryMB: 1024, DropRate: 0.003,
		KernelVersion: "4.18.0-348", Interface: "ens192", Namespace: "",
		ServiceName: "gateway", CloudProvider: "on_premise", Region: "cn-beijing",
	}
	s.agents["agent-vm-dmz-02"] = &Agent{
		ID: "agent-vm-dmz-02", Hostname: "vm-dmz-02", Status: "online",
		CollectMode: "dpdk", Cluster: "beijing-prod", QPS: 31200,
		LastHeartbeat: now.Add(-6 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", Arch: "amd64", CPUPercent: 25.8, MemoryMB: 1100, DropRate: 0.005,
		KernelVersion: "4.18.0-348", Interface: "ens192", Namespace: "",
		ServiceName: "gateway", CloudProvider: "on_premise", Region: "cn-beijing",
	}
	s.agents["agent-bj-backup"] = &Agent{
		ID: "agent-bj-backup", Hostname: "vm-backup-01", Status: "degraded",
		CollectMode: "gateway_log", Cluster: "beijing-backup", QPS: 22300,
		LastHeartbeat: now.Add(-45 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", Arch: "amd64", CPUPercent: 45.2, MemoryMB: 2048, DropRate: 0.05,
		KernelVersion: "4.18.0-348", Interface: "eth0", Namespace: "",
		ServiceName: "kong-gateway", CloudProvider: "on_premise", Region: "cn-beijing",
	}
	s.agents["agent-saas-tencent"] = &Agent{
		ID: "agent-saas-tencent", Hostname: "tencent-cvm-01", Status: "online",
		CollectMode: "ebpf", Cluster: "shenzhen-prod", QPS: 5600,
		LastHeartbeat: now.Add(-8 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", Arch: "arm64", CPUPercent: 7.3, MemoryMB: 320, DropRate: 0.001,
		KernelVersion: "5.4.0-169", Interface: "eth0", Namespace: "recommendation",
		ServiceName: "recommend-svc", CloudProvider: "tencent", Region: "cn-shenzhen",
	}
	s.agents["agent-offline-01"] = &Agent{
		ID: "agent-offline-01", Hostname: "vm-legacy-01", Status: "offline",
		CollectMode: "pcap", Cluster: "shanghai-legacy", QPS: 0,
		LastHeartbeat: now.Add(-2 * time.Hour), AgentVersion: "0.0.9",
		OS: "linux", Arch: "amd64", CPUPercent: 0, MemoryMB: 0, DropRate: 0,
		KernelVersion: "3.10.0-1160", Interface: "eth0", Namespace: "",
		ServiceName: "legacy-app", CloudProvider: "on_premise", Region: "cn-shanghai",
	}
}

func (s *AgentService) List() []Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Agent, 0, len(s.agents))
	for _, a := range s.agents {
		result = append(result, *a)
	}
	return result
}

func (s *AgentService) Get(id string) (*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent not found: %s", id)
	}
	return a, nil
}

func (s *AgentService) GetDetail(id string) (*AgentDetail, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent not found: %s", id)
	}
	return &AgentDetail{
		Agent:         *a,
		Metrics:       s.getAgentMetrics(id),
		Config:        s.getAgentConfig(id),
		RecentLogs:    s.getAgentLogs(id),
		CollectedAPIs: s.getCollectedAPIs(id),
	}, nil
}

func (s *AgentService) getAgentMetrics(id string) *AgentMetrics {
	metrics := map[string]*AgentMetrics{
		"agent-prod-k8s-01": {
			QPSHistory: []float64{14200, 14500, 14800, 15000, 15230, 15100, 14900, 15230},
			DropRateHistory: []float64{0.001, 0.001, 0.002, 0.001, 0.001, 0.001, 0.002, 0.001},
			CPUHistory: []float64{11.2, 12.0, 13.5, 12.8, 12.3, 11.9, 12.1, 12.3},
			MemoryHistory: []uint64{480, 490, 505, 510, 512, 508, 510, 512},
			KafkaLag: 0, BytesProcessed: 1847293447, PacketsProcessed: 892340123,
			UptimeSeconds: 86400 * 3,
		},
		"agent-bj-backup": {
			QPSHistory: []float64{21000, 21500, 22000, 22500, 22300, 23000, 23500, 22300},
			DropRateHistory: []float64{0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.05, 0.05},
			CPUHistory: []float64{25.0, 30.0, 35.0, 40.0, 45.2, 48.0, 46.0, 45.2},
			MemoryHistory: []uint64{1024, 1200, 1500, 1800, 2048, 2100, 2080, 2048},
			KafkaLag: 12500, BytesProcessed: 923847291, PacketsProcessed: 423456789,
			UptimeSeconds: 86400 * 7,
		},
	}
	if m, ok := metrics[id]; ok {
		return m
	}
	return &AgentMetrics{
		QPSHistory: []float64{0}, DropRateHistory: []float64{0},
		CPUHistory: []float64{0}, MemoryHistory: []uint64{0},
	}
}

func (s *AgentService) getAgentConfig(id string) *AgentConfig {
	configs := map[string]*AgentConfig{
		"agent-prod-k8s-01": {
			Mode: "ebpf", FilterPorts: []string{"80", "443", "8080", "8443"},
			CaptureHeaders: true, CaptureBody: true, MaxBodySizeKB: 64,
			KafkaBrokers: []string{"kafka-1:9092", "kafka-2:9092"},
			KafkaTopic: "raw-api-events",
		},
		"agent-bj-backup": {
			Mode: "gateway_log", FilterPorts: []string{},
			CaptureHeaders: true, CaptureBody: true, MaxBodySizeKB: 128,
			KafkaBrokers: []string{"kafka-1:9092"},
			KafkaTopic: "raw-api-events",
		},
	}
	if c, ok := configs[id]; ok {
		return c
	}
	return &AgentConfig{Mode: "auto"}
}

func (s *AgentService) getAgentLogs(id string) []LogEntry {
	now := time.Now()
	logs := map[string][]LogEntry{
		"agent-prod-k8s-01": {
			{Level: "info", Message: "Agent started successfully in ebpf mode", Timestamp: now.Add(-30 * time.Minute)},
			{Level: "info", Message: "Connected to Kafka cluster", Timestamp: now.Add(-30 * time.Minute)},
			{Level: "info", Message: "eBPF programs loaded: 3", Timestamp: now.Add(-29 * time.Minute)},
			{Level: "info", Message: "Path normalization model initialized", Timestamp: now.Add(-29 * time.Minute)},
			{Level: "debug", Message: "Processed 10000 events in last second", Timestamp: now.Add(-5 * time.Minute)},
		},
		"agent-bj-backup": {
			{Level: "info", Message: "Agent started in gateway_log mode", Timestamp: now.Add(-60 * time.Minute)},
			{Level: "warn", Message: "Kafka produce latency > 500ms", Timestamp: now.Add(-45 * time.Minute)},
			{Level: "warn", Message: "Drop rate exceeded 1%", Timestamp: now.Add(-40 * time.Minute)},
			{Level: "error", Message: "Kafka broker connection timeout, retrying...", Timestamp: now.Add(-35 * time.Minute)},
			{Level: "warn", Message: "Memory usage > 80%", Timestamp: now.Add(-20 * time.Minute)},
		},
	}
	if l, ok := logs[id]; ok {
		return l
	}
	return []LogEntry{}
}

func (s *AgentService) getCollectedAPIs(id string) int {
	counts := map[string]int{
		"agent-prod-k8s-01": 45,
		"agent-prod-k8s-02": 38,
		"agent-prod-k8s-03": 22,
		"agent-staging-01": 120,
		"agent-vm-dmz-01": 156,
		"agent-vm-dmz-02": 143,
		"agent-bj-backup": 89,
		"agent-saas-tencent": 67,
	}
	if c, ok := counts[id]; ok {
		return c
	}
	return 0
}

func (s *AgentService) Register(hostname, mode, cluster string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := fmt.Sprintf("agent-%s-%d", hostname, time.Now().Unix()%10000)
	s.agents[id] = &Agent{
		ID: id, Hostname: hostname, Status: "online",
		CollectMode: mode, Cluster: cluster,
		LastHeartbeat: time.Now(), AgentVersion: "0.1.0",
	}
	return id
}

func (s *AgentService) UpdateHeartbeat(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[id]; ok {
		a.LastHeartbeat = time.Now()
	}
}

func (s *AgentService) TotalCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.agents)
}

func (s *AgentService) OnlineCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, a := range s.agents {
		if a.Status == "online" {
			count++
		}
	}
	return count
}

func (s *AgentService) OfflineCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, a := range s.agents {
		if a.Status == "offline" {
			count++
		}
	}
	return count
}

func (s *AgentService) DegradedCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, a := range s.agents {
		if a.Status == "degraded" {
			count++
		}
	}
	return count
}
