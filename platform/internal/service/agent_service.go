package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type Agent struct {
	ID            string    `json:"agent_id"`
	Hostname      string    `json:"hostname"`
	Status        string    `json:"status"`
	CollectMode   string    `json:"collect_mode"`
	Cluster       string    `json:"cluster"`
	QPS           float64   `json:"qps"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	AgentVersion  string    `json:"agent_version"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryMB      uint64    `json:"memory_mb_used"`
	DropRate      float64   `json:"drop_rate"`
	KernelVersion string    `json:"kernel_version"`
	Interface     string    `json:"interface"`
	Namespace     string    `json:"namespace"`
	ServiceName   string    `json:"service_name"`
	CloudProvider string    `json:"cloud_provider"`
	Region        string    `json:"region"`
	// RegisteredAt is when the collector last registered (its start-up).
	RegisteredAt time.Time    `json:"registered_at,omitempty"`
	Config       *AgentConfig `json:"config,omitempty"`
}

type AgentDetail struct {
	Agent
	Metrics       *AgentMetrics `json:"metrics"`
	Config        *AgentConfig  `json:"config"`
	RecentLogs    []LogEntry    `json:"recent_logs"`
	CollectedAPIs int           `json:"collected_apis"`
}

// AgentMetrics are the collector's recent heartbeat samples, oldest first.
type AgentMetrics struct {
	SampleTimes     []time.Time `json:"sample_times"`
	QPSHistory      []float64   `json:"qps_history"`
	DropRateHistory []float64   `json:"drop_rate_history"`
	CPUHistory      []float64   `json:"cpu_history"`
	MemoryHistory   []uint64    `json:"memory_history"`
	UptimeSeconds   int64       `json:"uptime_seconds"`
}

// AgentConfig is the collection configuration a collector reported at
// registration.
type AgentConfig struct {
	Mode             string   `json:"mode"`
	FilterPorts      []string `json:"filter_ports,omitempty"`
	CaptureHeaders   bool     `json:"capture_headers"`
	CaptureBody      bool     `json:"capture_body"`
	MaxBodySizeKB    int      `json:"max_body_size_kb"`
	GatewayLogPath   string   `json:"gateway_log_path,omitempty"`
	GatewayLogFormat string   `json:"gateway_log_format,omitempty"`
}

// Registration is what a collector reports when it starts.
type Registration struct {
	ID, Hostname, CollectMode, Cluster, Version, OS, Arch string
	Config                                                *AgentConfig
}

// HeartbeatReport is what a collector reports with each heartbeat.
type HeartbeatReport struct {
	Status      string
	QPS         float64
	CPUPercent  float64
	MemoryMB    uint64
	DropRate    float64
	CollectMode string
}

type heartbeatSample struct {
	At       time.Time
	QPS      float64
	CPU      float64
	MemoryMB uint64
	DropRate float64
}

// Bounds of the per-collector in-memory history.
const (
	maxHeartbeatSamples = 60
	maxAgentLogs        = 50
	maxAgentEndpoints   = 50000
)

type LogEntry struct {
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type AgentService struct {
	mu     sync.RWMutex
	agents map[string]*Agent
	p      *persister
	now    func() time.Time

	// Recent heartbeats, observed events and endpoints per collector. Kept
	// in memory only: they describe the running collector, not records.
	samples   map[string][]heartbeatSample
	logs      map[string][]LogEntry
	endpoints map[string]map[string]struct{}
}

// Heartbeat age thresholds for the collector status shown to operators.
const (
	agentOnlineWithin   = 60 * time.Second
	agentDegradedWithin = 5 * time.Minute
)

// effective returns a copy of a with Status derived from heartbeat age: a
// collector that stops reporting turns degraded, then offline, instead of
// staying "online" forever.
func (s *AgentService) effective(a *Agent) Agent {
	c := *a
	age := s.now().Sub(a.LastHeartbeat)
	switch {
	case age > agentDegradedWithin:
		c.Status = "offline"
	case age > agentOnlineWithin:
		c.Status = "degraded"
	case a.Status == "degraded":
		// reported degraded by the collector itself
	default:
		c.Status = "online"
	}
	return c
}

func newAgentService(p *persister) *AgentService {
	return &AgentService{
		agents:    make(map[string]*Agent),
		p:         p,
		now:       time.Now,
		samples:   make(map[string][]heartbeatSample),
		logs:      make(map[string][]LogEntry),
		endpoints: make(map[string]map[string]struct{}),
	}
}

func NewAgentService() *AgentService {
	s := newAgentService(nil)
	s.seedAgents()
	return s
}

// NewAgentServiceFrom loads collectors from repo. Sample collectors are
// added only when seedDemo is set and the repository is empty.
func NewAgentServiceFrom(ctx context.Context, repo Repository, seedDemo bool) (*AgentService, error) {
	s := newAgentService(newPersister(repo, KindAgent))
	docs, err := repo.LoadDocuments(ctx, KindAgent)
	if err != nil {
		return nil, fmt.Errorf("load agents: %w", err)
	}
	for id, raw := range docs {
		var a Agent
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("decode agent %s: %w", id, err)
		}
		s.agents[id] = &a
	}
	if len(s.agents) == 0 && seedDemo {
		s.seedAgents()
		ids := make([]string, 0, len(s.agents))
		for id := range s.agents {
			ids = append(ids, id)
		}
		if err := s.p.writeThrough(ctx, ids, s.snapshot); err != nil {
			return nil, fmt.Errorf("save sample agents: %w", err)
		}
	}
	return s, nil
}

func (s *AgentService) snapshot(ids []string) map[string][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	docs := make(map[string][]byte, len(ids))
	for _, id := range ids {
		if a, ok := s.agents[id]; ok {
			docs[id] = mustJSON(a)
		}
	}
	return docs
}

// Flush persists heartbeat updates since the last flush.
func (s *AgentService) Flush(ctx context.Context) (int, error) {
	return s.p.flush(ctx, s.snapshot)
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
		result = append(result, s.effective(a))
	}
	return result
}

func (s *AgentService) Get(id string) (*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent %s: %w", id, ErrNotFound)
	}
	c := s.effective(a)
	return &c, nil
}

func (s *AgentService) GetDetail(id string) (*AgentDetail, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent %s: %w", id, ErrNotFound)
	}
	m := &AgentMetrics{
		SampleTimes: []time.Time{}, QPSHistory: []float64{}, DropRateHistory: []float64{},
		CPUHistory: []float64{}, MemoryHistory: []uint64{},
	}
	for _, smp := range s.samples[id] {
		m.SampleTimes = append(m.SampleTimes, smp.At)
		m.QPSHistory = append(m.QPSHistory, smp.QPS)
		m.DropRateHistory = append(m.DropRateHistory, smp.DropRate)
		m.CPUHistory = append(m.CPUHistory, smp.CPU)
		m.MemoryHistory = append(m.MemoryHistory, smp.MemoryMB)
	}
	if !a.RegisteredAt.IsZero() {
		m.UptimeSeconds = int64(s.now().Sub(a.RegisteredAt).Seconds())
	}
	cfg := a.Config
	if cfg == nil {
		cfg = &AgentConfig{Mode: a.CollectMode}
	}
	logs := make([]LogEntry, len(s.logs[id]))
	for i, l := range s.logs[id] { // newest first
		logs[len(logs)-1-i] = l
	}
	return &AgentDetail{
		Agent:         s.effective(a),
		Metrics:       m,
		Config:        cfg,
		RecentLogs:    logs,
		CollectedAPIs: len(s.endpoints[id]),
	}, nil
}

// logLocked records an event the platform observed about collector id.
func (s *AgentService) logLocked(id, level, msg string) {
	l := append(s.logs[id], LogEntry{Level: level, Message: msg, Timestamp: s.now()})
	if len(l) > maxAgentLogs {
		l = append([]LogEntry(nil), l[len(l)-maxAgentLogs:]...)
	}
	s.logs[id] = l
}

func (s *AgentService) Register(hostname, mode, cluster string) (string, error) {
	return s.RegisterWithID("", hostname, mode, cluster, "", "")
}

// RegisterWithID registers a collector from its basic identification.
func (s *AgentService) RegisterWithID(preferredID, hostname, mode, cluster, agentVersion, osName string) (string, error) {
	return s.RegisterAgent(Registration{ID: preferredID, Hostname: hostname, CollectMode: mode,
		Cluster: cluster, Version: agentVersion, OS: osName})
}

// RegisterAgent registers (or re-registers, after a collector restart) a
// collector and saves it; if saving fails the previous state is restored
// and the error returned.
func (s *AgentService) RegisterAgent(reg Registration) (string, error) {
	s.mu.Lock()
	id := fmt.Sprintf("agent-%s-%d", reg.Hostname, time.Now().Unix()%10000)
	if reg.ID != "" {
		id = reg.ID
	}
	now := s.now()
	prev, existed := s.agents[id]
	s.agents[id] = &Agent{
		ID: id, Hostname: reg.Hostname, Status: "online",
		CollectMode: reg.CollectMode, Cluster: reg.Cluster,
		LastHeartbeat: now, AgentVersion: reg.Version, OS: reg.OS, Arch: reg.Arch,
		RegisteredAt: now, Config: reg.Config,
	}
	s.mu.Unlock()

	if err := s.p.writeThrough(context.Background(), []string{id}, s.snapshot); err != nil {
		s.mu.Lock()
		if existed {
			s.agents[id] = prev
		} else {
			delete(s.agents, id)
		}
		s.mu.Unlock()
		return "", fmt.Errorf("save agent %s: %w", id, err)
	}

	s.mu.Lock()
	delete(s.samples, id)
	verb := "采集器注册"
	if existed {
		verb = "采集器重新注册（采集器重启或平台数据重置）"
	}
	s.logLocked(id, "info", fmt.Sprintf("%s：主机 %s，模式 %s，版本 %s", verb, reg.Hostname, reg.CollectMode, reg.Version))
	s.mu.Unlock()
	return id, nil
}

// Heartbeat records a collector's heartbeat and the metrics it reports. It
// returns ErrNotFound for an unknown collector, which should then register
// again.
func (s *AgentService) Heartbeat(id string, r HeartbeatReport) error {
	s.mu.Lock()
	a, ok := s.agents[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("agent %s: %w", id, ErrNotFound)
	}
	now := s.now()
	before := s.effective(a)
	wasDegraded := a.Status == "degraded"

	a.LastHeartbeat = now
	a.QPS, a.CPUPercent, a.MemoryMB, a.DropRate = r.QPS, r.CPUPercent, r.MemoryMB, r.DropRate
	if r.CollectMode != "" {
		a.CollectMode = r.CollectMode
	}
	a.Status = "online"
	if r.Status == "degraded" {
		a.Status = "degraded"
	}

	smp := append(s.samples[id], heartbeatSample{At: now, QPS: r.QPS, CPU: r.CPUPercent, MemoryMB: r.MemoryMB, DropRate: r.DropRate})
	if len(smp) > maxHeartbeatSamples {
		smp = append([]heartbeatSample(nil), smp[len(smp)-maxHeartbeatSamples:]...)
	}
	s.samples[id] = smp

	switch {
	case before.Status == "offline":
		s.logLocked(id, "info", fmt.Sprintf("离线 %s 后恢复心跳", now.Sub(before.LastHeartbeat).Round(time.Second)))
	case !wasDegraded && a.Status == "degraded":
		s.logLocked(id, "warn", fmt.Sprintf("采集器报告异常：丢弃率 %.2f%%", r.DropRate*100))
	case wasDegraded && a.Status == "online":
		s.logLocked(id, "info", fmt.Sprintf("采集器恢复正常：丢弃率 %.2f%%", r.DropRate*100))
	}
	s.mu.Unlock()
	s.p.markDirty(id)
	return nil
}

// UpdateHeartbeat marks a collector alive (traffic from it arrived) without
// changing the status it reported.
func (s *AgentService) UpdateHeartbeat(id string) {
	s.mu.Lock()
	a, ok := s.agents[id]
	if ok {
		a.LastHeartbeat = s.now()
	}
	s.mu.Unlock()
	if ok {
		s.p.markDirty(id)
	}
}

// SeenTraffic records that collector id delivered traffic for endpoint:
// the collector is alive, and the endpoint counts toward its collected
// APIs. Unknown collectors are ignored.
func (s *AgentService) SeenTraffic(id, endpoint string) {
	s.mu.Lock()
	a, ok := s.agents[id]
	if ok {
		a.LastHeartbeat = s.now()
		if endpoint != "" {
			set := s.endpoints[id]
			if set == nil {
				set = make(map[string]struct{})
				s.endpoints[id] = set
			}
			if len(set) < maxAgentEndpoints {
				set[endpoint] = struct{}{}
			}
		}
	}
	s.mu.Unlock()
	if ok {
		s.p.markDirty(id)
	}
}

func (s *AgentService) countStatus(status string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, a := range s.agents {
		if s.effective(a).Status == status {
			n++
		}
	}
	return n
}

func (s *AgentService) TotalCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.agents)
}

func (s *AgentService) OnlineCount() int   { return s.countStatus("online") }
func (s *AgentService) OfflineCount() int  { return s.countStatus("offline") }
func (s *AgentService) DegradedCount() int { return s.countStatus("degraded") }
