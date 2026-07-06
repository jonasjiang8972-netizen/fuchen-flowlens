package service

import (
	"fmt"
	"sync"
	"time"
)

// Agent model
type Agent struct {
	ID              string    `json:"agent_id"`
	Hostname        string    `json:"hostname"`
	Status          string    `json:"status"`
	CollectMode     string    `json:"collect_mode"`
	Cluster         string    `json:"cluster"`
	QPS             float64   `json:"qps"`
	LastHeartbeat   time.Time `json:"last_heartbeat"`
	AgentVersion    string    `json:"agent_version"`
	OS              string    `json:"os"`
	CPUPercent      float64   `json:"cpu_percent"`
	MemoryMB        uint64    `json:"memory_mb_used"`
	DropRate        float64   `json:"drop_rate"`
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
		ID: "agent-prod-k8s-01", Hostname: "k8s-node-01", Status: "online",
		CollectMode: "ebpf", Cluster: "shanghai-1", QPS: 15230,
		LastHeartbeat: now.Add(-5 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", CPUPercent: 12.3, MemoryMB: 512, DropRate: 0.001,
	}
	s.agents["agent-prod-k8s-02"] = &Agent{
		ID: "agent-prod-k8s-02", Hostname: "k8s-node-02", Status: "online",
		CollectMode: "ebpf", Cluster: "shanghai-1", QPS: 14800,
		LastHeartbeat: now.Add(-3 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", CPUPercent: 15.1, MemoryMB: 498, DropRate: 0.002,
	}
	s.agents["agent-bj-backup"] = &Agent{
		ID: "agent-bj-backup", Hostname: "vm-backup-01", Status: "degraded",
		CollectMode: "gateway_log", Cluster: "beijing-1", QPS: 22300,
		LastHeartbeat: now.Add(-45 * time.Second), AgentVersion: "0.1.0",
		OS: "linux", CPUPercent: 45.2, MemoryMB: 2048, DropRate: 0.05,
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
