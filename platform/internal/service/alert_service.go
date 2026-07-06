package service

import (
	"fmt"
	"sync"
	"time"
)

type Alert struct {
	ID                 string      `json:"alert_id"`
	Timestamp          time.Time   `json:"timestamp"`
	Severity           string      `json:"severity"`
	Title              string      `json:"title"`
	Description        string      `json:"description"`
	SourceRequirement  string      `json:"source_requirement"`
	RiskScore          int         `json:"risk_score"`
	Confidence         float64     `json:"confidence"`
	Status             string      `json:"status"`
	SourceIP           string      `json:"source_ip"`
	AccountID          string      `json:"account_id"`
	DeviceFingerprint  string      `json:"device_fingerprint"`
	AffectedAssetCount int         `json:"affected_asset_count"`
	AttackPath         []AttackStep `json:"attack_path"`
	Disposal           *DisposalInfo `json:"disposal,omitempty"`
}

type AttackStep struct {
	Sequence  int       `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
	SourceIP  string    `json:"source_ip"`
	Path      string    `json:"path"`
	Status    int       `json:"status_code"`
}

type DisposalInfo struct {
	Action     string    `json:"action"`
	Status     string    `json:"status"`
	ExecutedAt time.Time `json:"executed_at"`
}

type AlertService struct {
	mu     sync.RWMutex
	alerts map[string]*Alert
}

func NewAlertService() *AlertService {
	s := &AlertService{
		alerts: make(map[string]*Alert),
	}
	s.seedAlerts()
	return s
}

func (s *AlertService) seedAlerts() {
	now := time.Now()
	s.alerts["alt-001"] = &Alert{
		ID: "alt-001", Timestamp: now.Add(-5 * time.Minute), Severity: "high",
		Title: "疑似 BOLA 攻击：账号 usr-88213 高频遍历订单对象",
		Description: "账号 usr-88213 在过去 5 分钟内连续访问了 847 个不同订单 ID，遍历速率 12.4/s，远超历史基线。",
		SourceRequirement: "FR-DET-001", RiskScore: 91, Confidence: 0.92,
		Status: "open", SourceIP: "203.0.113.18", AccountID: "usr-88213",
		AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-5 * time.Minute), Action: "login", Detail: "正常登录", SourceIP: "203.0.113.18", Path: "/api/v1/auth/login", Status: 200},
			{Sequence: 2, Timestamp: now.Add(-4 * time.Minute), Action: "traverse", Detail: "开始遍历订单 ID", SourceIP: "203.0.113.18", Path: "/api/v1/order/{id}", Status: 200},
			{Sequence: 3, Timestamp: now.Add(-1 * time.Minute), Action: "traverse", Detail: "持续遍历中，已访问 847 个 ID", SourceIP: "203.0.113.18", Path: "/api/v1/order/{id}", Status: 200},
		},
	}
	s.alerts["alt-002"] = &Alert{
		ID: "alt-002", Timestamp: now.Add(-15 * time.Minute), Severity: "critical",
		Title: "撞库攻击：单 IP 尝试 68 个不同账号",
		Description: "IP 198.51.100.22 在过去 10 分钟内对登录接口发起 247 次失败尝试，涉及 68 个不同用户名。",
		SourceRequirement: "FR-DET-002", RiskScore: 88, Confidence: 0.95,
		Status: "acknowledged", SourceIP: "198.51.100.22",
		AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-15 * time.Minute), Action: "brute_force", Detail: "高频登录失败", SourceIP: "198.51.100.22", Path: "/api/v1/auth/login", Status: 401},
		},
	}
	s.alerts["alt-003"] = &Alert{
		ID: "alt-003", Timestamp: now.Add(-2 * time.Hour), Severity: "medium",
		Title: "影子 API 发现：/api/v1/legacy/export 未在 CMDB 注册",
		Description: "发现接口 /api/v1/legacy/export 有实际流量但未在官方 API 目录中注册，疑似遗留接口。",
		SourceRequirement: "FR-AST-002", RiskScore: 55, Confidence: 0.88,
		Status: "open",
		AffectedAssetCount: 1,
	}
}

func (s *AlertService) List() []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		result = append(result, *a)
	}
	return result
}

func (s *AlertService) Get(id string) (*Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, fmt.Errorf("alert not found: %s", id)
	}
	return a, nil
}

func (s *AlertService) ExecuteAction(alertID, action, target string, durationMin int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[alertID]
	if !ok {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	a.Status = "in_progress"
	a.Disposal = &DisposalInfo{
		Action:     action,
		Status:     "success",
		ExecutedAt: time.Now(),
	}
	return nil
}
