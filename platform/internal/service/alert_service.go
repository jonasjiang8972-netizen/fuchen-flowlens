package service

import (
	"fmt"
	"sync"
	"time"
)

type Alert struct {
	ID                 string       `json:"alert_id"`
	Timestamp          time.Time    `json:"timestamp"`
	Severity           string       `json:"severity"`
	Title              string       `json:"title"`
	Description        string       `json:"description"`
	SourceRequirement  string       `json:"source_requirement"`
	RiskScore          int          `json:"risk_score"`
	Confidence         float64      `json:"confidence"`
	Status             string       `json:"status"`
	SourceIP           string       `json:"source_ip"`
	AccountID          string       `json:"account_id"`
	DeviceFingerprint  string       `json:"device_fingerprint"`
	AffectedAssetCount int          `json:"affected_asset_count"`
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

type AlertDetail struct {
	Alert
	RelatedAlerts []string        `json:"related_alerts"`
	Timeline      []TimelineEvent `json:"timeline"`
	RawData       map[string]string `json:"raw_data"`
}

type TimelineEvent struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`
	Detail string    `json:"detail"`
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
		Description: "账号 usr-88213 在过去 5 分钟内连续访问了 847 个不同订单 ID，遍历速率 12.4/s，远超历史基线（0.3/s）。该账号信誉分 0.62，近期有多次异常登录记录。",
		SourceRequirement: "FR-DET-001", RiskScore: 91, Confidence: 0.92,
		Status: "open", SourceIP: "203.0.113.18", AccountID: "usr-88213",
		DeviceFingerprint: "df-a92c1e",
		AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-35 * time.Minute), Action: "login", Detail: "正常登录，IP归属地: 上海", SourceIP: "10.0.1.15", Path: "/api/v1/auth/login", Status: 200},
			{Sequence: 2, Timestamp: now.Add(-30 * time.Minute), Action: "ip_change", Detail: "IP 切换至 203.0.113.18（代理/VPN）", SourceIP: "203.0.113.18", Path: "/api/v1/auth/refresh", Status: 200},
			{Sequence: 3, Timestamp: now.Add(-25 * time.Minute), Action: "normal_access", Detail: "正常访问 /api/v1/user/1001", SourceIP: "203.0.113.18", Path: "/api/v1/user/1001", Status: 200},
			{Sequence: 4, Timestamp: now.Add(-20 * time.Minute), Action: "traverse_start", Detail: "开始遍历订单 ID: 5001-5200", SourceIP: "203.0.113.18", Path: "/api/v1/order/{id}", Status: 200},
			{Sequence: 5, Timestamp: now.Add(-15 * time.Minute), Action: "traverse_continue", Detail: "遍历订单 ID: 5201-5500，速率 15/s", SourceIP: "203.0.113.18", Path: "/api/v1/order/{id}", Status: 200},
			{Sequence: 6, Timestamp: now.Add(-10 * time.Minute), Action: "traverse_continue", Detail: "遍历订单 ID: 5501-5800，命中 723 个有效订单", SourceIP: "203.0.113.18", Path: "/api/v1/order/{id}", Status: 200},
			{Sequence: 7, Timestamp: now.Add(-5 * time.Minute), Action: "traverse_active", Detail: "仍在持续遍历，已访问 847 个不同 ID", SourceIP: "203.0.113.18", Path: "/api/v1/order/{id}", Status: 200},
		},
	}

	s.alerts["alt-002"] = &Alert{
		ID: "alt-002", Timestamp: now.Add(-15 * time.Minute), Severity: "critical",
		Title: "撞库攻击：单 IP 尝试 68 个不同账号",
		Description: "IP 198.51.100.22 在过去 10 分钟内对登录接口发起 247 次失败尝试，涉及 68 个不同用户名。失败率 95.5%，匹配已知撞库特征。",
		SourceRequirement: "FR-DET-002", RiskScore: 96, Confidence: 0.97,
		Status: "acknowledged", SourceIP: "198.51.100.22",
		DeviceFingerprint: "df-b83d2f",
		AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-25 * time.Minute), Action: "recon", Detail: "探测登录接口", SourceIP: "198.51.100.22", Path: "/api/v1/auth/login", Status: 405},
			{Sequence: 2, Timestamp: now.Add(-20 * time.Minute), Action: "brute_force", Detail: "开始批量尝试，涉及 68 个账号", SourceIP: "198.51.100.22", Path: "/api/v1/auth/login", Status: 401},
			{Sequence: 3, Timestamp: now.Add(-15 * time.Minute), Action: "brute_force", Detail: "持续尝试中", SourceIP: "198.51.100.22", Path: "/api/v1/auth/login", Status: 401},
		},
	}

	s.alerts["alt-003"] = &Alert{
		ID: "alt-003", Timestamp: now.Add(-45 * time.Minute), Severity: "medium",
		Title: "影子 API 发现：/api/v1/legacy/export 未在 CMDB 注册",
		Description: "发现接口 /api/v1/legacy/export 有实际流量但未在官方 API 目录中注册。该接口返回大量敏感数据（姓名、身份证、手机号），存在数据泄露风险。",
		SourceRequirement: "FR-AST-002", RiskScore: 65, Confidence: 0.92,
		Status: "open", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-004"] = &Alert{
		ID: "alt-004", Timestamp: now.Add(-30 * time.Minute), Severity: "medium",
		Title: "异常资源消耗：订单接口 QPS 超基线 5 倍",
		Description: "接口 /api/v1/order/{id} 当前 QPS 达到 3800，超出历史基线（750 QPS）5 倍。来源 IP 203.0.113.18 贡献了 42% 的流量。",
		SourceRequirement: "FR-DET-004", RiskScore: 72, Confidence: 0.85,
		Status: "open", SourceIP: "203.0.113.18", AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-35 * time.Minute), Action: "normal", Detail: "正常流量基线: 750 QPS", SourceIP: "multiple", Path: "/api/v1/order/{id}", Status: 200},
			{Sequence: 2, Timestamp: now.Add(-30 * time.Minute), Action: "spike", Detail: "QPS 突增至 3800", SourceIP: "203.0.113.18", Path: "/api/v1/order/{id}", Status: 200},
		},
	}

	s.alerts["alt-005"] = &Alert{
		ID: "alt-005", Timestamp: now.Add(-2 * time.Hour), Severity: "high",
		Title: "数据泄露风险：用户接口响应体包含未脱敏身份证号",
		Description: "接口 /api/v1/user/{id} 响应体中发现未脱敏的身份证号字段（id_card_no），格式为 18 位数字，违反《个人信息保护法》第 51 条。",
		SourceRequirement: "FR-DLP-003", RiskScore: 82, Confidence: 0.95,
		Status: "acknowledged", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-006"] = &Alert{
		ID: "alt-006", Timestamp: now.Add(-20 * time.Minute), Severity: "critical",
		Title: "支付接口撞库：单设备尝试 120 张不同银行卡",
		Description: "设备指纹 df-c44e5a 在 30 分钟内通过 /api/v1/payment/checkout 尝试了 120 张不同银行卡的卡号，成功 3 次。",
		SourceRequirement: "FR-RISK-003", RiskScore: 94, Confidence: 0.93,
		Status: "open", SourceIP: "45.33.22.11",
		DeviceFingerprint: "df-c44e5a", AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-50 * time.Minute), Action: "card_testing", Detail: "开始批量测试银行卡", SourceIP: "45.33.22.11", Path: "/api/v1/payment/checkout", Status: 402},
			{Sequence: 2, Timestamp: now.Add(-35 * time.Minute), Action: "card_hit", Detail: "成功匹配 1 张有效卡", SourceIP: "45.33.22.11", Path: "/api/v1/payment/checkout", Status: 200},
			{Sequence: 3, Timestamp: now.Add(-20 * time.Minute), Action: "card_active", Detail: "已尝试 120 张卡", SourceIP: "45.33.22.11", Path: "/api/v1/payment/checkout", Status: 402},
		},
	}

	s.alerts["alt-007"] = &Alert{
		ID: "alt-007", Timestamp: now.Add(-1 * time.Hour), Severity: "medium",
		Title: "影子 API 告警：/api/v1/user/{id}/orders 未在 CMDB 注册",
		Description: "发现接口 /api/v1/user/{id}/orders 有实际流量但未在官方 API 目录中注册。该接口返回用户完整订单历史。",
		SourceRequirement: "FR-AST-002", RiskScore: 58, Confidence: 0.88,
		Status: "open", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-008"] = &Alert{
		ID: "alt-008", Timestamp: now.Add(-3 * time.Hour), Severity: "high",
		Title: "明文传输敏感数据：legacy/export 通过 HTTP 传输",
		Description: "接口 /api/v1/legacy/export 通过 HTTP（非 HTTPS）传输，响应体包含姓名、身份证、手机号等敏感信息。",
		SourceRequirement: "FR-DET-008", RiskScore: 78, Confidence: 0.96,
		Status: "open", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-009"] = &Alert{
		ID: "alt-009", Timestamp: now.Add(-4 * time.Hour), Severity: "low",
		Title: "僵尸 API：库存接口连续 7 天无访问",
		Description: "接口 /api/v1/inventory/{warehouse_id}/stock 最近 7 天无实际业务访问，但接口仍可响应。",
		SourceRequirement: "FR-AST-002", RiskScore: 25, Confidence: 0.90,
		Status: "open", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-010"] = &Alert{
		ID: "alt-010", Timestamp: now.Add(-6 * time.Hour), Severity: "medium",
		Title: "爬虫行为识别：商品推荐接口异常设备指纹",
		Description: "设备指纹 df-d55f6b 在 2 小时内访问推荐接口 18000 次，请求间隔高度规律（方差 < 0.01s）。",
		SourceRequirement: "FR-RISK-002", RiskScore: 68, Confidence: 0.91,
		Status: "acknowledged", DeviceFingerprint: "df-d55f6b",
		AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-8 * time.Hour), Action: "crawl_start", Detail: "开始规律性请求", SourceIP: "104.236.88.99", Path: "recommendation.ProductService/List", Status: 0},
			{Sequence: 2, Timestamp: now.Add(-6 * time.Hour), Action: "crawl_active", Detail: "已获取 18000 条结果", SourceIP: "104.236.88.99", Path: "recommendation.ProductService/List", Status: 0},
		},
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

func (s *AlertService) GetDetail(id string) (*AlertDetail, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, fmt.Errorf("alert not found: %s", id)
	}
	return &AlertDetail{
		Alert:         *a,
		RelatedAlerts: s.getRelatedAlerts(id),
		Timeline:      s.getTimeline(id),
		RawData:       s.getRawData(id),
	}, nil
}

func (s *AlertService) getRelatedAlerts(alertID string) []string {
	related := map[string][]string{
		"alt-001": {"alt-004", "alt-005"},
		"alt-002": {"alt-006"},
		"alt-003": {"alt-007", "alt-008"},
		"alt-004": {"alt-001"},
		"alt-005": {"alt-001"},
		"alt-006": {"alt-002"},
		"alt-007": {"alt-003"},
		"alt-008": {"alt-003"},
	}
	if r, ok := related[alertID]; ok {
		return r
	}
	return []string{}
}

func (s *AlertService) getTimeline(alertID string) []TimelineEvent {
	now := time.Now()
	timelines := map[string][]TimelineEvent{
		"alt-001": {
			{Time: now.Add(-60 * time.Minute), Event: "基线建立", Detail: "账号 usr-88213 行为基线建立完成"},
			{Time: now.Add(-35 * time.Minute), Event: "正常登录", Detail: "从常用 IP 10.0.1.15 登录"},
			{Time: now.Add(-30 * time.Minute), Event: "IP 切换", Detail: "IP 切换至代理地址 203.0.113.18"},
			{Time: now.Add(-25 * time.Minute), Event: "行为异常", Detail: "开始遍历不属于自己的订单 ID"},
			{Time: now.Add(-20 * time.Minute), Event: "告警触发", Detail: "BOLA 检测引擎触发告警"},
			{Time: now.Add(-5 * time.Minute), Event: "持续攻击", Detail: "遍历仍在继续，已访问 847 个 ID"},
		},
		"alt-002": {
			{Time: now.Add(-30 * time.Minute), Event: "探测", Detail: "攻击者探测登录接口"},
			{Time: now.Add(-25 * time.Minute), Event: "撞库开始", Detail: "开始批量尝试不同用户名"},
			{Time: now.Add(-15 * time.Minute), Event: "告警触发", Detail: "撞库检测引擎触发告警"},
			{Time: now.Add(-10 * time.Minute), Event: "人工确认", Detail: "安全运营人员确认攻击"},
		},
		"alt-006": {
			{Time: now.Add(-50 * time.Minute), Event: "卡片测试开始", Detail: "设备 df-c44e5a 开始测试银行卡"},
			{Time: now.Add(-35 * time.Minute), Event: "首次命中", Detail: "成功匹配 1 张有效卡"},
			{Time: now.Add(-20 * time.Minute), Event: "持续攻击", Detail: "已尝试 120 张卡，成功 3 次"},
		},
	}
	if t, ok := timelines[alertID]; ok {
		return t
	}
	return []TimelineEvent{}
}

func (s *AlertService) getRawData(alertID string) map[string]string {
	return map[string]string{
		"user_agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"ja3_fingerprint": "e7d705a3286e19ea42f587b344ee6865",
		"request_count":   "847",
		"unique_ids":      "847",
		"success_rate":    "84.3%",
		"duration":        "25 minutes",
	}
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
