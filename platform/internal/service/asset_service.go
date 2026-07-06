package service

import (
	"fmt"
	"sync"
	"time"
)

type Asset struct {
	ID                      string         `json:"asset_id"`
	PathNormalized          string         `json:"path_normalized"`
	PathRawSamples          []string       `json:"path_raw_samples"`
	Method                  string         `json:"method"`
	ProtocolType            string         `json:"protocol_type"`
	Host                    string         `json:"host"`
	FirstSeen               time.Time      `json:"first_seen"`
	LastSeen                time.Time      `json:"last_seen"`
	DailyAvgCalls           int            `json:"daily_avg_calls"`
	SensitivityHint         string         `json:"sensitivity_hint"`
	ClaimStatus             string         `json:"claim_status"`
	Owner                   string         `json:"owner"`
	GroupPath               string         `json:"group_path"`
	NormalizationConfidence float64        `json:"normalization_confidence"`
	Status                  string         `json:"status"`
	SourceDistribution      map[string]string `json:"source_distribution"`
	SensitiveFields         []string       `json:"sensitive_fields"`
	RequestStats            *RequestStats   `json:"request_stats,omitempty"`
}

type RequestStats struct {
	TotalCalls24h    int                `json:"total_calls_24h"`
	UniqueCallers24h int                `json:"unique_callers_24h"`
	ErrorRate24h     float64            `json:"error_rate_24h"`
	AvgLatencyMs     float64            `json:"avg_latency_ms"`
	P95LatencyMs     float64            `json:"p95_latency_ms"`
	StatusCodeDist   map[string]int     `json:"status_code_distribution"`
	HourlyCalls      []int              `json:"hourly_calls"`
	TopCallers       []CallerInfo       `json:"top_callers"`
}

type CallerInfo struct {
	IP        string  `json:"ip"`
	Calls     int     `json:"calls"`
	ErrorRate float64 `json:"error_rate"`
}

type AssetDetail struct {
	Asset
	Alerts         []AlertSummary `json:"alerts"`
	ChangeHistory  []ChangeRecord `json:"change_history"`
	RelatedAssets  []string       `json:"related_assets"`
}

type AlertSummary struct {
	ID        string    `json:"alert_id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

type ChangeRecord struct {
	ChangeType string    `json:"change_type"`
	Before     string    `json:"before"`
	After      string    `json:"after"`
	Severity   string    `json:"severity"`
	DetectedAt time.Time `json:"detected_at"`
}

type AssetService struct {
	mu     sync.RWMutex
	assets map[string]*Asset
}

func NewAssetService() *AssetService {
	s := &AssetService{
		assets: make(map[string]*Asset),
	}
	s.seedAssets()
	return s
}

func (s *AssetService) seedAssets() {
	now := time.Now()

	s.assets["ast-001"] = &Asset{
		ID: "ast-001", PathNormalized: "/api/v1/user/{id}",
		PathRawSamples: []string{"/api/v1/user/1001", "/api/v1/user/1002", "/api/v1/user/1003"},
		Method: "GET", ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-45 * 24 * time.Hour), LastSeen: now.Add(-30 * time.Second),
		DailyAvgCalls: 45230, SensitivityHint: "medium",
		ClaimStatus: "claimed", Owner: "zhang.wei@company.com",
		GroupPath: "零售事业部/交易系统/用户模块",
		NormalizationConfidence: 0.94, Status: "active",
		SourceDistribution: map[string]string{"internal": "42%", "external": "58%"},
		SensitiveFields: []string{"phone", "email", "id_card_no"},
		RequestStats: &RequestStats{
			TotalCalls24h: 45230, UniqueCallers24h: 1280,
			ErrorRate24h: 0.3, AvgLatencyMs: 23.5, P95LatencyMs: 89.2,
			StatusCodeDist: map[string]int{"200": 45094, "401": 89, "404": 47},
			HourlyCalls: []int{820, 650, 430, 310, 280, 350, 890, 2100, 3800, 4200, 3900, 3600, 3400, 3200, 3100, 3300, 3500, 3800, 3200, 2800, 2400, 2100, 1800, 1200},
			TopCallers: []CallerInfo{
				{IP: "10.0.1.15", Calls: 8920, ErrorRate: 0.1},
				{IP: "10.0.2.30", Calls: 5430, ErrorRate: 0.0},
				{IP: "10.0.3.22", Calls: 3210, ErrorRate: 0.5},
			},
		},
	}

	s.assets["ast-002"] = &Asset{
		ID: "ast-002", PathNormalized: "/api/v1/order/{id}",
		PathRawSamples: []string{"/api/v1/order/5001", "/api/v1/order/5002"},
		Method: "GET", ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-40 * 24 * time.Hour), LastSeen: now.Add(-10 * time.Second),
		DailyAvgCalls: 28720, SensitivityHint: "high",
		ClaimStatus: "claimed", Owner: "li.ming@company.com",
		GroupPath: "零售事业部/交易系统/订单模块",
		NormalizationConfidence: 0.91, Status: "active",
		SourceDistribution: map[string]string{"internal": "35%", "external": "65%"},
		SensitiveFields: []string{"order_amount", "recipient_phone", "shipping_address"},
		RequestStats: &RequestStats{
			TotalCalls24h: 28720, UniqueCallers24h: 890,
			ErrorRate24h: 0.8, AvgLatencyMs: 45.2, P95LatencyMs: 156.8,
			StatusCodeDist: map[string]int{"200": 28490, "401": 180, "403": 30, "404": 20},
			HourlyCalls: []int{420, 310, 200, 150, 130, 180, 520, 1800, 2900, 3100, 2800, 2600, 2400, 2200, 2100, 2200, 2300, 2100, 1800, 1500, 1200, 1000, 700},
			TopCallers: []CallerInfo{
				{IP: "10.0.1.15", Calls: 5230, ErrorRate: 0.2},
				{IP: "203.0.113.18", Calls: 4840, ErrorRate: 12.4},
				{IP: "10.0.4.55", Calls: 3100, ErrorRate: 0.1},
			},
		},
	}

	s.assets["ast-003"] = &Asset{
		ID: "ast-003", PathNormalized: "/api/v1/payment/checkout",
		PathRawSamples: []string{"/api/v1/payment/checkout"},
		Method: "POST", ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-35 * 24 * time.Hour), LastSeen: now.Add(-1 * time.Minute),
		DailyAvgCalls: 8500, SensitivityHint: "high",
		ClaimStatus: "unclaimed", Owner: "",
		GroupPath: "零售事业部/交易系统/支付模块",
		NormalizationConfidence: 0.99, Status: "active",
		SourceDistribution: map[string]string{"internal": "10%", "external": "90%"},
		SensitiveFields: []string{"card_number", "cvv", "expiry", "amount", "payer_name"},
		RequestStats: &RequestStats{
			TotalCalls24h: 8500, UniqueCallers24h: 3200,
			ErrorRate24h: 2.1, AvgLatencyMs: 180.5, P95LatencyMs: 450.0,
			StatusCodeDist: map[string]int{"200": 8321, "400": 120, "402": 45, "500": 14},
			HourlyCalls: []int{120, 80, 50, 30, 20, 40, 150, 480, 720, 680, 620, 580, 560, 540, 550, 600, 650, 580, 520, 450, 380, 300, 220},
			TopCallers: []CallerInfo{
				{IP: "10.0.5.10", Calls: 2100, ErrorRate: 0.5},
				{IP: "10.0.5.11", Calls: 1800, ErrorRate: 0.3},
			},
		},
	}

	s.assets["ast-004"] = &Asset{
		ID: "ast-004", PathNormalized: "/api/v1/user/{id}/orders",
		PathRawSamples: []string{"/api/v1/user/1001/orders", "/api/v1/user/1002/orders"},
		Method: "GET", ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-30 * 24 * time.Hour), LastSeen: now.Add(-5 * time.Minute),
		DailyAvgCalls: 18900, SensitivityHint: "high",
		ClaimStatus: "claimed", Owner: "wang.fang@company.com",
		GroupPath: "零售事业部/交易系统/用户模块",
		NormalizationConfidence: 0.89, Status: "shadow",
		SourceDistribution: map[string]string{"internal": "60%", "external": "40%"},
		SensitiveFields: []string{"order_history", "total_spent"},
		RequestStats: &RequestStats{
			TotalCalls24h: 18900, UniqueCallers24h: 3400,
			ErrorRate24h: 1.2, AvgLatencyMs: 67.8, P95LatencyMs: 210.5,
			StatusCodeDist: map[string]int{"200": 18673, "401": 150, "404": 77},
			HourlyCalls: []int{280, 200, 130, 90, 80, 110, 350, 1200, 2100, 2000, 1800, 1700, 1600, 1500, 1550, 1650, 1750, 1500, 1300, 1100, 900, 700, 450},
			TopCallers: []CallerInfo{
				{IP: "10.0.1.15", Calls: 3200, ErrorRate: 0.1},
				{IP: "10.0.2.30", Calls: 2800, ErrorRate: 0.3},
			},
		},
	}

	s.assets["ast-005"] = &Asset{
		ID: "ast-005", PathNormalized: "/api/v1/admin/users",
		PathRawSamples: []string{"/api/v1/admin/users"},
		Method: "GET", ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-60 * 24 * time.Hour), LastSeen: now.Add(-3 * time.Hour),
		DailyAvgCalls: 450, SensitivityHint: "high",
		ClaimStatus: "claimed", Owner: "admin@company.com",
		GroupPath: "零售事业部/管理系统/用户管理",
		NormalizationConfidence: 1.0, Status: "active",
		SourceDistribution: map[string]string{"internal": "100%", "external": "0%"},
		SensitiveFields: []string{"role", "permissions", "department", "salary"},
		RequestStats: &RequestStats{
			TotalCalls24h: 450, UniqueCallers24h: 12,
			ErrorRate24h: 0.0, AvgLatencyMs: 15.2, P95LatencyMs: 45.0,
			StatusCodeDist: map[string]int{"200": 450},
			HourlyCalls: []int{5, 3, 2, 1, 0, 2, 8, 45, 62, 58, 52, 48, 46, 44, 42, 44, 48, 42, 35, 28, 22, 18, 12, 8},
			TopCallers: []CallerInfo{
				{IP: "10.0.0.5", Calls: 180, ErrorRate: 0.0},
				{IP: "10.0.0.6", Calls: 150, ErrorRate: 0.0},
			},
		},
	}

	s.assets["ast-006"] = &Asset{
		ID: "ast-006", PathNormalized: "/graphql",
		PathRawSamples: []string{"/graphql"},
		Method: "POST", ProtocolType: "GraphQL", Host: "api.example.com",
		FirstSeen: now.Add(-20 * 24 * time.Hour), LastSeen: now.Add(-20 * time.Second),
		DailyAvgCalls: 12400, SensitivityHint: "medium",
		ClaimStatus: "claimed", Owner: "chen.hao@company.com",
		GroupPath: "零售事业部/移动端/GraphQL",
		NormalizationConfidence: 1.0, Status: "active",
		SourceDistribution: map[string]string{"internal": "20%", "external": "80%"},
		SensitiveFields: []string{"user_profile", "favorite_items"},
		RequestStats: &RequestStats{
			TotalCalls24h: 12400, UniqueCallers24h: 5600,
			ErrorRate24h: 0.5, AvgLatencyMs: 35.0, P95LatencyMs: 120.0,
			StatusCodeDist: map[string]int{"200": 12338, "400": 62},
			HourlyCalls: []int{200, 150, 100, 70, 60, 90, 280, 850, 1200, 1100, 1000, 950, 900, 880, 920, 980, 1050, 950, 820, 700, 580, 450, 300},
			TopCallers: []CallerInfo{
				{IP: "10.0.6.10", Calls: 3200, ErrorRate: 0.2},
				{IP: "10.0.6.11", Calls: 2800, ErrorRate: 0.1},
			},
		},
	}

	s.assets["ast-007"] = &Asset{
		ID: "ast-007", PathNormalized: "/api/v1/inventory/{warehouse_id}/stock",
		PathRawSamples: []string{"/api/v1/inventory/wh01/stock", "/api/v1/inventory/wh02/stock"},
		Method: "GET", ProtocolType: "REST", Host: "api.example.com",
		FirstSeen: now.Add(-15 * 24 * time.Hour), LastSeen: now.Add(-2 * time.Hour),
		DailyAvgCalls: 2100, SensitivityHint: "low",
		ClaimStatus: "claimed", Owner: "liu.qiang@company.com",
		GroupPath: "供应链/仓储管理/库存模块",
		NormalizationConfidence: 0.88, Status: "zombie",
		SourceDistribution: map[string]string{"internal": "95%", "external": "5%"},
		SensitiveFields: []string{},
		RequestStats: &RequestStats{
			TotalCalls24h: 2100, UniqueCallers24h: 5,
			ErrorRate24h: 45.0, AvgLatencyMs: 890.0, P95LatencyMs: 3000.0,
			StatusCodeDist: map[string]int{"200": 1155, "500": 890, "502": 55},
			HourlyCalls: []int{90, 85, 80, 75, 70, 80, 100, 120, 130, 125, 120, 115, 110, 108, 105, 110, 115, 110, 105, 100, 95, 92, 88},
			TopCallers: []CallerInfo{
				{IP: "10.0.7.1", Calls: 2100, ErrorRate: 45.0},
			},
		},
	}

	s.assets["ast-008"] = &Asset{
		ID: "ast-008", PathNormalized: "/api/v1/legacy/export",
		PathRawSamples: []string{"/api/v1/legacy/export"},
		Method: "GET", ProtocolType: "REST", Host: "internal.example.com",
		FirstSeen: now.Add(-180 * 24 * time.Hour), LastSeen: now.Add(-45 * time.Minute),
		DailyAvgCalls: 120, SensitivityHint: "high",
		ClaimStatus: "unclaimed", Owner: "",
		GroupPath: "未分组",
		NormalizationConfidence: 1.0, Status: "shadow",
		SourceDistribution: map[string]string{"internal": "100%"},
		SensitiveFields: []string{"full_name", "id_card", "phone", "address", "email"},
		RequestStats: &RequestStats{
			TotalCalls24h: 120, UniqueCallers24h: 3,
			ErrorRate24h: 0.0, AvgLatencyMs: 2500.0, P95LatencyMs: 8000.0,
			StatusCodeDist: map[string]int{"200": 120},
			HourlyCalls: []int{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
			TopCallers: []CallerInfo{
				{IP: "10.0.8.1", Calls: 120, ErrorRate: 0.0},
			},
		},
	}

	s.assets["ast-009"] = &Asset{
		ID: "ast-009", PathNormalized: "recommendation.ProductService/List",
		PathRawSamples: []string{"recommendation.ProductService/List"},
		Method: "POST", ProtocolType: "gRPC", Host: "grpc-internal.example.com",
		FirstSeen: now.Add(-10 * 24 * time.Hour), LastSeen: now.Add(-5 * time.Second),
		DailyAvgCalls: 95000, SensitivityHint: "low",
		ClaimStatus: "claimed", Owner: "zhao.yang@company.com",
		GroupPath: "推荐系统/商品推荐/gRPC",
		NormalizationConfidence: 1.0, Status: "active",
		SourceDistribution: map[string]string{"internal": "100%"},
		SensitiveFields: []string{},
		RequestStats: &RequestStats{
			TotalCalls24h: 95000, UniqueCallers24h: 15,
			ErrorRate24h: 0.01, AvgLatencyMs: 5.2, P95LatencyMs: 18.0,
			StatusCodeDist: map[string]int{"OK": 94990, "INTERNAL": 10},
			HourlyCalls: []int{2800, 2100, 1500, 1000, 800, 1200, 3500, 6800, 7200, 6500, 5800, 5200, 4800, 4600, 4800, 5400, 6200, 5800, 4800, 4200, 3800, 3500, 3100},
			TopCallers: []CallerInfo{
				{IP: "10.0.9.10", Calls: 35000, ErrorRate: 0.0},
				{IP: "10.0.9.11", Calls: 30000, ErrorRate: 0.0},
			},
		},
	}

	s.assets["ast-010"] = &Asset{
		ID: "ast-010", PathNormalized: "/ws/notifications",
		PathRawSamples: []string{"/ws/notifications"},
		Method: "GET", ProtocolType: "WebSocket", Host: "api.example.com",
		FirstSeen: now.Add(-5 * 24 * time.Hour), LastSeen: now.Add(-1 * time.Second),
		DailyAvgCalls: 3200, SensitivityHint: "low",
		ClaimStatus: "claimed", Owner: "sun.ming@company.com",
		GroupPath: "零售事业部/消息服务/WebSocket",
		NormalizationConfidence: 1.0, Status: "active",
		SourceDistribution: map[string]string{"internal": "30%", "external": "70%"},
		SensitiveFields: []string{},
		RequestStats: &RequestStats{
			TotalCalls24h: 3200, UniqueCallers24h: 3100,
			ErrorRate24h: 0.1, AvgLatencyMs: 3.5, P95LatencyMs: 12.0,
			StatusCodeDist: map[string]int{"101": 3197, "4003": 3},
			HourlyCalls: []int{80, 60, 40, 30, 25, 35, 100, 200, 280, 260, 240, 220, 210, 200, 210, 230, 260, 240, 200, 170, 140, 120, 100},
			TopCallers: []CallerInfo{
				{IP: "10.0.10.1", Calls: 50, ErrorRate: 0.0},
			},
		},
	}
}

func (s *AssetService) List() []Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Asset, 0, len(s.assets))
	for _, a := range s.assets {
		result = append(result, *a)
	}
	return result
}

func (s *AssetService) Get(id string) (*Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	if !ok {
		return nil, fmt.Errorf("asset not found: %s", id)
	}
	return a, nil
}

func (s *AssetService) GetDetail(id string) (*AssetDetail, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	if !ok {
		return nil, fmt.Errorf("asset not found: %s", id)
	}
	return &AssetDetail{
		Asset: *a,
		Alerts:         s.getAssetAlerts(id),
		ChangeHistory:  s.getAssetChanges(id),
		RelatedAssets:  s.getRelatedAssets(id),
	}, nil
}

func (s *AssetService) getAssetAlerts(assetID string) []AlertSummary {
	alerts := map[string][]AlertSummary{
		"ast-001": {
			{ID: "alt-001", Title: "疑似 BOLA 攻击：账号遍历订单对象", Severity: "high", Status: "open", Timestamp: time.Now().Add(-5 * time.Minute)},
			{ID: "alt-005", Title: "数据泄露风险：响应体包含未脱敏身份证", Severity: "high", Status: "acknowledged", Timestamp: time.Now().Add(-2 * time.Hour)},
		},
		"ast-002": {
			{ID: "alt-001", Title: "疑似 BOLA 攻击：账号遍历订单对象", Severity: "high", Status: "open", Timestamp: time.Now().Add(-5 * time.Minute)},
			{ID: "alt-004", Title: "异常资源消耗：超高频访问", Severity: "medium", Status: "open", Timestamp: time.Now().Add(-30 * time.Minute)},
		},
		"ast-003": {
			{ID: "alt-006", Title: "撞库攻击：支付接口高频失败", Severity: "critical", Status: "open", Timestamp: time.Now().Add(-20 * time.Minute)},
		},
		"ast-004": {
			{ID: "alt-007", Title: "影子 API 告警：未在 CMDB 注册", Severity: "medium", Status: "open", Timestamp: time.Now().Add(-1 * time.Hour)},
		},
		"ast-008": {
			{ID: "alt-008", Title: "数据泄露风险：明文传输敏感数据", Severity: "high", Status: "open", Timestamp: time.Now().Add(-45 * time.Minute)},
		},
	}
	if a, ok := alerts[assetID]; ok {
		return a
	}
	return []AlertSummary{}
}

func (s *AssetService) getAssetChanges(assetID string) []ChangeRecord {
	changes := map[string][]ChangeRecord{
		"ast-001": {
			{ChangeType: "field_added", Before: "不含id_card字段", After: "响应体新增id_card字段", Severity: "high", DetectedAt: time.Now().Add(-2 * time.Hour)},
			{ChangeType: "auth_method", Before: "Bearer Token 必填", After: "无需认证（疑似误配置）", Severity: "high", DetectedAt: time.Now().Add(-12 * time.Hour)},
		},
		"ast-002": {
			{ChangeType: "field_added", Before: "不含recipient_phone字段", After: "响应体新增recipient_phone字段", Severity: "medium", DetectedAt: time.Now().Add(-1 * time.Hour)},
		},
	}
	if c, ok := changes[assetID]; ok {
		return c
	}
	return []ChangeRecord{}
}

func (s *AssetService) getRelatedAssets(assetID string) []string {
	related := map[string][]string{
		"ast-001": {"ast-004", "ast-005"},
		"ast-002": {"ast-001", "ast-004"},
		"ast-003": {"ast-001", "ast-002"},
		"ast-004": {"ast-001"},
	}
	if r, ok := related[assetID]; ok {
		return r
	}
	return []string{}
}

func (s *AssetService) Claim(id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
	if !ok {
		return fmt.Errorf("asset not found: %s", id)
	}
	a.ClaimStatus = "claimed"
	a.Owner = owner
	return nil
}
