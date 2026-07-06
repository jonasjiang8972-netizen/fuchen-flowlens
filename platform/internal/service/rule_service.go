package service

import (
	"fmt"
	"sync"
	"time"
)

// ─── Detection Rule Model ─────────────────────────────────────

type Rule struct {
	ID             string                 `json:"rule_id"`
	RequirementFR  string                 `json:"source_requirement"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Category       string                 `json:"category"`
	Severity       string                 `json:"severity"`
	Enabled        bool                   `json:"enabled"`
	DefaultScore   int                    `json:"default_risk_score"`
	Config         map[string]interface{} `json:"config"`
	Params         []RuleParam            `json:"params"`
	Recommendation string                 `json:"recommendation"`
	HitCount       int                    `json:"hit_count"`
	LastHitAt      *time.Time             `json:"last_hit_at,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

type RuleParam struct {
	Key          string      `json:"key"`
	Label        string      `json:"label"`
	Type         string      `json:"type"`
	DefaultValue interface{} `json:"default_value"`
	Min          float64     `json:"min,omitempty"`
	Max          float64     `json:"max,omitempty"`
	Unit         string      `json:"unit,omitempty"`
	Description  string      `json:"description"`
}

// ─── RuleService ──────────────────────────────────────────────

type RuleService struct {
	mu    sync.RWMutex
	rules map[string]*Rule
}

func NewRuleService() *RuleService {
	s := &RuleService{rules: make(map[string]*Rule)}
	s.seedRules()
	return s
}

func (s *RuleService) seedRules() {
	now := time.Now()
	s.rules["R-BOLA-001"] = &Rule{
		ID: "R-BOLA-001", RequirementFR: "FR-DET-001",
		Name: "BOLA 对象遍历检测", Category: "越权访问",
		Severity: "high", Enabled: true, DefaultScore: 80,
		Description: "检测账号在短时间高频访问不同对象ID的行为，识别对象级越权遍历攻击。基于账号-对象基线的偏离度加权评分。",
		Recommendation: "建议对该账号实施限流或临时封禁，检查该接口的对象级鉴权逻辑是否完整。",
		Config:  map[string]interface{}{"baseline_window": "5m", "score_algorithm": "weighted"},
		HitCount: 23, LastHitAt: &now,
		Params: []RuleParam{
			{Key: "traverse_threshold", Label: "遍历阈值", Type: "int", DefaultValue: 20.0, Min: 5, Max: 500, Unit: "个", Description: "5分钟内不同对象ID数量超过此值触发告警"},
			{Key: "rate_threshold", Label: "速率阈值", Type: "float", DefaultValue: 2.0, Min: 0.5, Max: 100, Unit: "/s", Description: "遍历速率超过此值加重评分"},
			{Key: "suspicion_score", Label: "怀疑基础分", Type: "int", DefaultValue: 60, Min: 0, Max: 100, Unit: "分", Description: "触发阈值时的基础风险评分"},
		},
		CreatedAt: now.Add(-30 * 24 * time.Hour), UpdatedAt: now.Add(-1 * time.Hour),
	}
	s.rules["R-AUTH-001"] = &Rule{
		ID: "R-AUTH-001", RequirementFR: "FR-DET-002",
		Name: "认证失效检测", Category: "身份安全",
		Severity: "critical", Enabled: true, DefaultScore: 90,
		Description: "检测单 IP 短时间多重账号登录失败行为，识别撞库/凭证填充攻击。结合失败率、账号数、速率三维度加权。",
		Recommendation: "建议对该 IP 实施临时封禁，检查是否有账号泄露风险。",
		Config: map[string]interface{}{"window": "10m", "algorithm": "multi_dimension"},
		HitCount: 7, LastHitAt: &now,
		Params: []RuleParam{
			{Key: "fail_count", Label: "失败次数阈值", Type: "int", DefaultValue: 30, Min: 5, Max: 500, Unit: "次", Description: "时间窗口内失败次数超过此值触发"},
			{Key: "unique_accounts", Label: "不同账号数", Type: "int", DefaultValue: 10, Min: 2, Max: 200, Unit: "个", Description: "涉及不同账号数超过此值加重"},
			{Key: "fail_rate", Label: "失败率阈值", Type: "float", DefaultValue: 0.8, Min: 0.1, Max: 1.0, Unit: "%", Description: "失败请求占比超过此值加权"},
		},
		CreatedAt: now.Add(-30 * 24 * time.Hour), UpdatedAt: now.Add(-2 * time.Hour),
	}
	s.rules["R-BFLA-001"] = &Rule{
		ID: "R-BFLA-001", RequirementFR: "FR-DET-005",
		Name: "BFLA 越权操作检测", Category: "越权访问",
		Severity: "high", Enabled: true, DefaultScore: 75,
		Description: "检测低权限账号访问管理端点或执行高权限操作。基于角色-接口访问矩阵，识别非授权角色的操作行为。",
		Recommendation: "检查该账号的角色配置是否正确，审核该接口的鉴权策略。",
		Config:  map[string]interface{}{"matrix_window": "1h", "strict_mode": false},
		HitCount: 5, LastHitAt: &now,
		Params: []RuleParam{
			{Key: "admin_endpoints", Label: "管理端点列表", Type: "string", DefaultValue: "/admin,/api/v1/admin,/manage,/supervisor", Unit: "路径前缀", Description: "逗号分隔的管理端点前缀"},
			{Key: "allowed_roles", Label: "允许的管理角色", Type: "string", DefaultValue: "super_admin,security_admin", Description: "允许访问管理端点的角色"},
			{Key: "strict_mode", Label: "严格模式", Type: "bool", DefaultValue: false, Description: "开启后所有未经历史访问的管理端点请求即告警"},
		},
		CreatedAt: now.Add(-25 * 24 * time.Hour), UpdatedAt: now.Add(-3 * time.Hour),
	}
	s.rules["R-DLP-001"] = &Rule{
		ID: "R-DLP-001", RequirementFR: "FR-DLP-001",
		Name: "敏感数据检测", Category: "数据安全",
		Severity: "high", Enabled: true, DefaultScore: 70,
		Description: "自动识别响应体中包含的敏感数据（身份证号、手机号、银行卡号等），按类型和数量分级告警。",
		Recommendation: "检查该接口返回的敏感字段是否必须，必要时实施脱敏处理。",
		Config:  map[string]interface{}{"engine": "regex", "masking_check": true},
		HitCount: 0,
		Params: []RuleParam{
			{Key: "id_card", Label: "身份证检测", Type: "bool", DefaultValue: true, Description: "启用18位身份证号正则+校验位检测"},
			{Key: "phone", Label: "手机号检测", Type: "bool", DefaultValue: true, Description: "启用中国大陆手机号检测"},
			{Key: "bank_card", Label: "银行卡检测", Type: "bool", DefaultValue: true, Description: "启用银行卡号 Luhn 校验检测"},
			{Key: "max_fields", Label: "单接口敏感字段上限", Type: "int", DefaultValue: 5, Min: 1, Max: 100, Description: "超过此数量加重风险评分"},
		},
		CreatedAt: now.Add(-20 * 24 * time.Hour), UpdatedAt: now.Add(-12 * time.Hour),
	}
	s.rules["R-BOT-001"] = &Rule{
		ID: "R-BOT-001", RequirementFR: "FR-RISK-002",
		Name: "爬虫行为检测", Category: "业务风控",
		Severity: "medium", Enabled: false, DefaultScore: 50,
		Description: "基于设备指纹、请求间隔规律、资源加载特征识别自动化爬虫行为。",
		Recommendation: "对该设备指纹实施验证码挑战或限流。",
		Config:  map[string]interface{}{"fingerprint": "ja3", "behavior_window": "10m"},
		HitCount: 0,
		Params: []RuleParam{
			{Key: "interval_variance", Label: "请求间隔方差阈值", Type: "float", DefaultValue: 0.1, Min: 0.01, Max: 1.0, Unit: "s", Description: "请求间隔标准差小于此值判定为脚本"},
			{Key: "no_resource", Label: "无资源加载触发", Type: "bool", DefaultValue: true, Description: "无CSS/JS/图片加载的请求判定为爬虫"},
			{Key: "burst_threshold", Label: "短时爆发阈值", Type: "int", DefaultValue: 100, Min: 10, Max: 1000, Description: "1分钟内请求超过此值触发"},
		},
		CreatedAt: now.Add(-15 * 24 * time.Hour), UpdatedAt: now.Add(-24 * time.Hour),
	}
	s.rules["R-RATE-001"] = &Rule{
		ID: "R-RATE-001", RequirementFR: "FR-DET-004",
		Name: "资源消耗异常检测", Category: "可用性",
		Severity: "medium", Enabled: false, DefaultScore: 50,
		Description: "检测接口 QPS 超出历史基线一定倍数的异常流量，识别资源耗尽攻击或异常突发请求。",
		Recommendation: "对该来源实施限流策略，检查是否遭遇DDoS攻击。",
		Config:  map[string]interface{}{"baseline_period": "7d", "alert_multiplier": 5},
		HitCount: 0,
		Params: []RuleParam{
			{Key: "multiplier", Label: "基线倍数阈值", Type: "float", DefaultValue: 5.0, Min: 1.5, Max: 100, Description: "当前QPS超历史基线N倍时触发"},
			{Key: "min_qps", Label: "最低QPS门槛", Type: "int", DefaultValue: 500, Min: 10, Max: 100000, Unit: "QPS", Description: "低于此QPS不检测，避免低频接口误报"},
			{Key: "window", Label: "检测窗口", Type: "int", DefaultValue: 5, Min: 1, Max: 60, Unit: "分钟", Description: "统计窗口大小"},
		},
		CreatedAt: now.Add(-10 * 24 * time.Hour), UpdatedAt: now.Add(-5 * 24 * time.Hour),
	}
	s.rules["R-SSRF-001"] = &Rule{
		ID: "R-SSRF-001", RequirementFR: "FR-DET-007",
		Name: "SSRF 服务端请求伪造检测", Category: "注入攻击",
		Severity: "high", Enabled: true, DefaultScore: 65,
		Description: "检测请求参数中包含内网地址、云元数据地址等SSRF特征。旁路模式下检出率≥50%，增强模式需集成VPC流日志。",
		Recommendation: "检查该接口是否需要对用户输入做URL白名单校验。",
		Config:  map[string]interface{}{"mode": "basic", "vpc_integration": false},
		HitCount: 0,
		Params: []RuleParam{
			{Key: "internal_nets", Label: "内网IP段", Type: "string", DefaultValue: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", Description: "匹配到这些网段的请求参数触发告警"},
			{Key: "metadata_ips", Label: "云元数据IP", Type: "string", DefaultValue: "169.254.169.254,100.100.100.200", Description: "云服务商元数据地址"},
			{Key: "vpc_integration", Label: "VPC流日志增强", Type: "bool", DefaultValue: false, Description: "开启后结合VPC流日志验证实际出向目的地"},
		},
		CreatedAt: now.Add(-20 * 24 * time.Hour), UpdatedAt: now.Add(-10 * 24 * time.Hour),
	}
}

func (s *RuleService) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Rule, 0, len(s.rules))
	for _, r := range s.rules {
		result = append(result, *r)
	}
	return result
}

func (s *RuleService) Get(id string) (*Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", id)
	}
	return r, nil
}

func (s *RuleService) UpdateConfig(id string, config map[string]interface{}, params []RuleParam) (*Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", id)
	}
	for k, v := range config {
		r.Config[k] = v
	}
	if params != nil {
		r.Params = params
	}
	r.UpdatedAt = time.Now()
	return r, nil
}

func (s *RuleService) UpdateEnabled(id string, enabled bool) (*Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", id)
	}
	r.Enabled = enabled
	r.UpdatedAt = time.Now()
	return r, nil
}

func (s *RuleService) IncrementHit(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if ok {
		r.HitCount++
		now := time.Now()
		r.LastHitAt = &now
	}
}

func (s *RuleService) ListByCategory(category string) []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Rule
	for _, r := range s.rules {
		if r.Category == category {
			result = append(result, *r)
		}
	}
	return result
}
