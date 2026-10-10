package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
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
	// Value is the effective value (the saved one, else DefaultValue). It is
	// filled in on copies handed out by the service and never stored.
	Value interface{} `json:"value"`
}

// ─── RuleService ──────────────────────────────────────────────

type RuleService struct {
	mu    sync.RWMutex
	rules map[string]*Rule
	p     *persister
}

// NewRuleService returns an in-memory service with the default rules.
func NewRuleService() *RuleService {
	s := &RuleService{rules: make(map[string]*Rule)}
	s.seedRules()
	return s
}

// NewRuleServiceFrom loads rules from repo. Default rules missing from the
// repository (first start, or rules added in a new version) are added and
// saved; stored rules keep their configuration.
func NewRuleServiceFrom(ctx context.Context, repo Repository) (*RuleService, error) {
	s := &RuleService{rules: make(map[string]*Rule), p: newPersister(repo, KindRule)}
	docs, err := repo.LoadDocuments(ctx, KindRule)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	for id, raw := range docs {
		var r Rule
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decode rule %s: %w", id, err)
		}
		s.rules[id] = &r
	}
	// Built-in rules take their definitions from this version; a stored rule
	// keeps its switch, statistics and the parameter values that are still
	// valid under the current definitions.
	var changed []string
	for id, def := range NewRuleService().rules {
		stored, ok := s.rules[id]
		if !ok {
			s.rules[id] = def
			changed = append(changed, id)
			continue
		}
		merged := def.clone()
		for i := range merged.Params {
			merged.Params[i].Value = nil // computed on read, never stored
		}
		merged.Enabled = stored.Enabled
		merged.HitCount = stored.HitCount
		merged.LastHitAt = stored.LastHitAt
		merged.CreatedAt = stored.CreatedAt
		merged.UpdatedAt = stored.UpdatedAt
		merged.Config = map[string]interface{}{}
		for key, v := range stored.Config {
			if param, ok := merged.param(key); ok {
				if norm, err := param.normalize(v); err == nil {
					merged.Config[key] = norm
				}
			}
		}
		if string(mustJSON(merged)) != string(mustJSON(stored)) {
			s.rules[id] = merged
			changed = append(changed, id)
		}
	}
	if err := s.p.writeThrough(ctx, changed, s.snapshot); err != nil {
		return nil, fmt.Errorf("save default rules: %w", err)
	}
	return s, nil
}

func (r *Rule) clone() *Rule {
	c := *r
	c.Config = make(map[string]interface{}, len(r.Config))
	for k, v := range r.Config {
		c.Config[k] = v
	}
	c.Params = append([]RuleParam(nil), r.Params...)
	for i := range c.Params {
		c.Params[i].Value = c.Params[i].DefaultValue
		if v, ok := r.Config[c.Params[i].Key]; ok {
			c.Params[i].Value = v
		}
	}
	if r.LastHitAt != nil {
		t := *r.LastHitAt
		c.LastHitAt = &t
	}
	return &c
}

func (s *RuleService) snapshot(ids []string) map[string][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	docs := make(map[string][]byte, len(ids))
	for _, id := range ids {
		if r, ok := s.rules[id]; ok {
			docs[id] = mustJSON(r)
		}
	}
	return docs
}

// Flush persists rules changed by high-frequency updates (hit counts).
func (s *RuleService) Flush(ctx context.Context) (int, error) {
	return s.p.flush(ctx, s.snapshot)
}

func (s *RuleService) seedRules() {
	now := time.Now()
	for _, r := range defaultRules() {
		r := r
		r.CreatedAt, r.UpdatedAt = now, now
		s.rules[r.ID] = &r
	}
}

// defaultRules are the built-in detection rules. Their definitions
// (name, description, parameters and ranges) are owned by the code; stored
// rules keep only their switch, parameter values and hit statistics.
func defaultRules() []Rule {
	return []Rule{
		{
			ID: "R-BOLA-001", RequirementFR: "FR-DET-001",
			Name: "BOLA 对象遍历检测", Category: "越权访问",
			Severity: "high", Enabled: true, DefaultScore: 70,
			Description:    "同一账号在统计窗口内访问的不同对象 ID 数达到阈值时告警，识别对象级越权遍历。达到阈值评 70 分，达到 3 倍阈值评 100 分。",
			Recommendation: "对该账号限流或临时封禁，检查该接口的对象级鉴权逻辑是否完整。",
			Params: []RuleParam{
				{Key: "window_minutes", Label: "统计窗口", Type: "int", DefaultValue: 5, Min: 1, Max: 60, Unit: "分钟", Description: "按此时间窗口统计每个账号访问的不同对象数"},
				{Key: "traverse_threshold", Label: "遍历阈值", Type: "int", DefaultValue: 20, Min: 5, Max: 1000, Unit: "个", Description: "窗口内访问的不同对象 ID 数达到此值触发告警"},
			},
		},
		{
			ID: "R-AUTH-001", RequirementFR: "FR-DET-002",
			Name: "认证失效检测", Category: "身份安全",
			Severity: "critical", Enabled: true, DefaultScore: 75,
			Description:    "同一来源 IP 在统计窗口内认证失败（HTTP 401）次数达到阈值时告警。涉及账号数达到阈值判定为撞库（85～100 分），否则判定为暴力破解（75 分）。",
			Recommendation: "对该 IP 临时封禁，排查涉及账号是否存在口令泄露。",
			Params: []RuleParam{
				{Key: "window_minutes", Label: "统计窗口", Type: "int", DefaultValue: 10, Min: 1, Max: 120, Unit: "分钟", Description: "按此时间窗口统计每个来源 IP 的认证失败"},
				{Key: "fail_count", Label: "失败次数阈值", Type: "int", DefaultValue: 20, Min: 3, Max: 1000, Unit: "次", Description: "窗口内认证失败次数达到此值触发告警"},
				{Key: "unique_accounts", Label: "撞库账号数", Type: "int", DefaultValue: 5, Min: 2, Max: 500, Unit: "个", Description: "涉及的不同账号数达到此值判定为撞库，否则为暴力破解"},
			},
		},
		{
			ID: "R-BFLA-001", RequirementFR: "FR-DET-005",
			Name: "BFLA 越权操作检测", Category: "越权访问",
			Severity: "high", Enabled: true, DefaultScore: 75,
			Description:    "非管理角色访问管理端点时告警：端点历史访问不足基线次数，或该角色在端点流量中的占比低于阈值。",
			Recommendation: "检查该账号的角色配置是否正确，审核该接口的鉴权策略。",
			Params: []RuleParam{
				{Key: "admin_endpoints", Label: "管理端点前缀", Type: "string", DefaultValue: "/admin,/api/v1/admin,/api/v1/system,/api/v1/users/roles,/manage,/supervisor,/actuator,/swagger-ui,/api/v1/audit", Unit: "路径前缀", Description: "逗号分隔，按完整路径段匹配"},
				{Key: "privileged_roles", Label: "管理角色", Type: "string", DefaultValue: "admin,administrator,super_admin,superadmin,root,sysadmin,system_admin,security_admin", Description: "逗号分隔，这些角色访问管理端点不告警"},
				{Key: "min_baseline", Label: "基线访问次数", Type: "int", DefaultValue: 10, Min: 1, Max: 100000, Unit: "次", Description: "端点历史访问达到此次数后才按占比判断，不足时非管理角色访问即告警"},
				{Key: "rare_share", Label: "罕见占比阈值", Type: "float", DefaultValue: 0.05, Min: 0.001, Max: 0.5, Description: "某角色在该端点流量中的占比低于此值时告警（0.05 即 5%）"},
				{Key: "strict_mode", Label: "严格模式", Type: "bool", DefaultValue: false, Description: "开启后非管理角色访问管理端点一律告警"},
			},
		},
		{
			ID: "R-DLP-001", RequirementFR: "FR-DLP-001",
			Name: "敏感数据检测", Category: "数据安全",
			Severity: "high", Enabled: true, DefaultScore: 75,
			Description:    "按字段名识别身份证号、手机号、银行卡号、凭证等敏感字段。导出类接口返回敏感字段，或单次返回的敏感字段数达到阈值时告警；含凭证时评 85 分。",
			Recommendation: "检查该接口返回的敏感字段是否必须，必要时实施脱敏或最小化返回。",
			Params: []RuleParam{
				{Key: "id_card", Label: "身份证号", Type: "bool", DefaultValue: true, Description: "识别 id_card、id_no、cert_no 等字段"},
				{Key: "phone", Label: "手机号", Type: "bool", DefaultValue: true, Description: "识别 phone、mobile 等字段"},
				{Key: "bank_card", Label: "银行卡号", Type: "bool", DefaultValue: true, Description: "识别 card、bank、account_no 等字段"},
				{Key: "credential", Label: "凭证", Type: "bool", DefaultValue: true, Description: "识别 password、token、secret、api_key 等字段"},
				{Key: "contact", Label: "地址与邮箱", Type: "bool", DefaultValue: false, Description: "识别 address、email 等字段"},
				{Key: "export_keywords", Label: "导出接口关键词", Type: "string", DefaultValue: "export,download,dump,batch", Description: "逗号分隔，路径包含这些关键词且返回敏感字段时告警"},
				{Key: "max_fields", Label: "敏感字段数阈值", Type: "int", DefaultValue: 3, Min: 1, Max: 50, Unit: "个", Description: "单次请求涉及的敏感字段数达到此值时告警"},
			},
		},
		{
			ID: "R-BOT-001", RequirementFR: "FR-RISK-002",
			Name: "爬虫行为检测", Category: "业务风控",
			Severity: "medium", Enabled: true, DefaultScore: 70,
			Description:    "同一调用方 1 分钟内请求数达到爆发阈值，或请求间隔高度规律（变异系数低于阈值）时判定为自动化脚本；两者同时出现评 85 分。",
			Recommendation: "对该调用方实施验证码挑战或限流。",
			Params: []RuleParam{
				{Key: "burst_threshold", Label: "爆发阈值", Type: "int", DefaultValue: 120, Min: 10, Max: 100000, Unit: "次/分钟", Description: "1 分钟内请求数达到此值触发"},
				{Key: "regularity_cv", Label: "间隔规律性阈值", Type: "float", DefaultValue: 0.1, Min: 0.01, Max: 1, Description: "最近请求间隔的变异系数（标准差/均值）低于此值判定为脚本"},
				{Key: "min_samples", Label: "规律性最少样本", Type: "int", DefaultValue: 30, Min: 10, Max: 1000, Unit: "次", Description: "至少有这么多次请求才判断间隔规律性"},
			},
		},
		{
			ID: "R-RATE-001", RequirementFR: "FR-DET-004",
			Name: "资源消耗异常检测", Category: "可用性",
			Severity: "medium", Enabled: true, DefaultScore: 70,
			Description:    "按接口统计每个窗口的请求数，与该接口的历史基线（指数加权平均）比较，超过基线倍数时告警。需要至少 3 个窗口的历史。",
			Recommendation: "对异常来源实施限流，排查是否遭遇资源耗尽攻击或业务突发。",
			Params: []RuleParam{
				{Key: "window_minutes", Label: "统计窗口", Type: "int", DefaultValue: 1, Min: 1, Max: 60, Unit: "分钟", Description: "按此时间窗口统计每个接口的请求数"},
				{Key: "multiplier", Label: "基线倍数阈值", Type: "float", DefaultValue: 5, Min: 1.5, Max: 100, Unit: "倍", Description: "窗口请求数超过历史基线此倍数时触发"},
				{Key: "min_requests", Label: "最低请求数", Type: "int", DefaultValue: 300, Min: 10, Max: 10000000, Unit: "次", Description: "窗口请求数低于此值不告警，避免低频接口误报"},
			},
		},
		{
			ID: "R-SSRF-001", RequirementFR: "FR-DET-007",
			Name: "SSRF 服务端请求伪造检测", Category: "注入攻击",
			Severity: "high", Enabled: true, DefaultScore: 75,
			Description:    "检测请求参数中指向内网地址（75 分）、危险协议（85 分）或云元数据地址（95 分）的 URL 和 IP。只匹配字面地址，不做域名解析。",
			Recommendation: "对该接口的用户输入做 URL 白名单校验，禁止访问内网和元数据地址。",
			Params: []RuleParam{
				{Key: "internal_nets", Label: "内网地址段", Type: "string", DefaultValue: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fc00::/7", Description: "逗号分隔的 CIDR，参数指向这些网段时告警"},
				{Key: "metadata_hosts", Label: "云元数据地址", Type: "string", DefaultValue: "169.254.169.254,100.100.100.200,metadata.google.internal,metadata.tencentyun.com", Description: "逗号分隔的 IP 或域名"},
				{Key: "blocked_schemes", Label: "危险协议", Type: "string", DefaultValue: "file,gopher,dict,ftp,ldap,jar", Description: "逗号分隔，参数中出现这些协议的 URL 时告警"},
			},
		},
	}
}

func (s *RuleService) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Rule, 0, len(s.rules))
	for _, r := range s.rules {
		result = append(result, *r.clone())
	}
	return result
}

func (s *RuleService) Get(id string) (*Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	if !ok {
		return nil, fmt.Errorf("rule %s: %w", id, ErrNotFound)
	}
	return r.clone(), nil
}

// update applies fn to a rule and persists it; if saving fails the rule is
// restored and the error returned, so memory never shows an unsaved change.
func (s *RuleService) update(id string, fn func(r *Rule)) (*Rule, error) {
	s.mu.Lock()
	r, ok := s.rules[id]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("rule %s: %w", id, ErrNotFound)
	}
	before := r.clone()
	fn(r)
	r.UpdatedAt = time.Now()
	s.mu.Unlock()

	if err := s.p.writeThrough(context.Background(), []string{id}, s.snapshot); err != nil {
		s.mu.Lock()
		s.rules[id] = before
		s.mu.Unlock()
		return nil, fmt.Errorf("save rule %s: %w", id, err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rules[id].clone(), nil
}

// UpdateConfig sets parameter values. Every key must be a parameter of the
// rule and every value must fit its type and range; otherwise nothing is
// changed and an ErrInvalid error names the problem.
func (s *RuleService) UpdateConfig(id string, config map[string]interface{}) (*Rule, error) {
	if len(config) == 0 {
		return nil, fmt.Errorf("%w: 没有要修改的参数", ErrInvalid)
	}
	def, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	values := make(map[string]interface{}, len(config))
	for key, v := range config {
		param, ok := def.param(key)
		if !ok {
			return nil, fmt.Errorf("%w: 规则 %s 没有参数 %s", ErrInvalid, id, key)
		}
		norm, err := param.normalize(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, param.Label, err)
		}
		values[key] = norm
	}
	return s.update(id, func(r *Rule) {
		if r.Config == nil {
			r.Config = make(map[string]interface{})
		}
		for k, v := range values {
			r.Config[k] = v
		}
	})
}

// IsEnabled reports whether rule id exists and is switched on.
func (s *RuleService) IsEnabled(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	return ok && r.Enabled
}

// Values returns the effective parameter values of rule id (saved values,
// else defaults), or nil when the rule does not exist.
func (s *RuleService) Values(id string) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	if !ok {
		return nil
	}
	values := make(map[string]interface{}, len(r.Params))
	for _, p := range r.Params {
		values[p.Key] = p.DefaultValue
		if v, ok := r.Config[p.Key]; ok {
			values[p.Key] = v
		}
	}
	return values
}

func (r *Rule) param(key string) (RuleParam, bool) {
	for _, p := range r.Params {
		if p.Key == key {
			return p, true
		}
	}
	return RuleParam{}, false
}

// maxStringParam bounds string parameters such as endpoint lists.
const maxStringParam = 4000

// normalize checks v against the parameter's type and range and returns it
// in canonical form (float64 for numbers).
func (p RuleParam) normalize(v interface{}) (interface{}, error) {
	switch p.Type {
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("应为开关值")
		}
		return b, nil
	case "string":
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("应为文本")
		}
		str = strings.TrimSpace(str)
		if str == "" {
			return nil, fmt.Errorf("不能为空")
		}
		if len(str) > maxStringParam {
			return nil, fmt.Errorf("不能超过 %d 个字符", maxStringParam)
		}
		return str, nil
	case "int", "float":
		var f float64
		switch n := v.(type) {
		case float64:
			f = n
		case int:
			f = float64(n)
		case json.Number:
			var err error
			if f, err = n.Float64(); err != nil {
				return nil, fmt.Errorf("应为数字")
			}
		default:
			return nil, fmt.Errorf("应为数字")
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("应为数字")
		}
		if p.Type == "int" && f != math.Trunc(f) {
			return nil, fmt.Errorf("应为整数")
		}
		if (p.Min != 0 || p.Max != 0) && (f < p.Min || f > p.Max) {
			return nil, fmt.Errorf("取值范围 %g～%g", p.Min, p.Max)
		}
		return f, nil
	}
	return nil, fmt.Errorf("不支持的参数类型 %s", p.Type)
}

func (s *RuleService) UpdateEnabled(id string, enabled bool) (*Rule, error) {
	return s.update(id, func(r *Rule) { r.Enabled = enabled })
}

func (s *RuleService) IncrementHit(id string) {
	s.mu.Lock()
	r, ok := s.rules[id]
	if ok {
		r.HitCount++
		now := time.Now()
		r.LastHitAt = &now
	}
	s.mu.Unlock()
	if ok {
		s.p.markDirty(id)
	}
}

func (s *RuleService) ListByCategory(category string) []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Rule
	for _, r := range s.rules {
		if r.Category == category {
			result = append(result, *r.clone())
		}
	}
	return result
}
