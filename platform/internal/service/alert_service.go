package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Alert struct {
	ID                 string        `json:"alert_id"`
	Timestamp          time.Time     `json:"timestamp"`
	Severity           string        `json:"severity"`
	Title              string        `json:"title"`
	Description        string        `json:"description"`
	SourceRequirement  string        `json:"source_requirement"`
	RiskScore          int           `json:"risk_score"`
	Confidence         float64       `json:"confidence"`
	Status             string        `json:"status"`
	SourceIP           string        `json:"source_ip"`
	AccountID          string        `json:"account_id"`
	DeviceFingerprint  string        `json:"device_fingerprint"`
	AffectedAssetCount int           `json:"affected_asset_count"`
	AttackPath         []AttackStep  `json:"attack_path"`
	Disposal           *DisposalInfo `json:"disposal,omitempty"`
	OccurrenceCount    int           `json:"occurrence_count,omitempty"`
	LastSeen           time.Time     `json:"last_seen,omitempty"`
	// History records every handling step (who, when, what), oldest first.
	History []AlertHistory `json:"history,omitempty"`
	// Endpoints are the APIs ("METHOD /path") the detections concerned.
	Endpoints []string `json:"endpoints,omitempty"`
}

// maxAlertEndpoints bounds the endpoints recorded per alert.
const maxAlertEndpoints = 20

// AddEndpoint records that alert id concerns endpoint.
func (s *AlertService) AddEndpoint(id, endpoint string) {
	if endpoint == "" {
		return
	}
	s.mu.Lock()
	a, ok := s.alerts[id]
	changed := false
	if ok && len(a.Endpoints) < maxAlertEndpoints {
		found := false
		for _, e := range a.Endpoints {
			found = found || e == endpoint
		}
		if !found {
			a.Endpoints = append(a.Endpoints, endpoint)
			changed = true
		}
	}
	s.mu.Unlock()
	if changed {
		s.p.markDirty(id)
	}
}

// ForEndpoint lists the alerts concerning endpoint, newest first.
func (s *AlertService) ForEndpoint(endpoint string) []AlertSummary {
	s.mu.RLock()
	var out []AlertSummary
	for _, a := range s.alerts {
		for _, e := range a.Endpoints {
			if e == endpoint {
				out = append(out, AlertSummary{ID: a.ID, Title: a.Title, Severity: a.Severity, Status: a.Status, Timestamp: a.Timestamp})
				break
			}
		}
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if out == nil {
		out = []AlertSummary{}
	}
	return out
}

// AlertHistory is one handling step on an alert.
type AlertHistory struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Status string    `json:"status"`
	Actor  string    `json:"actor"`
	Note   string    `json:"note,omitempty"`
}

// alertActions maps each handling action to the status it moves the alert
// to. Disposals (block, rate limit, lock) are recorded here; carrying them
// out is up to the gateway, WAF or SOAR that receives the forwarded event.
var alertActions = map[string]struct{ status, label string }{
	"acknowledge":    {"acknowledged", "确认告警"},
	"ip_block":       {"in_progress", "封禁来源 IP"},
	"rate_limit":     {"in_progress", "限流"},
	"account_lock":   {"in_progress", "锁定账号"},
	"resolve":        {"resolved", "标记已解决"},
	"false_positive": {"false_positive", "标记误报"},
	"reopen":         {"open", "重新打开"},
}

// maxAlertHistory bounds the handling steps kept per alert.
const maxAlertHistory = 100

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
	RelatedAlerts []string          `json:"related_alerts"`
	Timeline      []TimelineEvent   `json:"timeline"`
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
	// activeDetections maps a detection key to the alert that repeat
	// detections are merged into.
	activeDetections map[string]string
	now              func() time.Time
	seq              uint64 // makes detection alert IDs unique within a nanosecond
	p                *persister
}

const (
	// detectionMergeWindow is how long after its last occurrence a detection
	// alert keeps absorbing repeats of the same finding.
	detectionMergeWindow = 30 * time.Minute
	maxAttackPathSteps   = 50
)

func NewAlertService() *AlertService {
	s := &AlertService{
		alerts:           make(map[string]*Alert),
		activeDetections: make(map[string]string),
		now:              time.Now,
	}
	s.seedAlerts()
	return s
}

// NewAlertServiceFrom loads alerts from repo. Sample alerts are added only
// when seedDemo is set and the repository is empty; a production platform
// starts with no alerts rather than invented ones.
func NewAlertServiceFrom(ctx context.Context, repo Repository, seedDemo bool) (*AlertService, error) {
	s := &AlertService{
		alerts:           make(map[string]*Alert),
		activeDetections: make(map[string]string),
		now:              time.Now,
		p:                newPersister(repo, KindAlert),
	}
	docs, err := repo.LoadDocuments(ctx, KindAlert)
	if err != nil {
		return nil, fmt.Errorf("load alerts: %w", err)
	}
	for id, raw := range docs {
		var a Alert
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("decode alert %s: %w", id, err)
		}
		s.alerts[id] = &a
	}
	// Rebuild the merge index: each detection key points at its most
	// recently seen alert, so repeats keep merging across restarts.
	for id, a := range s.alerts {
		if a.OccurrenceCount == 0 {
			continue
		}
		key := detectionKey(a.SourceRequirement, a.AccountID, a.SourceIP)
		if cur, ok := s.activeDetections[key]; !ok || s.alerts[cur].LastSeen.Before(a.LastSeen) {
			s.activeDetections[key] = id
		}
	}
	if len(s.alerts) == 0 && seedDemo {
		s.seedAlerts()
		ids := make([]string, 0, len(s.alerts))
		for id := range s.alerts {
			ids = append(ids, id)
		}
		if err := s.p.writeThrough(ctx, ids, s.snapshot); err != nil {
			return nil, fmt.Errorf("save sample alerts: %w", err)
		}
	}
	return s, nil
}

func detectionKey(requirement, accountID, sourceIP string) string {
	return requirement + "|" + accountID + "|" + sourceIP
}

func (s *AlertService) snapshot(ids []string) map[string][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	docs := make(map[string][]byte, len(ids))
	for _, id := range ids {
		if a, ok := s.alerts[id]; ok {
			docs[id] = mustJSON(a)
		}
	}
	return docs
}

// Flush persists alerts changed by detections since the last flush.
func (s *AlertService) Flush(ctx context.Context) (int, error) {
	return s.p.flush(ctx, s.snapshot)
}

func (s *AlertService) seedAlerts() {
	now := time.Now()

	s.alerts["alt-001"] = &Alert{
		Endpoints: []string{"GET /api/v1/order/{id}"},
		ID:        "alt-001", Timestamp: now.Add(-5 * time.Minute), Severity: "high",
		Title:             "疑似 BOLA 攻击：账号 usr-88213 高频遍历订单对象",
		Description:       "账号 usr-88213 在过去 5 分钟内连续访问了 847 个不同订单 ID，遍历速率 12.4/s，远超历史基线（0.3/s）。该账号信誉分 0.62，近期有多次异常登录记录。",
		SourceRequirement: "FR-DET-001", RiskScore: 91, Confidence: 0.92,
		Status: "open", SourceIP: "203.0.113.18", AccountID: "usr-88213",
		DeviceFingerprint:  "df-a92c1e",
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
		Endpoints: []string{"POST /api/v1/payment/checkout"},
		ID:        "alt-002", Timestamp: now.Add(-15 * time.Minute), Severity: "critical",
		Title:             "撞库攻击：单 IP 尝试 68 个不同账号",
		Description:       "IP 198.51.100.22 在过去 10 分钟内对登录接口发起 247 次失败尝试，涉及 68 个不同用户名。失败率 95.5%，匹配已知撞库特征。",
		SourceRequirement: "FR-DET-002", RiskScore: 96, Confidence: 0.97,
		Status: "acknowledged", SourceIP: "198.51.100.22",
		DeviceFingerprint:  "df-b83d2f",
		AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-25 * time.Minute), Action: "recon", Detail: "探测登录接口", SourceIP: "198.51.100.22", Path: "/api/v1/auth/login", Status: 405},
			{Sequence: 2, Timestamp: now.Add(-20 * time.Minute), Action: "brute_force", Detail: "开始批量尝试，涉及 68 个账号", SourceIP: "198.51.100.22", Path: "/api/v1/auth/login", Status: 401},
			{Sequence: 3, Timestamp: now.Add(-15 * time.Minute), Action: "brute_force", Detail: "持续尝试中", SourceIP: "198.51.100.22", Path: "/api/v1/auth/login", Status: 401},
		},
	}

	s.alerts["alt-003"] = &Alert{
		Endpoints: []string{"GET /api/v1/legacy/export"},
		ID:        "alt-003", Timestamp: now.Add(-45 * time.Minute), Severity: "medium",
		Title:             "影子 API 发现：/api/v1/legacy/export 未在 CMDB 注册",
		Description:       "发现接口 /api/v1/legacy/export 有实际流量但未在官方 API 目录中注册。该接口返回大量敏感数据（姓名、身份证、手机号），存在数据泄露风险。",
		SourceRequirement: "FR-AST-002", RiskScore: 65, Confidence: 0.92,
		Status: "open", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-004"] = &Alert{
		Endpoints: []string{"GET /api/v1/order/{id}"},
		ID:        "alt-004", Timestamp: now.Add(-30 * time.Minute), Severity: "medium",
		Title:             "异常资源消耗：订单接口 QPS 超基线 5 倍",
		Description:       "接口 /api/v1/order/{id} 当前 QPS 达到 3800，超出历史基线（750 QPS）5 倍。来源 IP 203.0.113.18 贡献了 42% 的流量。",
		SourceRequirement: "FR-DET-004", RiskScore: 72, Confidence: 0.85,
		Status: "open", SourceIP: "203.0.113.18", AffectedAssetCount: 1,
		AttackPath: []AttackStep{
			{Sequence: 1, Timestamp: now.Add(-35 * time.Minute), Action: "normal", Detail: "正常流量基线: 750 QPS", SourceIP: "multiple", Path: "/api/v1/order/{id}", Status: 200},
			{Sequence: 2, Timestamp: now.Add(-30 * time.Minute), Action: "spike", Detail: "QPS 突增至 3800", SourceIP: "203.0.113.18", Path: "/api/v1/order/{id}", Status: 200},
		},
	}

	s.alerts["alt-005"] = &Alert{
		Endpoints: []string{"GET /api/v1/user/{id}"},
		ID:        "alt-005", Timestamp: now.Add(-2 * time.Hour), Severity: "high",
		Title:             "数据泄露风险：用户接口响应体包含未脱敏身份证号",
		Description:       "接口 /api/v1/user/{id} 响应体中发现未脱敏的身份证号字段（id_card_no），格式为 18 位数字，违反《个人信息保护法》第 51 条。",
		SourceRequirement: "FR-DLP-003", RiskScore: 82, Confidence: 0.95,
		Status: "acknowledged", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-006"] = &Alert{
		Endpoints: []string{"POST /api/v1/payment/checkout"},
		ID:        "alt-006", Timestamp: now.Add(-20 * time.Minute), Severity: "critical",
		Title:             "支付接口撞库：单设备尝试 120 张不同银行卡",
		Description:       "设备指纹 df-c44e5a 在 30 分钟内通过 /api/v1/payment/checkout 尝试了 120 张不同银行卡的卡号，成功 3 次。",
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
		Endpoints: []string{"GET /api/v1/legacy/export"},
		ID:        "alt-007", Timestamp: now.Add(-1 * time.Hour), Severity: "medium",
		Title:             "影子 API 告警：/api/v1/user/{id}/orders 未在 CMDB 注册",
		Description:       "发现接口 /api/v1/user/{id}/orders 有实际流量但未在官方 API 目录中注册。该接口返回用户完整订单历史。",
		SourceRequirement: "FR-AST-002", RiskScore: 58, Confidence: 0.88,
		Status: "open", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-008"] = &Alert{
		Endpoints: []string{"GET /api/v1/legacy/export"},
		ID:        "alt-008", Timestamp: now.Add(-3 * time.Hour), Severity: "high",
		Title:             "明文传输敏感数据：legacy/export 通过 HTTP 传输",
		Description:       "接口 /api/v1/legacy/export 通过 HTTP（非 HTTPS）传输，响应体包含姓名、身份证、手机号等敏感信息。",
		SourceRequirement: "FR-DET-008", RiskScore: 78, Confidence: 0.96,
		Status: "open", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-009"] = &Alert{
		ID: "alt-009", Timestamp: now.Add(-4 * time.Hour), Severity: "low",
		Title:             "僵尸 API：库存接口连续 7 天无访问",
		Description:       "接口 /api/v1/inventory/{warehouse_id}/stock 最近 7 天无实际业务访问，但接口仍可响应。",
		SourceRequirement: "FR-AST-002", RiskScore: 25, Confidence: 0.90,
		Status: "open", AffectedAssetCount: 1,
		AttackPath: []AttackStep{},
	}

	s.alerts["alt-010"] = &Alert{
		ID: "alt-010", Timestamp: now.Add(-6 * time.Hour), Severity: "medium",
		Title:             "爬虫行为识别：商品推荐接口异常设备指纹",
		Description:       "设备指纹 df-d55f6b 在 2 小时内访问推荐接口 18000 次，请求间隔高度规律（方差 < 0.01s）。",
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

// CreateDetectionAlert records a detection. Repeats of the same finding
// (requirement, account and source IP) are merged into the existing alert
// while it is still open or acknowledged and was last seen within
// detectionMergeWindow, instead of creating one alert per request.
func (s *AlertService) CreateDetectionAlert(sourceRequirement, severity, title, description, sourceIP, accountID string, riskScore int, confidence float64) Alert {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	key := detectionKey(sourceRequirement, accountID, sourceIP)
	if id, ok := s.activeDetections[key]; ok {
		if a, ok := s.alerts[id]; ok && mergeable(a, now) {
			a.OccurrenceCount++
			a.LastSeen = now
			a.Description = description
			if riskScore > a.RiskScore {
				a.RiskScore = riskScore
				a.Title = title
			}
			if severityRank(severity) > severityRank(a.Severity) {
				a.Severity = severity
			}
			if confidence > a.Confidence {
				a.Confidence = confidence
			}
			s.p.markDirty(id)
			if len(a.AttackPath) < maxAttackPathSteps {
				a.AttackPath = append(a.AttackPath, AttackStep{
					Sequence:  len(a.AttackPath) + 1,
					Timestamp: now,
					Action:    "detect",
					Detail:    description,
					SourceIP:  sourceIP,
				})
			}
			return *a
		}
	}

	s.seq++
	id := fmt.Sprintf("alt-det-%d-%d", now.UnixNano(), s.seq)
	alert := &Alert{
		ID:                 id,
		Timestamp:          now,
		Severity:           severity,
		Title:              title,
		Description:        description,
		SourceRequirement:  sourceRequirement,
		RiskScore:          riskScore,
		Confidence:         confidence,
		Status:             "open",
		SourceIP:           sourceIP,
		AccountID:          accountID,
		AffectedAssetCount: 1,
		OccurrenceCount:    1,
		LastSeen:           now,
		AttackPath: []AttackStep{
			{
				Sequence:  1,
				Timestamp: now,
				Action:    "detect",
				Detail:    description,
				SourceIP:  sourceIP,
			},
		},
	}
	s.alerts[id] = alert
	s.activeDetections[key] = id
	s.p.markDirty(id)
	return *alert
}

// mergeable reports whether a repeat detection may be folded into a. Once an
// alert has been acted on (disposal in progress or closed) a recurring attack
// should raise a fresh alert.
func mergeable(a *Alert, now time.Time) bool {
	if a.Status != "open" && a.Status != "acknowledged" && a.Status != "in_progress" {
		return false
	}
	return now.Sub(a.LastSeen) <= detectionMergeWindow
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func (s *AlertService) Get(id string) (*Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, fmt.Errorf("alert %s: %w", id, ErrNotFound)
	}
	c := *a
	c.AttackPath = append([]AttackStep(nil), a.AttackPath...)
	return &c, nil
}

func (s *AlertService) GetDetail(id string) (*AlertDetail, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, fmt.Errorf("alert %s: %w", id, ErrNotFound)
	}
	return &AlertDetail{
		Alert:         *a,
		RelatedAlerts: s.relatedLocked(a),
		Timeline:      timelineOf(a),
		RawData:       evidenceOf(a),
	}, nil
}

// maxRelatedAlerts bounds the related alerts listed for one alert.
const maxRelatedAlerts = 10

// relatedLocked lists other alerts from the same source IP or account,
// newest first.
func (s *AlertService) relatedLocked(a *Alert) []string {
	var rel []*Alert
	for _, o := range s.alerts {
		if o.ID == a.ID {
			continue
		}
		if (a.SourceIP != "" && o.SourceIP == a.SourceIP) || (a.AccountID != "" && o.AccountID == a.AccountID) {
			rel = append(rel, o)
		}
	}
	sort.Slice(rel, func(i, j int) bool { return rel[i].Timestamp.After(rel[j].Timestamp) })
	ids := []string{}
	for i, o := range rel {
		if i >= maxRelatedAlerts {
			break
		}
		ids = append(ids, o.ID)
	}
	return ids
}

// timelineOf merges the alert's detections and handling steps in time
// order.
func timelineOf(a *Alert) []TimelineEvent {
	events := []TimelineEvent{{Time: a.Timestamp, Event: "告警产生", Detail: a.Title}}
	for _, step := range a.AttackPath {
		detail := step.Detail
		if step.Path != "" {
			detail = fmt.Sprintf("%s（%s）", detail, step.Path)
		}
		events = append(events, TimelineEvent{Time: step.Timestamp, Event: "检测命中", Detail: detail})
	}
	for _, h := range a.History {
		label := alertActions[h.Action].label
		if label == "" {
			label = h.Action
		}
		detail := fmt.Sprintf("%s：%s", h.Actor, label)
		if h.Note != "" {
			detail += "，" + h.Note
		}
		events = append(events, TimelineEvent{Time: h.Time, Event: "处置", Detail: detail})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	return events
}

// evidenceOf summarises what the platform observed for the alert.
func evidenceOf(a *Alert) map[string]string {
	occ := a.OccurrenceCount
	if occ < 1 {
		occ = 1
	}
	last := a.LastSeen
	if last.IsZero() {
		last = a.Timestamp
	}
	ev := map[string]string{
		"occurrences": fmt.Sprintf("%d", occ),
		"first_seen":  a.Timestamp.Format(time.RFC3339),
		"last_seen":   last.Format(time.RFC3339),
		"duration":    last.Sub(a.Timestamp).Round(time.Second).String(),
		"risk_score":  fmt.Sprintf("%d", a.RiskScore),
		"confidence":  fmt.Sprintf("%.2f", a.Confidence),
	}
	if a.SourceIP != "" {
		ev["source_ip"] = a.SourceIP
	}
	if a.AccountID != "" {
		ev["account_id"] = a.AccountID
	}
	if a.SourceRequirement != "" {
		ev["source_requirement"] = a.SourceRequirement
	}
	return ev
}

// ExecuteAction applies a handling action (see alertActions) by actor and
// records it in the alert's history. The change is saved before it is
// reported; if saving fails the alert is restored. An unknown action is an
// ErrInvalid error.
func (s *AlertService) ExecuteAction(alertID, action, actor, note string) (*Alert, error) {
	def, ok := alertActions[action]
	if !ok {
		return nil, fmt.Errorf("%w: 不支持的处置动作 %s", ErrInvalid, action)
	}
	if len(note) > 500 {
		note = note[:500]
	}
	s.mu.Lock()
	a, ok := s.alerts[alertID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("alert %s: %w", alertID, ErrNotFound)
	}
	before := *a
	before.History = append([]AlertHistory(nil), a.History...)
	now := s.now()
	a.Status = def.status
	if def.status == "in_progress" {
		a.Disposal = &DisposalInfo{Action: action, Status: "recorded", ExecutedAt: now}
	}
	a.History = append(a.History, AlertHistory{Time: now, Action: action, Status: def.status, Actor: actor, Note: note})
	if len(a.History) > maxAlertHistory {
		a.History = append([]AlertHistory(nil), a.History[len(a.History)-maxAlertHistory:]...)
	}
	if def.status == "open" {
		a.LastSeen = now // reopened: merge new detections from now on
	}
	s.mu.Unlock()

	if err := s.p.writeThrough(context.Background(), []string{alertID}, s.snapshot); err != nil {
		s.mu.Lock()
		*a = before
		s.mu.Unlock()
		return nil, fmt.Errorf("save alert %s: %w", alertID, err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := *a
	return &c, nil
}

// DayStat counts the alerts raised and closed on one calendar day.
type DayStat struct {
	Date     string `json:"date"` // YYYY-MM-DD in the platform's time zone
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Closed   int    `json:"closed"` // resolved or marked false positive
}

// Trend returns one DayStat per day for the last days days (today
// included), oldest first. An alert counts on the day it was raised; a
// closure counts on the day it was resolved or marked false positive.
func (s *AlertService) Trend(days int) []DayStat {
	if days < 1 {
		days = 1
	}
	now := s.now().In(time.Local)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	start := today.AddDate(0, 0, -(days - 1))
	out := make([]DayStat, days)
	index := make(map[string]int, days)
	for i := range out {
		d := start.AddDate(0, 0, i).Format("2006-01-02")
		out[i].Date = d
		index[d] = i
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.alerts {
		if i, ok := index[a.Timestamp.In(time.Local).Format("2006-01-02")]; ok {
			switch a.Severity {
			case "critical":
				out[i].Critical++
			case "high":
				out[i].High++
			case "medium":
				out[i].Medium++
			default:
				out[i].Low++
			}
		}
		for _, h := range a.History {
			if h.Status == "resolved" || h.Status == "false_positive" {
				if i, ok := index[h.Time.In(time.Local).Format("2006-01-02")]; ok {
					out[i].Closed++
				}
			}
		}
	}
	return out
}
