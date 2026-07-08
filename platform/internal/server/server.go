package server

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/engine"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/ingest"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
	"golang.org/x/crypto/bcrypt"
)

type PlatformServer struct {
	store         storage.Store
	agentService  *service.AgentService
	assetService  *service.AssetService
	alertService  *service.AlertService
	ruleService   *service.RuleService
	bolaEngine    *engine.BOLAEngine
	authEngine    *engine.AuthFailureEngine
	bflaEngine    *engine.BFLAEngine
	ingestPipeline *ingest.Pipeline
	DemoMode      bool
}

type accessDetectionRequest struct {
	AccountID string `json:"account_id"`
	Role      string `json:"role"`
	Endpoint  string `json:"endpoint"`
	ObjectID  string `json:"object_id"`
	SourceIP  string `json:"source_ip"`
	Status    int    `json:"status_code"`
}

func NewPlatformServer(store storage.Store) *PlatformServer {
	srv := &PlatformServer{
		store:        store,
		agentService: service.NewAgentService(),
		assetService: service.NewAssetService(),
		alertService: service.NewAlertService(),
		ruleService:  service.NewRuleService(),
		bolaEngine:   engine.NewBOLAEngine(store),
		authEngine:   engine.NewAuthFailureEngine(store),
		bflaEngine:   engine.NewBFLAEngine(store),
	}
	srv.ingestPipeline = ingest.NewPipeline(20000, srv.processIngestEvent)
	return srv
}

func (s *PlatformServer) StartEngines(ctx context.Context) {
	go s.bolaEngine.StartCleanup(ctx)
	go s.authEngine.StartCleanup(ctx)
	s.ingestPipeline.Start(ctx, 4)
	logger.L().Info("Detection engines started")
}

// ─── Auth ──────────────────────────────────────────────────────

func (s *PlatformServer) LoginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	user, err := s.store.GetUserByUsername(context.Background(), req.Username)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role, user.TenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": "token generation failed"})
		return
	}
	c.JSON(200, gin.H{
		"token":    token,
		"user":     user.Username,
		"role":     user.Role,
		"tenant":   user.TenantID,
	})
}

// ─── Agent Management ──────────────────────────────────────────

func (s *PlatformServer) RegisterAgentHandler(c *gin.Context) {
	var req struct {
		AgentID      string  `json:"agent_id"`
		Hostname     string  `json:"hostname"`
		CollectMode  string  `json:"collect_mode"`
		Cluster      string  `json:"cluster"`
		AgentVersion string  `json:"agent_version"`
		OS           string  `json:"os"`
		CPUPercent   float64 `json:"cpu_percent"`
		MemoryMB     uint64  `json:"memory_mb"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	id := s.agentService.RegisterWithID(req.AgentID, req.Hostname, req.CollectMode, req.Cluster)
	c.JSON(200, gin.H{"agent_id": id, "status": "registered"})
}

func (s *PlatformServer) HeartbeatHandler(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status      string  `json:"status"`
		QPS         float64 `json:"qps"`
		CPUPercent  float64 `json:"cpu_percent"`
		MemoryMB    uint64  `json:"memory_mb"`
		DropRate    float64 `json:"drop_rate"`
		CollectMode string  `json:"collect_mode"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	s.agentService.UpdateHeartbeat(id)
	c.JSON(200, gin.H{"status": "ok"})
}

// ─── Health ────────────────────────────────────────────────────

func (s *PlatformServer) HealthHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "ok",
		"version": version.Version,
		"uptime":  time.Now().Unix(),
	})
}

// ─── Agents ────────────────────────────────────────────────────

func (s *PlatformServer) ListAgentsHandler(c *gin.Context) {
	agents := s.agentService.List()
	c.JSON(200, gin.H{
		"total":          len(agents),
		"online_count":   s.agentService.OnlineCount(),
		"offline_count":  s.agentService.OfflineCount(),
		"degraded_count": s.agentService.DegradedCount(),
		"items":          agents,
	})
}

func (s *PlatformServer) GetAgentHandler(c *gin.Context) {
	id := c.Param("id")
	detail, err := s.agentService.GetDetail(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, detail)
}

func (s *PlatformServer) AgentHealthSummaryHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"total_agents":   s.agentService.TotalCount(),
		"online":         s.agentService.OnlineCount(),
		"offline":        s.agentService.OfflineCount(),
		"degraded":       s.agentService.DegradedCount(),
		"total_qps":      156230,
		"avg_drop_rate":  0.008,
	})
}

// ─── Assets ────────────────────────────────────────────────────

func (s *PlatformServer) ListAssetsHandler(c *gin.Context) {
	assets := s.assetService.List()
	c.JSON(200, gin.H{
		"total":           len(assets),
		"high_sensitivity": countBySensitivity(assets, "high"),
		"shadow_count":     countByStatus(assets, "shadow"),
		"zombie_count":     countByStatus(assets, "zombie"),
		"unclaimed_count":  countByClaim(assets, "unclaimed"),
		"items":            assets,
	})
}

func (s *PlatformServer) GetAssetHandler(c *gin.Context) {
	id := c.Param("id")
	detail, err := s.assetService.GetDetail(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, detail)
}

func (s *PlatformServer) ClaimAssetHandler(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Owner string `json:"owner"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := s.assetService.Claim(id, req.Owner); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

// ─── Alerts ────────────────────────────────────────────────────

func (s *PlatformServer) ListAlertsHandler(c *gin.Context) {
	alerts := s.alertService.List()
	c.JSON(200, gin.H{
		"total":          len(alerts),
		"critical_count": countBySeverity(alerts, "critical"),
		"high_count":     countBySeverity(alerts, "high"),
		"medium_count":   countBySeverity(alerts, "medium"),
		"low_count":      countBySeverity(alerts, "low"),
		"open_count":     countByAlertStatus(alerts, "open"),
		"items":          alerts,
	})
}

func (s *PlatformServer) GetAlertHandler(c *gin.Context) {
	id := c.Param("id")
	detail, err := s.alertService.GetDetail(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, detail)
}

func (s *PlatformServer) AlertActionHandler(c *gin.Context) {
	id := c.Param("id")
	action := c.Param("action")
	var req struct {
		Target          string `json:"target"`
		DurationMinutes int    `json:"duration_minutes"`
	}
	c.ShouldBindJSON(&req)
	if err := s.alertService.ExecuteAction(id, action, req.Target, req.DurationMinutes); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok", "action": action})
}

// ─── Ingest Pipeline ───────────────────────────────────────────

func (s *PlatformServer) IngestEventHandler(c *gin.Context) {
	var evt shared.APIEvent
	if err := c.ShouldBindJSON(&evt); err != nil {
		c.JSON(400, gin.H{"error": "invalid event"})
		return
	}
	result := s.ingestPipeline.Submit(c.Request.Context(), []shared.APIEvent{evt})
	c.JSON(202, result)
}

func (s *PlatformServer) IngestBatchHandler(c *gin.Context) {
	var req struct {
		Events []shared.APIEvent `json:"events"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid batch"})
		return
	}
	if len(req.Events) == 0 {
		c.JSON(400, gin.H{"error": "empty batch"})
		return
	}
	if len(req.Events) > 5000 {
		c.JSON(413, gin.H{"error": "batch too large"})
		return
	}
	result := s.ingestPipeline.Submit(c.Request.Context(), req.Events)
	c.JSON(202, result)
}

func (s *PlatformServer) IngestMetricsHandler(c *gin.Context) {
	c.JSON(200, s.ingestPipeline.Metrics())
}

func (s *PlatformServer) processIngestEvent(ctx context.Context, evt shared.APIEvent) {
	normalizeIngestEvent(&evt)
	principal := resolvePrincipal(evt)
	sensitiveFields := classifySensitiveFields(evt)
	s.assetService.ObserveEvent(evt, sensitiveFields)

	req := accessDetectionRequest{
		AccountID: principal.ID,
		Role:      principal.Role,
		Endpoint:  evt.Application.PathNormalized,
		ObjectID:  objectIDFromEvent(evt),
		SourceIP:  evt.Network.SrcIP,
		Status:    int(evt.Application.StatusCode),
	}

	s.bflaEngine.RecordAccess(req.AccountID, req.Role, req.Endpoint)
	if req.Status == 401 {
		s.authEngine.RecordFailure(req.SourceIP, req.AccountID)
	}

	riskScore := 0
	reason := ""
	bolaScore, bolaReason := s.bolaEngine.Evaluate(req.AccountID, req.ObjectID, req.Endpoint, req.SourceIP)
	if bolaScore > riskScore {
		riskScore = bolaScore
		reason = bolaReason
	}
	authScore, authReason := s.authEngine.Evaluate(req.SourceIP)
	if authScore > riskScore {
		riskScore = authScore
		reason = authReason
	}
	bflaScore, bflaReason := s.bflaEngine.Evaluate(req.AccountID, req.Role, req.Endpoint)
	if bflaScore > riskScore {
		riskScore = bflaScore
		reason = bflaReason
	}
	if len(sensitiveFields) > 0 && strings.Contains(strings.ToLower(evt.Application.PathNormalized), "export") && riskScore < 75 {
		riskScore = 75
		reason = "敏感数据导出接口出现真实流量"
	}

	if riskScore >= 70 {
		sourceRequirement, severity, title := detectionMetadata(riskScore, reason, req)
		if len(sensitiveFields) > 0 && strings.Contains(reason, "敏感数据") {
			sourceRequirement = "FR-DLP-003"
			title = "敏感数据接口自动告警"
		}
		s.alertService.CreateDetectionAlert(sourceRequirement, severity, title, reason, req.SourceIP, req.AccountID, riskScore, principal.Confidence)
		s.ruleService.IncrementHit(ruleIDForRequirement(sourceRequirement))
	}

	if evt.AgentID != "" {
		s.agentService.UpdateHeartbeat(evt.AgentID)
		_ = s.store.UpdateAgentHeartbeat(ctx, evt.AgentID, time.Now())
	}
}

// ─── Detection Engine Adapters ─────────────────────────────────

func (s *PlatformServer) RecordAccessHandler(c *gin.Context) {
	var req accessDetectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	s.bflaEngine.RecordAccess(req.AccountID, req.Role, req.Endpoint)

	if req.Status == 401 {
		s.authEngine.RecordFailure(req.SourceIP, req.AccountID)
	}

	riskScore := 0
	reason := ""

	bolaScore, bolaReason := s.bolaEngine.Evaluate(req.AccountID, req.ObjectID, req.Endpoint, req.SourceIP)
	if bolaScore > riskScore {
		riskScore = bolaScore
		reason = bolaReason
	}

	authScore, authReason := s.authEngine.Evaluate(req.SourceIP)
	if authScore > riskScore {
		riskScore = authScore
		reason = authReason
	}

	bflaScore, bflaReason := s.bflaEngine.Evaluate(req.AccountID, req.Role, req.Endpoint)
	if bflaScore > riskScore {
		riskScore = bflaScore
		reason = bflaReason
	}

	var alert *service.Alert
	if riskScore >= 70 {
		sourceRequirement, severity, title := detectionMetadata(riskScore, reason, req)
		created := s.alertService.CreateDetectionAlert(
			sourceRequirement,
			severity,
			title,
			reason,
			req.SourceIP,
			req.AccountID,
			riskScore,
			0.86,
		)
		alert = &created
		s.ruleService.IncrementHit(ruleIDForRequirement(sourceRequirement))
	}

	c.JSON(200, gin.H{
		"risk_score": riskScore,
		"reason":     reason,
		"evaluated":  riskScore > 0,
		"alert":      alert,
	})
}

func detectionMetadata(riskScore int, reason string, req accessDetectionRequest) (string, string, string) {
	severity := "high"
	if riskScore >= 90 {
		severity = "critical"
	}
	if req.Status == 401 {
		return "FR-DET-002", severity, "认证失败/撞库风险自动告警"
	}
	if req.Endpoint != "" && isAdminEndpointPath(req.Endpoint) {
		return "FR-DET-005", severity, "BFLA 越权访问自动告警"
	}
	if reason != "" {
		return "FR-DET-001", severity, "BOLA 对象遍历自动告警"
	}
	return "FR-ALT-001", severity, "高风险访问自动告警"
}

func isAdminEndpointPath(endpoint string) bool {
	adminPrefixes := []string{"/admin", "/api/v1/admin", "/api/v1/system", "/api/v1/users/roles", "/manage", "/supervisor", "/actuator", "/swagger-ui", "/api/v1/audit"}
	for _, prefix := range adminPrefixes {
		if len(endpoint) >= len(prefix) && endpoint[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func ruleIDForRequirement(requirement string) string {
	switch requirement {
	case "FR-DET-001":
		return "R-BOLA-001"
	case "FR-DET-002":
		return "R-AUTH-001"
	case "FR-DET-005":
		return "R-BFLA-001"
	case "FR-DLP-001", "FR-DLP-003":
		return "R-DLP-001"
	default:
		return ""
	}
}

type resolvedPrincipal struct {
	ID         string
	Type       string
	Role       string
	Confidence float64
	Evidence   []string
}

func normalizeIngestEvent(evt *shared.APIEvent) {
	if evt.Application.PathNormalized == "" {
		evt.Application.PathNormalized = normalizePath(evt.Application.PathRaw)
	}
	if evt.Application.Method == "" {
		evt.Application.Method = "GET"
	}
	if evt.Application.ProtocolType == "" {
		evt.Application.ProtocolType = "REST"
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}
}

func normalizePath(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if looksLikeID(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func looksLikeID(value string) bool {
	if len(value) >= 8 && strings.Contains(value, "-") {
		return true
	}
	if len(value) >= 3 {
		allDigits := true
		for _, r := range value {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		return allDigits
	}
	return false
}

func resolvePrincipal(evt shared.APIEvent) resolvedPrincipal {
	headers := evt.Content.RequestHeaders
	if headers == nil {
		headers = map[string]string{}
	}
	query := evt.Content.QueryParams
	if query == nil {
		query = map[string]string{}
	}

	if v := firstNonEmpty(headers, "x-user-id", "x-account-id", "x-authenticated-user"); v != "" {
		return resolvedPrincipal{ID: v, Type: "external_user", Role: firstNonEmpty(headers, "x-user-role", "x-role"), Confidence: 0.92, Evidence: []string{"gateway_header"}}
	}
	if v := firstNonEmpty(headers, "x-api-key", "x-client-id", "x-app-id"); v != "" {
		return resolvedPrincipal{ID: "partner:" + shortToken(v), Type: "partner", Role: "partner", Confidence: 0.9, Evidence: []string{"api_key"}}
	}
	if v := firstNonEmpty(headers, "x-service-name", "x-caller-service"); v != "" {
		return resolvedPrincipal{ID: "svc:" + v, Type: "internal_service", Role: "service", Confidence: 0.95, Evidence: []string{"service_header"}}
	}
	if v := firstNonEmpty(query, "user_id", "account_id", "uid"); v != "" {
		return resolvedPrincipal{ID: v, Type: "external_user", Role: "user", Confidence: 0.78, Evidence: []string{"query_param"}}
	}
	if evt.Network.SrcIP != "" {
		return resolvedPrincipal{ID: "ip:" + evt.Network.SrcIP, Type: "network_principal", Role: networkRole(evt.Network.SrcIP), Confidence: 0.55, Evidence: []string{"source_ip"}}
	}
	return resolvedPrincipal{ID: "unknown", Type: "unknown", Role: "unknown", Confidence: 0.3, Evidence: []string{"none"}}
}

func firstNonEmpty(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if v := values[key]; v != "" {
			return v
		}
		for existing, v := range values {
			if strings.EqualFold(existing, key) && v != "" {
				return v
			}
		}
	}
	return ""
}

func shortToken(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:4] + "..." + value[len(value)-4:]
}

func networkRole(ip string) string {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "172.") {
		return "internal"
	}
	return "external"
}

func classifySensitiveFields(evt shared.APIEvent) []string {
	seen := map[string]bool{}
	add := func(field string) {
		if field != "" {
			seen[field] = true
		}
	}
	for key := range evt.Content.QueryParams {
		if isSensitiveName(key) {
			add(key)
		}
	}
	for key := range evt.Content.RequestHeaders {
		if isSensitiveName(key) {
			add(key)
		}
	}
	bodyText := strings.ToLower(string(evt.Content.ResponseBody))
	for _, marker := range []string{"phone", "mobile", "id_card", "card_number", "token", "password", "address", "email"} {
		if strings.Contains(bodyText, marker) {
			add(marker)
		}
	}
	result := make([]string, 0, len(seen))
	for field := range seen {
		result = append(result, field)
	}
	return result
}

func isSensitiveName(name string) bool {
	n := strings.ToLower(name)
	for _, marker := range []string{"phone", "mobile", "id_card", "card", "token", "password", "secret", "address", "email"} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}

func objectIDFromEvent(evt shared.APIEvent) string {
	for _, key := range []string{"object_id", "order_id", "user_id", "id"} {
		if v := evt.Content.QueryParams[key]; v != "" {
			return v
		}
	}
	parts := strings.Split(evt.Application.PathRaw, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if looksLikeID(parts[i]) {
			return parts[i]
		}
	}
	return evt.Application.PathNormalized
}

// ─── Detection Events ──────────────────────────────────────────

func (s *PlatformServer) ListDetectionEventsHandler(c *gin.Context) {
	events, err := s.store.ListRecentAlerts(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"total": len(events),
		"items": events,
	})
}

// ─── Rules Management ────────────────────────────────────────

func (s *PlatformServer) ListRulesHandler(c *gin.Context) {
	category := c.Query("category")
	var rules []service.Rule
	if category != "" {
		rules = s.ruleService.ListByCategory(category)
	} else {
		rules = s.ruleService.List()
	}
	c.JSON(200, gin.H{
		"total": len(rules),
		"items": rules,
	})
}

func (s *PlatformServer) GetRuleHandler(c *gin.Context) {
	id := c.Param("id")
	rule, err := s.ruleService.Get(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, rule)
}

func (s *PlatformServer) UpdateRuleHandler(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled *bool                     `json:"enabled"`
		Config  map[string]interface{}    `json:"config"`
		Params  []service.RuleParam       `json:"params"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if req.Enabled != nil {
		rule, err := s.ruleService.UpdateEnabled(id, *req.Enabled)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, rule)
		return
	}

	if req.Config != nil || req.Params != nil {
		rule, err := s.ruleService.UpdateConfig(id, req.Config, req.Params)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, rule)
		return
	}

	c.JSON(400, gin.H{"error": "no update fields provided"})
}

func (s *PlatformServer) HitRuleHandler(c *gin.Context) {
	id := c.Param("id")
	s.ruleService.IncrementHit(id)
	c.JSON(200, gin.H{"status": "ok"})
}

// ─── Categories ────────────────────────────────────────────────

func (s *PlatformServer) ListRuleCategoriesHandler(c *gin.Context) {
	categories := []string{"越权访问", "身份安全", "数据安全", "业务风控", "可用性", "注入攻击", "配置错误"}
	c.JSON(200, gin.H{"items": categories})
}

// ─── Audit Logs ────────────────────────────────────────────────

func (s *PlatformServer) ListAuditLogsHandler(c *gin.Context) {
	logs, err := s.store.ListAuditLogs(context.Background(), 100)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"total": len(logs),
		"items": logs,
	})
}

// ─── Flow Map ──────────────────────────────────────────────────

func (s *PlatformServer) FlowMapHandler(c *gin.Context) {
	nodes := []map[string]interface{}{
		{"id": "user-service", "type": "service", "label": "用户服务"},
		{"id": "order-service", "type": "service", "label": "订单服务"},
		{"id": "phone", "type": "field", "label": "手机号"},
		{"id": "id_card", "type": "field", "label": "身份证"},
	}
	edges := []map[string]interface{}{
		{"source": "user-service", "target": "phone", "field_name": "phone", "call_count": 45230},
		{"source": "user-service", "target": "id_card", "field_name": "id_card", "call_count": 1200},
		{"source": "order-service", "target": "phone", "field_name": "phone", "call_count": 28720},
	}
	c.JSON(200, gin.H{"nodes": nodes, "edges": edges})
}
