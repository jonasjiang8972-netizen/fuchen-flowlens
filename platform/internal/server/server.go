package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/apipath"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/redact"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/engine"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/iam"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/ingest"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

type PlatformServer struct {
	store          storage.Store
	iam            *iam.Service
	audit          *audit.Service
	agentService   *service.AgentService
	assetService   *service.AssetService
	alertService   *service.AlertService
	ruleService    *service.RuleService
	callerService  *service.CallerService
	topology       *service.TopologyService
	traffic        trafficCounters
	bolaEngine     *engine.BOLAEngine
	authEngine     *engine.AuthFailureEngine
	bflaEngine     *engine.BFLAEngine
	dlpEngine      *engine.DLPEngine
	botEngine      *engine.BotEngine
	rateEngine     *engine.RateEngine
	ssrfEngine     *engine.SSRFEngine
	ingestPipeline *ingest.Pipeline
	redactor       *redact.Redactor
	DemoMode       bool
	// SecureCookies sets the Secure flag on the session cookie; enable it
	// whenever the console is served over HTTPS.
	SecureCookies bool
}

type accessDetectionRequest struct {
	AccountID string `json:"account_id"`
	Role      string `json:"role"`
	Endpoint  string `json:"endpoint"`
	ObjectID  string `json:"object_id"`
	SourceIP  string `json:"source_ip"`
	Status    int    `json:"status_code"`
}

// NewPlatformServer returns a server whose business data (assets, alerts,
// rules, collectors) lives only in memory, seeded with sample data. It is
// used for development, demo mode and tests.
func NewPlatformServer(store storage.Store) *PlatformServer {
	return newServer(store, service.NewAgentService(), service.NewAssetService(),
		service.NewAlertService(), service.NewRuleService())
}

// NewPlatformServerFrom loads business data from store and persists changes
// back to it. Sample data is added only when seedDemo is set and the store
// holds none; default detection rules are always ensured.
func NewPlatformServerFrom(ctx context.Context, store storage.Store, seedDemo bool) (*PlatformServer, error) {
	agents, err := service.NewAgentServiceFrom(ctx, store, seedDemo)
	if err != nil {
		return nil, err
	}
	assets, err := service.NewAssetServiceFrom(ctx, store, seedDemo)
	if err != nil {
		return nil, err
	}
	alerts, err := service.NewAlertServiceFrom(ctx, store, seedDemo)
	if err != nil {
		return nil, err
	}
	rules, err := service.NewRuleServiceFrom(ctx, store)
	if err != nil {
		return nil, err
	}
	return newServer(store, agents, assets, alerts, rules), nil
}

func newServer(store storage.Store, agents *service.AgentService, assets *service.AssetService,
	alerts *service.AlertService, rules *service.RuleService) *PlatformServer {
	auditSvc := audit.New(store)
	auditSvc.SetSettings(store)
	srv := &PlatformServer{
		store:         store,
		audit:         auditSvc,
		iam:           iam.NewService(store, auditSvc),
		agentService:  agents,
		assetService:  assets,
		alertService:  alerts,
		ruleService:   rules,
		callerService: service.NewCallerService(),
		topology:      service.NewTopologyService(),
		bolaEngine:    engine.NewBOLAEngine(store),
		authEngine:    engine.NewAuthFailureEngine(store),
		bflaEngine:    engine.NewBFLAEngine(store),
		dlpEngine:     engine.NewDLPEngine(store),
		botEngine:     engine.NewBotEngine(store),
		rateEngine:    engine.NewRateEngine(store),
		ssrfEngine:    engine.NewSSRFEngine(store),
		redactor:      redact.New(""),
	}
	srv.applyAllRuleConfigs()
	srv.ingestPipeline = ingest.NewPipeline(20000, srv.processIngestEvent)
	return srv
}

// FlushAll persists business records changed by traffic since the last
// flush (asset statistics, alert merges, rule hits, heartbeats).
func (s *PlatformServer) FlushAll(ctx context.Context) error {
	var errs []error
	for name, flush := range map[string]func(context.Context) (int, error){
		"assets": s.assetService.Flush, "alerts": s.alertService.Flush,
		"rules": s.ruleService.Flush, "agents": s.agentService.Flush,
	} {
		if _, err := flush(ctx); err != nil {
			errs = append(errs, fmt.Errorf("flush %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *PlatformServer) StartEngines(ctx context.Context) {
	go s.bolaEngine.StartCleanup(ctx)
	go s.authEngine.StartCleanup(ctx)
	go s.botEngine.StartCleanup(ctx)
	go s.rateEngine.StartCleanup(ctx)
	s.ingestPipeline.Start(ctx, 4)
	logger.L().Info("Detection engines started")
}

// ─── Agent Management ──────────────────────────────────────────

func (s *PlatformServer) RegisterAgentHandler(c *gin.Context) {
	var req struct {
		AgentID      string               `json:"agent_id"`
		Hostname     string               `json:"hostname"`
		CollectMode  string               `json:"collect_mode"`
		Cluster      string               `json:"cluster"`
		AgentVersion string               `json:"agent_version"`
		OS           string               `json:"os"`
		Arch         string               `json:"arch"`
		Config       *service.AgentConfig `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	id, err := s.agentService.RegisterAgent(service.Registration{
		ID: req.AgentID, Hostname: req.Hostname, CollectMode: req.CollectMode, Cluster: req.Cluster,
		Version: req.AgentVersion, OS: req.OS, Arch: req.Arch, Config: req.Config,
	})
	if err != nil {
		logger.L().Errorf("agent register: %v", err)
		c.JSON(500, gin.H{"error": "保存采集器注册信息失败"})
		return
	}
	s.recordAgentEvent(c, "agent.register", id, fmt.Sprintf("hostname=%s mode=%s cluster=%s version=%s", req.Hostname, req.CollectMode, req.Cluster, req.AgentVersion))
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
	err := s.agentService.Heartbeat(id, service.HeartbeatReport{
		Status: req.Status, QPS: req.QPS, CPUPercent: req.CPUPercent,
		MemoryMB: req.MemoryMB, DropRate: req.DropRate, CollectMode: req.CollectMode,
	})
	if errors.Is(err, service.ErrNotFound) {
		// The collector registers again on 404.
		c.JSON(404, gin.H{"error": "采集器未注册"})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

// ─── Health ────────────────────────────────────────────────────

// startedAt is the process start time reported as uptime by /health.
var startedAt = time.Now()

func (s *PlatformServer) HealthHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "ok",
		"version": version.Version,
		"uptime":  int64(time.Since(startedAt).Seconds()),
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
		serviceErr(c, err)
		return
	}
	c.JSON(200, detail)
}

func (s *PlatformServer) AgentHealthSummaryHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"total_agents":  s.agentService.TotalCount(),
		"online":        s.agentService.OnlineCount(),
		"offline":       s.agentService.OfflineCount(),
		"degraded":      s.agentService.DegradedCount(),
		"total_qps":     156230,
		"avg_drop_rate": 0.008,
	})
}

// ─── Assets ────────────────────────────────────────────────────

func (s *PlatformServer) ListAssetsHandler(c *gin.Context) {
	assets := s.assetService.List()
	c.JSON(200, gin.H{
		"total":            len(assets),
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
		serviceErr(c, err)
		return
	}
	detail.Alerts = s.alertService.ForEndpoint(detail.Method + " " + detail.PathNormalized)
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
		serviceErr(c, err)
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
		serviceErr(c, err)
		return
	}
	c.JSON(200, detail)
}

func (s *PlatformServer) AlertActionHandler(c *gin.Context) {
	var req struct {
		Note string `json:"note"`
	}
	_ = c.ShouldBindJSON(&req)
	actor := "system"
	if p := auth.Principal(c); p != nil {
		actor = p.Username
	}
	alert, err := s.alertService.ExecuteAction(c.Param("id"), c.Param("action"), actor, strings.TrimSpace(req.Note))
	if err != nil {
		serviceErr(c, err)
		return
	}
	c.JSON(200, alert)
}

// ─── Ingest Pipeline ───────────────────────────────────────────

func (s *PlatformServer) IngestEventHandler(c *gin.Context) {
	var evt shared.APIEvent
	if err := c.ShouldBindJSON(&evt); err != nil {
		c.JSON(400, gin.H{"error": "invalid event"})
		return
	}
	result := s.ingestPipeline.Submit(c.Request.Context(), []shared.APIEvent{evt})
	c.JSON(ingestStatus(result), result)
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
	c.JSON(ingestStatus(result), result)
}

// ingestStatus returns 503 when nothing was accepted because the queue was
// full, so clients can back off; partial drops are reported in the body.
func ingestStatus(r ingest.SubmitResult) int {
	if r.Accepted == 0 && r.Dropped > 0 {
		return 503
	}
	return 202
}

func (s *PlatformServer) IngestMetricsHandler(c *gin.Context) {
	c.JSON(200, s.ingestPipeline.Metrics())
}

// SetRedactionKey sets the key for credential fingerprints; use the agent
// token so platform and collector fingerprints match.
func (s *PlatformServer) SetRedactionKey(key string) { s.redactor = redact.New(key) }

func (s *PlatformServer) processIngestEvent(ctx context.Context, evt shared.APIEvent) {
	// Split the query first so its values are redacted parameter by
	// parameter. Safety net: collectors redact before sending, but never
	// rely on it.
	normalizeIngestEvent(&evt)
	s.redactor.Event(&evt)
	principal := resolvePrincipal(evt)
	sensitiveFields := classifySensitiveFields(evt)
	s.assetService.ObserveEvent(evt, sensitiveFields)
	s.callerService.Observe(principal.ID, principal.Type, principal.Role, strings.Join(principal.Evidence, ","),
		principal.Confidence, evt.Application.Method+" "+evt.Application.PathNormalized, evt.Network.SrcIP,
		int(evt.Application.StatusCode))
	backend := evt.Metadata.ServiceName
	if backend == "" {
		backend = evt.Network.DstIP
	}
	host := evt.Application.Host
	if host == "" {
		host = evt.Network.DstIP
	}
	s.topology.Observe(principal.Type, host, backend, int(evt.Application.StatusCode))
	s.traffic.events.Add(1)
	if len(evt.Content.ResponseBody) > 0 {
		s.traffic.withBody.Add(1)
	}
	if principal.Type != "network_principal" && principal.Type != "unknown" {
		s.traffic.identified.Add(1)
	}

	req := accessDetectionRequest{
		AccountID: principal.ID,
		Role:      principal.Role,
		Endpoint:  evt.Application.PathNormalized,
		ObjectID:  objectIDFromEvent(evt),
		SourceIP:  evt.Network.SrcIP,
		Status:    int(evt.Application.StatusCode),
	}
	findings := s.evaluateAll(detectInput{
		req:       req,
		sensitive: exposedSensitiveFields(evt),
		method:    evt.Application.Method,
		query:     evt.Content.QueryParams,
		body:      evt.Content.RequestBody,
		at:        evt.Timestamp,

		networkOnly: principal.Type == "network_principal",
	})
	for _, d := range findings {
		s.raise(d, req, principal.Confidence)
	}

	if evt.AgentID != "" {
		s.agentService.SeenTraffic(evt.AgentID, evt.Application.Method+" "+evt.Application.PathNormalized)
	}
}

// ─── Detection Engine Adapters ─────────────────────────────────

// RecordAccessHandler runs the detection engines on one access described in
// the request body, as traffic would, and raises an alert when warranted.
func (s *PlatformServer) RecordAccessHandler(c *gin.Context) {
	var req accessDetectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	var d detection
	var alert *service.Alert
	for _, f := range s.evaluateAll(detectInput{req: req}) {
		a := s.raise(f, req, 0.86)
		if f.Score > d.Score {
			d, alert = f, a
		}
	}
	c.JSON(200, gin.H{
		"risk_score": d.Score,
		"reason":     d.Reason,
		"rule_id":    d.RuleID,
		"evaluated":  d.Score > 0,
		"alert":      alert,
	})
}

type resolvedPrincipal struct {
	ID         string
	Type       string
	Role       string
	Confidence float64
	Evidence   []string
}

// normalizeIngestEvent splits any query string off the request path into
// QueryParams and recomputes the API template of the path. The platform's
// template is authoritative so assets group the same way whatever collector
// (or collector version) sent the event.
func normalizeIngestEvent(evt *shared.APIEvent) {
	path, query := apipath.Split(evt.Application.PathRaw)
	evt.Application.PathRaw = path
	if len(query) > 0 {
		if evt.Content.QueryParams == nil {
			evt.Content.QueryParams = make(map[string]string, len(query))
		}
		for k, v := range query {
			if _, ok := evt.Content.QueryParams[k]; !ok {
				evt.Content.QueryParams[k] = v
			}
		}
	}
	if path != "" {
		evt.Application.PathNormalized = apipath.Normalize(path)
	} else {
		evt.Application.PathNormalized = apipath.Normalize(evt.Application.PathNormalized)
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

// shortToken shortens a credential for use as a caller ID. Collectors
// replace credentials with keyed SM3 fingerprints ("sm3:<hex>"); those keep
// a 12-digit prefix, which is stable per credential. Anything else keeps
// only its first and last four characters.
func shortToken(value string) string {
	if fp, ok := strings.CutPrefix(value, "sm3:"); ok {
		if len(fp) > 12 {
			fp = fp[:12]
		}
		return "sm3:" + fp
	}
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

// classifySensitiveFields lists the sensitive field names an event carries
// anywhere (query, request headers, response body), for the asset
// inventory.
func classifySensitiveFields(evt shared.APIEvent) []string {
	seen := map[string]bool{}
	for key := range evt.Content.QueryParams {
		if isSensitiveName(key) {
			seen[key] = true
		}
	}
	for key := range evt.Content.RequestHeaders {
		if isSensitiveName(key) {
			seen[key] = true
		}
	}
	for _, key := range responseFieldNames(evt.Content.ResponseBody) {
		if isSensitiveName(key) {
			seen[key] = true
		}
	}
	return sortedKeys(seen)
}

// exposedSensitiveFields lists the sensitive field names an endpoint exposes:
// fields of the response body and query parameters (sensitive data in URLs
// ends up in logs). Request headers are left out: an Authorization or API
// key header is the caller's own credential, not exposed data.
func exposedSensitiveFields(evt shared.APIEvent) []string {
	seen := map[string]bool{}
	for key := range evt.Content.QueryParams {
		if isSensitiveName(key) {
			seen[key] = true
		}
	}
	for _, key := range responseFieldNames(evt.Content.ResponseBody) {
		if isSensitiveName(key) {
			seen[key] = true
		}
	}
	return sortedKeys(seen)
}

func isSensitiveName(name string) bool {
	return engine.SensitiveType(name) != ""
}

// Bounds for walking a response body.
const (
	maxBodyScan   = 256 << 10
	maxFieldNames = 500
	maxJSONDepth  = 8
)

// responseFieldNames returns the object keys of a JSON response body
// (nested, bounded). For a non-JSON body it falls back to a keyword scan.
func responseFieldNames(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	if len(body) > maxBodyScan {
		body = body[:maxBodyScan]
	}
	var doc interface{}
	if err := json.Unmarshal(body, &doc); err == nil {
		seen := map[string]bool{}
		collectKeys(doc, 0, seen)
		return sortedKeys(seen)
	}
	text := strings.ToLower(string(body))
	var found []string
	for _, marker := range []string{"phone", "mobile", "id_card", "card_number", "bank_card", "password", "token", "secret", "address", "email"} {
		if strings.Contains(text, marker) {
			found = append(found, marker)
		}
	}
	return found
}

func collectKeys(v interface{}, depth int, seen map[string]bool) {
	if depth > maxJSONDepth || len(seen) >= maxFieldNames {
		return
	}
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			if len(seen) >= maxFieldNames {
				return
			}
			seen[k] = true
			collectKeys(child, depth+1, seen)
		}
	case []interface{}:
		// Elements of an array usually share a shape; a few are enough.
		for i, child := range t {
			if i >= 5 {
				break
			}
			collectKeys(child, depth+1, seen)
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func objectIDFromEvent(evt shared.APIEvent) string {
	for _, key := range []string{"object_id", "order_id", "user_id", "id"} {
		if v := evt.Content.QueryParams[key]; v != "" {
			return v
		}
	}
	parts := strings.Split(evt.Application.PathRaw, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if apipath.IsIdentifier(parts[i]) {
			return parts[i]
		}
	}
	return evt.Application.PathNormalized
}

// ─── Detection Events ──────────────────────────────────────────

func (s *PlatformServer) ListDetectionEventsHandler(c *gin.Context) {
	events, err := s.store.ListRecentAlerts(c.Request.Context(), time.Now().Add(-24*time.Hour), 1000)
	if err != nil {
		serviceErr(c, err)
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
		serviceErr(c, err)
		return
	}
	c.JSON(200, rule)
}

func (s *PlatformServer) UpdateRuleHandler(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Enabled *bool                  `json:"enabled"`
		Config  map[string]interface{} `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if req.Enabled != nil {
		rule, err := s.ruleService.UpdateEnabled(id, *req.Enabled)
		if err != nil {
			serviceErr(c, err)
			return
		}
		c.JSON(200, rule)
		return
	}

	if req.Config != nil {
		rule, err := s.ruleService.UpdateConfig(id, req.Config)
		if err != nil {
			serviceErr(c, err)
			return
		}
		s.applyRuleConfig(id)
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

// serviceErr maps service errors to responses without exposing internal
// details (such as database errors) to the client.
func serviceErr(c *gin.Context, err error) {
	if errors.Is(err, service.ErrNotFound) {
		c.JSON(404, gin.H{"error": "记录不存在"})
		return
	}
	if errors.Is(err, service.ErrInvalid) {
		c.JSON(400, gin.H{"error": strings.TrimPrefix(err.Error(), service.ErrInvalid.Error()+": ")})
		return
	}
	logger.L().Errorf("%s %s: %v", c.Request.Method, c.Request.URL.Path, err)
	c.JSON(500, gin.H{"error": "保存失败，请稍后重试"})
}
