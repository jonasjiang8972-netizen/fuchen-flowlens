package server

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/engine"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type PlatformServer struct {
	store         storage.Store
	agentService  *service.AgentService
	assetService  *service.AssetService
	alertService  *service.AlertService
	bolaEngine    *engine.BOLAEngine
	authEngine    *engine.AuthFailureEngine
	bflaEngine    *engine.BFLAEngine
}

func NewPlatformServer(store storage.Store) *PlatformServer {
	return &PlatformServer{
		store:        store,
		agentService: service.NewAgentService(),
		assetService: service.NewAssetService(),
		alertService: service.NewAlertService(),
		bolaEngine:   engine.NewBOLAEngine(store),
		authEngine:   engine.NewAuthFailureEngine(store),
		bflaEngine:   engine.NewBFLAEngine(store),
	}
}

func (s *PlatformServer) StartEngines(ctx context.Context) {
	go s.bolaEngine.StartCleanup(ctx)
	go s.authEngine.StartCleanup(ctx)
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
	id := s.agentService.Register(req.Hostname, req.CollectMode, req.Cluster)
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

// ─── Detection Engine Adapters ─────────────────────────────────

func (s *PlatformServer) RecordAccessHandler(c *gin.Context) {
	var req struct {
		AccountID string `json:"account_id"`
		Role      string `json:"role"`
		Endpoint  string `json:"endpoint"`
		ObjectID  string `json:"object_id"`
		SourceIP  string `json:"source_ip"`
		Status    int    `json:"status_code"`
	}
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

	c.JSON(200, gin.H{
		"risk_score": riskScore,
		"reason":     reason,
		"evaluated":  riskScore > 0,
	})
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
