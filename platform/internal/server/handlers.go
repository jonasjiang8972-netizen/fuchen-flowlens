package server

import (
	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
)

var agentService = service.NewAgentService()
var assetService = service.NewAssetService()
var alertService = service.NewAlertService()

func HealthHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "ok",
		"version": version.Version,
		"uptime":  0,
	})
}

func ListAgentsHandler(c *gin.Context) {
	agents := agentService.List()
	c.JSON(200, gin.H{
		"total":         len(agents),
		"online_count":  agentService.OnlineCount(),
		"offline_count": agentService.OfflineCount(),
		"degraded_count": agentService.DegradedCount(),
		"items":         agents,
	})
}

func GetAgentHandler(c *gin.Context) {
	id := c.Param("id")
	detail, err := agentService.GetDetail(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, detail)
}

func AgentHealthSummaryHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"total_agents":   agentService.TotalCount(),
		"online":         agentService.OnlineCount(),
		"offline":        agentService.OfflineCount(),
		"degraded":       agentService.DegradedCount(),
		"total_qps":      156230,
		"avg_drop_rate":  0.008,
	})
}

func ListAssetsHandler(c *gin.Context) {
	assets := assetService.List()
	c.JSON(200, gin.H{
		"total":            len(assets),
		"high_sensitivity": countBySensitivity(assets, "high"),
		"shadow_count":     countByStatus(assets, "shadow"),
		"zombie_count":     countByStatus(assets, "zombie"),
		"unclaimed_count":  countByClaim(assets, "unclaimed"),
		"items":            assets,
	})
}

func GetAssetHandler(c *gin.Context) {
	id := c.Param("id")
	detail, err := assetService.GetDetail(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, detail)
}

func ClaimAssetHandler(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Owner string `json:"owner"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := assetService.Claim(id, req.Owner); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

func ListAlertsHandler(c *gin.Context) {
	alerts := alertService.List()
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

func GetAlertHandler(c *gin.Context) {
	id := c.Param("id")
	detail, err := alertService.GetDetail(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, detail)
}

func AlertActionHandler(c *gin.Context) {
	id := c.Param("id")
	action := c.Param("action")
	var req struct {
		Target          string `json:"target"`
		DurationMinutes int    `json:"duration_minutes"`
	}
	c.ShouldBindJSON(&req)
	if err := alertService.ExecuteAction(id, action, req.Target, req.DurationMinutes); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok", "action": action})
}

func FlowMapHandler(c *gin.Context) {
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
	c.JSON(200, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}

func countBySensitivity(assets []service.Asset, s string) int {
	count := 0
	for _, a := range assets {
		if a.SensitivityHint == s {
			count++
		}
	}
	return count
}

func countByStatus(assets []service.Asset, s string) int {
	count := 0
	for _, a := range assets {
		if a.Status == s {
			count++
		}
	}
	return count
}

func countByClaim(assets []service.Asset, s string) int {
	count := 0
	for _, a := range assets {
		if a.ClaimStatus == s {
			count++
		}
	}
	return count
}

func countBySeverity(alerts []service.Alert, s string) int {
	count := 0
	for _, a := range alerts {
		if a.Severity == s {
			count++
		}
	}
	return count
}

func countByAlertStatus(alerts []service.Alert, s string) int {
	count := 0
	for _, a := range alerts {
		if a.Status == s {
			count++
		}
	}
	return count
}
