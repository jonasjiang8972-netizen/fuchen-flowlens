package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
)

var agentService = service.NewAgentService()
var assetService = service.NewAssetService()
var alertService = service.NewAlertService()

func listAgentsHandler(c *gin.Context) {
	agents := agentService.List()
	c.JSON(200, gin.H{
		"total":         len(agents),
		"online_count":  agentService.OnlineCount(),
		"offline_count": agentService.OfflineCount(),
		"items":         agents,
	})
}

func getAgentHandler(c *gin.Context) {
	id := c.Param("id")
	agent, err := agentService.Get(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, agent)
}

func agentHealthSummaryHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"total_agents":  agentService.TotalCount(),
		"online":        agentService.OnlineCount(),
		"offline":       agentService.OfflineCount(),
		"degraded":      agentService.DegradedCount(),
		"total_qps":     0,
		"avg_drop_rate": 0,
	})
}

func listAssetsHandler(c *gin.Context) {
	assets := assetService.List()
	c.JSON(200, gin.H{
		"total": len(assets),
		"items": assets,
	})
}

func getAssetHandler(c *gin.Context) {
	id := c.Param("id")
	asset, err := assetService.Get(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, asset)
}

func claimAssetHandler(c *gin.Context) {
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

func listAlertsHandler(c *gin.Context) {
	alerts := alertService.List()
	c.JSON(200, gin.H{
		"total": len(alerts),
		"items": alerts,
	})
}

func getAlertHandler(c *gin.Context) {
	id := c.Param("id")
	alert, err := alertService.Get(id)
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, alert)
}

func alertActionHandler(c *gin.Context) {
	id := c.Param("id")
	action := c.Param("action")
	var req struct {
		Target         string `json:"target"`
		DurationMinutes int   `json:"duration_minutes"`
	}
	c.ShouldBindJSON(&req)
	if err := alertService.ExecuteAction(id, action, req.Target, req.DurationMinutes); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "ok", "action": action})
}

func flowMapHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"nodes": []interface{}{},
		"edges": []interface{}{},
	})
}
