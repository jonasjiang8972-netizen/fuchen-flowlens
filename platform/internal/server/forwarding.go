package server

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/forward"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// auditEvent turns an audit record into a forwarded event.
func auditEvent(rec storage.AuditRecord) forward.Event {
	severity := "info"
	if rec.Result == "failure" {
		severity = "low"
	}
	return forward.Event{
		Type: forward.EventAudit, Time: rec.Time, Severity: severity, Title: rec.EventType,
		Fields: map[string]string{
			"seq": strconv.FormatInt(rec.Seq, 10), "event_type": rec.EventType, "actor": rec.Username, "role": rec.Role,
			"source_ip": rec.SourceIP, "console": rec.Console, "target": rec.Target, "result": rec.Result,
			"reason": rec.Reason, "detail": rec.Detail, "hash": rec.Hash,
		},
	}
}

// alertFields are the attributes forwarded with alert events.
func alertFields(a *service.Alert) map[string]string {
	return map[string]string{
		"alert_id": a.ID, "requirement": a.SourceRequirement, "status": a.Status,
		"risk_score": strconv.Itoa(a.RiskScore), "source_ip": a.SourceIP, "account": a.AccountID,
		"endpoint": strings.Join(a.Endpoints, " "), "reason": a.Description,
	}
}

func (s *PlatformServer) publishAlertCreated(a *service.Alert) {
	s.forwarder.Publish(forward.Event{Type: forward.EventAlertCreated, Time: a.Timestamp, Severity: a.Severity, Title: a.Title, Fields: alertFields(a)})
}

// publishAlertHandled forwards a handling step so a SOAR or gateway can
// carry out a recorded disposal (ip_block with source_ip, ...).
func (s *PlatformServer) publishAlertHandled(a *service.Alert, action, actor, note string) {
	f := alertFields(a)
	f["action"], f["actor"], f["note"] = action, actor, note
	s.forwarder.Publish(forward.Event{Type: forward.EventAlertHandled, Severity: a.Severity, Title: a.Title + "：" + action, Fields: f})
}

// GetForwardingHandler returns the targets (secrets masked) and their
// delivery statistics.
func (s *PlatformServer) GetForwardingHandler(c *gin.Context) {
	c.JSON(200, gin.H{"targets": s.forwarder.Config().Masked().Targets, "stats": s.forwarder.Stats()})
}

// UpdateForwardingHandler replaces the target list.
func (s *PlatformServer) UpdateForwardingHandler(c *gin.Context) {
	var req forward.Config
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	cfg, err := s.forwarder.Update(c.Request.Context(), req)
	if err != nil {
		if strings.HasPrefix(err.Error(), "save forwarding config") {
			logger.L().Errorf("forwarding: %v", err)
			c.JSON(500, gin.H{"error": "保存失败，请稍后重试"})
			return
		}
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"targets": cfg.Masked().Targets, "stats": s.forwarder.Stats()})
}

// TestForwardingHandler sends a test message to the target in the body
// (saved or not) and reports whether it was delivered.
func (s *PlatformServer) TestForwardingHandler(c *gin.Context) {
	var t forward.Target
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	if err := s.forwarder.Test(c.Request.Context(), t); err != nil {
		c.JSON(200, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
