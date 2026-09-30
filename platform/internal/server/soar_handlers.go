package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/soar"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// SetSOAR installs the enforcement manager. Until it is called the server
// has a manager with no connectors, so blocking is refused rather than
// silently pretending to work.
func (s *PlatformServer) SetSOAR(m *soar.Manager) { s.soar = m }

// SOAR returns the enforcement manager.
func (s *PlatformServer) SOAR() *soar.Manager { return s.soar }

// SOARConnectorsHandler lists connectors, their last check and the policy in
// force. It never returns credentials.
func (s *PlatformServer) SOARConnectorsHandler(c *gin.Context) {
	p := s.soar.Policy()
	protected := make([]string, 0, len(p.ProtectedNets))
	for _, n := range p.ProtectedNets {
		protected = append(protected, n.String())
	}
	c.JSON(200, gin.H{
		"enabled":    s.soar.Enabled(),
		"connectors": s.soar.Connectors(),
		"policy": gin.H{
			"dry_run": p.DryRun, "allow_private": p.AllowPrivate, "protected_networks": protected,
			"default_ttl_minutes": int(p.DefaultTTL / time.Minute), "max_ttl_minutes": int(p.MaxTTL / time.Minute),
			"max_blocks_per_hour": p.MaxBlocksPerHour,
		},
	})
}

// SOARTestHandler checks one connector.
func (s *PlatformServer) SOARTestHandler(c *gin.Context) {
	st, err := s.soar.Check(c.Request.Context(), c.Param("name"))
	if err != nil {
		soarErr(c, err)
		return
	}
	s.auditSOAR(c, "soar.test", c.Param("name"), st.Error, "连接测试："+st.Status)
	c.JSON(200, st)
}

// SOARBlocksHandler lists blocks, newest first. ?active=true limits it to
// those still in force.
func (s *PlatformServer) SOARBlocksHandler(c *gin.Context) {
	blocks := s.soar.Blocks(c.Query("active") == "true", 200)
	c.JSON(200, gin.H{"items": blocks, "total": len(blocks)})
}

type soarBlockRequest struct {
	IP         string   `json:"ip"`
	TTLMinutes int      `json:"ttl_minutes"`
	Reason     string   `json:"reason"`
	AlertID    string   `json:"alert_id"`
	Connectors []string `json:"connectors"`
}

// SOARBlockHandler blocks an address on the connected systems.
func (s *PlatformServer) SOARBlockHandler(c *gin.Context) {
	var req soarBlockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	if req.TTLMinutes < 0 {
		c.JSON(400, gin.H{"error": "ttl_minutes 不能为负"})
		return
	}
	b, err := s.blockIP(c, req)
	if b != nil && b.State == soar.StateFailed {
		c.JSON(http.StatusBadGateway, gin.H{"error": "所有联动系统都未能执行封禁", "block": b})
		return
	}
	if err != nil {
		soarErr(c, err)
		return
	}
	c.JSON(200, b)
}

// SOARUnblockHandler lifts the block on an address.
func (s *PlatformServer) SOARUnblockHandler(c *gin.Context) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.IP) == "" {
		c.JSON(400, gin.H{"error": "缺少 ip"})
		return
	}
	operator := ""
	if p := auth.Principal(c); p != nil {
		operator = p.Username
	}
	b, err := s.soar.Unblock(c.Request.Context(), req.IP, operator)
	res, reason, detail := audit.ResultSuccess, "", ""
	if b != nil {
		detail = resultsSummary(b.Results)
	}
	if err != nil {
		res, reason = audit.ResultFailure, err.Error()
	}
	s.auditAction(c, "soar.unblock", req.IP, res, reason, detail)
	if err != nil {
		if b != nil { // lifted on some connectors; the rest will be retried
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "block": b})
			return
		}
		soarErr(c, err)
		return
	}
	c.JSON(200, b)
}

// blockIP runs a block and records it in the audit trail, whoever asked.
func (s *PlatformServer) blockIP(c *gin.Context, req soarBlockRequest) (*soar.Block, error) {
	operator := ""
	if p := auth.Principal(c); p != nil {
		operator = p.Username
	}
	b, err := s.soar.Block(c.Request.Context(), soar.BlockInput{
		IP: req.IP, TTL: time.Duration(req.TTLMinutes) * time.Minute, Reason: req.Reason,
		AlertID: req.AlertID, Operator: operator, Connectors: req.Connectors,
	})
	res, reason, detail := audit.ResultSuccess, "", ""
	if b != nil {
		detail = fmt.Sprintf("ttl=%dm alert=%s %s", req.TTLMinutes, req.AlertID, resultsSummary(b.Results))
		if b.State == soar.StateFailed {
			res, reason = audit.ResultFailure, "所有联动系统都未能执行封禁"
		}
	}
	if err != nil {
		res, reason = audit.ResultFailure, err.Error()
	}
	target := req.IP
	if b != nil {
		target = b.IP
	}
	s.auditAction(c, "soar.block", target, res, reason, detail)
	return b, err
}

func resultsSummary(rs []soar.Result) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		switch {
		case r.Released:
			parts = append(parts, r.Connector+":released")
		case r.OK:
			parts = append(parts, r.Connector+":ok")
		default:
			parts = append(parts, r.Connector+":error("+r.Error+")")
		}
	}
	return strings.Join(parts, " ")
}

func (s *PlatformServer) auditSOAR(c *gin.Context, event, target, failure, detail string) {
	res := audit.ResultSuccess
	if failure != "" {
		res = audit.ResultFailure
	}
	s.auditAction(c, event, target, res, failure, detail)
}

// auditAction writes the request's audit record itself, so the generic
// middleware does not add a second, less informative one.
func (s *PlatformServer) auditAction(c *gin.Context, event, target, result, reason, detail string) {
	rec := storage.AuditRecord{
		Console: "security", EventType: event, Target: target, Result: result, Reason: reason, Detail: detail,
		Method: c.Request.Method, Path: c.Request.URL.Path,
	}
	if p := auth.Principal(c); p != nil {
		p.AuditActor(&rec)
	}
	if rec.SourceIP == "" {
		rec.SourceIP = c.ClientIP()
	}
	if err := s.audit.Record(c.Request.Context(), rec); err != nil {
		logger.L().Errorf("audit %s %s: %v", event, target, err)
	}
	c.Set(auth.AuditedKey, true)
}

// soarErr maps manager refusals to HTTP statuses.
func soarErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, soar.ErrNoConnectors):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error() + "。请先配置联动系统（见 docs/SOAR.md）", "code": "no_connectors"})
	case errors.Is(err, soar.ErrBadTarget), errors.Is(err, soar.ErrBadTTL), errors.Is(err, soar.ErrUnknownConn):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, soar.ErrNotBlocked):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, soar.ErrRateLimited):
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	default:
		logger.L().Errorf("soar %s %s: %v", c.Request.Method, c.Request.URL.Path, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务内部错误"})
	}
}
