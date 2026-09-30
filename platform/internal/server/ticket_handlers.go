package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
)

// raiseAlert records a detection and makes sure serious ones have a ticket, so
// nothing severe sits in the alert list waiting for someone to notice it.
func (s *PlatformServer) raiseAlert(requirement, severity, title, description, sourceIP, accountID string, riskScore int, confidence float64) service.Alert {
	a := s.alertService.CreateDetectionAlert(requirement, severity, title, description, sourceIP, accountID, riskScore, confidence)
	s.ticketService.EnsureForAlert(alertRef(a))
	return a
}

// alertRef describes an alert for automatic ticketing. Alerts from one source
// address for one detection share a ticket.
func alertRef(a service.Alert) service.AlertRef {
	group := ""
	if a.SourceIP != "" {
		group = a.SourceRequirement + "|" + a.SourceIP
	}
	return service.AlertRef{
		ID: a.ID, Severity: a.Severity, Title: a.Title, Description: a.Description,
		Action: recommendedAction(a.SourceRequirement), Account: a.AccountID, Group: group,
	}
}

// recommendedAction is the remediation a ticket suggests for a detection.
func recommendedAction(requirement string) string {
	switch requirement {
	case "FR-DET-001":
		return "限制该账号访问，核查对象级鉴权"
	case "FR-DET-002":
		return "封禁来源 IP，通知 IAM 对涉及账号强制改密"
	case "FR-DET-005":
		return "核查账号角色配置和功能级鉴权"
	case "FR-DLP-001", "FR-DLP-003":
		return "修复响应字段脱敏并回归验证"
	case "FR-RISK-002":
		return "对来源实施验证码挑战或限流"
	}
	return "研判并处置"
}

// SeedDemoTickets opens a ticket for each serious sample alert, so the demo
// work-order page matches the alerts. It runs only for demo data.
func (s *PlatformServer) SeedDemoTickets() {
	for _, a := range s.alertService.List() {
		s.ticketService.EnsureForAlert(alertRef(a))
	}
}

// TicketSummaryHandler serves the headline numbers.
func (s *PlatformServer) TicketSummaryHandler(c *gin.Context) {
	c.JSON(200, s.ticketService.Summary())
}

// ListTicketsHandler lists tickets, newest first.
//
//	GET /tickets?status=&severity=&owner=&alert_id=&q=&open=true
func (s *PlatformServer) ListTicketsHandler(c *gin.Context) {
	items := s.ticketService.List(service.TicketFilter{
		Status: c.Query("status"), Severity: c.Query("severity"), Owner: c.Query("owner"),
		AlertID: c.Query("alert_id"), Keyword: c.Query("q"), OpenOnly: c.Query("open") == "true",
	})
	c.JSON(200, gin.H{"items": items, "total": len(items)})
}

func (s *PlatformServer) GetTicketHandler(c *gin.Context) {
	t, err := s.ticketService.Get(c.Param("id"))
	if err != nil {
		ticketErr(c, err)
		return
	}
	c.JSON(200, t)
}

func actorName(c *gin.Context) string {
	if p := auth.Principal(c); p != nil && p.Username != "" {
		return p.Username
	}
	return "system"
}

// CreateTicketHandler opens a ticket, optionally from an alert.
func (s *PlatformServer) CreateTicketHandler(c *gin.Context) {
	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Owner       string `json:"owner"`
		Action      string `json:"action"`
		AlertID     string `json:"alert_id"`
		AssetID     string `json:"asset_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	// From an alert, unspecified fields default to the alert's own.
	if req.AlertID != "" {
		a, err := s.alertService.Get(req.AlertID)
		if err != nil {
			c.JSON(404, gin.H{"error": "告警不存在"})
			return
		}
		if req.Title == "" {
			req.Title = a.Title
		}
		if req.Severity == "" {
			req.Severity = a.Severity
		}
		if req.Description == "" {
			req.Description = a.Description
		}
		if req.Action == "" {
			req.Action = recommendedAction(a.SourceRequirement)
		}
	}
	t, err := s.ticketService.Create(service.CreateTicket{
		Title: req.Title, Description: req.Description, Severity: req.Severity, Owner: req.Owner,
		Action: req.Action, AlertID: req.AlertID, AssetID: req.AssetID,
	}, actorName(c))
	if err != nil {
		s.auditTicket(c, "ticket.create", req.Title, err, "")
		ticketErr(c, err)
		return
	}
	s.auditTicket(c, "ticket.create", t.ID, nil, fmt.Sprintf("severity=%s alert=%s", t.Severity, t.AlertID))
	c.JSON(http.StatusCreated, t)
}

// TransitionTicketHandler moves a ticket along its workflow.
func (s *PlatformServer) TransitionTicketHandler(c *gin.Context) {
	var req struct {
		To    string `json:"to"`
		Note  string `json:"note"`
		Owner string `json:"owner"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.To == "" {
		c.JSON(400, gin.H{"error": "缺少目标状态 to"})
		return
	}
	p := auth.Principal(c)
	t, err := s.ticketService.Transition(c.Param("id"), service.TransitionInput{
		To: req.To, Note: req.Note, Owner: req.Owner, Actor: actorName(c),
		// Demo mode has one simulated user, who could never satisfy the rule.
		AllowSelfReview: p != nil && p.UserID == "demo",
	})
	detail := "to=" + req.To
	if req.Note != "" {
		detail += " note=" + req.Note
	}
	s.auditTicket(c, "ticket.transition", c.Param("id"), err, detail)
	if err != nil {
		ticketErr(c, err)
		return
	}
	c.JSON(200, t)
}

// AssignTicketHandler changes a ticket's owner.
func (s *PlatformServer) AssignTicketHandler(c *gin.Context) {
	var req struct {
		Owner string `json:"owner"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	t, err := s.ticketService.Assign(c.Param("id"), req.Owner, actorName(c))
	s.auditTicket(c, "ticket.assign", c.Param("id"), err, "owner="+req.Owner)
	if err != nil {
		ticketErr(c, err)
		return
	}
	c.JSON(200, t)
}

// CommentTicketHandler adds a note to a ticket.
func (s *PlatformServer) CommentTicketHandler(c *gin.Context) {
	var req struct {
		Text string `json:"text"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请求格式错误"})
		return
	}
	t, err := s.ticketService.Comment(c.Param("id"), req.Text, actorName(c))
	s.auditTicket(c, "ticket.comment", c.Param("id"), err, "")
	if err != nil {
		ticketErr(c, err)
		return
	}
	c.JSON(200, t)
}

func (s *PlatformServer) auditTicket(c *gin.Context, event, target string, err error, detail string) {
	res, reason := audit.ResultSuccess, ""
	if err != nil {
		res, reason = audit.ResultFailure, err.Error()
	}
	s.auditAction(c, event, target, res, reason, detail)
}

// ticketErr maps ticket errors to HTTP responses.
func ticketErr(c *gin.Context, err error) {
	var ve *service.ValidationError
	var ex *service.TicketExistsError
	switch {
	case errors.As(err, &ex):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "code": "ticket_exists", "ticket_id": ex.TicketID})
	case errors.As(err, &ve):
		c.JSON(http.StatusBadRequest, gin.H{"error": ve.Msg})
	case errors.Is(err, service.ErrInvalidTransition):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "code": "invalid_transition"})
	case errors.Is(err, service.ErrSelfReview):
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error(), "code": "self_review"})
	case errors.Is(err, service.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "工单不存在"})
	default:
		logger.L().Errorf("ticket %s %s: %v", c.Request.Method, c.Request.URL.Path, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败，请稍后重试"})
	}
}
