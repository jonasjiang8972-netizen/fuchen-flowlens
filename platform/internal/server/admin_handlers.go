package server

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/iam"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// IAM exposes the identity service (bootstrap, tests).
func (s *PlatformServer) IAM() *iam.Service { return s.iam }

// Audit exposes the audit service.
func (s *PlatformServer) Audit() *audit.Service { return s.audit }

// StartMaintenance runs session cleanup and audit retention in the background.
func (s *PlatformServer) StartMaintenance(ctx context.Context) {
	go func() {
		sessions := time.NewTicker(5 * time.Minute)
		retention := time.NewTicker(24 * time.Hour)
		defer sessions.Stop()
		defer retention.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sessions.C:
				if err := s.iam.CleanupSessions(ctx); err != nil {
					logger.L().Warnf("session cleanup: %v", err)
				}
			case <-retention.C:
				days := s.iam.Policy(ctx).AuditRetentionDays
				n, err := s.audit.Purge(ctx, time.Duration(days)*24*time.Hour)
				if err != nil {
					logger.L().Warnf("audit retention purge: %v", err)
					continue
				}
				if n > 0 {
					_ = s.audit.Record(ctx, storage.AuditRecord{Username: "system", Console: "system",
						EventType: "audit.purge", Detail: fmt.Sprintf("按保留期 %d 天删除 %d 条过期审计记录", days, n)})
				}
			}
		}
	}()
}

// respondErr maps service errors to HTTP responses.
func respondErr(c *gin.Context, err error) {
	var ve *iam.ValidationError
	switch {
	case errors.As(err, &ve):
		c.JSON(http.StatusBadRequest, gin.H{"error": ve.Msg})
	case errors.Is(err, storage.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "记录不存在"})
	default:
		logger.L().Errorf("request %s %s failed: %v", c.Request.Method, c.Request.URL.Path, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务内部错误"})
	}
}

// ─── Auth ──────────────────────────────────────────────────────

func (s *PlatformServer) setSessionCookie(c *gin.Context, token string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: auth.CookieName, Value: token, Path: "/api", MaxAge: maxAge,
		HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode,
	})
}

func (s *PlatformServer) LoginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入用户名和口令"})
		return
	}
	res, err := s.iam.Login(c.Request.Context(), req.Username, req.Password, c.ClientIP(), c.GetHeader("User-Agent"))
	switch {
	case errors.Is(err, iam.ErrRateLimited):
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	case errors.Is(err, iam.ErrBadCredentials), errors.Is(err, iam.ErrAccountLocked),
		errors.Is(err, iam.ErrAccountDisabled), errors.Is(err, iam.ErrAccountExpired):
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	case err != nil:
		respondErr(c, err)
		return
	}
	s.setSessionCookie(c, res.Token, int(time.Until(res.ExpiresAt).Seconds()))
	// The token is also returned for API clients; the web console relies on
	// the HttpOnly cookie and never stores it.
	c.JSON(http.StatusOK, gin.H{
		"token": res.Token, "expires_at": res.ExpiresAt, "user": res.User, "console": res.Console,
		"must_change_password": res.MustChangePassword, "permissions": res.Permissions,
	})
}

func (s *PlatformServer) LogoutHandler(c *gin.Context) {
	if p := auth.Principal(c); p != nil && p.UserID != "demo" {
		if err := s.iam.Logout(c.Request.Context(), p); err != nil {
			respondErr(c, err)
			return
		}
	}
	c.Set(auth.AuditedKey, true)
	s.setSessionCookie(c, "", -1)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *PlatformServer) MeHandler(c *gin.Context) {
	p := auth.Principal(c)
	if p.UserID == "demo" {
		c.JSON(http.StatusOK, gin.H{"user": gin.H{"username": "demo", "display_name": p.DisplayName, "role": p.Role},
			"console": iam.ConsoleSecurity, "permissions": iam.PermissionsOf(p.Role), "must_change_password": false})
		return
	}
	me, err := s.iam.Me(c.Request.Context(), p)
	if err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": me, "console": iam.ConsoleOf(p.Role), "permissions": iam.PermissionsOf(p.Role),
		"must_change_password": p.MustChangePassword, "policy": s.iam.Policy(c.Request.Context())})
}

func (s *PlatformServer) ChangePasswordHandler(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	c.Set(auth.AuditedKey, true)
	if err := s.iam.ChangePassword(c.Request.Context(), auth.Principal(c), req.OldPassword, req.NewPassword); err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// ─── Users (system administrator) ──────────────────────────────

func (s *PlatformServer) ListUsersHandler(c *gin.Context) {
	users, err := s.iam.ListUsers(c.Request.Context())
	if err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"total": len(users), "items": users})
}

func (s *PlatformServer) CreateUserHandler(c *gin.Context) {
	var in iam.UserInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	c.Set(auth.AuditedKey, true)
	u, err := s.iam.CreateUser(c.Request.Context(), auth.Principal(c), in)
	if err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusCreated, u)
}

func (s *PlatformServer) UpdateUserHandler(c *gin.Context) {
	var in iam.UserInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	c.Set(auth.AuditedKey, true)
	u, err := s.iam.UpdateUser(c.Request.Context(), auth.Principal(c), c.Param("id"), in)
	if err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusOK, u)
}

func (s *PlatformServer) UserActionHandler(c *gin.Context) {
	ctx, actor, id := c.Request.Context(), auth.Principal(c), c.Param("id")
	c.Set(auth.AuditedKey, true)
	var (
		u   iam.UserView
		err error
	)
	switch c.Param("action") {
	case "enable":
		u, err = s.iam.SetStatus(ctx, actor, id, true)
	case "disable":
		u, err = s.iam.SetStatus(ctx, actor, id, false)
	case "unlock":
		u, err = s.iam.Unlock(ctx, actor, id)
	case "reset-password":
		var req struct {
			Password string `json:"password"`
		}
		if bindErr := c.ShouldBindJSON(&req); bindErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
			return
		}
		u, err = s.iam.ResetPassword(ctx, actor, id, req.Password)
	default:
		c.Set(auth.AuditedKey, false)
		c.JSON(http.StatusNotFound, gin.H{"error": "未知操作"})
		return
	}
	if err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusOK, u)
}

func (s *PlatformServer) DeleteUserHandler(c *gin.Context) {
	c.Set(auth.AuditedKey, true)
	if err := s.iam.DeleteUser(c.Request.Context(), auth.Principal(c), c.Param("id")); err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *PlatformServer) ListRolesHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": iam.Roles()})
}

// ─── Security policy (system administrator) ────────────────────

func (s *PlatformServer) GetPolicyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"policy": s.iam.Policy(c.Request.Context()), "defaults": iam.DefaultPolicy()})
}

func (s *PlatformServer) UpdatePolicyHandler(c *gin.Context) {
	var p iam.Policy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求格式错误"})
		return
	}
	c.Set(auth.AuditedKey, true)
	if err := s.iam.UpdatePolicy(c.Request.Context(), auth.Principal(c), p); err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": p})
}

// ─── Audit trail (audit administrator) ─────────────────────────

func auditQueryFrom(c *gin.Context) storage.AuditQuery {
	q := storage.AuditQuery{
		Username: c.Query("username"), EventType: c.Query("event_type"),
		Result: c.Query("result"), Console: c.Query("console"),
	}
	q.Limit, _ = strconv.Atoi(c.DefaultQuery("limit", "100"))
	q.Offset, _ = strconv.Atoi(c.Query("offset"))
	if q.Offset < 0 {
		q.Offset = 0
	}
	if t, err := time.Parse(time.RFC3339, c.Query("from")); err == nil {
		q.From = t
	}
	if t, err := time.Parse(time.RFC3339, c.Query("to")); err == nil {
		q.To = t
	}
	return q
}

func (s *PlatformServer) ListAuditHandler(c *gin.Context) {
	records, total, err := s.audit.List(c.Request.Context(), auditQueryFrom(c))
	if err != nil {
		respondErr(c, err)
		return
	}
	if records == nil {
		records = []storage.AuditRecord{}
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "items": records})
}

func (s *PlatformServer) VerifyAuditHandler(c *gin.Context) {
	res, err := s.audit.Verify(c.Request.Context())
	if err != nil {
		respondErr(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// ExportAuditHandler streams matching records as CSV (UTF-8 with BOM so
// spreadsheet software shows Chinese text correctly).
func (s *PlatformServer) ExportAuditHandler(c *gin.Context) {
	q := auditQueryFrom(c)
	q.Limit, q.Offset = 100000, 0
	records, _, err := s.audit.List(c.Request.Context(), q)
	if err != nil {
		respondErr(c, err)
		return
	}
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=flowlens-audit-%s.csv", time.Now().Format("20060102-150405")))
	_, _ = c.Writer.Write([]byte("\xEF\xBB\xBF"))
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"序号", "时间", "用户", "角色", "源IP", "控制台", "事件类型", "操作对象", "结果", "原因", "详情", "方法", "路径", "上一哈希", "哈希"})
	for _, r := range records {
		_ = w.Write([]string{strconv.FormatInt(r.Seq, 10), r.Time.Format(time.RFC3339), r.Username, r.Role, r.SourceIP,
			r.Console, r.EventType, r.Target, r.Result, r.Reason, r.Detail, r.Method, r.Path, r.PrevHash, r.Hash})
	}
	w.Flush()
}

// ─── Collectors & system (system administrator) ────────────────

func (s *PlatformServer) SystemInfoHandler(c *gin.Context) {
	storageKind := "memory"
	if _, ok := s.store.(*storage.PGStore); ok {
		storageKind = "postgresql"
	}
	c.JSON(http.StatusOK, gin.H{
		"version":       version.Version,
		"storage":       storageKind,
		"secure_cookie": s.SecureCookies,
		"demo_mode":     s.DemoMode,
		"ingest":        s.ingestPipeline.Metrics(),
	})
}

// RecordAgentEvent writes an audit record for collector-side actions.
func (s *PlatformServer) recordAgentEvent(c *gin.Context, event, target, detail string) {
	_ = s.audit.Record(c.Request.Context(), storage.AuditRecord{
		Username: "agent", Role: "agent", SourceIP: c.ClientIP(), Console: "agent",
		EventType: event, Target: target, Detail: detail, Method: c.Request.Method, Path: c.Request.URL.Path,
	})
}
