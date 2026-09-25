package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/iam"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

const (
	// CookieName holds the session token (HttpOnly, SameSite=Strict).
	CookieName = "fl_session"
	// CSRFHeader must accompany state-changing requests authenticated by the
	// cookie. Browsers cannot add it cross-site without a CORS preflight,
	// which the platform refuses for unknown origins.
	CSRFHeader = "X-Requested-With"
	CSRFValue  = "FlowLens"

	principalKey = "fl.principal"
	// AuditedKey marks a request whose handler wrote its own audit record.
	AuditedKey = "fl.audited"
)

// Principal returns the authenticated operator of the request, or nil.
func Principal(c *gin.Context) *iam.Principal {
	if v, ok := c.Get(principalKey); ok {
		return v.(*iam.Principal)
	}
	return nil
}

func tokenFrom(c *gin.Context) (token string, fromCookie bool) {
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer "), false
	}
	if v, err := c.Cookie(CookieName); err == nil {
		return v, true
	}
	return "", false
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// RequireSession authenticates the request by its session token. When demo
// is true every request runs as the all-permissions demo principal.
func RequireSession(svc *iam.Service, demo bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if demo {
			c.Set(principalKey, iam.DemoPrincipal())
			c.Next()
			return
		}
		token, fromCookie := tokenFrom(c)
		if fromCookie && !safeMethod(c.Request.Method) && c.GetHeader(CSRFHeader) != CSRFValue {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "缺少请求来源校验头", "code": "csrf"})
			return
		}
		p, err := svc.Authenticate(c.Request.Context(), token, c.ClientIP())
		if err != nil {
			status := http.StatusUnauthorized
			msg := iam.ErrSessionInvalid.Error()
			if !errors.Is(err, iam.ErrSessionInvalid) {
				status, msg = http.StatusInternalServerError, "认证服务暂不可用"
			}
			c.AbortWithStatusJSON(status, gin.H{"error": msg, "code": "unauthenticated"})
			return
		}
		c.Set(principalKey, p)
		c.Next()
	}
}

// RequirePermission rejects principals without perm and records the denial
// in the audit trail.
func RequirePermission(auditSvc *audit.Service, console string, perm iam.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		p := Principal(c)
		if p.Can(perm) {
			c.Next()
			return
		}
		code, msg := "forbidden", iam.ErrForbidden.Error()
		if p != nil && p.MustChangePassword {
			code, msg = "password_change_required", iam.ErrPasswordRequired.Error()
		}
		rec := storage.AuditRecord{Console: console, EventType: "access.denied", Target: c.FullPath(),
			Result: audit.ResultFailure, Reason: "缺少权限 " + string(perm), Method: c.Request.Method, Path: c.Request.URL.Path}
		p.AuditActor(&rec)
		_ = auditSvc.Record(c.Request.Context(), rec)
		c.Set(AuditedKey, true)
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msg, "code": code})
	}
}
