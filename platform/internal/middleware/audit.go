package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// routeEvents names the audit event of each audited route (method + gin
// route pattern). Routes whose handlers record richer events themselves set
// auth.AuditedKey and are skipped here.
var routeEvents = map[string]string{
	"POST /api/v1/assets/:id/claim":             "asset.claim",
	"POST /api/v1/alerts/:id/:action":           "alert.action",
	"PUT /api/v1/rules/:id":                     "rule.update",
	"POST /api/v1/rules/:id/hit":                "rule.hit",
	"POST /api/v1/detect/access":                "detect.record",
	"GET /api/v1/admin/audit-logs":              "audit.query",
	"GET /api/v1/admin/audit-logs/verify":       "audit.verify",
	"GET /api/v1/admin/audit-logs/export":       "audit.export",
	"POST /api/v1/admin/audit-logs/verify-full": "audit.verify_full_start",
}

// Audit records state-changing requests, plus reads of the audit trail
// itself, for authenticated consoles. console is "admin" or "security".
func Audit(auditSvc *audit.Service, console string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if c.GetBool(auth.AuditedKey) {
			return
		}
		key := c.Request.Method + " " + c.FullPath()
		event, known := routeEvents[key]
		if !known {
			if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
				return
			}
			event = console + "." + strings.ToLower(c.Request.Method)
		}

		rec := storage.AuditRecord{
			Console: console, EventType: event, Method: c.Request.Method, Path: c.Request.URL.Path,
			Result: audit.ResultSuccess, SourceIP: c.ClientIP(),
		}
		var targets []string
		for _, p := range c.Params {
			targets = append(targets, p.Key+"="+p.Value)
		}
		rec.Target = strings.Join(targets, " ")
		if q := c.Request.URL.RawQuery; q != "" && strings.HasPrefix(event, "audit.") {
			rec.Detail = q
		}
		if status := c.Writer.Status(); status >= 400 {
			rec.Result = audit.ResultFailure
			rec.Reason = http.StatusText(status)
		}
		auth.Principal(c).AuditActor(&rec)
		_ = auditSvc.Record(c.Request.Context(), rec)
	}
}
