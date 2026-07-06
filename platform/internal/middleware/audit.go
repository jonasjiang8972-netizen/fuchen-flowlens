package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

func AuditMiddleware(store storage.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		method := c.Request.Method
		user := auth.GetUsername(c)

		writer := &responseWriter{ResponseWriter: c.Writer, statusCode: 200}
		c.Writer = writer

		c.Next()

		if path != "/api/v1/health" && path != "/api/v1/auth/login" {
			detail := method + " " + path
			if writer.statusCode >= 400 {
				detail += " -> " + http.StatusText(writer.statusCode)
			}
			go func(p, u, d string) {
				_ = store.SaveAuditLog(nil, u, method, p, d)
			}(path, user, detail)
		}
	}
}

type responseWriter struct {
	gin.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
