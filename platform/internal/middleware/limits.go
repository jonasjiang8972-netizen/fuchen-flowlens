package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxBody caps request bodies at n bytes so oversized requests cannot
// exhaust memory.
func MaxBody(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > n {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "请求体过大"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		c.Next()
	}
}
