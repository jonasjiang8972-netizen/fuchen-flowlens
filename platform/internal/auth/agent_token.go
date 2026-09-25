package auth

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AgentTokenHeader carries the shared secret agents use to call the
// register, heartbeat and ingest endpoints.
const AgentTokenHeader = "X-Agent-Token"

// AgentTokenMiddleware authenticates agents with a shared token. It fails
// closed: when no token is configured every agent request is rejected.
func AgentTokenMiddleware(token string) gin.HandlerFunc {
	expected := []byte(token)
	return func(c *gin.Context) {
		if len(expected) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "agent token not configured on platform"})
			return
		}
		got := c.GetHeader(AgentTokenHeader)
		if got == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing agent token"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(got), expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid agent token"})
			return
		}
		c.Set("username", "agent")
		c.Set("role", "agent")
		c.Next()
	}
}
