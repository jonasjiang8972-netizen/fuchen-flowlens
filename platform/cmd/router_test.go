package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/auth"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/server"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

func newTestRouter(t *testing.T, token string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := storage.NewStore("mem")
	return setupRouter(server.NewPlatformServer(store), store, false, token)
}

func agentPost(r *gin.Engine, path, token string) int {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"agent_id":"a1","hostname":"h","events":[{"event_id":"e1"}]}`))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(auth.AgentTokenHeader, token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestAgentEndpointsRequireAgentToken(t *testing.T) {
	r := newTestRouter(t, "s3cret")
	paths := []string{"/api/v1/agents/register", "/api/v1/agents/a1/heartbeat", "/api/v1/ingest/batch"}

	for _, p := range paths {
		if code := agentPost(r, p, ""); code != http.StatusUnauthorized {
			t.Errorf("%s without token: got %d, want 401", p, code)
		}
		if code := agentPost(r, p, "wrong"); code != http.StatusUnauthorized {
			t.Errorf("%s with wrong token: got %d, want 401", p, code)
		}
		if code := agentPost(r, p, "s3cret"); code == http.StatusUnauthorized {
			t.Errorf("%s with valid token: got 401", p)
		}
	}
}

func TestAgentEndpointsFailClosedWithoutConfiguredToken(t *testing.T) {
	r := newTestRouter(t, "")
	if code := agentPost(r, "/api/v1/ingest/batch", "anything"); code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 when platform has no agent token", code)
	}
}

func TestAgentTokenDoesNotGrantUserAPIs(t *testing.T) {
	r := newTestRouter(t, "s3cret")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	req.Header.Set(auth.AgentTokenHeader, "s3cret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("agent token on user API: got %d, want 401", w.Code)
	}
}
