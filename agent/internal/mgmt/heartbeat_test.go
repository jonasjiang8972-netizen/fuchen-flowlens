package mgmt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

func TestHeartbeatLoopRetriesRegistrationAndReregisters(t *testing.T) {
	_ = logger.Init(false)
	minHeartbeatInterval = time.Millisecond
	defer func() { minHeartbeatInterval = time.Second }()

	var mu sync.Mutex
	registers, heartbeats := 0, 0
	known := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			registers++
			if registers <= 2 { // platform still starting
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			known = true
			w.Write([]byte(`{"agent_id":"a1"}`))
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			heartbeats++
			if heartbeats == 3 { // platform lost the agent
				known = false
			}
			if !known {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write([]byte(`{"status":"ok"}`))
		}
	}))
	defer srv.Close()

	c, err := NewClient(config.ManagementConfig{PlatformEndpoint: strings.TrimPrefix(srv.URL, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.StartHeartbeatLoop(ctx, config.ManagementConfig{HeartbeatInterval: 5 * time.Millisecond},
			&AgentRegistration{AgentID: "a1"}, func() HeartbeatPayload { return HeartbeatPayload{} })
		close(done)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		r, h := registers, heartbeats
		mu.Unlock()
		if r >= 4 && h >= 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("registers=%d heartbeats=%d: want retries after 503 and re-registration after 404", r, h)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}
