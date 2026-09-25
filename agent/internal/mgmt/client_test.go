package mgmt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func TestClientSendsAgentToken(t *testing.T) {
	var gotTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokens = append(gotTokens, r.Header.Get(AgentTokenHeader))
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.Write([]byte(`{"agent_id":"a1"}`))
		case strings.HasSuffix(r.URL.Path, "/ingest/batch"):
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"accepted":1,"dropped":2}`))
		}
	}))
	defer srv.Close()

	c := NewClient(config.ManagementConfig{
		PlatformEndpoint: strings.TrimPrefix(srv.URL, "http://"),
		AuthToken:        "s3cret",
	})
	ctx := context.Background()
	if err := c.Register(ctx, &AgentRegistration{AgentID: "a1"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := c.SendHeartbeat(ctx, &HeartbeatPayload{}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	dropped, err := c.SendEvents(ctx, make([]shared.APIEvent, 3))
	if err != nil || dropped != 2 {
		t.Fatalf("send events: dropped=%d err=%v, want 2, nil", dropped, err)
	}

	if len(gotTokens) != 3 {
		t.Fatalf("got %d requests, want 3", len(gotTokens))
	}
	for i, tok := range gotTokens {
		if tok != "s3cret" {
			t.Errorf("request %d token = %q, want s3cret", i, tok)
		}
	}
}
