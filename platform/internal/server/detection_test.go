package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func alertsFor(srv *PlatformServer, requirement, ip string) []string {
	var out []string
	for _, a := range srv.alertService.List() {
		if a.SourceRequirement == requirement && a.SourceIP == ip {
			out = append(out, a.Description)
		}
	}
	return out
}

func TestIngestFlagsUnmaskedResponse(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	srv.SetRedactionKey("k")
	evt := shared.APIEvent{Timestamp: time.Now()}
	evt.Network.SrcIP = "203.0.113.10"
	evt.Application.Method = "GET"
	evt.Application.PathRaw = "/api/customers/42"
	evt.Application.PathNormalized = "/api/customers/{id}"
	evt.Application.StatusCode = 200
	evt.Content.ResponseBody = []byte(`{"id_card":"11010519491231002X","mobile":"13812345678"}`)
	srv.processIngestEvent(context.Background(), evt)

	got := alertsFor(srv, "FR-DLP-001", "203.0.113.10")
	if len(got) != 1 {
		t.Fatalf("got %d DLP alerts, want 1", len(got))
	}
	if !strings.Contains(got[0], "脱敏缺陷") || strings.Contains(got[0], "11010519491231002X") {
		t.Fatalf("unexpected description: %s", got[0])
	}
}

func TestIngestAcceptsCollectorFindingsAfterMasking(t *testing.T) {
	// The collector already masked the body; its scan result arrives as labels.
	srv := NewPlatformServer(storage.NewMemStore())
	evt := shared.APIEvent{Timestamp: time.Now()}
	evt.Network.SrcIP = "203.0.113.11"
	evt.Application.PathNormalized = "/api/customers/{id}"
	evt.Content.ResponseBody = []byte(`{"mobile":"138****5678"}`)
	evt.Metadata.Labels = map[string]string{"dlp.scanned": "1", "dlp.unmasked.phone": "1"}
	srv.processIngestEvent(context.Background(), evt)
	if n := len(alertsFor(srv, "FR-DLP-001", "203.0.113.11")); n != 1 {
		t.Fatalf("collector-reported defect produced %d alerts, want 1", n)
	}
}

func TestIngestMaskedResponseIsQuiet(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	evt := shared.APIEvent{Timestamp: time.Now()}
	evt.Network.SrcIP = "203.0.113.12"
	evt.Application.PathNormalized = "/api/customers/{id}"
	evt.Content.ResponseBody = []byte(`{"mobile":"138****5678"}`)
	srv.processIngestEvent(context.Background(), evt)
	if n := len(alertsFor(srv, "FR-DLP-001", "203.0.113.12")); n != 0 {
		t.Fatalf("masked response produced %d alerts", n)
	}
}

func TestIngestFlagsScriptedClient(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	base := time.Now()
	for i := 0; i < 20; i++ {
		evt := shared.APIEvent{Timestamp: base.Add(time.Duration(i) * 500 * time.Millisecond)}
		evt.Network.SrcIP = "203.0.113.20"
		evt.Application.Method = "GET"
		evt.Application.PathNormalized = "/api/products"
		evt.Application.StatusCode = 200
		evt.Content.RequestHeaders = map[string]string{"user-agent": "python-requests/2.31"}
		srv.processIngestEvent(context.Background(), evt)
		time.Sleep(time.Millisecond)
	}
	// Engine time is wall-clock: 20 calls a millisecond apart are perfectly
	// regular and the UA is a scripting client.
	if n := len(alertsFor(srv, "FR-RISK-002", "203.0.113.20")); n == 0 {
		t.Fatal("no bot alert for a scripted client")
	}
}
