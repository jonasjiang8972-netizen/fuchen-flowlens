package server

import (
	"context"
	"strings"
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func TestIngestRedactsBeforeStoring(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	srv.SetRedactionKey("k")
	var evt shared.APIEvent
	evt.Application.Method = "GET"
	evt.Application.Host = "bank.example"
	evt.Application.PathRaw = "/api/customers/13800138000/cards/6222021234567890128"
	evt.Application.PathNormalized = "/api/customers/{phone}/cards/{card}"
	evt.Content.ResponseBody = []byte(`{"id_card":"110101199003074514","password":"x"}`)
	srv.processIngestEvent(context.Background(), evt)

	// The platform computes the template itself, whatever the collector sent.
	for _, a := range srv.assetService.List() {
		if a.PathNormalized != "/api/customers/{id}/cards/{id}" {
			continue
		}
		joined := strings.Join(a.PathRawSamples, " ")
		if strings.Contains(joined, "13800138000") || strings.Contains(joined, "6222021234567890128") {
			t.Fatalf("raw path sample kept personal data: %v", a.PathRawSamples)
		}
		if !contains(a.SensitiveFields, "id_card") {
			t.Fatalf("classification lost after redaction: %v", a.SensitiveFields)
		}
		return
	}
	t.Fatal("asset not created")
}

func TestIngestSplitsQueryAndGroupsAssets(t *testing.T) {
	srv := NewPlatformServer(storage.NewMemStore())
	before := len(srv.assetService.List())
	for i, target := range []string{"/api/v1/orders?page=1", "/api/v1/orders?page=2", "/api/v1/users/821", "/api/v1/users/9"} {
		var evt shared.APIEvent
		evt.Application.Method = "GET"
		evt.Application.Host = "shop.example"
		evt.Application.PathRaw = target
		evt.Application.PathNormalized = target // an old collector's untouched value
		evt.EventID = string(rune('a' + i))
		srv.processIngestEvent(context.Background(), evt)
	}
	got := map[string]bool{}
	for _, a := range srv.assetService.List() {
		got[a.PathNormalized] = true
		if strings.Contains(a.PathNormalized, "?") {
			t.Fatalf("query string kept in asset path %q", a.PathNormalized)
		}
	}
	if !got["/api/v1/orders"] || !got["/api/v1/users/{id}"] {
		t.Fatalf("assets = %v", got)
	}
	if n := len(srv.assetService.List()) - before; n != 2 {
		t.Fatalf("4 requests to 2 endpoints created %d assets", n)
	}
}

func contains(items []string, s string) bool {
	for _, i := range items {
		if i == s {
			return true
		}
	}
	return false
}
