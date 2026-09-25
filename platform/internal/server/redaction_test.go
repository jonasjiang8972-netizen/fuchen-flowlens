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

	for _, a := range srv.assetService.List() {
		if a.PathNormalized != evt.Application.PathNormalized {
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

func contains(items []string, s string) bool {
	for _, i := range items {
		if i == s {
			return true
		}
	}
	return false
}
