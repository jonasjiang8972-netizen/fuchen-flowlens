package apipath

import (
	"fmt"
	"testing"
)

func TestSplit(t *testing.T) {
	path, q := Split("/api/v1/orders?page=3&size=20&page=9&url=http%3A%2F%2F10.0.0.1%2Fx&flag#frag")
	if path != "/api/v1/orders" {
		t.Fatalf("path = %q", path)
	}
	if q["page"] != "3" || q["size"] != "20" || q["url"] != "http://10.0.0.1/x" || q["flag"] != "" {
		t.Fatalf("query = %v", q)
	}
	if _, ok := q["flag"]; !ok {
		t.Fatalf("parameter without value dropped: %v", q)
	}
	if p, q := Split("/plain"); p != "/plain" || q != nil {
		t.Fatalf("no query: %q %v", p, q)
	}
	if p, q := Split("/a%20b?"); p != "/a b" || q != nil {
		t.Fatalf("empty query: %q %v", p, q)
	}
	// An escaped "?" inside the path stays escaped rather than turning into
	// a query separator.
	if p, _ := Split("/files/what%3Fx"); p != "/files/what%3Fx" {
		t.Fatalf("escaped ? = %q", p)
	}
}

func TestSplitBoundsParams(t *testing.T) {
	target := "/x?"
	for i := 0; i < 500; i++ {
		target += fmt.Sprintf("p%d=1&", i)
	}
	if _, q := Split(target); len(q) != maxQueryParams {
		t.Fatalf("kept %d params, want %d", len(q), maxQueryParams)
	}
}

func TestNormalize(t *testing.T) {
	for raw, want := range map[string]string{
		"/api/v1/users/123":            "/api/v1/users/{id}",
		"/api/v1/users/123/orders/456": "/api/v1/users/{id}/orders/{id}",
		"/users/7":                     "/users/{id}",
		"/api/v2/items/0b1e2f4a-9c3d-4e5f-8a7b-6c5d4e3f2a1b": "/api/v2/items/{uuid}",
		"/objects/507f1f77bcf86cd799439011":                  "/objects/{hash}",
		"/api/v1/orders?page=3":                              "/api/v1/orders",
		"/api/v1/health":                                     "/api/v1/health",
		"/static/app.js":                                     "/static/app.js",
		"/":                                                  "/",
		"":                                                   "",
		"/cafe/beef":                                         "/cafe/beef", // short hex words are kept
	} {
		if got := Normalize(raw); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", raw, got, want)
		}
	}
}
