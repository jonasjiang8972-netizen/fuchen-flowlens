package normalizer

import (
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func TestNormalizeEventSplitsQueryAndTemplatesPath(t *testing.T) {
	evt := &shared.APIEvent{}
	evt.Application.PathRaw = "/api/v1/users/821/orders?page=2&url=http%3A%2F%2F169.254.169.254%2F"
	evt.Content.QueryParams = map[string]string{"page": "keep-existing"}
	New().NormalizeEvent(evt)
	if evt.Application.PathRaw != "/api/v1/users/821/orders" {
		t.Fatalf("PathRaw = %q", evt.Application.PathRaw)
	}
	if evt.Application.PathNormalized != "/api/v1/users/{id}/orders" {
		t.Fatalf("PathNormalized = %q", evt.Application.PathNormalized)
	}
	if evt.Content.QueryParams["page"] != "keep-existing" || evt.Content.QueryParams["url"] != "http://169.254.169.254/" {
		t.Fatalf("QueryParams = %v", evt.Content.QueryParams)
	}
	if evt.Application.Method != "GET" || evt.Timestamp.IsZero() {
		t.Fatalf("defaults not filled: %+v", evt.Application)
	}
}
