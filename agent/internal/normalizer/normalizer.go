package normalizer

import (
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/apipath"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

// Normalizer fills in derived fields of collected events before they are
// redacted and sent: query parameters split off the request target, the
// API template of the path, and defaults for missing fields.
type Normalizer struct{}

func New() *Normalizer { return &Normalizer{} }

// NormalizePath returns the API template of a path (/users/123 ->
// /users/{id}).
func (n *Normalizer) NormalizePath(rawPath string) string {
	return apipath.Normalize(rawPath)
}

func (n *Normalizer) NormalizeEvent(evt *shared.APIEvent) *shared.APIEvent {
	if evt.Application.PathRaw != "" {
		path, query := apipath.Split(evt.Application.PathRaw)
		evt.Application.PathRaw = path
		if len(query) > 0 {
			if evt.Content.QueryParams == nil {
				evt.Content.QueryParams = make(map[string]string, len(query))
			}
			for k, v := range query {
				if _, ok := evt.Content.QueryParams[k]; !ok {
					evt.Content.QueryParams[k] = v
				}
			}
		}
		evt.Application.PathNormalized = apipath.Normalize(path)
	}

	if evt.Application.Method == "" {
		evt.Application.Method = "GET"
	}
	if evt.Application.ProtocolType == "" {
		evt.Application.ProtocolType = "REST"
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}
	if evt.Metadata.Env == "" {
		evt.Metadata.Env = "prod"
	}
	return evt
}
