package soar

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

const kongTag = "flowlens-block"

// Kong blocks addresses through one global ip-restriction plugin, tagged so
// FlowLens only ever touches its own. The plugin's deny list is the set of
// blocked addresses; Kong requires it to be non-empty, so the plugin is
// removed when the last address is lifted.
type Kong struct {
	base   string
	token  string
	client *http.Client
	mu     sync.Mutex
}

func NewKong(adminURL, token string) *Kong {
	return &Kong{base: strings.TrimRight(adminURL, "/"), token: token, client: newHTTPClient()}
}

func (k *Kong) Name() string  { return "kong" }
func (k *Kong) Label() string { return "Kong 网关" }

func (k *Kong) headers() map[string]string {
	if k.token == "" {
		return nil
	}
	return map[string]string{"Kong-Admin-Token": k.token}
}

type kongPlugin struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Config struct {
		Deny []string `json:"deny"`
	} `json:"config"`
}

func (k *Kong) find(ctx context.Context) (*kongPlugin, error) {
	var page struct {
		Data []kongPlugin `json:"data"`
	}
	if err := doJSON(ctx, k.client, http.MethodGet, k.base+"/plugins?tags="+kongTag, k.headers(), nil, &page); err != nil {
		return nil, err
	}
	for i := range page.Data {
		if page.Data[i].Name == "ip-restriction" {
			return &page.Data[i], nil
		}
	}
	return nil, nil
}

func (k *Kong) Block(ctx context.Context, req Request) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	p, err := k.find(ctx)
	if err != nil {
		return "", err
	}
	if p == nil {
		body := map[string]any{
			"name": "ip-restriction", "instance_name": kongTag, "tags": []string{kongTag},
			"config": map[string]any{"deny": []string{req.IP}},
		}
		return "", doJSON(ctx, k.client, http.MethodPost, k.base+"/plugins", k.headers(), body, nil)
	}
	if containsIP(p.Config.Deny, req.IP) {
		return "", nil
	}
	deny := append(append([]string(nil), p.Config.Deny...), req.IP)
	return "", doJSON(ctx, k.client, http.MethodPatch, k.base+"/plugins/"+p.ID, k.headers(), map[string]any{"config": map[string]any{"deny": deny}}, nil)
}

func (k *Kong) Unblock(ctx context.Context, ip, _ string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	p, err := k.find(ctx)
	if err != nil || p == nil {
		return err
	}
	deny, found := withoutIP(p.Config.Deny, ip)
	if !found {
		return nil
	}
	if len(deny) == 0 {
		err := doJSON(ctx, k.client, http.MethodDelete, k.base+"/plugins/"+p.ID, k.headers(), nil, nil)
		if isStatus(err, http.StatusNotFound) {
			return nil
		}
		return err
	}
	return doJSON(ctx, k.client, http.MethodPatch, k.base+"/plugins/"+p.ID, k.headers(), map[string]any{"config": map[string]any{"deny": deny}}, nil)
}

func (k *Kong) Check(ctx context.Context) error {
	return doJSON(ctx, k.client, http.MethodGet, k.base+"/", k.headers(), nil, nil)
}
