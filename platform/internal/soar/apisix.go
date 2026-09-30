package soar

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

const apisixRule = "flowlens-block"

// APISIX blocks addresses through one global rule holding an ip-restriction
// plugin. The rule's blacklist is the set of blocked addresses; it is
// deleted when the last address is lifted.
type APISIX struct {
	base   string
	key    string
	client *http.Client
	mu     sync.Mutex
}

func NewAPISIX(adminURL, apiKey string) *APISIX {
	return &APISIX{base: strings.TrimRight(adminURL, "/"), key: apiKey, client: newHTTPClient()}
}

func (a *APISIX) Name() string  { return "apisix" }
func (a *APISIX) Label() string { return "APISIX 网关" }

func (a *APISIX) headers() map[string]string { return map[string]string{"X-API-KEY": a.key} }

func (a *APISIX) url() string { return a.base + "/apisix/admin/global_rules/" + apisixRule }

type apisixRuleBody struct {
	Plugins struct {
		IPRestriction struct {
			Blacklist []string `json:"blacklist"`
		} `json:"ip-restriction"`
	} `json:"plugins"`
}

// list returns the current blacklist (nil when the rule does not exist).
// APISIX 3.x wraps the rule in "value"; 2.x in "node.value".
func (a *APISIX) list(ctx context.Context) ([]string, error) {
	var resp struct {
		Value apisixRuleBody `json:"value"`
		Node  struct {
			Value apisixRuleBody `json:"value"`
		} `json:"node"`
	}
	err := doJSON(ctx, a.client, http.MethodGet, a.url(), a.headers(), nil, &resp)
	if isStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if l := resp.Value.Plugins.IPRestriction.Blacklist; len(l) > 0 {
		return l, nil
	}
	return resp.Node.Value.Plugins.IPRestriction.Blacklist, nil
}

func (a *APISIX) put(ctx context.Context, list []string) error {
	body := map[string]any{"plugins": map[string]any{"ip-restriction": map[string]any{
		"blacklist": list, "message": "Blocked by FlowLens",
	}}}
	return doJSON(ctx, a.client, http.MethodPut, a.url(), a.headers(), body, nil)
}

func (a *APISIX) Block(ctx context.Context, req Request) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	list, err := a.list(ctx)
	if err != nil {
		return "", err
	}
	if containsIP(list, req.IP) {
		return "", nil
	}
	return "", a.put(ctx, append(append([]string(nil), list...), req.IP))
}

func (a *APISIX) Unblock(ctx context.Context, ip, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	list, err := a.list(ctx)
	if err != nil {
		return err
	}
	rest, found := withoutIP(list, ip)
	if !found {
		return nil
	}
	if len(rest) == 0 {
		err := doJSON(ctx, a.client, http.MethodDelete, a.url(), a.headers(), nil, nil)
		if isStatus(err, http.StatusNotFound) {
			return nil
		}
		return err
	}
	return a.put(ctx, rest)
}

func (a *APISIX) Check(ctx context.Context) error {
	return doJSON(ctx, a.client, http.MethodGet, a.base+"/apisix/admin/global_rules", a.headers(), nil, nil)
}
