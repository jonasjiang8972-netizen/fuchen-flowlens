package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// SSRFEngine flags request parameters that point the server at internal
// networks, cloud metadata services or dangerous URL schemes. It matches
// literal addresses only; it does not resolve names.
type SSRFEngine struct {
	store  storage.Store
	mu     sync.RWMutex
	now    func() time.Time
	events *cooldown

	internal []*net.IPNet
	metadata map[string]bool // lower-case hosts and IPs
	schemes  map[string]bool
}

// SSRF defaults, matching rule R-SSRF-001.
const (
	ssrfDefaultInternalNets   = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fc00::/7"
	ssrfDefaultMetadataHosts  = "169.254.169.254,100.100.100.200,metadata.google.internal,metadata.tencentyun.com"
	ssrfDefaultBlockedSchemes = "file,gopher,dict,ftp,ldap,jar"

	ssrfMaxValues   = 200
	ssrfMaxValueLen = 2048
	ssrfMaxBody     = 64 << 10
)

func NewSSRFEngine(store storage.Store) *SSRFEngine {
	e := &SSRFEngine{store: store, now: time.Now, events: newCooldown()}
	e.Configure(nil)
	return e
}

// Configure applies rule R-SSRF-001's parameters: internal_nets (CIDRs),
// metadata_hosts and blocked_schemes, all comma-separated. Invalid CIDRs
// are skipped.
func (e *SSRFEngine) Configure(p Params) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.internal = nil
	for _, cidr := range p.List("internal_nets", ssrfDefaultInternalNets) {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			e.internal = append(e.internal, n)
		}
	}
	e.metadata = map[string]bool{}
	for _, h := range p.List("metadata_hosts", ssrfDefaultMetadataHosts) {
		e.metadata[strings.ToLower(strings.Trim(h, "[]"))] = true
	}
	e.schemes = map[string]bool{}
	for _, s := range p.List("blocked_schemes", ssrfDefaultBlockedSchemes) {
		e.schemes[strings.ToLower(strings.TrimSuffix(s, "://"))] = true
	}
}

// Evaluate inspects the query parameters and the JSON request body of one
// request to endpoint and scores the most dangerous value found.
func (e *SSRFEngine) Evaluate(endpoint, sourceIP string, query map[string]string, body []byte) (int, string) {
	values := ssrfCandidates(query, body)
	if len(values) == 0 {
		return 0, ""
	}
	e.mu.RLock()
	best, reason := 0, ""
	for _, kv := range values {
		if score, why := e.classify(kv[0], kv[1]); score > best {
			best = score
			reason = fmt.Sprintf("SSRF 特征: %s 的参数 %s=%s %s", endpoint, kv[0], truncate(kv[1], 120), why)
		}
	}
	e.mu.RUnlock()
	if best == 0 {
		return 0, ""
	}

	if e.events.allow(endpoint+"|"+sourceIP, e.now()) {
		severity := "high"
		if best >= 90 {
			severity = "critical"
		}
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("ssrf-%d", time.Now().UnixNano()),
			Type: "SSRF", Severity: severity,
			Title:     fmt.Sprintf("SSRF 尝试: %s", endpoint),
			Detail:    reason,
			SourceIP:  sourceIP,
			RiskScore: best,
			CreatedAt: time.Now(),
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save SSRF event: %v", err)
		}
	}
	return best, reason
}

// classify scores one parameter value: a cloud metadata address 95, a
// blocked scheme 85, an internal address 75. Values with a scheme are
// checked in every parameter; a bare address only in parameters whose name
// says it is a fetch target, since fields such as client_ip legitimately
// carry internal addresses.
func (e *SSRFEngine) classify(name, value string) (int, string) {
	v := strings.TrimSpace(value)
	if v == "" {
		return 0, ""
	}
	if dv, err := url.QueryUnescape(v); err == nil {
		v = dv
	}
	host := ""
	scheme := ""
	if i := strings.Index(v, "://"); i > 0 {
		scheme = strings.ToLower(v[:i])
		if u, err := url.Parse(v); err == nil {
			host = u.Hostname()
		} else {
			host = hostOf(v[i+3:])
		}
	} else if targetParam(name) && looksLikeHost(v) {
		host = hostOf(v)
	}

	best, why := 0, ""
	if scheme != "" && e.schemes[scheme] {
		best, why = 85, fmt.Sprintf("使用危险协议 %s://", scheme)
	}
	if host == "" {
		return best, why
	}
	h := strings.ToLower(strings.Trim(host, "[]"))
	ip := literalIP(h)
	if e.metadata[h] || (ip != nil && e.metadata[ip.String()]) {
		return 95, fmt.Sprintf("指向云元数据地址 %s", host)
	}
	if best < 75 {
		if h == "localhost" || strings.HasSuffix(h, ".localhost") {
			return 75, fmt.Sprintf("指向本机 %s", host)
		}
		if ip != nil {
			for _, n := range e.internal {
				if n.Contains(ip) {
					return 75, fmt.Sprintf("指向内网地址 %s", ip)
				}
			}
		}
	}
	return best, why
}

// ssrfCandidates collects (name, value) pairs from the query and from the
// string values of a JSON body, bounded in number and length, in a stable
// order.
func ssrfCandidates(query map[string]string, body []byte) [][2]string {
	var out [][2]string
	add := func(k, v string) {
		if len(out) < ssrfMaxValues && v != "" && len(v) <= ssrfMaxValueLen {
			out = append(out, [2]string{k, v})
		}
	}
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add(k, query[k])
	}
	if len(body) > 0 && len(body) <= ssrfMaxBody {
		var doc interface{}
		if json.Unmarshal(body, &doc) == nil {
			walkStrings(doc, "", 0, add)
		}
	}
	return out
}

func walkStrings(v interface{}, name string, depth int, add func(k, v string)) {
	if depth > 8 {
		return
	}
	switch t := v.(type) {
	case string:
		add(name, t)
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkStrings(t[k], k, depth+1, add)
		}
	case []interface{}:
		for _, child := range t {
			walkStrings(child, name, depth+1, add)
		}
	}
}

// targetParamHints are name fragments of parameters that tell the server
// where to connect.
var targetParamHints = []string{"url", "uri", "link", "host", "domain", "target", "dest", "endpoint",
	"callback", "redirect", "proxy", "server", "webhook", "feed", "src", "fetch", "next", "return", "goto", "image", "img"}

func targetParam(name string) bool {
	n := strings.ToLower(name)
	for _, h := range targetParamHints {
		if strings.Contains(n, h) {
			return true
		}
	}
	return false
}

// looksLikeHost reports a bare value that is an address rather than text:
// an IP literal, a host:port, or localhost.
func looksLikeHost(v string) bool {
	if strings.ContainsAny(v, " \t/") && !strings.HasPrefix(v, "[") {
		return false
	}
	h := strings.ToLower(hostOf(v))
	return h == "localhost" || strings.HasSuffix(h, ".localhost") || net.ParseIP(strings.Trim(h, "[]")) != nil ||
		(strings.Contains(v, ":") && literalIP(h) != nil)
}

// hostOf returns the host part of "host", "host:port" or "host/path".
func hostOf(v string) string {
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		return h
	}
	return v
}

// literalIP parses an IP literal, including the decimal (2130706433) and
// hexadecimal (0x7f000001) IPv4 forms used to slip past naive filters.
func literalIP(h string) net.IP {
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
		return ip
	}
	var n uint64
	var err error
	switch {
	case strings.HasPrefix(h, "0x"):
		n, err = strconv.ParseUint(h[2:], 16, 32)
	case h != "" && strings.Trim(h, "0123456789") == "" && len(h) >= 8:
		n, err = strconv.ParseUint(h, 10, 32)
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).To4()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
