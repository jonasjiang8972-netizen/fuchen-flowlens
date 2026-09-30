package soar

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	aliyunVersion = "2021-10-01"
	aliyunAlgo    = "ACS3-HMAC-SHA256"
)

// AliyunWAF blocks addresses through Alibaba Cloud WAF 3.0 by adding rules to
// an IP-blacklist defense template the operator created beforehand.
//
// EXPERIMENTAL: the request signing (ACS3-HMAC-SHA256) follows the public
// specification and is covered by tests, but the WAF rule payload
// (buildRules) follows the WAF 3.0 OpenAPI documentation and has not been
// exercised against a live WAF instance. Use "test connection" and dry-run
// mode, and verify one block in the WAF console, before relying on it.
type AliyunWAF struct {
	keyID, keySecret string
	instanceID       string
	templateID       string
	endpoint         string
	client           *http.Client
	now              func() time.Time
	mu               sync.Mutex
}

// AliyunConfig configures the connector.
type AliyunConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	InstanceID      string
	TemplateID      string
	Region          string // default cn-hangzhou
	Endpoint        string // overrides the regional endpoint (tests, private links)
}

func NewAliyunWAF(c AliyunConfig) *AliyunWAF {
	ep := c.Endpoint
	if ep == "" {
		region := c.Region
		if region == "" {
			region = "cn-hangzhou"
		}
		ep = "https://wafopenapi." + region + ".aliyuncs.com"
	}
	return &AliyunWAF{
		keyID: c.AccessKeyID, keySecret: c.AccessKeySecret, instanceID: c.InstanceID, templateID: c.TemplateID,
		endpoint: strings.TrimRight(ep, "/"), client: newHTTPClient(), now: time.Now,
	}
}

func (a *AliyunWAF) Name() string       { return "aliyun_waf" }
func (a *AliyunWAF) Label() string      { return "阿里云 WAF" }
func (a *AliyunWAF) Experimental() bool { return true }

// percentEncode is RFC 3986 encoding as the signature requires: unreserved
// characters stay, everything else (including space) is %XX.
func percentEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// canonicalQuery sorts parameters by name and encodes them.
func canonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(params[k]))
	}
	return strings.Join(parts, "&")
}

// signRequest computes the ACS3-HMAC-SHA256 Authorization header for a
// body-less RPC call and returns the headers to send.
func signRequest(keyID, keySecret, method, host, action, version string, params map[string]string, at time.Time, nonce string) map[string]string {
	payloadHash := sha256Hex(nil)
	hdr := map[string]string{
		"host":                  host,
		"x-acs-action":          action,
		"x-acs-version":         version,
		"x-acs-date":            at.UTC().Format("2006-01-02T15:04:05Z"),
		"x-acs-signature-nonce": nonce,
		"x-acs-content-sha256":  payloadHash,
	}
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.TrimSpace(hdr[k]) + "\n")
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{method, "/", canonicalQuery(params), canonHeaders.String(), signed, payloadHash}, "\n")
	toSign := aliyunAlgo + "\n" + sha256Hex([]byte(canonical))
	mac := hmac.New(sha256.New, []byte(keySecret))
	mac.Write([]byte(toSign))
	hdr["Authorization"] = fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s", aliyunAlgo, keyID, signed, hex.EncodeToString(mac.Sum(nil)))
	return hdr
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (a *AliyunWAF) call(ctx context.Context, action string, params map[string]string, out any) error {
	u, err := url.Parse(a.endpoint)
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	hdrs := signRequest(a.keyID, a.keySecret, http.MethodPost, u.Host, action, aliyunVersion, params, a.now(), hex.EncodeToString(nonce))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/?"+canonicalQuery(params), nil)
	if err != nil {
		return err
	}
	for k, v := range hdrs {
		if k == "host" {
			continue // set from the URL
		}
		req.Header.Set(k, v)
	}
	var envelope struct {
		Code      string          `json:"Code"`
		Message   string          `json:"Message"`
		RequestID string          `json:"RequestId"`
		Raw       json.RawMessage `json:"-"`
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil && resp.StatusCode < 300 {
		return fmt.Errorf("阿里云返回了无法解析的响应: %w", err)
	}
	_ = json.Unmarshal(body, &envelope)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("阿里云 WAF %s 失败: HTTP %d %s %s (RequestId %s)", action, resp.StatusCode, envelope.Code, envelope.Message, envelope.RequestID)
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// buildRules is the one place that knows the WAF rule payload shape.
func buildRules(req Request) (string, error) {
	rules := []map[string]any{{
		"name":        "flowlens-" + req.IP,
		"remoteAddr":  []string{req.IP},
		"description": "FlowLens 自动封禁 " + req.AlertID,
		"ruleStatus":  1,
	}}
	raw, err := json.Marshal(rules)
	return string(raw), err
}

func (a *AliyunWAF) Block(ctx context.Context, req Request) (string, error) {
	rules, err := buildRules(req)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var out struct {
		RuleIds json.RawMessage `json:"RuleIds"`
	}
	err = a.call(ctx, "CreateDefenseRule", map[string]string{
		"InstanceId": a.instanceID, "TemplateId": a.templateID, "DefenseScene": "ip_blacklist", "Rules": rules,
	}, &out)
	if err != nil {
		return "", err
	}
	return ruleRef(out.RuleIds), nil
}

// ruleRef turns the RuleIds response field (a string or a list) into the
// comma-separated reference stored for unblocking.
func ruleRef(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var nums []json.Number
	if json.Unmarshal(raw, &nums) == nil {
		parts := make([]string, len(nums))
		for i, n := range nums {
			parts[i] = n.String()
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func (a *AliyunWAF) Unblock(ctx context.Context, _, ref string) error {
	if ref == "" {
		return fmt.Errorf("缺少 WAF 规则 ID，无法解除，请在 WAF 控制台手动删除")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.call(ctx, "DeleteDefenseRule", map[string]string{
		"InstanceId": a.instanceID, "TemplateId": a.templateID, "RuleIds": ref,
	}, nil)
}

func (a *AliyunWAF) Check(ctx context.Context) error {
	return a.call(ctx, "DescribeInstance", map[string]string{}, nil)
}
