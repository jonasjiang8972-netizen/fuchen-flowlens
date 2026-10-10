// Package forward sends alerts, alert handling and audit records to
// external systems (SIEM / SOC over syslog, SOAR or ticketing over
// webhooks).
package forward

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Event types a target can subscribe to.
const (
	EventAlertCreated = "alert.created" // a new alert was raised
	EventAlertHandled = "alert.handled" // an operator acknowledged, disposed of or closed an alert
	EventAudit        = "audit"         // a platform audit record
	EventTest         = "test"          // sent by the "test" button
)

var knownEvents = map[string]bool{EventAlertCreated: true, EventAlertHandled: true, EventAudit: true}

// Target is one destination.
type Target struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"` // syslog | webhook
	Enabled bool     `json:"enabled"`
	Events  []string `json:"events"`
	// MinSeverity filters alert events: low | medium | high | critical.
	MinSeverity string `json:"min_severity"`

	// syslog
	Address  string `json:"address,omitempty"`  // host:port
	Protocol string `json:"protocol,omitempty"` // udp | tcp | tls
	Format   string `json:"format,omitempty"`   // json | cef
	Facility int    `json:"facility,omitempty"` // 0..23, default 13 (log audit)

	// webhook
	URL    string `json:"url,omitempty"`
	Secret string `json:"secret,omitempty"` // HMAC-SHA256 signing key
}

// Config is the saved list of targets.
type Config struct {
	Targets []Target `json:"targets"`
}

// maskedSecret stands in for a stored secret in API responses; sending it
// back keeps the stored value.
const maskedSecret = "******"

const maxTargets = 20

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Validate normalises and checks a configuration.
func (c *Config) Validate() error {
	if len(c.Targets) > maxTargets {
		return fmt.Errorf("最多配置 %d 个外发目标", maxTargets)
	}
	seen := map[string]bool{}
	for i := range c.Targets {
		t := &c.Targets[i]
		if t.ID == "" {
			t.ID = newID()
		}
		if seen[t.ID] {
			return fmt.Errorf("外发目标 ID 重复：%s", t.ID)
		}
		seen[t.ID] = true
		if err := t.validate(); err != nil {
			name := t.Name
			if name == "" {
				name = t.ID
			}
			return fmt.Errorf("%s：%w", name, err)
		}
	}
	return nil
}

func (t *Target) validate() error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" || len(t.Name) > 64 {
		return fmt.Errorf("名称不能为空且不超过 64 个字符")
	}
	if len(t.Events) == 0 {
		return fmt.Errorf("至少选择一类外发事件")
	}
	for _, e := range t.Events {
		if !knownEvents[e] {
			return fmt.Errorf("不支持的事件类型 %s", e)
		}
	}
	if t.MinSeverity == "" {
		t.MinSeverity = "low"
	}
	if _, ok := severityRank[t.MinSeverity]; !ok {
		return fmt.Errorf("最低告警等级应为 low、medium、high 或 critical")
	}
	switch t.Type {
	case "syslog":
		host, port, err := net.SplitHostPort(strings.TrimSpace(t.Address))
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("syslog 地址应为 主机:端口，例如 10.0.0.5:514")
		}
		t.Address = net.JoinHostPort(host, port)
		if t.Protocol == "" {
			t.Protocol = "udp"
		}
		if t.Protocol != "udp" && t.Protocol != "tcp" && t.Protocol != "tls" {
			return fmt.Errorf("syslog 协议应为 udp、tcp 或 tls")
		}
		if t.Format == "" {
			t.Format = "json"
		}
		if t.Format != "json" && t.Format != "cef" {
			return fmt.Errorf("syslog 格式应为 json 或 cef")
		}
		if t.Facility == 0 {
			t.Facility = 13
		}
		if t.Facility < 0 || t.Facility > 23 {
			return fmt.Errorf("syslog facility 取值 0～23")
		}
		t.URL, t.Secret = "", ""
	case "webhook":
		u, err := url.Parse(strings.TrimSpace(t.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("Webhook 地址应为 http:// 或 https:// 开头的 URL")
		}
		t.URL = u.String()
		if len(t.Secret) > 256 {
			return fmt.Errorf("签名密钥不能超过 256 个字符")
		}
		t.Address, t.Protocol, t.Format, t.Facility = "", "", "", 0
	default:
		return fmt.Errorf("类型应为 syslog 或 webhook")
	}
	return nil
}

// wants reports whether t should receive an event of typ and severity.
func (t *Target) wants(typ, severity string) bool {
	if !t.Enabled {
		return false
	}
	if typ == EventTest {
		return true
	}
	subscribed := false
	for _, e := range t.Events {
		subscribed = subscribed || e == typ
	}
	if !subscribed {
		return false
	}
	if typ == EventAlertCreated || typ == EventAlertHandled {
		return severityRank[severity] >= severityRank[t.MinSeverity]
	}
	return true
}

// Masked returns a copy without secrets, for API responses.
func (c Config) Masked() Config {
	out := Config{Targets: make([]Target, len(c.Targets))}
	for i, t := range c.Targets {
		if t.Secret != "" {
			t.Secret = maskedSecret
		}
		out.Targets[i] = t
	}
	return out
}

// keepSecrets replaces masked secrets in c with the stored ones of the same
// target ID.
func (c *Config) keepSecrets(stored Config) {
	prev := map[string]string{}
	for _, t := range stored.Targets {
		prev[t.ID] = t.Secret
	}
	for i := range c.Targets {
		if c.Targets[i].Secret == maskedSecret {
			c.Targets[i].Secret = prev[c.Targets[i].ID]
		}
	}
}

func newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "fwd-" + hex.EncodeToString(b[:])
}
