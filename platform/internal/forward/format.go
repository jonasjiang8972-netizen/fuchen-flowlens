package forward

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/version"
)

// Event is one message to forward. Fields holds the event's attributes as
// flat strings (alert ID, source IP, user, ...); they become the JSON
// "data" object and CEF extensions.
type Event struct {
	Type     string            `json:"type"`
	Time     time.Time         `json:"time"`
	Severity string            `json:"severity"`
	Title    string            `json:"title"`
	Fields   map[string]string `json:"data"`
}

// envelope is the JSON document sent to webhooks and in JSON syslog.
type envelope struct {
	Product  string            `json:"product"`
	Version  string            `json:"version"`
	Type     string            `json:"type"`
	Time     string            `json:"time"`
	Severity string            `json:"severity"`
	Title    string            `json:"title"`
	Data     map[string]string `json:"data"`
}

func (e Event) JSON() []byte {
	b, _ := json.Marshal(envelope{
		Product: "FlowLens", Version: version.Version, Type: e.Type,
		Time: e.Time.UTC().Format(time.RFC3339), Severity: e.Severity, Title: e.Title, Data: e.Fields,
	})
	return b
}

// cefSeverity maps severities to CEF's 0-10 scale.
var cefSeverity = map[string]int{"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}

// cefKeys maps event fields to CEF extension keys; unmapped fields use
// FlowLens custom string keys (cs1..cs6 are limited, so they go into msg).
var cefKeys = map[string]string{
	"source_ip":  "src",
	"account":    "suser",
	"actor":      "duser",
	"endpoint":   "request",
	"action":     "act",
	"result":     "outcome",
	"alert_id":   "externalId",
	"event_type": "cat",
	"reason":     "reason",
}

// CEF formats the event as ArcSight Common Event Format.
func (e Event) CEF() string {
	sig := e.Type
	if r := e.Fields["requirement"]; r != "" {
		sig = r
	} else if t := e.Fields["event_type"]; t != "" {
		sig = t
	}
	sev, ok := cefSeverity[e.Severity]
	if !ok {
		sev = 1
	}
	ext := []string{"rt=" + fmt.Sprint(e.Time.UnixMilli())}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var rest []string
	for _, k := range keys {
		v := e.Fields[k]
		if v == "" {
			continue
		}
		if ck, ok := cefKeys[k]; ok {
			ext = append(ext, ck+"="+cefExt(v))
		} else {
			rest = append(rest, k+"="+v)
		}
	}
	if len(rest) > 0 {
		ext = append(ext, "msg="+cefExt(strings.Join(rest, " ")))
	}
	return fmt.Sprintf("CEF:0|FlowLens|FlowLens API Security|%s|%s|%s|%d|%s",
		cefHeader(version.Version), cefHeader(sig), cefHeader(e.Title), sev, strings.Join(ext, " "))
}

// cefHeader escapes header fields (| and \).
func cefHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "\n", " ", "\r", " ").Replace(s)
}

// cefExt escapes extension values (= and \, newlines).
func cefExt(s string) string {
	return strings.NewReplacer(`\`, `\\`, "=", `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
}

// syslogSeverity maps severities to RFC 5424 severity codes.
var syslogSeverity = map[string]int{"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}

var hostname = func() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "-"
	}
	return h
}()

// Syslog wraps a message in an RFC 5424 header.
func (e Event) Syslog(facility int, body string) string {
	sev, ok := syslogSeverity[e.Severity]
	if !ok {
		sev = 6
	}
	msgID := strings.ReplaceAll(e.Type, ".", "_")
	return fmt.Sprintf("<%d>1 %s %s flowlens - %s - %s",
		facility*8+sev, e.Time.UTC().Format(time.RFC3339Nano), hostname, msgID, body)
}
