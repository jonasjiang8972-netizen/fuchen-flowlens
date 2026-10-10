package gwlog

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

// CombinedLogFormat is nginx's predefined "combined" format.
const CombinedLogFormat = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

// nginxParser parses access log lines written with one nginx log_format.
type nginxParser struct {
	re       *regexp.Regexp
	vars     []string // variable name per capture group
	clientIP string   // "remote_addr" or "x_forwarded_for"
}

var nginxVar = regexp.MustCompile(`\$(\{[a-zA-Z0-9_]+\}|[a-zA-Z0-9_]+)`)

// newNginxParser compiles a log_format string (as written in nginx.conf,
// without the format name) into a line parser. Each variable becomes a
// capture group; the text between variables must match literally.
func newNginxParser(format, clientIP string) (*nginxParser, error) {
	format = strings.TrimSpace(format)
	if format == "" {
		format = CombinedLogFormat
	}
	// A format copied from nginx.conf may keep its quotes and line breaks:
	//   '$remote_addr - ...'
	//   '"$http_user_agent"';
	format = strings.TrimSuffix(strings.TrimSpace(format), ";")
	if strings.HasPrefix(format, "'") {
		var b strings.Builder
		for _, part := range regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(format, -1) {
			b.WriteString(part[1])
		}
		format = b.String()
	}

	p := &nginxParser{clientIP: clientIP}
	var expr strings.Builder
	expr.WriteString("^")
	last := 0
	locs := nginxVar.FindAllStringSubmatchIndex(format, -1)
	if len(locs) == 0 {
		return nil, fmt.Errorf("nginx log format has no variables")
	}
	for i, loc := range locs {
		expr.WriteString(regexp.QuoteMeta(format[last:loc[0]]))
		name := strings.Trim(format[loc[2]:loc[3]], "{}")
		// The last variable takes the rest of the line; others stop at the
		// next literal text (non-greedy).
		if i == len(locs)-1 && loc[1] == len(format) {
			expr.WriteString("(.*)")
		} else {
			expr.WriteString("(.*?)")
		}
		p.vars = append(p.vars, name)
		last = loc[1]
	}
	expr.WriteString(regexp.QuoteMeta(format[last:]))
	expr.WriteString("$")
	re, err := regexp.Compile(expr.String())
	if err != nil {
		return nil, fmt.Errorf("compile nginx log format: %w", err)
	}
	p.re = re
	return p, nil
}

// parse turns one log line into an event, or nil when the line does not
// match the format.
func (p *nginxParser) parse(line string) *shared.APIEvent {
	m := p.re.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	fields := make(map[string]string, len(p.vars))
	for i, name := range p.vars {
		v := m[i+1]
		if v == "-" {
			v = ""
		}
		fields[name] = v
	}

	evt := newEvent()
	app := &evt.Application
	if req := fields["request"]; req != "" {
		// "GET /path?x=1 HTTP/1.1"
		parts := strings.SplitN(req, " ", 3)
		app.Method = parts[0]
		if len(parts) > 1 {
			app.PathRaw = parts[1]
		}
	}
	if v := fields["request_method"]; v != "" {
		app.Method = v
	}
	if v := fields["request_uri"]; v != "" {
		app.PathRaw = v
	} else if v := fields["uri"]; v != "" && app.PathRaw == "" {
		app.PathRaw = v
		if args := fields["args"]; args != "" {
			app.PathRaw += "?" + args
		}
	}
	for _, k := range []string{"host", "http_host", "server_name"} {
		if v := fields[k]; v != "" {
			app.Host = strings.Split(v, ":")[0]
			break
		}
	}
	if v, err := strconv.Atoi(fields["status"]); err == nil {
		app.StatusCode = uint16(v)
	}
	if v, err := strconv.ParseUint(firstNonEmpty(fields["bytes_sent"], fields["body_bytes_sent"]), 10, 64); err == nil {
		app.BytesOut = v
	}
	if v, err := strconv.ParseUint(fields["request_length"], 10, 64); err == nil {
		app.BytesIn = v
	}
	if v, err := strconv.ParseFloat(fields["request_time"], 64); err == nil {
		app.DurationMs = v * 1000
	}

	evt.Network.SrcIP = fields["remote_addr"]
	if p.clientIP == "x_forwarded_for" {
		if xff := fields["http_x_forwarded_for"]; xff != "" {
			evt.Network.SrcIP = strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	if v := fields["upstream_addr"]; v != "" {
		// "10.0.1.5:8080" or "10.0.1.5:8080, 10.0.1.6:8080" after retries
		first := strings.TrimSpace(strings.Split(v, ",")[0])
		evt.Network.DstIP = hostPart(first)
	}

	if ts, ok := nginxTime(fields); ok {
		evt.Timestamp = ts
	}

	// $http_<name> variables are request headers ($http_x_user_id is
	// X-User-Id). Cookies are never collected.
	for name, v := range fields {
		if v == "" || !strings.HasPrefix(name, "http_") || name == "http_cookie" {
			continue
		}
		if evt.Content.RequestHeaders == nil {
			evt.Content.RequestHeaders = map[string]string{}
		}
		evt.Content.RequestHeaders[strings.ReplaceAll(strings.TrimPrefix(name, "http_"), "_", "-")] = v
	}
	return evt
}

// nginxTime reads the request time from $time_iso8601, $time_local or
// $msec, whichever the format has.
func nginxTime(f map[string]string) (time.Time, bool) {
	if v := f["time_iso8601"]; v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t, true
		}
	}
	if v := f["time_local"]; v != "" {
		if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", v); err == nil {
			return t, true
		}
	}
	if v := f["msec"]; v != "" {
		if sec, err := strconv.ParseFloat(v, 64); err == nil && sec > 0 {
			return time.UnixMilli(int64(sec * 1000)), true
		}
	}
	return time.Time{}, false
}

func hostPart(addr string) string {
	if strings.HasPrefix(addr, "[") { // [::1]:8080
		if i := strings.Index(addr, "]"); i > 0 {
			return addr[1:i]
		}
	}
	if strings.Count(addr, ":") == 1 {
		return strings.Split(addr, ":")[0]
	}
	return addr
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
