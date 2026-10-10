package gwlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/collector"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

func TestNginxCombined(t *testing.T) {
	p, err := newNginxParser("", "")
	if err != nil {
		t.Fatal(err)
	}
	line := `203.0.113.9 - - [10/Oct/2026:13:55:36 +0800] "GET /api/v1/users/42?fields=name HTTP/1.1" 200 2326 "https://shop.example/" "Mozilla/5.0 (X11; Linux) \"quoted\""`
	evt := p.parse(line)
	if evt == nil {
		t.Fatal("combined line not parsed")
	}
	a := evt.Application
	if a.Method != "GET" || a.PathRaw != "/api/v1/users/42?fields=name" || a.StatusCode != 200 || a.BytesOut != 2326 {
		t.Fatalf("application: %+v", a)
	}
	if evt.Network.SrcIP != "203.0.113.9" {
		t.Fatalf("src ip %q", evt.Network.SrcIP)
	}
	want := time.Date(2026, 10, 10, 5, 55, 36, 0, time.UTC)
	if !evt.Timestamp.Equal(want) {
		t.Fatalf("timestamp %v, want %v", evt.Timestamp, want)
	}
	if evt.Content.RequestHeaders["user-agent"] == "" || evt.Content.RequestHeaders["referer"] != "https://shop.example/" {
		t.Fatalf("headers: %v", evt.Content.RequestHeaders)
	}
}

func TestNginxCustomFormatFromConfig(t *testing.T) {
	// Copied from nginx.conf, quotes, line breaks and semicolon included.
	format := `'$remote_addr - [$time_iso8601] "$request" $status $bytes_sent '
                   '$request_time "$upstream_addr" $host "$http_x_user_id" "$http_x_forwarded_for" "$http_cookie"';`
	p, err := newNginxParser(format, "x_forwarded_for")
	if err != nil {
		t.Fatal(err)
	}
	line := `10.0.0.2 - [2026-10-10T13:55:36+08:00] "POST /api/v1/orders HTTP/2.0" 201 512 0.042 "10.1.0.7:8080, 10.1.0.8:8080" shop.example:443 "u-1001" "198.51.100.7, 10.0.0.2" "sid=secret"`
	evt := p.parse(line)
	if evt == nil {
		t.Fatal("custom line not parsed")
	}
	a := evt.Application
	if a.Method != "POST" || a.PathRaw != "/api/v1/orders" || a.StatusCode != 201 || a.BytesOut != 512 || a.DurationMs != 42 || a.Host != "shop.example" {
		t.Fatalf("application: %+v", a)
	}
	if evt.Network.SrcIP != "198.51.100.7" || evt.Network.DstIP != "10.1.0.7" {
		t.Fatalf("network: %+v", evt.Network)
	}
	if evt.Content.RequestHeaders["x-user-id"] != "u-1001" {
		t.Fatalf("identity header missing: %v", evt.Content.RequestHeaders)
	}
	if _, ok := evt.Content.RequestHeaders["cookie"]; ok {
		t.Fatalf("cookie collected: %v", evt.Content.RequestHeaders)
	}
	if evt.Timestamp.UTC().Hour() != 5 {
		t.Fatalf("timestamp %v", evt.Timestamp)
	}
}

func TestNginxUnmatchedLineAndBadFormat(t *testing.T) {
	p, _ := newNginxParser("", "")
	if p.parse("not an access log line") != nil {
		t.Fatal("garbage parsed")
	}
	if _, err := newNginxParser("no variables here", ""); err == nil {
		t.Fatal("format without variables accepted")
	}
	g := New().(*GatewayLogCollector)
	if err := g.Initialize(collector.CollectorConfig{GWLogFormat: "xml"}); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestNginxMsecAndUriArgs(t *testing.T) {
	p, err := newNginxParser(`$msec $request_method $uri $args $status`, "")
	if err != nil {
		t.Fatal(err)
	}
	evt := p.parse(`1791601536.123 GET /search q=phone 200`)
	if evt == nil || evt.Application.PathRaw != "/search?q=phone" || evt.Timestamp.UnixMilli() != 1791601536123 {
		t.Fatalf("event: %+v", evt)
	}
}

func TestKongJSON(t *testing.T) {
	line := `{"request":{"method":"GET","uri":"/api/v1/preview?url=x","headers":{"host":"api.example:8443","x-user-id":"u-7","cookie":"a=b","accept":["a","b"]},"querystring":{"url":"http://169.254.169.254/","debug":true},"size":120},"response":{"status":403,"size":88},"client_ip":"198.51.100.3","latencies":{"request":17},"service":{"name":"preview-svc"},"started_at":1791601536123}`
	evt := parseJSON(line)
	if evt == nil {
		t.Fatal("kong line not parsed")
	}
	if evt.Application.Host != "api.example" || evt.Application.StatusCode != 403 || evt.Application.DurationMs != 17 || evt.Metadata.ServiceName != "preview-svc" {
		t.Fatalf("event: %+v %+v", evt.Application, evt.Metadata)
	}
	if evt.Content.RequestHeaders["x-user-id"] != "u-7" || evt.Content.RequestHeaders["accept"] != "a" {
		t.Fatalf("headers: %v", evt.Content.RequestHeaders)
	}
	if _, ok := evt.Content.RequestHeaders["cookie"]; ok {
		t.Fatal("cookie kept")
	}
	if evt.Content.QueryParams["url"] != "http://169.254.169.254/" {
		t.Fatalf("query: %v", evt.Content.QueryParams)
	}
	if evt.Timestamp.UnixMilli() != 1791601536123 {
		t.Fatalf("timestamp %v", evt.Timestamp)
	}
}

func TestCollectorWithNginxFormat(t *testing.T) {
	_ = logger.Init(false)
	openRetryInterval = 20 * time.Millisecond
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	g := New().(*GatewayLogCollector)
	if err := g.Initialize(collector.CollectorConfig{GWLogPath: path, GWLogFormat: "nginx"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := g.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	time.Sleep(150 * time.Millisecond)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	defer f.Close()
	f.WriteString(`10.0.0.9 - - [10/Oct/2026:13:55:36 +0800] "DELETE /api/v1/orders/9 HTTP/1.1" 204 0 "-" "curl/8.0"` + "\n")
	select {
	case evt := <-g.Events():
		if evt.Application.Method != "DELETE" || evt.Application.StatusCode != 204 {
			t.Fatalf("event: %+v", evt.Application)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event from nginx log line")
	}
}
