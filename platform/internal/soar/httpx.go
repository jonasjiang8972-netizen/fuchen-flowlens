package soar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpClient is shared by the connectors that speak HTTP. Redirects are not
// followed: a connector URL is operator-configured, and following a redirect
// would send credentials wherever the response points.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// statusError describes an unexpected HTTP status without echoing more of
// the response than an operator needs to diagnose it.
type statusError struct {
	Status int
	Body   string
}

func (e *statusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

// doJSON sends an optional JSON body and decodes an optional JSON response.
// Any status outside 2xx is returned as *statusError.
func doJSON(ctx context.Context, c *http.Client, method, url string, headers map[string]string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return &statusError{Status: resp.StatusCode, Body: msg}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func isStatus(err error, code int) bool {
	se, ok := err.(*statusError)
	return ok && se.Status == code
}

// withoutIP returns list without ip, and whether ip was present.
func withoutIP(list []string, ip string) ([]string, bool) {
	out := make([]string, 0, len(list))
	found := false
	for _, x := range list {
		if x == ip {
			found = true
			continue
		}
		out = append(out, x)
	}
	return out, found
}

func containsIP(list []string, ip string) bool {
	for _, x := range list {
		if x == ip {
			return true
		}
	}
	return false
}
