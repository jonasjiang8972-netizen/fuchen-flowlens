package soar

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Webhook posts each action to a URL, signed so the receiver can verify it
// came from FlowLens. It is the integration point for SOAR platforms and
// in-house automation.
//
// Request body: {"action":"block_ip"|"unblock_ip"|"ping","ip":...,"reason":...,
// "alert_id":...,"ttl_seconds":...,"sent_at":<unix>}.
// Headers: X-FlowLens-Timestamp (unix seconds) and
// X-FlowLens-Signature: sha256=hex(HMAC-SHA256(secret, timestamp + "." + body)).
// Receivers should reject timestamps that are far from their own clock.
type Webhook struct {
	url    string
	secret []byte
	client *http.Client
	now    func() time.Time
}

func NewWebhook(url, secret string) *Webhook {
	return &Webhook{url: url, secret: []byte(secret), client: newHTTPClient(), now: time.Now}
}

func (w *Webhook) Name() string  { return "webhook" }
func (w *Webhook) Label() string { return "SOAR / Webhook" }

// Sign returns the signature header value for a timestamp and body.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (w *Webhook) post(ctx context.Context, payload map[string]any) error {
	payload["sent_at"] = w.now().Unix()
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(w.now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FlowLens-Timestamp", ts)
	req.Header.Set("X-FlowLens-Signature", Sign(w.secret, ts, body))
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return fmt.Errorf("接收方返回 HTTP %d: %s", resp.StatusCode, msg)
	}
	return nil
}

func (w *Webhook) Block(ctx context.Context, req Request) (string, error) {
	return "", w.post(ctx, map[string]any{
		"action": "block_ip", "ip": req.IP, "reason": req.Reason, "alert_id": req.AlertID,
		"ttl_seconds": int64(req.TTL / time.Second),
	})
}

func (w *Webhook) Unblock(ctx context.Context, ip, _ string) error {
	return w.post(ctx, map[string]any{"action": "unblock_ip", "ip": ip})
}

func (w *Webhook) Check(ctx context.Context) error {
	return w.post(ctx, map[string]any{"action": "ping"})
}
