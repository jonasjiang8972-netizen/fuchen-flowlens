// Package redact removes credentials and masks personal financial
// information in captured API traffic before it leaves the collector
// (JR/T 0171-2020: authentication data is not retained; identity, phone and
// card numbers are masked). The platform applies it again on ingest.
//
// Field names are kept so sensitive-data classification still works; only
// values are removed or masked.
package redact

import (
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/emmansun/gmsm/sm3"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

// Removed replaces secret values (passwords, PINs, CVVs).
const Removed = "[REDACTED]"

// credentialHeaders carry authentication data. Their values are replaced by
// a keyed SM3 fingerprint: the credential never leaves the collector, but
// the same credential still maps to the same caller for detection.
var credentialHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true, "x-access-token": true, "x-csrf-token": true,
	"x-client-secret": true, "x-amz-security-token": true,
}

// secretKeyParts mark field names whose values are secrets and are dropped.
var secretKeyParts = []string{"password", "passwd", "pwd", "passcode", "secret", "pin", "cvv", "cvn", "cvc", "otp", "captcha", "private_key", "token"}

// IsSecretKey reports whether a field name denotes a secret value.
func IsSecretKey(name string) bool {
	n := strings.ToLower(name)
	if credentialHeaders[n] {
		return true
	}
	for _, part := range secretKeyParts {
		if n == part || strings.Contains(n, part) {
			return true
		}
	}
	return false
}

var (
	// 18-digit mainland resident ID (last char may be X).
	idCardRe = regexp.MustCompile(`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`)
	// Mainland mobile number.
	phoneRe = regexp.MustCompile(`\b1[3-9]\d{9}\b`)
	// Candidate bank card numbers (13-19 digits, optional spaces/dashes);
	// confirmed with the Luhn check before masking.
	cardRe = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
)

// Redactor applies redaction with a per-deployment fingerprint key.
type Redactor struct {
	key []byte
}

// New returns a Redactor. key keys the credential fingerprints; use a
// deployment secret so fingerprints cannot be brute-forced offline.
func New(key string) *Redactor {
	return &Redactor{key: []byte(key)}
}

// Fingerprint returns a short keyed SM3 digest identifying a credential.
func (r *Redactor) Fingerprint(value string) string {
	m := hmac.New(sm3.New, r.key)
	m.Write([]byte(value))
	return "sm3:" + hex.EncodeToString(m.Sum(nil))[:16]
}

func isFingerprint(v string) bool {
	if len(v) != 20 || !strings.HasPrefix(v, "sm3:") {
		return false
	}
	_, err := hex.DecodeString(v[4:])
	return err == nil
}

// MaskText masks ID card, phone and bank card numbers in free text.
func MaskText(s string) string {
	s = idCardRe.ReplaceAllStringFunc(s, func(v string) string { return v[:3] + strings.Repeat("*", len(v)-7) + v[len(v)-4:] })
	s = cardRe.ReplaceAllStringFunc(s, func(v string) string {
		digits := strings.NewReplacer(" ", "", "-", "").Replace(v)
		if len(digits) < 13 || !luhn(digits) {
			return v
		}
		return digits[:6] + strings.Repeat("*", len(digits)-10) + digits[len(digits)-4:]
	})
	s = phoneRe.ReplaceAllStringFunc(s, func(v string) string { return v[:3] + "****" + v[7:] })
	return s
}

func luhn(digits string) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// Event redacts an event in place: headers, query parameters, bodies and the
// raw path.
func (r *Redactor) Event(evt *shared.APIEvent) {
	c := &evt.Content
	c.RequestHeaders = r.headers(c.RequestHeaders)
	c.ResponseHeaders = r.headers(c.ResponseHeaders)
	c.QueryParams = r.params(c.QueryParams)
	c.RequestBody = r.body(c.RequestBody, c.ContentType)
	c.ResponseBody = r.body(c.ResponseBody, "")
	evt.Application.PathRaw = MaskText(evt.Application.PathRaw)
}

func (r *Redactor) headers(h map[string]string) map[string]string {
	for k, v := range h {
		switch {
		case credentialHeaders[strings.ToLower(k)]:
			if v != "" && !isFingerprint(v) {
				h[k] = r.Fingerprint(v)
			}
		case IsSecretKey(k):
			h[k] = Removed
		default:
			h[k] = MaskText(v)
		}
	}
	return h
}

func (r *Redactor) params(p map[string]string) map[string]string {
	for k, v := range p {
		if IsSecretKey(k) {
			p[k] = Removed
		} else {
			p[k] = MaskText(v)
		}
	}
	return p
}

func (r *Redactor) body(b []byte, contentType string) []byte {
	if len(b) == 0 {
		return b
	}
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var v any
		if json.Unmarshal(b, &v) == nil {
			if out, err := json.Marshal(redactJSON(v)); err == nil {
				return out
			}
		}
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if vals, err := url.ParseQuery(trimmed); err == nil {
			for k, vs := range vals {
				for i := range vs {
					if IsSecretKey(k) {
						vs[i] = Removed
					} else {
						vs[i] = MaskText(vs[i])
					}
				}
			}
			return []byte(vals.Encode())
		}
	}
	// Unparseable or truncated bodies: mask personal data patterns, and drop
	// "key":"value" style secrets textually.
	return []byte(MaskText(secretPairRe.ReplaceAllString(string(b), `$1"`+Removed+`"`)))
}

var secretPairRe = regexp.MustCompile(`(?i)("(?:[a-z_]*(?:password|passwd|pwd|secret|pin|cvv|cvn|token)[a-z_]*)"\s*:\s*)"[^"]*"`)

func redactJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if IsSecretKey(k) {
				if _, isObj := val.(map[string]any); !isObj {
					t[k] = Removed
					continue
				}
			}
			t[k] = redactJSON(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactJSON(t[i])
		}
		return t
	case string:
		return MaskText(t)
	case float64:
		// Numbers can carry phone or card numbers too (e.g. "mobile": 13800138000).
		s := strings.TrimSuffix(strings.TrimSuffix(jsonNumber(t), ".0"), ".00")
		if masked := MaskText(s); masked != s {
			return masked
		}
		return t
	default:
		return v
	}
}

func jsonNumber(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}
