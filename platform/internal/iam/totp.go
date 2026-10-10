package iam

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238 defaults, understood by every authenticator
// app): HMAC-SHA1, 30-second steps, 6 digits. One step of clock skew is
// accepted either way.
const (
	totpStep   = 30
	totpDigits = 6
	totpSkew   = 1
	totpIssuer = "FlowLens"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTOTPSecret returns a random 160-bit secret, base32 encoded.
func newTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate totp secret: %v", err))
	}
	return b32.EncodeToString(b)
}

// totpCode returns the code for secret at time step counter.
func totpCode(secret string, counter int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1000000), nil
}

// verifyTOTP checks code against secret around now. It returns the matched
// step, which must be greater than lastStep so a code cannot be replayed.
func verifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits || secret == "" {
		return 0, false
	}
	cur := now.Unix() / totpStep
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := cur + d
		want, err := totpCode(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			if step <= lastStep {
				return 0, false
			}
			return step, true
		}
	}
	return 0, false
}

// totpURI is the otpauth:// URI encoded in the enrollment QR code.
func totpURI(username, secret string) string {
	label := url.PathEscape(totpIssuer + ":" + username)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpStep))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
