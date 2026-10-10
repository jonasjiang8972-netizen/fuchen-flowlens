package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// totpAt returns the code offset steps from now (one step of skew is
// accepted by the platform).
func totpAt(t *testing.T, secret string, offset int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30+offset))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

func TestMFAOverHTTP(t *testing.T) {
	h := newHarness(t, "")
	sys := h.ready("sysadmin")
	sec := h.ready("secadmin")

	enroll := func(token string) string {
		t.Helper()
		w := h.do(http.MethodPost, "/api/v1/auth/mfa/setup", token, "")
		var setup struct {
			Secret string `json:"secret"`
			URI    string `json:"otpauth_uri"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil || w.Code != http.StatusOK || setup.Secret == "" {
			t.Fatalf("setup: %d %s", w.Code, w.Body.String())
		}
		if w = h.do(http.MethodPost, "/api/v1/auth/mfa/enable", token, `{"code":"`+totpAt(t, setup.Secret, 0)+`"}`); w.Code != http.StatusOK {
			t.Fatalf("enable: %d %s", w.Code, w.Body.String())
		}
		return setup.Secret
	}
	enroll(sys)

	// Policy on: an unenrolled administrator is blocked until enrolling.
	w := h.do(http.MethodGet, "/api/v1/admin/security-policy", sys, "")
	var got struct {
		Policy map[string]any `json:"policy"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	got.Policy["mfa_required_admins"] = true
	body, _ := json.Marshal(got.Policy)
	if w = h.do(http.MethodPut, "/api/v1/admin/security-policy", sys, string(body)); w.Code != http.StatusOK {
		t.Fatalf("policy: %d %s", w.Code, w.Body.String())
	}
	w = h.do(http.MethodGet, "/api/v1/assets", sec, "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "mfa_enrollment_required") {
		t.Fatalf("unenrolled: %d %s", w.Code, w.Body.String())
	}
	secret := enroll(sec)
	if w = h.do(http.MethodGet, "/api/v1/assets", sec, ""); w.Code != http.StatusOK {
		t.Fatalf("after enrolling: %d %s", w.Code, w.Body.String())
	}

	// Login now takes two steps; the password step grants no session.
	w = h.do(http.MethodPost, "/api/v1/auth/login", "", `{"username":"secadmin","password":"`+newPassword+`"}`)
	var step1 map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &step1)
	if step1["mfa_required"] != true || step1["token"] != nil || len(w.Result().Cookies()) != 0 {
		t.Fatalf("password step: %s", w.Body.String())
	}
	w = h.do(http.MethodPost, "/api/v1/auth/login/mfa", "", `{"mfa_token":"`+step1["mfa_token"].(string)+`","code":"000000"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", w.Code)
	}
	// The enrollment code's step is used up; the next step's code is
	// within the accepted skew.
	code := totpAt(t, secret, 1)
	w = h.do(http.MethodPost, "/api/v1/auth/login/mfa", "", `{"mfa_token":"`+step1["mfa_token"].(string)+`","code":"`+code+`"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("code step: %d %s", w.Code, w.Body.String())
	}

	// The system administrator can reset it; listing shows the state.
	var me struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	_ = json.Unmarshal(h.do(http.MethodGet, "/api/v1/auth/me", sec, "").Body.Bytes(), &me)
	if w = h.do(http.MethodPost, "/api/v1/admin/users/"+me.User.ID+"/reset-mfa", sys, ""); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"mfa_enabled":false`) {
		t.Fatalf("reset: %d %s", w.Code, w.Body.String())
	}
}
