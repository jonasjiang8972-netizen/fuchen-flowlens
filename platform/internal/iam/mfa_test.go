package iam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238Vectors(t *testing.T) {
	// RFC 6238 appendix B, SHA1 key "12345678901234567890" (last 6 digits).
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := totpCode(secret, ts/totpStep)
		if err != nil || got != want {
			t.Errorf("t=%d: got %s, want %s (%v)", ts, got, want, err)
		}
	}
}

func TestVerifyTOTPSkewAndReplay(t *testing.T) {
	secret := newTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	prev, _ := totpCode(secret, now.Unix()/totpStep-1)
	step, ok := verifyTOTP(secret, prev, now, 0)
	if !ok {
		t.Fatal("previous-step code rejected")
	}
	if _, ok := verifyTOTP(secret, prev, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	old, _ := totpCode(secret, now.Unix()/totpStep-3)
	if _, ok := verifyTOTP(secret, old, now, 0); ok {
		t.Fatal("code 90s old accepted")
	}
	if _, ok := verifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
}

// enroll turns on MFA for p and returns the secret.
func (f *fixture) enroll(t *testing.T, p *Principal) string {
	t.Helper()
	ctx := context.Background()
	setup, err := f.svc.SetupMFA(ctx, p)
	if err != nil || !strings.HasPrefix(setup.URI, "otpauth://totp/FlowLens:") {
		t.Fatalf("setup: %+v %v", setup, err)
	}
	if err := f.svc.EnableMFA(ctx, p, "000000"); err == nil {
		t.Fatal("wrong enrollment code accepted")
	}
	code, _ := totpCode(setup.Secret, f.now.Unix()/totpStep)
	if err := f.svc.EnableMFA(ctx, p, code); err != nil {
		t.Fatal(err)
	}
	return setup.Secret
}

func TestMFALogin(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	secret := f.enroll(t, f.sysadmin(t))
	f.advance(time.Minute)

	res, err := f.login(t, "sysadmin", goodPw)
	if err != nil || !res.MFARequired || res.Token != "" || res.MFAToken == "" {
		t.Fatalf("password step: %+v %v", res, err)
	}
	// Another IP cannot use the challenge.
	code, _ := totpCode(secret, f.now.Unix()/totpStep)
	if _, err := f.svc.LoginTOTP(ctx, res.MFAToken, code, "10.9.9.9", "x"); !errors.Is(err, ErrMFAChallenge) {
		t.Fatalf("other ip: %v", err)
	}
	if _, err := f.svc.LoginTOTP(ctx, res.MFAToken, "000000", "10.0.0.1", "x"); !errors.Is(err, ErrMFACode) {
		t.Fatalf("wrong code: %v", err)
	}
	done, err := f.svc.LoginTOTP(ctx, res.MFAToken, code, "10.0.0.1", "x")
	if err != nil || done.Token == "" || !done.User.MFAEnabled {
		t.Fatalf("code step: %+v %v", done, err)
	}
	// The challenge is single-use and the code cannot be replayed.
	if _, err := f.svc.LoginTOTP(ctx, res.MFAToken, code, "10.0.0.1", "x"); !errors.Is(err, ErrMFAChallenge) {
		t.Fatalf("reused challenge: %v", err)
	}
	res2, _ := f.login(t, "sysadmin", goodPw)
	if _, err := f.svc.LoginTOTP(ctx, res2.MFAToken, code, "10.0.0.1", "x"); !errors.Is(err, ErrMFACode) {
		t.Fatalf("replayed code: %v", err)
	}
	// Challenges expire.
	f.advance(6 * time.Minute)
	code, _ = totpCode(secret, f.now.Unix()/totpStep)
	if _, err := f.svc.LoginTOTP(ctx, res2.MFAToken, code, "10.0.0.1", "x"); !errors.Is(err, ErrMFAChallenge) {
		t.Fatalf("expired challenge: %v", err)
	}
	var ok bool
	for _, r := range f.events(t, "auth.login") {
		if r.Result == "success" && strings.Contains(r.Detail, "动态验证码") {
			ok = true
		}
	}
	if !ok {
		t.Fatal("second-factor login not audited")
	}
}

func TestWrongMFACodesLockTheAccount(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enroll(t, f.sysadmin(t))
	var err error
	for i := 0; i < DefaultPolicy().LockoutThreshold; i++ {
		res, lerr := f.login(t, "sysadmin", goodPw)
		if lerr != nil {
			t.Fatalf("attempt %d: %v", i, lerr)
		}
		_, err = f.svc.LoginTOTP(ctx, res.MFAToken, "000000", "10.0.0.1", "x")
	}
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("after threshold: %v", err)
	}
	if _, err := f.login(t, "sysadmin", goodPw); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked account logged in: %v", err)
	}
}

func TestMFAPolicyForAdmins(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.sysadmin(t)
	pol := DefaultPolicy()
	pol.MFARequiredForAdmins = true
	if err := f.svc.UpdatePolicy(ctx, admin, pol); err == nil {
		t.Fatal("unenrolled operator turned the requirement on")
	}
	f.enroll(t, admin)
	if err := f.svc.UpdatePolicy(ctx, admin, pol); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Minute)
	r, _ := f.login(t, "secadmin", initPw)
	sec, _ := f.svc.Authenticate(ctx, r.Token, "10.0.0.1")
	_ = f.svc.ChangePassword(ctx, sec, initPw, goodPw)
	res, err := f.login(t, "secadmin", goodPw)
	if err != nil || res.MFARequired || !res.User.MustEnrollMFA {
		t.Fatalf("unenrolled admin login: %+v %v", res, err)
	}
	p, _ := f.svc.Authenticate(ctx, res.Token, "10.0.0.1")
	if !p.MustEnrollMFA || p.Can(PermSecurityRead) {
		t.Fatal("unenrolled admin keeps permissions")
	}
	secret := f.enroll(t, p)
	p, _ = f.svc.Authenticate(ctx, res.Token, "10.0.0.1")
	if p.MustEnrollMFA || !p.Can(PermSecurityRead) {
		t.Fatal("enrolled admin lacks permissions")
	}
	f.advance(time.Minute)
	code, _ := totpCode(secret, f.now.Unix()/totpStep)
	if err := f.svc.DisableMFA(ctx, p, goodPw, code); err == nil {
		t.Fatal("disabled MFA against policy")
	}
}

func TestDisableAndResetMFA(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.sysadmin(t)
	secret := f.enroll(t, admin)
	f.advance(time.Minute)
	code, _ := totpCode(secret, f.now.Unix()/totpStep)
	if err := f.svc.DisableMFA(ctx, admin, "wrong", code); err == nil {
		t.Fatal("disabled with wrong password")
	}
	if err := f.svc.DisableMFA(ctx, admin, goodPw, code); err != nil {
		t.Fatal(err)
	}
	if me, _ := f.svc.Me(ctx, admin); me.MFAEnabled {
		t.Fatal("still enabled")
	}

	// Reset another account's second factor.
	res, _ := f.login(t, "secadmin", initPw)
	sec, _ := f.svc.Authenticate(ctx, res.Token, "10.0.0.1")
	_ = f.svc.ChangePassword(ctx, sec, initPw, goodPw)
	sec, _ = f.svc.Authenticate(ctx, res.Token, "10.0.0.1")
	f.enroll(t, sec)
	if _, err := f.svc.ResetMFA(ctx, admin, admin.UserID); err == nil {
		t.Fatal("reset own MFA")
	}
	v, err := f.svc.ResetMFA(ctx, admin, sec.UserID)
	if err != nil || v.MFAEnabled {
		t.Fatalf("reset: %+v %v", v, err)
	}
	if _, err := f.svc.Authenticate(ctx, res.Token, "10.0.0.1"); err == nil {
		t.Fatal("reset did not sign the account out")
	}
	if len(f.events(t, "user.reset_mfa")) == 0 {
		t.Fatal("reset not audited")
	}
}
