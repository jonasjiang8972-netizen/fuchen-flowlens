package iam

import (
	"context"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

// Second-factor login challenges live in memory: a restart only means the
// operator enters the password again.
const (
	mfaChallengeTTL      = 5 * time.Minute
	mfaChallengeAttempts = 5
)

type mfaChallenge struct {
	userID, ip, userAgent string
	expires               time.Time
	attempts              int
}

// adminRoles are the roles MFARequiredForAdmins applies to.
var adminRoles = map[Role]bool{RoleSysAdmin: true, RoleAuditAdmin: true, RoleSecAdmin: true}

// mustEnroll reports whether the policy requires u to enroll a second
// factor it does not have yet.
func mustEnroll(pol Policy, u *storage.User) bool {
	return pol.MFARequiredForAdmins && adminRoles[Role(u.Role)] && !u.TOTPEnabled
}

func (s *Service) pruneChallengesLocked(now time.Time) {
	for k, c := range s.challenges {
		if !now.Before(c.expires) {
			delete(s.challenges, k)
		}
	}
}

// LoginTOTP completes a login that Login answered with MFARequired. Wrong
// codes count toward the account lockout like wrong passwords, and the
// challenge is bound to the source IP of the password step.
func (s *Service) LoginTOTP(ctx context.Context, mfaToken, code, ip, userAgent string) (*LoginResult, error) {
	pol := s.Policy(ctx)
	now := s.now()
	key := HashToken(mfaToken)
	s.mu.Lock()
	s.pruneChallengesLocked(now)
	ch := s.challenges[key]
	if ch == nil || ch.ip != ip {
		s.mu.Unlock()
		return nil, ErrMFAChallenge
	}
	ch.attempts++
	if ch.attempts >= mfaChallengeAttempts {
		delete(s.challenges, key) // last try
	}
	s.mu.Unlock()

	fail := func(u *storage.User, reason string, err error) (*LoginResult, error) {
		_ = s.audit.Record(ctx, storage.AuditRecord{UserID: u.ID, Username: u.Username, Role: u.Role, SourceIP: ip, Console: "auth",
			EventType: "auth.login", Target: u.Username, Result: audit.ResultFailure, Reason: reason})
		return nil, err
	}
	if !s.limiter.allow(ip, pol.LoginRatePerIPMinute, now) {
		return nil, ErrRateLimited
	}
	u, err := s.store.GetUserByID(ctx, ch.userID)
	if err != nil {
		return nil, ErrMFAChallenge
	}
	if u.Status != "active" {
		return fail(u, "账号已停用", ErrAccountDisabled)
	}
	if u.LockedUntil != nil && now.Before(*u.LockedUntil) {
		s.dropChallenge(key)
		return fail(u, "账号锁定中", ErrAccountLocked)
	}
	if !u.TOTPEnabled {
		s.dropChallenge(key)
		return nil, ErrMFAChallenge
	}
	step, ok := verifyTOTP(u.TOTPSecret, code, now, u.TOTPLastStep)
	if !ok {
		reason, err := s.countFailure(ctx, u, pol, now, "动态验证码错误")
		if err != nil {
			return nil, err
		}
		if u.LockedUntil != nil {
			s.dropChallenge(key)
			return fail(u, reason, ErrAccountLocked)
		}
		return fail(u, reason, ErrMFACode)
	}
	s.dropChallenge(key)
	u.TOTPLastStep = step
	return s.finishLogin(ctx, u, pol, now, ip, userAgent, "口令 + 动态验证码")
}

func (s *Service) dropChallenge(key string) {
	s.mu.Lock()
	delete(s.challenges, key)
	s.mu.Unlock()
}

// MFASetup is the enrollment material shown once as a QR code.
type MFASetup struct {
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
}

// SetupMFA starts enrollment: it generates a secret that becomes active
// only once EnableMFA confirms a code from the authenticator.
func (s *Service) SetupMFA(ctx context.Context, p *Principal) (MFASetup, error) {
	u, err := s.store.GetUserByID(ctx, p.UserID)
	if err != nil {
		return MFASetup{}, err
	}
	if u.TOTPEnabled {
		return MFASetup{}, invalid("已启用双因素认证；如需更换身份验证器，请先关闭")
	}
	u.TOTPPending, u.UpdatedAt = newTOTPSecret(), s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return MFASetup{}, err
	}
	s.record(ctx, p, "auth.mfa_setup", u.Username, audit.ResultSuccess, "", "")
	return MFASetup{Secret: u.TOTPPending, URI: totpURI(u.Username, u.TOTPPending)}, nil
}

// EnableMFA confirms enrollment with a code from the authenticator.
func (s *Service) EnableMFA(ctx context.Context, p *Principal, code string) error {
	u, err := s.store.GetUserByID(ctx, p.UserID)
	if err != nil {
		return err
	}
	if u.TOTPEnabled {
		return invalid("已启用双因素认证")
	}
	if u.TOTPPending == "" {
		return invalid("请先生成绑定二维码")
	}
	step, ok := verifyTOTP(u.TOTPPending, code, s.now(), 0)
	if !ok {
		s.record(ctx, p, "auth.mfa_enable", u.Username, audit.ResultFailure, "动态验证码错误", "")
		return invalid("动态验证码错误，请确认手机时间准确后重试")
	}
	u.TOTPSecret, u.TOTPPending, u.TOTPEnabled, u.TOTPLastStep, u.UpdatedAt = u.TOTPPending, "", true, step, s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return err
	}
	s.record(ctx, p, "auth.mfa_enable", u.Username, audit.ResultSuccess, "", "TOTP")
	return nil
}

// DisableMFA turns the second factor off after checking the password and a
// current code. It is refused while the policy requires MFA for the role.
func (s *Service) DisableMFA(ctx context.Context, p *Principal, password, code string) error {
	u, err := s.store.GetUserByID(ctx, p.UserID)
	if err != nil {
		return err
	}
	if !u.TOTPEnabled {
		return invalid("未启用双因素认证")
	}
	pol := s.Policy(ctx)
	if pol.MFARequiredForAdmins && adminRoles[Role(u.Role)] {
		s.record(ctx, p, "auth.mfa_disable", u.Username, audit.ResultFailure, "安全策略要求管理员启用双因素认证", "")
		return invalid("安全策略要求管理员启用双因素认证，不能关闭")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		s.record(ctx, p, "auth.mfa_disable", u.Username, audit.ResultFailure, "口令错误", "")
		return invalid("口令错误")
	}
	if _, ok := verifyTOTP(u.TOTPSecret, code, s.now(), u.TOTPLastStep); !ok {
		s.record(ctx, p, "auth.mfa_disable", u.Username, audit.ResultFailure, "动态验证码错误", "")
		return invalid("动态验证码错误")
	}
	clearTOTP(u)
	u.UpdatedAt = s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return err
	}
	s.record(ctx, p, "auth.mfa_disable", u.Username, audit.ResultSuccess, "", "")
	return nil
}

// ResetMFA clears another account's second factor (lost phone) and signs it
// out; with the policy on, the account must enroll again at next login.
func (s *Service) ResetMFA(ctx context.Context, actor *Principal, id string) (UserView, error) {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return UserView{}, err
	}
	if u.ID == actor.UserID {
		s.record(ctx, actor, "user.reset_mfa", u.Username, audit.ResultFailure, "不能重置自己的双因素认证", "")
		return UserView{}, invalid("不能重置自己的双因素认证")
	}
	clearTOTP(u)
	u.UpdatedAt = s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return UserView{}, err
	}
	_ = s.store.DeleteUserSessions(ctx, u.ID, "")
	s.record(ctx, actor, "user.reset_mfa", u.Username, audit.ResultSuccess, "", "")
	return s.viewWithPolicy(u, s.Policy(ctx)), nil
}

func clearTOTP(u *storage.User) {
	u.TOTPEnabled, u.TOTPSecret, u.TOTPPending, u.TOTPLastStep = false, "", "", 0
}
