package iam

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm3"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

const policySettingKey = "security_policy"

// Errors surfaced to clients. Wrong username and wrong password share one
// message so accounts cannot be enumerated.
var (
	ErrBadCredentials   = errors.New("用户名或口令错误")
	ErrAccountLocked    = errors.New("账号已锁定，请稍后再试或联系系统管理员")
	ErrAccountDisabled  = errors.New("账号已停用，请联系系统管理员")
	ErrAccountExpired   = errors.New("账号已过有效期，请联系系统管理员")
	ErrRateLimited      = errors.New("登录尝试过于频繁，请稍后再试")
	ErrSessionInvalid   = errors.New("会话无效或已过期，请重新登录")
	ErrForbidden        = errors.New("没有执行该操作的权限")
	ErrPasswordRequired = errors.New("口令已过期或为初始口令，请先修改口令")
)

// ValidationError carries a user-facing message for a rejected request.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ValidationError{Msg: fmt.Sprintf(format, a...)} }

// Principal is the authenticated operator behind a request.
type Principal struct {
	UserID             string `json:"user_id"`
	Username           string `json:"username"`
	DisplayName        string `json:"display_name"`
	Role               Role   `json:"role"`
	MustChangePassword bool   `json:"must_change_password"`
	SourceIP           string `json:"-"`
	sessionHash        string
	demo               bool
}

// DemoPrincipal is used when the platform runs with -demo (no login). It
// holds every permission and must never be used outside demo mode.
func DemoPrincipal() *Principal {
	return &Principal{UserID: "demo", Username: "demo", DisplayName: "演示用户", Role: RoleSecAdmin, demo: true}
}

// Can reports whether the principal holds permission p. A principal that
// must change its password holds no permissions until it does.
func (p *Principal) Can(perm Permission) bool {
	if p != nil && p.demo {
		return true
	}
	return p != nil && !p.MustChangePassword && Can(p.Role, perm)
}

// AuditActor fills the actor fields of an audit record.
func (p *Principal) AuditActor(rec *storage.AuditRecord) {
	if p == nil {
		return
	}
	rec.UserID, rec.Username, rec.Role = p.UserID, p.Username, string(p.Role)
	if p.SourceIP != "" {
		rec.SourceIP = p.SourceIP
	}
}

type Service struct {
	store   storage.IdentityStore
	audit   *audit.Service
	limiter *ipLimiter
	now     func() time.Time

	mu         sync.Mutex
	policy     Policy
	policyAt   time.Time
	dummyHash  []byte
	bcryptCost int
}

func NewService(store storage.IdentityStore, auditSvc *audit.Service) *Service {
	s := &Service{
		store:      store,
		audit:      auditSvc,
		limiter:    newIPLimiter(),
		now:        time.Now,
		bcryptCost: bcrypt.DefaultCost,
	}
	s.dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), s.bcryptCost)
	return s
}

// ─── Policy ────────────────────────────────────────────────────

// Policy returns the current security policy, cached for 30 seconds.
func (s *Service) Policy(ctx context.Context) Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.policyAt.IsZero() && s.now().Sub(s.policyAt) < 30*time.Second {
		return s.policy
	}
	p := DefaultPolicy()
	if raw, err := s.store.GetSetting(ctx, policySettingKey); err == nil {
		var stored Policy
		if json.Unmarshal(raw, &stored) == nil && stored.Validate() == nil {
			p = stored
		}
	}
	s.policy, s.policyAt = p, s.now()
	return p
}

func (s *Service) UpdatePolicy(ctx context.Context, actor *Principal, p Policy) error {
	if err := p.Validate(); err != nil {
		s.record(ctx, actor, "policy.update", "security_policy", audit.ResultFailure, err.Error(), "")
		return &ValidationError{Msg: err.Error()}
	}
	old := s.Policy(ctx)
	raw, _ := json.Marshal(p)
	if err := s.store.PutSetting(ctx, policySettingKey, raw); err != nil {
		return err
	}
	s.mu.Lock()
	s.policy, s.policyAt = p, s.now()
	s.mu.Unlock()
	before, _ := json.Marshal(old)
	s.record(ctx, actor, "policy.update", "security_policy", audit.ResultSuccess, "", fmt.Sprintf("before=%s after=%s", before, raw))
	return nil
}

// ─── Bootstrap ─────────────────────────────────────────────────

// BootstrapResult lists the accounts created on first start.
type BootstrapResult struct {
	Usernames         []string
	GeneratedPassword string // set when no initial password was supplied
}

// Bootstrap creates one account per management duty on an empty user store.
// All of them must change the initial password at first login.
func (s *Service) Bootstrap(ctx context.Context, initialPassword string) (*BootstrapResult, error) {
	n, err := s.store.CountUsers(ctx)
	if err != nil || n > 0 {
		return nil, err
	}
	res := &BootstrapResult{}
	if initialPassword == "" {
		initialPassword = generatePassword()
		res.GeneratedPassword = initialPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(initialPassword), s.bcryptCost)
	if err != nil {
		return nil, err
	}
	now := s.now()
	seed := []struct {
		username, name string
		role           Role
	}{
		{"sysadmin", "系统管理员", RoleSysAdmin},
		{"auditadmin", "审计管理员", RoleAuditAdmin},
		{"secadmin", "安全管理员", RoleSecAdmin},
	}
	for _, sd := range seed {
		u := &storage.User{
			ID: newID("usr"), Username: sd.username, DisplayName: sd.name,
			PasswordHash: string(hash), PasswordChangedAt: now, MustChangePassword: true,
			Role: string(sd.role), Status: "active", CreatedBy: "system", CreatedAt: now, UpdatedAt: now,
		}
		if err := s.store.CreateUser(ctx, u); err != nil {
			return nil, err
		}
		res.Usernames = append(res.Usernames, sd.username)
		s.record(ctx, nil, "user.bootstrap", sd.username, audit.ResultSuccess, "", "role="+string(sd.role))
	}
	return res, nil
}

// ─── Login / sessions ──────────────────────────────────────────

type LoginResult struct {
	Token              string       `json:"-"`
	ExpiresAt          time.Time    `json:"expires_at"`
	User               UserView     `json:"user"`
	Console            Console      `json:"console"`
	MustChangePassword bool         `json:"must_change_password"`
	Permissions        []Permission `json:"permissions"`
}

func (s *Service) Login(ctx context.Context, username, password, ip, userAgent string) (*LoginResult, error) {
	pol := s.Policy(ctx)
	now := s.now()
	fail := func(u *storage.User, reason string, err error) (*LoginResult, error) {
		rec := storage.AuditRecord{Username: username, SourceIP: ip, Console: "auth", EventType: "auth.login",
			Target: username, Result: audit.ResultFailure, Reason: reason}
		if u != nil {
			rec.UserID, rec.Role = u.ID, u.Role
		}
		_ = s.audit.Record(ctx, rec)
		return nil, err
	}

	if !s.limiter.allow(ip, pol.LoginRatePerIPMinute, now) {
		return fail(nil, "单 IP 登录频率超限", ErrRateLimited)
	}
	u, err := s.store.GetUserByUsername(ctx, username)
	if errors.Is(err, storage.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password)) // equalise timing
		return fail(nil, "用户不存在", ErrBadCredentials)
	}
	if err != nil {
		return nil, err
	}
	if u.Status != "active" {
		return fail(u, "账号已停用", ErrAccountDisabled)
	}
	if u.ExpiresAt != nil && !now.Before(*u.ExpiresAt) {
		return fail(u, "账号已过有效期", ErrAccountExpired)
	}
	if u.LockedUntil != nil && now.Before(*u.LockedUntil) {
		return fail(u, "账号锁定中", ErrAccountLocked)
	}
	if pol.AccountInactiveDays > 0 {
		last := u.CreatedAt
		if u.LastLoginAt != nil {
			last = *u.LastLoginAt
		}
		if now.Sub(last) > time.Duration(pol.AccountInactiveDays)*24*time.Hour {
			u.Status, u.UpdatedAt = "disabled", now
			if err := s.store.UpdateUser(ctx, u); err != nil {
				return nil, err
			}
			s.record(ctx, nil, "user.auto_disable", u.Username, audit.ResultSuccess, "", fmt.Sprintf("超过 %d 天未登录", pol.AccountInactiveDays))
			return fail(u, "长期未登录，账号已自动停用", ErrAccountDisabled)
		}
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		u.FailedAttempts++
		reason := fmt.Sprintf("口令错误（连续第 %d 次）", u.FailedAttempts)
		if u.FailedAttempts >= pol.LockoutThreshold {
			until := now.Add(time.Duration(pol.LockoutMinutes) * time.Minute)
			u.LockedUntil, u.FailedAttempts = &until, 0
			reason += "，账号已锁定"
			s.record(ctx, nil, "user.lock", u.Username, audit.ResultSuccess, "", fmt.Sprintf("连续 %d 次登录失败，锁定至 %s", pol.LockoutThreshold, until.Format(time.RFC3339)))
		}
		u.UpdatedAt = now
		if err := s.store.UpdateUser(ctx, u); err != nil {
			return nil, err
		}
		return fail(u, reason, ErrBadCredentials)
	}

	// Success
	u.FailedAttempts, u.LockedUntil = 0, nil
	u.LastLoginAt, u.LastLoginIP, u.UpdatedAt = &now, ip, now
	if now.Sub(u.PasswordChangedAt) > time.Duration(pol.PasswordMaxAgeDays)*24*time.Hour {
		u.MustChangePassword = true
	}
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return nil, err
	}
	token := randomToken()
	sess := &storage.Session{
		TokenHash: HashToken(token), UserID: u.ID, SourceIP: ip, UserAgent: truncate(userAgent, 256),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Duration(pol.SessionMaxHours) * time.Hour),
	}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	detail := ""
	if u.MustChangePassword {
		detail = "须修改口令后才能操作"
	}
	_ = s.audit.Record(ctx, storage.AuditRecord{UserID: u.ID, Username: u.Username, Role: u.Role, SourceIP: ip,
		Console: string(ConsoleOf(Role(u.Role))), EventType: "auth.login", Target: u.Username, Result: audit.ResultSuccess, Detail: detail})
	return &LoginResult{
		Token: token, ExpiresAt: sess.ExpiresAt, User: viewOf(u), Console: ConsoleOf(Role(u.Role)),
		MustChangePassword: u.MustChangePassword, Permissions: PermissionsOf(Role(u.Role)),
	}, nil
}

// Authenticate resolves a bearer token to its principal, enforcing idle and
// absolute session timeouts.
func (s *Service) Authenticate(ctx context.Context, token, ip string) (*Principal, error) {
	if token == "" {
		return nil, ErrSessionInvalid
	}
	h := HashToken(token)
	sess, err := s.store.GetSession(ctx, h)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	pol := s.Policy(ctx)
	now := s.now()
	if now.Sub(sess.LastSeenAt) > time.Duration(pol.SessionIdleMinutes)*time.Minute || !now.Before(sess.ExpiresAt) {
		_ = s.store.DeleteSession(ctx, h)
		return nil, ErrSessionInvalid
	}
	u, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil {
		_ = s.store.DeleteSession(ctx, h)
		return nil, ErrSessionInvalid
	}
	if u.Status != "active" || (u.LockedUntil != nil && now.Before(*u.LockedUntil)) ||
		(u.ExpiresAt != nil && !now.Before(*u.ExpiresAt)) || !ValidRole(Role(u.Role)) {
		_ = s.store.DeleteSession(ctx, h)
		return nil, ErrSessionInvalid
	}
	// Limit writes: refresh last-seen at most every 30 seconds.
	if now.Sub(sess.LastSeenAt) > 30*time.Second {
		_ = s.store.TouchSession(ctx, h, now)
	}
	return &Principal{
		UserID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: Role(u.Role),
		MustChangePassword: u.MustChangePassword, SourceIP: ip, sessionHash: h,
	}, nil
}

func (s *Service) Logout(ctx context.Context, p *Principal) error {
	if err := s.store.DeleteSession(ctx, p.sessionHash); err != nil {
		return err
	}
	s.record(ctx, p, "auth.logout", p.Username, audit.ResultSuccess, "", "")
	return nil
}

// CleanupSessions removes idle and expired sessions.
func (s *Service) CleanupSessions(ctx context.Context) error {
	pol := s.Policy(ctx)
	now := s.now()
	return s.store.DeleteExpiredSessions(ctx, now.Add(-time.Duration(pol.SessionIdleMinutes)*time.Minute), now)
}

// ChangePassword changes the principal's own password. Other sessions of
// the account are signed out.
func (s *Service) ChangePassword(ctx context.Context, p *Principal, oldPassword, newPassword string) error {
	u, err := s.store.GetUserByID(ctx, p.UserID)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(oldPassword)) != nil {
		s.record(ctx, p, "auth.password_change", u.Username, audit.ResultFailure, "原口令错误", "")
		return invalid("原口令错误")
	}
	if err := s.setPassword(ctx, u, newPassword, false); err != nil {
		s.record(ctx, p, "auth.password_change", u.Username, audit.ResultFailure, err.Error(), "")
		return err
	}
	if err := s.store.DeleteUserSessions(ctx, u.ID, p.sessionHash); err != nil {
		return err
	}
	s.record(ctx, p, "auth.password_change", u.Username, audit.ResultSuccess, "", "")
	return nil
}

func (s *Service) setPassword(ctx context.Context, u *storage.User, password string, mustChange bool) error {
	pol := s.Policy(ctx)
	if err := pol.CheckPassword(password, u.Username); err != nil {
		return invalid("%s", err.Error())
	}
	for _, h := range append([]string{u.PasswordHash}, u.PasswordHistory...) {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil {
			return invalid("不能使用最近 %d 次用过的口令", pol.PasswordHistory)
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return err
	}
	history := append([]string{u.PasswordHash}, u.PasswordHistory...)
	if len(history) > pol.PasswordHistory {
		history = history[:pol.PasswordHistory]
	}
	now := s.now()
	u.PasswordHash, u.PasswordHistory = string(hash), history
	u.PasswordChangedAt, u.MustChangePassword, u.UpdatedAt = now, mustChange, now
	u.FailedAttempts, u.LockedUntil = 0, nil
	return s.store.UpdateUser(ctx, u)
}

// ─── Account administration (system administrator) ─────────────

// UserView is the account data shown in the management console.
type UserView struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name"`
	Email              string     `json:"email"`
	Role               Role       `json:"role"`
	RoleName           string     `json:"role_name"`
	Console            Console    `json:"console"`
	Status             string     `json:"status"`
	Locked             bool       `json:"locked"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	MustChangePassword bool       `json:"must_change_password"`
	PasswordChangedAt  time.Time  `json:"password_changed_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP        string     `json:"last_login_ip"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
}

func roleName(r Role) string {
	for _, info := range roles {
		if info.Role == r {
			return info.Name
		}
	}
	return string(r)
}

func viewOf(u *storage.User) UserView {
	locked := u.LockedUntil != nil && time.Now().Before(*u.LockedUntil)
	return UserView{
		ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Email: u.Email,
		Role: Role(u.Role), RoleName: roleName(Role(u.Role)), Console: ConsoleOf(Role(u.Role)),
		Status: u.Status, Locked: locked, LockedUntil: u.LockedUntil, MustChangePassword: u.MustChangePassword,
		PasswordChangedAt: u.PasswordChangedAt, LastLoginAt: u.LastLoginAt, LastLoginIP: u.LastLoginIP,
		ExpiresAt: u.ExpiresAt, CreatedBy: u.CreatedBy, CreatedAt: u.CreatedAt,
	}
}

func (s *Service) ListUsers(ctx context.Context) ([]UserView, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]UserView, 0, len(users))
	for i := range users {
		out = append(out, viewOf(&users[i]))
	}
	return out, nil
}

// Me returns the principal's own account view.
func (s *Service) Me(ctx context.Context, p *Principal) (UserView, error) {
	u, err := s.store.GetUserByID(ctx, p.UserID)
	if err != nil {
		return UserView{}, err
	}
	return viewOf(u), nil
}

type UserInput struct {
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Email       string     `json:"email"`
	Role        Role       `json:"role"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Password    string     `json:"password"` // initial password, create only
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)
var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func (in UserInput) validate(create bool) error {
	if create && !usernameRe.MatchString(in.Username) {
		return invalid("用户名须为 3–32 位字母、数字或 . _ -")
	}
	if !ValidRole(in.Role) {
		return invalid("未知角色：%s", in.Role)
	}
	if in.Email != "" && !emailRe.MatchString(in.Email) {
		return invalid("邮箱格式不正确")
	}
	if len([]rune(in.DisplayName)) > 64 {
		return invalid("姓名不能超过 64 个字符")
	}
	return nil
}

func (s *Service) CreateUser(ctx context.Context, actor *Principal, in UserInput) (UserView, error) {
	if err := in.validate(true); err != nil {
		s.record(ctx, actor, "user.create", in.Username, audit.ResultFailure, err.Error(), "")
		return UserView{}, err
	}
	if err := s.Policy(ctx).CheckPassword(in.Password, in.Username); err != nil {
		s.record(ctx, actor, "user.create", in.Username, audit.ResultFailure, "初始口令不符合策略", "")
		return UserView{}, invalid("初始口令不符合策略：%s", err.Error())
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), s.bcryptCost)
	if err != nil {
		return UserView{}, err
	}
	now := s.now()
	u := &storage.User{
		ID: newID("usr"), Username: in.Username, DisplayName: in.DisplayName, Email: in.Email,
		PasswordHash: string(hash), PasswordChangedAt: now, MustChangePassword: true,
		Role: string(in.Role), Status: "active", ExpiresAt: in.ExpiresAt,
		CreatedBy: actor.Username, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateUser(ctx, u); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			s.record(ctx, actor, "user.create", in.Username, audit.ResultFailure, "用户名已存在", "")
			return UserView{}, invalid("用户名已存在")
		}
		return UserView{}, err
	}
	s.record(ctx, actor, "user.create", u.Username, audit.ResultSuccess, "", "role="+u.Role)
	return viewOf(u), nil
}

func (s *Service) UpdateUser(ctx context.Context, actor *Principal, id string, in UserInput) (UserView, error) {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return UserView{}, err
	}
	in.Username = u.Username
	if err := in.validate(false); err != nil {
		s.record(ctx, actor, "user.update", u.Username, audit.ResultFailure, err.Error(), "")
		return UserView{}, err
	}
	roleChanged := Role(u.Role) != in.Role
	if roleChanged && u.ID == actor.UserID {
		s.record(ctx, actor, "user.update", u.Username, audit.ResultFailure, "不能修改自己的角色", "")
		return UserView{}, invalid("不能修改自己的角色")
	}
	if roleChanged {
		if err := s.guardLastManager(ctx, u, "修改角色"); err != nil {
			s.record(ctx, actor, "user.update", u.Username, audit.ResultFailure, err.Error(), "")
			return UserView{}, err
		}
	}
	detail := ""
	if roleChanged {
		detail = fmt.Sprintf("role %s -> %s", u.Role, in.Role)
	}
	u.DisplayName, u.Email, u.Role, u.ExpiresAt, u.UpdatedAt = in.DisplayName, in.Email, string(in.Role), in.ExpiresAt, s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return UserView{}, err
	}
	if roleChanged {
		_ = s.store.DeleteUserSessions(ctx, u.ID, "")
	}
	s.record(ctx, actor, "user.update", u.Username, audit.ResultSuccess, "", detail)
	return viewOf(u), nil
}

// SetStatus enables or disables an account.
func (s *Service) SetStatus(ctx context.Context, actor *Principal, id string, active bool) (UserView, error) {
	event := "user.enable"
	if !active {
		event = "user.disable"
	}
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return UserView{}, err
	}
	if !active {
		if u.ID == actor.UserID {
			s.record(ctx, actor, event, u.Username, audit.ResultFailure, "不能停用自己的账号", "")
			return UserView{}, invalid("不能停用自己的账号")
		}
		if err := s.guardLastManager(ctx, u, "停用"); err != nil {
			s.record(ctx, actor, event, u.Username, audit.ResultFailure, err.Error(), "")
			return UserView{}, err
		}
		u.Status = "disabled"
	} else {
		u.Status = "active"
		// Re-enabling counts as activity so the inactivity rule does not
		// immediately disable the account again.
		now := s.now()
		u.LastLoginAt = &now
	}
	u.UpdatedAt = s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return UserView{}, err
	}
	if !active {
		_ = s.store.DeleteUserSessions(ctx, u.ID, "")
	}
	s.record(ctx, actor, event, u.Username, audit.ResultSuccess, "", "")
	return viewOf(u), nil
}

func (s *Service) Unlock(ctx context.Context, actor *Principal, id string) (UserView, error) {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return UserView{}, err
	}
	u.LockedUntil, u.FailedAttempts, u.UpdatedAt = nil, 0, s.now()
	if err := s.store.UpdateUser(ctx, u); err != nil {
		return UserView{}, err
	}
	s.record(ctx, actor, "user.unlock", u.Username, audit.ResultSuccess, "", "")
	return viewOf(u), nil
}

// ResetPassword sets a new temporary password that must be changed at the
// next login, and signs the account out everywhere.
func (s *Service) ResetPassword(ctx context.Context, actor *Principal, id, password string) (UserView, error) {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return UserView{}, err
	}
	if u.ID == actor.UserID {
		s.record(ctx, actor, "user.reset_password", u.Username, audit.ResultFailure, "请通过修改口令功能修改自己的口令", "")
		return UserView{}, invalid("请通过“修改口令”修改自己的口令")
	}
	if err := s.setPassword(ctx, u, password, true); err != nil {
		s.record(ctx, actor, "user.reset_password", u.Username, audit.ResultFailure, err.Error(), "")
		return UserView{}, err
	}
	_ = s.store.DeleteUserSessions(ctx, u.ID, "")
	s.record(ctx, actor, "user.reset_password", u.Username, audit.ResultSuccess, "", "")
	return viewOf(u), nil
}

func (s *Service) DeleteUser(ctx context.Context, actor *Principal, id string) error {
	u, err := s.store.GetUserByID(ctx, id)
	if err != nil {
		return err
	}
	if u.ID == actor.UserID {
		s.record(ctx, actor, "user.delete", u.Username, audit.ResultFailure, "不能删除自己的账号", "")
		return invalid("不能删除自己的账号")
	}
	if err := s.guardLastManager(ctx, u, "删除"); err != nil {
		s.record(ctx, actor, "user.delete", u.Username, audit.ResultFailure, err.Error(), "")
		return err
	}
	if err := s.store.DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	s.record(ctx, actor, "user.delete", u.Username, audit.ResultSuccess, "", "role="+u.Role)
	return nil
}

// guardLastManager refuses to remove the last active system or audit
// administrator, which would leave that duty with nobody.
func (s *Service) guardLastManager(ctx context.Context, u *storage.User, action string) error {
	role := Role(u.Role)
	if u.Status != "active" || (role != RoleSysAdmin && role != RoleAuditAdmin) {
		return nil
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, other := range users {
		if other.ID != u.ID && other.Role == u.Role && other.Status == "active" {
			return nil
		}
	}
	return invalid("不能%s最后一个启用的%s", action, roleName(role))
}

// ─── Helpers ───────────────────────────────────────────────────

func (s *Service) record(ctx context.Context, actor *Principal, event, target, result, reason, detail string) {
	rec := storage.AuditRecord{Console: string(ConsoleAdmin), EventType: event, Target: target, Result: result, Reason: reason, Detail: detail}
	if strings.HasPrefix(event, "auth.") {
		rec.Console = "auth"
	}
	if actor == nil {
		rec.Username, rec.Console = "system", "system"
	}
	actor.AuditActor(&rec)
	_ = s.audit.Record(ctx, rec)
}

// HashToken returns the SM3 hash (hex) of a session token.
func HashToken(token string) string {
	sum := sm3.Sum([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate session token: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func newID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + "-" + hex.EncodeToString(b)
}

// generatePassword returns a random password satisfying the default policy.
func generatePassword() string {
	const (
		upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower  = "abcdefghijkmnopqrstuvwxyz"
		digits = "23456789"
		syms   = "!@#%^*-_=+"
	)
	sets := []string{upper, lower, digits, syms}
	all := upper + lower + digits + syms
	out := make([]byte, 16)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range out {
		set := all
		if i < len(sets) {
			set = sets[i]
		}
		out[i] = set[int(b[i])%len(set)]
	}
	return string(out)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
