package iam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

const (
	initPw = "Init#Pass2026"
	goodPw = "N3w!Secure-Pass"
)

type fixture struct {
	svc   *Service
	store *storage.MemStore
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{store: storage.NewMemStore(), now: time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)}
	f.svc = NewService(f.store, audit.New(f.store))
	f.svc.bcryptCost = bcrypt.MinCost
	f.svc.now = func() time.Time { return f.now }
	if _, err := f.svc.Bootstrap(context.Background(), initPw); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func (f *fixture) login(t *testing.T, user, pw string) (*LoginResult, error) {
	t.Helper()
	return f.svc.Login(context.Background(), user, pw, "10.0.0.1", "test")
}

// sysadmin returns a ready system administrator principal.
func (f *fixture) sysadmin(t *testing.T) *Principal {
	t.Helper()
	res, err := f.login(t, "sysadmin", initPw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.Authenticate(context.Background(), res.Token, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ChangePassword(context.Background(), p, initPw, goodPw); err != nil {
		t.Fatal(err)
	}
	p, _ = f.svc.Authenticate(context.Background(), res.Token, "10.0.0.1")
	return p
}

func (f *fixture) events(t *testing.T, prefix string) []storage.AuditRecord {
	t.Helper()
	recs, _, _ := f.store.ListAudit(context.Background(), storage.AuditQuery{EventType: prefix})
	return recs
}

func TestBootstrapCreatesSeparatedAccountsOnce(t *testing.T) {
	f := newFixture(t)
	users, _ := f.svc.ListUsers(context.Background())
	roles := map[Role]bool{}
	for _, u := range users {
		roles[u.Role] = true
		if !u.MustChangePassword {
			t.Errorf("%s does not have to change the initial password", u.Username)
		}
	}
	if !roles[RoleSysAdmin] || !roles[RoleAuditAdmin] || !roles[RoleSecAdmin] || len(users) != 3 {
		t.Fatalf("bootstrap users: %+v", users)
	}
	if res, _ := f.svc.Bootstrap(context.Background(), initPw); res != nil {
		t.Fatal("second bootstrap created accounts")
	}
}

func TestBootstrapGeneratesPolicyCompliantPassword(t *testing.T) {
	store := storage.NewMemStore()
	svc := NewService(store, audit.New(store))
	svc.bcryptCost = bcrypt.MinCost
	res, err := svc.Bootstrap(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := DefaultPolicy().CheckPassword(res.GeneratedPassword, ""); err != nil {
		t.Fatalf("generated password %q violates policy: %v", res.GeneratedPassword, err)
	}
}

func TestLoginLocksAfterRepeatedFailures(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 5; i++ {
		if _, err := f.login(t, "secadmin", "Wrong#Pass1"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if _, err := f.login(t, "secadmin", initPw); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("correct password while locked: %v, want locked", err)
	}
	if len(f.events(t, "user.lock")) != 1 {
		t.Fatal("lock not audited")
	}
	f.advance(31 * time.Minute)
	if _, err := f.login(t, "secadmin", initPw); err != nil {
		t.Fatalf("after lockout period: %v", err)
	}
}

func TestUnknownUserAndWrongPasswordLookTheSame(t *testing.T) {
	f := newFixture(t)
	_, e1 := f.login(t, "nobody", "Wrong#Pass1")
	_, e2 := f.login(t, "secadmin", "Wrong#Pass1")
	if e1 == nil || e1.Error() != e2.Error() {
		t.Fatalf("errors differ: %v vs %v", e1, e2)
	}
}

func TestLoginRateLimitPerIP(t *testing.T) {
	f := newFixture(t)
	var err error
	for i := 0; i < 21; i++ {
		_, err = f.svc.Login(context.Background(), "u"+strings.Repeat("x", i), "Wrong#Pass1", "6.6.6.6", "")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("21st attempt in a minute: %v, want rate limited", err)
	}
	if _, err := f.svc.Login(context.Background(), "sysadmin", initPw, "10.9.9.9", ""); err != nil {
		t.Fatalf("other IP affected: %v", err)
	}
	f.advance(time.Minute)
	if _, err := f.svc.Login(context.Background(), "sysadmin", initPw, "6.6.6.6", ""); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestSessionIdleAndAbsoluteTimeouts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	res, _ := f.login(t, "secadmin", initPw)

	f.advance(14 * time.Minute)
	if _, err := f.svc.Authenticate(ctx, res.Token, ""); err != nil {
		t.Fatalf("within idle timeout: %v", err)
	}
	f.advance(16 * time.Minute)
	if _, err := f.svc.Authenticate(ctx, res.Token, ""); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("after 16 idle minutes: %v, want invalid", err)
	}

	res, _ = f.login(t, "secadmin", initPw)
	for i := 0; i < 8*6; i++ { // stay active every 10 minutes for 8 hours
		f.advance(10 * time.Minute)
		if _, err := f.svc.Authenticate(ctx, res.Token, ""); err != nil {
			if i < 8*6-1 {
				t.Fatalf("active session ended early at step %d: %v", i, err)
			}
			return
		}
	}
	t.Fatal("session outlived the 8 hour absolute limit")
}

func TestMustChangePasswordBlocksPermissions(t *testing.T) {
	f := newFixture(t)
	res, _ := f.login(t, "secadmin", initPw)
	p, _ := f.svc.Authenticate(context.Background(), res.Token, "")
	if p.Can(PermSecurityRead) {
		t.Fatal("principal with initial password holds permissions")
	}
	if err := f.svc.ChangePassword(context.Background(), p, initPw, goodPw); err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.Authenticate(context.Background(), res.Token, "")
	if err != nil || !p.Can(PermSecurityRead) {
		t.Fatalf("after change: %v can=%v", err, p != nil && p.Can(PermSecurityRead))
	}
}

func TestPasswordHistoryAndPolicy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.sysadmin(t) // initPw -> goodPw

	for _, tc := range []struct{ pw, want string }{
		{"short1!", "长度"},
		{"alllowercase123", "3 类"},
		{"Has Space#123", "空白"},
		{"Xsysadmin#1234", "用户名"},
		{goodPw, "最近"},
		{initPw, "最近"},
	} {
		err := f.svc.ChangePassword(ctx, p, goodPw, tc.pw)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("password %q: %v, want error containing %q", tc.pw, err, tc.want)
		}
	}
	if err := f.svc.ChangePassword(ctx, p, "Wrong#Old1", "Other#Pass2026"); err == nil {
		t.Error("wrong old password accepted")
	}
}

func TestExpiredPasswordForcesChange(t *testing.T) {
	f := newFixture(t)
	f.sysadmin(t)
	f.advance(91 * 24 * time.Hour)
	// Keep the account from tripping the 90-day inactivity rule first.
	u, _ := f.store.GetUserByUsername(context.Background(), "sysadmin")
	last := f.now.Add(-time.Hour)
	u.LastLoginAt = &last
	_ = f.store.UpdateUser(context.Background(), u)

	res, err := f.login(t, "sysadmin", goodPw)
	if err != nil || !res.MustChangePassword {
		t.Fatalf("after 91 days: err=%v must_change=%v", err, res != nil && res.MustChangePassword)
	}
}

func TestInactiveAccountIsDisabled(t *testing.T) {
	f := newFixture(t)
	f.advance(91 * 24 * time.Hour)
	if _, err := f.login(t, "secadmin", initPw); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("login after 91 idle days: %v, want disabled", err)
	}
	if len(f.events(t, "user.auto_disable")) != 1 {
		t.Fatal("auto-disable not audited")
	}
}

func TestAdminCannotRemoveLastManagerOrActOnSelf(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.sysadmin(t)
	users, _ := f.svc.ListUsers(ctx)
	byName := map[string]UserView{}
	for _, u := range users {
		byName[u.Username] = u
	}

	if _, err := f.svc.SetStatus(ctx, admin, byName["auditadmin"].ID, false); err == nil {
		t.Error("disabled the last audit administrator")
	}
	if err := f.svc.DeleteUser(ctx, admin, byName["auditadmin"].ID); err == nil {
		t.Error("deleted the last audit administrator")
	}
	if _, err := f.svc.SetStatus(ctx, admin, admin.UserID, false); err == nil {
		t.Error("disabled own account")
	}
	if _, err := f.svc.UpdateUser(ctx, admin, admin.UserID, UserInput{Role: RoleAuditAdmin}); err == nil {
		t.Error("changed own role")
	}
	if _, err := f.svc.ResetPassword(ctx, admin, admin.UserID, "Other#Pass2026"); err == nil {
		t.Error("reset own password through admin path")
	}

	// With a second audit administrator the first may be disabled.
	if _, err := f.svc.CreateUser(ctx, admin, UserInput{Username: "audit2", Role: RoleAuditAdmin, Password: initPw}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetStatus(ctx, admin, byName["auditadmin"].ID, false); err != nil {
		t.Errorf("disable with a second audit admin: %v", err)
	}
}

func TestDisableAndRoleChangeEndSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.sysadmin(t)
	res, _ := f.login(t, "secadmin", initPw)
	sec, _ := f.store.GetUserByUsername(ctx, "secadmin")

	if _, err := f.svc.UpdateUser(ctx, admin, sec.ID, UserInput{Role: RoleViewer}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, res.Token, ""); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session survived role change: %v", err)
	}
	res, _ = f.login(t, "secadmin", initPw)
	if _, err := f.svc.SetStatus(ctx, admin, sec.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, res.Token, ""); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session survived disable: %v", err)
	}
}

func TestCreateUserValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.sysadmin(t)
	for _, in := range []UserInput{
		{Username: "ab", Role: RoleViewer, Password: initPw},
		{Username: "ok.user", Role: "super_admin", Password: initPw},
		{Username: "ok.user", Role: RoleViewer, Password: "weak"},
		{Username: "ok.user", Role: RoleViewer, Password: initPw, Email: "not-an-email"},
		{Username: "SECADMIN", Role: RoleViewer, Password: initPw},
	} {
		if _, err := f.svc.CreateUser(ctx, admin, in); err == nil {
			t.Errorf("accepted invalid input %+v", in)
		}
	}
}

func TestPolicyFloorsCannotBeWeakened(t *testing.T) {
	f := newFixture(t)
	admin := f.sysadmin(t)
	weak := DefaultPolicy()
	weak.AuditRetentionDays = 30
	if err := f.svc.UpdatePolicy(context.Background(), admin, weak); err == nil {
		t.Fatal("accepted 30-day audit retention")
	}
	weak = DefaultPolicy()
	weak.SessionIdleMinutes = 120
	if err := f.svc.UpdatePolicy(context.Background(), admin, weak); err == nil {
		t.Fatal("accepted 120-minute idle timeout")
	}
	ok := DefaultPolicy()
	ok.PasswordMinLength = 12
	if err := f.svc.UpdatePolicy(context.Background(), admin, ok); err != nil {
		t.Fatal(err)
	}
	if f.svc.Policy(context.Background()).PasswordMinLength != 12 {
		t.Fatal("policy not applied")
	}
}

func TestRoleMatrixHasNoOverlapBetweenDuties(t *testing.T) {
	admin := map[Permission]bool{PermUserManage: true, PermPolicyManage: true, PermAgentManage: true, PermSystemManage: true}
	for _, r := range Roles() {
		for _, p := range r.Permissions {
			switch r.Role {
			case RoleAuditAdmin:
				if p != PermAuditRead {
					t.Errorf("audit admin holds %s", p)
				}
			case RoleSysAdmin:
				if !admin[p] {
					t.Errorf("system admin holds non-admin permission %s", p)
				}
			default:
				if admin[p] || p == PermAuditRead {
					t.Errorf("%s holds management permission %s", r.Role, p)
				}
			}
		}
	}
}
