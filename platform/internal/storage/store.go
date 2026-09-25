package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("not found")

type AlertEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail"`
	SourceIP  string    `json:"source_ip"`
	AccountID string    `json:"account_id"`
	RiskScore int       `json:"risk_score"`
	CreatedAt time.Time `json:"created_at"`
}

// User is a platform operator account.
type User struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name"`
	Email              string     `json:"email"`
	PasswordHash       string     `json:"-"`
	PasswordHistory    []string   `json:"-"` // previous hashes, newest first
	PasswordChangedAt  time.Time  `json:"password_changed_at"`
	MustChangePassword bool       `json:"must_change_password"`
	Role               string     `json:"role"`
	Status             string     `json:"status"` // active | disabled
	FailedAttempts     int        `json:"failed_attempts"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP        string     `json:"last_login_ip"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"` // account validity end
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// Session is a server-side login session. Only the SM3 hash of the bearer
// token is stored, so a database leak does not expose live tokens.
type Session struct {
	TokenHash  string    `json:"-"`
	UserID     string    `json:"user_id"`
	SourceIP   string    `json:"source_ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"` // absolute lifetime
}

// AuditRecord is one append-only audit entry. Hash chains each record to the
// previous one (SM3), so edits or deletions in the middle are detectable.
type AuditRecord struct {
	Seq       int64     `json:"seq"`
	Time      time.Time `json:"time"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	SourceIP  string    `json:"source_ip"`
	Console   string    `json:"console"`    // admin | security | agent | system
	EventType string    `json:"event_type"` // e.g. auth.login, user.create
	Target    string    `json:"target"`
	Result    string    `json:"result"` // success | failure
	Reason    string    `json:"reason,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// AuditQuery filters audit records. Zero values mean "no filter".
type AuditQuery struct {
	Username  string
	EventType string // prefix match, e.g. "auth." or "user.create"
	Result    string
	Console   string
	From, To  time.Time
	Limit     int
	Offset    int
}

// IdentityStore persists accounts, sessions and platform settings.
type IdentityStore interface {
	CreateUser(ctx context.Context, u *User) error
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id string) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	CountUsers(ctx context.Context) (int, error)

	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, tokenHash string) (*Session, error)
	TouchSession(ctx context.Context, tokenHash string, at time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	// DeleteUserSessions removes the user's sessions except keepHash (may be empty).
	DeleteUserSessions(ctx context.Context, userID, keepHash string) error
	DeleteExpiredSessions(ctx context.Context, idleBefore, now time.Time) error

	// Settings are small JSON documents keyed by name (e.g. security policy).
	GetSetting(ctx context.Context, key string) ([]byte, error)
	PutSetting(ctx context.Context, key string, value []byte) error
}

// AuditStore persists the audit trail. AppendAudit must serialise appends:
// it calls chain with the hash of the current last record, and stores the
// record chain returns, atomically.
type AuditStore interface {
	AppendAudit(ctx context.Context, rec *AuditRecord, chain func(prevHash string) string) error
	ListAudit(ctx context.Context, q AuditQuery) ([]AuditRecord, int, error)
	// WalkAudit visits every record in ascending seq order.
	WalkAudit(ctx context.Context, fn func(AuditRecord) error) error
	DeleteAuditBefore(ctx context.Context, t time.Time) (int64, error)
}

type Store interface {
	IdentityStore
	AuditStore

	// Detection events (for engines to store findings)
	SaveDetectionEvent(ctx context.Context, e *AlertEvent) error
	ListRecentAlerts(ctx context.Context, since time.Time) ([]AlertEvent, error)

	Close() error
}
