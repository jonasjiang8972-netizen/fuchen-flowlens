package storage

import (
	"context"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
)

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

type Store interface {
	// Agent
	SaveAgent(ctx context.Context, a *service.Agent) error
	GetAgent(ctx context.Context, id string) (*service.Agent, error)
	ListAgents(ctx context.Context) ([]service.Agent, error)
	UpdateAgentHeartbeat(ctx context.Context, id string, ts time.Time) error
	UpdateAgentStatus(ctx context.Context, id string, status string) error

	// Asset
	SaveAsset(ctx context.Context, a *service.Asset) error
	GetAsset(ctx context.Context, id string) (*service.Asset, error)
	ListAssets(ctx context.Context) ([]service.Asset, error)
	ClaimAsset(ctx context.Context, id, owner string) error

	// Alert
	SaveAlert(ctx context.Context, a *service.Alert) error
	GetAlert(ctx context.Context, id string) (*service.Alert, error)
	ListAlerts(ctx context.Context) ([]service.Alert, error)
	UpdateAlertStatus(ctx context.Context, id, status string) error

	// Audit
	SaveAuditLog(ctx context.Context, user, action, resource, detail string) error
	ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error)

	// User
	SaveUser(ctx context.Context, u *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)

	// Detection events (for engine to store findings)
	SaveDetectionEvent(ctx context.Context, e *AlertEvent) error
	ListRecentAlerts(ctx context.Context, since time.Time) ([]AlertEvent, error)

	Close() error
}

type AuditLog struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	TenantID     string    `json:"tenant_id"`
	CreatedAt    time.Time `json:"created_at"`
}

func NewStore(dbType string) Store {
	return NewMemStore()
}
