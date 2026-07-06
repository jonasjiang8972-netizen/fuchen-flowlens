package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
	"golang.org/x/crypto/bcrypt"
)

type MemStore struct {
	mu            sync.RWMutex
	agents        map[string]*service.Agent
	assets        map[string]*service.Asset
	alerts        map[string]*service.Alert
	auditLogs     []AuditLog
	users         map[string]*User
	detectEvents  []AlertEvent
}

func NewMemStore() *MemStore {
	s := &MemStore{
		agents:   make(map[string]*service.Agent),
		assets:   make(map[string]*service.Asset),
		alerts:   make(map[string]*service.Alert),
		auditLogs: make([]AuditLog, 0),
		users:    make(map[string]*User),
		detectEvents: make([]AlertEvent, 0),
	}
	s.seedUsers()
	return s
}

func (s *MemStore) seedUsers() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	s.users["admin"] = &User{
		ID: "user-001", Username: "admin",
		PasswordHash: string(hash),
		Role: "super_admin", TenantID: "tenant-001",
		CreatedAt: time.Now(),
	}
	s.users["sec-ops"] = &User{
		ID: "user-002", Username: "sec-ops",
		PasswordHash: string(hash),
		Role: "security_admin", TenantID: "tenant-001",
		CreatedAt: time.Now(),
	}
}

func (s *MemStore) SaveAgent(_ context.Context, a *service.Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[a.ID] = a
	return nil
}

func (s *MemStore) GetAgent(_ context.Context, id string) (*service.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent not found: %s", id)
	}
	return a, nil
}

func (s *MemStore) ListAgents(_ context.Context) ([]service.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]service.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		result = append(result, *a)
	}
	return result, nil
}

func (s *MemStore) UpdateAgentHeartbeat(_ context.Context, id string, ts time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[id]; ok {
		a.LastHeartbeat = ts
	}
	return nil
}

func (s *MemStore) UpdateAgentStatus(_ context.Context, id string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[id]; ok {
		a.Status = status
	}
	return nil
}

func (s *MemStore) SaveAsset(_ context.Context, a *service.Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets[a.ID] = a
	return nil
}

func (s *MemStore) GetAsset(_ context.Context, id string) (*service.Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	if !ok {
		return nil, fmt.Errorf("asset not found: %s", id)
	}
	return a, nil
}

func (s *MemStore) ListAssets(_ context.Context) ([]service.Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]service.Asset, 0, len(s.assets))
	for _, a := range s.assets {
		result = append(result, *a)
	}
	return result, nil
}

func (s *MemStore) ClaimAsset(_ context.Context, id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
	if !ok {
		return fmt.Errorf("asset not found: %s", id)
	}
	a.ClaimStatus = "claimed"
	a.Owner = owner
	return nil
}

func (s *MemStore) SaveAlert(_ context.Context, a *service.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts[a.ID] = a
	return nil
}

func (s *MemStore) GetAlert(_ context.Context, id string) (*service.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.alerts[id]
	if !ok {
		return nil, fmt.Errorf("alert not found: %s", id)
	}
	return a, nil
}

func (s *MemStore) ListAlerts(_ context.Context) ([]service.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]service.Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		result = append(result, *a)
	}
	return result, nil
}

func (s *MemStore) UpdateAlertStatus(_ context.Context, id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[id]
	if !ok {
		return fmt.Errorf("alert not found: %s", id)
	}
	a.Status = status
	return nil
}

func (s *MemStore) SaveAuditLog(_ context.Context, user, action, resource, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs = append(s.auditLogs, AuditLog{
		ID: fmt.Sprintf("log-%d", len(s.auditLogs)+1),
		User: user, Action: action, Resource: resource,
		Detail: detail, CreatedAt: time.Now(),
	})
	return nil
}

func (s *MemStore) ListAuditLogs(_ context.Context, limit int) ([]AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.auditLogs)
	if n > limit {
		n = limit
	}
	return s.auditLogs[:n], nil
}

func (s *MemStore) SaveUser(_ context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Username] = u
	return nil
}

func (s *MemStore) GetUserByUsername(_ context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("user not found: %s", username)
	}
	return u, nil
}

func (s *MemStore) GetUserByID(_ context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found: %s", id)
}

func (s *MemStore) SaveDetectionEvent(_ context.Context, e *AlertEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.detectEvents = append(s.detectEvents, *e)
	return nil
}

func (s *MemStore) ListRecentAlerts(_ context.Context, since time.Time) ([]AlertEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []AlertEvent
	for _, e := range s.detectEvents {
		if e.CreatedAt.After(since) {
			result = append(result, e)
		}
	}
	return result, nil
}

func (s *MemStore) Close() error { return nil }
