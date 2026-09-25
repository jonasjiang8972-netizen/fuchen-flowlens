package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemStore keeps everything in process memory. It is for development and
// tests only: all data, including the audit trail, is lost on restart.
type MemStore struct {
	mu           sync.RWMutex
	users        map[string]*User // by ID
	sessions     map[string]*Session
	settings     map[string][]byte
	documents    map[string]map[string][]byte // kind -> id -> JSON
	audit        []AuditRecord
	auditSeq     int64
	detectEvents []AlertEvent
}

func NewMemStore() *MemStore {
	return &MemStore{
		users:        make(map[string]*User),
		sessions:     make(map[string]*Session),
		settings:     make(map[string][]byte),
		documents:    make(map[string]map[string][]byte),
		detectEvents: make([]AlertEvent, 0),
	}
}

func cloneUser(u *User) *User {
	c := *u
	c.PasswordHistory = append([]string(nil), u.PasswordHistory...)
	for _, p := range []**time.Time{&c.LockedUntil, &c.LastLoginAt, &c.ExpiresAt} {
		if *p != nil {
			t := **p
			*p = &t
		}
	}
	return &c
}

// ─── Users ─────────────────────────────────────────────────────

func (s *MemStore) CreateUser(_ context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; ok {
		return fmt.Errorf("user id %s already exists", u.ID)
	}
	for _, existing := range s.users {
		if strings.EqualFold(existing.Username, u.Username) {
			return fmt.Errorf("username %s already exists", u.Username)
		}
	}
	s.users[u.ID] = cloneUser(u)
	return nil
}

func (s *MemStore) UpdateUser(_ context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; !ok {
		return ErrNotFound
	}
	s.users[u.ID] = cloneUser(u)
	return nil
}

func (s *MemStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return ErrNotFound
	}
	delete(s.users, id)
	for h, sess := range s.sessions {
		if sess.UserID == id {
			delete(s.sessions, h)
		}
	}
	return nil
}

func (s *MemStore) GetUserByID(_ context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneUser(u), nil
}

func (s *MemStore) GetUserByUsername(_ context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Username, username) {
			return cloneUser(u), nil
		}
	}
	return nil, ErrNotFound
}

func (s *MemStore) ListUsers(_ context.Context) ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, *cloneUser(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (s *MemStore) CountUsers(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users), nil
}

// ─── Sessions ──────────────────────────────────────────────────

func (s *MemStore) CreateSession(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *sess
	s.sessions[sess.TokenHash] = &c
	return nil
}

func (s *MemStore) GetSession(_ context.Context, tokenHash string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[tokenHash]
	if !ok {
		return nil, ErrNotFound
	}
	c := *sess
	return &c, nil
}

func (s *MemStore) TouchSession(_ context.Context, tokenHash string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[tokenHash]; ok {
		sess.LastSeenAt = at
	}
	return nil
}

func (s *MemStore) DeleteSession(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, tokenHash)
	return nil
}

func (s *MemStore) DeleteUserSessions(_ context.Context, userID, keepHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, sess := range s.sessions {
		if sess.UserID == userID && h != keepHash {
			delete(s.sessions, h)
		}
	}
	return nil
}

func (s *MemStore) DeleteExpiredSessions(_ context.Context, idleBefore, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h, sess := range s.sessions {
		if sess.LastSeenAt.Before(idleBefore) || !now.Before(sess.ExpiresAt) {
			delete(s.sessions, h)
		}
	}
	return nil
}

// ─── Settings ──────────────────────────────────────────────────

func (s *MemStore) GetSetting(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.settings[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (s *MemStore) PutSetting(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings[key] = append([]byte(nil), value...)
	return nil
}

// ─── Audit ─────────────────────────────────────────────────────

func (s *MemStore) AppendAudit(_ context.Context, rec *AuditRecord, chain func(prevHash string) string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := ""
	if n := len(s.audit); n > 0 {
		prev = s.audit[n-1].Hash
	}
	s.auditSeq++
	rec.Seq = s.auditSeq
	rec.PrevHash = prev
	rec.Hash = chain(prev)
	s.audit = append(s.audit, *rec)
	return nil
}

func matchAudit(r AuditRecord, q AuditQuery) bool {
	if q.Username != "" && !strings.EqualFold(r.Username, q.Username) {
		return false
	}
	if q.EventType != "" && !strings.HasPrefix(r.EventType, q.EventType) {
		return false
	}
	if q.Result != "" && r.Result != q.Result {
		return false
	}
	if q.Console != "" && r.Console != q.Console {
		return false
	}
	if !q.From.IsZero() && r.Time.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !r.Time.Before(q.To) {
		return false
	}
	return true
}

// ListAudit returns matching records newest first.
func (s *MemStore) ListAudit(_ context.Context, q AuditQuery) ([]AuditRecord, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var matched []AuditRecord
	for i := len(s.audit) - 1; i >= 0; i-- {
		if matchAudit(s.audit[i], q) {
			matched = append(matched, s.audit[i])
		}
	}
	total := len(matched)
	if q.Offset > len(matched) {
		q.Offset = len(matched)
	}
	matched = matched[q.Offset:]
	if q.Limit > 0 && len(matched) > q.Limit {
		matched = matched[:q.Limit]
	}
	return matched, total, nil
}

func (s *MemStore) WalkAudit(_ context.Context, fn func(AuditRecord) error) error {
	s.mu.RLock()
	records := append([]AuditRecord(nil), s.audit...)
	s.mu.RUnlock()
	for _, r := range records {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

func (s *MemStore) DeleteAuditBefore(_ context.Context, t time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := 0
	for i < len(s.audit) && s.audit[i].Time.Before(t) {
		i++
	}
	s.audit = append([]AuditRecord(nil), s.audit[i:]...)
	return int64(i), nil
}

// ─── Documents ─────────────────────────────────────────────────

func (s *MemStore) LoadDocuments(_ context.Context, kind string) (map[string][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]byte, len(s.documents[kind]))
	for id, v := range s.documents[kind] {
		out[id] = append([]byte(nil), v...)
	}
	return out, nil
}

func (s *MemStore) SaveDocuments(_ context.Context, kind string, docs map[string][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.documents[kind] == nil {
		s.documents[kind] = make(map[string][]byte)
	}
	for id, v := range docs {
		s.documents[kind][id] = append([]byte(nil), v...)
	}
	return nil
}

// ─── Detection events ──────────────────────────────────────────

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
