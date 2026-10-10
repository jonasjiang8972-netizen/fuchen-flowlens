package service

import (
	"sort"
	"sync"
	"time"
)

// Caller aggregates the traffic of one resolved principal (user, partner
// key, service, or a bare source IP) since the platform started.
type Caller struct {
	ID         string    `json:"caller_id"`
	Type       string    `json:"type"`
	Role       string    `json:"role,omitempty"`
	Confidence float64   `json:"confidence"`
	Evidence   string    `json:"evidence"`
	Requests   int64     `json:"requests"`
	Errors     int64     `json:"errors"` // responses with status >= 400
	Endpoints  int       `json:"endpoints"`
	SourceIPs  []string  `json:"source_ips"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type callerState struct {
	Caller
	endpoints map[string]struct{}
	ips       map[string]struct{}
}

// CallerStats summarises callers by type, counting requests as well.
type CallerStats struct {
	Since    time.Time        `json:"since"`
	Callers  int              `json:"callers"`
	Requests int64            `json:"requests"`
	ByType   map[string]int   `json:"callers_by_type"`
	Traffic  map[string]int64 `json:"requests_by_type"`
	// Untracked counts requests from new callers dropped once the caller
	// table was full.
	Untracked int64 `json:"untracked_requests"`
}

// CallerService keeps per-caller traffic statistics in memory. They are
// statistics of the running platform, not records, and start over on
// restart.
type CallerService struct {
	mu        sync.RWMutex
	callers   map[string]*callerState
	since     time.Time
	untracked int64
	now       func() time.Time
}

// Bounds of the caller table.
const (
	maxCallers         = 20000
	maxCallerEndpoints = 1000
	maxCallerIPs       = 5
)

func NewCallerService() *CallerService {
	return &CallerService{callers: make(map[string]*callerState), since: time.Now(), now: time.Now}
}

// Observe counts one request by caller id to endpoint from sourceIP with
// the given status code.
func (s *CallerService) Observe(id, typ, role, evidence string, confidence float64, endpoint, sourceIP string, status int) {
	if id == "" {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.callers[id]
	if !ok {
		if len(s.callers) >= maxCallers {
			s.untracked++
			return
		}
		c = &callerState{
			Caller:    Caller{ID: id, Type: typ, FirstSeen: now},
			endpoints: make(map[string]struct{}),
			ips:       make(map[string]struct{}),
		}
		s.callers[id] = c
	}
	c.Type, c.Role, c.Evidence = typ, role, evidence
	if confidence > c.Confidence {
		c.Confidence = confidence
	}
	c.Requests++
	if status >= 400 {
		c.Errors++
	}
	c.LastSeen = now
	if endpoint != "" && len(c.endpoints) < maxCallerEndpoints {
		c.endpoints[endpoint] = struct{}{}
	}
	if sourceIP != "" && len(c.ips) < maxCallerIPs {
		c.ips[sourceIP] = struct{}{}
	}
}

// List returns callers, optionally of one type, busiest first, at most
// limit of them.
func (s *CallerService) List(typ string, limit int) []Caller {
	s.mu.RLock()
	out := make([]Caller, 0, len(s.callers))
	for _, c := range s.callers {
		if typ != "" && c.Type != typ {
			continue
		}
		cp := c.Caller
		cp.Endpoints = len(c.endpoints)
		cp.SourceIPs = make([]string, 0, len(c.ips))
		for ip := range c.ips {
			cp.SourceIPs = append(cp.SourceIPs, ip)
		}
		sort.Strings(cp.SourceIPs)
		out = append(out, cp)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *CallerService) Stats() CallerStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := CallerStats{Since: s.since, ByType: map[string]int{}, Traffic: map[string]int64{}, Untracked: s.untracked}
	for _, c := range s.callers {
		st.Callers++
		st.Requests += c.Requests
		st.ByType[c.Type]++
		st.Traffic[c.Type] += c.Requests
	}
	return st
}
