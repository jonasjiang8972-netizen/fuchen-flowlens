package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

type BFLAEngine struct {
	store      storage.Store
	mu         sync.RWMutex
	roleMatrix map[string]map[string]int
	now        func() time.Time
	events     *cooldown

	adminPrefixes   []string
	privilegedRoles map[string]bool
	minBaseline     int
	rareShare       float64
	strict          bool
}

// BFLA defaults, matching rule R-BFLA-001.
const (
	bflaDefaultAdminEndpoints  = "/admin,/api/v1/admin,/api/v1/system,/api/v1/users/roles,/manage,/supervisor,/actuator,/swagger-ui,/api/v1/audit"
	bflaDefaultPrivilegedRoles = "admin,administrator,super_admin,superadmin,root,sysadmin,system_admin,security_admin"
	bflaDefaultMinBaseline     = 10
	bflaDefaultRareShare       = 0.05
)

func NewBFLAEngine(store storage.Store) *BFLAEngine {
	e := &BFLAEngine{
		store:      store,
		roleMatrix: make(map[string]map[string]int),
		now:        time.Now,
		events:     newCooldown(),
	}
	e.Configure(nil)
	return e
}

// Configure applies rule R-BFLA-001's parameters: admin_endpoints and
// privileged_roles (comma-separated), min_baseline (accesses an endpoint
// needs before role shares count), rare_share (share under which a role is
// flagged) and strict_mode (flag every non-privileged access).
func (e *BFLAEngine) Configure(p Params) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.adminPrefixes = nil
	for _, prefix := range p.List("admin_endpoints", bflaDefaultAdminEndpoints) {
		e.adminPrefixes = append(e.adminPrefixes, strings.TrimRight(prefix, "/"))
	}
	e.privilegedRoles = make(map[string]bool)
	for _, role := range p.List("privileged_roles", bflaDefaultPrivilegedRoles) {
		e.privilegedRoles[strings.ToLower(role)] = true
	}
	if e.minBaseline = p.Int("min_baseline", bflaDefaultMinBaseline); e.minBaseline < 1 {
		e.minBaseline = bflaDefaultMinBaseline
	}
	if e.rareShare = p.Float("rare_share", bflaDefaultRareShare); e.rareShare <= 0 || e.rareShare >= 1 {
		e.rareShare = bflaDefaultRareShare
	}
	e.strict = p.Bool("strict_mode", false)
}

// IsAdminEndpoint reports whether endpoint is under a configured management
// prefix (whole path segments only).
func (e *BFLAEngine) IsAdminEndpoint(endpoint string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isAdminLocked(endpoint)
}

func (e *BFLAEngine) isAdminLocked(endpoint string) bool {
	for _, prefix := range e.adminPrefixes {
		if prefix == "" {
			continue
		}
		if endpoint == prefix || strings.HasPrefix(endpoint, prefix+"/") {
			return true
		}
	}
	return false
}

func (e *BFLAEngine) RecordAccess(accountID, role, endpoint string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.roleMatrix[endpoint]; !ok {
		e.roleMatrix[endpoint] = make(map[string]int)
	}
	e.roleMatrix[endpoint][role]++
}

// Evaluate flags a non-privileged role on a management endpoint when the
// endpoint has too little history (under min_baseline accesses), when the
// role's share of its traffic is under rare_share, or always in strict mode.
func (e *BFLAEngine) Evaluate(accountID, role, endpoint string) (int, string) {
	e.mu.RLock()
	if !e.isAdminLocked(endpoint) || e.privilegedRoles[strings.ToLower(role)] {
		e.mu.RUnlock()
		return 0, ""
	}
	roleAccess, ok := e.roleMatrix[endpoint]
	if !ok {
		e.mu.RUnlock()
		return 0, ""
	}
	totalAccess := 0
	for _, count := range roleAccess {
		totalAccess += count
	}
	currentRoleAccess := roleAccess[role]
	minBaseline, rareShare, strict := e.minBaseline, e.rareShare, e.strict
	e.mu.RUnlock()

	share := float64(currentRoleAccess) / float64(totalAccess)
	var reason string
	switch {
	case strict:
		reason = fmt.Sprintf("BFLA 检测: 角色 %s 访问管理端点 %s（严格模式）", role, endpoint)
	case totalAccess < minBaseline:
		reason = fmt.Sprintf("BFLA 检测: 角色 %s 访问管理端点 %s (基线不足: 仅 %d 次历史访问)", role, endpoint, totalAccess)
	case share < rareShare:
		reason = fmt.Sprintf("BFLA 检测: 角色 %s 异常访问管理端点 %s (历史占比: %.1f%%)", role, endpoint, share*100)
	default:
		return 0, ""
	}

	riskScore := 75
	if e.events.allow(accountID+"|"+endpoint, e.now()) {
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("bfla-%d", time.Now().UnixNano()),
			Type: "BFLA", Severity: "high",
			Title:     fmt.Sprintf("BFLA 检测: %s 越权访问管理端点", accountID),
			Detail:    reason,
			AccountID: accountID,
			RiskScore: riskScore,
			CreatedAt: time.Now(),
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save BFLA event: %v", err)
		}
	}
	return riskScore, reason
}
