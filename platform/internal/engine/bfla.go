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
}

func NewBFLAEngine(store storage.Store) *BFLAEngine {
	return &BFLAEngine{
		store:      store,
		roleMatrix: make(map[string]map[string]int),
		now:        time.Now,
		events:     newCooldown(),
	}
}

var adminEndpoints = []string{
	"/admin", "/api/v1/admin", "/api/v1/system",
	"/api/v1/users/roles", "/manage", "/supervisor",
	"/actuator", "/swagger-ui", "/api/v1/audit",
}

// privilegedRoles are expected to use management endpoints and are never
// flagged by BFLA.
var privilegedRoles = map[string]bool{
	"admin": true, "administrator": true, "super_admin": true, "superadmin": true,
	"root": true, "sysadmin": true, "system_admin": true, "security_admin": true,
}

// bflaMinBaseline is the number of recorded accesses an endpoint needs before
// the per-role share is meaningful.
const bflaMinBaseline = 10

func isAdminEndpoint(endpoint string) bool {
	for _, prefix := range adminEndpoints {
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
// endpoint has no baseline yet, or when that role makes up under 5% of its
// historical traffic.
func (e *BFLAEngine) Evaluate(accountID, role, endpoint string) (int, string) {
	if !isAdminEndpoint(endpoint) || privilegedRoles[strings.ToLower(role)] {
		return 0, ""
	}

	e.mu.RLock()
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
	e.mu.RUnlock()

	share := float64(currentRoleAccess) / float64(totalAccess)
	var reason string
	switch {
	case totalAccess < bflaMinBaseline:
		reason = fmt.Sprintf("BFLA 检测: 角色 %s 访问管理端点 %s (基线不足: 仅 %d 次历史访问)", role, endpoint, totalAccess)
	case share < 0.05:
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
