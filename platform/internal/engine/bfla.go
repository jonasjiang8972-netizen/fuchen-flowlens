package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

type BFLAEngine struct {
	store       storage.Store
	mu          sync.RWMutex
	roleMatrix map[string]map[string]int
}

func NewBFLAEngine(store storage.Store) *BFLAEngine {
	return &BFLAEngine{
		store:       store,
		roleMatrix: make(map[string]map[string]int),
	}
}

var adminEndpoints = []string{
	"/admin", "/api/v1/admin", "/api/v1/system",
	"/api/v1/users/roles", "/manage", "/supervisor",
	"/actuator", "/swagger-ui", "/api/v1/audit",
}

func (e *BFLAEngine) RecordAccess(accountID, role, endpoint string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.roleMatrix[endpoint]; !ok {
		e.roleMatrix[endpoint] = make(map[string]int)
	}
	e.roleMatrix[endpoint][role]++
}

func (e *BFLAEngine) Evaluate(accountID, role, endpoint string) (int, string) {
	isAdminEndpoint := false
	for _, prefix := range adminEndpoints {
		if len(endpoint) >= len(prefix) && endpoint[:len(prefix)] == prefix {
			isAdminEndpoint = true
			break
		}
	}

	if !isAdminEndpoint {
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

	if totalAccess < 10 || (totalAccess > 0 && float64(currentRoleAccess)/float64(totalAccess) < 0.05) {
		riskScore := 75
		reason := fmt.Sprintf("BFLA 检测: 角色 %s 异常访问管理端点 %s (历史占比: %.1f%%)", role, endpoint, float64(currentRoleAccess)/float64(totalAccess)*100)

		evt := &storage.AlertEvent{
			ID: fmt.Sprintf("bfla-%d", time.Now().UnixNano()),
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
		return riskScore, reason
	}

	return 0, ""
}
