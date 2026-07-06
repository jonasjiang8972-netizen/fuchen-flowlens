package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

type AuthFailureEngine struct {
	store       storage.Store
	mu          sync.RWMutex
	failTracker map[string]*AuthTracker
}

type AuthTracker struct {
	IP          string
	FailCount   int
	UsernameSet map[string]bool
	FirstSeen   time.Time
	LastSeen    time.Time
}

func NewAuthFailureEngine(store storage.Store) *AuthFailureEngine {
	return &AuthFailureEngine{
		store:       store,
		failTracker: make(map[string]*AuthTracker),
	}
}

func (e *AuthFailureEngine) RecordFailure(ip, username string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	tracker, ok := e.failTracker[ip]
	if !ok {
		tracker = &AuthTracker{
			IP:          ip,
			UsernameSet: make(map[string]bool),
			FirstSeen:   time.Now(),
		}
		e.failTracker[ip] = tracker
	}

	tracker.FailCount++
	tracker.UsernameSet[username] = true
	tracker.LastSeen = time.Now()
}

func (e *AuthFailureEngine) Evaluate(ip string) (int, string) {
	e.mu.RLock()
	tracker, ok := e.failTracker[ip]
	e.mu.RUnlock()
	if !ok {
		return 0, ""
	}

	failCount := tracker.FailCount
	uniqueUsers := len(tracker.UsernameSet)
	duration := time.Since(tracker.FirstSeen).Minutes()
	if duration < 1 {
		duration = 1
	}
	rate := float64(failCount) / duration

	riskScore := 0
	reason := ""

	if rate > 10 && uniqueUsers > 5 {
		riskScore = 80 + min(int((rate-10)*2), 20)
		reason = fmt.Sprintf("撞库特征: %s 在 %.0f 分钟内尝试 %d 个不同账号, 速率 %.1f/s", ip, duration, uniqueUsers, rate)
	} else if rate > 5 && uniqueUsers > 3 {
		riskScore = 60
		reason = fmt.Sprintf("高频失败登录: %s, %d 次/%.0f 分钟", ip, failCount, duration)
	}

	if riskScore >= 70 {
		evt := &storage.AlertEvent{
			ID: fmt.Sprintf("auth-%d", time.Now().UnixNano()),
			Type: "CREDENTIAL_STUFFING", Severity: "critical",
			Title:     fmt.Sprintf("撞库攻击: IP %s 尝试 %d 个不同账号", ip, uniqueUsers),
			Detail:    reason,
			SourceIP:  ip,
			RiskScore: riskScore,
			CreatedAt: time.Now(),
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save auth event: %v", err)
		}
	}

	return riskScore, reason
}

func (e *AuthFailureEngine) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			for ip, t := range e.failTracker {
				if time.Since(t.LastSeen) > 1*time.Hour {
					delete(e.failTracker, ip)
				}
			}
			e.mu.Unlock()
		}
	}
}
