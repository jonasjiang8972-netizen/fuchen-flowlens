package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// AuthFailureEngine detects brute force and credential stuffing from
// authentication failures (HTTP 401) per source IP in a sliding window.
type AuthFailureEngine struct {
	store       storage.Store
	mu          sync.RWMutex
	failTracker map[string]*AuthTracker
	now         func() time.Time
	events      *cooldown

	window         time.Duration
	failCount      int
	uniqueAccounts int
}

type AuthTracker struct {
	IP       string
	Failures []authFailure
	LastSeen time.Time
}

type authFailure struct {
	At      time.Time
	Account string
}

// Authentication-failure defaults, matching rule R-AUTH-001.
const (
	authDefaultWindowMin      = 10
	authDefaultFailCount      = 20
	authDefaultUniqueAccounts = 5
)

func NewAuthFailureEngine(store storage.Store) *AuthFailureEngine {
	return &AuthFailureEngine{
		store:          store,
		failTracker:    make(map[string]*AuthTracker),
		now:            time.Now,
		events:         newCooldown(),
		window:         authDefaultWindowMin * time.Minute,
		failCount:      authDefaultFailCount,
		uniqueAccounts: authDefaultUniqueAccounts,
	}
}

// Configure applies rule R-AUTH-001's parameters: window_minutes,
// fail_count (failures per IP and window) and unique_accounts (distinct
// accounts that turn brute force into credential stuffing).
func (e *AuthFailureEngine) Configure(p Params) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.window = p.Minutes("window_minutes", authDefaultWindowMin)
	if e.failCount = p.Int("fail_count", authDefaultFailCount); e.failCount < 1 {
		e.failCount = authDefaultFailCount
	}
	if e.uniqueAccounts = p.Int("unique_accounts", authDefaultUniqueAccounts); e.uniqueAccounts < 2 {
		e.uniqueAccounts = authDefaultUniqueAccounts
	}
}

func (e *AuthFailureEngine) RecordFailure(ip, username string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	tracker, ok := e.failTracker[ip]
	if !ok {
		tracker = &AuthTracker{IP: ip}
		e.failTracker[ip] = tracker
	}
	tracker.Failures = append(pruneFailures(tracker.Failures, now.Add(-e.window)), authFailure{At: now, Account: username})
	if n := len(tracker.Failures); n > maxWindowEntries {
		tracker.Failures = append([]authFailure(nil), tracker.Failures[n-maxWindowEntries:]...)
	}
	tracker.LastSeen = now
}

// pruneFailures drops failures at or before cutoff; failures are in time
// order, so the kept ones are a suffix.
func pruneFailures(fs []authFailure, cutoff time.Time) []authFailure {
	i := 0
	for i < len(fs) && !fs[i].At.After(cutoff) {
		i++
	}
	return fs[i:]
}

// Evaluate scores an IP by its failures in the window. Reaching fail_count
// with at least unique_accounts distinct accounts is credential stuffing
// (85-100); with fewer accounts it is brute force (75).
func (e *AuthFailureEngine) Evaluate(ip string) (int, string) {
	e.mu.RLock()
	tracker, ok := e.failTracker[ip]
	if !ok {
		e.mu.RUnlock()
		return 0, ""
	}
	now := e.now()
	cutoff := now.Add(-e.window)
	failures := 0
	accounts := make(map[string]bool)
	for _, f := range tracker.Failures {
		if f.At.After(cutoff) {
			failures++
			accounts[f.Account] = true
		}
	}
	window, failCount, uniqueAccounts := e.window, e.failCount, e.uniqueAccounts
	e.mu.RUnlock()

	if failures < failCount {
		return 0, ""
	}
	minutes := window.Minutes()
	var (
		riskScore int
		reason    string
		evtType   = "BRUTE_FORCE"
		title     = fmt.Sprintf("暴力破解: IP %s 认证失败 %d 次", ip, failures)
	)
	if len(accounts) >= uniqueAccounts {
		riskScore = scaled(85, 15, float64(failures)/float64(failCount), 4)
		reason = fmt.Sprintf("撞库特征: %s 在 %.0f 分钟内认证失败 %d 次，涉及 %d 个不同账号", ip, minutes, failures, len(accounts))
		evtType = "CREDENTIAL_STUFFING"
		title = fmt.Sprintf("撞库攻击: IP %s 尝试 %d 个不同账号", ip, len(accounts))
	} else {
		riskScore = 75
		reason = fmt.Sprintf("暴力破解: %s 在 %.0f 分钟内认证失败 %d 次，涉及 %d 个账号", ip, minutes, failures, len(accounts))
	}

	if e.events.allow(ip, now) {
		severity := "high"
		if riskScore >= 90 {
			severity = "critical"
		}
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("auth-%d", time.Now().UnixNano()),
			Type: evtType, Severity: severity,
			Title:     title,
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
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			for ip, t := range e.failTracker {
				if e.now().Sub(t.LastSeen) > e.window {
					delete(e.failTracker, ip)
				}
			}
			e.mu.Unlock()
		}
	}
}
