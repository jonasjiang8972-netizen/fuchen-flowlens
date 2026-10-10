package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

type BOLAEngine struct {
	store       storage.Store
	mu          sync.RWMutex
	accountBase map[string]*AccountBaseline
	now         func() time.Time
	events      *cooldown
	window      time.Duration
	threshold   int
}

// maxWindowEntries bounds the accesses kept per subject in a sliding window,
// so one very busy account or IP cannot exhaust memory.
const maxWindowEntries = 20000

// BOLA defaults, matching rule R-BOLA-001.
const (
	bolaDefaultWindowMin = 5
	bolaDefaultThreshold = 20
)

type AccountBaseline struct {
	AccountID     string
	WindowAccess  []ObjectAccess
	LastAccess    time.Time
	TraverseRate  float64
	TotalAccesses int
	AvgIntervalMs float64
}

type ObjectAccess struct {
	ObjectID string
	At       time.Time
}

func NewBOLAEngine(store storage.Store) *BOLAEngine {
	return &BOLAEngine{
		store:       store,
		accountBase: make(map[string]*AccountBaseline),
		now:         time.Now,
		events:      newCooldown(),
		window:      bolaDefaultWindowMin * time.Minute,
		threshold:   bolaDefaultThreshold,
	}
}

// Configure applies rule R-BOLA-001's parameters: window_minutes and
// traverse_threshold (distinct objects one account may touch per window).
func (e *BOLAEngine) Configure(p Params) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.window = p.Minutes("window_minutes", bolaDefaultWindowMin)
	e.threshold = p.Int("traverse_threshold", bolaDefaultThreshold)
	if e.threshold < 1 {
		e.threshold = bolaDefaultThreshold
	}
}

// Evaluate records an object access and scores the account: reaching the
// distinct-object threshold within the window scores 70, rising to 100 at
// three times the threshold.
func (e *BOLAEngine) Evaluate(accountID, objectID, endpoint, sourceIP string) (int, string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	baseline, ok := e.accountBase[accountID]
	if !ok {
		baseline = &AccountBaseline{AccountID: accountID}
		e.accountBase[accountID] = baseline
	}

	now := e.now()
	baseline.TotalAccesses++
	baseline.WindowAccess = append(baseline.WindowAccess, ObjectAccess{ObjectID: objectID, At: now})
	interval := now.Sub(baseline.LastAccess).Milliseconds()
	if baseline.LastAccess.IsZero() {
		interval = 1000
	}

	baseline.AvgIntervalMs = (baseline.AvgIntervalMs*float64(baseline.TotalAccesses-1) + float64(interval)) / float64(baseline.TotalAccesses)
	baseline.LastAccess = now

	windowStart := now.Add(-e.window)
	writeIdx := 0
	windowObjects := make(map[string]bool)
	for _, access := range baseline.WindowAccess {
		if access.At.After(windowStart) {
			baseline.WindowAccess[writeIdx] = access
			writeIdx++
			windowObjects[access.ObjectID] = true
		}
	}
	baseline.WindowAccess = baseline.WindowAccess[:writeIdx]
	if n := len(baseline.WindowAccess); n > maxWindowEntries {
		baseline.WindowAccess = append([]ObjectAccess(nil), baseline.WindowAccess[n-maxWindowEntries:]...)
	}

	uniqueCount := len(windowObjects)
	minutes := e.window.Minutes()
	baseline.TraverseRate = float64(uniqueCount) / minutes

	riskScore := 0
	reason := ""
	if uniqueCount >= e.threshold {
		riskScore = scaled(70, 30, float64(uniqueCount)/float64(e.threshold), 2)
		reason = fmt.Sprintf("对象遍历: %.0f 分钟内访问 %d 个不同对象（阈值 %d），%.1f 个/分钟",
			minutes, uniqueCount, e.threshold, baseline.TraverseRate)
	}

	if riskScore >= 70 && e.events.allow(accountID, now) {
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("bola-%d", time.Now().UnixNano()),
			Type: "BOLA", Severity: "high",
			Title:     fmt.Sprintf("BOLA 检测: 账号 %s 异常遍历", accountID),
			Detail:    reason,
			SourceIP:  sourceIP,
			AccountID: accountID,
			RiskScore: riskScore,
			CreatedAt: time.Now(),
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save BOLA event: %v", err)
		}
	}

	return riskScore, reason
}

func (e *BOLAEngine) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			for id, b := range e.accountBase {
				if e.now().Sub(b.LastAccess) > 24*time.Hour {
					delete(e.accountBase, id)
				}
			}
			e.mu.Unlock()
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
