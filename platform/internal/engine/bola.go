package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

type BOLAEngine struct {
	store       storage.Store
	mu          sync.RWMutex
	accountBase map[string]*AccountBaseline
}

type AccountBaseline struct {
	AccountID     string
	ObjectIDs     map[string]int
	LastAccess    time.Time
	TraverseRate  float64
	TotalAccesses int
	AvgIntervalMs float64
}

func NewBOLAEngine(store storage.Store) *BOLAEngine {
	return &BOLAEngine{
		store:       store,
		accountBase: make(map[string]*AccountBaseline),
	}
}

func (e *BOLAEngine) Evaluate(accountID, objectID, endpoint, sourceIP string) (int, string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	baseline, ok := e.accountBase[accountID]
	if !ok {
		baseline = &AccountBaseline{
			AccountID: accountID,
			ObjectIDs: make(map[string]int),
		}
		e.accountBase[accountID] = baseline
	}

	now := time.Now()
	baseline.TotalAccesses++
	baseline.ObjectIDs[objectID]++
	interval := now.Sub(baseline.LastAccess).Milliseconds()
	if baseline.LastAccess.IsZero() {
		interval = 1000
	}

	baseline.AvgIntervalMs = (baseline.AvgIntervalMs*float64(baseline.TotalAccesses-1) + float64(interval)) / float64(baseline.TotalAccesses)
	baseline.LastAccess = now

	uniqueCount := len(baseline.ObjectIDs)
	traverseRate := float64(uniqueCount) / float64(max(int(now.Sub(now.Add(-5*time.Minute)).Minutes()), 1))

	riskScore := 0
	reason := ""

	if uniqueCount > 50 && traverseRate > 5.0 {
		riskScore = 80 + min(int((traverseRate-5.0)*2), 20)
		reason = fmt.Sprintf("高遍历速率: %d 个唯一对象, %.1f/s", uniqueCount, traverseRate)
	} else if uniqueCount > 20 && traverseRate > 2.0 {
		riskScore = 60 + min(int((traverseRate-2.0)*5), 20)
		reason = fmt.Sprintf("中等遍历: %d 个唯一对象, %.1f/s", uniqueCount, traverseRate)
	} else if uniqueCount > 100 {
		riskScore = 50
		reason = fmt.Sprintf("大量对象访问: %d 个", uniqueCount)
	}

	if riskScore >= 70 {
		evt := &storage.AlertEvent{
			ID: fmt.Sprintf("bola-%d", time.Now().UnixNano()),
			Type: "BOLA", Severity: "high",
			Title:       fmt.Sprintf("BOLA 检测: 账号 %s 异常遍历", accountID),
			Detail:      reason,
			SourceIP:    sourceIP,
			AccountID:   accountID,
			RiskScore:   riskScore,
			CreatedAt:   time.Now(),
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
				if time.Since(b.LastAccess) > 24*time.Hour {
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
