package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// RateEngine detects traffic surges per endpoint: requests in the current
// window compared with an exponentially weighted baseline of past windows.
type RateEngine struct {
	store     storage.Store
	mu        sync.Mutex
	endpoints map[string]*rateEndpoint
	now       func() time.Time
	events    *cooldown

	window      time.Duration
	multiplier  float64
	minRequests int
}

type rateEndpoint struct {
	windowStart time.Time
	count       int
	sources     map[string]int // requests per source IP in the current window
	baseline    float64        // weighted average of completed windows
	windows     int            // completed windows in the baseline
	last        time.Time      // latest event time seen
	lastSeen    time.Time      // platform time of the latest event
}

// Rate defaults, matching rule R-RATE-001.
const (
	rateDefaultWindowMin   = 1
	rateDefaultMultiplier  = 5.0
	rateDefaultMinRequests = 300
	// rateMinWindows is how many completed windows a baseline needs before
	// it is trusted.
	rateMinWindows = 3
	// rateAlpha is the weight of the newest window in the baseline.
	rateAlpha = 0.3
	// rateMaxGapWindows bounds the empty windows folded into a baseline
	// after an endpoint was idle.
	rateMaxGapWindows = 60
	rateMaxSources    = 1000
)

func NewRateEngine(store storage.Store) *RateEngine {
	e := &RateEngine{store: store, endpoints: make(map[string]*rateEndpoint), now: time.Now, events: newCooldown()}
	e.Configure(nil)
	return e
}

// Configure applies rule R-RATE-001's parameters: window_minutes,
// multiplier and min_requests. Changing the window discards the baselines,
// which were counted per window.
func (e *RateEngine) Configure(p Params) {
	e.mu.Lock()
	defer e.mu.Unlock()
	window := p.Minutes("window_minutes", rateDefaultWindowMin)
	if window != e.window {
		e.endpoints = make(map[string]*rateEndpoint)
	}
	e.window = window
	if e.multiplier = p.Float("multiplier", rateDefaultMultiplier); e.multiplier <= 1 {
		e.multiplier = rateDefaultMultiplier
	}
	if e.minRequests = p.Int("min_requests", rateDefaultMinRequests); e.minRequests < 1 {
		e.minRequests = rateDefaultMinRequests
	}
}

// Evaluate counts one request to endpoint from sourceIP made at the given
// time (zero means now) and scores the current window: over multiplier
// times the baseline, with at least min_requests requests, scores 70,
// rising to 85 at twice that. It also returns the busiest source IP of the
// window.
func (e *RateEngine) Evaluate(endpoint, sourceIP string, at time.Time) (int, string, string) {
	e.mu.Lock()
	clock := e.now()
	now := at
	if now.IsZero() || now.Sub(clock) > maxClockSkew || clock.Sub(now) > maxClockSkew {
		now = clock
	}
	ep, ok := e.endpoints[endpoint]
	if !ok {
		ep = &rateEndpoint{windowStart: now.Truncate(e.window), sources: map[string]int{}}
		e.endpoints[endpoint] = ep
	}
	if now.Before(ep.last) {
		now = ep.last
	}
	ep.last, ep.lastSeen = now, clock

	if elapsed := now.Sub(ep.windowStart); elapsed >= e.window {
		e.closeWindow(ep, ep.count)
		gaps := int(elapsed/e.window) - 1
		if gaps > rateMaxGapWindows {
			gaps = rateMaxGapWindows
		}
		for i := 0; i < gaps; i++ {
			e.closeWindow(ep, 0)
		}
		ep.windowStart = now.Truncate(e.window)
		ep.count = 0
		ep.sources = map[string]int{}
	}
	ep.count++
	if _, ok := ep.sources[sourceIP]; ok || len(ep.sources) < rateMaxSources {
		ep.sources[sourceIP]++
	}

	count, baseline, windows := ep.count, ep.baseline, ep.windows
	limit := baseline * e.multiplier
	multiplier, minRequests, window := e.multiplier, e.minRequests, e.window
	top, topCount := "", 0
	if windows >= rateMinWindows && count >= minRequests && float64(count) > limit {
		for ip, n := range ep.sources {
			if n > topCount {
				top, topCount = ip, n
			}
		}
	}
	e.mu.Unlock()

	if windows < rateMinWindows || count < minRequests || float64(count) <= limit {
		return 0, "", ""
	}
	ratio := 2.0
	if limit > 0 {
		ratio = float64(count) / limit
	}
	score := scaled(70, 15, ratio, 1)
	reason := fmt.Sprintf("流量突增: %s 在 %.0f 分钟窗口内请求 %d 次，历史基线 %.0f 次（阈值 %.1f 倍）；请求最多的来源 %s（%d 次）",
		endpoint, window.Minutes(), count, baseline, multiplier, top, topCount)

	if e.events.allow(endpoint, clock) {
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("rate-%d", time.Now().UnixNano()),
			Type: "RATE_ANOMALY", Severity: "medium",
			Title:     fmt.Sprintf("资源消耗异常: %s", endpoint),
			Detail:    reason,
			SourceIP:  top,
			RiskScore: score,
			CreatedAt: time.Now(),
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save rate event: %v", err)
		}
	}
	return score, reason, top
}

// closeWindow folds a completed window's count into the baseline. Until the
// baseline is trusted it is a plain average; afterwards windows that were
// themselves anomalous are left out so an ongoing surge cannot raise the
// baseline that should flag it.
func (e *RateEngine) closeWindow(ep *rateEndpoint, count int) {
	c := float64(count)
	switch {
	case ep.windows < rateMinWindows:
		ep.baseline = (ep.baseline*float64(ep.windows) + c) / float64(ep.windows+1)
	case count >= e.minRequests && c > ep.baseline*e.multiplier:
		return
	default:
		ep.baseline = rateAlpha*c + (1-rateAlpha)*ep.baseline
	}
	ep.windows++
}

func (e *RateEngine) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			for k, ep := range e.endpoints {
				if e.now().Sub(ep.lastSeen) > 24*time.Hour {
					delete(e.endpoints, k)
				}
			}
			e.mu.Unlock()
		}
	}
}
