package engine

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// BotEngine flags automated clients per caller (account, API key or source
// IP): a burst of requests within a minute, or request intervals so regular
// that a script is the likely source.
type BotEngine struct {
	store    storage.Store
	mu       sync.Mutex
	subjects map[string]*botSubject
	now      func() time.Time
	events   *cooldown

	burst      int
	cv         float64
	minSamples int
}

type botSubject struct {
	minute   []time.Time // requests in the last minute, oldest first
	recent   []time.Time // the last minSamples+1 requests, oldest first
	lastSeen time.Time
}

// maxClockSkew is how far an event timestamp may be from the platform clock
// before it is distrusted.
const maxClockSkew = 5 * time.Minute

// Bot defaults, matching rule R-BOT-001.
const (
	botDefaultBurst      = 120
	botDefaultCV         = 0.1
	botDefaultMinSamples = 30
	// Mean intervals between botMinRegularGap and botMaxRegularGap count as
	// a scripted rhythm. Shorter gaps are machine-speed bursts (left to the
	// burst threshold, and typical of batched timestamps); a job polling
	// every few minutes is regular but not a crawler.
	botMinRegularGap = 100 * time.Millisecond
	botMaxRegularGap = 10 * time.Second
)

func NewBotEngine(store storage.Store) *BotEngine {
	e := &BotEngine{store: store, subjects: make(map[string]*botSubject), now: time.Now, events: newCooldown()}
	e.Configure(nil)
	return e
}

// Configure applies rule R-BOT-001's parameters: burst_threshold (requests
// per minute), regularity_cv (coefficient of variation of intervals under
// which requests count as scripted) and min_samples.
func (e *BotEngine) Configure(p Params) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.burst = p.Int("burst_threshold", botDefaultBurst); e.burst < 1 {
		e.burst = botDefaultBurst
	}
	if e.cv = p.Float("regularity_cv", botDefaultCV); e.cv <= 0 {
		e.cv = botDefaultCV
	}
	if e.minSamples = p.Int("min_samples", botDefaultMinSamples); e.minSamples < 3 {
		e.minSamples = botDefaultMinSamples
	}
}

// Evaluate records one request by subject made at the given time (the
// event's own timestamp; zero means now) and scores it: a burst or a
// scripted rhythm scores 70, both together 85. Timestamps far from the
// clock are replaced by now, and out-of-order ones are clamped so each
// subject's history stays ordered.
func (e *BotEngine) Evaluate(subject, sourceIP string, at time.Time) (int, string) {
	e.mu.Lock()
	clock := e.now()
	now := at
	if now.IsZero() || now.Sub(clock) > maxClockSkew || clock.Sub(now) > maxClockSkew {
		now = clock
	}
	s, ok := e.subjects[subject]
	if !ok {
		s = &botSubject{}
		e.subjects[subject] = s
	}
	if n := len(s.recent); n > 0 && now.Before(s.recent[n-1]) {
		now = s.recent[n-1]
	}
	s.lastSeen = clock

	cutoff := now.Add(-time.Minute)
	i := 0
	for i < len(s.minute) && !s.minute[i].After(cutoff) {
		i++
	}
	s.minute = append(s.minute[i:], now)
	if n := len(s.minute); n > maxWindowEntries {
		s.minute = append([]time.Time(nil), s.minute[n-maxWindowEntries:]...)
	}
	s.recent = append(s.recent, now)
	if n := len(s.recent); n > e.minSamples+1 {
		s.recent = append(s.recent[:0], s.recent[n-e.minSamples-1:]...)
	}

	perMinute := len(s.minute)
	burst := perMinute >= e.burst
	cv, gap, regular := 0.0, time.Duration(0), false
	if len(s.recent) == e.minSamples+1 {
		cv, gap = intervalStats(s.recent)
		regular = gap >= botMinRegularGap && gap <= botMaxRegularGap && cv < e.cv
	}
	burstLimit, cvLimit := e.burst, e.cv
	e.mu.Unlock()

	var score int
	var reason string
	switch {
	case burst && regular:
		score = 85
		reason = fmt.Sprintf("自动化脚本: %s 1 分钟内请求 %d 次（阈值 %d），且请求间隔高度规律（变异系数 %.3f，平均间隔 %s）",
			subject, perMinute, burstLimit, cv, gap.Round(time.Millisecond))
	case burst:
		score = 70
		reason = fmt.Sprintf("请求爆发: %s 1 分钟内请求 %d 次（阈值 %d）", subject, perMinute, burstLimit)
	case regular:
		score = 70
		reason = fmt.Sprintf("请求间隔规律: %s 最近请求间隔的变异系数 %.3f（阈值 %.3f），平均间隔 %s",
			subject, cv, cvLimit, gap.Round(time.Millisecond))
	default:
		return 0, ""
	}

	if e.events.allow(subject, clock) {
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("bot-%d", time.Now().UnixNano()),
			Type: "BOT", Severity: "medium",
			Title:     fmt.Sprintf("爬虫行为: %s", subject),
			Detail:    reason,
			SourceIP:  sourceIP,
			AccountID: subject,
			RiskScore: score,
			CreatedAt: time.Now(),
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save bot event: %v", err)
		}
	}
	return score, reason
}

// intervalStats returns the coefficient of variation and the mean of the
// gaps between consecutive times.
func intervalStats(ts []time.Time) (float64, time.Duration) {
	n := len(ts) - 1
	if n < 1 {
		return 0, 0
	}
	var sum float64
	gaps := make([]float64, n)
	for i := 0; i < n; i++ {
		gaps[i] = float64(ts[i+1].Sub(ts[i]))
		sum += gaps[i]
	}
	mean := sum / float64(n)
	if mean <= 0 {
		return 0, 0
	}
	var sq float64
	for _, g := range gaps {
		sq += (g - mean) * (g - mean)
	}
	return math.Sqrt(sq/float64(n)) / mean, time.Duration(mean)
}

func (e *BotEngine) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			for k, s := range e.subjects {
				if e.now().Sub(s.lastSeen) > time.Hour {
					delete(e.subjects, k)
				}
			}
			e.mu.Unlock()
		}
	}
}
