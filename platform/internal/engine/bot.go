package engine

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// BotRequest is the part of a request the bot engine looks at.
type BotRequest struct {
	SourceIP  string
	UserAgent string
	// JA3 is the TLS client fingerprint when the collector supplies one.
	JA3 string
	// Browserlike is true when the request carries the headers a browser
	// always sends (Accept-Language, Referer or Origin).
	Browserlike bool
}

// BotEngine scores automated-client behavior per client (JA3 fingerprint,
// or source IP plus User-Agent when none is available). Signals:
//
//	known crawler / scripting User-Agent          +30
//	near-constant request interval (script)       +40
//	burst above the per-minute threshold          +30
//	no browser headers on a non-trivial sample    +10
//	fingerprint on the operator's deny list       +40
//
// Two strong signals reach 70 and raise an alert; one alone does not.
type BotEngine struct {
	store storage.Store
	mu    sync.Mutex
	// clients holds recent request times per client, bounded by maxBotClients.
	clients  map[string]*botClient
	knownJA3 map[string]bool
	now      func() time.Time
	events   *cooldown

	// IntervalStdDev is the largest standard deviation (seconds) of the
	// request interval still treated as scripted. BurstPerMinute is the
	// request count per minute that counts as a burst.
	IntervalStdDev float64
	BurstPerMinute int
}

type botClient struct {
	times    []time.Time
	browser  []bool // per request in times: carried browser headers
	lastSeen time.Time
}

const (
	maxBotClients   = 50000
	botHistory      = 120
	botMinIntervals = 10
	botIdleTTL      = 30 * time.Minute
)

// botUserAgents are substrings (lowercase) of common crawler, scripting and
// headless-browser User-Agents.
var botUserAgents = []string{
	"python-requests", "python-urllib", "aiohttp", "httpx", "scrapy", "curl/", "wget/",
	"go-http-client", "okhttp", "java/", "apache-httpclient", "libwww-perl", "node-fetch", "axios/",
	"headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
	"bot", "spider", "crawler", "slurp",
}

func NewBotEngine(store storage.Store) *BotEngine {
	return &BotEngine{
		store:          store,
		clients:        make(map[string]*botClient),
		knownJA3:       make(map[string]bool),
		now:            time.Now,
		events:         newCooldown(),
		IntervalStdDev: 0.1,
		BurstPerMinute: 100,
	}
}

// SetKnownJA3 replaces the deny list of fingerprints of known automation
// tools.
func (e *BotEngine) SetKnownJA3(hashes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.knownJA3 = make(map[string]bool, len(hashes))
	for _, h := range hashes {
		e.knownJA3[strings.ToLower(strings.TrimSpace(h))] = true
	}
}

func botKey(r BotRequest) string {
	if r.JA3 != "" {
		return "ja3:" + strings.ToLower(r.JA3)
	}
	return "ip:" + r.SourceIP + "|" + r.UserAgent
}

// IsBotUserAgent reports whether ua names a crawler or scripting client.
func IsBotUserAgent(ua string) bool {
	if ua == "" {
		return true
	}
	l := strings.ToLower(ua)
	for _, m := range botUserAgents {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// Observe records one request and returns the client's current score and the
// reasons behind it.
func (e *BotEngine) Observe(r BotRequest) (int, string) {
	now := e.now()
	key := botKey(r)

	e.mu.Lock()
	c, ok := e.clients[key]
	if !ok {
		if len(e.clients) >= maxBotClients {
			e.pruneLocked(now)
		}
		if len(e.clients) >= maxBotClients {
			e.mu.Unlock()
			return 0, "" // table full of active clients: fail open
		}
		c = &botClient{}
		e.clients[key] = c
	}
	c.lastSeen = now
	c.times = append(c.times, now)
	c.browser = append(c.browser, r.Browserlike)
	if len(c.times) > botHistory {
		c.times = c.times[len(c.times)-botHistory:]
		c.browser = c.browser[len(c.browser)-botHistory:]
	}
	times := append([]time.Time(nil), c.times...)
	headerless := 0
	for _, b := range c.browser {
		if !b {
			headerless++
		}
	}
	deny := r.JA3 != "" && e.knownJA3[strings.ToLower(r.JA3)]
	e.mu.Unlock()

	score := 0
	var reasons []string
	if deny {
		score += 40
		reasons = append(reasons, "TLS 指纹命中自动化工具库")
	}
	if IsBotUserAgent(r.UserAgent) {
		score += 30
		reasons = append(reasons, fmt.Sprintf("User-Agent 为爬虫/脚本客户端(%q)", truncate(r.UserAgent, 40)))
	}
	if sd, mean, n := intervalStats(times); n >= botMinIntervals && sd < e.IntervalStdDev && mean < 10 {
		score += 40
		reasons = append(reasons, fmt.Sprintf("请求间隔高度规律(标准差 %.3fs,均值 %.2fs,%d 次)", sd, mean, n+1))
	}
	if n := countSince(times, now.Add(-time.Minute)); n > e.BurstPerMinute {
		score += 30
		reasons = append(reasons, fmt.Sprintf("1 分钟内 %d 次请求(阈值 %d)", n, e.BurstPerMinute))
	}
	if len(times) >= botMinIntervals && headerless == len(times) {
		score += 10
		reasons = append(reasons, "请求缺少浏览器特征头(Accept-Language/Referer/Origin)")
	}
	if score == 0 {
		return 0, ""
	}
	score = min(score, 95)
	reason := "Bot 检测: " + strings.Join(reasons, "; ")

	if score >= 50 && e.events.allow("bot|"+key, now) {
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("bot-%d", now.UnixNano()),
			Type: "BOT", Severity: "medium",
			Title:  "自动化客户端: " + r.SourceIP,
			Detail: reason, SourceIP: r.SourceIP, RiskScore: score, CreatedAt: now,
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save BOT event: %v", err)
		}
	}
	return score, reason
}

// intervalStats returns the standard deviation and mean, in seconds, of the
// gaps between consecutive request times, and the number of gaps.
func intervalStats(times []time.Time) (stddev, mean float64, n int) {
	if len(times) < 2 {
		return 0, 0, 0
	}
	gaps := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i].Sub(times[i-1]).Seconds())
	}
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))
	for _, g := range gaps {
		stddev += (g - mean) * (g - mean)
	}
	return math.Sqrt(stddev / float64(len(gaps))), mean, len(gaps)
}

func countSince(times []time.Time, since time.Time) int {
	n := 0
	for _, t := range times {
		if t.After(since) {
			n++
		}
	}
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (e *BotEngine) pruneLocked(now time.Time) {
	for k, c := range e.clients {
		if now.Sub(c.lastSeen) > botIdleTTL {
			delete(e.clients, k)
		}
	}
}

// StartCleanup drops idle clients until ctx ends.
func (e *BotEngine) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			e.pruneLocked(e.now())
			e.mu.Unlock()
		}
	}
}
