package server

import (
	"fmt"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// trafficCounters count ingested events since start for the coverage view.
type trafficCounters struct {
	events     atomic.Uint64
	withBody   atomic.Uint64 // a response body was captured
	identified atomic.Uint64 // the caller was more than a source IP
}

// ─── Alert trend ───────────────────────────────────────────────

// AlertTrendHandler returns alerts raised per day and severity, and alerts
// closed per day, for the last ?days= days (default 7, at most 90).
func (s *PlatformServer) AlertTrendHandler(c *gin.Context) {
	days, err := strconv.Atoi(c.DefaultQuery("days", "7"))
	if err != nil || days < 1 || days > 90 {
		c.JSON(400, gin.H{"error": "days 取值 1～90"})
		return
	}
	c.JSON(200, gin.H{"items": s.alertService.Trend(days)})
}

// ─── Callers ───────────────────────────────────────────────────

// callerRules describe how resolvePrincipal identifies callers, in order.
var callerRules = []gin.H{
	{"order": 1, "type": "external_user", "source": "请求头 x-user-id / x-account-id / x-authenticated-user", "confidence": 0.92, "note": "网关认证后透传的用户身份"},
	{"order": 2, "type": "partner", "source": "请求头 x-api-key / x-client-id / x-app-id", "confidence": 0.90, "note": "按 API Key 区分合作方，只保留首尾 4 位"},
	{"order": 3, "type": "internal_service", "source": "请求头 x-service-name / x-caller-service", "confidence": 0.95, "note": "服务间调用声明的调用方"},
	{"order": 4, "type": "external_user", "source": "URL 参数 user_id / account_id / uid", "confidence": 0.78, "note": "参数可被调用方伪造，置信度较低"},
	{"order": 5, "type": "network_principal", "source": "来源 IP", "confidence": 0.55, "note": "以上都没有时，按来源 IP 归并"},
}

// ListCallersHandler returns the busiest callers (optionally ?type=) with
// their open alerts, statistics by type and the identification rules.
func (s *PlatformServer) ListCallersHandler(c *gin.Context) {
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "200"))
	if err != nil || limit < 1 || limit > 1000 {
		limit = 200
	}
	callers := s.callerService.List(c.Query("type"), limit)

	alerts := map[string]int{}
	for _, a := range s.alertService.List() {
		if a.AccountID != "" && a.Status != "resolved" && a.Status != "false_positive" {
			alerts[a.AccountID]++
		}
	}
	items := make([]gin.H, 0, len(callers))
	for _, cl := range callers {
		items = append(items, gin.H{
			"caller_id": cl.ID, "type": cl.Type, "role": cl.Role, "confidence": cl.Confidence,
			"evidence": cl.Evidence, "requests": cl.Requests, "errors": cl.Errors,
			"endpoints": cl.Endpoints, "source_ips": cl.SourceIPs,
			"first_seen": cl.FirstSeen, "last_seen": cl.LastSeen, "open_alerts": alerts[cl.ID],
		})
	}
	c.JSON(200, gin.H{"items": items, "stats": s.callerService.Stats(), "rules": callerRules})
}

// ─── Topology ──────────────────────────────────────────────────

// TopologyHandler returns caller -> host -> backend traffic since start.
func (s *PlatformServer) TopologyHandler(c *gin.Context) {
	c.JSON(200, s.topology.Snapshot())
}

// ─── Coverage ──────────────────────────────────────────────────

// blindSpot is a gap in what the platform can see, with how to close it.
type blindSpot struct {
	Type     string `json:"type"`
	Area     string `json:"area"`
	Impact   string `json:"impact"`
	Severity string `json:"severity"`
	Fix      string `json:"fix"`
	Link     string `json:"link,omitempty"` // console page that addresses it
}

// Coverage thresholds.
const (
	staleAssetAfter  = 24 * time.Hour
	identityMinShare = 0.5
	bodyMinShare     = 0.1
)

// CoverageSummaryHandler reports what the platform can and cannot see:
// collectors, asset ownership and freshness, caller identification and
// response body capture, with a list of blind spots derived from them.
func (s *PlatformServer) CoverageSummaryHandler(c *gin.Context) {
	now := time.Now()
	var spots []blindSpot

	agents := s.agentService.List()
	agentStatus := map[string]int{}
	for _, a := range agents {
		agentStatus[a.Status]++
		switch a.Status {
		case "offline":
			spots = append(spots, blindSpot{Type: "采集器离线", Area: a.ID, Severity: "high",
				Impact: fmt.Sprintf("%s 超过 5 分钟没有心跳，该采集点的流量不可见", a.Hostname),
				Fix:    "检查采集器进程、到平台的网络和 Agent 令牌"})
		case "degraded":
			spots = append(spots, blindSpot{Type: "采集器异常", Area: a.ID, Severity: "medium",
				Impact: fmt.Sprintf("心跳延迟或丢弃率 %.2f%%，部分流量缺失", a.DropRate*100),
				Fix:    "查看采集器运行事件，检查主机负载和平台接收能力"})
		}
	}
	if len(agents) == 0 {
		spots = append(spots, blindSpot{Type: "未部署采集器", Area: "全部", Severity: "high",
			Impact: "平台没有流量来源，资产和检测结果都为空", Fix: "按安装手册部署 Agent，接入网关访问日志"})
	}

	assets := s.assetService.List()
	var unclaimed, stale, sensitive, sensitiveUnclaimed int
	for _, a := range assets {
		owned := a.ClaimStatus == "claimed" && a.Owner != ""
		if !owned {
			unclaimed++
		}
		if !a.LastSeen.IsZero() && now.Sub(a.LastSeen) > staleAssetAfter {
			stale++
		}
		if len(a.SensitiveFields) > 0 {
			sensitive++
			if !owned {
				sensitiveUnclaimed++
			}
		}
	}
	if sensitiveUnclaimed > 0 {
		spots = append(spots, blindSpot{Type: "敏感接口无责任人", Area: fmt.Sprintf("%d 个接口", sensitiveUnclaimed), Severity: "high", Link: "assets",
			Impact: "涉及敏感字段的接口出现风险时无法自动分派", Fix: "在 API 资产中认领并填写责任人"})
	}
	if n := unclaimed - sensitiveUnclaimed; n > 0 {
		spots = append(spots, blindSpot{Type: "接口无责任人", Area: fmt.Sprintf("%d 个接口", n), Severity: "medium", Link: "assets",
			Impact: "风险处置需要人工确认归属", Fix: "在 API 资产中认领"})
	}
	if stale > 0 {
		spots = append(spots, blindSpot{Type: "接口长时间无流量", Area: fmt.Sprintf("%d 个接口", stale), Severity: "low", Link: "assets",
			Impact: "超过 24 小时没有流量：可能已下线，也可能是采集中断", Fix: "确认接口状态；仍在使用的接口检查对应采集器"})
	}

	events := s.traffic.events.Load()
	identified := s.traffic.identified.Load()
	withBody := s.traffic.withBody.Load()
	share := func(n uint64) float64 {
		if events == 0 {
			return 0
		}
		return float64(n) / float64(events)
	}
	if events > 0 && share(identified) < identityMinShare {
		spots = append(spots, blindSpot{Type: "调用方无法识别", Area: fmt.Sprintf("%.0f%% 的请求", (1-share(identified))*100), Severity: "medium", Link: "identity-center",
			Impact: "只能按来源 IP 归并调用方，越权和爬虫检测按 IP 而非账号进行",
			Fix:    "让网关透传 x-user-id、x-api-key 或 x-service-name 请求头"})
	}
	if events > 0 && share(withBody) < bodyMinShare {
		spots = append(spots, blindSpot{Type: "未采集响应体", Area: fmt.Sprintf("%.0f%% 的请求", (1-share(withBody))*100), Severity: "medium", Link: "data-gov",
			Impact: "敏感数据检测只能依据 URL 参数，无法发现响应中返回的敏感字段",
			Fix:    "网关访问日志不含响应体；需要时使用能采集响应体的采集方式"})
	}

	rank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(spots, func(i, j int) bool { return rank[spots[i].Severity] < rank[spots[j].Severity] })
	if spots == nil {
		spots = []blindSpot{}
	}

	c.JSON(200, gin.H{
		"agents": gin.H{"total": len(agents), "online": agentStatus["online"], "degraded": agentStatus["degraded"], "offline": agentStatus["offline"]},
		"assets": gin.H{"total": len(assets), "unclaimed": unclaimed, "stale": stale, "sensitive": sensitive, "sensitive_unclaimed": sensitiveUnclaimed},
		"traffic": gin.H{
			"since": startedAt, "events": events,
			"identified_share": share(identified), "body_share": share(withBody),
		},
		"blind_spots": spots,
	})
}
