package server

import (
	"strings"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/engine"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
)

// alertThreshold is the risk score from which a detection raises an alert.
const alertThreshold = 70

// Detection rule IDs; each maps to one engine.
const (
	ruleBOLA = "R-BOLA-001"
	ruleAuth = "R-AUTH-001"
	ruleBFLA = "R-BFLA-001"
	ruleDLP  = "R-DLP-001"
	ruleBot  = "R-BOT-001"
	ruleRate = "R-RATE-001"
	ruleSSRF = "R-SSRF-001"
)

// ruleTitles are the titles of alerts raised by each rule.
var ruleTitles = map[string]string{
	ruleBOLA: "BOLA 对象遍历自动告警",
	ruleAuth: "认证失败/撞库风险自动告警",
	ruleBFLA: "BFLA 越权访问自动告警",
	ruleDLP:  "敏感数据接口自动告警",
	ruleBot:  "爬虫行为自动告警",
	ruleRate: "接口流量突增自动告警",
	ruleSSRF: "SSRF 服务端请求伪造自动告警",
}

// detection is the strongest finding for one request.
type detection struct {
	RuleID string
	Score  int
	Reason string
	// Subject overrides the account and source IP the alert is filed under
	// when the finding concerns something else (an endpoint for traffic
	// surges), so one surge is one alert rather than one per caller.
	Subject   string
	SubjectIP string
	override  bool
	// Endpoint is the API ("METHOD /path") the request went to.
	Endpoint string
}

// detectInput is one request as seen by the engines.
type detectInput struct {
	req       accessDetectionRequest
	sensitive []string // sensitive field names the endpoint exposes
	method    string
	query     map[string]string
	body      []byte // request body
	// networkOnly marks a caller identified by source IP alone.
	networkOnly bool
	at          time.Time // when the request was made; zero means now
}

// evaluate returns the highest-scoring finding for one request (see
// evaluateAll).
func (s *PlatformServer) evaluate(in detectInput) detection {
	var best detection
	for _, d := range s.evaluateAll(in) {
		if d.Score > best.Score {
			best = d
		}
	}
	return best
}

// evaluateAll runs every enabled rule's engine on one request and returns
// each rule's finding (score > 0). One request can concern several rules,
// such as a scripted crawler that also walks objects. Disabled rules are
// not evaluated. Baselines that take time to build (BFLA role shares,
// authentication failures) keep being recorded while their rule is off, so
// switching it on takes effect at once.
func (s *PlatformServer) evaluateAll(in detectInput) []detection {
	req := in.req
	var found []detection
	consider := func(ruleID string, score int, reason string) {
		if score > 0 {
			found = append(found, detection{RuleID: ruleID, Score: score, Reason: reason})
		}
	}

	s.bflaEngine.RecordAccess(req.AccountID, req.Role, req.Endpoint)
	if req.Status == 401 {
		s.authEngine.RecordFailure(req.SourceIP, req.AccountID)
	}

	// A caller known only by an internal source IP carries no role: its
	// "internal" label says where it is, not what it may do, so BFLA would
	// flag every internal client that reaches a management endpoint.
	// External-only callers are still checked.
	if s.ruleService.IsEnabled(ruleBFLA) && !(in.networkOnly && req.Role == "internal") {
		score, reason := s.bflaEngine.Evaluate(req.AccountID, req.Role, req.Endpoint)
		consider(ruleBFLA, score, reason)
	}
	if req.Status == 401 && s.ruleService.IsEnabled(ruleAuth) {
		score, reason := s.authEngine.Evaluate(req.SourceIP)
		consider(ruleAuth, score, reason)
	}
	if s.ruleService.IsEnabled(ruleBOLA) {
		score, reason := s.bolaEngine.Evaluate(req.AccountID, req.ObjectID, req.Endpoint, req.SourceIP)
		consider(ruleBOLA, score, reason)
	}
	if len(in.sensitive) > 0 && s.ruleService.IsEnabled(ruleDLP) {
		score, reason := s.dlpEngine.Evaluate(req.Endpoint, req.SourceIP, in.sensitive)
		consider(ruleDLP, score, reason)
	}
	if req.AccountID != "" && s.ruleService.IsEnabled(ruleBot) {
		score, reason := s.botEngine.Evaluate(req.AccountID, req.SourceIP, in.at)
		consider(ruleBot, score, reason)
	}
	if (len(in.query) > 0 || len(in.body) > 0) && s.ruleService.IsEnabled(ruleSSRF) {
		score, reason := s.ssrfEngine.Evaluate(req.Endpoint, req.SourceIP, in.query, in.body)
		consider(ruleSSRF, score, reason)
	}
	if req.Endpoint != "" && s.ruleService.IsEnabled(ruleRate) {
		endpoint := strings.TrimSpace(in.method + " " + req.Endpoint)
		score, reason, top := s.rateEngine.Evaluate(endpoint, req.SourceIP, in.at)
		if score > 0 {
			found = append(found, detection{RuleID: ruleRate, Score: score, Reason: reason,
				Subject: "endpoint:" + endpoint, SubjectIP: top, override: true})
		}
	}
	if req.Endpoint != "" {
		for i := range found {
			found[i].Endpoint = strings.TrimSpace(in.method + " " + req.Endpoint)
		}
	}
	return found
}

// raise turns a finding at or above alertThreshold into an alert (merged
// with an open alert for the same rule, account and IP) and counts a hit on
// its rule. It returns nil when the finding is below the threshold.
func (s *PlatformServer) raise(d detection, req accessDetectionRequest, confidence float64) *service.Alert {
	if d.Score < alertThreshold || d.RuleID == "" {
		return nil
	}
	rule, err := s.ruleService.Get(d.RuleID)
	if err != nil {
		return nil
	}
	severity := rule.Severity
	switch {
	case d.Score >= 90:
		severity = "critical"
	case severity == "critical":
		severity = "high"
	}
	title := ruleTitles[d.RuleID]
	if title == "" {
		title = rule.Name
	}
	account, ip := req.AccountID, req.SourceIP
	if d.override {
		account, ip = d.Subject, d.SubjectIP
	}
	alert := s.alertService.CreateDetectionAlert(rule.RequirementFR, severity, title, d.Reason,
		ip, account, d.Score, confidence)
	if d.Endpoint != "" {
		s.alertService.AddEndpoint(alert.ID, d.Endpoint)
	}
	s.ruleService.IncrementHit(d.RuleID)
	return &alert
}

// configurable is an engine that takes its thresholds from a rule.
type configurable interface{ Configure(engine.Params) }

func (s *PlatformServer) engineFor(ruleID string) configurable {
	switch ruleID {
	case ruleBOLA:
		return s.bolaEngine
	case ruleAuth:
		return s.authEngine
	case ruleBFLA:
		return s.bflaEngine
	case ruleDLP:
		return s.dlpEngine
	case ruleBot:
		return s.botEngine
	case ruleRate:
		return s.rateEngine
	case ruleSSRF:
		return s.ssrfEngine
	}
	return nil
}

// applyRuleConfig pushes rule ruleID's current parameter values into its
// engine; call it at start-up and after every parameter change.
func (s *PlatformServer) applyRuleConfig(ruleID string) {
	if e := s.engineFor(ruleID); e != nil {
		e.Configure(engine.Params(s.ruleService.Values(ruleID)))
	}
}

func (s *PlatformServer) applyAllRuleConfigs() {
	for _, r := range s.ruleService.List() {
		s.applyRuleConfig(r.ID)
	}
}
