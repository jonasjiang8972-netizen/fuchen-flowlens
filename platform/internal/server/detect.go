package server

import (
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
)

// ruleTitles are the titles of alerts raised by each rule.
var ruleTitles = map[string]string{
	ruleBOLA: "BOLA 对象遍历自动告警",
	ruleAuth: "认证失败/撞库风险自动告警",
	ruleBFLA: "BFLA 越权访问自动告警",
	ruleDLP:  "敏感数据接口自动告警",
}

// detection is the strongest finding for one request.
type detection struct {
	RuleID string
	Score  int
	Reason string
}

// detectInput is one request as seen by the engines.
type detectInput struct {
	req       accessDetectionRequest
	sensitive []string // field names seen in the request or response
}

// evaluate runs every enabled rule's engine on one request and returns the
// highest-scoring finding. Disabled rules are not evaluated. Baselines that
// take time to build (BFLA role shares, authentication failures) keep being
// recorded while their rule is off, so switching it on takes effect at once.
func (s *PlatformServer) evaluate(in detectInput) detection {
	req := in.req
	var best detection
	consider := func(ruleID string, score int, reason string) {
		if score > best.Score {
			best = detection{RuleID: ruleID, Score: score, Reason: reason}
		}
	}

	s.bflaEngine.RecordAccess(req.AccountID, req.Role, req.Endpoint)
	if req.Status == 401 {
		s.authEngine.RecordFailure(req.SourceIP, req.AccountID)
	}

	if s.ruleService.IsEnabled(ruleBFLA) {
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
	return best
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
	alert := s.alertService.CreateDetectionAlert(rule.RequirementFR, severity, title, d.Reason,
		req.SourceIP, req.AccountID, d.Score, confidence)
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
