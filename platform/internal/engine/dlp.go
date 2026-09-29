package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/sensitive"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// DLPEngine turns per-response sensitive-data findings into risk scores.
// Two conditions are flagged:
//   - masking defect: an ID card, phone or bank card number left unmasked in
//     a response (score 75 and up);
//   - bulk exposure: more sensitive values in one response than MaxFields,
//     even when masked (score 70).
//
// Values are never stored; alerts carry counts and types only.
type DLPEngine struct {
	store     storage.Store
	MaxFields int
	now       func() time.Time
	events    *cooldown
}

// NewDLPEngine returns an engine that flags responses with more than
// maxFields sensitive values (the rule's default is 5).
func NewDLPEngine(store storage.Store, maxFields int) *DLPEngine {
	if maxFields <= 0 {
		maxFields = 5
	}
	return &DLPEngine{store: store, MaxFields: maxFields, now: time.Now, events: newCooldown()}
}

// DLPResult is the outcome of one evaluation.
type DLPResult struct {
	Score          int
	Reason         string
	MaskingDefect  bool
	UnmaskedByType map[sensitive.Type]int
}

// Evaluate scores the findings of one response on endpoint.
func (e *DLPEngine) Evaluate(endpoint, accountID, sourceIP string, f sensitive.Findings) DLPResult {
	unmasked := f.UnmaskedTotal()
	total := f.Total()
	res := DLPResult{}

	switch {
	case unmasked > 0:
		res.MaskingDefect = true
		res.UnmaskedByType = map[sensitive.Type]int{}
		var parts []string
		types := 0
		for _, t := range sensitive.Types {
			if n := f.Unmasked[t]; n > 0 && t.Maskable() {
				res.UnmaskedByType[t] = n
				parts = append(parts, fmt.Sprintf("%s %d 处", t.Name(), n))
				types++
			}
		}
		// 75 for one value, +5 per extra type, +1 per extra value up to 10.
		res.Score = min(75+5*(types-1)+min(unmasked-1, 10), 95)
		res.Reason = fmt.Sprintf("脱敏缺陷: 接口 %s 的响应包含未脱敏的敏感数据(%s)", endpoint, strings.Join(parts, "、"))
	case total > e.MaxFields:
		res.Score = 70
		res.Reason = fmt.Sprintf("敏感数据批量返回: 接口 %s 单次响应含 %d 个敏感数据(阈值 %d)", endpoint, total, e.MaxFields)
	default:
		return res
	}

	if e.events.allow("dlp|"+endpoint+"|"+fmt.Sprint(res.MaskingDefect), e.now()) {
		sev := "high"
		if res.Score >= 90 {
			sev = "critical"
		}
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("dlp-%d", e.now().UnixNano()),
			Type: "DLP", Severity: sev,
			Title:  "敏感数据检测: " + endpoint,
			Detail: res.Reason, SourceIP: sourceIP, AccountID: accountID,
			RiskScore: res.Score, CreatedAt: e.now(),
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save DLP event: %v", err)
		}
	}
	return res
}
