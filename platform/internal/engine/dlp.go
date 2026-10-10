package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// Sensitive data types recognised by field name. Collectors mask the values
// before they leave the host, so detection relies on field names.
const (
	SensitiveIDCard     = "id_card"
	SensitivePhone      = "phone"
	SensitiveBankCard   = "bank_card"
	SensitiveCredential = "credential"
	SensitiveContact    = "contact"
)

var sensitiveMarkers = []struct {
	kind    string
	markers []string
}{
	// Order matters: "id_card" must not be read as a bank card.
	{SensitiveIDCard, []string{"id_card", "idcard", "id_no", "idno", "identity", "cert_no", "certno", "sfz"}},
	{SensitiveBankCard, []string{"card", "bank", "account_no", "acct_no", "iban"}},
	{SensitivePhone, []string{"phone", "mobile", "telephone", "tel_no", "telno"}},
	{SensitiveCredential, []string{"password", "passwd", "pwd", "token", "secret", "api_key", "apikey", "access_key", "credential"}},
	{SensitiveContact, []string{"address", "email"}},
}

var sensitiveLabels = map[string]string{
	SensitiveIDCard:     "身份证号",
	SensitivePhone:      "手机号",
	SensitiveBankCard:   "银行卡号",
	SensitiveCredential: "凭证",
	SensitiveContact:    "地址/邮箱",
}

// SensitiveType returns the sensitive data type a field name indicates, or
// "" when it indicates none.
func SensitiveType(field string) string {
	n := strings.ToLower(field)
	for _, m := range sensitiveMarkers {
		for _, marker := range m.markers {
			if strings.Contains(n, marker) {
				return m.kind
			}
		}
	}
	return ""
}

// DLPEngine raises sensitive-data findings for responses that return
// sensitive fields from export-like endpoints or return many of them at once.
type DLPEngine struct {
	store  storage.Store
	mu     sync.RWMutex
	now    func() time.Time
	events *cooldown

	enabled        map[string]bool
	exportKeywords []string
	maxFields      int
}

// DLP defaults, matching rule R-DLP-001.
const (
	dlpDefaultExportKeywords = "export,download,dump,batch"
	dlpDefaultMaxFields      = 3
)

func NewDLPEngine(store storage.Store) *DLPEngine {
	e := &DLPEngine{store: store, now: time.Now, events: newCooldown()}
	e.Configure(nil)
	return e
}

// Configure applies rule R-DLP-001's parameters: one switch per sensitive
// type (id_card, phone, bank_card, credential, contact), export_keywords and
// max_fields.
func (e *DLPEngine) Configure(p Params) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = map[string]bool{
		SensitiveIDCard:     p.Bool(SensitiveIDCard, true),
		SensitivePhone:      p.Bool(SensitivePhone, true),
		SensitiveBankCard:   p.Bool(SensitiveBankCard, true),
		SensitiveCredential: p.Bool(SensitiveCredential, true),
		SensitiveContact:    p.Bool(SensitiveContact, false),
	}
	e.exportKeywords = nil
	for _, k := range p.List("export_keywords", dlpDefaultExportKeywords) {
		e.exportKeywords = append(e.exportKeywords, strings.ToLower(k))
	}
	if e.maxFields = p.Int("max_fields", dlpDefaultMaxFields); e.maxFields < 1 {
		e.maxFields = dlpDefaultMaxFields
	}
}

// Evaluate scores one request to endpoint whose traffic carried fields.
// Only fields of enabled types count. An export-like endpoint with any of
// them, or max_fields or more of them, scores 75; credentials raise it to 85.
func (e *DLPEngine) Evaluate(endpoint, sourceIP string, fields []string) (int, string) {
	e.mu.RLock()
	matched := make(map[string]string) // field -> type
	for _, f := range fields {
		if kind := SensitiveType(f); kind != "" && e.enabled[kind] {
			matched[f] = kind
		}
	}
	if len(matched) == 0 {
		e.mu.RUnlock()
		return 0, ""
	}
	path := strings.ToLower(endpoint)
	export := ""
	for _, k := range e.exportKeywords {
		if strings.Contains(path, k) {
			export = k
			break
		}
	}
	maxFields := e.maxFields
	e.mu.RUnlock()

	if export == "" && len(matched) < maxFields {
		return 0, ""
	}

	names := make([]string, 0, len(matched))
	kinds := map[string]bool{}
	for f, kind := range matched {
		names = append(names, f)
		kinds[kind] = true
	}
	sort.Strings(names)
	labels := make([]string, 0, len(kinds))
	for _, m := range sensitiveMarkers {
		if kinds[m.kind] {
			labels = append(labels, sensitiveLabels[m.kind])
		}
	}

	riskScore := 75
	if kinds[SensitiveCredential] {
		riskScore = 85
	}
	var reason string
	if export != "" {
		reason = fmt.Sprintf("敏感数据导出: %s 返回 %s（字段 %s）", endpoint, strings.Join(labels, "、"), strings.Join(names, ", "))
	} else {
		reason = fmt.Sprintf("敏感数据集中返回: %s 单次返回 %d 个敏感字段（阈值 %d）: %s", endpoint, len(names), maxFields, strings.Join(names, ", "))
	}

	if e.events.allow(endpoint, e.now()) {
		evt := &storage.AlertEvent{
			ID:   fmt.Sprintf("dlp-%d", time.Now().UnixNano()),
			Type: "SENSITIVE_DATA", Severity: "high",
			Title:     fmt.Sprintf("敏感数据暴露: %s", endpoint),
			Detail:    reason,
			SourceIP:  sourceIP,
			RiskScore: riskScore,
			CreatedAt: time.Now(),
		}
		if err := e.store.SaveDetectionEvent(context.Background(), evt); err != nil {
			logger.L().Errorf("Failed to save DLP event: %v", err)
		}
	}
	return riskScore, reason
}
