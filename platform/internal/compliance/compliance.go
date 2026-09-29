// Package compliance turns the platform's live state into a self-assessment
// against MLPS level 3 (等保 2.0 三级) and financial-sector expectations.
//
// Each check is one of three kinds, and the report says which:
//
//	live       decided from the running platform (policy values, accounts, alerts…)
//	capability a fact about what the product implements, taken from the code
//	manual     cannot be judged by software (premises, staff, drills)
//
// A check the platform cannot verify is never reported as passing.
package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/iam"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/service"
)

// Statuses.
const (
	Pass    = "pass"
	Partial = "partial"
	Fail    = "fail"
	Manual  = "manual" // needs a human to judge
)

// Bases: how a check's status was decided.
const (
	BasisLive       = "live"
	BasisCapability = "capability"
	BasisManual     = "manual"
)

// Templates.
const (
	TemplateMLPS3   = "mlps3"
	TemplateFinance = "finance"
)

// Deployment is how this instance was started, which the platform cannot
// see for itself.
type Deployment struct {
	DBPersistent       bool   // PostgreSQL rather than in-memory storage
	DBSSLMode          string // sslmode from the DSN; empty when unknown
	TLS                bool   // the platform terminates TLS itself
	SecureCookies      bool   // served over HTTPS (possibly by a proxy)
	ClientCertRequired bool   // collectors must present a client certificate
	AgentTokenSet      bool
	DemoMode           bool
	SOARConnectors     int // real connectors configured (the demo simulator does not count)
	SOARDryRun         bool
	BOLAModelEnabled   bool
	BOLAModelTrained   bool
}

// Snapshot is everything the report is built from.
type Snapshot struct {
	Now        time.Time
	Policy     iam.Policy
	Users      []iam.UserView
	AuditCheck *audit.VerifyResult // nil when verification could not run
	AuditErr   string
	Deploy     Deployment
	Assets     []service.Asset
	Alerts     []service.Alert
	Tickets    service.TicketSummary
	// SeriousAlertsWithoutTicket counts open high/critical alerts that no
	// ticket covers.
	SeriousAlertsWithoutTicket int
	Agents                     []service.Agent
	Rules                      []service.Rule
}

// Check is one assessed item.
type Check struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Requirement string `json:"requirement"`
	Ref         string `json:"ref"`
	Status      string `json:"status"`
	Basis       string `json:"basis"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation,omitempty"`
}

// Section groups checks of one category.
type Section struct {
	Category string  `json:"category"`
	Checks   []Check `json:"checks"`
}

// Counts summarises statuses.
type Counts struct {
	Pass    int `json:"pass"`
	Partial int `json:"partial"`
	Fail    int `json:"fail"`
	Manual  int `json:"manual"`
	Total   int `json:"total"`
}

// Report is a generated assessment.
type Report struct {
	Template    string    `json:"template"`
	Title       string    `json:"title"`
	GeneratedAt time.Time `json:"generated_at"`
	Disclaimer  string    `json:"disclaimer"`
	Summary     Counts    `json:"summary"`
	Sections    []Section `json:"sections"`
	Demo        bool      `json:"demo,omitempty"`
}

// TemplateInfo describes an available template.
type TemplateInfo struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Templates lists the report templates.
func Templates() []TemplateInfo {
	return []TemplateInfo{
		{TemplateMLPS3, "等保 2.0 三级自查", "对照 GB/T 22239-2019 第三级的安全通信网络、安全计算环境、安全管理中心要求，逐项给出运行状态和证据"},
		{TemplateFinance, "金融行业自查", "在等保三级自查基础上，突出个人金融信息保护、数据分级与日志留存，条目引用 JR/T 0071、JR/T 0171、JR/T 0197 与相关法律"},
	}
}

const disclaimer = "本报告是产品对自身运行状态的自查，不是等保测评结论，也不能替代测评机构出具的报告。" +
	"“实时”项由平台当前的配置和数据判定；“能力”项说明产品是否实现了相应功能，取自代码而非现场验证；" +
	"“需人工”项涉及机房、制度、人员、演练等软件无法判断的内容。条款编号仅作定位，请以标准原文为准，" +
	"个别数值要求（口令长度、更换周期等）以客户内部制度为准。"

// Categories, in report order.
const (
	CatIdentity = "身份鉴别"
	CatAccess   = "访问控制与三权分立"
	CatAudit    = "安全审计"
	CatComm     = "通信传输与密码应用"
	CatData     = "数据安全与个人信息保护"
	CatAssets   = "API 资产与采集覆盖"
	CatResponse = "入侵防范与处置响应"
	CatManual   = "管理制度与人工核查"
)

var categoryOrder = []string{CatIdentity, CatAccess, CatAudit, CatComm, CatData, CatAssets, CatResponse, CatManual}

// refs maps a check to its reference in each template. A check with no entry
// for a template is left out of it.
var refs = map[string]map[string]string{
	"ID-1": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.1 身份鉴别", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.1"},
	"ID-2": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.1 身份鉴别", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.1"},
	"ID-3": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.1 身份鉴别", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.1"},
	"ID-4": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.2 访问控制", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.2"},
	"ID-5": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.1 身份鉴别", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.1"},
	"ID-6": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.2 访问控制", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.2"},
	"AC-1": {TemplateMLPS3: "GB/T 22239-2019 8.1.5 安全管理中心", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.5"},
	"AC-2": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.2 访问控制", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.2"},
	"AU-1": {TemplateMLPS3: "网络安全法第二十一条；GB/T 22239-2019 8.1.4.3", TemplateFinance: "网络安全法第二十一条；JR/T 0071-2020"},
	"AU-2": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.3 安全审计", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.3"},
	"AU-3": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.3 安全审计", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.3"},
	"AU-4": {TemplateMLPS3: "GB/T 22239-2019 8.1.5 安全管理中心（集中管控）", TemplateFinance: "JR/T 0071-2020"},
	"AU-5": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.3 安全审计", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.3"},
	"TR-1": {TemplateMLPS3: "GB/T 22239-2019 8.1.2 安全通信网络（通信传输）", TemplateFinance: "JR/T 0071-2020；JR/T 0171-2020（传输）"},
	"TR-2": {TemplateMLPS3: "GB/T 22239-2019 8.1.2 安全通信网络（通信传输）", TemplateFinance: "JR/T 0071-2020"},
	"TR-3": {TemplateMLPS3: "GB/T 39786-2021 第三级", TemplateFinance: "GB/T 39786-2021 第三级；JR/T 0071-2020"},
	"TR-4": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.8 数据保密性", TemplateFinance: "JR/T 0071-2020；JR/T 0171-2020（存储）"},
	"DA-1": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.11 个人信息保护", TemplateFinance: "JR/T 0171-2020；个人信息保护法"},
	"DA-2": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.11 个人信息保护", TemplateFinance: "JR/T 0171-2020（展示与传输）；个人信息保护法"},
	"DA-3": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.11 个人信息保护", TemplateFinance: "JR/T 0171-2020；数据安全法"},
	"DA-4": {TemplateFinance: "JR/T 0197-2020；JR/T 0223-2021"},
	"DA-5": {TemplateFinance: "JR/T 0171-2020（展示）；个人信息保护法"},
	"AS-1": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.4 入侵防范（资产清点）", TemplateFinance: "JR/T 0071-2020；数据安全法"},
	"AS-2": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.2 访问控制（责任到人）", TemplateFinance: "JR/T 0071-2020；数据安全法"},
	"AS-3": {TemplateMLPS3: "GB/T 22239-2019 8.1.5 安全管理中心（集中监测）", TemplateFinance: "JR/T 0071-2020"},
	"IR-1": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.4 入侵防范", TemplateFinance: "JR/T 0071-2020；GB/T 22239-2019 8.1.4.4"},
	"IR-2": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.4 入侵防范", TemplateFinance: "JR/T 0071-2020"},
	"IR-3": {TemplateMLPS3: "GB/T 22239-2019 8.1.5 安全管理中心", TemplateFinance: "JR/T 0071-2020"},
	"IR-4": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.4 入侵防范", TemplateFinance: "JR/T 0071-2020"},
	"IR-5": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.4 入侵防范", TemplateFinance: "JR/T 0071-2020"},
	"MG-1": {TemplateMLPS3: "GB/T 22239-2019 7 安全物理环境", TemplateFinance: "JR/T 0071-2020"},
	"MG-2": {TemplateMLPS3: "GB/T 22239-2019 8.1.10 安全管理制度、8.1.9 安全管理人员", TemplateFinance: "JR/T 0071-2020"},
	"MG-3": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.9 数据备份恢复", TemplateFinance: "JR/T 0071-2020；JR/T 0223-2021"},
	"MG-4": {TemplateMLPS3: "GB/T 22239-2019 8.1.4.4 入侵防范（漏洞与风险管理）", TemplateFinance: "JR/T 0071-2020"},
	"MG-5": {TemplateMLPS3: "GB/T 39786-2021", TemplateFinance: "GB/T 39786-2021；JR/T 0071-2020"},
}

type builder struct {
	s      Snapshot
	checks []Check
}

func (b *builder) add(c Check) { b.checks = append(b.checks, c) }

// Build assesses the snapshot against a template.
func Build(template string, snap Snapshot) (Report, error) {
	var title string
	for _, t := range Templates() {
		if t.ID == template {
			title = t.Title + "报告"
		}
	}
	if title == "" {
		return Report{}, fmt.Errorf("未知的报告模板 %q", template)
	}
	if snap.Now.IsZero() {
		snap.Now = time.Now()
	}
	b := &builder{s: snap}
	b.identity()
	b.access()
	b.auditing()
	b.comm()
	b.data()
	b.assets()
	b.response()
	b.manual()

	r := Report{Template: template, Title: title, GeneratedAt: snap.Now, Disclaimer: disclaimer, Demo: snap.Deploy.DemoMode}
	byCat := map[string][]Check{}
	for _, c := range b.checks {
		ref, ok := refs[c.ID][template]
		if !ok {
			continue
		}
		c.Ref = ref
		byCat[c.Category] = append(byCat[c.Category], c)
		r.Summary.Total++
		switch c.Status {
		case Pass:
			r.Summary.Pass++
		case Partial:
			r.Summary.Partial++
		case Fail:
			r.Summary.Fail++
		default:
			r.Summary.Manual++
		}
	}
	for _, cat := range categoryOrder {
		if cs := byCat[cat]; len(cs) > 0 {
			r.Sections = append(r.Sections, Section{Category: cat, Checks: cs})
		}
	}
	return r, nil
}

// ─── Identity ──────────────────────────────────────────────────

func (b *builder) identity() {
	p := b.s.Policy
	pw := p.PasswordMinLength >= 8 && p.PasswordMinClasses >= 3 && p.PasswordMaxAgeDays > 0 && p.PasswordMaxAgeDays <= 90 && p.PasswordHistory >= 1
	b.add(Check{ID: "ID-1", Category: CatIdentity, Title: "口令复杂度、有效期与历史", Basis: BasisLive,
		Requirement: "口令有复杂度要求并定期更换，不能重复使用旧口令",
		Status:      statusOf(pw),
		Evidence:    fmt.Sprintf("最短 %d 位，须含 %d 类字符；%d 天强制更换；不得与最近 %d 次相同", p.PasswordMinLength, p.PasswordMinClasses, p.PasswordMaxAgeDays, p.PasswordHistory),
		Remediation: onFail(pw, "在系统管理后台的安全策略中调整口令策略")})

	lock := p.LockoutThreshold >= 3 && p.LockoutThreshold <= 10 && p.LockoutMinutes >= 10
	b.add(Check{ID: "ID-2", Category: CatIdentity, Title: "登录失败锁定与限速", Basis: BasisLive,
		Requirement: "限制非法登录次数，达到上限后锁定",
		Status:      statusOf(lock),
		Evidence:    fmt.Sprintf("连续失败 %d 次锁定 %d 分钟；同一来源每分钟最多 %d 次登录尝试", p.LockoutThreshold, p.LockoutMinutes, p.LoginRatePerIPMinute),
		Remediation: onFail(lock, "调整安全策略中的锁定阈值和时长")})

	sess := p.SessionIdleMinutes > 0 && p.SessionIdleMinutes <= 30 && p.SessionMaxHours > 0 && p.SessionMaxHours <= 12
	b.add(Check{ID: "ID-3", Category: CatIdentity, Title: "会话超时", Basis: BasisLive,
		Requirement: "登录会话空闲超时自动退出",
		Status:      statusOf(sess),
		Evidence:    fmt.Sprintf("空闲 %d 分钟退出；会话最长 %d 小时；退出后令牌立即失效", p.SessionIdleMinutes, p.SessionMaxHours),
		Remediation: onFail(sess, "调整安全策略中的会话时长")})

	initial := 0
	for _, u := range b.s.Users {
		if u.Status == "active" && u.MustChangePassword {
			initial++
		}
	}
	b.add(Check{ID: "ID-4", Category: CatIdentity, Title: "初始口令已修改", Basis: BasisLive,
		Requirement: "默认账号和初始口令必须在首次使用时修改",
		Status:      statusOf(initial == 0),
		Evidence:    fmt.Sprintf("%d 个启用账号仍在使用初始口令（系统会在首次登录时强制修改）；账号总数 %d", initial, len(b.s.Users)),
		Remediation: onFail(initial == 0, "让这些账号完成首次登录并修改口令，或在系统管理后台停用不用的账号")})

	b.add(Check{ID: "ID-5", Category: CatIdentity, Title: "双因素认证", Basis: BasisCapability, Status: Fail,
		Requirement: "采用口令、密码技术、生物技术中两种或以上组合的鉴别，其中一种至少使用密码技术",
		Evidence:    "目前只支持用户名加口令，尚未实现 TOTP 动态口令或 USB Key / 数字证书登录",
		Remediation: "接入 TOTP 或国密 USB Key 登录（路线图中尚未排期）；在此之前，等保三级测评这一项不能通过"})

	stale := 0
	if p.AccountInactiveDays > 0 {
		cutoff := b.s.Now.AddDate(0, 0, -p.AccountInactiveDays)
		for _, u := range b.s.Users {
			if u.Status != "active" {
				continue
			}
			last := u.CreatedAt
			if u.LastLoginAt != nil {
				last = *u.LastLoginAt
			}
			if last.Before(cutoff) {
				stale++
			}
		}
	}
	status, ev := Pass, fmt.Sprintf("长期未登录账号自动停用（%d 天）；当前没有超期未登录的启用账号", p.AccountInactiveDays)
	switch {
	case p.AccountInactiveDays <= 0:
		status, ev = Fail, "未启用长期未登录账号自动停用"
	case stale > 0:
		status, ev = Fail, fmt.Sprintf("%d 个启用账号超过 %d 天未登录（自动停用任务会处理，但它们目前仍可登录）", stale, p.AccountInactiveDays)
	}
	b.add(Check{ID: "ID-6", Category: CatIdentity, Title: "多余和过期账号", Basis: BasisLive, Status: status, Evidence: ev,
		Requirement: "及时停用多余、过期账号，避免共享账号",
		Remediation: onFail(status == Pass, "在系统管理后台停用或删除这些账号，并在安全策略中启用自动停用")})
}

// ─── Access control ────────────────────────────────────────────

func (b *builder) access() {
	have := map[iam.Role]int{}
	for _, u := range b.s.Users {
		if u.Status == "active" {
			have[u.Role]++
		}
	}
	var missing []string
	for _, r := range []struct {
		role iam.Role
		name string
	}{{iam.RoleSysAdmin, "系统管理员"}, {iam.RoleAuditAdmin, "审计管理员"}, {iam.RoleSecAdmin, "安全管理员"}} {
		if have[r.role] == 0 {
			missing = append(missing, r.name)
		}
	}
	ok := len(missing) == 0
	ev := fmt.Sprintf("系统管理员 %d、审计管理员 %d、安全管理员 %d 个启用账号；每个账号只有一个角色，没有超级管理员；系统与审计管理员职责互斥", have[iam.RoleSysAdmin], have[iam.RoleAuditAdmin], have[iam.RoleSecAdmin])
	if !ok {
		ev = "缺少启用账号的角色：" + strings.Join(missing, "、")
	}
	b.add(Check{ID: "AC-1", Category: CatAccess, Title: "三权分立", Basis: BasisLive, Status: statusOf(ok), Evidence: ev,
		Requirement: "系统管理、安全管理、审计管理由不同角色承担，互不越权",
		Remediation: onFail(ok, "为缺少的角色创建并启用账号；同一个人不应兼任多个角色")})

	b.add(Check{ID: "AC-2", Category: CatAccess, Title: "最小权限与逐接口授权", Basis: BasisCapability, Status: Pass,
		Requirement: "按最小权限授权，每个接口都做权限校验",
		Evidence:    "五种内置角色；每个接口按权限校验，被拒绝的访问会写入审计；测试覆盖“角色 × 接口”的授权组合。尚不支持按业务线或资产分组的数据级授权",
		Remediation: "如需按业务线隔离数据，需要后续版本的数据级授权"})
}

// ─── Audit ─────────────────────────────────────────────────────

func (b *builder) auditing() {
	p := b.s.Policy
	ok := p.AuditRetentionDays >= 180
	b.add(Check{ID: "AU-1", Category: CatAudit, Title: "日志留存不少于六个月", Basis: BasisLive, Status: statusOf(ok),
		Requirement: "网络日志留存不少于六个月",
		Evidence:    fmt.Sprintf("审计日志保留 %d 天（下限 180 天，不能配置得更低）", p.AuditRetentionDays),
		Remediation: onFail(ok, "把审计保留期调到 180 天以上")})

	persist := b.s.Deploy.DBPersistent
	ev := "审计日志存入 PostgreSQL，数据库触发器禁止修改和删除已有记录"
	if !persist {
		ev = "未配置数据库（FLOWLENS_DB_DSN），审计日志只在内存中，重启即丢失"
	}
	b.add(Check{ID: "AU-2", Category: CatAudit, Title: "审计日志持久化", Basis: BasisLive, Status: statusOf(persist), Evidence: ev,
		Requirement: "审计记录持久保存，不因重启丢失",
		Remediation: onFail(persist, "配置 FLOWLENS_DB_DSN 使用 PostgreSQL")})

	st, ev := Manual, "本次未能执行完整性校验"
	if b.s.AuditErr != "" {
		ev = "完整性校验出错：" + b.s.AuditErr
	}
	if r := b.s.AuditCheck; r != nil {
		if r.OK {
			st, ev = Pass, fmt.Sprintf("SM3 哈希链校验通过（本次校验 %d 条，序号 %d 至 %d）", r.Checked, r.FirstSeq, r.LastSeq)
		} else {
			st, ev = Fail, fmt.Sprintf("哈希链在序号 %d 处断裂：%s", r.BrokenAt, r.Reason)
		}
	}
	b.add(Check{ID: "AU-3", Category: CatAudit, Title: "审计日志防篡改", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "对审计记录进行保护，避免被未预期地删除、修改或覆盖",
		Remediation: onFail(st == Pass, "立即在系统管理后台做完整校验并保全数据库现场")})

	b.add(Check{ID: "AU-4", Category: CatAudit, Title: "审计对接 SOC / SIEM", Basis: BasisCapability, Status: Fail,
		Requirement: "审计数据可集中收集和分析",
		Evidence:    "只能在管理后台查询和导出 CSV，尚不支持 syslog 或 Kafka 实时输出到集中平台",
		Remediation: "如客户有 SIEM，需要开发审计输出；目前只能定期导出"})

	b.add(Check{ID: "AU-5", Category: CatAudit, Title: "关键操作可追溯到人", Basis: BasisCapability, Status: Pass,
		Requirement: "审计覆盖重要用户行为和安全事件，记录主体、时间、结果",
		Evidence:    "登录成功与失败、账号与权限变更、策略变更、越权访问、告警处置、IP 封禁与解封、工单流转、规则修改、审计查询与导出都记录操作人、来源地址、对象和结果"})
}

// ─── Communication and cryptography ────────────────────────────

func (b *builder) comm() {
	d := b.s.Deploy
	st, ev := Fail, "平台以明文 HTTP 提供服务，登录口令和会话在网络上可被窃听"
	switch {
	case d.TLS:
		st, ev = Pass, "平台自身提供 TLS 1.2+"
	case d.SecureCookies:
		st, ev = Partial, "已按 HTTPS 部署（会话 Cookie 带 Secure），由前置代理终止 TLS；平台无法验证代理侧的证书和协议版本，请人工核查"
	}
	b.add(Check{ID: "TR-1", Category: CatComm, Title: "控制台与 API 传输加密", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "通信过程中对整个报文或会话过程进行加密，防止鉴别信息被窃听",
		Remediation: onFail(st == Pass, "配置 FLOWLENS_TLS_CERT/KEY，或在前置 nginx 启用 HTTPS 并设置 FLOWLENS_COOKIE_SECURE=true")})

	st, ev = Fail, "采集器既没有配置共享令牌，也没有客户端证书，任何人都可以向平台上报数据"
	switch {
	case d.ClientCertRequired:
		st, ev = Pass, "采集器必须出示客户端证书（双向 TLS），并携带共享令牌"
	case d.AgentTokenSet:
		st, ev = Partial, "采集器使用共享令牌认证，未强制客户端证书；令牌泄露后没有第二道防线，且所有采集器共用同一个令牌"
	}
	b.add(Check{ID: "TR-2", Category: CatComm, Title: "采集器通道认证", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "采集通道对通信双方进行身份验证",
		Remediation: onFail(st == Pass, "配置 FLOWLENS_TLS_CLIENT_CA 强制采集器使用客户端证书，并为每个采集器签发独立证书")})

	b.add(Check{ID: "TR-3", Category: CatComm, Title: "商用密码应用（SM2 / SM3 / SM4）", Basis: BasisCapability, Status: Partial,
		Requirement: "身份鉴别、传输、存储中使用商用密码",
		Evidence:    "已使用 SM3：审计哈希链、会话令牌哈希、凭证指纹。未实现：SM2 证书登录、SM4 存储加密、国密 TLS；口令仍用 bcrypt；未对接密码机",
		Remediation: "国密改造属于路线图 v1.3.0；需要密评的项目在此之前不能通过"})

	mode := strings.ToLower(d.DBSSLMode)
	switch {
	case !d.DBPersistent:
		st, ev = Manual, "未使用数据库，本项不适用"
	case mode == "verify-full" || mode == "verify-ca":
		st, ev = Pass, "数据库连接启用了 TLS 并校验证书（sslmode="+mode+"）"
	case mode == "require":
		st, ev = Partial, "数据库连接启用了 TLS 但不校验证书（sslmode=require），无法防范中间人"
	case mode == "":
		st, ev = Manual, "无法从连接串判断数据库连接是否加密，请人工核查"
	default:
		st, ev = Partial, "数据库连接未加密（sslmode="+mode+"）。同一内部网络内的 POC 部署可接受；生产环境应启用 TLS"
	}
	b.add(Check{ID: "TR-4", Category: CatComm, Title: "数据库连接加密", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "重要数据在传输和存储过程中保证保密性",
		Remediation: onFail(st == Pass || st == Manual, "外部数据库使用 sslmode=verify-full；数据落盘加密由数据库或磁盘层负责，需人工核查")})
}

// ─── Data security ─────────────────────────────────────────────

func (b *builder) data() {
	b.add(Check{ID: "DA-1", Category: CatData, Title: "采集端脱敏", Basis: BasisCapability, Status: Pass,
		Requirement: "个人信息和鉴别信息在采集和传输环节最小化、去标识化",
		Evidence:    "凭证替换为带密钥的 SM3 指纹，口令类字段删除，身份证、手机号、银行卡号掩码；平台收到后再做一次兜底；平台不保存请求体和响应体原文"})

	unmasked := 0
	for _, a := range b.s.Assets {
		for _, f := range a.SensitiveFields {
			if strings.Contains(f, "未脱敏") {
				unmasked++
				break
			}
		}
	}
	openDLP := 0
	for _, al := range b.s.Alerts {
		if (al.SourceRequirement == "FR-DLP-001" || al.SourceRequirement == "FR-DLP-003") && (al.Status == "open" || al.Status == "acknowledged" || al.Status == "in_progress") {
			openDLP++
		}
	}
	ok := unmasked == 0 && openDLP == 0
	ev := "没有接口被发现返回未脱敏的敏感数据，也没有未处置的脱敏缺陷告警"
	if !ok {
		ev = fmt.Sprintf("%d 个接口被发现返回未脱敏的敏感数据；%d 条脱敏缺陷告警尚未处置", unmasked, openDLP)
	}
	b.add(Check{ID: "DA-2", Category: CatData, Title: "接口返回的敏感数据已脱敏", Basis: BasisLive, Status: statusOf(ok), Evidence: ev,
		Requirement: "个人信息在展示和传输中按要求脱敏",
		Remediation: onFail(ok, "在数据治理页查看脱敏缺陷，推动接口负责人修复并回归验证")})

	high, unclaimed := 0, 0
	for _, a := range b.s.Assets {
		if a.SensitivityHint == "high" || len(a.SensitiveFields) > 0 {
			high++
			if a.ClaimStatus != "claimed" {
				unclaimed++
			}
		}
	}
	st, ev := Pass, fmt.Sprintf("识别到 %d 个涉及敏感数据的接口，均已认领责任人", high)
	switch {
	case high == 0:
		st, ev = Manual, "尚未识别到涉及敏感数据的接口。可能是确实没有，也可能是采集覆盖不足，请对照业务确认"
	case unclaimed > 0:
		st, ev = Fail, fmt.Sprintf("%d 个涉及敏感数据的接口中，%d 个还没有责任人", high, unclaimed)
	}
	b.add(Check{ID: "DA-3", Category: CatData, Title: "敏感数据接口有责任人", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "重要数据的处理有明确的责任主体",
		Remediation: onFail(st == Pass || st == Manual, "在 API 资产页为这些接口认领责任人")})

	b.add(Check{ID: "DA-4", Category: CatData, Title: "数据分级与全生命周期管理", Basis: BasisCapability, Status: Fail,
		Requirement: "按金融数据分级指南对数据分级，并落实全生命周期保护",
		Evidence:    "只有低/中/高的敏感度提示，没有对齐 JR/T 0197 的分级（如 C1–C3 类个人金融信息），也没有保留期与销毁管理",
		Remediation: "需要数据分级模型和保留期策略；路线图尚未排期"})

	b.add(Check{ID: "DA-5", Category: CatData, Title: "界面展示脱敏与明文授权查看", Basis: BasisCapability, Status: Partial,
		Requirement: "展示个人信息时默认脱敏，需要时经授权查看",
		Evidence:    "敏感数据在采集端已掩码，平台不接收也不保存明文，所以界面上看不到明文；尚未实现“经单独授权查看明文”的流程",
		Remediation: "如业务需要调阅明文，需要额外的授权与留痕机制"})
}

// ─── Assets and coverage ───────────────────────────────────────

func (b *builder) assets() {
	total, shadow, zombie, unclaimed := len(b.s.Assets), 0, 0, 0
	for _, a := range b.s.Assets {
		switch a.Status {
		case "shadow":
			shadow++
		case "zombie":
			zombie++
		}
		if a.ClaimStatus != "claimed" {
			unclaimed++
		}
	}
	st, ev := Pass, fmt.Sprintf("共 %d 个 API 资产，没有影子和僵尸接口", total)
	switch {
	case total == 0:
		st, ev = Manual, "尚未发现任何 API 资产，请确认采集器已接入"
	case shadow+zombie > 0:
		ratio := float64(shadow+zombie) / float64(total)
		st = Partial
		if ratio > 0.10 {
			st = Fail
		}
		ev = fmt.Sprintf("共 %d 个 API 资产，其中影子接口 %d 个、僵尸接口 %d 个（占 %.0f%%）", total, shadow, zombie, ratio*100)
	}
	b.add(Check{ID: "AS-1", Category: CatAssets, Title: "资产清单与影子接口", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "掌握暴露面，清理未登记和不再使用的接口",
		Remediation: onFail(st == Pass || st == Manual, "对影子接口补登记或下线，对僵尸接口确认后关闭")})

	st, ev = Pass, fmt.Sprintf("%d 个资产均已认领责任人", total)
	switch {
	case total == 0:
		st, ev = Manual, "尚未发现任何 API 资产"
	case unclaimed > 0:
		ratio := float64(unclaimed) / float64(total)
		st = Partial
		if ratio > 0.20 {
			st = Fail
		}
		ev = fmt.Sprintf("%d 个资产中 %d 个未认领（占 %.0f%%）", total, unclaimed, ratio*100)
	}
	b.add(Check{ID: "AS-2", Category: CatAssets, Title: "资产责任人覆盖", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "每个接口有明确责任人",
		Remediation: onFail(st == Pass || st == Manual, "在 API 资产页批量认领，或对接 CMDB")})

	agents := len(b.s.Agents)
	online := 0
	for _, a := range b.s.Agents {
		if a.Status == "online" {
			online++
		}
	}
	switch {
	case agents == 0:
		st, ev = Fail, "没有任何采集器注册，平台看不到任何流量"
	case online == agents:
		st, ev = Pass, fmt.Sprintf("%d 个采集器全部在线", agents)
	case float64(online)/float64(agents) >= 0.9:
		st, ev = Partial, fmt.Sprintf("%d 个采集器中 %d 个在线，其余离线或降级", agents, online)
	default:
		st, ev = Fail, fmt.Sprintf("%d 个采集器中只有 %d 个在线，存在较大的监控盲区", agents, online)
	}
	b.add(Check{ID: "AS-3", Category: CatAssets, Title: "采集覆盖与在线率", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "对网络与应用层流量持续监测",
		Remediation: onFail(st == Pass, "在覆盖率页排查离线采集器")})
}

// ─── Detection and response ────────────────────────────────────

func (b *builder) response() {
	enabled := 0
	var off []string
	for _, r := range b.s.Rules {
		if r.Enabled {
			enabled++
		} else {
			off = append(off, r.Name)
		}
	}
	total := len(b.s.Rules)
	sort.Strings(off)
	st, ev := Pass, fmt.Sprintf("%d 条检测规则全部启用", total)
	switch {
	case total == 0:
		st, ev = Fail, "没有检测规则"
	case enabled < total:
		st = Fail
		if float64(enabled)/float64(total) >= 0.5 {
			st = Partial
		}
		ev = fmt.Sprintf("%d 条规则中 %d 条启用；未启用：%s", total, enabled, strings.Join(off, "、"))
	}
	b.add(Check{ID: "IR-1", Category: CatResponse, Title: "检测策略启用", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "对网络攻击和异常访问行为进行检测",
		Remediation: onFail(st == Pass, "在检测策略页评估并启用未开启的规则")})

	seriousOpen := 0
	for _, a := range b.s.Alerts {
		if (a.Severity == "critical" || a.Severity == "high") && (a.Status == "open" || a.Status == "acknowledged") {
			seriousOpen++
		}
	}
	t := b.s.Tickets
	st = Pass
	ev = fmt.Sprintf("没有超过 SLA 的工单；未处置的高危及以上告警 %d 条，开放工单 %d 张", seriousOpen, t.Open)
	if t.Overdue > 0 {
		st, ev = Fail, fmt.Sprintf("%d 张工单已超过 SLA；未处置的高危及以上告警 %d 条", t.Overdue, seriousOpen)
	} else if t.AtRisk > 0 || t.Unassigned > 0 {
		st, ev = Partial, fmt.Sprintf("没有超时工单，但 %d 张临近超时、%d 张开放工单没有负责人；未处置的高危及以上告警 %d 条", t.AtRisk, t.Unassigned, seriousOpen)
	}
	b.add(Check{ID: "IR-2", Category: CatResponse, Title: "告警及时处置", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "发现攻击行为后及时报告和处置",
		Remediation: onFail(st == Pass, "在处置闭环页优先处理超时和无负责人的工单")})

	ok := b.s.SeriousAlertsWithoutTicket == 0
	ev = "所有未关闭的高危及以上告警都有工单；工单需经不同人员复核才能闭环，每步留痕"
	if !ok {
		ev = fmt.Sprintf("%d 条未关闭的高危及以上告警没有工单", b.s.SeriousAlertsWithoutTicket)
	}
	b.add(Check{ID: "IR-3", Category: CatResponse, Title: "处置闭环与复核", Basis: BasisLive, Status: statusOf(ok), Evidence: ev,
		Requirement: "安全事件的处置有记录、有责任人、有复核",
		Remediation: onFail(ok, "为这些告警创建工单（告警详情页的“创建工单”）")})

	d := b.s.Deploy
	switch {
	case d.SOARConnectors == 0:
		st, ev = Fail, "没有配置任何联动系统，告警上的“封禁”无法真正执行"
	case d.SOARDryRun:
		st, ev = Partial, fmt.Sprintf("已配置 %d 个联动系统，但处于演练模式，封禁只记录不执行", d.SOARConnectors)
	default:
		st, ev = Pass, fmt.Sprintf("已配置 %d 个联动系统；封禁有内网/受保护网段保护、时长上限、每小时限量，到期自动解除，全程审计", d.SOARConnectors)
	}
	b.add(Check{ID: "IR-4", Category: CatResponse, Title: "联动处置能力", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "具备对攻击源采取阻断措施的能力",
		Remediation: onFail(st == Pass, "按 docs/SOAR.md 配置网关或 WAF 联动；先用演练模式验证")})

	switch {
	case !d.BOLAModelEnabled:
		st, ev = Partial, "对象遍历（BOLA）检测只使用规则，异常检测模型已关闭；规则抓不到低于阈值的慢速遍历"
	case !d.BOLAModelTrained:
		st, ev = Partial, "异常检测模型已启用但样本还不足以训练，当前只使用规则；流量积累后会自动训练"
	default:
		st, ev = Pass, "对象遍历（BOLA）检测使用规则加孤立森林模型，模型已训练。检出率来自合成数据的测量，未经线上验证"
	}
	b.add(Check{ID: "IR-5", Category: CatResponse, Title: "异常行为检测", Basis: BasisLive, Status: st, Evidence: ev,
		Requirement: "识别规则之外的异常访问行为",
		Remediation: onFail(st == Pass, "保持模型开启并持续接入流量；上线前用真实流量评估误报")})
}

// ─── Manual ────────────────────────────────────────────────────

func (b *builder) manual() {
	m := func(id, title, req, ev string) {
		b.add(Check{ID: id, Category: CatManual, Title: title, Basis: BasisManual, Status: Manual, Requirement: req, Evidence: ev})
	}
	m("MG-1", "机房与物理环境", "物理位置选择、访问控制、防盗防火防水等", "软件无法判断，需要现场核查机房和承载环境")
	m("MG-2", "安全管理制度与人员", "有安全管理制度、岗位设置、人员录用与培训、外部人员管理", "需要审阅制度文件和人员管理记录")
	m("MG-3", "数据备份与恢复演练", "重要数据定期备份，并验证可以恢复", "平台数据全部在 PostgreSQL，备份、异地存放和恢复演练由数据库运维负责；平台本身不做备份，也没有验证过恢复")
	m("MG-4", "漏洞扫描与渗透测试", "定期扫描漏洞并处置，重要系统做渗透测试", "尚无第三方渗透测试报告；依赖漏洞（如 echarts 5.x 的中危 XSS）以及 govulncheck 需在可联网环境中执行并保留报告")
	m("MG-5", "密码应用安全性评估（密评）", "按 GB/T 39786-2021 对密码应用做安全性评估", "需要由具备资质的机构评估；当前国密改造只完成一部分，见“商用密码应用”一项")
}

// ─── helpers ───────────────────────────────────────────────────

func statusOf(ok bool) string {
	if ok {
		return Pass
	}
	return Fail
}

func onFail(ok bool, hint string) string {
	if ok {
		return ""
	}
	return hint
}
