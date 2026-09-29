// Package soar turns alert dispositions into real enforcement: it blocks a
// source address on the gateways, WAFs and automation platforms the operator
// has connected, and lifts the block again when it expires.
//
// Blocking a wrong address can cut off customers or internal services, so
// the manager is deliberately conservative: it refuses non-public and
// protected addresses, requires a bounded lifetime, caps how many blocks may
// be issued per hour, and supports a dry-run mode that changes nothing.
package soar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/audit"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// DocKind is the document kind blocks are persisted under.
const DocKind = "soar_block"

// Block states.
const (
	StateActive   = "active"   // enforced on at least one connector
	StateReleased = "released" // lifted (expired or unblocked by an operator)
	StateFailed   = "failed"   // no connector accepted it
	StateDryRun   = "dry_run"  // recorded only; nothing was sent
)

// Errors returned for requests the manager refuses.
var (
	ErrNoConnectors = errors.New("未配置任何联动系统")
	ErrUnknownConn  = errors.New("联动系统不存在")
	ErrBadTarget    = errors.New("目标地址不可封禁")
	ErrBadTTL       = errors.New("封禁时长无效")
	ErrRateLimited  = errors.New("封禁次数超过每小时上限")
	ErrNotBlocked   = errors.New("该地址当前没有生效的封禁")
)

// Adapter enforces blocks on one external system. Implementations must be
// idempotent (blocking a blocked address, or unblocking an unknown one, is
// not an error) and safe for concurrent use.
type Adapter interface {
	Name() string  // stable identifier, e.g. "kong"
	Label() string // display name
	// Block applies the block and returns a reference the connector needs to
	// lift it again (empty when the address alone is enough).
	Block(ctx context.Context, req Request) (ref string, err error)
	Unblock(ctx context.Context, ip, ref string) error
	// Check verifies the connector is reachable and correctly configured.
	Check(ctx context.Context) error
}

// Request describes one block.
type Request struct {
	IP      string
	Reason  string
	AlertID string
	TTL     time.Duration
}

// Result is what one connector did with a block.
type Result struct {
	Connector string `json:"connector"`
	OK        bool   `json:"ok"`
	Ref       string `json:"ref,omitempty"`
	Error     string `json:"error,omitempty"`
	// Released is set once the block has been lifted on this connector.
	Released bool `json:"released,omitempty"`
}

// Block is one block action and its lifecycle.
type Block struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	State     string    `json:"state"`
	Reason    string    `json:"reason,omitempty"`
	AlertID   string    `json:"alert_id,omitempty"`
	Operator  string    `json:"operator,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Results   []Result  `json:"results"`
	// ReleasedAt and ReleasedBy record how the block ended.
	ReleasedAt *time.Time `json:"released_at,omitempty"`
	ReleasedBy string     `json:"released_by,omitempty"`
}

// Policy holds the guardrails applied to every block.
type Policy struct {
	// ProtectedNets are never blocked (office egress, monitoring, partners).
	ProtectedNets []*net.IPNet
	// AllowPrivate permits blocking private/loopback addresses. Off by
	// default: those are usually your own services.
	AllowPrivate     bool
	DefaultTTL       time.Duration
	MaxTTL           time.Duration
	MaxBlocksPerHour int
	DryRun           bool
}

// DefaultPolicy is the conservative baseline.
func DefaultPolicy() Policy {
	return Policy{DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour, MaxBlocksPerHour: 30}
}

// ConnectorStatus is a connector as shown to operators. It never carries
// credentials.
type ConnectorStatus struct {
	Name         string     `json:"name"`
	Label        string     `json:"label"`
	Status       string     `json:"status"` // unchecked | ok | error
	LastChecked  *time.Time `json:"last_checked,omitempty"`
	Error        string     `json:"error,omitempty"`
	ActiveBlocks int        `json:"active_blocks"`
	Experimental bool       `json:"experimental,omitempty"`
}

// Recorder writes audit entries for actions the manager takes on its own,
// such as lifting an expired block.
type Recorder interface {
	Record(ctx context.Context, rec storage.AuditRecord) error
}

// Manager coordinates connectors, guardrails and block lifecycle.
type Manager struct {
	policy   Policy
	adapters []Adapter
	byName   map[string]Adapter
	store    storage.DocumentStore
	rec      Recorder
	now      func() time.Time

	mu      sync.Mutex
	blocks  map[string]*Block
	issued  []time.Time
	seq     uint64
	checked map[string]*checkResult
}

type checkResult struct {
	at  time.Time
	err string
}

// NewManager builds a manager over the given connectors. store may be nil
// (blocks then live only in memory) and rec may be nil.
func NewManager(policy Policy, adapters []Adapter, store storage.DocumentStore, rec Recorder) *Manager {
	if policy.DefaultTTL <= 0 {
		policy.DefaultTTL = time.Hour
	}
	if policy.MaxTTL <= 0 {
		policy.MaxTTL = 24 * time.Hour
	}
	if policy.MaxBlocksPerHour <= 0 {
		policy.MaxBlocksPerHour = 30
	}
	m := &Manager{
		policy: policy, adapters: adapters, byName: make(map[string]Adapter),
		store: store, rec: rec, now: time.Now,
		blocks: make(map[string]*Block), checked: make(map[string]*checkResult),
	}
	for _, a := range adapters {
		m.byName[a.Name()] = a
	}
	return m
}

// Load restores persisted blocks so active ones are lifted on schedule after
// a restart.
func (m *Manager) Load(ctx context.Context) error {
	if m.store == nil {
		return nil
	}
	docs, err := m.store.LoadDocuments(ctx, DocKind)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, raw := range docs {
		var b Block
		if err := json.Unmarshal(raw, &b); err != nil {
			logger.L().Warnf("soar: skipping unreadable block %s: %v", id, err)
			continue
		}
		m.blocks[b.ID] = &b
	}
	return nil
}

// Enabled reports whether any connector is configured.
func (m *Manager) Enabled() bool { return len(m.adapters) > 0 }

// Policy returns the guardrails in force.
func (m *Manager) Policy() Policy { return m.policy }

// ValidateTarget applies the address guardrails.
func (m *Manager) ValidateTarget(ip string) (string, error) {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return "", fmt.Errorf("%w：%q 不是有效的 IP 地址", ErrBadTarget, ip)
	}
	if p.IsUnspecified() || p.IsMulticast() || p.IsLinkLocalUnicast() || p.IsLinkLocalMulticast() {
		return "", fmt.Errorf("%w：%s 是特殊用途地址", ErrBadTarget, p)
	}
	if !m.policy.AllowPrivate && (p.IsPrivate() || p.IsLoopback()) {
		return "", fmt.Errorf("%w：%s 是内网地址，默认不允许封禁（FLOWLENS_SOAR_ALLOW_PRIVATE 可放开）", ErrBadTarget, p)
	}
	for _, n := range m.policy.ProtectedNets {
		if n.Contains(p) {
			return "", fmt.Errorf("%w：%s 在受保护网段 %s 内", ErrBadTarget, p, n)
		}
	}
	return p.String(), nil
}

// BlockInput is a request to block an address.
type BlockInput struct {
	IP         string
	TTL        time.Duration // zero uses the policy default
	Reason     string
	AlertID    string
	Operator   string
	Connectors []string // empty means every configured connector
}

// Block enforces a block on the selected connectors. It succeeds when at
// least one connector accepts it; per-connector outcomes are in the result.
func (m *Manager) Block(ctx context.Context, in BlockInput) (*Block, error) {
	if !m.Enabled() {
		return nil, ErrNoConnectors
	}
	ip, err := m.ValidateTarget(in.IP)
	if err != nil {
		return nil, err
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = m.policy.DefaultTTL
	}
	if ttl < time.Minute || ttl > m.policy.MaxTTL {
		return nil, fmt.Errorf("%w：须在 1 分钟到 %s 之间", ErrBadTTL, m.policy.MaxTTL)
	}
	targets, err := m.pick(in.Connectors)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	now := m.now()
	if !m.allowLocked(now) {
		m.mu.Unlock()
		return nil, ErrRateLimited
	}
	existing := m.activeLocked(ip)
	m.mu.Unlock()

	req := Request{IP: ip, Reason: in.Reason, AlertID: in.AlertID, TTL: ttl}
	var results []Result
	for _, a := range targets {
		results = append(results, m.applyBlock(ctx, a, req))
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	b := existing
	if b == nil {
		m.seq++
		b = &Block{ID: fmt.Sprintf("blk-%d-%d", now.UnixNano(), m.seq), IP: ip, CreatedAt: now}
		m.blocks[b.ID] = b
	}
	b.Reason, b.AlertID, b.Operator = in.Reason, in.AlertID, in.Operator
	b.ExpiresAt = now.Add(ttl)
	b.Results = mergeResults(b.Results, results)
	b.State = stateOf(b.Results, m.policy.DryRun)
	if b.State == StateActive || b.State == StateDryRun {
		m.issued = append(m.issued, now)
	}
	m.persistLocked(ctx, b)
	return cloneBlock(b), nil
}

func (m *Manager) applyBlock(ctx context.Context, a Adapter, req Request) Result {
	res := Result{Connector: a.Name()}
	if m.policy.DryRun {
		res.OK = true
		res.Ref = "dry-run"
		return res
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ref, err := a.Block(cctx, req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK, res.Ref = true, ref
	return res
}

// Unblock lifts the active block on ip on every connector that holds it.
func (m *Manager) Unblock(ctx context.Context, ip, operator string) (*Block, error) {
	// Only the syntax is checked: a block made before a policy change (say,
	// a network since added to the protected list) must still be liftable.
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return nil, fmt.Errorf("%w：%q 不是有效的 IP 地址", ErrBadTarget, ip)
	}
	ip = p.String()
	m.mu.Lock()
	b := m.activeLocked(ip)
	m.mu.Unlock()
	if b == nil {
		return nil, ErrNotBlocked
	}
	return m.release(ctx, b.ID, operator)
}

func (m *Manager) release(ctx context.Context, id, by string) (*Block, error) {
	m.mu.Lock()
	b, ok := m.blocks[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotBlocked
	}
	pending := make([]Result, 0, len(b.Results))
	for _, r := range b.Results {
		if r.OK && !r.Released {
			pending = append(pending, r)
		}
	}
	ip := b.IP
	m.mu.Unlock()

	outcome := make(map[string]string) // connector -> error ("" = lifted)
	for _, r := range pending {
		a := m.byName[r.Connector]
		if a == nil {
			outcome[r.Connector] = "" // connector removed from config: nothing to lift
			continue
		}
		if m.policy.DryRun || r.Ref == "dry-run" {
			outcome[r.Connector] = ""
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := a.Unblock(cctx, ip, r.Ref)
		cancel()
		if err != nil {
			outcome[r.Connector] = err.Error()
		} else {
			outcome[r.Connector] = ""
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	failed := 0
	for i := range b.Results {
		r := &b.Results[i]
		msg, ran := outcome[r.Connector]
		if !ran {
			continue
		}
		if msg == "" {
			r.Released = true
			r.Error = ""
		} else {
			r.Error = "解封失败：" + msg
			failed++
		}
	}
	if failed == 0 {
		now := m.now()
		b.State, b.ReleasedAt, b.ReleasedBy = StateReleased, &now, by
	}
	m.persistLocked(ctx, b)
	if failed > 0 {
		return cloneBlock(b), fmt.Errorf("%d 个联动系统解封失败，将自动重试", failed)
	}
	return cloneBlock(b), nil
}

// Run lifts expired blocks until ctx ends. A block whose connector cannot be
// reached stays active and is retried on the next pass.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.ExpireDue(ctx)
		}
	}
}

// ExpireDue lifts every block past its expiry and returns how many it
// processed.
func (m *Manager) ExpireDue(ctx context.Context) int {
	m.mu.Lock()
	now := m.now()
	var due []string
	for id, b := range m.blocks {
		if (b.State == StateActive || b.State == StateDryRun) && !b.ExpiresAt.After(now) {
			due = append(due, id)
		}
	}
	m.mu.Unlock()
	sort.Strings(due)
	for _, id := range due {
		b, err := m.release(ctx, id, "system")
		ip := ""
		if b != nil {
			ip = b.IP
		}
		res, reason := audit.ResultSuccess, ""
		if err != nil {
			res, reason = audit.ResultFailure, err.Error()
			logger.L().Warnf("soar: lifting expired block %s (%s): %v", id, ip, err)
		}
		if m.rec != nil {
			_ = m.rec.Record(ctx, storage.AuditRecord{
				Console: "system", EventType: "soar.unblock", Username: "system", Target: ip,
				Result: res, Reason: reason, Detail: "封禁到期自动解除",
			})
		}
	}
	return len(due)
}

// Blocks returns blocks newest first; activeOnly limits it to those still in
// force.
func (m *Manager) Blocks(activeOnly bool, limit int) []Block {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Block, 0, len(m.blocks))
	for _, b := range m.blocks {
		if activeOnly && b.State != StateActive && b.State != StateDryRun {
			continue
		}
		out = append(out, *cloneBlock(b))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Connectors lists connectors with their last check result.
func (m *Manager) Connectors() []ConnectorStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := make(map[string]int)
	for _, b := range m.blocks {
		if b.State != StateActive {
			continue
		}
		for _, r := range b.Results {
			if r.OK && !r.Released {
				active[r.Connector]++
			}
		}
	}
	out := make([]ConnectorStatus, 0, len(m.adapters))
	for _, a := range m.adapters {
		st := ConnectorStatus{Name: a.Name(), Label: a.Label(), Status: "unchecked", ActiveBlocks: active[a.Name()]}
		if e, ok := a.(interface{ Experimental() bool }); ok && e.Experimental() {
			st.Experimental = true
		}
		if c := m.checked[a.Name()]; c != nil {
			at := c.at
			st.LastChecked = &at
			if c.err == "" {
				st.Status = "ok"
			} else {
				st.Status, st.Error = "error", c.err
			}
		}
		out = append(out, st)
	}
	return out
}

// Check tests one connector and remembers the result.
func (m *Manager) Check(ctx context.Context, name string) (ConnectorStatus, error) {
	a := m.byName[name]
	if a == nil {
		return ConnectorStatus{}, ErrUnknownConn
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := a.Check(cctx)
	m.mu.Lock()
	cr := &checkResult{at: m.now()}
	if err != nil {
		cr.err = err.Error()
	}
	m.checked[name] = cr
	m.mu.Unlock()
	for _, st := range m.Connectors() {
		if st.Name == name {
			return st, nil
		}
	}
	return ConnectorStatus{Name: name}, nil
}

// ─── internals ─────────────────────────────────────────────────

func (m *Manager) pick(names []string) ([]Adapter, error) {
	if len(names) == 0 {
		return m.adapters, nil
	}
	var out []Adapter
	seen := make(map[string]bool)
	for _, n := range names {
		a := m.byName[n]
		if a == nil {
			return nil, fmt.Errorf("%w：%s", ErrUnknownConn, n)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *Manager) allowLocked(now time.Time) bool {
	cutoff := now.Add(-time.Hour)
	keep := m.issued[:0]
	for _, t := range m.issued {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	m.issued = keep
	return len(m.issued) < m.policy.MaxBlocksPerHour
}

func (m *Manager) activeLocked(ip string) *Block {
	var found *Block
	for _, b := range m.blocks {
		if b.IP == ip && (b.State == StateActive || b.State == StateDryRun) {
			if found == nil || b.CreatedAt.After(found.CreatedAt) {
				found = b
			}
		}
	}
	return found
}

func (m *Manager) persistLocked(ctx context.Context, b *Block) {
	if m.store == nil {
		return
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return
	}
	if err := m.store.SaveDocuments(ctx, DocKind, map[string][]byte{b.ID: raw}); err != nil {
		logger.L().Errorf("soar: persisting block %s: %v", b.ID, err)
	}
}

// mergeResults keeps the newest result per connector, so re-blocking an
// address retries connectors that failed before without losing the reference
// a successful one holds.
func mergeResults(old, fresh []Result) []Result {
	byName := make(map[string]Result, len(old)+len(fresh))
	var order []string
	for _, r := range old {
		byName[r.Connector] = r
		order = append(order, r.Connector)
	}
	for _, r := range fresh {
		prev, had := byName[r.Connector]
		if had && prev.OK && !prev.Released && !r.OK {
			continue // keep the working block; the retry failed
		}
		if !had {
			order = append(order, r.Connector)
		}
		byName[r.Connector] = r
	}
	out := make([]Result, 0, len(order))
	for _, n := range order {
		out = append(out, byName[n])
	}
	return out
}

func stateOf(results []Result, dryRun bool) string {
	for _, r := range results {
		if r.OK && !r.Released {
			if dryRun {
				return StateDryRun
			}
			return StateActive
		}
	}
	return StateFailed
}

func cloneBlock(b *Block) *Block {
	c := *b
	c.Results = append([]Result(nil), b.Results...)
	return &c
}
