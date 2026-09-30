package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ticket states.
const (
	TicketPending       = "pending"        // waiting to be picked up
	TicketProcessing    = "processing"     // someone is working on it
	TicketReview        = "review"         // fix submitted, waiting for a second person
	TicketDone          = "done"           // reviewed and closed
	TicketFalsePositive = "false_positive" // closed as not a real problem
)

// Ticket event types.
const (
	EventCreated    = "created"
	EventAssigned   = "assigned"
	EventTransition = "transition"
	EventComment    = "comment"
	EventAlertAct   = "alert_action"
	EventRepeat     = "repeat"
)

// slaFor is how long a ticket of each severity may stay open.
var slaFor = map[string]time.Duration{
	"critical": 4 * time.Hour,
	"high":     24 * time.Hour,
	"medium":   72 * time.Hour,
	"low":      7 * 24 * time.Hour,
}

// transitions lists which states each state may move to. Work cannot skip
// review: a ticket reaches done only from review.
var transitions = map[string][]string{
	TicketPending:       {TicketProcessing, TicketFalsePositive},
	TicketProcessing:    {TicketReview, TicketFalsePositive},
	TicketReview:        {TicketDone, TicketProcessing, TicketFalsePositive},
	TicketDone:          {TicketProcessing},
	TicketFalsePositive: {TicketProcessing},
}

// Errors callers can match with errors.Is / errors.As.
var (
	ErrInvalidTransition = errors.New("状态不能这样变更")
	ErrSelfReview        = errors.New("复核人不能是提交复核的人")
)

// ValidationError is a request the caller can fix.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// TicketExistsError is returned when an alert already has an open ticket.
type TicketExistsError struct{ TicketID string }

func (e *TicketExistsError) Error() string { return "该告警已有未关闭的工单 " + e.TicketID }

// TicketEvent is one entry of a ticket's history.
type TicketEvent struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Type   string    `json:"type"`
	From   string    `json:"from,omitempty"`
	To     string    `json:"to,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Ticket is a governance work order.
type Ticket struct {
	ID          string `json:"ticket_id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Owner       string `json:"owner,omitempty"`
	Action      string `json:"action,omitempty"` // what needs to be done
	AlertID     string `json:"alert_id,omitempty"`
	// RelatedAlerts are further alerts from the same source and detection that
	// were folded into this ticket instead of opening their own.
	RelatedAlerts []string      `json:"related_alerts,omitempty"`
	RelatedCount  int           `json:"related_count,omitempty"` // all folded-in alerts, including ones past the list cap
	AssetID       string        `json:"asset_id,omitempty"`
	Auto          bool          `json:"auto_created,omitempty"`
	CreatedBy     string        `json:"created_by"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	DueAt         time.Time     `json:"due_at"`
	ClosedAt      *time.Time    `json:"closed_at,omitempty"`
	SubmittedBy   string        `json:"submitted_by,omitempty"` // who sent it to review
	Reopened      int           `json:"reopened,omitempty"`
	Group         string        `json:"group,omitempty"` // attack source + detection this ticket covers
	Timeline      []TicketEvent `json:"timeline"`
}

// TicketView is a ticket with values derived from the current time.
type TicketView struct {
	Ticket
	Open       bool `json:"open"`
	Overdue    bool `json:"overdue"`
	SLAPercent int  `json:"sla_percent"` // share of the SLA used; over 100 when overdue
}

// TicketSummary is the headline numbers for the work-order page.
type TicketSummary struct {
	Total          int            `json:"total"`
	Open           int            `json:"open"`
	Overdue        int            `json:"overdue"`
	AtRisk         int            `json:"at_risk"` // open and past 80% of the SLA
	Unassigned     int            `json:"unassigned"`
	ByStatus       map[string]int `json:"by_status"`
	Closed7d       int            `json:"closed_7d"`
	MeanHoursToFix float64        `json:"mean_hours_to_close"` // over tickets closed as done in the last 30 days
	OwnerCoverage  float64        `json:"owner_coverage"`      // share of open tickets with an owner
}

// TicketFilter narrows List. Zero values mean "any".
type TicketFilter struct {
	Status   string
	Severity string
	Owner    string
	AlertID  string
	Keyword  string
	OpenOnly bool
}

// CreateTicket is a request to open a ticket.
type CreateTicket struct {
	Title       string
	Description string
	Severity    string
	Owner       string
	Action      string
	AlertID     string
	AssetID     string
}

// TicketService keeps tickets in memory and writes them to the repository.
type TicketService struct {
	mu      sync.RWMutex
	tickets map[string]*Ticket
	byAlert map[string]string // alert id -> the ticket that covers it
	byGroup map[string]string // attack source + detection -> its most recent ticket
	seq     int
	now     func() time.Time
	p       *persister
	// onClose is told when a ticket bound to an alert changes the alert's
	// standing: done -> resolved, false_positive -> false_positive,
	// reopened -> in_progress.
	onClose func(alertID, alertStatus string)
}

func NewTicketService() *TicketService {
	return &TicketService{tickets: make(map[string]*Ticket), byAlert: make(map[string]string), byGroup: make(map[string]string), now: time.Now}
}

// NewTicketServiceFrom loads tickets from repo.
func NewTicketServiceFrom(ctx context.Context, repo Repository) (*TicketService, error) {
	s := NewTicketService()
	s.p = newPersister(repo, KindTicket)
	docs, err := repo.LoadDocuments(ctx, KindTicket)
	if err != nil {
		return nil, fmt.Errorf("load tickets: %w", err)
	}
	for id, raw := range docs {
		var t Ticket
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("decode ticket %s: %w", id, err)
		}
		s.tickets[id] = &t
		if n := ticketNumber(id); n > s.seq {
			s.seq = n
		}
		if t.AlertID != "" {
			if cur, ok := s.tickets[s.byAlert[t.AlertID]]; !ok || cur.CreatedAt.Before(t.CreatedAt) {
				s.byAlert[t.AlertID] = id
			}
		}
		for _, rel := range t.RelatedAlerts {
			if _, ok := s.byAlert[rel]; !ok {
				s.byAlert[rel] = id
			}
		}
		if t.Group != "" {
			if cur, ok := s.tickets[s.byGroup[t.Group]]; !ok || cur.CreatedAt.Before(t.CreatedAt) {
				s.byGroup[t.Group] = id
			}
		}
	}
	return s, nil
}

func ticketNumber(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "TKT-"))
	return n
}

// SetAlertSync registers the callback that keeps an alert's status in step
// with its ticket.
func (s *TicketService) SetAlertSync(fn func(alertID, alertStatus string)) { s.onClose = fn }

func (s *TicketService) snapshot(ids []string) map[string][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	docs := make(map[string][]byte, len(ids))
	for _, id := range ids {
		if t, ok := s.tickets[id]; ok {
			docs[id] = mustJSON(t)
		}
	}
	return docs
}

// Flush persists tickets created automatically since the last flush.
func (s *TicketService) Flush(ctx context.Context) (int, error) {
	return s.p.flush(ctx, s.snapshot)
}

func isOpen(status string) bool {
	return status != TicketDone && status != TicketFalsePositive
}

func (s *TicketService) view(t *Ticket, now time.Time) TicketView {
	v := TicketView{Ticket: *t, Open: isOpen(t.Status)}
	v.Timeline = append([]TicketEvent(nil), t.Timeline...)
	if v.Open {
		total := t.DueAt.Sub(t.CreatedAt)
		if total > 0 {
			v.SLAPercent = int(float64(now.Sub(t.CreatedAt)) / float64(total) * 100)
		}
		v.Overdue = now.After(t.DueAt)
	}
	return v
}

// List returns tickets newest first.
func (s *TicketService) List(f TicketFilter) []TicketView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	kw := strings.ToLower(strings.TrimSpace(f.Keyword))
	var out []TicketView
	for _, t := range s.tickets {
		switch {
		case f.Status != "" && t.Status != f.Status,
			f.Severity != "" && t.Severity != f.Severity,
			f.Owner != "" && t.Owner != f.Owner,
			f.AlertID != "" && t.AlertID != f.AlertID,
			f.OpenOnly && !isOpen(t.Status):
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(t.Title+" "+t.ID+" "+t.Owner+" "+t.AlertID), kw) {
			continue
		}
		out = append(out, s.view(t, now))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out
}

// Get returns one ticket.
func (s *TicketService) Get(id string) (*TicketView, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tickets[id]
	if !ok {
		return nil, fmt.Errorf("ticket %s: %w", id, ErrNotFound)
	}
	v := s.view(t, s.now())
	return &v, nil
}

// Summary computes the headline numbers.
func (s *TicketService) Summary() TicketSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now()
	sum := TicketSummary{Total: len(s.tickets), ByStatus: map[string]int{}}
	var owned int
	var fixHours float64
	var fixed int
	for _, t := range s.tickets {
		sum.ByStatus[t.Status]++
		if isOpen(t.Status) {
			sum.Open++
			if t.Owner == "" {
				sum.Unassigned++
			} else {
				owned++
			}
			v := s.view(t, now)
			if v.Overdue {
				sum.Overdue++
			} else if v.SLAPercent >= 80 {
				sum.AtRisk++
			}
			continue
		}
		if t.ClosedAt == nil {
			continue
		}
		if now.Sub(*t.ClosedAt) <= 7*24*time.Hour {
			sum.Closed7d++
		}
		if t.Status == TicketDone && now.Sub(*t.ClosedAt) <= 30*24*time.Hour {
			fixHours += t.ClosedAt.Sub(t.CreatedAt).Hours()
			fixed++
		}
	}
	if fixed > 0 {
		sum.MeanHoursToFix = fixHours / float64(fixed)
	}
	if sum.Open > 0 {
		sum.OwnerCoverage = float64(owned) / float64(sum.Open)
	}
	return sum
}

func validateCreate(in *CreateTicket) error {
	in.Title = strings.TrimSpace(in.Title)
	in.Owner = strings.TrimSpace(in.Owner)
	if in.Title == "" {
		return &ValidationError{"标题不能为空"}
	}
	if len([]rune(in.Title)) > 200 || len([]rune(in.Description)) > 4000 || len([]rune(in.Action)) > 1000 || len([]rune(in.Owner)) > 100 {
		return &ValidationError{"内容过长"}
	}
	if _, ok := slaFor[in.Severity]; !ok {
		return &ValidationError{"等级必须是 critical、high、medium 或 low"}
	}
	return nil
}

// Create opens a ticket. When it is tied to an alert that already has an
// open ticket, it returns *TicketExistsError instead of a duplicate.
func (s *TicketService) Create(in CreateTicket, actor string) (*TicketView, error) {
	return s.create(in, actor, false, "")
}

func (s *TicketService) create(in CreateTicket, actor string, auto bool, group string) (*TicketView, error) {
	if err := validateCreate(&in); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if in.AlertID != "" {
		if cur, ok := s.tickets[s.byAlert[in.AlertID]]; ok && isOpen(cur.Status) {
			s.mu.Unlock()
			return nil, &TicketExistsError{TicketID: cur.ID}
		}
	}
	now := s.now()
	s.seq++
	t := &Ticket{
		ID: fmt.Sprintf("TKT-%04d", s.seq), Title: in.Title, Description: in.Description, Severity: in.Severity,
		Status: TicketPending, Owner: in.Owner, Action: in.Action, AlertID: in.AlertID, AssetID: in.AssetID, Auto: auto,
		Group: group, CreatedBy: actor, CreatedAt: now, UpdatedAt: now, DueAt: now.Add(slaFor[in.Severity]),
		Timeline: []TicketEvent{{At: now, Actor: actor, Type: EventCreated, Detail: "SLA " + slaFor[in.Severity].String()}},
	}
	s.tickets[t.ID] = t
	if t.AlertID != "" {
		s.byAlert[t.AlertID] = t.ID
	}
	if group != "" {
		s.byGroup[group] = t.ID
	}
	s.mu.Unlock()

	if auto {
		s.p.markDirty(t.ID) // ingest path: persisted by the periodic flush
	} else if err := s.p.writeThrough(context.Background(), []string{t.ID}, s.snapshot); err != nil {
		s.mu.Lock()
		delete(s.tickets, t.ID)
		if s.byAlert[t.AlertID] == t.ID {
			delete(s.byAlert, t.AlertID)
		}
		if group != "" && s.byGroup[group] == t.ID {
			delete(s.byGroup, group)
		}
		s.mu.Unlock()
		return nil, fmt.Errorf("save ticket: %w", err)
	}
	return s.Get(t.ID)
}

// AlertRef describes an alert for automatic ticketing.
type AlertRef struct {
	ID          string
	Severity    string
	Title       string
	Description string
	Action      string
	Account     string
	// Group ties alerts from one attack together (detection type plus source
	// address). Empty means the alert stands alone.
	Group string
}

// maxRelatedListed bounds how many folded-in alerts a ticket lists and how
// many timeline entries they add; the rest are only counted.
const maxRelatedListed = 50

// EnsureForAlert makes sure a serious alert is covered by a ticket. It runs on
// every detection, so the repeat case is cheap.
//
// One attack raises many alerts (credential stuffing across 30 accounts is 30
// alerts), and 30 tickets would bury the queue, so alerts from the same source
// and detection share one ticket: the first opens it, the rest are attached.
// If that ticket was closed as done, a new wave opens a fresh one; if it was
// closed as a false positive, later alerts from the same source stay quiet.
// Only high and critical alerts get a ticket.
func (s *TicketService) EnsureForAlert(a AlertRef) {
	if a.ID == "" || (a.Severity != "critical" && a.Severity != "high") {
		return
	}
	s.mu.Lock()
	if _, covered := s.byAlert[a.ID]; covered {
		s.mu.Unlock()
		return
	}
	if a.Group != "" {
		if id, ok := s.byGroup[a.Group]; ok {
			t := s.tickets[id]
			switch {
			case isOpen(t.Status):
				now := s.now()
				t.RelatedCount++
				if len(t.RelatedAlerts) < maxRelatedListed {
					t.RelatedAlerts = append(t.RelatedAlerts, a.ID)
					detail := "关联告警 " + a.ID
					if a.Account != "" {
						detail += "（账号 " + a.Account + "）"
					}
					t.Timeline = append(t.Timeline, TicketEvent{At: now, Actor: "system", Type: EventRepeat, Detail: detail})
				}
				t.UpdatedAt = now
				s.byAlert[a.ID] = id
				s.mu.Unlock()
				s.p.markDirty(id)
				return
			case t.Status == TicketFalsePositive:
				s.byAlert[a.ID] = id // already judged harmless: do not raise it again
				s.mu.Unlock()
				return
			}
		}
	}
	s.mu.Unlock()
	_, _ = s.create(CreateTicket{Title: a.Title, Description: a.Description, Severity: a.Severity, Action: a.Action, AlertID: a.ID}, "system", true, a.Group)
}

// mutate applies fn to a ticket under the lock, then persists it. If saving
// fails the change is rolled back so memory never runs ahead of the database.
func (s *TicketService) mutate(id string, fn func(t *Ticket, now time.Time) error) (*TicketView, error) {
	s.mu.Lock()
	t, ok := s.tickets[id]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("ticket %s: %w", id, ErrNotFound)
	}
	before := *t
	before.Timeline = append([]TicketEvent(nil), t.Timeline...)
	now := s.now()
	if err := fn(t, now); err != nil {
		*t = before
		s.mu.Unlock()
		return nil, err
	}
	t.UpdatedAt = now
	s.mu.Unlock()

	if err := s.p.writeThrough(context.Background(), []string{id}, s.snapshot); err != nil {
		s.mu.Lock()
		*s.tickets[id] = before
		s.mu.Unlock()
		return nil, fmt.Errorf("save ticket %s: %w", id, err)
	}
	return s.Get(id)
}

// Assign sets the ticket's owner.
func (s *TicketService) Assign(id, owner, actor string) (*TicketView, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" || len([]rune(owner)) > 100 {
		return nil, &ValidationError{"负责人不能为空，且不超过 100 个字符"}
	}
	return s.mutate(id, func(t *Ticket, now time.Time) error {
		if !isOpen(t.Status) {
			return &ValidationError{"已关闭的工单不能改派，请先重新打开"}
		}
		prev := t.Owner
		t.Owner = owner
		detail := "指派给 " + owner
		if prev != "" {
			detail = "由 " + prev + " 改派给 " + owner
		}
		t.Timeline = append(t.Timeline, TicketEvent{At: now, Actor: actor, Type: EventAssigned, Detail: detail})
		return nil
	})
}

// Comment adds a note to the ticket.
func (s *TicketService) Comment(id, text, actor string) (*TicketView, error) {
	text = strings.TrimSpace(text)
	if text == "" || len([]rune(text)) > 2000 {
		return nil, &ValidationError{"备注不能为空，且不超过 2000 个字符"}
	}
	return s.mutate(id, func(t *Ticket, now time.Time) error {
		t.Timeline = append(t.Timeline, TicketEvent{At: now, Actor: actor, Type: EventComment, Detail: text})
		return nil
	})
}

// TransitionInput asks to move a ticket to another state.
type TransitionInput struct {
	To    string
	Note  string
	Owner string // optional: assign while starting work
	Actor string
	// AllowSelfReview lets the person who submitted a fix also approve it.
	// Only demo mode sets it, where there is a single simulated user.
	AllowSelfReview bool
}

// Transition moves a ticket along the workflow.
func (s *TicketService) Transition(id string, in TransitionInput) (*TicketView, error) {
	in.Note = strings.TrimSpace(in.Note)
	if len([]rune(in.Note)) > 2000 {
		return nil, &ValidationError{"说明不超过 2000 个字符"}
	}
	var alertID, alertStatus string
	v, err := s.mutate(id, func(t *Ticket, now time.Time) error {
		allowed := false
		for _, to := range transitions[t.Status] {
			if to == in.To {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("%w：%s 不能直接变为 %s", ErrInvalidTransition, t.Status, in.To)
		}
		from := t.Status
		if owner := strings.TrimSpace(in.Owner); owner != "" {
			if len([]rune(owner)) > 100 {
				return &ValidationError{"负责人不超过 100 个字符"}
			}
			t.Owner = owner
		}
		switch in.To {
		case TicketProcessing:
			if from == TicketPending && t.Owner == "" {
				return &ValidationError{"开始处理前需要指定负责人"}
			}
			if from != TicketPending && in.Note == "" { // rejected review, or reopened
				return &ValidationError{"请说明驳回或重新打开的原因"}
			}
			if from == TicketDone || from == TicketFalsePositive {
				t.Reopened++
				t.ClosedAt = nil
				t.DueAt = now.Add(slaFor[t.Severity]) // a reopened problem gets a fresh clock
				alertID, alertStatus = t.AlertID, "in_progress"
			}
			if from == TicketReview {
				t.SubmittedBy = ""
			}
		case TicketReview:
			if in.Note == "" {
				return &ValidationError{"提交复核时请填写处置说明"}
			}
			t.SubmittedBy = in.Actor
		case TicketDone:
			if !in.AllowSelfReview && in.Actor == t.SubmittedBy {
				return ErrSelfReview
			}
			t.ClosedAt = &now
			alertID, alertStatus = t.AlertID, "resolved"
		case TicketFalsePositive:
			if in.Note == "" {
				return &ValidationError{"标记误报时请说明理由"}
			}
			t.ClosedAt = &now
			alertID, alertStatus = t.AlertID, "false_positive"
		}
		t.Status = in.To
		t.Timeline = append(t.Timeline, TicketEvent{At: now, Actor: in.Actor, Type: EventTransition, From: from, To: in.To, Detail: in.Note})
		return nil
	})
	if err == nil && alertID != "" && s.onClose != nil {
		s.onClose(alertID, alertStatus)
	}
	return v, err
}

// NoteAlertAction records on the alert's open ticket that an action was taken
// (for example a block), so the ticket history shows what was done.
func (s *TicketService) NoteAlertAction(alertID, actor, detail string) {
	s.mu.RLock()
	id, ok := s.byAlert[alertID]
	open := ok && isOpen(s.tickets[id].Status)
	s.mu.RUnlock()
	if !open {
		return
	}
	_, _ = s.mutate(id, func(t *Ticket, now time.Time) error {
		t.Timeline = append(t.Timeline, TicketEvent{At: now, Actor: actor, Type: EventAlertAct, Detail: detail})
		return nil
	})
}

// ForAlert returns the alert's most recent ticket, if any.
func (s *TicketService) ForAlert(alertID string) *TicketView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tickets[s.byAlert[alertID]]
	if !ok {
		return nil
	}
	v := s.view(t, s.now())
	return &v
}
