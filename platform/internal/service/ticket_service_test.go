package service

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTickets() (*TicketService, *time.Time) {
	s := NewTicketService()
	clock := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }
	return s, &clock
}

func mustCreate(t *testing.T, s *TicketService, in CreateTicket) *TicketView {
	t.Helper()
	v, err := s.Create(in, "alice")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func step(t *testing.T, s *TicketService, id string, in TransitionInput) *TicketView {
	t.Helper()
	v, err := s.Transition(id, in)
	if err != nil {
		t.Fatalf("transition %s -> %s: %v", id, in.To, err)
	}
	return v
}

func TestTicketValidation(t *testing.T) {
	s, _ := newTickets()
	long := strings.Repeat("x", 201)
	for name, in := range map[string]CreateTicket{
		"no title":     {Severity: "high"},
		"blank title":  {Title: "   ", Severity: "high"},
		"long title":   {Title: long, Severity: "high"},
		"bad severity": {Title: "t", Severity: "urgent"},
		"no severity":  {Title: "t"},
	} {
		_, err := s.Create(in, "alice")
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
	}
	if len(s.List(TicketFilter{})) != 0 {
		t.Error("rejected requests created tickets")
	}
}

func TestTicketFullLifecycleAndSLA(t *testing.T) {
	s, clock := newTickets()
	tk := mustCreate(t, s, CreateTicket{Title: "BOLA 调查", Severity: "critical", AlertID: "alt-1", Action: "限流"})
	if tk.ID != "TKT-0001" || tk.Status != TicketPending || !tk.DueAt.Equal(clock.Add(4*time.Hour)) || !tk.Open {
		t.Fatalf("new ticket = %+v", tk)
	}

	// Starting work needs an owner.
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketProcessing, Actor: "bob"}); err == nil {
		t.Fatal("started without an owner")
	}
	step(t, s, tk.ID, TransitionInput{To: TicketProcessing, Owner: "订单团队", Actor: "bob"})

	// Review needs a note; done cannot be reached from processing.
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketReview, Actor: "bob"}); err == nil {
		t.Error("review without a note accepted")
	}
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketDone, Actor: "carol"}); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("processing -> done: %v, want ErrInvalidTransition", err)
	}
	*clock = clock.Add(3 * time.Hour)
	v := step(t, s, tk.ID, TransitionInput{To: TicketReview, Note: "已补对象级鉴权", Actor: "bob"})
	if v.SubmittedBy != "bob" || v.SLAPercent != 75 || v.Overdue {
		t.Errorf("in review: %+v", v)
	}

	// The person who submitted the fix cannot approve it.
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketDone, Actor: "bob"}); !errors.Is(err, ErrSelfReview) {
		t.Errorf("self review: %v, want ErrSelfReview", err)
	}
	*clock = clock.Add(30 * time.Minute)
	v = step(t, s, tk.ID, TransitionInput{To: TicketDone, Note: "验证通过", Actor: "carol"})
	if v.Status != TicketDone || v.ClosedAt == nil || v.Open || v.Overdue {
		t.Errorf("done: %+v", v)
	}
	if n := len(v.Timeline); n != 4 { // created, processing, review, done
		t.Errorf("timeline has %d events: %+v", n, v.Timeline)
	}
	last := v.Timeline[len(v.Timeline)-1]
	if last.From != TicketReview || last.To != TicketDone || last.Actor != "carol" || last.Detail != "验证通过" {
		t.Errorf("last event = %+v", last)
	}
}

func TestTicketRejectedReviewAndReopen(t *testing.T) {
	s, clock := newTickets()
	tk := mustCreate(t, s, CreateTicket{Title: "t", Severity: "high", Owner: "team"})
	step(t, s, tk.ID, TransitionInput{To: TicketProcessing, Actor: "bob"})
	step(t, s, tk.ID, TransitionInput{To: TicketReview, Note: "fixed", Actor: "bob"})

	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketProcessing, Actor: "carol"}); err == nil {
		t.Error("rejecting a review without a reason accepted")
	}
	v := step(t, s, tk.ID, TransitionInput{To: TicketProcessing, Note: "回归测试没过", Actor: "carol"})
	if v.SubmittedBy != "" {
		t.Error("rejection should clear the submitter so the next reviewer is not blocked")
	}
	step(t, s, tk.ID, TransitionInput{To: TicketReview, Note: "重新修复", Actor: "dave"})
	step(t, s, tk.ID, TransitionInput{To: TicketDone, Actor: "bob"}) // bob may review dave's fix

	// Reopening restarts the SLA clock.
	*clock = clock.Add(48 * time.Hour)
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketProcessing, Actor: "carol"}); err == nil {
		t.Error("reopened without a reason")
	}
	v = step(t, s, tk.ID, TransitionInput{To: TicketProcessing, Note: "问题复现", Actor: "carol"})
	if v.Reopened != 1 || v.ClosedAt != nil || !v.Open || !v.DueAt.Equal(clock.Add(24*time.Hour)) || v.Overdue {
		t.Errorf("reopened: %+v", v)
	}
}

func TestTicketFalsePositive(t *testing.T) {
	s, _ := newTickets()
	tk := mustCreate(t, s, CreateTicket{Title: "t", Severity: "medium"})
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketFalsePositive, Actor: "bob"}); err == nil {
		t.Error("false positive without a reason accepted")
	}
	v := step(t, s, tk.ID, TransitionInput{To: TicketFalsePositive, Note: "内部压测流量", Actor: "bob"})
	if v.Open || v.ClosedAt == nil {
		t.Errorf("%+v", v)
	}
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketReview, Note: "x", Actor: "bob"}); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("closed ticket -> review: %v", err)
	}
}

func TestTicketSelfReviewOnlyWhenAllowed(t *testing.T) {
	s, _ := newTickets()
	tk := mustCreate(t, s, CreateTicket{Title: "t", Severity: "low", Owner: "me"})
	step(t, s, tk.ID, TransitionInput{To: TicketProcessing, Actor: "demo"})
	step(t, s, tk.ID, TransitionInput{To: TicketReview, Note: "n", Actor: "demo"})
	step(t, s, tk.ID, TransitionInput{To: TicketDone, Actor: "demo", AllowSelfReview: true})
}

func TestTicketOverdueAndSummary(t *testing.T) {
	s, clock := newTickets()
	crit := mustCreate(t, s, CreateTicket{Title: "c", Severity: "critical"}) // 4h
	mustCreate(t, s, CreateTicket{Title: "h", Severity: "high", Owner: "team"})
	low := mustCreate(t, s, CreateTicket{Title: "l", Severity: "low", Owner: "team"})
	step(t, s, low.ID, TransitionInput{To: TicketProcessing, Actor: "bob"})
	step(t, s, low.ID, TransitionInput{To: TicketReview, Note: "n", Actor: "bob"})
	*clock = clock.Add(10 * time.Hour)
	step(t, s, low.ID, TransitionInput{To: TicketDone, Actor: "carol"})

	sum := s.Summary()
	if sum.Total != 3 || sum.Open != 2 || sum.Overdue != 1 || sum.Unassigned != 1 || sum.Closed7d != 1 {
		t.Errorf("summary = %+v", sum)
	}
	if sum.OwnerCoverage != 0.5 {
		t.Errorf("owner coverage = %v, want 0.5", sum.OwnerCoverage)
	}
	if sum.MeanHoursToFix != 10 {
		t.Errorf("mean hours to close = %v, want 10", sum.MeanHoursToFix)
	}
	v, _ := s.Get(crit.ID)
	if !v.Overdue || v.SLAPercent <= 100 {
		t.Errorf("critical after 10h: %+v", v)
	}
	// 20h into a 24h SLA is at risk but not overdue.
	*clock = clock.Add(10 * time.Hour)
	if sum := s.Summary(); sum.AtRisk != 1 {
		t.Errorf("at risk = %d, want 1: %+v", sum.AtRisk, sum)
	}
}

func TestTicketAutoCreationForAlerts(t *testing.T) {
	s, _ := newTickets()
	s.EnsureForAlert(AlertRef{ID: "alt-1", Severity: "critical", Title: "撞库", Description: "d", Action: "封禁"})
	s.EnsureForAlert(AlertRef{ID: "alt-1", Severity: "critical", Title: "撞库", Description: "d", Action: "封禁"}) // a repeat of the same alert
	s.EnsureForAlert(AlertRef{ID: "alt-2", Severity: "medium", Title: "低", Description: "d", Action: ""})
	s.EnsureForAlert(AlertRef{ID: "alt-3", Severity: "low", Title: "更低", Description: "d", Action: ""})
	s.EnsureForAlert(AlertRef{ID: "", Severity: "high", Title: "无告警", Description: "d", Action: ""})
	list := s.List(TicketFilter{})
	if len(list) != 1 || list[0].AlertID != "alt-1" || !list[0].Auto || list[0].CreatedBy != "system" {
		t.Fatalf("auto-created tickets = %+v", list)
	}
	// Once the ticket is closed a repeat of the same alert does not reopen it.
	step(t, s, list[0].ID, TransitionInput{To: TicketFalsePositive, Note: "测试", Actor: "bob"})
	s.EnsureForAlert(AlertRef{ID: "alt-1", Severity: "critical", Title: "撞库", Description: "d", Action: "封禁"})
	if n := len(s.List(TicketFilter{})); n != 1 {
		t.Errorf("a closed alert's ticket was recreated: %d tickets", n)
	}
}

func TestTicketCreateForAlertWithOpenTicket(t *testing.T) {
	s, _ := newTickets()
	first := mustCreate(t, s, CreateTicket{Title: "a", Severity: "high", AlertID: "alt-1"})
	_, err := s.Create(CreateTicket{Title: "again", Severity: "high", AlertID: "alt-1"}, "bob")
	var ex *TicketExistsError
	if !errors.As(err, &ex) || ex.TicketID != first.ID {
		t.Fatalf("want TicketExistsError for %s, got %v", first.ID, err)
	}
	step(t, s, first.ID, TransitionInput{To: TicketFalsePositive, Note: "n", Actor: "bob"})
	if _, err := s.Create(CreateTicket{Title: "new one", Severity: "high", AlertID: "alt-1"}, "bob"); err != nil {
		t.Errorf("a new ticket after the old one closed: %v", err)
	}
	if got := s.ForAlert("alt-1"); got == nil || got.Title != "new one" {
		t.Errorf("ForAlert should return the newest ticket: %+v", got)
	}
	if s.ForAlert("nope") != nil {
		t.Error("unknown alert has a ticket")
	}
}

func TestTicketAlertSync(t *testing.T) {
	s, _ := newTickets()
	var mu sync.Mutex
	var calls []string
	s.SetAlertSync(func(id, st string) { mu.Lock(); calls = append(calls, id+":"+st); mu.Unlock() })
	tk := mustCreate(t, s, CreateTicket{Title: "t", Severity: "high", AlertID: "alt-9", Owner: "o"})
	step(t, s, tk.ID, TransitionInput{To: TicketProcessing, Actor: "a"})
	step(t, s, tk.ID, TransitionInput{To: TicketReview, Note: "n", Actor: "a"})
	step(t, s, tk.ID, TransitionInput{To: TicketDone, Actor: "b"})
	step(t, s, tk.ID, TransitionInput{To: TicketProcessing, Note: "again", Actor: "b"})
	step(t, s, tk.ID, TransitionInput{To: TicketFalsePositive, Note: "fp", Actor: "b"})
	want := "alt-9:resolved,alt-9:in_progress,alt-9:false_positive"
	if got := strings.Join(calls, ","); got != want {
		t.Errorf("alert sync calls = %s, want %s", got, want)
	}
	// A failed transition must not touch the alert.
	calls = nil
	s.Transition(tk.ID, TransitionInput{To: TicketDone, Actor: "b"})
	if len(calls) != 0 {
		t.Errorf("rejected transition notified the alert: %v", calls)
	}
}

func TestTicketAssignCommentAndAlertAction(t *testing.T) {
	s, _ := newTickets()
	tk := mustCreate(t, s, CreateTicket{Title: "t", Severity: "high", AlertID: "alt-1"})
	v, err := s.Assign(tk.ID, "  安全运营 ", "alice")
	if err != nil || v.Owner != "安全运营" {
		t.Fatalf("assign: %+v %v", v, err)
	}
	v, _ = s.Assign(tk.ID, "订单团队", "alice")
	if last := v.Timeline[len(v.Timeline)-1]; !strings.Contains(last.Detail, "由 安全运营 改派给 订单团队") {
		t.Errorf("reassignment event = %+v", last)
	}
	if _, err := s.Assign(tk.ID, " ", "alice"); err == nil {
		t.Error("blank owner accepted")
	}
	if _, err := s.Comment(tk.ID, "", "alice"); err == nil {
		t.Error("blank comment accepted")
	}
	if _, err := s.Comment(tk.ID, "已联系业务方", "alice"); err != nil {
		t.Fatal(err)
	}
	s.NoteAlertAction("alt-1", "bob", "已封禁 198.51.100.9")
	s.NoteAlertAction("unknown", "bob", "ignored")
	v, _ = s.Get(tk.ID)
	if last := v.Timeline[len(v.Timeline)-1]; last.Type != EventAlertAct || !strings.Contains(last.Detail, "198.51.100.9") {
		t.Errorf("alert action not recorded: %+v", last)
	}
	step(t, s, tk.ID, TransitionInput{To: TicketFalsePositive, Note: "n", Actor: "bob"})
	if _, err := s.Assign(tk.ID, "someone", "alice"); err == nil {
		t.Error("reassigning a closed ticket accepted")
	}
	if _, err := s.Get("TKT-9999"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown ticket: %v", err)
	}
	if _, err := s.Comment("TKT-9999", "x", "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("comment on unknown ticket: %v", err)
	}
}

func TestTicketListFilters(t *testing.T) {
	s, clock := newTickets()
	a := mustCreate(t, s, CreateTicket{Title: "订单遍历", Severity: "high", Owner: "订单团队", AlertID: "alt-1"})
	*clock = clock.Add(time.Minute)
	mustCreate(t, s, CreateTicket{Title: "撞库", Severity: "critical", Owner: "安全运营"})
	step(t, s, a.ID, TransitionInput{To: TicketFalsePositive, Note: "n", Actor: "x"})

	count := func(f TicketFilter) int { return len(s.List(f)) }
	if count(TicketFilter{}) != 2 || count(TicketFilter{OpenOnly: true}) != 1 || count(TicketFilter{Status: TicketFalsePositive}) != 1 ||
		count(TicketFilter{Severity: "critical"}) != 1 || count(TicketFilter{Owner: "订单团队"}) != 1 || count(TicketFilter{AlertID: "alt-1"}) != 1 ||
		count(TicketFilter{Keyword: "撞"}) != 1 || count(TicketFilter{Keyword: "tkt-0001"}) != 1 || count(TicketFilter{Keyword: "nothing"}) != 0 {
		t.Errorf("filters returned unexpected counts")
	}
	if all := s.List(TicketFilter{}); all[0].Title != "撞库" {
		t.Errorf("newest first expected, got %s", all[0].Title)
	}
}

func TestTicketsPersistAndSurviveReload(t *testing.T) {
	repo := newMemRepo()
	s, err := NewTicketServiceFrom(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	tk, _ := s.Create(CreateTicket{Title: "持久化", Severity: "high", AlertID: "alt-1", Owner: "o"}, "alice")
	s.Transition(tk.ID, TransitionInput{To: TicketProcessing, Actor: "alice"})
	s.EnsureForAlert(AlertRef{ID: "alt-2", Severity: "critical", Title: "auto", Description: "d", Action: ""})
	if repo.count(KindTicket) != 1 {
		t.Fatalf("user-created ticket must be written immediately, repo has %d", repo.count(KindTicket))
	}
	if n, err := s.Flush(ctx); err != nil || n != 1 || repo.count(KindTicket) != 2 {
		t.Fatalf("flush persisted %d (%v), repo has %d", n, err, repo.count(KindTicket))
	}

	again, err := NewTicketServiceFrom(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.Get(tk.ID)
	if err != nil || got.Status != TicketProcessing || len(got.Timeline) != 2 {
		t.Fatalf("reloaded ticket = %+v %v", got, err)
	}
	// Numbering continues, and the alert index is rebuilt.
	next, _ := again.Create(CreateTicket{Title: "next", Severity: "low"}, "alice")
	if next.ID != "TKT-0003" {
		t.Errorf("next id = %s, want TKT-0003", next.ID)
	}
	if _, err := again.Create(CreateTicket{Title: "dup", Severity: "high", AlertID: "alt-1"}, "alice"); err == nil {
		t.Error("duplicate open ticket for alt-1 accepted after reload")
	}
}

func TestTicketWriteFailureRollsBack(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewTicketServiceFrom(ctx, repo)
	tk, _ := s.Create(CreateTicket{Title: "t", Severity: "high", Owner: "o"}, "alice")

	repo.setFail(true)
	if _, err := s.Create(CreateTicket{Title: "lost", Severity: "high", AlertID: "alt-1"}, "alice"); err == nil {
		t.Error("create succeeded while the database was down")
	}
	if len(s.List(TicketFilter{})) != 1 || s.ForAlert("alt-1") != nil {
		t.Error("failed create left a ticket behind")
	}
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketProcessing, Actor: "alice"}); err == nil {
		t.Error("transition succeeded while the database was down")
	}
	if v, _ := s.Get(tk.ID); v.Status != TicketPending || len(v.Timeline) != 1 {
		t.Errorf("failed transition was not rolled back: %+v", v)
	}
	repo.setFail(false)
	if _, err := s.Transition(tk.ID, TransitionInput{To: TicketProcessing, Actor: "alice"}); err != nil {
		t.Errorf("after recovery: %v", err)
	}
}

func TestTicketConcurrentUse(t *testing.T) {
	s := NewTicketService()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				v, err := s.Create(CreateTicket{Title: "t", Severity: "low", Owner: "o"}, "u")
				if err != nil {
					t.Error(err)
					return
				}
				s.Transition(v.ID, TransitionInput{To: TicketProcessing, Actor: "u"})
				s.Comment(v.ID, "c", "u")
				s.List(TicketFilter{})
				s.Summary()
			}
		}(w)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, v := range s.List(TicketFilter{}) {
		if seen[v.ID] {
			t.Fatalf("duplicate id %s", v.ID)
		}
		seen[v.ID] = true
	}
	if len(seen) != 400 {
		t.Errorf("%d tickets, want 400", len(seen))
	}
}

func TestAlertSetStatus(t *testing.T) {
	s := NewAlertService()
	a := s.CreateDetectionAlert("FR-DET-002", "high", "t", "d", "198.51.100.1", "acct", 90, 0.9)
	if err := s.SetStatus(a.ID, "resolved"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(a.ID); got.Status != "resolved" {
		t.Errorf("status = %s", got.Status)
	}
	if err := s.SetStatus(a.ID, "bogus"); err == nil {
		t.Error("invalid status accepted")
	}
	if err := s.SetStatus("missing", "open"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown alert: %v", err)
	}
}

func TestTicketsGroupAlertsFromOneSource(t *testing.T) {
	s, _ := newTickets()
	ref := func(id, account, group string) AlertRef {
		return AlertRef{ID: id, Severity: "critical", Title: "撞库", Description: "d", Account: account, Group: group}
	}
	// Credential stuffing from one address across many accounts: 30 alerts.
	for i := 0; i < 30; i++ {
		s.EnsureForAlert(ref("alt-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "acct-"+string(rune('a'+i%26)), "FR-DET-002|198.51.100.7"))
	}
	list := s.List(TicketFilter{})
	if len(list) != 1 {
		t.Fatalf("30 alerts from one source opened %d tickets, want 1", len(list))
	}
	tk := list[0]
	if tk.RelatedCount != 29 || len(tk.RelatedAlerts) != 29 || tk.AlertID != "alt-aa" {
		t.Errorf("ticket = alert %s, related %d/%d", tk.AlertID, len(tk.RelatedAlerts), tk.RelatedCount)
	}
	last := tk.Timeline[len(tk.Timeline)-1]
	if last.Type != EventRepeat || !strings.Contains(last.Detail, "关联告警") {
		t.Errorf("last event = %+v", last)
	}
	// A different detection, or a different source, is a different problem.
	s.EnsureForAlert(ref("alt-x1", "", "FR-DET-001|198.51.100.7"))
	s.EnsureForAlert(ref("alt-x2", "", "FR-DET-002|203.0.113.9"))
	s.EnsureForAlert(ref("alt-x3", "", "")) // no source: stands alone
	s.EnsureForAlert(ref("alt-x4", "", ""))
	if n := len(s.List(TicketFilter{})); n != 5 {
		t.Errorf("%d tickets, want 5 (one per source+detection, plus two standalone)", n)
	}
	// Each folded-in alert resolves to the shared ticket.
	if got := s.ForAlert("alt-ab"); got == nil || got.ID != tk.ID {
		t.Errorf("ForAlert(alt-ab) = %+v", got)
	}
	// Repeating an alert already covered changes nothing.
	before, _ := s.Get(tk.ID)
	s.EnsureForAlert(ref("alt-ab", "acct-b", "FR-DET-002|198.51.100.7"))
	if after, _ := s.Get(tk.ID); after.RelatedCount != before.RelatedCount {
		t.Errorf("a repeat alert was counted twice: %d -> %d", before.RelatedCount, after.RelatedCount)
	}
}

func TestTicketGroupingAfterClosure(t *testing.T) {
	s, _ := newTickets()
	ref := func(id string) AlertRef {
		return AlertRef{ID: id, Severity: "high", Title: "t", Description: "d", Group: "FR-DET-002|198.51.100.7"}
	}
	s.EnsureForAlert(ref("alt-1"))
	tk := s.List(TicketFilter{})[0]
	step(t, s, tk.ID, TransitionInput{To: TicketProcessing, Owner: "o", Actor: "a"})
	step(t, s, tk.ID, TransitionInput{To: TicketReview, Note: "n", Actor: "a"})
	step(t, s, tk.ID, TransitionInput{To: TicketDone, Actor: "b"})

	// A later wave from the same source after a real fix is a new problem.
	s.EnsureForAlert(ref("alt-2"))
	if n := len(s.List(TicketFilter{})); n != 2 {
		t.Fatalf("after a done ticket, a new wave opened %d tickets in total, want 2", n)
	}
	second := s.ForAlert("alt-2")
	// Judged harmless: later alerts from that source do not raise it again.
	step(t, s, second.ID, TransitionInput{To: TicketFalsePositive, Note: "合作方扫描", Actor: "a"})
	s.EnsureForAlert(ref("alt-3"))
	s.EnsureForAlert(ref("alt-4"))
	if n := len(s.List(TicketFilter{})); n != 2 {
		t.Errorf("alerts from a source marked false positive opened tickets: %d total", n)
	}
}

func TestTicketRelatedAlertsAreBounded(t *testing.T) {
	s, _ := newTickets()
	for i := 0; i < maxRelatedListed+40; i++ {
		s.EnsureForAlert(AlertRef{ID: "alt-" + string(rune(0x4e00+i)), Severity: "high", Title: "t", Group: "g"})
	}
	tk := s.List(TicketFilter{})[0]
	if len(tk.RelatedAlerts) != maxRelatedListed || tk.RelatedCount != maxRelatedListed+39 {
		t.Errorf("listed %d, counted %d", len(tk.RelatedAlerts), tk.RelatedCount)
	}
	if len(tk.Timeline) != 1+maxRelatedListed {
		t.Errorf("timeline grew to %d entries; folded-in alerts must not grow it without bound", len(tk.Timeline))
	}
}

func TestTicketGroupSurvivesReload(t *testing.T) {
	repo := newMemRepo()
	s, _ := NewTicketServiceFrom(ctx, repo)
	s.EnsureForAlert(AlertRef{ID: "alt-1", Severity: "high", Title: "t", Group: "g"})
	s.EnsureForAlert(AlertRef{ID: "alt-2", Severity: "high", Title: "t", Group: "g"})
	if _, err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	again, _ := NewTicketServiceFrom(ctx, repo)
	again.EnsureForAlert(AlertRef{ID: "alt-3", Severity: "high", Title: "t", Group: "g"})
	again.EnsureForAlert(AlertRef{ID: "alt-2", Severity: "high", Title: "t", Group: "g"})
	list := again.List(TicketFilter{})
	if len(list) != 1 || list[0].RelatedCount != 2 {
		t.Errorf("after reload: %d tickets, related %d; the group index was not rebuilt", len(list), list[0].RelatedCount)
	}
}
