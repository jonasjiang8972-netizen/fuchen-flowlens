package service

import (
	"testing"
	"time"
)

func newTestAlertService() (*AlertService, *time.Time) {
	s := NewAlertService()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestDetectionAlertsMergeRepeats(t *testing.T) {
	s, now := newTestAlertService()
	before := len(s.List())

	first := s.CreateDetectionAlert("FR-BOLA-001", "high", "BOLA", "d1", "1.2.3.4", "acct-1", 71, 0.8)
	*now = now.Add(time.Minute)
	merged := s.CreateDetectionAlert("FR-BOLA-001", "critical", "BOLA 高危", "d2", "1.2.3.4", "acct-1", 90, 0.9)

	if merged.ID != first.ID {
		t.Fatalf("repeat created a new alert %s, want merge into %s", merged.ID, first.ID)
	}
	if got := len(s.List()); got != before+1 {
		t.Fatalf("alert count %d, want %d", got, before+1)
	}
	if merged.OccurrenceCount != 2 || merged.RiskScore != 90 || merged.Severity != "critical" ||
		merged.Title != "BOLA 高危" || merged.Description != "d2" || len(merged.AttackPath) != 2 ||
		!merged.LastSeen.Equal(*now) || !merged.Timestamp.Equal(first.Timestamp) {
		t.Fatalf("unexpected merged alert: %+v", merged)
	}

	// A lower score later must not downgrade the alert.
	*now = now.Add(time.Minute)
	merged = s.CreateDetectionAlert("FR-BOLA-001", "high", "BOLA", "d3", "1.2.3.4", "acct-1", 70, 0.5)
	if merged.RiskScore != 90 || merged.Severity != "critical" || merged.Confidence != 0.9 {
		t.Fatalf("merge downgraded alert: %+v", merged)
	}
}

func TestDetectionAlertsSeparateByKey(t *testing.T) {
	s, _ := newTestAlertService()
	a := s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "1.2.3.4", "acct-1", 80, 0.8)
	for _, b := range []Alert{
		s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "1.2.3.4", "acct-2", 80, 0.8),
		s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "5.6.7.8", "acct-1", 80, 0.8),
		s.CreateDetectionAlert("FR-AUTH-001", "high", "t", "d", "1.2.3.4", "acct-1", 80, 0.8),
	} {
		if b.ID == a.ID {
			t.Fatalf("different finding merged into %s", a.ID)
		}
	}
}

func TestDetectionAlertsReopenAfterWindow(t *testing.T) {
	s, now := newTestAlertService()
	a := s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "1.2.3.4", "acct-1", 80, 0.8)
	*now = now.Add(detectionMergeWindow + time.Second)
	b := s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "1.2.3.4", "acct-1", 80, 0.8)
	if b.ID == a.ID {
		t.Fatal("repeat after the merge window was merged")
	}
}

func TestDetectionAlertsReopenAfterDisposal(t *testing.T) {
	s, now := newTestAlertService()
	a := s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "1.2.3.4", "acct-1", 80, 0.8)
	s.alerts[a.ID].Status = "in_progress"
	*now = now.Add(time.Minute)
	b := s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "1.2.3.4", "acct-1", 80, 0.8)
	if b.ID == a.ID {
		t.Fatal("repeat merged into an alert already under disposal")
	}

	// acknowledged alerts still absorb repeats
	s.alerts[b.ID].Status = "acknowledged"
	c := s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "1.2.3.4", "acct-1", 80, 0.8)
	if c.ID != b.ID {
		t.Fatal("repeat not merged into acknowledged alert")
	}
}

func TestDetectionAlertAttackPathIsCapped(t *testing.T) {
	s, _ := newTestAlertService()
	var a Alert
	for i := 0; i < maxAttackPathSteps+20; i++ {
		a = s.CreateDetectionAlert("FR-BOLA-001", "high", "t", "d", "1.2.3.4", "acct-1", 80, 0.8)
	}
	if len(a.AttackPath) != maxAttackPathSteps || a.OccurrenceCount != maxAttackPathSteps+20 {
		t.Fatalf("path=%d occurrences=%d", len(a.AttackPath), a.OccurrenceCount)
	}
}
