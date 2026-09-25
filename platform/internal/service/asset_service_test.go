package service

import (
	"math"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func apiEvent(path, rawPath, srcIP string, status uint16, durationMs float64) shared.APIEvent {
	var evt shared.APIEvent
	evt.Timestamp = time.Date(2026, 1, 1, 9, 30, 0, 0, time.UTC)
	evt.Network.SrcIP = srcIP
	evt.Network.DstIP = "10.1.0.5"
	evt.Application.Method = "GET"
	evt.Application.Host = "api.example.com"
	evt.Application.PathNormalized = path
	evt.Application.PathRaw = rawPath
	evt.Application.StatusCode = status
	evt.Application.DurationMs = durationMs
	return evt
}

func TestObserveEventDiscoversAndMergesAsset(t *testing.T) {
	s := NewAssetService()
	before := len(s.List())

	a1 := s.ObserveEvent(apiEvent("/api/orders/{id}", "/api/orders/1", "10.0.0.1", 200, 10), nil)
	a2 := s.ObserveEvent(apiEvent("/api/orders/{id}", "/api/orders/2", "10.0.0.1", 200, 10), nil)

	if a1.ID != a2.ID {
		t.Fatalf("same method/host/path produced different assets: %s vs %s", a1.ID, a2.ID)
	}
	if got := len(s.List()); got != before+1 {
		t.Fatalf("asset count %d, want %d", got, before+1)
	}
	if a2.ClaimStatus != "unclaimed" || a2.GroupPath != "自动发现/订单域" || a2.RequestStats.TotalCalls24h != 2 {
		t.Fatalf("unexpected asset: claim=%s group=%s calls=%d", a2.ClaimStatus, a2.GroupPath, a2.RequestStats.TotalCalls24h)
	}
	if len(a2.PathRawSamples) != 2 {
		t.Fatalf("raw samples %v, want 2", a2.PathRawSamples)
	}
	if a2.RequestStats.HourlyCalls[9] != 2 {
		t.Fatalf("hourly bucket 9 = %d, want 2", a2.RequestStats.HourlyCalls[9])
	}
}

func TestObserveEventRawSamplesAreCapped(t *testing.T) {
	s := NewAssetService()
	var a Asset
	for i := 0; i < 10; i++ {
		a = s.ObserveEvent(apiEvent("/api/users/{id}", "/api/users/"+string(rune('a'+i)), "10.0.0.1", 200, 0), nil)
	}
	if len(a.PathRawSamples) != 5 {
		t.Fatalf("raw samples %d, want capped at 5", len(a.PathRawSamples))
	}
}

func TestObserveEventSensitivity(t *testing.T) {
	s := NewAssetService()
	a := s.ObserveEvent(apiEvent("/api/profile", "", "10.0.0.1", 200, 0), []string{"phone"})
	if a.SensitivityHint != "medium" {
		t.Fatalf("phone field hint %q, want medium", a.SensitivityHint)
	}
	a = s.ObserveEvent(apiEvent("/api/profile", "", "10.0.0.1", 200, 0), []string{"bank_card"})
	if a.SensitivityHint != "high" || len(a.SensitiveFields) != 2 {
		t.Fatalf("hint=%q fields=%v, want high with 2 fields", a.SensitivityHint, a.SensitiveFields)
	}
}

func TestObserveEventErrorRateRecovers(t *testing.T) {
	s := NewAssetService()
	a := s.ObserveEvent(apiEvent("/api/pay", "", "10.0.0.1", 500, 0), nil)
	if a.RequestStats.ErrorRate24h != 100 {
		t.Fatalf("after one error rate=%v, want 100", a.RequestStats.ErrorRate24h)
	}
	for i := 0; i < 3; i++ {
		a = s.ObserveEvent(apiEvent("/api/pay", "", "10.0.0.1", 200, 0), nil)
	}
	if a.RequestStats.ErrorRate24h != 25 {
		t.Fatalf("1 error in 4 calls rate=%v, want 25", a.RequestStats.ErrorRate24h)
	}
	if c := a.RequestStats.TopCallers[0]; c.Calls != 4 || c.ErrorRate != 25 {
		t.Fatalf("caller stats %+v, want 4 calls at 25%%", c)
	}
}

func TestObserveEventAverageLatencyIsMean(t *testing.T) {
	s := NewAssetService()
	var a Asset
	for _, d := range []float64{100, 100, 100, 400} {
		a = s.ObserveEvent(apiEvent("/api/slow", "", "10.0.0.1", 200, d), nil)
	}
	// Events without a duration must not skew the mean.
	a = s.ObserveEvent(apiEvent("/api/slow", "", "10.0.0.1", 200, 0), nil)
	if math.Abs(a.RequestStats.AvgLatencyMs-175) > 1e-9 {
		t.Fatalf("avg latency %v, want 175", a.RequestStats.AvgLatencyMs)
	}
}

func TestObserveEventSourceDistribution(t *testing.T) {
	s := NewAssetService()
	var a Asset
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.20.0.1", "8.8.8.8"} {
		a = s.ObserveEvent(apiEvent("/api/mixed", "", ip, 200, 0), nil)
	}
	if a.SourceDistribution["internal"] != "75%" || a.SourceDistribution["external"] != "25%" {
		t.Fatalf("distribution %v, want 75%% internal / 25%% external", a.SourceDistribution)
	}
}

func TestIsInternalIP(t *testing.T) {
	cases := map[string]bool{
		"10.1.2.3":    true,
		"192.168.0.1": true,
		"172.16.0.1":  true,
		"172.31.9.9":  true,
		"172.32.0.1":  false,
		"172.15.0.1":  false,
		"8.8.8.8":     false,
		"unknown":     false,
	}
	for ip, want := range cases {
		if got := isInternalIP(ip); got != want {
			t.Errorf("isInternalIP(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestClaim(t *testing.T) {
	s := NewAssetService()
	a := s.ObserveEvent(apiEvent("/api/claim-me", "", "10.0.0.1", 200, 0), nil)
	if err := s.Claim(a.ID, "team-pay"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(a.ID)
	if got.ClaimStatus != "claimed" || got.Owner != "team-pay" {
		t.Fatalf("claim not applied: %+v", got)
	}
	if err := s.Claim("missing", "x"); err == nil {
		t.Fatal("claiming a missing asset succeeded")
	}
}
