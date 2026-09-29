package engine

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/storage"
)

// Synthetic workload. Ordinary accounts mostly re-read a handful of their own
// objects; a minority browse many; a few service accounts poll a couple of
// objects thousands of times. Attackers walk through object IDs at different
// speeds. The numbers are invented to exercise the model, not measured from
// production, so they show that the mechanism works, not what real-world
// detection rates will be.
type session struct {
	account string
	unique  int
	total   int
	span    time.Duration
}

func poisson(rng *rand.Rand, mean float64) int {
	l, k, p := expNeg(mean), 0, 1.0
	for p > l {
		k++
		p *= rng.Float64()
	}
	return k - 1
}

func expNeg(x float64) float64 {
	r := 1.0
	for x > 0 {
		step := x
		if step > 1 {
			step = 1
		}
		// exp(-step) via a short series is accurate enough for the sampler.
		t, term := 1.0, 1.0
		for i := 1; i < 12; i++ {
			term *= -step / float64(i)
			t += term
		}
		r *= t
		x -= step
	}
	return r
}

func normalSession(rng *rand.Rand, i int) session {
	s := session{account: fmt.Sprintf("user-%d", i), span: 5 * time.Minute}
	switch r := rng.Float64(); {
	case r < 0.05: // service account polling a few objects
		s.unique, s.total = 2+rng.Intn(4), 100+rng.Intn(500)
	case r < 0.20: // browsing user
		s.unique = 6 + rng.Intn(6)
		s.total = s.unique + rng.Intn(s.unique+1)
	default:
		s.unique = 1 + poisson(rng, 1.5)
		if s.unique > 8 {
			s.unique = 8
		}
		s.total = s.unique + poisson(rng, 3)
	}
	return s
}

// attackSession walks `unique` distinct objects, one after another.
func attackSession(rng *rand.Rand, i, unique int) session {
	return session{account: fmt.Sprintf("attacker-%d-%d", unique, i), unique: unique, total: unique, span: 5 * time.Minute}
}

// run replays a session and returns the highest score any request received.
func run(e *BOLAEngine, clk *fakeClock, rng *rand.Rand, s session) int {
	start := clk.Now()
	times := make([]time.Duration, s.total)
	for i := range times {
		times[i] = time.Duration(rng.Int63n(int64(s.span)))
	}
	sort.Slice(times, func(a, b int) bool { return times[a] < times[b] })
	best := 0
	for i, at := range times {
		clk.t = start.Add(at)
		obj := i % s.unique // normal accounts revisit; attackers (total==unique) never repeat
		if score, _ := e.Evaluate(s.account, fmt.Sprintf("obj-%s-%d", s.account, obj), "/api/orders/{id}", "203.0.113.5"); score > best {
			best = score
		}
	}
	clk.t = start.Add(s.span + 6*time.Minute) // let the window expire before the next account
	return best
}

func trainedEngine(t *testing.T, seed int64, useML bool) (*BOLAEngine, *fakeClock, *rand.Rand) {
	t.Helper()
	e := NewBOLAEngine(storage.NewMemStore())
	clk := newFakeClock()
	e.now = clk.Now
	e.ml.auto = false
	e.ml.seed = 99
	rng := rand.New(rand.NewSource(seed))
	// Training traffic: mostly ordinary, with a few unlabeled attackers mixed
	// in, as there would be in real traffic.
	for i := 0; i < 600; i++ {
		s := normalSession(rng, i)
		if i%40 == 0 {
			s = attackSession(rng, i, 12+rng.Intn(40))
		}
		run(e, clk, rng, s)
	}
	if useML {
		e.Retrain()
	}
	return e, clk, rng
}

type rates struct{ slow, medium, fast, falsePos float64 }

func measure(t *testing.T, seed int64, useML bool) rates {
	t.Helper()
	e, clk, rng := trainedEngine(t, seed, useML)
	const n = 100
	hit := func(unique int) float64 {
		c := 0
		for i := 0; i < n; i++ {
			if run(e, clk, rng, attackSession(rng, 1000+i, unique+rng.Intn(4))) >= 70 {
				c++
			}
		}
		return float64(c) / n
	}
	r := rates{slow: hit(12), medium: hit(22), fast: hit(60)}
	fp := 0
	const normals = 400
	for i := 0; i < normals; i++ {
		if run(e, clk, rng, normalSession(rng, 5000+i)) >= 70 {
			fp++
		}
	}
	r.falsePos = float64(fp) / normals
	return r
}

func TestBOLAAnomalyModelCatchesSlowTraversal(t *testing.T) {
	// Traffic and training are seeded, so these figures are reproducible. They
	// are measured on synthetic data (see the note at the top of this file).
	// Slow traversal (12-15 objects per 5 minutes) is under every rule
	// threshold; the model must catch a useful share of it without flagging
	// ordinary accounts, whatever sample of traffic it happened to train on.
	var slowSum float64
	const seeds = 8
	for seed := int64(1); seed <= seeds; seed++ {
		rules := measure(t, seed, false)
		full := measure(t, seed, true)
		t.Logf("seed %d: rules slow %.0f%% | rules+ML slow %.0f%% medium %.0f%% fast %.0f%% false positives %.2f%%",
			seed, rules.slow*100, full.slow*100, full.medium*100, full.fast*100, full.falsePos*100)
		if rules.slow != 0 {
			t.Errorf("seed %d: the rules alone caught slow traversal (%.0f%%); the scenario no longer tests the model", seed, rules.slow*100)
		}
		if full.medium != 1 || full.fast != 1 {
			t.Errorf("seed %d: medium/fast traversal must stay fully detected, got %.0f%%/%.0f%%", seed, full.medium*100, full.fast*100)
		}
		if full.falsePos > 0.005 {
			t.Errorf("seed %d: %.2f%% of ordinary accounts flagged, want under 0.5%%", seed, full.falsePos*100)
		}
		slowSum += full.slow
	}
	if avg := slowSum / seeds; avg < 0.3 {
		t.Errorf("model catches only %.0f%% of slow traversal on average, want at least 30%%", avg*100)
	}
}

func TestBOLAAnomalyModelIgnoresBusyServiceAccounts(t *testing.T) {
	e, clk, rng := trainedEngine(t, 3, true)
	// Thousands of requests against three objects: extreme on volume, but not
	// traversal, so it must not be reported as BOLA.
	for i := 0; i < 10; i++ {
		s := session{account: fmt.Sprintf("svc-%d", i), unique: 3, total: 1500, span: 5 * time.Minute}
		if score := run(e, clk, rng, s); score >= 70 {
			t.Fatalf("service account scored %d", score)
		}
	}
}

func TestBOLAWithoutTrainedModelBehavesLikeRules(t *testing.T) {
	e, _, clk := newBOLA()
	if st := e.MLStatus(); st.Trained || !st.Enabled || st.MinSamples != mlMinSamples {
		t.Fatalf("fresh engine status = %+v", st)
	}
	// 15 objects would interest the model, but there is none yet.
	if score, _ := traverse(e, clk, "patient", 0, 15); score != 0 {
		t.Errorf("untrained engine scored %d", score)
	}
	e.Retrain() // far too little data
	if e.MLStatus().Trained {
		t.Error("a model was trained on almost no samples")
	}
}

func TestBOLARuleHitIsAnnotatedNotInflated(t *testing.T) {
	e, clk, rng := trainedEngine(t, 4, true)
	score := run(e, clk, rng, attackSession(rng, 1, 60))
	// Compare with an engine that has no model: the score must be identical.
	plain, clk2, rng2 := trainedEngine(t, 4, false)
	if want := run(plain, clk2, rng2, attackSession(rng2, 1, 60)); score != want {
		t.Errorf("with model %d, without %d: the model must not change a rule-based score", score, want)
	}
	e.mu.Lock()
	sc, r := applyML(90, "高遍历速率", bolaFeatures{Unique: 60, Accesses: 60}, 0.9, DefaultMLThreshold)
	e.mu.Unlock()
	if sc != 90 || !strings.Contains(r, "异常检测得分 0.90") {
		t.Errorf("annotation: %d %q", sc, r)
	}
}

func TestBOLAMLScoreScalesWithAnomaly(t *testing.T) {
	f := bolaFeatures{Unique: 15, Accesses: 15}
	low, _ := applyML(0, "", f, DefaultMLThreshold, DefaultMLThreshold)
	high, reason := applyML(0, "", f, 1.0, DefaultMLThreshold)
	if low != mlBaseScore || high != mlMaxScore || !strings.Contains(reason, "机器学习") {
		t.Errorf("scores %d..%d (%q), want %d..%d", low, high, reason, mlBaseScore, mlMaxScore)
	}
	for name, ft := range map[string]bolaFeatures{
		"too few objects":    {Unique: 9, Accesses: 9},
		"mostly repeat hits": {Unique: 12, Accesses: 200},
	} {
		if sc, _ := applyML(0, "", ft, 0.99, DefaultMLThreshold); sc != 0 {
			t.Errorf("%s scored %d, want 0", name, sc)
		}
	}
	if sc, _ := applyML(0, "", f, DefaultMLThreshold-0.01, DefaultMLThreshold); sc != 0 {
		t.Errorf("below threshold scored %d", sc)
	}
}

func TestBOLAConfigureML(t *testing.T) {
	e, _, _ := trainedEngine(t, 5, true)
	for _, bad := range []float64{0.5, 0.2, 1, 1.5, -1} {
		if err := e.ConfigureML(true, bad); err == nil {
			t.Errorf("threshold %v accepted", bad)
		}
	}
	if err := e.ConfigureML(true, 0.7); err != nil || e.MLStatus().Threshold != 0.7 {
		t.Fatalf("valid threshold rejected: %v", err)
	}
	if err := e.ConfigureML(false, 0.7); err != nil {
		t.Fatal(err)
	}
	before := e.MLStatus().Samples
	clk := newFakeClock()
	e.now = clk.Now
	for i := 0; i < 50; i++ {
		e.Evaluate(fmt.Sprintf("off-%d", i), "obj-1", "/x", "1.1.1.1")
	}
	if got := e.MLStatus(); got.Enabled || got.Samples != before {
		t.Errorf("a disabled model kept sampling: %+v (before %d)", got, before)
	}
	// Disabled: even an obvious outlier gets the plain rule score.
	if score, _ := traverse(e, clk, "patient", 0, 15); score != 0 {
		t.Errorf("disabled model still scored %d", score)
	}
}

func TestBOLASampleReservoirIsBounded(t *testing.T) {
	e := NewBOLAEngine(storage.NewMemStore())
	clk := newFakeClock()
	e.now = clk.Now
	e.ml.auto = false
	for i := 0; i < mlMaxSamples+800; i++ {
		e.Evaluate(fmt.Sprintf("acct-%d", i), "obj-1", "/x", "1.1.1.1")
	}
	if got := e.MLStatus().Samples; got != mlMaxSamples {
		t.Errorf("reservoir holds %d samples, want it capped at %d", got, mlMaxSamples)
	}
}

func TestBOLASamplingIsRateLimitedPerAccount(t *testing.T) {
	e := NewBOLAEngine(storage.NewMemStore())
	clk := newFakeClock()
	e.now = clk.Now
	e.ml.auto = false
	for i := 0; i < 100; i++ { // 100 requests in 10 seconds from one account
		e.Evaluate("chatty", fmt.Sprintf("obj-%d", i), "/x", "1.1.1.1")
		clk.Advance(100 * time.Millisecond)
	}
	if got := e.MLStatus().Samples; got != 1 {
		t.Errorf("one busy account contributed %d samples in 10s, want 1", got)
	}
}

func TestBOLAAutoTrainsInBackground(t *testing.T) {
	e := NewBOLAEngine(storage.NewMemStore())
	clk := newFakeClock()
	e.now = clk.Now
	for i := 0; i < mlMinSamples+50; i++ {
		e.Evaluate(fmt.Sprintf("acct-%d", i), fmt.Sprintf("obj-%d", i%3), "/x", "1.1.1.1")
		clk.Advance(2 * time.Second)
	}
	clk.Advance(mlRetrainEvery)
	e.Evaluate("trigger", "obj-1", "/x", "1.1.1.1")
	deadline := time.Now().Add(5 * time.Second)
	for !e.MLStatus().Trained {
		if time.Now().After(deadline) {
			t.Fatalf("model never trained: %+v", e.MLStatus())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := e.MLStatus(); st.TrainedRows < mlMinSamples || st.TrainedAt.IsZero() {
		t.Errorf("status after training: %+v", st)
	}
}

func TestBOLAEvaluateAndRetrainRace(t *testing.T) {
	e, _, _ := trainedEngine(t, 6, true)
	e.now = time.Now
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				e.Evaluate(fmt.Sprintf("w%d-%d", w, i%20), fmt.Sprintf("o-%d", i), "/x", "1.1.1.1")
				if i%100 == 0 {
					e.Retrain()
					e.MLStatus()
				}
			}
		}(w)
	}
	wg.Wait()
}
