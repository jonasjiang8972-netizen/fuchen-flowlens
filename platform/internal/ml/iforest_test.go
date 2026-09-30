package ml

import (
	"math"
	"math/rand"
	"testing"
)

func cluster(rng *rand.Rand, n int) [][]float64 {
	d := make([][]float64, n)
	for i := range d {
		d[i] = []float64{rng.NormFloat64(), rng.NormFloat64()}
	}
	return d
}

func TestFitRejectsBadInput(t *testing.T) {
	for name, data := range map[string][][]float64{
		"empty": nil, "one row": {{1}}, "no features": {{}, {}},
		"ragged": {{1, 2}, {1}}, "nan": {{1}, {math.NaN()}}, "inf": {{1}, {math.Inf(1)}},
	} {
		if _, err := Fit(data, Options{}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestOutliersScoreHigherThanInliers(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	data := cluster(rng, 500)
	f, err := Fit(data, Options{Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	inlier := f.Score([]float64{0, 0})
	outlier := f.Score([]float64{8, 8})
	if outlier < 0.7 || inlier > 0.5 || outlier <= inlier {
		t.Errorf("inlier %.3f outlier %.3f: want inlier <0.5 and outlier >0.7", inlier, outlier)
	}
	for _, s := range []float64{inlier, outlier} {
		if s <= 0 || s >= 1 {
			t.Errorf("score %v outside (0,1)", s)
		}
	}
}

func TestSeedMakesTrainingDeterministic(t *testing.T) {
	data := cluster(rand.New(rand.NewSource(3)), 300)
	a, _ := Fit(data, Options{Seed: 42})
	b, _ := Fit(data, Options{Seed: 42})
	c, _ := Fit(data, Options{Seed: 43})
	x := []float64{2, -3}
	if a.Score(x) != b.Score(x) {
		t.Error("same seed produced different forests")
	}
	if a.Score(x) == c.Score(x) {
		t.Error("different seeds produced identical scores")
	}
}

func TestScoreHandlesEdgeCases(t *testing.T) {
	var nilForest *Forest
	if nilForest.Score([]float64{1}) != 0 {
		t.Error("nil forest should score 0")
	}
	f, _ := Fit([][]float64{{1, 1}, {1, 1}, {1, 1}}, Options{}) // constant data: nothing to split
	if s := f.Score([]float64{1, 1}); s <= 0 || s >= 1 {
		t.Errorf("constant data score %v", s)
	}
	if f.Score([]float64{1}) != 0 {
		t.Error("wrong dimension should score 0")
	}
	// With only two training rows every point is isolated at the same depth, so
	// nothing can be told apart: this is why callers require a minimum sample.
	two, err := Fit([][]float64{{1}, {2}}, Options{Trees: 5})
	if err != nil || two.Score([]float64{100}) != two.Score([]float64{1.5}) {
		t.Errorf("two-row model should not discriminate: %v", err)
	}
	small, err := Fit([][]float64{{1}, {1.1}, {1.2}, {0.9}, {1.05}, {0.95}, {1.15}, {1.0}}, Options{Trees: 50, Seed: 2})
	if err != nil || small.Score([]float64{50}) <= small.Score([]float64{1.05}) {
		t.Errorf("eight-row model should rank the outlier higher: %v", err)
	}
}

func TestThresholdQuantile(t *testing.T) {
	data := cluster(rand.New(rand.NewSource(5)), 400)
	f, _ := Fit(data, Options{Seed: 1})
	th := f.Threshold(data, 0.95)
	above := 0
	for _, r := range data {
		if f.Score(r) > th {
			above++
		}
	}
	if above > 400*5/100 {
		t.Errorf("%d points above the 95%% threshold, want at most 20", above)
	}
	if f.Threshold(nil, 0.9) != 1 {
		t.Error("empty data threshold should be 1")
	}
}

func TestAvgPathKnownValues(t *testing.T) {
	if avgPath(1) != 0 || avgPath(2) != 1 {
		t.Error("c(1) must be 0 and c(2) must be 1")
	}
	// c(256) ~ 10.24 (from the isolation forest paper's setup).
	if v := avgPath(256); math.Abs(v-10.24) > 0.05 {
		t.Errorf("c(256) = %.3f, want ~10.24", v)
	}
}
