package engine

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/platform/internal/ml"
)

// The rule thresholds in Evaluate catch fast traversal but miss a patient
// attacker who stays under them. The isolation forest learns what ordinary
// accounts look like on this platform and flags accounts that stand out from
// that population, with a guard so that only traversal-shaped outliers score:
// a service account hammering one object is unusual too, but is not BOLA.
// DefaultMLThreshold is the anomaly score at which an account is flagged.
// It was chosen on synthetic traffic (see docs/DETECTION_ENGINES.md): lower
// values catch more slow traversal but start flagging ordinary heavy browsers.
const DefaultMLThreshold = 0.62

const (
	mlMinSamples   = 200              // training rows before the model is used
	mlMaxSamples   = 4096             // reservoir size
	mlSampleEvery  = 30 * time.Second // per-account sampling interval
	mlRetrainEvery = 5 * time.Minute
	mlMinUnique    = 10  // fewest distinct objects in the window to flag
	mlMinNewRatio  = 0.7 // share of window accesses that hit a distinct object
	mlBaseScore    = 70  // risk score at the threshold (alert level)
	mlMaxScore     = 92  // risk score for the most extreme outliers
)

// bolaFeatures describes an account's last five minutes.
type bolaFeatures struct {
	Unique     int
	Accesses   int
	Cumulative int
	RatePerMin float64
}

// vector turns the features into the model input. Counts are log-scaled so a
// few very busy accounts do not dominate the splits.
func (f bolaFeatures) vector() []float64 {
	ratio := 0.0
	if f.Accesses > 0 {
		ratio = float64(f.Unique) / float64(f.Accesses)
	}
	return []float64{
		math.Log1p(float64(f.Unique)),
		math.Log1p(float64(f.Accesses)),
		ratio,
		math.Log1p(f.RatePerMin),
		math.Log1p(float64(f.Cumulative)),
	}
}

func (f bolaFeatures) newRatio() float64 {
	if f.Accesses == 0 {
		return 0
	}
	return float64(f.Unique) / float64(f.Accesses)
}

// MLStatus reports the state of the anomaly model.
type MLStatus struct {
	Enabled     bool      `json:"enabled"`
	Trained     bool      `json:"trained"`
	TrainedAt   time.Time `json:"trained_at,omitempty"`
	Samples     int       `json:"samples"`
	MinSamples  int       `json:"min_samples"`
	Threshold   float64   `json:"threshold"`
	TrainedRows int       `json:"trained_rows"`
}

// mlState is the model and its training data; guarded by BOLAEngine.mu.
type mlState struct {
	rng        *rand.Rand
	samples    [][]float64
	seen       int // rows offered to the reservoir
	lastSample map[string]time.Time
	model      *ml.Forest
	trainedAt  time.Time
	trainedOn  int
	training   bool
	lastTrain  time.Time
	auto       bool
	seed       int64
	enabled    bool
	threshold  float64
}

func newMLState() *mlState {
	seed := time.Now().UnixNano()
	return &mlState{rng: rand.New(rand.NewSource(seed)), lastSample: make(map[string]time.Time), auto: true, seed: seed, enabled: true, threshold: DefaultMLThreshold}
}

// observeLocked offers the account's current features to the training
// reservoir, at most once per mlSampleEvery per account so that busy accounts
// do not crowd out the rest. e.mu must be held.
func (e *BOLAEngine) observeLocked(account string, f bolaFeatures, now time.Time) {
	m := e.ml
	if !m.enabled || f.Unique == 0 {
		return
	}
	if last, ok := m.lastSample[account]; ok && now.Sub(last) < mlSampleEvery {
		return
	}
	if len(m.lastSample) > 50000 {
		for k, t := range m.lastSample {
			if now.Sub(t) > time.Hour {
				delete(m.lastSample, k)
			}
		}
	}
	m.lastSample[account] = now
	m.seen++
	v := f.vector()
	if len(m.samples) < mlMaxSamples {
		m.samples = append(m.samples, v)
	} else if j := m.rng.Intn(m.seen); j < mlMaxSamples { // reservoir sampling
		m.samples[j] = v
	}
	if m.auto && !m.training && len(m.samples) >= mlMinSamples && now.Sub(m.lastTrain) >= mlRetrainEvery {
		m.training, m.lastTrain = true, now
		go e.Retrain()
	}
}

// Retrain fits a new model on the samples collected so far. It runs in the
// background as traffic accumulates and can be called directly.
func (e *BOLAEngine) Retrain() {
	e.mu.Lock()
	rows := make([][]float64, len(e.ml.samples))
	copy(rows, e.ml.samples)
	seed := e.ml.seed
	e.ml.seed++
	e.mu.Unlock()

	var model *ml.Forest
	if len(rows) >= mlMinSamples {
		var err error
		if model, err = ml.Fit(rows, ml.Options{Seed: seed}); err != nil {
			logger.L().Errorf("BOLA anomaly model: training failed: %v", err)
			model = nil
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.ml.training = false
	if model != nil {
		e.ml.model, e.ml.trainedAt, e.ml.trainedOn = model, e.now(), len(rows)
	}
}

// MLStatus reports whether the anomaly model is trained and on how much data.
func (e *BOLAEngine) MLStatus() MLStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return MLStatus{
		Enabled: e.ml.enabled, Trained: e.ml.model != nil, TrainedAt: e.ml.trainedAt, Samples: len(e.ml.samples),
		MinSamples: mlMinSamples, Threshold: e.ml.threshold, TrainedRows: e.ml.trainedOn,
	}
}

// anomalyLocked returns the account's anomaly score, or false when no model
// is trained yet. e.mu must be held.
func (e *BOLAEngine) anomalyLocked(f bolaFeatures) (float64, bool) {
	if !e.ml.enabled || e.ml.model == nil {
		return 0, false
	}
	return e.ml.model.Score(f.vector()), true
}

// applyML combines the rule result with the model's opinion. Rules keep
// their score; the model can add an alert for traversal the rules miss, or
// annotate one they caught.
func applyML(score int, reason string, f bolaFeatures, anomaly, threshold float64) (int, string) {
	flag := anomaly >= threshold && f.Unique >= mlMinUnique && f.newRatio() >= mlMinNewRatio
	if !flag {
		return score, reason
	}
	if score >= 70 {
		return score, fmt.Sprintf("%s（异常检测得分 %.2f）", reason, anomaly)
	}
	span := (anomaly - threshold) / (1 - threshold)
	score = mlBaseScore + int(math.Min(1, math.Max(0, span))*float64(mlMaxScore-mlBaseScore))
	return score, fmt.Sprintf("异常遍历（机器学习）: 5分钟内访问 %d 个唯一对象，其中 %.0f%% 为首次访问，行为偏离其他账号（异常检测得分 %.2f）",
		f.Unique, f.newRatio()*100, anomaly)
}

// ConfigureML turns the anomaly model on or off and sets the flagging
// threshold. A threshold outside (0.5, 1) is rejected: at or below 0.5 the
// model flags ordinary accounts, and at 1 it never flags anything.
func (e *BOLAEngine) ConfigureML(enabled bool, threshold float64) error {
	if threshold <= 0.5 || threshold >= 1 {
		return fmt.Errorf("阈值必须在 0.5 到 1 之间（不含），当前为 %v", threshold)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ml.enabled, e.ml.threshold = enabled, threshold
	return nil
}
