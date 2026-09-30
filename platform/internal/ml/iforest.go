// Package ml holds the small machine-learning building blocks the detection
// engines use. It has no dependencies beyond the standard library.
package ml

import (
	"errors"
	"math"
	"math/rand"
	"sort"
)

// Options configure Fit. Zero values use the defaults from the isolation
// forest paper (100 trees, 256 samples per tree).
type Options struct {
	Trees     int
	SubSample int
	Seed      int64
}

// Forest is a trained isolation forest (Liu, Ting & Zhou, 2008). Points that
// are easy to separate from the rest with random axis-aligned splits are
// anomalies: they end up close to the root of many trees.
type Forest struct {
	trees []*node
	psi   int
	norm  float64 // c(psi), the average path length of an unsuccessful search
	dim   int
}

type node struct {
	feature     int
	split       float64
	left, right *node
	size        int // leaf: training points that reached it
}

// Fit trains a forest on data, where every row has the same number of
// features. It needs at least two rows.
func Fit(data [][]float64, opt Options) (*Forest, error) {
	if len(data) < 2 {
		return nil, errors.New("ml: need at least 2 training rows")
	}
	dim := len(data[0])
	if dim == 0 {
		return nil, errors.New("ml: rows have no features")
	}
	for _, r := range data {
		if len(r) != dim {
			return nil, errors.New("ml: rows have different lengths")
		}
		for _, v := range r {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, errors.New("ml: training data contains NaN or Inf")
			}
		}
	}
	if opt.Trees <= 0 {
		opt.Trees = 100
	}
	if opt.SubSample <= 0 {
		opt.SubSample = 256
	}
	psi := opt.SubSample
	if psi > len(data) {
		psi = len(data)
	}
	rng := rand.New(rand.NewSource(opt.Seed))
	limit := int(math.Ceil(math.Log2(float64(psi))))
	f := &Forest{psi: psi, norm: avgPath(psi), dim: dim, trees: make([]*node, opt.Trees)}
	for i := range f.trees {
		idx := rng.Perm(len(data))[:psi]
		rows := make([][]float64, psi)
		for j, k := range idx {
			rows[j] = data[k]
		}
		f.trees[i] = build(rows, 0, limit, rng)
	}
	return f, nil
}

func build(rows [][]float64, depth, limit int, rng *rand.Rand) *node {
	if depth >= limit || len(rows) <= 1 {
		return &node{size: len(rows)}
	}
	// Pick a feature that still varies; give up if none does.
	dim := len(rows[0])
	for _, q := range rng.Perm(dim) {
		lo, hi := rows[0][q], rows[0][q]
		for _, r := range rows {
			lo, hi = math.Min(lo, r[q]), math.Max(hi, r[q])
		}
		if lo == hi {
			continue
		}
		p := lo + rng.Float64()*(hi-lo)
		var l, r [][]float64
		for _, row := range rows {
			if row[q] < p {
				l = append(l, row)
			} else {
				r = append(r, row)
			}
		}
		if len(l) == 0 || len(r) == 0 {
			continue // p landed on the boundary
		}
		return &node{feature: q, split: p, left: build(l, depth+1, limit, rng), right: build(r, depth+1, limit, rng)}
	}
	return &node{size: len(rows)}
}

// avgPath is c(n): the expected path length of an unsuccessful search in a
// binary search tree of n points, used to normalise depths.
func avgPath(n int) float64 {
	switch {
	case n <= 1:
		return 0
	case n == 2:
		return 1
	}
	const euler = 0.5772156649015329
	return 2*(math.Log(float64(n-1))+euler) - 2*float64(n-1)/float64(n)
}

func (n *node) path(x []float64, depth int) float64 {
	for n.left != nil {
		if x[n.feature] < n.split {
			n = n.left
		} else {
			n = n.right
		}
		depth++
	}
	return float64(depth) + avgPath(n.size)
}

// Score returns the anomaly score of x in (0, 1): near 1 is very anomalous,
// around 0.5 or below is ordinary. A point with the wrong number of features
// scores 0.
func (f *Forest) Score(x []float64) float64 {
	if f == nil || len(x) != f.dim || f.norm == 0 {
		return 0
	}
	var sum float64
	for _, t := range f.trees {
		sum += t.path(x, 0)
	}
	return math.Pow(2, -(sum/float64(len(f.trees)))/f.norm)
}

// Threshold returns the score below which the given fraction of the training
// data falls (for example 0.99 gives a cut-off that flags the top 1%).
func (f *Forest) Threshold(data [][]float64, quantile float64) float64 {
	if len(data) == 0 {
		return 1
	}
	s := make([]float64, len(data))
	for i, r := range data {
		s[i] = f.Score(r)
	}
	sort.Float64s(s)
	i := int(math.Ceil(quantile*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}
