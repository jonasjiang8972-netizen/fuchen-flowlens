package engine

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Params holds the effective parameter values of a detection rule, keyed by
// parameter key. Values arrive from JSON, so numbers may be float64,
// json.Number or strings; the accessors fall back to def when a value is
// missing or of the wrong type.
type Params map[string]interface{}

func (p Params) Float(key string, def float64) float64 {
	switch v := p[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f
		}
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
	}
	return def
}

func (p Params) Int(key string, def int) int {
	return int(p.Float(key, float64(def)))
}

func (p Params) Minutes(key string, def int) time.Duration {
	n := p.Int(key, def)
	if n < 1 {
		n = def
	}
	return time.Duration(n) * time.Minute
}

func (p Params) Bool(key string, def bool) bool {
	switch v := p[key].(type) {
	case bool:
		return v
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func (p Params) String(key, def string) string {
	if v, ok := p[key].(string); ok {
		return v
	}
	return def
}

// List splits a comma-separated string parameter into trimmed, non-empty
// items.
func (p Params) List(key, def string) []string {
	return splitList(p.String(key, def))
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// scaled returns base plus up to span points as ratio grows from 1 to
// 1+steps, so a detection just over its threshold scores base and one far
// over it approaches base+span.
func scaled(base, span int, ratio, steps float64) int {
	if ratio <= 1 {
		return base
	}
	extra := int((ratio - 1) / steps * float64(span))
	if extra > span {
		extra = span
	}
	return base + extra
}
