package iam

import (
	"sync"
	"time"
)

// ipLimiter is a fixed-window counter of login attempts per source IP.
type ipLimiter struct {
	mu      sync.Mutex
	windows map[string]*ipWindow
}

type ipWindow struct {
	start time.Time
	count int
}

func newIPLimiter() *ipLimiter {
	return &ipLimiter{windows: make(map[string]*ipWindow)}
}

// allow counts an attempt from ip at now and reports whether it is within
// limit attempts per minute.
func (l *ipLimiter) allow(ip string, limit int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.windows[ip]
	if !ok || now.Sub(w.start) >= time.Minute {
		if len(l.windows) > 50000 {
			for k, v := range l.windows {
				if now.Sub(v.start) >= time.Minute {
					delete(l.windows, k)
				}
			}
		}
		w = &ipWindow{start: now}
		l.windows[ip] = w
	}
	w.count++
	return w.count <= limit
}
