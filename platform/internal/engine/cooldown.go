package engine

import (
	"sync"
	"time"
)

// eventCooldown is how long an engine waits before storing another
// detection event for the same subject (account, IP, ...). The risk score
// is still returned for every request; only persisted events are throttled.
const eventCooldown = 10 * time.Minute

// cooldown remembers when a detection event was last stored per key.
type cooldown struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newCooldown() *cooldown {
	return &cooldown{last: make(map[string]time.Time)}
}

// allow reports whether an event for key may be stored at now, and if so
// records it. Expired keys are pruned opportunistically.
func (c *cooldown) allow(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.last[key]; ok && now.Sub(t) < eventCooldown {
		return false
	}
	if len(c.last) > 10000 {
		for k, t := range c.last {
			if now.Sub(t) >= eventCooldown {
				delete(c.last, k)
			}
		}
	}
	c.last[key] = now
	return true
}
