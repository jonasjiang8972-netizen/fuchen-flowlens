package ingest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

type Handler func(context.Context, shared.APIEvent)

type Pipeline struct {
	queue   chan shared.APIEvent
	handler Handler

	mu         sync.RWMutex
	seen       map[string]time.Time
	accepted   uint64
	dropped    uint64
	duplicates uint64
	processed  uint64
	lastEventAt time.Time
}

type SubmitResult struct {
	Accepted   int `json:"accepted"`
	Dropped    int `json:"dropped"`
	Duplicates int `json:"duplicates"`
	QueueDepth int `json:"queue_depth"`
}

type Metrics struct {
	Accepted   uint64    `json:"accepted"`
	Dropped    uint64    `json:"dropped"`
	Duplicates uint64    `json:"duplicates"`
	Processed  uint64    `json:"processed"`
	QueueDepth int       `json:"queue_depth"`
	QueueSize  int       `json:"queue_size"`
	LastEventAt time.Time `json:"last_event_at"`
}

func NewPipeline(queueSize int, handler Handler) *Pipeline {
	if queueSize <= 0 {
		queueSize = 10000
	}
	return &Pipeline{
		queue:   make(chan shared.APIEvent, queueSize),
		handler: handler,
		seen:    make(map[string]time.Time),
	}
}

func (p *Pipeline) Start(ctx context.Context, workers int) {
	if workers <= 0 {
		workers = 4
	}
	for i := 0; i < workers; i++ {
		go p.worker(ctx)
	}
	go p.cleanupSeen(ctx)
}

func (p *Pipeline) Submit(ctx context.Context, events []shared.APIEvent) SubmitResult {
	result := SubmitResult{}
	for i := range events {
		evt := events[i]
		if evt.EventID == "" {
			evt.EventID = fmt.Sprintf("evt-%d-%d", time.Now().UnixNano(), i)
		}
		if evt.Timestamp.IsZero() {
			evt.Timestamp = time.Now()
		}

		if p.isDuplicate(evt.EventID) {
			result.Duplicates++
			continue
		}

		select {
		case <-ctx.Done():
			result.Dropped++
		case p.queue <- evt:
			result.Accepted++
			p.mu.Lock()
			p.accepted++
			p.lastEventAt = time.Now()
			p.mu.Unlock()
		default:
			result.Dropped++
			p.mu.Lock()
			p.dropped++
			p.mu.Unlock()
		}
	}
	result.QueueDepth = len(p.queue)
	return result
}

func (p *Pipeline) Metrics() Metrics {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Metrics{
		Accepted:   p.accepted,
		Dropped:    p.dropped,
		Duplicates: p.duplicates,
		Processed:  p.processed,
		QueueDepth: len(p.queue),
		QueueSize:  cap(p.queue),
		LastEventAt: p.lastEventAt,
	}
}

func (p *Pipeline) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-p.queue:
			if p.handler != nil {
				p.handler(ctx, evt)
			}
			p.mu.Lock()
			p.processed++
			p.mu.Unlock()
		}
	}
}

func (p *Pipeline) isDuplicate(eventID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[eventID]; ok {
		p.duplicates++
		return true
	}
	p.seen[eventID] = time.Now()
	return false
}

func (p *Pipeline) cleanupSeen(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-30 * time.Minute)
			p.mu.Lock()
			for id, ts := range p.seen {
				if ts.Before(cutoff) {
					delete(p.seen, id)
				}
			}
			p.mu.Unlock()
		}
	}
}
