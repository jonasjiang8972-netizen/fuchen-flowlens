package ingest

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func TestSubmitDeduplicates(t *testing.T) {
	p := NewPipeline(10, nil)
	evt := shared.APIEvent{EventID: "e1"}

	r := p.Submit(context.Background(), []shared.APIEvent{evt, evt})
	if r.Accepted != 1 || r.Duplicates != 1 {
		t.Fatalf("got %+v, want 1 accepted and 1 duplicate", r)
	}
}

func TestDroppedEventCanBeRetried(t *testing.T) {
	p := NewPipeline(1, nil) // no workers started, so the queue stays full

	r := p.Submit(context.Background(), []shared.APIEvent{{EventID: "a"}, {EventID: "b"}})
	if r.Accepted != 1 || r.Dropped != 1 {
		t.Fatalf("got %+v, want 1 accepted and 1 dropped", r)
	}

	<-p.queue // free a slot
	r = p.Submit(context.Background(), []shared.APIEvent{{EventID: "b"}})
	if r.Accepted != 1 || r.Duplicates != 0 {
		t.Fatalf("retry of dropped event got %+v, want accepted", r)
	}

	m := p.Metrics()
	if m.Dropped != 1 || m.Accepted != 2 {
		t.Fatalf("metrics %+v, want dropped=1 accepted=2", m)
	}
}

func TestSeenTableIsBounded(t *testing.T) {
	p := NewPipeline(1, nil)
	now := time.Now() // fresh entries, so pruning cannot free space
	for i := 0; i < maxSeen; i++ {
		p.seen["fill-"+strconv.Itoa(i)] = now
	}

	if p.isDuplicate("new") {
		t.Fatal("new ID reported as duplicate")
	}
	if len(p.seen) != maxSeen {
		t.Fatalf("seen table has %d entries, want %d", len(p.seen), maxSeen)
	}
}
