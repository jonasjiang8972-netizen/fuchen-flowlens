package service

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
)

// ErrNotFound is wrapped by service errors for records that do not exist.
var ErrNotFound = errors.New("not found")

// Document kinds persisted through a Repository.
const (
	KindAsset = "asset"
	KindAlert = "alert"
	KindRule  = "rule"
	KindAgent = "agent"
)

// Repository persists business records as JSON documents keyed by kind and
// id. Services keep their working set in memory for the ingest hot path and
// write through this interface.
type Repository interface {
	LoadDocuments(ctx context.Context, kind string) (map[string][]byte, error)
	SaveDocuments(ctx context.Context, kind string, docs map[string][]byte) error
}

// persister writes a service's records to its repository.
//
// User actions persist synchronously (writeThrough) so a failure can be
// reported and rolled back. High-frequency updates (traffic statistics,
// alert merges, rule hit counts, heartbeats) only mark the record dirty;
// Flush writes them in batches. writeMu orders every write so an older
// snapshot never overwrites a newer one.
type persister struct {
	repo    Repository
	kind    string
	writeMu sync.Mutex

	dirtyMu sync.Mutex
	dirty   map[string]bool
}

func newPersister(repo Repository, kind string) *persister {
	return &persister{repo: repo, kind: kind, dirty: make(map[string]bool)}
}

// enabled reports whether records are persisted at all (memory-only
// services have no repository).
func (p *persister) enabled() bool { return p != nil && p.repo != nil }

func (p *persister) markDirty(id string) {
	if !p.enabled() {
		return
	}
	p.dirtyMu.Lock()
	p.dirty[id] = true
	p.dirtyMu.Unlock()
}

// writeThrough persists the given records now. snapshot is called under
// writeMu and must return the current JSON of each id (taking the service
// lock itself).
func (p *persister) writeThrough(ctx context.Context, ids []string, snapshot func(ids []string) map[string][]byte) error {
	if !p.enabled() {
		return nil
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	docs := snapshot(ids)
	if len(docs) == 0 {
		return nil
	}
	if err := p.repo.SaveDocuments(ctx, p.kind, docs); err != nil {
		return err
	}
	p.dirtyMu.Lock()
	for id := range docs {
		delete(p.dirty, id)
	}
	p.dirtyMu.Unlock()
	return nil
}

// flush persists every dirty record. Failed records stay dirty and are
// retried on the next flush.
func (p *persister) flush(ctx context.Context, snapshot func(ids []string) map[string][]byte) (int, error) {
	if !p.enabled() {
		return 0, nil
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.dirtyMu.Lock()
	ids := make([]string, 0, len(p.dirty))
	for id := range p.dirty {
		ids = append(ids, id)
	}
	p.dirty = make(map[string]bool)
	p.dirtyMu.Unlock()
	if len(ids) == 0 {
		return 0, nil
	}
	docs := snapshot(ids)
	if err := p.repo.SaveDocuments(ctx, p.kind, docs); err != nil {
		p.dirtyMu.Lock()
		for _, id := range ids {
			p.dirty[id] = true
		}
		p.dirtyMu.Unlock()
		return 0, err
	}
	return len(docs), nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // records are plain structs; this cannot fail
	}
	return b
}
