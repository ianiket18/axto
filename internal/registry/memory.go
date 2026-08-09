package registry

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// InMemoryRegistry is a Registry backed by a process-local map. It's useful
// for local development (running several signer instances plus an
// aggregator in one process) and for tests; it is not shared across
// processes, so it cannot back a real horizontally scaled deployment.
type InMemoryRegistry struct {
	mu      sync.Mutex
	records map[string]PublicKeyRecord
}

func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{records: make(map[string]PublicKeyRecord)}
}

func (r *InMemoryRegistry) Publish(_ context.Context, rec PublicKeyRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.records[rec.KeyID]; exists {
		return fmt.Errorf("registry: key %q already published", rec.KeyID)
	}
	r.records[rec.KeyID] = rec
	return nil
}

func (r *InMemoryRegistry) Retire(_ context.Context, keyID string, retireAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[keyID]
	if !ok {
		return fmt.Errorf("registry: key %q not found", keyID)
	}
	if rec.RetireAt == nil || retireAt.Before(*rec.RetireAt) {
		rec.RetireAt = &retireAt
		r.records[keyID] = rec
	}
	return nil
}

func (r *InMemoryRegistry) ListServable(_ context.Context, asOf time.Time) ([]PublicKeyRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PublicKeyRecord, 0, len(r.records))
	for _, rec := range r.records {
		if rec.Servable(asOf) {
			out = append(out, rec)
		}
	}
	return out, nil
}
