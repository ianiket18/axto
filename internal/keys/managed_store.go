package keys

import (
	"context"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aniket/axto/internal/registry"
)

// ManagedStore is the Store used by a horizontally scaled deployment: it
// still signs from a key cached in local memory -- Current never makes a
// network call -- but it also keeps the shared registry.Registry in sync
// so the JWKS aggregator (internal/jwksagg) can see every instance's
// public key.
//
// Two rules matter for correctness and are enforced here, not by callers:
//
//   - A new key is published to the registry and that publish call must
//     succeed before ManagedStore starts signing with it. Otherwise a
//     verifier could see a token whose kid isn't in JWKS yet.
//   - When a key is rotated out, it's retired with a deadline far enough
//     out that any token already signed with it remains verifiable until
//     that token's own expiry. maxTokenTTL is the caller's declaration of
//     the longest TTL it will ever hand to mint.Service; ManagedStore
//     doesn't enforce that cap itself (see mint.Service.MaxTTL for that).
type ManagedStore struct {
	mu          sync.RWMutex
	current     Key
	reg         registry.Registry
	instanceID  string
	maxTokenTTL time.Duration
}

// NewManagedStore generates the instance's first signing key, publishes it
// to reg, and returns a ManagedStore ready to sign. instanceID identifies
// this process in the registry (for observability, not correctness) and
// maxTokenTTL is the retirement grace period used by Rotate.
func NewManagedStore(ctx context.Context, reg registry.Registry, instanceID string, maxTokenTTL time.Duration) (*ManagedStore, error) {
	s := &ManagedStore{reg: reg, instanceID: instanceID, maxTokenTTL: maxTokenTTL}
	key, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("keys: generate signing key: %w", err)
	}
	if err := s.publish(ctx, key); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.current = key
	s.mu.Unlock()
	return s, nil
}

func (s *ManagedStore) Current() Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// JWKS returns only this instance's own current public key. It exists for
// local introspection (e.g. a debug endpoint on the signer itself); the
// JWKS a verifier should actually trust is the aggregator's, which unions
// every instance's servable keys via the shared registry.
func (s *ManagedStore) JWKS() jose.JSONWebKeySet {
	key := s.Current()
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.PrivateKey.Public(),
		KeyID:     key.ID,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}}}
}

// Rotate generates a new signing key, publishes it, switches Current to
// it, and retires the outgoing key with a deadline of maxTokenTTL from
// now. Callers wanting periodic rotation should call this on a timer;
// ManagedStore itself has no background goroutine.
func (s *ManagedStore) Rotate(ctx context.Context) error {
	newKey, err := generateKey()
	if err != nil {
		return fmt.Errorf("keys: generate signing key: %w", err)
	}
	if err := s.publish(ctx, newKey); err != nil {
		return err
	}

	s.mu.Lock()
	oldKey := s.current
	s.current = newKey
	s.mu.Unlock()

	if err := s.reg.Retire(ctx, oldKey.ID, time.Now().Add(s.maxTokenTTL)); err != nil {
		return fmt.Errorf("keys: retire outgoing key %q: %w", oldKey.ID, err)
	}
	return nil
}

func (s *ManagedStore) publish(ctx context.Context, key Key) error {
	rec := registry.PublicKeyRecord{
		KeyID:      key.ID,
		InstanceID: s.instanceID,
		PublicKey: jose.JSONWebKey{
			Key:       key.PrivateKey.Public(),
			KeyID:     key.ID,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
		PublishedAt: time.Now(),
	}
	if err := s.reg.Publish(ctx, rec); err != nil {
		return fmt.Errorf("keys: publish key %q: %w", key.ID, err)
	}
	return nil
}
