package keys

import (
	"context"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aniket/axto/internal/registry"
)

// ManagedStore is the Store used by a horizontally scaled deployment. It
// still signs from a key cached in local memory -- Current never makes a
// network call -- but keeps the shared registry.Registry in sync so the
// JWKS aggregator can see every instance's public key, and runs its own
// key lifecycle: each signing key has a lifetime, a replacement is staged
// (published but not yet used) once the current key is past half its
// lifetime, and that replacement becomes the signing key once the current
// one's lifetime is up. The outgoing key stays servable in JWKS for
// maxTokenTTL afterward so tokens it already signed remain verifiable.
type ManagedStore struct {
	mu               sync.RWMutex
	current          Key
	currentExpiresAt time.Time
	staged           *Key

	reg         registry.Registry
	instanceID  string
	keyLifetime time.Duration
	maxTokenTTL time.Duration
}

// NewManagedStore generates the instance's first signing key, publishes it
// to reg, and returns a ManagedStore ready to sign. Call Run (or Tick on
// your own schedule) to drive the staging/activation lifecycle.
func NewManagedStore(ctx context.Context, reg registry.Registry, instanceID string, keyLifetime, maxTokenTTL time.Duration) (*ManagedStore, error) {
	s := &ManagedStore{reg: reg, instanceID: instanceID, keyLifetime: keyLifetime, maxTokenTTL: maxTokenTTL}
	key, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("keys: generate signing key: %w", err)
	}
	if err := s.publish(ctx, key); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.current = key
	s.currentExpiresAt = time.Now().Add(keyLifetime)
	s.mu.Unlock()
	return s, nil
}

func (s *ManagedStore) Current() Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// JWKS returns only this instance's own current public key. It exists for
// local introspection; the JWKS a verifier should trust is the
// aggregator's, which unions every instance's servable keys.
func (s *ManagedStore) JWKS() jose.JSONWebKeySet {
	key := s.Current()
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.PrivateKey.Public(),
		KeyID:     key.ID,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}}}
}

// Tick advances the key lifecycle. Call it on a schedule shorter than
// keyLifetime/2 so the staging and activation points below are caught
// promptly rather than drifting.
func (s *ManagedStore) Tick(ctx context.Context) error {
	s.mu.RLock()
	expiresAt := s.currentExpiresAt
	alreadyStaged := s.staged != nil
	s.mu.RUnlock()

	now := time.Now()
	halfLife := expiresAt.Add(-s.keyLifetime / 2)

	if !alreadyStaged && now.After(halfLife) {
		if err := s.stage(ctx); err != nil {
			return err
		}
	}
	if now.After(expiresAt) {
		if err := s.activateStaged(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Run calls Tick every checkInterval until ctx is done. Errors are
// reported via onError (nil is fine to ignore them); Tick simply retries
// at the next tick either way.
func (s *ManagedStore) Run(ctx context.Context, checkInterval time.Duration, onError func(error)) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Tick(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

func (s *ManagedStore) stage(ctx context.Context) error {
	newKey, err := generateKey()
	if err != nil {
		return fmt.Errorf("keys: generate signing key: %w", err)
	}
	if err := s.publish(ctx, newKey); err != nil {
		return err
	}
	s.mu.Lock()
	s.staged = &newKey
	s.mu.Unlock()
	return nil
}

func (s *ManagedStore) activateStaged(ctx context.Context) error {
	s.mu.Lock()
	if s.staged == nil {
		s.mu.Unlock()
		return nil
	}
	outgoing := s.current
	s.current = *s.staged
	s.currentExpiresAt = time.Now().Add(s.keyLifetime)
	s.staged = nil
	s.mu.Unlock()

	if err := s.reg.Retire(ctx, outgoing.ID, time.Now().Add(s.maxTokenTTL)); err != nil {
		return fmt.Errorf("keys: retire outgoing key %q: %w", outgoing.ID, err)
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
