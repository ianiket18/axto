// Package keys manages Axto's signing key material. Axto only ever needs
// two things from a key: something to sign with (Current) and something
// to publish so others can verify (JWKS) -- it never looks anything up by
// key, since it has no callers to authenticate against key ownership.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// Key is one ES256 signing keypair, identified by kid.
type Key struct {
	ID         string
	PrivateKey *ecdsa.PrivateKey
}

// Store holds the current signing key and publishes the public half of
// every key it still considers valid for verification, so a token signed
// just before a rotation can still be verified against the old key.
type Store interface {
	Current() Key
	JWKS() jose.JSONWebKeySet
}

// InMemoryStore generates one ES256 key at process startup and keeps it in
// memory for the life of the process. This is a placeholder for local dev
// and early testing only: a restart invalidates every outstanding token
// (nothing to reload from), and there's no rotation. Production use should
// replace this with something durable -- the design doc calls out reusing
// an OpenBao-backed secret store, matching how access-platform's
// internal/secretstore already handles other key material.
type InMemoryStore struct {
	key Key
}

func NewInMemoryStore() (*InMemoryStore, error) {
	key, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("keys: generate signing key: %w", err)
	}
	return &InMemoryStore{key: key}, nil
}

func (s *InMemoryStore) Current() Key {
	return s.key
}

func (s *InMemoryStore) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       s.key.PrivateKey.Public(),
			KeyID:     s.key.ID,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}},
	}
}

func generateKey() (Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Key{}, fmt.Errorf("generate ES256 keypair: %w", err)
	}
	id, err := randomID()
	if err != nil {
		return Key{}, err
	}
	return Key{ID: id, PrivateKey: priv}, nil
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
