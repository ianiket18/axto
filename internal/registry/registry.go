// Package registry is the shared record of every signer instance's public
// key. A signer instance never reads it back to sign -- signing always
// uses the key already cached in memory (see internal/keys.ManagedStore).
// The registry exists for two things only: letting a new or rotated key
// become verifiable before it's ever used, and letting the JWKS aggregator
// (internal/jwksagg) publish the union of every instance's currently-valid
// public keys without needing to talk to the instances themselves.
package registry

import (
	"context"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// PublicKeyRecord is one signer instance's public key as published to the
// registry. RetireAt is nil for a key that's still in active use; once a
// key is rotated out, RetireAt is set to the time it should stop being
// servable in JWKS -- that must be no earlier than the expiry of the
// longest-lived token that could have been signed with it.
type PublicKeyRecord struct {
	KeyID       string
	InstanceID  string
	PublicKey   jose.JSONWebKey
	PublishedAt time.Time
	RetireAt    *time.Time
}

// Servable reports whether the record should still appear in JWKS as of t.
func (r PublicKeyRecord) Servable(t time.Time) bool {
	return r.RetireAt == nil || t.Before(*r.RetireAt)
}

// Registry is the shared store of public key material across every signer
// instance. Implementations must make Publish visible to ListServable
// before the publishing instance starts signing with that key -- callers
// rely on this ordering to avoid a token being signed with a kid that
// isn't verifiable yet.
type Registry interface {
	// Publish records a new public key as active (servable, no retirement
	// time). Publishing the same KeyID twice is an error.
	Publish(ctx context.Context, rec PublicKeyRecord) error

	// Retire marks an existing key to stop being servable at retireAt.
	// Retiring a key that's already retired moves its retirement time
	// only if the new one is earlier -- a key already scheduled to leave
	// the JWKS soon should not have its window extended by a second call.
	Retire(ctx context.Context, keyID string, retireAt time.Time) error

	// ListServable returns every record with Servable(asOf) true.
	ListServable(ctx context.Context, asOf time.Time) ([]PublicKeyRecord, error)
}
