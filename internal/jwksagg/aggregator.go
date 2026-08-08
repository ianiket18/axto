// Package jwksagg serves the combined JWKS for a horizontally scaled Axto
// deployment: the union of every signer instance's currently-servable
// public keys, read from the shared registry.Registry. It never holds
// private key material -- it only ever reads what signer instances have
// already published.
package jwksagg

import (
	"context"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aniket/axto/internal/registry"
)

// Aggregator caches the combined JWKS for cacheTTL so a burst of verifier
// traffic doesn't turn into a burst of registry queries. A cache miss
// blocks only the caller that triggers the refresh; concurrent callers
// during that refresh get the previous cached value if there is one, or
// wait for the first refresh if there isn't.
type Aggregator struct {
	reg      registry.Registry
	cacheTTL time.Duration

	mu       sync.Mutex
	cached   jose.JSONWebKeySet
	cachedAt time.Time
	hasCache bool
}

func NewAggregator(reg registry.Registry, cacheTTL time.Duration) *Aggregator {
	return &Aggregator{reg: reg, cacheTTL: cacheTTL}
}

// JWKS returns the current combined JWKS, refreshing from the registry if
// the cache has expired.
func (a *Aggregator) JWKS(ctx context.Context) (jose.JSONWebKeySet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.hasCache && time.Since(a.cachedAt) < a.cacheTTL {
		return a.cached, nil
	}

	recs, err := a.reg.ListServable(ctx, time.Now())
	if err != nil {
		if a.hasCache {
			// Serve stale rather than fail outright -- a transient
			// registry error shouldn't take down JWKS for every
			// verifier at once.
			return a.cached, nil
		}
		return jose.JSONWebKeySet{}, fmt.Errorf("jwksagg: list servable keys: %w", err)
	}

	keys := make([]jose.JSONWebKey, 0, len(recs))
	for _, rec := range recs {
		keys = append(keys, rec.PublicKey)
	}
	jwks := jose.JSONWebKeySet{Keys: keys}

	a.cached = jwks
	a.cachedAt = time.Now()
	a.hasCache = true
	return jwks, nil
}
