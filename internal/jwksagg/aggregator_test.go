package jwksagg

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aniket/axto/internal/registry"
)

func testPublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return priv.Public()
}

func TestAggregator_ReturnsUnionOfServableKeys(t *testing.T) {
	reg := registry.NewInMemoryRegistry()
	ctx := context.Background()
	now := time.Now()

	mustPublish(t, reg, "a", now)
	mustPublish(t, reg, "b", now)

	agg := NewAggregator(reg, time.Minute)
	jwks, err := agg.JWKS(ctx)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(jwks.Keys))
	}
}

func TestAggregator_CachesWithinTTL(t *testing.T) {
	reg := &countingRegistry{Registry: registry.NewInMemoryRegistry()}
	ctx := context.Background()
	mustPublish(t, reg, "a", time.Now())

	agg := NewAggregator(reg, time.Hour)
	if _, err := agg.JWKS(ctx); err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if _, err := agg.JWKS(ctx); err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if reg.listCalls != 1 {
		t.Fatalf("expected exactly 1 registry call within the cache TTL, got %d", reg.listCalls)
	}
}

func TestAggregator_RefreshesAfterTTLExpires(t *testing.T) {
	reg := &countingRegistry{Registry: registry.NewInMemoryRegistry()}
	ctx := context.Background()
	mustPublish(t, reg, "a", time.Now())

	agg := NewAggregator(reg, time.Millisecond)
	if _, err := agg.JWKS(ctx); err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := agg.JWKS(ctx); err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if reg.listCalls != 2 {
		t.Fatalf("expected a refresh after the cache TTL elapsed, got %d calls", reg.listCalls)
	}
}

func TestAggregator_ServesStaleOnRegistryErrorAfterFirstSuccess(t *testing.T) {
	reg := &countingRegistry{Registry: registry.NewInMemoryRegistry()}
	ctx := context.Background()
	mustPublish(t, reg, "a", time.Now())

	agg := NewAggregator(reg, time.Millisecond)
	first, err := agg.JWKS(ctx)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	time.Sleep(5 * time.Millisecond)
	reg.failNext = true
	second, err := agg.JWKS(ctx)
	if err != nil {
		t.Fatalf("expected a stale value instead of an error, got: %v", err)
	}
	if len(second.Keys) != len(first.Keys) {
		t.Fatalf("expected the stale cached JWKS to be served, got %+v", second)
	}
}

func TestAggregator_ReturnsErrorOnFirstLoadFailure(t *testing.T) {
	reg := &countingRegistry{Registry: registry.NewInMemoryRegistry(), failNext: true}
	agg := NewAggregator(reg, time.Minute)

	if _, err := agg.JWKS(context.Background()); err == nil {
		t.Fatal("expected an error when the very first load fails with nothing cached yet")
	}
}

func mustPublish(t *testing.T, reg registry.Registry, kid string, now time.Time) {
	t.Helper()
	rec := registry.PublicKeyRecord{
		KeyID:       kid,
		InstanceID:  "instance-1",
		PublicKey:   jose.JSONWebKey{Key: testPublicKey(t), KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"},
		PublishedAt: now,
	}
	if err := reg.Publish(context.Background(), rec); err != nil {
		t.Fatalf("Publish: %v", err)
	}
}

type countingRegistry struct {
	registry.Registry
	listCalls int
	failNext  bool
}

func (c *countingRegistry) ListServable(ctx context.Context, asOf time.Time) ([]registry.PublicKeyRecord, error) {
	c.listCalls++
	if c.failNext {
		c.failNext = false
		return nil, errors.New("simulated registry failure")
	}
	return c.Registry.ListServable(ctx, asOf)
}
