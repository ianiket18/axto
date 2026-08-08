package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// runContractTests exercises the Registry interface's documented behavior
// against any implementation, so both InMemoryRegistry and
// PostgresRegistry are held to the same contract.
func runContractTests(t *testing.T, newRegistry func(t *testing.T) Registry) {
	t.Run("PublishThenListServable", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		now := time.Now().Truncate(time.Second)

		rec := PublicKeyRecord{
			KeyID:       "key-a",
			InstanceID:  "instance-1",
			PublicKey:   testJWK(t, "key-a"),
			PublishedAt: now,
		}
		if err := reg.Publish(ctx, rec); err != nil {
			t.Fatalf("Publish: %v", err)
		}

		recs, err := reg.ListServable(ctx, now)
		if err != nil {
			t.Fatalf("ListServable: %v", err)
		}
		if len(recs) != 1 || recs[0].KeyID != "key-a" {
			t.Fatalf("expected exactly key-a to be servable, got %+v", recs)
		}
	})

	t.Run("PublishingSameKeyIDTwiceFails", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		rec := PublicKeyRecord{KeyID: "dup", InstanceID: "instance-1", PublicKey: testJWK(t, "dup"), PublishedAt: time.Now()}

		if err := reg.Publish(ctx, rec); err != nil {
			t.Fatalf("first Publish: %v", err)
		}
		if err := reg.Publish(ctx, rec); err == nil {
			t.Fatal("expected publishing the same KeyID twice to fail")
		}
	})

	t.Run("RetiredKeyStopsBeingServableAfterRetireAt", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		now := time.Now().Truncate(time.Second)

		rec := PublicKeyRecord{KeyID: "key-b", InstanceID: "instance-1", PublicKey: testJWK(t, "key-b"), PublishedAt: now}
		if err := reg.Publish(ctx, rec); err != nil {
			t.Fatalf("Publish: %v", err)
		}

		retireAt := now.Add(time.Minute)
		if err := reg.Retire(ctx, "key-b", retireAt); err != nil {
			t.Fatalf("Retire: %v", err)
		}

		before, err := reg.ListServable(ctx, retireAt.Add(-time.Second))
		if err != nil {
			t.Fatalf("ListServable before retirement: %v", err)
		}
		if len(before) != 1 {
			t.Fatalf("expected key-b to still be servable just before retireAt, got %+v", before)
		}

		after, err := reg.ListServable(ctx, retireAt.Add(time.Second))
		if err != nil {
			t.Fatalf("ListServable after retirement: %v", err)
		}
		if len(after) != 0 {
			t.Fatalf("expected key-b to no longer be servable after retireAt, got %+v", after)
		}
	})

	t.Run("RetiringTwiceKeepsTheEarlierDeadline", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		now := time.Now().Truncate(time.Second)

		rec := PublicKeyRecord{KeyID: "key-c", InstanceID: "instance-1", PublicKey: testJWK(t, "key-c"), PublishedAt: now}
		if err := reg.Publish(ctx, rec); err != nil {
			t.Fatalf("Publish: %v", err)
		}

		earlier := now.Add(time.Minute)
		later := now.Add(time.Hour)
		if err := reg.Retire(ctx, "key-c", earlier); err != nil {
			t.Fatalf("first Retire: %v", err)
		}
		if err := reg.Retire(ctx, "key-c", later); err != nil {
			t.Fatalf("second Retire: %v", err)
		}

		// The earlier deadline must win: by `earlier`, the key must
		// already be gone, even though a later Retire call asked for
		// more time.
		recs, err := reg.ListServable(ctx, earlier.Add(time.Second))
		if err != nil {
			t.Fatalf("ListServable: %v", err)
		}
		if len(recs) != 0 {
			t.Fatalf("expected the earlier retirement deadline to win, got %+v", recs)
		}
	})

	t.Run("RetiringUnknownKeyFails", func(t *testing.T) {
		reg := newRegistry(t)
		if err := reg.Retire(context.Background(), "does-not-exist", time.Now()); err == nil {
			t.Fatal("expected retiring an unpublished key to fail")
		}
	})
}

func TestInMemoryRegistry(t *testing.T) {
	runContractTests(t, func(t *testing.T) Registry {
		return NewInMemoryRegistry()
	})
}

func TestPostgresRegistry(t *testing.T) {
	dsn := os.Getenv("AXTO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AXTO_TEST_DATABASE_URL not set; skipping Postgres-backed registry tests")
	}
	runContractTests(t, func(t *testing.T) Registry {
		reg, err := NewPostgresRegistry(context.Background(), dsn)
		if err != nil {
			t.Fatalf("NewPostgresRegistry: %v", err)
		}
		t.Cleanup(func() {
			reg.db.Exec("DELETE FROM axto_signing_keys")
			reg.Close()
		})
		return reg
	})
}

func testJWK(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
}
