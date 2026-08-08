package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/aniket/axto/internal/httpapi"
	"github.com/aniket/axto/internal/keys"
	"github.com/aniket/axto/internal/mint"
	"github.com/aniket/axto/internal/registry"
)

func main() {
	internalToken := os.Getenv("AXTO_INTERNAL_TOKEN")
	if internalToken == "" {
		log.Fatal("AXTO_INTERNAL_TOKEN must be set (shared secret gating the Mint endpoint)")
	}

	ctx := context.Background()
	keyStore, maxTTL := setUpKeyStore(ctx)

	handler := httpapi.NewHandler(mint.NewService(keyStore, maxTTL), keyStore, internalToken)

	addr := os.Getenv("AXTO_ADDR")
	if addr == "" {
		addr = ":8090"
	}

	log.Printf("axto listening on %s", addr)
	if err := http.ListenAndServe(addr, handler.Routes()); err != nil {
		log.Fatal(err)
	}
}

// setUpKeyStore chooses between two deployment modes:
//
//   - No AXTO_DATABASE_URL: a single in-memory key for local development.
//     There's nothing to publish to, so no other instance could ever see
//     this instance's key anyway.
//   - AXTO_DATABASE_URL set: a keys.ManagedStore backed by a shared
//     Postgres registry.Registry, with a background rotation loop. This
//     is the horizontally scaled mode -- run several signer instances
//     this way plus a separate axto-jwks aggregator (cmd/axto-jwks) in
//     front of the same database.
//
// It returns the configured max token TTL alongside the store, since
// mint.Service must reject any request whose TTL would outlive the
// signing key's retirement grace period.
func setUpKeyStore(ctx context.Context) (keys.Store, time.Duration) {
	dsn := os.Getenv("AXTO_DATABASE_URL")
	if dsn == "" {
		keyStore, err := keys.NewInMemoryStore()
		if err != nil {
			log.Fatalf("generate signing key: %v", err)
		}
		return keyStore, 0
	}

	maxTTL := envDuration("AXTO_MAX_TOKEN_TTL", 15*time.Minute)
	rotationPeriod := envDuration("AXTO_KEY_ROTATION_PERIOD", 24*time.Hour)

	reg, err := registry.NewPostgresRegistry(ctx, dsn)
	if err != nil {
		log.Fatalf("connect to key registry: %v", err)
	}

	instanceID := os.Getenv("AXTO_INSTANCE_ID")
	if instanceID == "" {
		instanceID = uuid.NewString()
	}

	keyStore, err := keys.NewManagedStore(ctx, reg, instanceID, maxTTL)
	if err != nil {
		log.Fatalf("initialize managed key store: %v", err)
	}

	go runRotationLoop(ctx, keyStore, rotationPeriod)

	return keyStore, maxTTL
}

func runRotationLoop(ctx context.Context, store *keys.ManagedStore, period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := store.Rotate(ctx); err != nil {
				log.Printf("key rotation failed, will retry at the next tick: %v", err)
			} else {
				log.Printf("rotated signing key (new kid: %s)", store.Current().ID)
			}
		}
	}
}

func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid duration for %s: %v", name, err)
	}
	return d
}
