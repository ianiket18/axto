package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/aniket/axto/internal/config"
	"github.com/aniket/axto/internal/httpapi"
	"github.com/aniket/axto/internal/keys"
	"github.com/aniket/axto/internal/mint"
	"github.com/aniket/axto/internal/registry"
)

func main() {
	configPath := flag.String("config", "", "path to the signer config file (see configs/axto.example.yaml)")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("must set -config to a config file path (see configs/axto.example.yaml)")
	}

	cfg, err := config.LoadSignerConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx := context.Background()
	keyStore, maxTTL := setUpKeyStore(ctx, cfg)

	handler := httpapi.NewHandler(mint.NewService(keyStore, maxTTL), keyStore, cfg.InternalToken)

	log.Printf("axto listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, handler.Routes()); err != nil {
		log.Fatal(err)
	}
}

// setUpKeyStore chooses between two deployment modes:
//
//   - No database URL: a single in-memory key for local development.
//     There's nothing to publish to, so no other instance could ever see
//     this instance's key anyway.
//   - A database URL is configured: a keys.ManagedStore backed by a
//     shared Postgres registry.Registry, ticked on a schedule to stage
//     and activate keys on its own lifecycle. This is the horizontally
//     scaled mode -- run several signer instances this way plus a
//     separate axto-jwks aggregator (cmd/axto-jwks) in front of the same
//     database.
//
// It returns the configured max token TTL alongside the store, since
// mint.Service must reject any request whose TTL would outlive the
// signing key's retirement grace period.
func setUpKeyStore(ctx context.Context, cfg *config.SignerConfig) (keys.Store, time.Duration) {
	if cfg.Database.URL == "" {
		keyStore, err := keys.NewInMemoryStore()
		if err != nil {
			log.Fatalf("generate signing key: %v", err)
		}
		return keyStore, 0
	}

	reg, err := registry.NewPostgresRegistry(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatalf("connect to key registry: %v", err)
	}

	instanceID := cfg.InstanceID
	if instanceID == "" {
		instanceID = uuid.NewString()
	}

	maxTTL := time.Duration(cfg.Keys.MaxTokenTTL)
	keyStore, err := keys.NewManagedStore(ctx, reg, instanceID, time.Duration(cfg.Keys.Lifetime), maxTTL)
	if err != nil {
		log.Fatalf("initialize managed key store: %v", err)
	}

	go keyStore.Run(ctx, time.Duration(cfg.Keys.CheckInterval), func(err error) {
		log.Printf("key lifecycle tick failed, will retry at the next tick: %v", err)
	})

	return keyStore, maxTTL
}
