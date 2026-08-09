// Command axto-jwks serves the combined JWKS for a horizontally scaled
// Axto deployment: the union of every signer instance's currently
// servable public keys, read from the same Postgres registry the signer
// instances (cmd/axto) publish to. It holds no private key material and
// needs no internal token -- there is nothing on this service worth
// authenticating a caller against.
//
// Run one or more replicas of this behind a load balancer; they're
// stateless aside from a short in-memory cache, so scaling it is just
// scaling replica count.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/aniket/axto/internal/config"
	"github.com/aniket/axto/internal/jwksagg"
	"github.com/aniket/axto/internal/registry"
)

func main() {
	configPath := flag.String("config", "", "path to the aggregator config file (see configs/axto-jwks.example.yaml)")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("must set -config to a config file path (see configs/axto-jwks.example.yaml)")
	}

	cfg, err := config.LoadAggregatorConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.Database.URL == "" {
		log.Fatal("database.url must be set")
	}

	ctx := context.Background()
	reg, err := registry.NewPostgresRegistry(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatalf("connect to key registry: %v", err)
	}

	handler := jwksagg.NewHandler(jwksagg.NewAggregator(reg, time.Duration(cfg.JWKSCacheTTL)))

	log.Printf("axto-jwks listening on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, handler.Routes()); err != nil {
		log.Fatal(err)
	}
}
