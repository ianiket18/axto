// Command axto-jwks serves the combined JWKS for a horizontally scaled
// Axto deployment: the union of every signer instance's currently
// servable public keys, read from the same Postgres registry the signer
// instances (cmd/axto) publish to. It holds no private key material and
// needs no AXTO_INTERNAL_TOKEN -- there is nothing on this service worth
// authenticating a caller against.
//
// Run one or more replicas of this behind a load balancer; they're
// stateless aside from a short in-memory cache, so scaling it is just
// scaling replica count.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aniket/axto/internal/jwksagg"
	"github.com/aniket/axto/internal/registry"
)

func main() {
	dsn := os.Getenv("AXTO_DATABASE_URL")
	if dsn == "" {
		log.Fatal("AXTO_DATABASE_URL must be set")
	}

	ctx := context.Background()
	reg, err := registry.NewPostgresRegistry(ctx, dsn)
	if err != nil {
		log.Fatalf("connect to key registry: %v", err)
	}

	cacheTTL := 10 * time.Second
	if v := os.Getenv("AXTO_JWKS_CACHE_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("invalid AXTO_JWKS_CACHE_TTL: %v", err)
		}
		cacheTTL = d
	}

	handler := jwksagg.NewHandler(jwksagg.NewAggregator(reg, cacheTTL))

	addr := os.Getenv("AXTO_ADDR")
	if addr == "" {
		addr = ":8091"
	}

	log.Printf("axto-jwks listening on %s", addr)
	if err := http.ListenAndServe(addr, handler.Routes()); err != nil {
		log.Fatal(err)
	}
}
