# Axto

[![CI](https://github.com/aniket/axto/actions/workflows/ci.yml/badge.svg)](https://github.com/aniket/axto/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/aniket/axto.svg)](https://pkg.go.dev/github.com/aniket/axto)

**Axto** (Access Token Exchange) is a minimal, internal-only signing
service. It holds a signing key and does exactly one thing: sign a claim
set as a token, for a caller that has already decided the claims are
worth asserting. It never verifies anything, never looks anything up, and
has no database.

The idea is deliberately narrow: verification, authorization, claim
shape, revocation policy — all of that belongs to whatever calls Axto,
not to Axto itself. Keeping the signing service this small is what makes
it auditable and safe to trust with a private key.

## What it exposes

```
POST /internal/tokens:mint      (internal only, bearer-token gated)
  { "claims": {...}, "tokenType": "jwt", "ttlSeconds": 300 }
  -> { "token": "eyJ...", "jti": "...", "expiresAt": "..." }

GET /.well-known/jwks.json      (public, unauthenticated)
```

`claims` is opaque to Axto — it signs whatever it's given, adding only
`iat`/`exp`/`jti`. Every other design decision (what a `sub` looks like,
whether a token carries a grant, actor chains for delegation) lives
entirely in what the *caller* puts into `claims` before calling Mint, not
in this repo. This contract is intentionally the whole surface area, and
it's not expected to grow — see [CONTRIBUTING.md](CONTRIBUTING.md) before
proposing something that would change it.

## Running locally

Single instance, no database, no rotation — for local development only:

```
AXTO_INTERNAL_TOKEN=devsecret go run ./cmd/axto
```

`AXTO_INTERNAL_TOKEN` is required — it's the shared secret that gates
`/internal/tokens:mint`. This is a placeholder for real service-to-service
auth (mTLS, or an internal-only network boundary that makes the whole
question moot).

`AXTO_ADDR` overrides the listen address (default `:8090`).

## Running horizontally

Axto scales the way SPIRE Server does, not the way Dex does: there is no
single shared signing key coordinated through a lock. Each `cmd/axto`
instance generates and caches its own key **in memory**, and signs from
that cache — a signing call never touches the network. What *is* shared
is a small registry table (Postgres today) that instances publish their
public key to, and a separate, stateless `cmd/axto-jwks` service that
reads that table and serves the union of every instance's still-valid
public keys as one JWKS document. Verifiers only ever talk to the
aggregator, never to a specific signer instance.

```mermaid
flowchart TB
    subgraph Signers["cmd/axto instances (horizontally scaled)"]
        A1["Instance A\nkey cached in memory"]
        A2["Instance B\nkey cached in memory"]
    end
    Reg[("Postgres registry\npublic keys + retirement deadlines")]
    JWKS["cmd/axto-jwks\n(reads registry, holds no private key)"]
    V["Verifiers"]

    A1 -- "publish pubkey before signing\nretire outgoing key on rotation" --> Reg
    A2 -- "publish pubkey before signing\nretire outgoing key on rotation" --> Reg
    Reg --> JWKS
    JWKS -->|"GET /.well-known/jwks.json"| V
```

Two rules make this safe, enforced in code rather than left as convention:

- **Publish before sign.** `keys.ManagedStore` publishes a new key to the
  registry and only switches to signing with it after that publish
  succeeds — a verifier should never see a `kid` that isn't in JWKS yet.
- **Retire, don't delete.** When a key rotates out, it's kept servable in
  JWKS until `AXTO_MAX_TOKEN_TTL` after rotation — long enough for any
  token already signed with it to finish its own lifetime.
  `mint.Service` enforces the matching cap on the other end: it rejects
  any mint request whose TTL would outlive that retirement window, so a
  token can never outlive its own verifiability.

```
# every instance, including cmd/axto-jwks
AXTO_DATABASE_URL=postgres://user:pass@host:5432/axto

# cmd/axto only
AXTO_INTERNAL_TOKEN=...            # required, gates /internal/tokens:mint
AXTO_MAX_TOKEN_TTL=15m             # default 15m; also the key-retirement grace period
AXTO_KEY_ROTATION_PERIOD=24h       # default 24h
AXTO_INSTANCE_ID=...               # optional; random UUID if unset

# cmd/axto-jwks only
AXTO_JWKS_CACHE_TTL=10s            # default 10s
```

Run several `cmd/axto` replicas and one or more `cmd/axto-jwks` replicas
behind a load balancer, all pointed at the same database.

## Status

Early: in-memory signing key per instance (`keys.InMemoryStore` for a
single dev process, `keys.ManagedStore` for the horizontally scaled mode
above), a Postgres-backed key registry, and the JWKS aggregator. Not yet
wired into a real caller, and the registry has no migration tool beyond
`CREATE TABLE IF NOT EXISTS` on startup (guarded by a Postgres advisory
lock so concurrent instances don't race on it, but still a placeholder
for a real schema-migration story if this grows past one table).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for
the development workflow and the DCO sign-off required on every commit.
This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
