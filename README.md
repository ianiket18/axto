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

```
AXTO_INTERNAL_TOKEN=devsecret go run ./cmd/axto
```

`AXTO_INTERNAL_TOKEN` is required — it's the shared secret that gates
`/internal/tokens:mint`. This is a placeholder for real service-to-service
auth (mTLS, or an internal-only network boundary that makes the whole
question moot).

`AXTO_ADDR` overrides the listen address (default `:8090`).

## Status

Early scaffold: in-memory ES256 key (regenerated on every restart, no
rotation, no durable storage). Not yet wired into a real caller. Next up:
durable key storage with rotation, and a reference integration showing
how a caller verifies its own inputs before asking Axto to sign.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for
the development workflow and the DCO sign-off required on every commit.
This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
