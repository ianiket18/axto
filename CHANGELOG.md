# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
once it reaches a tagged release.

## [Unreleased]

### Added

- Initial scaffold: in-memory ES256 key store, `Mint` service, and an
  HTTP API for minting and JWKS.
- Horizontal scaling: a shared key registry, `keys.ManagedStore` for
  per-instance signing with publish-before-sign and key retirement, and
  a separate `cmd/axto-jwks` aggregator service.
