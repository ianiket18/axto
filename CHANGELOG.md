# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
once it reaches a tagged release.

## [Unreleased]

### Added

- Initial scaffold: in-memory ES256 key store, `Mint` service, and an
  HTTP API for minting and JWKS.
- Horizontal scaling: a shared key registry with versioned migrations,
  `keys.ManagedStore` for per-instance signing with a stage-at-half-life /
  activate-at-expiry key lifecycle, and a `cmd/axto-jwks` aggregator.
- YAML config files (`-config`) replace environment variables for both
  binaries; secrets can still be sourced from the environment via an
  `"env:VAR_NAME"` value.
