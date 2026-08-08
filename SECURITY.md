# Security Policy

Axto signs tokens for other services to trust — a vulnerability here has
outsized impact. Please report privately, not via a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
**Security tab → Report a vulnerability**. This opens a private
advisory visible only to maintainers until a fix is ready.

If that's unavailable, open an issue titled "Security contact needed"
with no details, and a maintainer will follow up with a private channel.

## Scope

In scope: anything in this repository — key handling, token signing,
the JWKS endpoint, the mint authorization check.

Out of scope: vulnerabilities in services that *consume* Axto-issued
tokens (report those to the relevant service instead), and vulnerabilities
in third-party dependencies (report upstream, but let us know too so we
can track and update).

## What to expect

We aim to acknowledge reports within 5 business days and to agree on a
disclosure timeline once the issue is confirmed.
