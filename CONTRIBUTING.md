# Contributing to Axto

Thanks for considering a contribution. Axto is intentionally small in
scope — see the design principle in [README.md](README.md) ("Axto's
contract never changes") before proposing a feature. Most new
functionality belongs in a *caller's* claim construction, not in Axto
itself.

## Before you open a PR

For anything beyond a small fix, open an issue first describing the
problem you're solving. This avoids spending time on a PR that doesn't
fit the project's scope.

## Development

```
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

All four must be clean before review. There's no separate lint config
beyond `go vet` and `gofmt` today.

## Sign off your commits (DCO)

Every commit must include a `Signed-off-by` line, certifying you wrote
it or otherwise have the right to submit it under this project's license
(the [Developer Certificate of Origin](https://developercertificate.org/)).

Add it automatically with:

```
git commit -s -m "your message"
```

PRs with unsigned commits will be blocked by CI until amended
(`git commit --amend -s`, or `git rebase --exec 'git commit --amend --no-edit -s' <base>`
for multiple commits).

## Code review

- Keep PRs focused — one change, one PR.
- Add or update tests for any behavior change.
- Explain the *why* in the PR description, not just the what.

## Reporting security issues

Do not open a public issue for a suspected vulnerability. See
[SECURITY.md](SECURITY.md).
