# Contributing to Protocol Ward

Thanks for considering a contribution. Protocol Ward is in **public beta**: interfaces, config keys and log lines can still change between releases.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the shape.
- Read `docs/engineering/invariants.md`. A change that violates an invariant is a bug, whatever its tests say.
- `CLAUDE.md` holds the same working rules for AI coding agents.

## Sign-off (required)

Every commit needs a [Developer Certificate of Origin](https://developercertificate.org/) sign-off:

```
git commit -s -m "fix: your message"
```

This adds `Signed-off-by: Your Name <your@email>`. It certifies that you have the right to submit the change under the project's licence, Apache-2.0.

## Branches, commits and checks

- Branch off `main` with a short kebab-case name (`fix/dns-cache-eviction-race`).
- One concern per pull request.
- Use conventional commit messages (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`).
- Install [`pre-commit`](https://pre-commit.com), run `make bootstrap` once, then make sure **`make ci` passes locally** before you push. There is no PR CI during the beta (ADR-0002). The pre-push hook runs lint, vet, race tests, `go mod verify` and `govulncheck`.
- The Go toolchain is pinned by the `toolchain` line in `go.mod`; `mise.toml` mirrors that version for mise users. Change both together.
- Code under `internal/` and `pkg/` is test-first: add the failing test in the same change.
- Supported platforms are Linux and macOS.

## Tests

- Unit tests live next to the code (`foo.go` → `foo_test.go`).
- Every Go package under `internal/` or `pkg/` has a row in `docs/engineering/testing.md`, added in the same commit as the package.
- `make dod` runs the versioned acceptance harness.

## Repository layout

| Path | Purpose |
|---|---|
| `cmd/ward/` | The single `ward` binary (daemon + CLI) |
| `cmd/wardwasm/` | WebAssembly build of the detector and decision path for the browser demos |
| `cmd/wardtestmodel/`, `cmd/wardtestdot/` | Test siblings: deterministic classifier, DoT upstream |
| `internal/` | Implementation; not API-stable |
| `pkg/` | Public Go API: classifier contract, decision schema, lexical detector |
| `plugins/` | Integrations and connectors (empty today) |
| `scripts/` | Repo tooling and the DoD harness |
| `deploy/`, `web/` | Placeholders for packaging and a future dashboard |
| `docs/` | Product, engineering, design docs |

## Licensing of contributions

The whole repository is licensed under the [Apache License 2.0](LICENSE) (SPDX `Apache-2.0`); `NOTICE` carries the copyright line and third-party attributions. Contributions are accepted under the same licence: inbound = outbound, as Apache-2.0 §5 describes. The DCO sign-off is the only paperwork; there is no separate contributor agreement. Every Go file starts with `// SPDX-License-Identifier: Apache-2.0`, and `make check` enforces it.

## Security

Do not file public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
