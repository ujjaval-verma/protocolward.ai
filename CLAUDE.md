# Guidance for AI coding agents (and humans) in this repository

Claude Code and similar agents load this file automatically. It holds the rules that every contributor follows, human or agent. Personal workflow belongs in an untracked `CLAUDE.local.md` (gitignored).

## How to work here

- **Test first** for anything under `internal/` or `pkg/`: write the failing test, watch it fail, make it pass. Empty skeleton packages are exempt only until their first behaviour lands.
- **Evidence before claims.** `make ci` must pass before you say a change is done. Paste the command and its result.
- **Small slices.** Aim for at most 8 tasks, or at most 3 production Go files under `internal/` + `pkg/`, per change, whichever comes first. If a change would exceed that, split it. Two clean changes review faster than one wide one. A purely mechanical change, like a rename or a header across all files, is the exception; say so in the commit message.
- **Optional review templates.** `docs/engineering/spec-review.md` (before code) and `docs/engineering/code-review.md` (before push) are the adversarial review prompts the maintainer uses. They work with any agent.
- Design notes, plans and review reports go in `docs/superpowers/`. That directory is gitignored and local-only; the name follows the superpowers Claude Code plugin's convention. Never cite a file there from tracked docs or code. `make check` fails if you do (`scripts/check-public.sh`).

## Repository invariants (non-negotiable)

- **The AI is a classifier, never a decider.** Detector and model outputs are typed (`pkg/schema`); the deterministic policy engine (`internal/policy`) chooses actions. In the public beta, detector verdicts are flagged, never enforced.
- **No flow data leaves the device.** At any tier. Pro = managed feeds + opt-in alert relay (alert metadata only, as defined in invariant 4) + support (+ Roaming, planned). Pro+ Mesh is a candidate, not committed.
- **Update channel is pull-only.** The device initiates; no inbound connections on the update path.
- **Decoys never appear in config exports** or any shareable artifact.
- **No silent drops** by default. Every block carries user-visible attribution and a one-click allowlist override (invariant 7; the one-click override is not built yet, so until it is, an allowlist entry is the override).
- **No Electron. No Viper.** See `docs/engineering/invariants.md` (Anti-goals).
- **Every Go package under `internal/` or `pkg/` has a row in `docs/engineering/testing.md`**, added in the same commit as the package. Enforced by `scripts/check-testing-doc.sh`.
- **Every Go file starts with `// SPDX-License-Identifier: Apache-2.0`.** The whole repository is Apache-2.0 (`LICENSE`, `NOTICE`). Enforced by `scripts/check-spdx.sh`.

## Where things live

- Product: `docs/product/vision.md` (direction), `docs/product/pitch.md`, `docs/product/deployment-modes.md`
- Architecture and invariants: `docs/engineering/architecture.md`, `docs/engineering/invariants.md`
- Decisions: `docs/engineering/decisions/ADR-NNNN-*.md`
- Brand: `DESIGN.md`; mascot brief `docs/design/mascot.md` (pose canon includes Flight (dorsal), used by the README header, protocolward.ai hero and docs 404; perched-watching is planned, no asset; the Hover motif maps to `pkg/detect` today; tagline #1 is the README headline, and product descriptors are not taglines)
- User docs and demos: https://protocolward.ai (separate repository)

## Dev loop

```
make bootstrap  # one-time: pinned tools into .tools/ + pre-commit and pre-push hooks
make help       # all targets, by section
make check      # lint + vet + test + testing-doc + spdx + public-content + third-party-licence gate
make ci         # check + build + wasm compile/size gate (run before pushing; there is no PR CI)
make test       # tests with race detector
make lint       # golangci-lint (pinned)
make fmt        # gofumpt -w
make vuln       # govulncheck (also runs on pre-push)
make audit      # pre-release: go mod verify + govulncheck + goreleaser check
make build      # bin/ward
make wasm       # dist/wasm/ward.wasm for the browser demos
make dod        # v0.2 Definition of Done harness
```

Targets are quiet by default; pass `V=1` for full commands.

**Go toolchain pin.** The `toolchain` line in `go.mod` is authoritative (`go` and the release workflow read it). `mise.toml` pins the same Go version for mise users. Bump both in the same commit.

## Definition of Done

`make dod` is the versioned acceptance gate (`docs/engineering/definition-of-done.md`, runner `scripts/dod.sh`). The current target is v0.2. It exits 0 only when every v0.2 bullet passes. **Do not relax a bullet to make it green.** Either ship the feature or do not claim the version.

## Security posture

See `docs/engineering/decisions/ADR-0002-security-posture.md`. In short:

- **No PR CI during the public beta.** Local hooks are the enforcement: pre-commit ≤ 5 s, pre-push ≤ 20 s (`go mod tidy`, lint, vet, `go test -race -short`, `go mod verify`, `govulncheck`).
- **`git push --no-verify` is a policy violation.** If you bypass, run `make ci && make audit` by hand and roll back if either fails.
- **JS/TS: pnpm only**, Node 24 LTS, `engine-strict=true`, `onlyBuiltDependencies: []`.

## Commits

Conventional commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`). **DCO sign-off is required** (`git commit -s`); see `CONTRIBUTING.md`.

## Dates

All authored dates are UTC: ADR `Date:` lines and any date in `docs/`.
