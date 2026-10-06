# ADR-0002 — Security Posture (CI, Hooks, Vuln Scanning, Package Managers)

- **Status:** Accepted
- **Date:** 2026-05-22
- **Author:** Ujjaval Verma
- **Supersedes:** the CI workflow scaffolded in sub-project 0 (removed in this ADR)
- **Related:** ADR-0001 (foundation design)
- **Amended:** 2026-10-05 — PR CI stays deferred past the public beta (operator decision; see §1 and ADR-0007)

## Context

Protocol Ward is a security-positioned product whose thesis is supply-chain awareness (`docs/product/pitch.md`). Pre-public, the project is solo-developed; a GitHub Actions workflow running on every push is theater without value. Locally enforced hooks and disciplined tooling deliver the actual security guarantees.

This ADR captures the policies that determine when and how code is validated against current CVEs, package-manager pinning, and the path from local enforcement to public-repo CI.

## Decision

### 1. No PR CI; the tag-triggered release workflow is the only workflow

`.github/workflows/` holds one workflow, `release.yml`, which runs only on `v*.*.*` tags (goreleaser + cosign). Nothing runs on pushes or pull requests. All validation happens locally via git hooks and `make ci`.

**Amendment (2026-10-05).** The original text deferred CI to sub-project 8 and expected a successor ADR to add CI as required checks when the repository went public. On 2026-10-05 the operator decided to go public as a beta **without** PR CI. Local hooks and `make ci` remain the gate for every change, and contributors run them (CONTRIBUTING.md). PR CI is reconsidered when outside contributions arrive (see Revisit conditions). No successor ADR is needed for the beta.

### 2. Hook tiering with strict latency budgets

| Stage | Budget | Contents |
|---|---|---|
| pre-commit | ≤5s | trailing-ws, eof-fix, check-yaml/json, large-file, merge-conflict, mixed-line-ending, go-fmt, codespell |
| pre-push | ≤20s | golangci-lint, go vet, `go test -race -short`, go mod tidy, go mod verify, **`govulncheck`** |
| `make audit` (manual, pre-release) | unbounded | full `go test -race`, future syft+grype SBOM, future cosign verify of update-channel artifacts, pnpm audit signatures (when web exists) |

Re-evaluation ladder if pre-push exceeds 20s sustainably:

1. Split `go test -race -short` (pre-push) from `go test -race` full (audit-only).
2. Once the repo is public, move the heaviest checks into a pre-merge GitHub workflow as required checks.
3. Last resort: nightly local launchd job runs `make audit` against HEAD.

### 3. `git push --no-verify` is a policy violation

The pre-push hook is the only enforcement point until public-repo CI exists. Bypassing it via `--no-verify` is a deliberate violation of this ADR; the committer is on the hook to manually run `make ci && make audit` before the next push, and to roll back the bypassed push if either fails.

### 4. Vulnerability scanning

**Go:** `govulncheck` (golang.org/x/vuln) — call-graph aware, fewer false positives than SBOM scanners. Pinned in `.tools/` via `GOVULNCHECK_VERSION` in the Makefile. `gosec` continues to run as a golangci-lint linter for static SAST.

**JS/TS (once `web/` and `site/` package.json files exist):** `pnpm audit --audit-level=moderate` + **`pnpm audit signatures`** (verifies npm provenance attestations — the supply-chain defense most repos skip). Both run on pre-push via the `make audit` recipe.

**Deferred to sub-project 8 (release pipeline):** `syft`-generated SBOM, `grype` CVE scan, `cosign` signing, SLSA Level 3 attestation. Day-to-day, govulncheck + pnpm audit signatures are sufficient.

### 5. Package manager: pnpm only; runtime: Node 24 LTS

**Rejected alternatives:**

- **Bun (Oven Inc):** Fast, integrated, but a security-positioned product should not bet on a young runtime where threat-model surface and audit history are still maturing. Reconsider in 2027.
- **Deno:** Best security model (capability-based permissions), but the npm-compat layer adds friction for a stack built on shadcn / Astro / React (both Node-first). Worth considering for any standalone CLI utility we ship later.
- **Yarn Berry:** PnP is a strict-isolation win, but cybersec/devops momentum has shifted to pnpm.

**Enforcement:**

- `packageManager: pnpm@9.15.0` in root `package.json` — corepack rejects `npm install` for any contributor.
- `engines.node >= 24.0.0` + `.nvmrc` pinned to `24` (Node 24 LTS "Krypton", Active LTS since 2025-10-28).
- `.npmrc` sets `engine-strict=true`, `audit-level=moderate`, `node-linker=isolated`, registry pinned to `https://registry.npmjs.org/`.
- `onlyBuiltDependencies: []` — every package needing postinstall must be explicitly added to the allowlist. Directly mitigates the axios / TanStack attack class described in `docs/product/pitch.md`.

### 6. Future capability-based runtime sandboxing

When `web/` or `site/` ship real build pipelines, evaluate Node 24's `--permission` mode for build-time script isolation. Not required for v0.1; revisit when JS surfaces are non-trivial.

## Consequences

- Pre-push becomes mildly slower (5–10s typical, ≤20s budget) — acceptable for the supply-chain guarantee.
- Solo dev can choose to bypass with `--no-verify`; that is a documented policy violation, not an accident.
- No green-checkmark hygiene burden on GitHub; contributors run `make ci` locally.
- Re-introducing PR CI later means adding a workflow that runs `make ci` with the policies captured here as required checks.

## Revisit conditions

- Pre-push latency exceeds 20s for ≥2 consecutive weeks on a fresh-tree push.
- A CVE arrives that `govulncheck` does not detect but `grype` or Socket.dev would have. Pulls SBOM tooling into pre-push.
- Bun, Deno, or another runtime gains a credible security track record (Sigstore-equivalent provenance, formal audits) that justifies a swap. ≥18 months sustained signal required.
- Outside pull requests arrive faster than local review can keep up with. (The repository going public on 2026-10-05 was considered and did not by itself trigger CI; see the §1 amendment.)

## References

- `Makefile` — `make audit` ladder; `.tools/govulncheck` install target
- `.pre-commit-config.yaml` — hook tiering
- `package.json`, `.npmrc`, `.nvmrc`, `pnpm-workspace.yaml` — pnpm + Node enforcement
- `docs/product/pitch.md` — supply-chain attack thesis this posture defends against
