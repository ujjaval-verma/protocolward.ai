# ADR-0002 — Security Posture (CI, Hooks, Vuln Scanning, Package Managers)

- **Status:** Accepted
- **Date:** 2026-05-22
- **Author:** Ujjaval Verma
- **Supersedes:** the CI workflow scaffolded in sub-project 0 (removed in this ADR)
- **Related:** ADR-0001 (foundation design)
- **Amended:** 2026-10-05 — PR CI stays deferred past the public beta (operator decision; see §1 and ADR-0007)
- **Amended:** 2026-10-20 — invariant gates (public-content, SPDX, testing-doc, third-party licences, wasm compile + size) added to pre-push (§2)
- **Amended:** 2026-10-20 — pre-push runs the full race suite; lint, vet, tests and the wasm gate run concurrently; the 20 s budget is defined cold (§2)
- **Amended:** 2026-10-20 — nightly post-merge verification of `main` on GitHub Actions (`nightly.yml`); replaces the local launchd step of the re-evaluation ladder (§1, §2; issue #11)
- **Amended:** 2026-10-21 — GitHub repository settings: secret scanning and push protection on; Actions restricted to an allowlist with SHA pinning required (§1; issue #12)
- **Amended:** 2026-10-23 — Actions SHA-pin gate (check-actions-pinned) in make check and on pre-push (§1, §2; issue #42)
- **Amended:** 2026-10-23 — Dependabot alerts and private vulnerability reporting on; automated security-update PRs off (§1, §4; issue #41)

## Context

Protocol Ward is a security-positioned product whose thesis is supply-chain awareness (`docs/product/pitch.md`). Pre-public, the project is solo-developed; a GitHub Actions workflow running on every push is theater without value. Locally enforced hooks and disciplined tooling deliver the actual security guarantees.

This ADR captures the policies that determine when and how code is validated against current CVEs, package-manager pinning, and the path from local enforcement to public-repo CI.

## Decision

### 1. No PR CI; workflows run only on release tags and a nightly schedule

`.github/workflows/` holds two workflows. `release.yml` runs only on `v*.*.*` tags (goreleaser + cosign). `nightly.yml` re-verifies `main` after merge (see the 2026-10-20 amendment below). Nothing runs on pushes or pull requests, and no workflow is a required check. All validation before merge happens locally via git hooks and `make ci`.

**Amendment (2026-10-05).** The original text deferred CI to sub-project 8 and expected a successor ADR to add CI as required checks when the repository went public. On 2026-10-05 the operator decided to go public as a beta **without** PR CI. Local hooks and `make ci` remain the gate for every change, and contributors run them (CONTRIBUTING.md). PR CI is reconsidered when outside contributions arrive (see Revisit conditions). No successor ADR is needed for the beta.

**Amendment (2026-10-20, issue #11).** Merged pull requests and web edits were never re-verified after merge, and `make dod`, the wasm smoke test and a goreleaser build ran only by hand or at tag time. `.github/workflows/nightly.yml` now runs against `main` on a daily cron and on `workflow_dispatch`. It detects breakage after merge; it is never a required check and never gates a merge, so the pre-push hook and `make ci` remain the gate. When `main` is unchanged since the workflow's last successful run, only `govulncheck` runs, because the vulnerability database is then the only input that changed. Otherwise it runs `make ci`, `make audit`, `make wasm-smoke`, `make dod` and a goreleaser snapshot build that neither publishes nor signs. The workflow sets `permissions: {}` at the top level and grants each job only what it uses (`actions: read` to find the last successful run, `contents: read` to check out, `issues: write` to report). Every action is pinned by full commit SHA, and no secrets are used. A failing run opens one issue labelled `ci:nightly-failure`; later failures comment on that issue, and the next green run closes it. GitHub disables scheduled workflows in a public repository after 60 days without repository activity, so the release checklist (`docs/engineering/release.md`) confirms the workflow is enabled and its last run was green.

**Amendment (2026-10-21, issue #12).** Two free protections for public repositories were off, and Actions could run any action at any ref. The maintainer set the following through the REST API on 2026-10-21; anyone with admin access can read them back:

- Secret scanning and push protection are enabled (`security_and_analysis.secret_scanning` and `secret_scanning_push_protection`). A push that contains a detected provider secret is blocked; bypassing it records a reason. Non-provider patterns and validity checks stay off.
- Actions may run only selected actions (`allowed_actions: selected`): actions owned by GitHub (`github_owned_allowed: true`) plus `sigstore/cosign-installer@*` and `goreleaser/goreleaser-action@*`, which `release.yml` uses. Actions from Marketplace verified creators are not allowed (`verified_allowed: false`).
- SHA pinning is required (`sha_pinning_required: true`): a `uses:` reference that is not a full commit SHA fails at job setup. This turns the existing practice of pinning by SHA into a rule GitHub enforces. The `check-actions-pinned` gate (issue #42) now catches an unpinned `uses:` in `make check` and on pre-push, before the push, rather than only at job setup.
- The default `GITHUB_TOKEN` permission stays read-only and cannot approve pull requests (unchanged).

Neither workflow needed a change. Every `uses:` was already a full commit SHA and every action is on the allowlist. A `workflow_dispatch` run of `nightly.yml` with `force_full=true` on `main` after the go1.26.10 toolchain bump (run 39665246214) succeeded in every job, including the full verify job, under the policy. `release.yml` runs only on tags, so it could not be dispatched. Reading it shows its four actions (`actions/checkout`, `actions/setup-go`, `sigstore/cosign-installer`, `goreleaser/goreleaser-action`) are all pinned by full SHA and matched by the allowlist. The first real tag is the live proof. The patterns allow any ref, so bumping a pinned SHA needs no settings change, while adding an action does.

To add a new third-party action, pin it by full commit SHA in the workflow and add an `owner/repo@*` pattern to `patterns_allowed` through `PUT repos/{owner}/{repo}/actions/permissions/selected-actions` (send the full list; the call replaces it). To read the current settings: `gh api repos/{owner}/{repo}/actions/permissions`, `gh api repos/{owner}/{repo}/actions/permissions/selected-actions` and `gh api repos/{owner}/{repo} --jq .security_and_analysis`.

**Amendment (2026-10-23, issue #41).** Dependabot alerts and private vulnerability reporting were off. The maintainer approved enabling both on 2026-10-22, and they were applied through the REST API on 2026-10-23:

- Dependabot alerts are enabled. Read back with `gh api -i repos/{owner}/{repo}/vulnerability-alerts` (HTTP 204 means on).
- Private vulnerability reporting is enabled. Read back with `gh api repos/{owner}/{repo}/private-vulnerability-reporting` (`{"enabled":true}`). Reporters use "Report a vulnerability" on the Security tab, and `SECURITY.md` points to it as the preferred channel.
- Automated security-update PRs stay off. Read back with `gh api repos/{owner}/{repo} --jq .security_and_analysis.dependabot_security_updates.status` (`disabled`). With no PR CI, nothing would gate the PRs Dependabot opens, so the maintainer triages alerts by hand. There is no release-checklist gate for alerts.

### 2. Hook tiering with strict latency budgets

| Stage | Budget | Contents |
|---|---|---|
| pre-commit | ≤5s | trailing-ws, eof-fix, check-yaml/json, large-file, merge-conflict, mixed-line-ending, go-fmt, codespell |
| pre-push | ≤20s cold | go mod tidy -diff, golangci-lint + go vet + full `go test -race` (`make test`) + wasm compile and 5 MB size gate (one hook, `make -j4`), go mod verify, **`govulncheck`**, check-public, check-spdx, check-testing-doc, check-licenses, check-actions-pinned |
| `make audit` (manual, pre-release) | unbounded | full `go test -race`, future syft+grype SBOM, future cosign verify of update-channel artifacts, pnpm audit signatures (when web exists) |

Note (2026-10-06): `make audit` today runs `go mod verify`, govulncheck and `goreleaser check`; the full race suite runs in `make ci`, and pnpm audit runs in `make audit` once a lockfile exists, not on pre-push.

Note (2026-10-20): the invariant gates run on pre-push through the same Make targets `make check`/`make ci` use, so the two cannot drift. Measured warm cost is about 2 s. They check the checked-out working tree (including untracked files), not the pushed commits; `make ci` on the commit you push remains the gate.

Note (2026-10-20, issue #25): the pre-push budget is measured cold, meaning empty Go build and golangci-lint caches (equivalent to `go clean -cache` plus `golangci-lint cache clean`), with the module cache and hook environments warm, on the maintainer's Apple M5 Pro. Measured 17.3/17.5/18.4 s cold, 8.8/9.0 s warm (was about 27 s cold). The hook runs the full race suite through `make test`, so the hook and `make ci` share one test timeout (`TEST_TIMEOUT`).

Note (2026-10-23, issue #42): `check-actions-pinned` is a pre-push hook through the same Make target `make check` uses (`make check-actions-pinned`: its self-test, then the scan of `.github/workflows` and `.github/actions` for a `uses:` that is not a full commit SHA). Measured warm cost is 0.46 to 0.47 s. Cold pre-push, same definition as the issue #25 note and taken on the same machine, three runs each: 18.4/17.5/18.5 s before the hook, 17.9/17.7/18.1 s with it. The difference is inside run-to-run variance, because the gate needs no Go build or lint cache, so it costs the same cold as warm; it stays under the 20 s budget.

Re-evaluation ladder if pre-push exceeds 20s sustainably:

1. Move the full race suite off pre-push to `make ci` only, keeping a fast subset on pre-push.
2. Once the repo is public, move the heaviest checks into a pre-merge GitHub workflow as required checks.
3. Last resort: move the slowest remaining pre-push checks to the nightly workflow (§1, `nightly.yml`), which already runs `make ci`, `make audit` and `make dod` against `main`. This trades detection before push for detection within a day of merge.

Note (2026-10-20, issue #11): step 3 previously read "nightly local launchd job runs `make audit` against HEAD". The nightly GitHub workflow replaces it: it runs on a clean machine rather than one checkout, verifies `main` rather than a local HEAD, and reports a failure as a repository issue rather than on one laptop.

### 3. `git push --no-verify` is a policy violation

The pre-push hook is the only enforcement point until public-repo CI exists. Bypassing it via `--no-verify` is a deliberate violation of this ADR; the committer is on the hook to manually run `make ci && make audit` before the next push, and to roll back the bypassed push if either fails.

### 4. Vulnerability scanning

**Go:** `govulncheck` (golang.org/x/vuln) — call-graph aware, fewer false positives than SBOM scanners. Pinned in `.tools/` via `GOVULNCHECK_VERSION` in the Makefile. `gosec` continues to run as a golangci-lint linter for static SAST. Dependabot alerts (§1 amendment of 2026-10-23) complement it: they flag any vulnerable dependency version in the Go modules listed in `go.mod`, whether or not the code reaches it. JS manifests are covered once `web/` or `site/` declare dependencies. Actions pinned by full commit SHA (§1, issue #12) get no Dependabot alerts, because GitHub only alerts for actions referenced by a semantic version. `govulncheck` stays the call-graph gate.

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

- Pre-push becomes mildly slower (about 9 s warm and 18 s cold as of 2026-10-20, ≤20s cold budget) — acceptable for the supply-chain guarantee.
- The `check-actions-pinned` gate adds about 0.5 s to pre-push (a few lines of bash over the workflow files, no build cache involved) and means an unpinned `uses:` is caught before the push instead of only at job setup.
- Solo dev can choose to bypass with `--no-verify`; that is a documented policy violation, not an accident.
- No green-checkmark hygiene burden on GitHub; contributors run `make ci` locally.
- A nightly workflow re-verifies `main` after merge. It costs a few runner-minutes on days `main` changed and a minute or two otherwise (free for a public repository). A failure surfaces as one open `ci:nightly-failure` issue, not as a red check on a pull request, so a break can sit on `main` for up to a day.
- If the repository sees no activity for 60 days, GitHub disables the nightly schedule. It is re-enabled by hand (`gh workflow enable nightly.yml`); the release checklist catches it.
- Adding a third-party action now needs a repository setting change as well as a workflow change, and an unpinned `uses:` fails at job setup rather than in review. Both are deliberate.
- Dependabot alerts surface in the Security tab and open no PRs, so there is nothing to gate. Vulnerability reports arrive privately as draft security advisories rather than public issues.
- Re-introducing PR CI later means adding a `pull_request` trigger that runs `make ci` with the policies captured here as required checks; `nightly.yml` already runs the same targets on `main`.

## Revisit conditions

- Pre-push latency exceeds 20s for ≥2 consecutive weeks on a cold push (empty Go build and lint caches).
- A CVE arrives that `govulncheck` does not detect but `grype` or Socket.dev would have. Pulls SBOM tooling into pre-push.
- Bun, Deno, or another runtime gains a credible security track record (Sigstore-equivalent provenance, formal audits) that justifies a swap. ≥18 months sustained signal required.
- Outside pull requests arrive faster than local review can keep up with. (The repository going public on 2026-10-05 was considered and did not by itself trigger CI; see the §1 amendment.)
- The nightly workflow catches, within one month, two breaks on `main` that a pre-merge check would have caught. Pulls PR CI forward.
- PR CI exists. Reconsider automated Dependabot security-update PRs then, since checks could gate them.
- A Dependabot alert stays open and unread for more than a release cycle. Set a triage cadence or add a release-checklist check then.

## References

- `Makefile` — `make audit` ladder; `.tools/govulncheck` install target
- `.github/workflows/nightly.yml` — nightly post-merge verification of `main` (§1 amendment of 2026-10-20)
- GitHub repository settings (Actions permissions, secret scanning; Dependabot alerts, private vulnerability reporting): recorded in the §1 amendments of 2026-10-21 and 2026-10-23 (issues #12, #41); not in version control
- `.pre-commit-config.yaml` — hook tiering
- `package.json`, `.npmrc`, `.nvmrc`, `pnpm-workspace.yaml` — pnpm + Node enforcement
- `docs/product/pitch.md` — supply-chain attack thesis this posture defends against
