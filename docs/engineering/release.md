# Release Process

The release process for Protocol Ward. Three gates: one automated, one manual, and one for publishing the public repository.

> **Status:** public beta. Gates 1 and 3 apply to every publish of the public repository; Gate 2 applies to tagged releases.

## Gate 1 — `make dod` (automated)

The versioned acceptance harness. See [`docs/engineering/definition-of-done.md`](definition-of-done.md). Every bullet PASS, exit 0. Run from a fresh clone (or `make distclean && make bootstrap && make dod`) to prove no working-tree pollution.

## Gate 2 — Mac mini rig run (manual)

Per ADR-0001 D7 as amended by ADR-0007, the rig run gates **tagged releases**, not repository visibility. The harness cannot verify it; an operator does.

### Rig checklist (v0.1 — fill in as bullets land)

- [ ] **Fresh clone** of `main` on the Mac mini, `make bootstrap`, `make ci` green.
- [ ] **`make dod`** green (gate 1).
- [ ] **DNS forwarder mode** — router DHCP advertises the mini's IP as DNS. Verify a phone on the same network resolves via ward.
- [ ] **Blocklist hit** — known-tracked hostname (e.g. an ads CDN you actually use) returns the configured block_response from a phone, with attribution visible in `ward` logs.
- [ ] **Allowlist override** — a hostname added to the local allowlist forwards instead of blocks, attribution visible.
- [ ] **Decoy tripwire** *(blocked-on sub-project 4)* — synthetic decoy hostname resolves to the rig's decoy listener; an alert fires; the alert metadata is visible in the dashboard.
- [ ] **Dashboard reachability** *(blocked-on sub-project 6)* — `http://<mini>:<port>/` loads in a browser on the LAN. Read-only; no auth at MVP+.
- [ ] **Config export hygiene** *(blocked-on sub-project 4)* — `ward config export` from the rig does NOT contain any of the configured decoy hostnames (invariant 6).
- [ ] **Signed update flow** *(blocked-on sub-project 8)* — `ward update check` reaches the update channel, fetches signed TUF metadata, verifies a cosign signature, applies the update. Rollback path also exercised.
- [ ] **Reboot survival** — rig restarts; ward comes back up via `launchd` (or `systemd` if Linux rig variant); first DNS query within 10s of boot.
- [ ] **24-hour soak** — leave it running on the home network for 24 hours. No queries dropped silently; no unexpected log volume; no memory growth visible in `top`.

Sign-off: date + operator name on each checked item.

## Gate 3 — Public repository

The public repository `github.com/ujjaval-verma/protocolward.ai` is published from a single squashed commit of this tree (ADR-0007). Before each publish:

1. `make ci && make dod && make audit` on this tree.
2. On the squashed tree, after `git add -A` (the gates scan tracked files only): `scripts/check-public.sh <dir>` and `scripts/check-spdx.sh <dir>` both exit 0.
3. Author and committer emails on the squashed commit are the maintainer's public address only.

Tagged releases (`v*.*.*`) build with goreleaser and are signed with cosign by `.github/workflows/release.yml`. That is the only GitHub Actions workflow; there is no PR CI (ADR-0002).

Each release archive (`ward_<os>_<arch>.tar.gz`) carries `THIRD_PARTY_LICENSES/`: the licence, NOTICE and PATENTS files of every Go module linked into `ward` on the released platforms, plus the Go standard library's licence, with `MODULES.txt` listing each module and version. The goreleaser `before` hook generates it with `scripts/third-party-licenses.sh` (not committed; gitignored) and fails the release if a linked module has no licence file. `make check` runs `scripts/check-third-party-licenses.sh`, so a dependency without a licence is caught when it is added, not at tag time.
