# Release Process

The release process for Protocol Ward. Every change to `main` passes the local gates; every tag passes Gate 1. A GA (non-prerelease) tag also needs the manual rig run (Gate 2).

> **Status:** public beta. Development happens in this public repository.
>
> | Tag kind | Example | Gates |
> |---|---|---|
> | Beta (pre-release) | `v0.2.0-beta.2` | Gate 1 (`make ci && make dod && make audit`) |
> | GA | `v0.2.0` | Gate 1 **and** Gate 2 (Mac mini rig run) |
>
> goreleaser publishes any tag with a pre-release suffix (`-beta.N`, `-rc.N`) as a GitHub pre-release (`prerelease: auto` in `.goreleaser.yaml`).
>
> `v0.2.0-beta.1` was tagged but never released: its release run failed at signing. `v0.2.0-beta.2` superseded it as the first release (2026-10-07).

## Gate 1 — `make ci && make dod && make audit` (automated; every tag)

- `make ci`: lint, vet, race tests, testing-doc, SPDX, public-content and third-party-licence gates, build, js/wasm compile and 5 MB size gate. The release workflow runs it again on the tag.
- `make dod`: the versioned acceptance harness ([`definition-of-done.md`](definition-of-done.md)). Every bullet PASS, exit 0.
- `make audit`: `go mod verify`, govulncheck, `goreleaser check`.

Run from a fresh clone (or `make distclean && make bootstrap`) on the commit you are about to tag, to prove no working-tree pollution. This gate is sufficient for a beta (pre-release) tag.

## Gate 2 — Mac mini rig run (manual; GA tags only)

Per ADR-0001 D7 as amended by ADR-0007, the rig run gates releases, not repository visibility. It is required before a GA (non-prerelease) tag such as `v0.2.0`; beta and release-candidate tags (`-beta.N`, `-rc.N`) ship on Gate 1 alone. The harness cannot verify the rig run; an operator does.

### Rig checklist (v0.2)

- [ ] **Fresh clone** of `main` on the Mac mini, `make bootstrap`, `make ci` green.
- [ ] **Gate 1** green on the rig (`make dod` and `make audit`; `make ci` is the item above).
- [ ] **DNS forwarder mode** — router DHCP advertises the mini's IP as DNS. Verify a phone on the same network resolves via ward.
- [ ] **Blocklist hit** — known-tracked hostname (e.g. an ads CDN you actually use) returns the configured block_response from a phone, with attribution visible in `ward` logs.
- [ ] **Allowlist override** — a hostname added to the local allowlist forwards instead of blocks, attribution visible.
- [ ] **Decoy tripwire** — a phone queries a configured decoy hostname: it gets the configured block response, `ward` logs a `policy: alert` line with the decoy ID, and the dashboard's recent-decisions table shows a `decoy` row.
- [ ] **Dashboard reachability** — on the mini (or through `ssh -L 18987:127.0.0.1:18987 <mini>`), `http://127.0.0.1:18987/` loads and shows recent decisions and flags. Confirm it is NOT reachable at `http://<mini-LAN-IP>:18987/` from another LAN device (loopback-only, invariant 4). Read-only; no auth.
- [ ] **Config export hygiene** — `ward config export` from the rig does NOT contain any of the configured decoy hostnames (invariant 6).
- [ ] **Update verifier** — `ward update verify testdata/update/v0.1-good` passes on the rig binary and `ward update verify testdata/update/v0.1-tampered-target` fails.
- [ ] **Signed update flow** *(not built yet: `ward update fetch` and `ward update apply` are planned)* — fetch signed TUF metadata from the update channel, verify the cosign signature, apply the update, exercise the rollback path.
- [ ] **Reboot survival** *(not built yet: no `launchd` plist or `systemd` unit ships in `deploy/`)* — rig restarts; ward comes back up via `launchd` (or `systemd` if Linux rig variant); first DNS query within 10s of boot.
- [ ] **24-hour soak** — leave it running on the home network for 24 hours. No queries dropped silently; no unexpected log volume; no memory growth visible in `top`.

Sign-off: date + operator name on each checked item.

## Every change to `main`

This repository is the development repository; there is no separate publish step. The public repository was created on 2026-10-06 from one squashed commit of the earlier private tree (ADR-0007); that was a one-time launch.

1. `make ci` passes before you push (the pre-push hook runs a fast subset; `make ci` also runs the SPDX, public-content and third-party-licence gates (`scripts/check-spdx.sh`, `scripts/check-public.sh`, `scripts/check-third-party-licenses.sh`)).
2. Every commit carries a DCO sign-off (`git commit -s`; `CONTRIBUTING.md`).

## Tagged release build

Tagged releases (`v*.*.*`) build with goreleaser and are signed with cosign by `.github/workflows/release.yml`. That is the only GitHub Actions workflow; there is no PR CI (ADR-0002).

Each release archive (`ward_<os>_<arch>.tar.gz`) carries `THIRD_PARTY_LICENSES/`: the licence, NOTICE and PATENTS files of every Go module linked into `ward` on the released platforms, plus the Go standard library's licence, with `MODULES.txt` listing each module and version. The goreleaser `before` hook generates it with `scripts/third-party-licenses.sh` (not committed; gitignored) and fails the release if a linked module has no licence file. `make check` runs `scripts/check-third-party-licenses.sh`, so a dependency without a licence is caught when it is added, not at tag time.

### Verifying a release

`checksums.txt` is signed keylessly with cosign v3 in the release workflow. The signature, the short-lived signing certificate and the transparency-log entry are in one Sigstore bundle, `checksums.txt.sigstore.json`. To verify a release, download `checksums.txt`, `checksums.txt.sigstore.json` and the archive you want from the release page, then:

```sh
TAG=v0.2.0-beta.2   # the release you downloaded
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/ujjaval-verma/protocolward.ai/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt      # Linux
shasum -a 256 --ignore-missing -c checksums.txt  # macOS
```

`cosign verify-blob` must print `Verified OK`, and the checksum line for your archive must say `OK`. The release workflow signs with cosign v3.0.6; verify with cosign v3.
