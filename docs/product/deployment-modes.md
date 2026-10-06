# Deployment Modes

Protocol Ward is planned in five named tiers. Community is what exists today, in public beta. The rest are plans; their scope grows as each phase approaches. Pricing is not published.

| Mode | Audience | Status | Model |
|---|---|---|---|
| **Community** | Homelab, DIY, self-hosters, security-literate individuals | **Public beta** | Apache-2.0, free for any use |
| **Pro** | Privacy-conscious power users; off-LAN device coverage | Planned (v0.3) | Paid services (managed feeds, alert relay, support) on the same Apache-2.0 core |
| **Pro+ (Mesh)** | Multi-device, multi-site personal or small-team coverage | Candidate (Bet 5 in vision.md) | Not decided |
| **SMB** | Small orgs without a SOC | Planned (Phase 2) | Not decided |
| **Enterprise** | Regulated orgs, SOC-equipped | Planned (Phase 3) | Commercial add-ons, support and managed services |

## Community (public beta)

Configured with one YAML file and the `ward` CLI.

- Fast-path DNS blocking from hosts-format lists (entries with `0.0.0.0`, `127.0.0.1` or `0` sinks) and AdGuard `||host^` lines. Domain-only lists, IPv6 sinks and inline comments are not accepted yet.
- Allowlist precedence
- Decoy tripwire hostnames, never exported by `ward config export`
- On-device lexical hostname detector: **flag-only** in beta. It analyses each hostname that misses your lists today; timing and per-device history are coming soon.
- Read-only web dashboard
- Offline verification of a signed update fixture (`ward update verify <dir>`: TUF metadata and cosign signature checks); a live update client is planned
- Platforms: Linux and macOS (Windows planned)
- Install: `go install protocolward.ai/ward/cmd/ward@latest`

Coming soon: enforcement mode, local LLM explainer, curated default blocklist bundle, and packaging (container image, Helm chart, Ansible role, Pi 5 image, macOS package, Home Assistant add-on).

## Pro (planned)

Everything in Community, plus:

- **Managed signed threat-intel feed.** Curated, signed, refreshed through the same pull-only channel as everything else.
- **Opt-in alert relay.** Push alerts to a phone or webhook without exposing inbound ports on the home appliance. It carries **alert metadata only**, as defined in invariant 4, and no flow data.
- **Roaming Mode (v0.3).** A laptop runs the same Go daemon. Off-LAN, it tunnels DNS back to the home appliance over WireGuard, and the home appliance stays authoritative. Key handling is Headscale-compatible, so it can grow into a mesh.
- **Native macOS client (Phase 2).** SwiftUI + Network Extension content filter with the Go core as an XPC engine. It works even with no home appliance.

## Pro+ Mesh (candidate, not committed)

Generalizes Pro Roaming to many devices and sites under one policy, via a WireGuard mesh with a coordination plane: Headscale integration, a partner, or a thin control plane of our own. Scope is deferred until Roaming has usage signal (Bet 5 in vision.md). Invariant 4 applies unchanged.

## SMB (Phase 2, planned)

Per vision.md, "What We Ship First", Phase 2: policy-mediated local-agent bridge, managed-CA TLS inspection, guided onboarding, dashboard-first UX, MLX-backed model adapter.

## Enterprise (Phase 3, planned)

Per vision.md, Phase 3: SSO/SAML, RBAC, SIEM connectors, FIPS-validated builds, SBOM, SLSA Level 3, air-gapped update bundles. Opt-in sharing of alert metadata between deployments is a candidate research track, never flow data. Enterprise is sold as commercial add-ons, support and managed services; the core stays Apache-2.0 (ADR-0007).
