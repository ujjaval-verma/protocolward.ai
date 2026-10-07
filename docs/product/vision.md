# Protocol Ward — Product Vision (v4)

> **Status:** Draft v4.1, revised 2026-10-06. Supersedes v3.
> **Scope:** This is the product direction, not a description of what ships today. What ships today is in the README roadmap. In the public beta, Ward analyses each hostname that misses your lists on-device; timing and per-device history are coming soon.

## The Bet

The internet is being rebuilt as an API surface for autonomous agents. Agentic traffic grew **7,851%** in 2025 (HUMAN Security, *2026 State of AI Traffic & Cyberthreat Benchmark Report*). Local agents — OpenClaw, MCP servers, LLM browser extensions — are already turning laptops and routers into API brokers for cloud models. For the organizations that care most about what leaves the perimeter (privacy-sensitive SMBs, regulated enterprises, technically-literate home operators), this is a first-order problem, and we have found no on-premises, open-source tool that addresses it.

Static blocklists alone don't work against agents that rotate IPs, adapt payloads, and mimic human requests. Cloud "AI firewalls" don't work for buyers who can't ship raw internal traffic to OpenAI for inspection. The answer is **a sovereign, edge-native traffic proxy that layers curated blocklists, behavioral AI classification, and high-signal decoy detection — running entirely on hardware the operator controls, open-source at the core.**

**Protocol Ward** is software — a hardened Go data plane plus a local open-weights model handling slow-path classification — planned for distribution as a container image, a Helm chart, an Ansible role, and a flashable reference image (coming soon). We will publish validated hardware BOMs. We don't sell the hardware.

## What It Feels Like

*These scenarios describe the destination. Today Ward is a DNS resolver: it sees hostnames, not URL paths, and its behavioral detector flags without blocking (beta).*

**A law firm's partner installs a new AI research extension in their browser.** It quietly enumerates `/api/` endpoints on the internal document management system. Protocol Ward sees an inside-host making sequential, templatic requests to paths that have never been hit from that device before; the Go proxy holds the flow and queues it to the local model. Gemma 4 reads the device's 24-hour history, the request cadence, and the endpoint pattern, and classifies the behavior as programmatic enumeration. The policy engine severs the connection, marks the endpoint as touched by an unauthorized agent, and fires an alert to the SIEM. The partner's browser shows a clear block page — not a silent failure — with a one-click override request routed to IT.

**Your smart TV starts polling a new telemetry endpoint after a firmware update.** Not on any blocklist. Protocol Ward's fast-path cache misses; the slow path classifies the flow as anomalous telemetry (design target: seconds, asynchronously) based on device behavior history and destination metadata. Sunk. Logged. TV keeps working.

**A decoy API endpoint (`/api/admin/backup`) that does not exist in any legitimate application gets hit.** This is a honeytoken — placed by Protocol Ward, documented nowhere, touched only by something enumerating. The proxy fires a high-confidence breach alert on the fast path (design target: sub-millisecond). No model invocation needed: decoys are the cheapest, highest-signal detector in security, and they exploit attacker behavior rather than defender compute. This is the Thinkst Canary insight, applied at the network-proxy layer.

The destination is a three-tier defense model:

- **Static blocklists → fast path (design target: sub-millisecond):** known-bad domains — trackers, malware C2s, phishing infrastructure — are matched against curated, updateable blocklists compiled into the Go proxy's policy cache. Zero model invocation. The design assumption is that this path handles most everyday threats before any model is involved.
- **Behavioral AI → slow path (design target: 1–4 seconds, async; not yet benchmarked):** unknown or ambiguous flows that miss the blocklist are classified on-device. This is the layer aimed at adaptive threats, novel C2 infrastructure, and supply chain payloads phoning home to domains no blocklist has seen yet. Today (beta) Ward analyses each hostname that misses your lists on-device and flags machine-generated-looking names without blocking; timing and per-device history come next, then an optional local LLM explainer (ADR-0006).
- **Decoys → near-zero-false-positive path (design target: sub-millisecond):** decoy hostnames today (endpoint honeytokens arrive with the reverse proxy) that no legitimate traffic ever touches. A hit is an immediate high-confidence alert. No model invocation, no blocklist lookup — this tier exploits attacker behavior rather than defender compute.

## What We're Building

Three layers, cleanly separated.

```
┌─────────────────────────┐
│  External Network       │
│  (Cloud AI, APIs, Web)  │
└────────┬────────────────┘
         │ Inbound/Outbound Traffic
         ▼
┌─────────────────────────┐     ┌──────────────────────┐
│  Protocol Ward Proxy    │────▶│  Policy State Engine │
│  (Go data plane)        │     │  (Deterministic Go)  │
└────────┬────────────────┘     └──────────┬───────────┘
         │ Fast-path routing               │
         ▼                                 ▼
┌─────────────────────────┐     ┌──────────────────────┐
│  Model Runtime          │     │  Local Devices /     │
│  (Open weights, local)  │     │  Internal Services   │
│  Slow path (target 1–4s)│     └──────────────────────┘
└─────────────────────────┘
```

### 1. The Data Plane (Go)

A DNS resolver today, with a reverse proxy planned. Intercepts DNS, plans to inspect available metadata (SNI where visible, TLS handshake fields, DNS query patterns, flow timing, decoy endpoint hits), enforces policy decisions, and is planned to emit structured flow records to the SIEM/log sink of the operator's choice. Fast-path cache hits are designed to route in under one millisecond (design target; not yet benchmarked). Cache misses hand flow context to the intelligence layer.

The fast-path cache is populated from two sources: operator-defined policy rules, and **curated public blocklists** compiled into the cache at startup and refreshed via the signed pull-only update channel. The planned default blocklist bundle covers three categories (today Ward loads any hosts-format or AdGuard-format list the operator configures):

- **Tracking and ads:** [OISD](https://oisd.nl) (big tier), [Hagezi](https://github.com/hagezi/dns-blocklists) (normal tier), EasyPrivacy — covers the long tail of ad networks, trackers, and telemetry endpoints across consumer devices and smart home hardware.
- **Malware and C2:** [URLhaus](https://urlhaus.abuse.ch) (abuse.ch live malware distribution feed), [Feodo Tracker](https://feodotracker.abuse.ch) (botnet and banking trojan C2 infrastructure), [Emerging Threats Open](https://rules.emergingthreats.net) (Proofpoint's open C2/exploit-kit ruleset) — directly relevant to supply chain payloads phoning home.
- **Phishing:** [PhishTank](https://phishtank.org) — community-verified phishing infrastructure.

Blocklists will update daily via the same signed, pull-only channel used for model-weight and policy updates (planned; today `ward update verify` checks signed TUF metadata). The device initiates; no inbound connections are accepted. Operators can add custom lists or suppress individual entries. Today Ward reads hosts-format (`0.0.0.0`/`127.0.0.1`/`0` sinks) and AdGuard `||host^` lists, which covers the hosts-format exports most Pi-hole users already curate; plain one-domain-per-line lists are skipped with a warning and not accepted yet.

**Pi-hole list compatibility is deliberate.** A large share of the target homelab audience already curates Pi-hole blocklists. Protocol Ward aims to be a superset: the same hosts-format lists, plus behavioral analysis for threats the lists haven't seen yet.

### 2. The Intelligence Layer (open-weights, model-abstracted)

The planned reference LLM is **Google Gemma 4 E4B** (released 2 April 2026, Apache 2.0, ~4.5B effective parameters, multimodal, 128k context). In the public beta the shipped classifier is a small on-device lexical detector (`pkg/detect`); an LLM becomes an optional explainer later (ADR-0006). **But the project is not wedded to Gemma.** A model abstraction layer (`pkg/model`) exposes a narrow interface (classify today; summarize and explain are planned) with planned adapters for Gemma, Qwen 3, DeepSeek, Mistral, and any future open-weights model meeting the licensing criteria in §Assumptions and Bets.

Operating context is bounded to **4–8k tokens** for classification (recent device history + current flow). The 128k ceiling is for on-demand forensic analysis, not every packet, and is realistically usable only on the enterprise hardware tier — see §Reference Architectures. Smaller tiers cap practical context at the level their RAM envelope sustains after KV-cache overhead. Nothing phones home. Model weights and policy updates are delivered via a signed, pull-only channel.

### 3. The Policy State Engine

The model is strictly a classifier and summarizer. Its outputs conform to a typed schema and map to hardcoded Go routines. When enforcement ships, a `malicious` verdict maps to a deterministic block and a `telemetry` verdict to a sinkhole answer. In the beta, verdicts are flagged, never enforced. The AI provides context; the state machine executes. This is the project's answer to the "unpredictable LLM in a security loop" objection.

## Deployment Modes

Three personas, three UX surfaces — same core. Pro (paid services) and Pro+ Mesh (a candidate) sit on top of Community and are not separate UX surfaces; the full tier list is in `docs/product/deployment-modes.md`.

| Mode | Persona | Primary UX | Scope |
| --- | --- | --- | --- |
| **Community** | Homelab, DIY, self-hosters | CLI + YAML config files first; web dashboard second | Full core functionality; community-supported |
| **SMB** | Small orgs without a SOC | Web dashboard first; config files compatible | Core + guided onboarding, basic alerting, maintenance updates |
| **Enterprise** | Regulated orgs, SOC-equipped | Dashboard + admin UI first; full config-as-code supported | Core + SSO/SAML, RBAC, SIEM connectors, audit log retention, air-gapped update bundles, FIPS-validated crypto, SLA support |

Both UX surfaces read the same config format. A homelab operator can export their config and hand it to an enterprise admin who opens it in the dashboard. A company can check their dashboard-built config into Git.

## Reference Architectures

Validated hardware configurations with published BOMs, benchmarks, and deployment guides. **We do not sell any of these** — we will publish what works.

| Tier | Reference configuration | RAM | Notes |
| --- | --- | --- | --- |
| **DIY / homelab** | Raspberry Pi 5 + Hailo-10H accelerator (M.2 or HAT-form-factor board) | 8 GB | Design target ~8–11 tok/s on 2–4B quantized; Hailo LLM runtime support is newer than its CNN story, so this number is a design target pending our own benchmarks |
| **DIY / homelab (alt)** | Rockchip RK3588 board (Orange Pi 5 Pro, Radxa Rock 5B+) | 8–16 GB | Community-supported |
| **SMB (NVIDIA edge)** | NVIDIA Jetson Orin Nano (8 GB) | 8 GB | Candidate for E4B-class models; throughput pending our own benchmarks |
| **SMB (Apple Silicon)** | Apple Mac mini (M2 / M3 / M4) | 16–32 GB unified | MLX or Metal-accelerated llama.cpp; strong tokens/watt; macOS host with Docker or native launchd deployment |
| **SMB (x86)** | Intel N100 / N305 or AMD Ryzen AI (7840U, 8845HS, Ryzen AI Max) mini-PC, optionally paired with a Hailo-8/10 accelerator | 16–32 GB | Broad peripheral support; Ryzen AI's integrated NPU materially improves slow-path throughput over N100 |
| **Enterprise (rackmount)** | 1U rackmount with discrete GPU (e.g., RTX A2000 / L4) | 32–64 GB VRAM | Only tier where full 128k context is realistically usable; multi-tenant capable |
| **Enterprise (Apple Silicon)** | Mac Studio (M-series Ultra) | 64–192 GB unified | Alternative to mid-range rackmount GPU for orgs already standardized on Apple hardware; full 128k context usable |

A bare Raspberry Pi 4 is **not** supported — insufficient memory headroom. A Pi 5 without a Hailo accelerator runs via CPU inference (estimate: 3–5 tok/s on 2B quantized, unbenchmarked) and is treated as **experimental**, not a supported reference configuration.

## Threat Model

In scope:
- Outbound telemetry, tracking, and unauthorized data exfiltration from devices on the network
- Inbound probes and scanners targeting local services
- **Local agentic tools** (OpenClaw, MCP servers, LLM browser extensions) calling into internal APIs without declared authorization
- **Lateral movement** detection via decoy endpoints and honeytokens (primitives ship in Phase 1 across all tiers; centralized decoy-placement UX and SIEM correlation are enterprise-first)
- Insider threat patterns (unusual enumeration, off-hours bulk access, agent-driven credential sweep)
- Unauthorized cloud agents polling internal networks via forwarded ports or exposed services
- Local-agent hijacking of the "ClawJacked" kind (Oasis Security, February 2026: a malicious website could brute-force a locally running OpenClaw gateway over a localhost WebSocket; fixed within about a day of disclosure)

Out of scope (explicit):
- Nation-state adversaries with endpoint access
- Decryption of TLS 1.3 + ECH payloads in *community* mode without a user-provisioned CA (supported in *enterprise* mode via managed-CA flow — see §TLS Inspection)
- Supply-chain attacks on model weights (mitigated by signature verification, not detection)
- ISP-level DNS hijacking (surfaced as a diagnostic rather than silently failing)
- Physical tampering with the appliance

## TLS Inspection

**Community mode:** no TLS interception by default. Classification operates on metadata that remains visible in TLS 1.3 + ECH: flow timing, volume, handshake fields where unencrypted, DNS patterns, decoy hits, and cooperative payloads from local agents that route through the proxy intentionally. An opt-in CA-provisioning flow for desktop browsers on operator-owned devices is planned.

**Enterprise / SMB mode — Managed CA mode:** first-class support for TLS interception using the organization's existing enterprise CA, distributed via MDM. Documented integration with Microsoft Intune, Jamf, Kandji, and open-source alternatives (FleetDM, MicroMDM). Deep payload inspection is available on managed devices with declared consent paths. This is standard enterprise practice and removes the main consumer-era objection to DPI.

## Key Risks and How We Handle Them

1. **ECH / DoH / QUIC opacity (community mode).** The external inspection surface is shrinking. Our bet: metadata-plus-behavior classification plus decoy endpoints plus cooperative local-agent integration covers the threat model more honestly than claiming payload DPI on a consumer network.
2. **False positives.** A proxy that breaks production traffic gets uninstalled. Every block carries user-visible attribution today; a per-device allowlist override and a one-click feedback loop that locally retunes policy are planned. No silent drops by default. In enterprise, blocks route through a review queue before enforcement on a configurable fraction of flows.
3. **Model staleness on offline devices.** Signed, pull-only update channel for policy rules, threat signatures, and model-weight deltas. Device initiates; no inbound connection accepted. Updates are auditable and reproducible from public manifests. Enterprise mode adds air-gapped bundle import.
4. **Open-weights license risk.** See §Assumptions and Bets. Model abstraction layer keeps swap cost low.
5. **Edge-model capability plateau.** See §Assumptions and Bets. If capability stops tracking, slow-path accuracy caps our ceiling — not an existential risk, but a roadmap constraint.
6. **Prompt injection against the local classifier.** The slow path consumes attacker-controllable strings — hostnames, User-Agent values, TLS ALPN fields, URI paths on inbound probes — as part of the flow context. A crafted payload could attempt to coerce the classifier into returning a benign label. Mitigations: schema-constrained decoding so outputs can only be a typed enum, input sanitization before the prompt boundary, structural separation of attacker-controlled fields from instruction context, and an adversarial-evaluation suite (`ward eval`) that exercises known injection patterns against each validated adapter. The deterministic policy engine (§3) is the final backstop — a flipped label still has to map to a handler that does something the attacker wants.

## Why the Edge is the Moat

- **Privacy as a precondition.** The buyers who want this tool cannot pipe internal traffic to cloud APIs for analysis. Cloud-native competitors cannot replicate local-only inference without destroying their economics.
- **Fast-path latency the cloud can't touch.** Our design target is sub-millisecond policy decisions, which require the decision engine to sit next to the packets. No roundtrip survives line-rate.
- **Open weights + open source = defensible composition.** Cloud competitors can add "AI traffic analysis" tiers, but they cannot match the combination of on-premises inference + open source + open weights. That tuple is our identity.

## Open Source and Community

Protocol Ward is open source under the **Apache License 2.0, everywhere**: the data plane, policy engine, detector, model runtime integration, dashboard, public Go packages and plugins (ADR-0007, which supersedes ADR-0001 D6). Anyone may use, embed, modify and redistribute it, including commercially and as a hosted service.

- **Open source (Apache-2.0):** everything in this repository. Free for any use, with an explicit patent grant.
- **Pro (paid services):** managed signed threat-intel feeds, the opt-in alert relay (alert metadata only, invariant 4) and support. These are services, not licence terms.
- **Enterprise (commercial add-ons, support and managed services):** SSO/SAML, RBAC, audit log retention, FIPS-validated crypto builds, air-gapped update tooling, SLA support. These are commercial add-ons, support and managed services, not a relicensing of the core; any add-on that cannot be Apache-2.0 ships as a separate module outside this repository, and the core stays Apache-2.0.
- **Governance:** BDFL; an RFC process will be published, and trusted-committer status after sustained contribution. Foundation formation deferred until commercial viability is proven.
- **Contribution:** DCO (`git commit -s`), inbound = outbound: contributions are Apache-2.0, like the project, so no CLA is needed. Public credit for responsible disclosures (a Hall of Fame page is planned). Intent to apply for MITRE CNA status once a coordinated-disclosure track record is established across multiple published CVEs.
- **Security disclosure:** `SECURITY.md` (email `security@protocolward.ai`), 90-day coordinated disclosure, public credit for reporters.

Why Apache-2.0 everywhere: a DNS appliance wins by being embedded by router OEMs, homelab distributions and integrators, and copyleft review blocks exactly those adopters. What earns money here (managed feeds, the relay, support and enterprise operations) is a service that no code licence protects either way. The trade-off is accepted: the permissive release is irreversible, and there is no dual-licensing revenue.

## What We Ship First

### Phase 1 — Community edition (core intent-aware proxy)

Phase 1 ships in versions; ADR-0001 D2 keeps AI out of v0.1.

- **v0.1 (done; pre-public milestone, no tagged release):** Go DNS data plane with fast-path blocklists and allowlists, decoy tripwires, decoy-free config export, `ward` CLI, read-only web dashboard, signed-update verification.
- **v0.2 (done; pre-public milestone, no tagged release):** classifier contract (`pkg/model`, `pkg/schema`), sibling-process model isolation, eval harness.
- **Public beta (now; first tagged release `v0.2.0-beta.1`, a pre-release):** on-device lexical hostname detector (`pkg/detect`), flag-only; in-browser demos at protocolward.ai.
- **Coming soon:** timing and per-device history signals; enforcement of verdicts; a local LLM explainer with a Gemma 4 E4B reference adapter and a second validated adapter (Qwen 3 or DeepSeek); reverse proxy; packaging as a container image (Linux amd64/arm64), Helm chart, Ansible role, flashable Pi 5 image, macOS package and Home Assistant add-on.

### Phase 2 — SMB hardening

- Policy-mediated **local-agent bridge**: typed API surface for OpenClaw, MCP servers, and LLM tools to access internal resources with declared scopes and payload sanitization
- Managed-CA mode for TLS inspection on operator-owned devices (Intune / Jamf / Kandji integrations)
- Signed threat-intelligence subscription for SMB (planned; see the Pro managed feed in `docs/product/deployment-modes.md`)
- **Native macOS client** (Pro): SwiftUI + Network Extension content filter with the Go core as an XPC engine; works with no home appliance (`docs/product/deployment-modes.md`)
- **Validated MLX-backed model adapter for Apple Silicon**: promotes the Mac mini reference tier from "supported" to "recommended" once the adapter clears the full validation gauntlet (schema-constrained decoding, adversarial-eval suite, Bet-1 acceptance criteria, parity benchmarks against the reference Gemma-via-llama.cpp adapter, signed release through the pull-only update channel)
- Guided onboarding flow; dashboard-first UX

### Phase 3 — Enterprise edition

- SSO/SAML, OIDC, RBAC, scoped API tokens
- SIEM connectors (Splunk HEC, Elastic, Panther, OpenSearch, syslog/CEF)
- Audit log retention with tamper-evidence
- FIPS-validated crypto builds; SBOM (SPDX + CycloneDX); SLSA Level 3 attestation target (procurement bar)
- Air-gapped update bundle import / export
- Opt-in sharing of alert metadata (as defined in invariant 4) between deployments: a candidate research track, never flow data

## Assumptions and Bets

Explicit bets, tracked so that when — not if — one breaks, the project has a known re-plan trigger rather than a quiet drift.

### Bet 1 — Open weights with permissive licensing remain available and improve faster than proprietary edge models

- **What we assume:** The open-weights trajectory (Gemma, Qwen, DeepSeek, Mistral, Llama-class) continues. Permissive licensing (Apache 2.0, MIT, BSD) is available somewhere in the set. Edge capability roughly doubles per year for the next 2–3 years before tapering.
- **What we commit to:** Model abstraction layer from day one. Never hard-code to a single model family. Ship at least two validated adapters before the LLM explainer leaves beta.
- **Acceptance criteria for a model:** open weights, OSI-approved permissive license (Apache 2.0 / MIT / BSD preferred), reproducible builds, no user-count caps, fits the target RAM envelope at 4-bit quantization.
- **Break conditions — re-plan if any of these trigger:**
  - No qualifying model within our parameter class released in 12 months
  - Edge capability (measured by our internal classification benchmark) fails to improve release-over-release for two consecutive cycles
  - Dominant open-weights licenses shift to user-count-capped or field-of-use-restricted terms
- **Mitigation if broken:** Extend the model abstraction layer to include fine-tuned small specialized classifiers (100M–500M parameter XGBoost/transformer hybrids) trained on our own threat corpus. Lose some generality; keep the product.

### Bet 2 — Software-only; no consumer hardware business

- **What we assume:** There is a coherent market in DIY enthusiasts + privacy-sensitive SMBs + regulated enterprises who will install software on hardware they already own or can source from a published BOM. We do not need to own the hardware supply chain.
- **What we commit to:** No hardware SKUs. Published BOMs, benchmarks, and deployment guides for validated reference architectures. Software is the product.
- **Break conditions — re-plan if any of these trigger:**
  - Fewer than a target absolute count of sustained community installs at 30 days post-download (initial target: 2,000 by Phase 1 GA + 6 months; revisited quarterly as the download baseline is known)
  - Enterprise buyers consistently cite "please just sell us a box" as the primary blocker in win/loss calls
  - Reference hardware becomes unavailable (supply chain) and community alternatives don't emerge
- **Mitigation if broken:** Partner with an existing hardware vendor (System76, Protectli, SolidRun) for a co-branded appliance — not vertically integrate.

### Bet 3 — The enterprise buyer with privacy/sovereignty requirements is a real and growing segment

- **What we assume:** EU AI Act obligations phasing in through 2027 (high-risk deadlines moved by the 2026 Digital Omnibus), post-2024 AI-backlash sentiment, and the accelerating agentic-traffic threat create durable demand among law firms, journalism orgs, medical practices, crypto custodians, defense subcontractors, and EU sovereignty buyers.
- **What we commit to:** Engineering investment in enterprise-grade features (SSO, RBAC, SIEM, FIPS, SBOM) from Phase 3 — not bolted on post-ARR.
- **Break conditions:** Twelve months post-Phase-2 GA with fewer than 10 paying enterprise deployments and no clear pipeline.
- **Mitigation if broken:** Double down on community edition + threat-intel subscription as the primary revenue path. Shelve the enterprise tier; treat the project as a high-adoption OSS tool with a small sustaining-support business.

### Bet 4 — On-prem proxy is the right architectural shape

- **What we assume:** Inline policy enforcement at the network boundary, combined with local-agent bridging, remains the correct abstraction. Not a pure observation / SIEM play, not a pure agent-runtime sandbox.
- **Break conditions:** Agentic ecosystems standardize on a declarative permissions model (MCP-level capability brokering, OAuth-for-agents) that obsoletes network-level enforcement.
- **Mitigation:** Pivot the local-agent bridge to be the primary surface; deprecate the DNS/proxy layer to maintenance-only.

### Bet 5 — Pro+ Mesh is worth building only if Roaming earns it (candidate)

- **What we assume:** Some Pro users will want several devices and sites under one policy, beyond one laptop roaming back to one home appliance.
- **What we commit to:** Build Roaming Mode (v0.3) with Headscale-compatible key handling so a mesh stays possible. Build nothing mesh-specific until Roaming has usage signal. Invariant 4 applies unchanged: no flow data crosses the mesh's coordination plane.
- **Break conditions:** Six months after Roaming ships, fewer than a meaningful share of Pro users run it on more than one device, or a partner (Headscale, Tailscale) covers the need without us.
- **Mitigation if broken:** Pro stays single-site plus Roaming; Pro+ Mesh is dropped from `deployment-modes.md`.

## Appendix A — Deception, Not Traps

Protocol Ward ships **decoy endpoints and honeytokens** — placed inside the policy-controlled surface, touched only by something enumerating. A hit is a near-zero-false-positive intrusion signal. This is the Thinkst Canary model. It works because the value is the *alert*, not the attacker's wasted time.

Protocol Ward does **not** ship compute-burning honeypots that feed attackers fabricated responses. That approach loses the compute race on edge hardware (generating fake XML at an estimated single-digit tok/s while a scanner moves on in under a second) and introduces legal ambiguity that varies by jurisdiction. We stayed out of that trap in v2 and stay out of it here — the reasoning hasn't changed. Active retaliation is not in our threat model.

## Appendix B — What changed between versions

- **v4.1 (freshness pass, 2026-10-06):** planned features (CA provisioning, per-device override, RFC process, Hall of Fame) marked as planned; v0.1 and v0.2 described as pre-public milestones; native macOS client listed in Phase 2 (Pro), matching `deployment-modes.md`.
- **v4 (public beta, 2026-10-05):** relicensed to Apache-2.0 everywhere (ADR-0007); Pro is paid services and Enterprise is commercial add-ons, support and managed services. Phases rewritten to match shipped versions; claims fact-checked; Bet 5 added.
- **v3 (cleanup, 2026-04-25):** restored Gemma 4 E4B as the unambiguous reference model after a brief detour through "Gemma 3n with Gemma 4 as migration target" — the detour was an over-cautious editorial call; Gemma 4 E4B shipped April 2026 under Apache 2.0 and is the model the project is built around. Clarified the licensing precedent (superseded in v4). Split the enterprise reference architecture into a discrete-GPU rackmount row and a Mac Studio Ultra row to make "VRAM or unified" precise. Clarified that decoy primitives ship in Phase 1 across all tiers, with centralized placement UX and SIEM correlation gated to enterprise.
- **v3 (revision, 2026-04-22):** corrected the licensing precedent (superseded in v4). Reference architectures reworked: replaced speculative "AI HAT+ 2" SKU with Hailo-10H accelerator as a capability, added Apple Silicon Mac mini and AMD Ryzen AI rows for SMB, marked Pi-5-without-accelerator as experimental. Marked 8–11 tok/s Hailo number as a design target. Tied 128k context claim to enterprise tier explicitly. Added prompt-injection risk (Key Risks #6) with schema-constrained decoding and adversarial-eval mitigation. Tightened Bet 2 break condition from an attrition percentage to an absolute sustained-install count. SLSA target raised to Level 3. MITRE CNA application gated on a disclosure track record rather than a single CVE. Added MLX-backed model adapter validation as an explicit Phase 2 deliverable gating Mac mini "recommended" status.
- **v2 → v3:** committed to a copyleft core with permissive plugins and a commercial enterprise tier (superseded in v4). Dropped consumer hardware plan. Reference architectures replace "target hardware we sell." Model abstraction layer made explicit. Decoy endpoints / honeytokens reinstated in Phase 1 (Thinkst framing, not compute-waste). Managed-CA mode added for enterprise TLS inspection. Deployment modes split into Community / SMB / Enterprise with distinct UX surfaces. Threat model expanded to include insider, lateral movement, exfiltration. Explicit "Assumptions and Bets" section with break conditions.
- **v1 → v2:** fixed sub-millisecond latency overclaim with two-tier model. Corrected Gemma 4 E4B parameter count. Added threat model, update mechanism, false-positive UX. Honeypot moved to appendix. SSL bumping gated behind explicit consent.
