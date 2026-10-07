# Protocol Ward: the layer that is still there when the rest has failed

**Every layer above this one can fail, and in a supply-chain attack it does so by design.**

The registry was trusted. CI was green. The maintainer account looked legitimate. Then `npm install` ran a postinstall script, and the code it dropped started calling a server you had never heard of.

This happens. On 31 March 2026, an attacker used a hijacked maintainer account to publish **axios@1.14.1** and **axios@0.30.4** (GHSA-fw8c-xr5c-95f9, SNYK-JS-AXIOS-15850650). Both pulled in a new dependency, `plain-crypto-js`, whose postinstall script installed a cross-platform remote-access trojan. On macOS it landed at `/Library/Caches/com.apple.act.mond` and called out to a domain registered the day before. The versions were live for about three hours.

Six weeks later, on 11 May 2026, 84 malicious versions of 42 `@tanstack/*` packages were published (CVE-2026-45321, GHSA-g7cv-rxg3-hmpx). The payload stole cloud credentials, GitHub tokens and SSH keys, and sent them out through the Session messenger's file-upload network: `filev2.getsession.org` and `seed1`–`seed3.getsession.org`. Analyses by Semgrep and Wiz describe a LaunchAgent (a systemd user unit on Linux) that polled GitHub every 60 seconds and ran `rm -rf ~/` once the stolen token was revoked.

Your package manager did not stop either one. A lockfile pinned to a compromised version did not help, and neither did a fresh resolve that picked it up.

**Protocol Ward is not a supply-chain prevention tool.** It does not inspect tarballs, audit postinstall scripts, or stop code from running.

It sits at the network boundary, on hardware you own, and decides which names your devices may resolve. The malware will run, because the install chain is long and nobody audits all of it. What Ward can do is make sure that **it cannot reach its destination.**

---

## The attack phase that matters

Supply-chain malware can harvest credentials locally, and Ward does not stop that. But exfiltration, the C2 callback and the next-stage download all need a network connection, and on almost every network that starts with a DNS lookup. Blocking those domains stops exfiltration over those names.

```text
 npm install                ← attack executes here; Ward does not see this
        │
        ▼
 postinstall drops payload  ← filesystem event; out of scope
        │
        ▼
 payload resolves its C2    ← Protocol Ward answers here
        │
        ▼
 blocked, with attribution  ← no route out
```

The TanStack advisory says it plainly: domain blocking is the only network mitigation. That is the seam Ward fills.

One practical note from the same incident: remove the LaunchAgent or systemd unit **before** you revoke the stolen token. Blocking the exfiltration domains does not disarm the wipe; revocation triggers it.

---

## Three tiers, one seam

```text
Blocklists          → fast path   (known-bad names, no model)
Lexical detector    → on-device   (names no list has seen yet; flag-only in beta)
Decoys              → tripwires   (names nothing legitimate ever resolves)
```

**Blocklists, the fast path.** Ward loads hosts-format lists and AdGuard `||host^` rules you point it at (`/etc/hosts` style files and AdAway and AdGuard syntaxes; plain bare-domain lines are skipped with a warning), which covers hosts-format or AdGuard-format exports of lists such as OISD, Hagezi, StevenBlack and URLhaus. A match is answered with your configured block response without any model in the path, and the log line names the list and the rule. Add `getsession.org` to a list and the TanStack exfiltration path is closed. Coming soon: a curated default bundle refreshed through Ward's signed, pull-only update channel.

**Lexical detector, on-device.** The detector is opt-in (`model: { builtin: lexical }` in your config). When enabled, Ward analyses each hostname that misses your lists on-device, skipping local names and OS connectivity checks; behavioral signals (timing and per-device history) are next. The detector scores the name itself (randomness, rare letter sequences, digits, consonant runs, length) to spot machine-generated domains that no list has seen yet. In the beta it **raises a flag and never blocks**: flags appear on the dashboard with their reasons, and you add a name to a blocklist to enforce. Coming soon: timing and per-device history signals, enforcement mode, and an optional local LLM that explains a flag in plain language. Nothing is sent anywhere for analysis.

**Decoys, tripwires.** You configure hostnames that no legitimate device on your network ever looks up, such as `nas-backup.home.arpa`. A lookup is a high-confidence sign that something is enumerating your network, and Ward raises an alert with attribution. No model runs. Decoys never appear in `ward config export`, so a shared config cannot tip off an attacker.

**The AI classifies; the deterministic policy engine decides.** Detector and model outputs are a typed enum. The policy engine is a stateless Go function with an exhaustive case for every value. A model never has direct effect on whether a query is answered; in the beta no detector verdict leads to an applied action; a built-in detector verdict's only effect is a dashboard flag, and an external classifier's verdict is only logged.

---

## Against the two attacks above

### axios (GHSA-fw8c-xr5c-95f9)
The trojan's C2 domain was a day old, so no list knew it at the time of the attack. Today Ward stops it once the domain is on any list you load. Hostname scoring is the first detector signal. The signals aimed squarely at this pattern are timing and per-device history: a developer machine contacting a never-seen domain moments after an install. They are coming soon.

### TanStack (CVE-2026-45321)
The exfiltration domains are public and stable. Block `getsession.org` and the stolen credentials have no route out through that network. Ward logs every blocked lookup with the device and the matching rule, so you know which machine to clean. Remove the persistence first, then rotate the tokens.

---

## The honest threat model

**In scope:**
- Outbound connections from malware that has already executed, at the point it resolves a name
- C2 and exfiltration lookups from supply-chain payloads and dropped binaries
- Enumeration of your network, caught by decoy hostnames
- Smart-device telemetry and tracker lookups

**Explicitly out of scope:**
- Preventing malicious code from executing during install
- Inspecting npm/pip/cargo tarball contents
- Filesystem or process-level monitoring
- Nation-state adversaries with existing endpoint access
- Traffic that never makes a DNS lookup Ward can see (hard-coded IPs, a resolver that bypasses Ward)

This is not a weakness to apologise for. It describes where the network boundary sits relative to the package ecosystem.

---

## Where it runs

Ward is one Go binary for Linux and macOS; Windows support is planned for the future. The development rig is a Mac mini (M4 Pro, 24 GB) acting as the network's DNS forwarder. Reference hardware tiers are in `docs/product/vision.md`. Everything runs on hardware you own. There is no cloud telemetry, and no traffic is shipped off-site for analysis.

---

## Join the Ward

Apache-2.0 licensed, free for any use, including commercial. Configure with one YAML file and the `ward` CLI. Every block carries attribution in the logs and dashboard, because a resolver that silently breaks things gets uninstalled; a one-click allowlist override is coming. Try the demos at https://protocolward.ai.

The supply chain will be compromised again. The question is what happens next.
