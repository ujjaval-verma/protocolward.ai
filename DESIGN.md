---
version: alpha
name: Protocol Ward
description: Sovereign edge proxy with curated blocklists, behavioral classification, and decoy detection.
colors:
  bg:              "#0B0F14"   # near-black slate, primary background
  bg-elevated:     "#11161D"   # cards, panels, modals
  bg-inset:        "#070A0E"   # inset wells, code blocks
  border:          "#1D2530"
  border-strong:   "#2A3340"
  text:            "#E6EAF0"
  text-muted:      "#8A95A5"
  text-subtle:     "#5A6470"
  accent:          "#F2A23B"   # warm amber, primary accent
  accent-hover:    "#F4B765"
  accent-deep:     "#C77D1C"
  ok:              "#3CB39B"   # muted teal, healthy state
  ok-subtle:       "#1F4A44"
  warn:            "#E8B547"
  danger:          "#D9544A"   # restrained red, used only for enforcement events
  danger-subtle:   "#3A1F1D"
  decoy:           "#A874D7"   # decoy-event highlight, used sparingly
typography:
  display:
    fontFamily: Inter
    fontSize: 56px
    fontWeight: 700
    lineHeight: 1.05
    letterSpacing: -0.04em
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: 700
    lineHeight: 1.15
    letterSpacing: -0.03em
  headline-md:
    fontFamily: Inter
    fontSize: 22px
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: -0.02em
  body-lg:
    fontFamily: Inter
    fontSize: 17px
    fontWeight: 400
    lineHeight: 1.6
  body-md:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: 400
    lineHeight: 1.55
  body-sm:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.5
  mono-md:
    fontFamily: "JetBrains Mono"
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.5
  mono-sm:
    fontFamily: "JetBrains Mono"
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
spacing:
  scale: [0, 2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128]
radius:
  sm: 4px
  md: 6px
  lg: 10px
  xl: 16px
motion:
  duration-fast: 120ms
  duration-base: 200ms
  duration-slow: 360ms
  easing-base: cubic-bezier(0.2, 0.8, 0.2, 1)
---

# DESIGN.md — Protocol Ward Brand DNA

This file is the single source of truth for brand identity across the dashboard, CLI styled output, landing site, and any future surfaces. The dashboard in `internal/web/` mirrors the colour tokens above in its CSS, and the CLI's styled output in `cmd/ward` approximates the accent and status colours. The protocolward.ai docs site, kept in a separate repository, maps the same tokens into its theme.

## Voice & tone

Protocol Ward speaks like a security operator, not a marketing agency.

- **Direct.** "12 trackers blocked in the last hour." not "We've made the internet better for you!"
- **Calm.** The product handles the alarming things so the operator doesn't have to feel alarmed. Restrained type, restrained motion, restrained red.
- **Technically honest.** No "AI magic." Every block has a reason; every decoy hit names the endpoint; every classification cites the signal.
- **Operator-respectful.** The operator is assumed to be competent. We do not condescend, we do not over-explain, we do not gamify.

## Visual register

The product looks like a **security operations console**, not a fintech card or a SaaS dashboard.

- Background is near-black slate (`#0B0F14`), with subtle hue so it doesn't read as a console emulator but doesn't pretend to be paper.
- Surfaces step up one tone (`#11161D`) — flat hierarchy, no drop shadows, sharp borders.
- Type is restrained Inter for product UI, JetBrains Mono for any code/hostname/IP/cadence. Mono is *prominent* — half the value of the product is showing the operator what's going on at the wire level, and that calls for monospace dignity.
- Amber accent (`#F2A23B`) is the brand color — used for primary actions, status highlights, and the wordmark. Distinct from the cyan/blue saturation of most security products.
- Teal (`#3CB39B`) for healthy / pass states. Restrained red (`#D9544A`) for actual enforcement events only — not for general warnings.
- Decoy events get a faint purple (`#A874D7`) highlight; rare enough that the color stays semantic.

## Adjacent inspirations

- **Linear** — terminal-y restraint, lowercase confidence
- **Tailscale** — quietness, dense information without visual noise
- **Thinkst Canary** — security operations register, the rhythm of a tool that is used by professionals

## What we are *not*

- Not sassygit/peerdb's purple-gradient SaaS register
- Not Cloudflare's orange-on-white
- Not a generic terminal screenshot dressed up as design
- Not a startup landing page with "Trusted by 10,000+ teams" social proof

## Surfaces that consume this file

- `web/` — reserved for a future interactive dashboard; its Tailwind config will read these tokens
- protocolward.ai docs site (separate repository) — Starlight theme maps these tokens
- `internal/web/` — the read-only dashboard's CSS mirrors the colour tokens
- `cmd/ward` — lipgloss styling for `ward doctor` and startup errors approximates the accent and status colours
- `docs/design/visual-language.md` — translates tokens into component conventions (later sub-project)

## Companion docs

- `docs/design/mascot.md` — Kestrel mascot brief: names, motif ("hover, then strike"), pose canon, taglines, OpenClaw peer narrative, deployment surfaces.
