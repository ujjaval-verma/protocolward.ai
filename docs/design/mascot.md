# Kestrel — Mascot & Narrative Brief

This document locks the mascot's species, name, motif, visual register, pose canon, taglines, and deployment surfaces. It is the source of truth for any illustration, copy, or community asset that involves Kestrel. It extends `DESIGN.md` (brand DNA); when the two conflict, `DESIGN.md` wins for tokens (colors, typography, motion) and this document wins for character and copy.

## 1. The species

**Common kestrel** — *Falco tinnunculus*. A small falcon, ~30–40cm long, widespread across Eurasia and Africa. The species choice is load-bearing for the brand because of the **hover hunt**: the kestrel is one of very few raptors that holds station in mid-air, head locked on a fixed point on the ground, before stooping to take prey. Most other falcons either still-hunt from a perch or strike in level flight. The kestrel hovers.

Field marks the mascot inherits:
- **Mustache stripe.** A dark vertical mark from below the eye down the cheek. All falcons have it; in the kestrel it's the single most recognizable facial mark and the illustration leans on it as the kestrel tell.
- **Rufous back, spotted with black.** The chestnut-amber back of the male — close enough to DESIGN.md `accent` (#F2A23B) that this is not a coincidence; the brand color was chosen with the kestrel already in mind.
- **Spotted underside.** Cream belly with dark spots; rendered sparingly in the illustration.
- **Tail.** Adult male: blue-grey, unbarred, with a broad black subterminal band and a white tip. Female and juvenile: rufous with dark cross-bars and a dark subterminal band. The mascot is drawn as the adult male.
- **Hover pose.** Wings spread and beating, tail fanned downward as a stabilizer, head locked on the ground regardless of body sway. *This is the canonical pose for the motif; no current surface uses it. The README and the hero use Flight (dorsal), §5.*

The species is a real, living animal. Anything we render or write should be defensible to a birder — the brand should not be fragile to "actually, that's not a kestrel" corrections.

## 2. Names

| Layer | Name | Where it appears |
|---|---|---|
| Product | **Protocol Ward** | Wordmark, repo, package name, formal docs, the company-style mention |
| Mascot / in-universe character | **Kestrel** | Operator vernacular, community channels, mascot illustrations, `ward doctor` output |
| CLI binary | `ward` | Shell, scripts, systemd units, manpages |

**Protocol Ward** names the discipline; **Kestrel** names the character. They are not interchangeable. Operators will say *"running Kestrel"* the way OpenClaw users say *"raising lobsters"* — this is desirable. Resist the gravitational pull to rename the product to Kestrel later; the two names doing two jobs is the point.

## 3. The motif: hover, then strike

The kestrel hovers stationary above a field for seconds at a time before dropping to take ground prey. That rhythm — **bounded observation, deterministic action** — is the architecture of Protocol Ward:

- **Hover** = slow-path classifier (`pkg/model`, v0.2+). Bounded context, bounded latency, no side effects.
- **Strike** = `internal/policy`. Exhaustively cased, deterministic, no judgement at the moment of action.

This motif is the single most important narrative anchor and should reappear in:
- Hero copy on the landing site.
- The "How it works" section of `docs/product/`.
- Any explainer that talks about the three-tier defense.
- The pose of every mascot illustration (see §5).

**Zoological correctness is cheap and load-bearing.** Do not write the motif as "mid-flight strike," "aerial interception," or anything implying the kestrel takes prey out of the air. Kestrels are ground-prey hunters from a hover; getting this right avoids correction-by-HN-commenter and reinforces the brand's "we know what we are" register.

## 4. Visual register

Kestrel is rendered in three sanctioned registers. The OpenClaw illustration register (organic, illustrative, cartoon-leaning, red `#e81b25`) is the *contrast anchor*, not the model to follow.

### 4.1 Flat vector illustration (README header, protocolward.ai hero, favicon)

Flat-shaded layered paths traced from the reference photo (see the credit in §10). No gradients, no outlines, transparent background (hero; the favicon adds an opaque `#0B0F14` tile and thin feather strokes). The hero is `docs/assets/kestrel-flight.svg` (87 paths, 13 fills); the favicon is `docs/assets/kestrel-favicon.svg`.

| Hex | Source | Use |
|---|---|---|
| `#0B0F14` | `bg` | Eye, bill tip, tail band, deepest shadow |
| `#E6EAF0` | `text` | Tail tip, cheek, belly highlights |
| `#8A95A5` | `text-muted` | Blue-grey head and tail |
| `#C77D1C` | `accent-deep` | Rufous shadow, back spots |
| `#2A1D17` `#4A3329` `#70554A` `#A68C7E` | illustration only | Browns for the flight feathers |
| `#E3894A` `#F2A867` | illustration only | Rufous back and highlights |
| `#3A4250` `#5D6879` | illustration only | Greys for the head and tail shading |
| `#F5CF3D` | illustration only | Eye-ring and cere yellow |

The nine illustration-only shades exist for this artwork. They are never UI colours; DESIGN.md tokens remain the only palette for product surfaces. The favicon is hand-drawn in the same style on a `#0B0F14` rounded tile and adds three more illustration-only browns (`#6E5246`, `#3E2B22`, `#A08578`).

The hero reads on both `#0B0F14` and white, but each background swallows one extreme. On dark, the black tail band, eye and bill tip merge into the background, and the darkest brown wing tips lose contrast. On white, the white tail tip and cheek do the same. Use the hero on either; where field-mark legibility matters, prefer a mid-tone background or the favicon tile.

### 4.2 Pixel-art (stickers, small decorative use)

Crisp 8-bit silhouette with a tight kestrel-specific palette. Use `shape-rendering="crispEdges"` on the SVG element so the grid stays sharp at any size. No current surface uses it; it is kept for stickers and small decorative pieces.

| Token | Hex | Use |
|---|---|---|
| `accent` | `#F2A23B` | Chestnut back, wings, tail base — the dominant color |
| `accent-deep` | `#C77D1C` | Wing-edge shadow, tail-band shadow, depth pass |
| `text` | `#E6EAF0` | Cream belly, breast |
| `bg-elevated` | `#11161D` | Dark markings: head crown, eye, mustache stripe, primary feather tips, tail bars |

All four come from DESIGN.md — no off-palette colors. The pixel-art kestrel can render in light mode or dark mode without modification because the dark markings are also the silhouette outline.

### 4.3 Geometric silhouette (in-app, dashboard glyphs)

Single-color `#F2A23B` flat fill, no outline, no gradient, no shadow. Use when the kestrel is a glyph at small sizes (≤48px), inside the web dashboard chrome, or anywhere mixing with operator data where the illustration would compete for attention.

**Favicon exception.** The browser-tab favicon is the §4.1 vector kestrel on a `#0B0F14` rounded tile (`docs/assets/kestrel-favicon.svg`). The flat amber silhouette remains the rule for every other glyph at 48px or below.

### 4.4 What's off-brand (do not produce)

- Cartoon-anime kestrel with large eyes or expressive face.
- Photoreal feather rendering or watercolor naturalism.
- Kestrel holding any object: sword, gun, shield, keyboard, USB stick. The kestrel does not need props.
- Rainbow gradients, neon glow, lens flare, or any "Web3" register.
- Multi-color rendering outside the §4.1 (including the favicon's extra browns) and §4.2 palettes.
- Kestrel facing the viewer head-on with wings spread heraldically (reads as eagle / military insignia; we are not that).
- A different falcon. Peregrines, merlins, and hobbies are not kestrels. They do not hover. They are not us.

## 5. Pose canon

Four sanctioned poses. Anything else needs a written justification before it ships.

1. **Hover (canonical).** Viewed from below or front: wings fully spread and slightly downward; tail fanned for stabilization; talons drawn up under the body; head tilted toward the ground. This remains the canonical pose for the motif and for any future illustration where the kestrel is the focal element. Mirrors the motif (§3).
2. **Perched-watching.** Silhouette of a kestrel perched on a post or wire, head turned in profile. Use for empty states, 404 pages, and `ward doctor` healthy output. Conveys "stationed, alert."
3. **Flight (dorsal).** Seen from above while gliding: wings spread, tail closed, head forward. The README header and the protocolward.ai hero use it, drawn as the §4.1 vector illustration (`docs/assets/kestrel-flight.svg`). Hover stays the motif (§3).
4. **Stoop (deferred).** Wings folded, diving. Reserved for the "blocked event" surface in the dashboard once it exists. Do not produce until that surface is designed; we don't want stoop floating around as decorative art divorced from a "strike just happened" semantic.

## 6. Taglines

Three sanctioned taglines, each bound to its surfaces. Mixing them or coining new ones requires updating this document first.

| Tagline | Use on | Do not use on |
|---|---|---|
| **"Quiet observation. Deterministic strike."** | Landing hero, README headline, docs nav, primary external presence | Pitch deck (too understated for that audience) |
| "Small. Patient. Lethal to phone-home." | Pitch deck, supply-chain narrative pages, the section of `docs/product/pitch.md` that names the threat class | Landing hero (over-narrow; phone-home is not the only thing Kestrel is lethal to) |
| **"The lobster molts. The kestrel watches the perimeter."** | `docs/community/peers.md`, OpenClaw-adjacent community posts, stickers, any context where the OpenClaw friendly-rivalry is in play | Primary marketing — requires audience familiarity with OpenClaw to land |

Voice rules that override any tagline: per `DESIGN.md`, no AI-magic, no superlatives, no "Trusted by 10,000+ teams" social proof, no exclamation marks. If a tagline ever wants an exclamation marks, the tagline is wrong.

## 7. Emoji conventions

There is no kestrel emoji in Unicode. When an emoji is unavoidable in operator-facing copy:

- **Generic bird-of-prey contexts:** 🦅 (eagle) is the closest available glyph. Acceptable in README badges, commit titles, alert labels, and Discord channel headers. Always pair it on first use with the word "Kestrel" so readers know it's a stand-in.
- **Quiet-watching contexts:** 👁 (eye) for observation, 🪶 (feather) for the slow-path narrative. Avoid stacking emoji.
- **Strike/enforcement contexts:** no emoji. Enforcement events are dignified — text-only attribution + remediation per invariant 7.

Do not invent unicode-art kestrels (`\v/` etc.) — they age badly and break in terminals without proper font fallbacks.

## 8. OpenClaw peer narrative

Kestrel's relationship to OpenClaw is **third-person admiration with technical complementarity** — not partnership, not parody, not competition.

OpenClaw is the cheerful crustacean doing powerful agentic work. Kestrel is the quiet predator patrolling the perimeter so the lobster can molt in peace. The two products solve different problems and the contrast is welcome.

**The honest scope claim:** Protocol Ward does not protect AI agents from being compromised. It protects the *network* from compromised AI agents. When an agent like OpenClaw gets prompt-injected through untrusted content, the lethal trifecta closes only if the third leg — egress — is open. Kestrel patrols that leg.

**Do:**
- Acknowledge OpenClaw by name in `docs/community/peers.md` and any blog post that frames the lethal-trifecta containment story.
- Use the third tagline ("The lobster molts. The kestrel watches the perimeter.") in community contexts.
- Refer to OpenClaw's manifesto values ("Your assistant. Your machine. Your rules.") approvingly when the topic is local-first sovereignty.

**Do not:**
- Claim partnership, integration, or endorsement.
- Mimic OpenClaw's absurdist-playful voice register — tonal contrast is part of the brand boundary.
- Speak for OpenClaw or assume reciprocity.
- Use OpenClaw's mascot illustrations in our materials beyond fair-use reference.

## 9. Deployment surfaces

Where Kestrel appears, where it doesn't, and what's deferred.

| Surface | Status | Notes |
|---|---|---|
| Wordmark / primary lockup | **No** | Linear-style restraint. "Protocol Ward" alone. Kestrel is character, not logotype. |
| Landing hero | Yes | Vector flight (dorsal) pose. Owns the hero composition; tagline #1 underneath. |
| `README.md` header | Yes | Vector flight (dorsal). A small geometric-silhouette variant is acceptable next to the title. |
| Social preview (Open Graph, GitHub) | Yes | 1280x640, `docs/assets/og.png`. Vector register on `#0B0F14` with a lifted mid-tone backdrop behind the bird. The docs site serves the same file as its `og:image`. |
| Docs sidebar / 404 / empty states | Yes | Perched-watching pose, geometric silhouette register. One per page maximum. |
| Dashboard chrome (`web/`) | **No** | Operator data does not compete with mascot. Mascot may appear in onboarding, empty states, and `404`/error views only. |
| `ward serve` startup banner | **Deferred** | ASCII Kestrel + version on startup. Planned for sub-project 5 (`ward` CLI / `ward doctor` polish). Do not retrofit silently. |
| `ward doctor` healthy state | Deferred | Perched-watching glyph next to "all systems quiet" output. Same target sub-project as above. |
| Swag / stickers | Yes | Pixel-art hover pose preferred. Third tagline ("The lobster molts...") earns a sticker of its own. |
| Community channels (Discord, mailing list avatars) | Yes | Pixel-art hover or perched-watching. |

Future surfaces (any new mascot deployment) get added to this table by PR. The table is the gate.

## 10. Cross-references

- `DESIGN.md` — brand DNA: colors, typography, voice, register.
- `docs/product/vision.md` — product thesis (Kestrel motif should appear here when the narrative gets a polish pass).
- `docs/product/pitch.md` — supply-chain attack framing; natural home for tagline #2.
- `docs/engineering/architecture.md` — three-tier defense; Kestrel motif maps to the slow-path → policy state-engine boundary.
- `docs/community/peers.md` — *not yet created*; will house the OpenClaw peer narrative when it lands.
- [Wikipedia: Common kestrel](https://en.wikipedia.org/wiki/Common_kestrel) — species reference for anyone illustrating or writing about Kestrel.
- Reference credit: the flight (dorsal) vector illustration and favicon are traced from [Pexels photo 32761241](https://www.pexels.com/photo/32761241/) by Siegfried Poepperl (adult male common kestrel; the Pexels License permits modified derivatives).

## 11. Revisions

Any change to §1 (species), §2 (names), §3 (motif), §5 (pose canon), or §6 (taglines) requires both an update to this document and a one-line callout in `CLAUDE.md`. Other sections may be amended freely as the product matures.
