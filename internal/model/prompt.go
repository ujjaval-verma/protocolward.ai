// SPDX-License-Identifier: Apache-2.0

// Package model is the SP10b sibling-process classifier adapter — the first
// implementation of pkg/model.Classifier. The adapter spawns a child runtime
// (a model-server binary, typically llama.cpp wrapping a Gemma checkpoint)
// and relays typed Input → Verdict over newline-delimited JSON on stdio.
//
// # Invariants
//
//   - Invariant #1 ("the AI is a classifier, never a decider"): this package
//     imports only stdlib + pkg/model + pkg/schema. It MUST NOT import
//     internal/policy or internal/dataplane. T-INV1 in adapter_test.go
//     asserts this structurally via go list -deps.
//
//   - Invariant #3 (sibling-process exception to "one binary"): the child is
//     a separate OS process spawned via os/exec.Cmd. SP10c's bullet 14
//     harness will assert that ward survives a SIGKILL of the child.
//
//   - ADR-0004 D2: the Input fields ClientHints and UserAgent are attacker-
//     influenced; this package sanitizes + length-bounds them before they
//     flow into the wire envelope handed to the child.
package model

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"protocolward.ai/ward/pkg/model"
)

// Per-field caps. Chosen to keep the marshalled request comfortably under
// the Tier-2 4-8k token budget (architecture.md). Worst-case payload is
// 253 (hostname) + 512 (UA) + 8*256 (hints) = 2813 bytes; at ~3 chars/
// token that is ~940 tokens of context, leaving the child's prompt
// template ample headroom inside the 4-8k bound.
const (
	// maxHostnameLen is RFC 1035's hard limit for a fully-qualified domain
	// name. The caller already pre-normalized; this cap is a defensive
	// backstop against a malformed Input.Hostname that somehow exceeds it.
	maxHostnameLen = 253
	// maxUserAgentLen bounds the UA string. Real-world UAs cluster well
	// under this; the cap stops a hostile UA from dominating the prompt.
	maxUserAgentLen = 512
	// maxClientHints caps how many entries we forward to the child;
	// excess entries are dropped (silently — the caller is misusing the
	// API if they pass more than this).
	maxClientHints = 8
	// maxClientHintLen bounds each entry. Same rationale as user-agent.
	maxClientHintLen = 256
)

// sanitize returns a copy of in with attacker-influenced strings stripped
// of control runes and bounded to the per-field caps. The original Input
// is not mutated; the returned value is safe to marshal into the wire
// request envelope.
//
// Order of operations matters: control-rune strip BEFORE length cap, so
// the cap counts user-visible bytes rather than letting an attacker
// inflate the field with control runes that survive into the prompt.
func sanitize(in model.Input) model.Input {
	out := model.Input{
		Hostname:  boundString(stripControl(in.Hostname), maxHostnameLen),
		UserAgent: boundString(stripControl(in.UserAgent), maxUserAgentLen),
	}
	if len(in.ClientHints) == 0 {
		return out
	}
	n := len(in.ClientHints)
	if n > maxClientHints {
		n = maxClientHints
	}
	out.ClientHints = make([]string, n)
	for i := 0; i < n; i++ {
		out.ClientHints[i] = boundString(stripControl(in.ClientHints[i]), maxClientHintLen)
	}
	return out
}

// boundString returns s truncated to maxLen bytes. UTF-8 boundaries are
// NOT respected — the input is attacker-controlled, and a torn trailing
// rune is acceptable. For test-input convenience and so callers can pass
// negative caps without panic, maxLen ≤ 0 returns the empty string.
func boundString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// stripControl returns s with all unicode.IsControl runes removed EXCEPT
// tab and space (which are not classified as IsControl by unicode anyway,
// but the guard is explicit for reader clarity). Newline / carriage
// return / NUL / BEL etc. are all dropped — they would either break the
// newline-delimited wire frame or inject prompt-template manipulation
// tokens.
//
// Zero-width / format runes (U+200B and friends) are categorized as
// unicode.Cf (format) rather than Cc (control); they are dropped here
// too because they're a known prompt-injection vector (vision.md Key
// Risk #6) and have no legitimate role in a hostname / UA / ALPN value.
func stripControl(s string) string {
	if s == "" {
		return s
	}
	// Fast path: no runes to strip — avoid the builder allocation.
	if !strings.ContainsFunc(s, func(r rune) bool {
		if r == '\t' || r == ' ' {
			return false
		}
		return unicode.IsControl(r) || unicode.In(r, unicode.Cf)
	}) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == utf8.RuneError {
			// Drop invalid UTF-8 (range-over-string yields RuneError for bad bytes).
			continue
		}
		if r == '\t' || r == ' ' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
