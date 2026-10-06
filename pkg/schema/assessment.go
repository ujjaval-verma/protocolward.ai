// SPDX-License-Identifier: Apache-2.0

package schema

// Reason codes carried in [Reason.Code]. They are stable machine
// identifiers: dashboards, the wasm demo and tests switch on them, so a
// code is never renamed, only added.
const (
	// ReasonHighEntropy: the label's character distribution is unusually
	// uniform (Shannon entropy).
	ReasonHighEntropy = "high_entropy"
	// ReasonRareNgrams: the label's letter sequences are rare among
	// popular domain names (character-trigram model).
	ReasonRareNgrams = "rare_ngrams"
	// ReasonDigitHeavy: a large share of the label's characters are digits.
	ReasonDigitHeavy = "digit_heavy"
	// ReasonConsonantRun: the label contains a long run of consonants.
	ReasonConsonantRun = "consonant_run"
	// ReasonLongLabel: the label is unusually long.
	ReasonLongLabel = "long_label"
)

// Reason is one explained contribution to an [Assessment]'s Score.
type Reason struct {
	// Code is one of the Reason* constants.
	Code string `json:"code"`
	// Detail is short human text, at most 120 bytes. It never contains
	// attacker-controlled input.
	Detail string `json:"detail"`
	// Weight is this reason's contribution to Score, ≥ 0.
	Weight float64 `json:"weight"`
}

// Assessment is a detector's explained output for one hostname. Like
// [Verdict] it is pure data (invariant 1): internal/policy decides what,
// if anything, happens to the connection.
type Assessment struct {
	// Verdict is the classification. Detectors in pkg/detect only ever
	// produce VerdictBenign or VerdictMalicious.
	Verdict Verdict `json:"verdict"`
	// Score is in [0,1]; higher means more DGA-like.
	Score float64 `json:"score"`
	// Reasons are sorted by Weight, descending. Nil when Verdict is
	// VerdictBenign and Score < 0.2 (JSON null).
	Reasons []Reason `json:"reasons"`
}
