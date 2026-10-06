// SPDX-License-Identifier: Apache-2.0

// Package detect is Protocol Ward's on-device lexical DGA detector. It
// scores a single hostname for the character-level signature of
// algorithmically generated domain names (DGA) and returns a typed
// [schema.Assessment]. It is a classifier, never a decider (invariant 1):
// nothing here touches connection state, and in the public beta its
// verdicts are flag-only.
//
// # What is scored
//
// Only the registrable label: the DNS label immediately left of the public
// suffix ("d1x2y3.cloudfront.net" scores "cloudfront"; "bbc.co.uk" scores
// "bbc"). Multi-label public suffixes come from a small built-in subset of
// the Public Suffix List; any other final label is treated as a one-label
// suffix. Reverse-DNS names (in-addr.arpa, ip6.arpa), punycode labels
// (xn--), single-label names and names under local-use TLDs (local, lan,
// home, internal, localdomain, localhost, corp, mail, intranet, private,
// domain, workgroup, test, example, invalid) or home.arpa are not scored and
// come back Benign with Score 0: none of them is a registered domain.
//
// # Features
//
// Five features of the label each map to a sub-score in [0,1] and carry a
// fixed weight; the weights sum to 1, so Score is in [0,1] and each
// Reason's Weight is that feature's contribution. Score ≥ the malicious
// threshold yields VerdictMalicious; anything else is VerdictBenign. The
// lexical detector never yields VerdictTelemetry (that stays with lists).
//
// # N-gram table provenance
//
// ngrams.bin is a character-trigram table built by scripts/build-ngrams
// from the Majestic Million (CC BY 3.0, https://majestic.com); see NOTICE
// in this directory. Only derived statistics are embedded.
//
// # Portability
//
// Stdlib only; no os, net, os/exec, syscall, goroutines or package-level
// mutable state, so the package compiles for GOOS=js GOARCH=wasm.
package detect

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// ErrInvalidHostname is returned (wrapped, with a fixed reason) by Assess
// and Classify when the input is not a syntactically valid DNS name.
var ErrInvalidHostname = errors.New("detect: invalid hostname")

//go:embed ngrams.bin
var ngramsBin []byte

// Feature weights. They sum to 1.0 (asserted in tests). Tuned in the
// S1 eval task against testdata/eval/lexical-v1.jsonl.
const (
	weightNgram     = 0.45
	weightEntropy   = 0.15
	weightDigit     = 0.15
	weightConsonant = 0.15
	weightLength    = 0.10

	// maliciousThreshold is T_mal: Score ≥ this → VerdictMalicious.
	maliciousThreshold = 0.50
	// reasonFloor drops contributions too small to explain anything.
	reasonFloor = 0.02
	// quietScore: below this a Benign assessment carries no Reasons.
	quietScore = 0.2
	// shortLabel: labels shorter than this have their score damped
	// linearly (n/shortLabel), since 2–5 char brands are dense in benign
	// space and DGAs rarely emit them.
	shortLabel = 7
)

// Lexical is the hostname-only DGA detector. The zero value is not
// usable; construct with New. Safe for concurrent use: all state is
// read-only after New.
type Lexical struct {
	scale float64   // quanta per bit in table
	v     int       // alphabet size
	index [256]int8 // byte → symbol index, -1 if absent
	table []byte    // v^3 quantised -log2 P(c | a b)
}

// Compile-time contract assertions.
var (
	_ model.Classifier = (*Lexical)(nil)
	_ model.Assessor   = (*Lexical)(nil)
)

// New returns a ready detector. It parses the embedded trigram table and
// panics if the table is malformed — that is a build defect caught by
// this package's tests, never a runtime condition.
func New() *Lexical {
	l, err := parseTable(ngramsBin)
	if err != nil {
		panic(fmt.Sprintf("detect: embedded ngrams.bin: %v", err))
	}
	return l
}

// parseTable decodes ngrams.bin: "PWNG", version (1), scale (quanta per
// bit), alphabet length v, the v alphabet bytes (index 0 = '^' boundary),
// then v^3 bytes of round(-log2 P(c | a b) * scale) indexed (a*v+b)*v+c.
func parseTable(b []byte) (*Lexical, error) {
	const hdr = 7
	if len(b) < hdr || string(b[:4]) != "PWNG" {
		return nil, errors.New("bad magic")
	}
	if b[4] != 1 {
		return nil, fmt.Errorf("unsupported version %d", b[4])
	}
	scale, v := int(b[5]), int(b[6])
	if scale == 0 || v < 2 || v > 64 || len(b) != hdr+v+v*v*v {
		return nil, errors.New("bad header or length")
	}
	l := &Lexical{scale: float64(scale), v: v, table: b[hdr+v:]}
	for i := range l.index {
		l.index[i] = -1
	}
	for i, c := range b[hdr : hdr+v] {
		if l.index[c] != -1 {
			return nil, fmt.Errorf("duplicate alphabet symbol %q", c)
		}
		l.index[c] = int8(i) //nolint:gosec // i < v ≤ 64
	}
	if l.index['^'] != 0 {
		return nil, errors.New("alphabet must start with boundary symbol '^'")
	}
	for c := byte('a'); c <= 'z'; c++ {
		if l.index[c] < 0 {
			return nil, fmt.Errorf("alphabet missing %q", c)
		}
	}
	for _, c := range []byte("0123456789-") {
		if l.index[c] < 0 {
			return nil, fmt.Errorf("alphabet missing %q", c)
		}
	}
	return l, nil
}

// Classify implements model.Classifier: it is Assess(...).Verdict.
func (l *Lexical) Classify(ctx context.Context, in model.Input) (schema.Verdict, error) {
	a, err := l.Assess(ctx, in)
	if err != nil {
		return schema.VerdictBenign, err
	}
	return a.Verdict, nil
}

// Assess implements model.Assessor. It is a pure function of in.Hostname.
// The hostname is lowercased and one trailing dot is stripped before
// validation. Invalid input returns an error wrapping ErrInvalidHostname.
func (l *Lexical) Assess(ctx context.Context, in model.Input) (schema.Assessment, error) {
	if err := ctx.Err(); err != nil {
		return schema.Assessment{}, err
	}
	labels, err := validate(in.Hostname)
	if err != nil {
		return schema.Assessment{}, err
	}
	label, ok := registrableLabel(labels)
	if !ok {
		return schema.Assessment{Verdict: schema.VerdictBenign}, nil
	}
	return l.score(label), nil
}

// validate normalises and checks h, returning its labels. Reasons in the
// error are fixed strings; the hostname itself is never echoed.
func validate(h string) ([]string, error) {
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidHostname)
	}
	if len(h) > 253 {
		return nil, fmt.Errorf("%w: longer than 253 bytes", ErrInvalidHostname)
	}
	// Reject non-ASCII before case folding: strings.ToLower maps U+212A
	// (Kelvin sign) to "k" and U+0130 to "i", which would smuggle
	// non-ASCII input past the byte check below.
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			return nil, fmt.Errorf("%w: invalid character", ErrInvalidHostname)
		}
	}
	h = strings.ToLower(h)
	labels := strings.Split(h, ".")
	for _, lb := range labels {
		switch {
		case lb == "":
			return nil, fmt.Errorf("%w: empty label", ErrInvalidHostname)
		case len(lb) > 63:
			return nil, fmt.Errorf("%w: label longer than 63 bytes", ErrInvalidHostname)
		case lb[0] == '-' || lb[len(lb)-1] == '-':
			return nil, fmt.Errorf("%w: label starts or ends with hyphen", ErrInvalidHostname)
		}
		for i := 0; i < len(lb); i++ {
			c := lb[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return nil, fmt.Errorf("%w: invalid character", ErrInvalidHostname)
			}
		}
	}
	if isDigits(labels[len(labels)-1]) {
		return nil, fmt.Errorf("%w: numeric top-level label", ErrInvalidHostname)
	}
	return labels, nil
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// multiLabelSuffixes is a hand-picked subset of the Public Suffix List's
// ICANN section: the multi-label suffixes most common in home-network DNS
// traffic, plus local-use and reverse-DNS zones. Single-label TLDs need
// no entry. Value true means "names under this suffix are not scored".
var multiLabelSuffixes = map[string]bool{
	"co.uk": false, "org.uk": false, "ac.uk": false, "gov.uk": false, "net.uk": false,
	"com.au": false, "net.au": false, "org.au": false, "edu.au": false, "gov.au": false,
	"co.nz": false, "org.nz": false, "co.jp": false, "ne.jp": false, "or.jp": false, "ac.jp": false,
	"co.kr": false, "or.kr": false, "co.in": false, "org.in": false, "gov.in": false,
	"co.za": false, "org.za": false, "co.il": false, "com.br": false, "net.br": false,
	"com.cn": false, "net.cn": false, "org.cn": false, "com.hk": false, "com.tw": false,
	"com.sg": false, "com.my": false, "com.mx": false, "com.ar": false, "com.tr": false,
	"com.ua": false, "co.id": false, "com.vn": false, "com.ph": false, "com.pk": false,
	"com.sa": false, "com.eg": false, "com.ng": false, "co.th": false, "gov.br": false,
	"home.arpa":    true,
	"in-addr.arpa": true, "ip6.arpa": true,
}

// localTLDs are reserved or de-facto local-use top-level labels (RFC 6761
// "localhost", RFC 6762 "local", ICANN-reserved "internal", RFC 2606/6761
// "test"/"example"/"invalid", ICANN's non-delegated "corp"/"mail", and
// common home-router and Windows-domain defaults). Names under them are never registered public
// domains, so a DGA cannot live there and they are not scored.
var localTLDs = map[string]bool{
	"local": true, "lan": true, "home": true, "internal": true,
	"localdomain": true, "localhost": true,
	// ICANN name-collision TLDs (never delegated, 2018) and de-facto LAN
	// suffixes, plus RFC 2606/6761 reserved TLDs.
	"corp": true, "mail": true, "intranet": true, "private": true,
	"domain": true, "workgroup": true,
	"test": true, "example": true, "invalid": true,
}

// registrableLabel returns the label immediately left of the public
// suffix, and false when the name must not be scored (reverse-DNS zones,
// punycode, local-use names). Single-label names (LAN device names such as
// "desktop-7h3k2l9") and names under a local-use TLD or home.arpa are never
// registered domains, so they are not scored.
func registrableLabel(labels []string) (string, bool) {
	n := len(labels)
	// A bare unscored zone (in-addr.arpa, ip6.arpa, home.arpa) is itself
	// not a registered domain.
	if n == 1 || localTLDs[labels[n-1]] || multiLabelSuffixes[strings.Join(labels, ".")] {
		return "", false
	}
	sfx := 1
	// multiLabelSuffixes holds 2-label suffixes only, so k never exceeds 2.
	for k := min(2, n-1); k >= 2; k-- {
		skip, ok := multiLabelSuffixes[strings.Join(labels[n-k:], ".")]
		if !ok {
			continue
		}
		if skip {
			return "", false
		}
		sfx = k
		break
	}
	label := labels[n-sfx-1]
	if strings.HasPrefix(label, "xn--") {
		return "", false
	}
	return label, true
}

// features are the raw per-label measurements.
type features struct {
	length    int
	entropy   float64 // Shannon, bits per char
	meanNLL   float64 // mean -log2 P under the trigram table, bits
	digit     float64 // digits / length
	consonant int     // longest run of consonant letters (y counts as vowel)
}

func (l *Lexical) measure(label string) features {
	f := features{length: len(label)}
	var counts [256]int
	digits, run := 0, 0
	for i := 0; i < len(label); i++ {
		c := label[i]
		counts[c]++
		switch {
		case c >= '0' && c <= '9':
			digits++
			run = 0
		case c >= 'a' && c <= 'z' && !strings.ContainsRune("aeiouy", rune(c)):
			run++
			f.consonant = max(f.consonant, run)
		default:
			run = 0
		}
	}
	n := float64(len(label))
	for _, k := range counts {
		if k > 0 {
			p := float64(k) / n
			f.entropy -= p * math.Log2(p)
		}
	}
	f.digit = float64(digits) / n
	f.meanNLL = l.meanNLL(label)
	return f
}

// meanNLL is the mean negative log2 probability of the padded label
// "^^" + label + "^" under the trigram table. '_' is looked up as '-'.
func (l *Lexical) meanNLL(label string) float64 {
	sym := func(c byte) int {
		if c == '_' {
			c = '-'
		}
		return int(l.index[c])
	}
	a, b := 0, 0
	sum, count := 0.0, 0
	step := func(c int) {
		sum += float64(l.table[(a*l.v+b)*l.v+c])
		count++
		a, b = b, c
	}
	for i := 0; i < len(label); i++ {
		step(sym(label[i]))
	}
	step(0)
	return sum / l.scale / float64(count)
}

// ramp maps x linearly from [lo,hi] onto [0,1], clamped.
func ramp(x, lo, hi float64) float64 {
	switch {
	case x <= lo:
		return 0
	case x >= hi:
		return 1
	}
	return (x - lo) / (hi - lo)
}

func (l *Lexical) score(label string) schema.Assessment {
	f := l.measure(label)
	damp := math.Min(1, float64(f.length)/shortLabel)
	parts := []schema.Reason{
		{
			Code:   schema.ReasonRareNgrams,
			Detail: fmt.Sprintf("letter sequences rare in popular names (%.1f bits/char)", f.meanNLL),
			Weight: weightNgram * ramp(f.meanNLL, 3.5, 6.0) * damp,
		},
		{
			Code:   schema.ReasonHighEntropy,
			Detail: fmt.Sprintf("high character entropy (%.2f bits)", f.entropy),
			Weight: weightEntropy * ramp(f.entropy, 2.8, 4.0) * damp,
		},
		{
			Code:   schema.ReasonDigitHeavy,
			Detail: fmt.Sprintf("%.0f%% of characters are digits", f.digit*100),
			Weight: weightDigit * ramp(f.digit, 0.15, 0.5) * damp,
		},
		{
			Code:   schema.ReasonConsonantRun,
			Detail: fmt.Sprintf("run of %d consonants", f.consonant),
			Weight: weightConsonant * ramp(float64(f.consonant), 3, 6) * damp,
		},
		{
			Code:   schema.ReasonLongLabel,
			Detail: fmt.Sprintf("long label (%d characters)", f.length),
			Weight: weightLength * ramp(float64(f.length), 12, 24) * damp,
		},
	}
	total := 0.0
	reasons := make([]schema.Reason, 0, len(parts))
	for _, p := range parts {
		total += p.Weight
		if p.Weight >= reasonFloor {
			reasons = append(reasons, p)
		}
	}
	total = math.Min(1, math.Max(0, total))
	verdict := schema.VerdictBenign
	if total >= maliciousThreshold {
		verdict = schema.VerdictMalicious
	}
	sort.SliceStable(reasons, func(i, j int) bool { return reasons[i].Weight > reasons[j].Weight })
	if len(reasons) == 0 || (verdict == schema.VerdictBenign && total < quietScore) {
		reasons = nil
	}
	return schema.Assessment{Verdict: verdict, Score: total, Reasons: reasons}
}
