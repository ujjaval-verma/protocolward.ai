// SPDX-License-Identifier: Apache-2.0

// Command build-ngrams regenerates pkg/detect/ngrams.bin (the character-
// trigram table embedded by the lexical DGA detector) and the lexical eval
// fixture testdata/eval/lexical-v1.jsonl.
//
// Source: the Majestic Million (https://majestic.com/reports/majestic-million),
// licensed CC BY 3.0. Only derived statistics (quantised trigram
// log-probabilities) and a 1-in-10 held-out sample of top-ranked domain
// names are committed; the CSV itself is not. Attribution lives in
// pkg/detect/NOTICE and testdata/eval/NOTICE.
//
// Usage (from the repo root):
//
//	curl -sSfLo /tmp/majestic_million.csv https://downloads.majestic.com/majestic_million.csv
//	go run ./scripts/build-ngrams -in /tmp/majestic_million.csv
//
// The output is deterministic for a given input CSV. Record the CSV's
// SHA-256 and download date in pkg/detect/NOTICE when regenerating.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

// alphabet is written into the table header; pkg/detect reads it back
// from the header, so the two sides cannot drift. Index 0 is the
// start/end boundary symbol.
const alphabet = "^abcdefghijklmnopqrstuvwxyz0123456789-"

const (
	magic   = "PWNG"
	version = 1
	scale   = 8 // quanta per bit: stored byte = round(-log2 p * scale), max 255
	beta    = 1.0
)

type options struct {
	in           string
	out          string
	evalOut      string
	trainTop     int
	holdoutTop   int
	holdoutEvery int
	dgaPerFamily int
}

func main() {
	var o options
	flag.StringVar(&o.in, "in", "", "path to majestic_million.csv (required)")
	flag.StringVar(&o.out, "out", "pkg/detect/ngrams.bin", "trigram table output path")
	flag.StringVar(&o.evalOut, "eval-out", "testdata/eval/lexical-v1.jsonl", "eval fixture output path")
	flag.IntVar(&o.trainTop, "train-top", 200000, "train on ranks 1..N (minus the held-out ranks)")
	flag.IntVar(&o.holdoutTop, "holdout-top", 20000, "hold out ranks 1..N that are multiples of -holdout-every")
	flag.IntVar(&o.holdoutEvery, "holdout-every", 10, "hold out every Nth rank within -holdout-top")
	flag.IntVar(&o.dgaPerFamily, "dga-per-family", 500, "generated DGA names per family in the eval fixture")
	flag.Parse()
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "build-ngrams:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.in == "" {
		return errors.New("-in is required (download https://downloads.majestic.com/majestic_million.csv)")
	}
	f, err := os.Open(o.in)
	if err != nil {
		return err
	}
	defer f.Close()
	train, holdout, err := readMajestic(f, o)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.out, buildTable(train), 0o600); err != nil {
		return err
	}
	return writeEval(o.evalOut, holdout, generateDGA(o.dgaPerFamily))
}

// readMajestic returns training labels (first DNS label of each domain)
// and held-out full domain names. Rows whose first label contains bytes
// outside the alphabet, or that are punycode, are skipped.
func readMajestic(r io.Reader, o options) (train, holdout []string, err error) {
	cr := csv.NewReader(bufio.NewReader(r))
	cr.FieldsPerRecord = -1
	if _, err := cr.Read(); err != nil { // header
		return nil, nil, fmt.Errorf("read header: %w", err)
	}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if len(rec) < 3 {
			continue
		}
		rank, err := strconv.Atoi(rec[0])
		if err != nil {
			return nil, nil, fmt.Errorf("bad rank %q: %w", rec[0], err)
		}
		if rank > o.trainTop {
			break
		}
		domain := strings.ToLower(strings.TrimSuffix(rec[2], "."))
		first, _, _ := strings.Cut(domain, ".")
		if first == "" || strings.HasPrefix(first, "xn--") || !inAlphabet(first) {
			continue
		}
		if rank <= o.holdoutTop && rank%o.holdoutEvery == 0 {
			holdout = append(holdout, domain)
			continue
		}
		train = append(train, first)
	}
	return train, holdout, nil
}

func inAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet[1:], s[i]) < 0 {
			return false
		}
	}
	return true
}

func sym(c byte) int { return strings.IndexByte(alphabet, c) }

// buildTable computes P(c | a b) with the bigram-backoff interpolation
// (C(abc) + beta*Pbi(c|b)) / (C(ab.) + beta), Pbi(c|b) = (C(bc)+1)/(C(b.)+V),
// over the padded string "^^" + label + "^", and serialises it.
func buildTable(labels []string) []byte {
	v := len(alphabet)
	c3 := make([]float64, v*v*v)
	c2 := make([]float64, v*v)
	for _, l := range labels {
		p := "^^" + l + "^"
		for i := 0; i+2 < len(p); i++ {
			a, b, c := sym(p[i]), sym(p[i+1]), sym(p[i+2])
			c3[(a*v+b)*v+c]++
			c2[b*v+c]++
		}
	}
	out := make([]byte, 0, 7+v+v*v*v)
	out = append(out, magic...)
	out = append(out, version, scale, byte(v))
	out = append(out, alphabet...)
	for a := range v {
		for b := range v {
			var ctx3, ctx2 float64
			for c := range v {
				ctx3 += c3[(a*v+b)*v+c]
				ctx2 += c2[b*v+c]
			}
			for c := range v {
				pbi := (c2[b*v+c] + 1) / (ctx2 + float64(v))
				p := (c3[(a*v+b)*v+c] + beta*pbi) / (ctx3 + beta)
				q := math.Round(-math.Log2(p) * scale)
				out = append(out, byte(math.Min(q, 255)))
			}
		}
	}
	return out
}

type evalLine struct {
	Hostname        string `json:"hostname"`
	ExpectedVerdict string `json:"expected_verdict"`
	Label           string `json:"label"`
}

func writeEval(path string, benign []string, dga []dgaRecord) error {
	f, err := os.Create(path) //nolint:gosec // operator-supplied output path
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, h := range benign {
		if err := enc.Encode(evalLine{h, "benign", "benign-majestic"}); err != nil {
			return errors.Join(err, f.Close())
		}
	}
	for _, d := range dga {
		if err := enc.Encode(evalLine{d.Hostname, "malicious", d.Label}); err != nil {
			return errors.Join(err, f.Close())
		}
	}
	if err := w.Flush(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}
