// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/md5" //nolint:gosec // MD5 reproduces the Bamital-family name shape; not a security use
	"encoding/hex"
	"fmt"
	"time"
)

// wikiDGA is the date-seeded reference DGA printed in the Wikipedia
// "Domain generation algorithm" article. Known vector: 2014-01-07 →
// "intgmxdeadnxuyla". Python ints are unbounded; every intermediate here
// stays below 2^58, so uint64 arithmetic reproduces it exactly.
func wikiDGA(year, month, day uint64) string {
	b := make([]byte, 0, 16)
	for range 16 {
		year = ((year ^ 8*year) >> 11) ^ ((year & 0xFFFFFFF0) << 17)
		month = ((month ^ 4*month) >> 25) ^ 16*(month&0xFFFFFFF8)
		day = ((day ^ (day << 13)) >> 19) ^ ((day & 0xFFFFFFFE) << 12)
		b = append(b, byte((year^month^day)%25)+'a')
	}
	return string(b)
}

// ramnitRand is the Park–Miller minimal-standard LCG (Schrage's method)
// used by the Ramnit DGA family, per public reverse-engineering write-ups.
type ramnitRand struct{ value uint32 }

func (r *ramnitRand) intn(mod uint32) uint32 {
	ix := int64(r.value)
	ix = 16807*(ix%127773) - 2836*(ix/127773)
	r.value = uint32(ix) //nolint:gosec // deliberate truncation: matches the reference "& 0xFFFFFFFF"
	return r.value % mod
}

// ramnitDGA yields n Ramnit-style labels (8–19 letters from a–y) for seed.
func ramnitDGA(seed uint32, n int) []string {
	r := &ramnitRand{value: seed}
	out := make([]string, 0, n)
	for range n {
		seedA := r.value
		length := r.intn(12) + 8
		seedB := r.value
		b := make([]byte, 0, length)
		for range length {
			b = append(b, byte(r.intn(25))+'a')
		}
		out = append(out, string(b))
		m := uint64(seedA) * uint64(seedB)
		r.value = uint32((m + m>>32) & 0xFFFFFFFF) //nolint:gosec // masked to 32 bits
	}
	return out
}

// md5DGA yields the Bamital-family name shape: 32 lowercase hex chars,
// the MD5 of a date-and-index string.
func md5DGA(day time.Time, i int) string {
	sum := md5.Sum([]byte(fmt.Sprintf("%s|%d", day.Format("2006-01-02"), i))) //nolint:gosec // see import comment
	return hex.EncodeToString(sum[:])
}

// dgaRecord is one generated malicious eval name.
type dgaRecord struct {
	Hostname string
	Label    string
}

// generateDGA returns perFamily names from each of the three families,
// deterministically (fixed dates and seeds).
func generateDGA(perFamily int) []dgaRecord {
	out := make([]dgaRecord, 0, 3*perFamily)
	start := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	for i := range perFamily {
		d := start.AddDate(0, 0, i)
		out = append(out, dgaRecord{
			Hostname: wikiDGA(uint64(d.Year()), uint64(d.Month()), uint64(d.Day())) + ".com", //nolint:gosec // positive date parts
			Label:    "dga-wiki",
		})
	}
	seeds := []uint32{0x4F2A9C1B, 0x1D3E5F70, 0x9ABCDEF1, 0x0BADC0DE, 0x2468ACE0}
	per := (perFamily + len(seeds) - 1) / len(seeds)
	ram := 0
	for _, s := range seeds {
		for _, lbl := range ramnitDGA(s, per) {
			if ram == perFamily {
				break
			}
			out = append(out, dgaRecord{Hostname: lbl + ".com", Label: "dga-ramnit"})
			ram++
		}
	}
	for i := range perFamily {
		d := start.AddDate(0, 0, i/10)
		out = append(out, dgaRecord{Hostname: md5DGA(d, i%10) + ".info", Label: "dga-md5"})
	}
	return out
}
