// SPDX-License-Identifier: Apache-2.0

// Package decoy implements an in-memory exact-match set of honeytoken
// hostnames (decoys). A DNS query whose qname matches a decoy entry is
// expected to trip an alert in the dataplane — see the package consumer in
// internal/dataplane.
//
// # Why exact match, not suffix
//
// Decoys are point-targets: an operator plants "vault.internal.acme" as
// scenery; only an attacker who scraped the local config would query that
// exact name. A subdomain like "scanner.vault.internal.acme" almost
// certainly is NOT the planted token (the attacker would query the planted
// name as-is) and may instead be a benign device. Suffix matching would
// turn decoys into a noisy second blocklist — the opposite of the high-
// confidence threat signal they are meant to be. This is the semantic
// difference from hostlist.Set, which deliberately performs longest-suffix
// matching for blocklist/allowlist use cases.
//
// # Construction
//
// New loads hosts-file sources from disk; FromEntries builds the same Set
// from an in-memory slice for the browser demo build (cmd/wardwasm).
//
// # Invariants
//
//   - No silent drops (invariant #7): every parser skip is reported via Stats.
//   - Every error names remediation (invariant #8): exported error types
//     include a remediation hint in their Error() string.
//   - decoy.Set deliberately does NOT implement policy.Matcher. The Match
//     signature is structurally compatible but the absence of an interface
//     assertion prevents a future contributor from wiring a decoy set into
//     policy.Engine as an allow/block source — which would route decoy hits
//     through Engine.Decide and lose the alarm semantic. (Ralph spec-review
//     T0 B4, 2026-05-25.)
package decoy

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"protocolward.ai/ward/internal/hostlist"
)

// MissingSourceError is returned when a configured source file cannot be
// opened. Mirrors hostlist.MissingSourceError so the dataplane error-handling
// pattern is consistent across the two surfaces.
type MissingSourceError struct {
	Path string
	Err  error
}

func (e *MissingSourceError) Error() string {
	return fmt.Sprintf("decoy: source not found at %q: %v — remediation: create the file or remove the entry from ward.yaml decoys[*]", e.Path, e.Err)
}

func (e *MissingSourceError) Unwrap() error { return e.Err }

// EmptySourceError is returned when a source loads zero parseable entries.
type EmptySourceError struct {
	ID   string
	Path string
}

func (e *EmptySourceError) Error() string {
	return fmt.Sprintf("decoy: source %q at %q yielded zero parseable entries — remediation: verify the file is a hosts-file with \"0.0.0.0 hostname\" or plain \"hostname\" lines", e.ID, e.Path)
}

// DuplicateIDError is returned when two decoy sources share an id.
type DuplicateIDError struct {
	ID string
}

func (e *DuplicateIDError) Error() string {
	return fmt.Sprintf("decoy: duplicate source id %q — remediation: each decoys[*].id must be unique", e.ID)
}

// InvalidEntryError is returned by FromEntries for an entry that cannot be
// a decoy hostname. Index is the entry's position in the input slice.
type InvalidEntryError struct {
	Index int
	Entry string
}

func (e *InvalidEntryError) Error() string {
	return fmt.Sprintf("decoy: entry %d %q is not a valid hostname — remediation: pass bare hostnames such as \"nas-backup.home.arpa\" (ASCII letters, digits, hyphen and underscore; labels up to 63 bytes, name up to 253; no spaces, control characters, comments, IP prefix or empty labels)", e.Index, truncateEntry(e.Entry))
}

// maxEchoedEntryBytes bounds how much of a rejected entry Error() echoes.
const maxEchoedEntryBytes = 64

// truncateEntry shortens s to at most maxEchoedEntryBytes bytes without
// splitting a UTF-8 sequence, marking the cut with "...".
func truncateEntry(s string) string {
	if len(s) <= maxEchoedEntryBytes {
		return s
	}
	cut := maxEchoedEntryBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// Stats describes per-source parse outcome. Same shape as hostlist.Stats so
// the caller can log both kinds uniformly.
type Stats struct {
	ID           string
	Path         string
	Entries      int
	SkippedLines int
	LoadDuration time.Duration
}

// Set is the read-only exact-match decoy lookup. Construct via New; the
// returned *Set is safe for concurrent reads (no runtime mutation surface
// in v0.1).
type Set struct {
	entries map[string]string // normalized hostname -> decoy_id
}

// New parses sources into a Set. Sources are processed in order; a
// duplicate-id collision returns an error without partial state.
func New(sources []hostlist.Source) (*Set, []Stats, error) {
	if err := checkDuplicateIDs(sources); err != nil {
		return nil, nil, err
	}
	s := &Set{entries: make(map[string]string)}
	stats := make([]Stats, 0, len(sources))
	for _, src := range sources {
		st, err := s.loadOne(src)
		if err != nil {
			return nil, nil, err
		}
		stats = append(stats, st)
	}
	return s, stats, nil
}

// FromEntries builds a Set from bare hostnames without touching the
// filesystem (the browser build has none). Entries are normalized like
// file lines (lowercase, trimmed, one trailing dot stripped). Unlike the
// lenient file parser, each entry must also be a name a DNS query could
// carry: ASCII letters, digits, hyphen and underscore only (so no
// whitespace, control characters or '#'), labels of 1-63 bytes without a
// leading or trailing hyphen, and at most 253 bytes in all. These are the
// same rules the browser demo's Decide applies to a query, so an accepted
// decoy can always match. An invalid entry fails
// the whole call with *InvalidEntryError and returns no Set. Duplicates
// coalesce. A nil or empty slice yields an empty, usable Set. Match
// reports decoy_id hostlist.InlineSourceID for every entry.
func FromEntries(names []string) (*Set, error) {
	s := &Set{entries: make(map[string]string, len(names))}
	for i, raw := range names {
		host := normalize(raw)
		if !validDecoyName(host) {
			return nil, &InvalidEntryError{Index: i, Entry: raw}
		}
		s.entries[host] = hostlist.InlineSourceID
	}
	return s, nil
}

// validDecoyName reports whether host (already normalized) is a DNS-shaped
// name: <=253 bytes, labels 1-63 bytes of [a-z0-9_-] with no leading or
// trailing hyphen.
func validDecoyName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			switch c := label[i]; {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// Match reports whether hostname matches a decoy entry. Returns the
// decoy_id and the matched (already-normalized) hostname on hit. Match is
// case-insensitive and tolerates a trailing dot.
func (s *Set) Match(hostname string) (decoyID, matched string, ok bool) {
	norm := normalize(hostname)
	if norm == "" {
		return "", "", false
	}
	id, hit := s.entries[norm]
	if !hit {
		return "", "", false
	}
	return id, norm, true
}

func (s *Set) loadOne(src hostlist.Source) (Stats, error) {
	t0 := time.Now()
	f, err := os.Open(src.Path)
	if err != nil {
		return Stats{}, &MissingSourceError{Path: src.Path, Err: err}
	}
	defer f.Close()

	stat := Stats{ID: src.ID, Path: src.Path}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		host, ok := parseLine(raw)
		if !ok {
			if strings.TrimSpace(raw) != "" {
				stat.SkippedLines++
			}
			continue
		}
		if _, dup := s.entries[host]; dup {
			// Duplicate within or across sources is silently coalesced
			// (same host, same alarm); count once in Entries.
			continue
		}
		s.entries[host] = src.ID
		stat.Entries++
	}
	if err := scanner.Err(); err != nil {
		return Stats{}, fmt.Errorf("decoy: scan %q: %w — remediation: check filesystem health and re-run", src.Path, err)
	}
	if stat.Entries == 0 {
		return Stats{}, &EmptySourceError{ID: src.ID, Path: src.Path}
	}
	stat.LoadDuration = time.Since(t0)
	return stat, nil
}

func parseLine(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	// strip inline comment
	if i := strings.Index(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	switch len(fields) {
	case 1:
		return normalize(fields[0]), true
	case 2:
		// hosts-file shape: "0.0.0.0 hostname"
		return normalize(fields[1]), true
	default:
		return "", false
	}
}

func normalize(s string) string {
	out := strings.ToLower(strings.TrimSpace(s))
	out = strings.TrimSuffix(out, ".")
	return out
}

func checkDuplicateIDs(sources []hostlist.Source) error {
	seen := make(map[string]struct{}, len(sources))
	for _, s := range sources {
		if _, dup := seen[s.ID]; dup {
			return &DuplicateIDError{ID: s.ID}
		}
		seen[s.ID] = struct{}{}
	}
	return nil
}
