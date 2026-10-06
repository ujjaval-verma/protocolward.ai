// SPDX-License-Identifier: Apache-2.0

// Package hostlist parses hosts-file sources into an in-memory reversed-label
// matcher used by the dataplane to short-circuit DNS queries for listed hostnames.
//
// # Usage
//
// Call [Load] with one or more [Source] values to obtain a compiled [Set] and
// per-source [Stats]. Pass the [Set] to the dataplane. On a match, [Set.Match]
// returns the list_id, the matched suffix, and ok=true.
//
// Call [FromEntries] with bare hostnames to build a [Set] in memory (no
// files); used by the browser demo build in cmd/wardwasm.
//
// Error types: [MissingSourceError] (file not found), [EmptySourceError] (file
// has no parseable entries), [DuplicateIDError] (two sources share the same ID).
//
// # Invariants
//
//   - No silent drops (invariant #7): every parser skip is counted in Stats and
//     the first 16 skips per source emit a WARN log; subsequent skips increment
//     the counter silently and are reported in the per-source summary.
//   - Every error names remediation (invariant #8): exported error types include
//     a remediation hint in their Error() string.
//   - Strict at the file level, lenient at the line level: missing or
//     entry-empty source files fail Load; unparsable lines are skipped + counted.
//   - Stats.Entries counts unique reversed-label keys per source, not raw lines;
//     a hostname listed multiple times within one source counts as one entry.
package hostlist

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Source is one configured input to Load.
type Source struct {
	ID   string // logical name used in attribution logs
	Path string // local file path
}

// Stats describes per-source parse outcome.
type Stats struct {
	ID           string
	Path         string
	Entries      int // unique reversed-label keys parsed from this source; duplicates within the same source count once, but a hostname also present in another source still counts here
	SkippedLines int
	LoadDuration time.Duration
}

// MissingSourceError is returned when a configured source file cannot be opened.
type MissingSourceError struct {
	Path string
	Err  error
}

func (e *MissingSourceError) Error() string {
	return fmt.Sprintf("hostlist: source not found at %q: %v — remediation: create the file or remove the entry from ward.yaml", e.Path, e.Err)
}

func (e *MissingSourceError) Unwrap() error { return e.Err }

// EmptySourceError is returned when a source loads zero parseable entries.
type EmptySourceError struct {
	ID   string
	Path string
}

func (e *EmptySourceError) Error() string {
	return fmt.Sprintf("hostlist: source %q at %q yielded zero parseable entries — remediation: verify the file is a hosts-file with \"0.0.0.0 hostname\" or \"127.0.0.1 hostname\" lines", e.ID, e.Path)
}

// DuplicateIDError is returned when two sources share an id.
type DuplicateIDError struct {
	ID string
}

func (e *DuplicateIDError) Error() string {
	return fmt.Sprintf("hostlist: duplicate source id %q — remediation: each blocklists[*].id and allowlists[*].id must be unique across all hostlist sources", e.ID)
}

// InlineSourceID is the list_id Match reports for entries supplied through
// FromEntries, which have no configured source file and therefore no
// operator-chosen id.
const InlineSourceID = "inline"

// InvalidEntryError is returned by FromEntries when an entry is not a bare,
// valid hostname. Index is the entry's position in the input slice.
type InvalidEntryError struct {
	Index  int
	Entry  string
	Reason string
}

func (e *InvalidEntryError) Error() string {
	return fmt.Sprintf("hostlist: entry %d %q rejected: %s — remediation: pass bare hostnames such as \"ads.example.com\" (no IP prefix, no AdGuard syntax)", e.Index, truncateEntry(e.Entry), e.Reason)
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

// Set is the in-memory compiled blocklist.
//
// Storage uses reversed-label keys: "ads.example.com" is stored as
// "com.example.ads". This lets Match walk progressively shorter prefixes
// (longest-suffix-first) with O(labels) map probes.
type Set struct {
	entries map[string]string // reversed-label hostname → list_id
}

const (
	warnCapPerSource = 16
	scanBufInitial   = 64 * 1024       // bufio.Scanner initial buffer size
	maxLineSizeBytes = 1 * 1024 * 1024 // guard against adversarial / truncated lines (1 MiB)
)

// Load reads each source file, parses hosts-file entries, and returns a
// compiled Set plus per-source Stats.
//
// Strict at the file level: a missing or fully-empty (zero parseable entries)
// source returns a typed error (MissingSourceError, EmptySourceError).
// Lenient at the line level: unparsable lines are skipped and counted in
// Stats; the first warnCapPerSource skips per source emit a WARN log via
// slog and further skips are silent.
func Load(sources []Source) (*Set, []Stats, error) {
	if err := checkDuplicateIDs(sources); err != nil {
		return nil, nil, err
	}
	set := &Set{entries: make(map[string]string)}
	stats := make([]Stats, 0, len(sources))
	for _, src := range sources {
		stat, err := loadOne(src, set.entries)
		if err != nil {
			return nil, nil, err
		}
		stats = append(stats, stat)
	}
	return set, stats, nil
}

// FromEntries compiles an in-memory Set from bare hostnames without touching
// the filesystem (the browser build has none). Each entry passes the same
// normalize + validate gate as a hosts-file line accepted by Load
// (lowercase, trailing dot stripped, ASCII letters/digits/dot/hyphen,
// system aliases excluded). The first invalid entry fails the whole call
// with *InvalidEntryError and returns no Set — no partial state.
// Duplicates coalesce. A nil or empty slice yields an empty, usable Set.
// Every match reports list_id InlineSourceID.
func FromEntries(names []string) (*Set, error) {
	entries := make(map[string]string, len(names))
	for i, raw := range names {
		host, ok, reason := validateHostname(raw)
		if !ok {
			// The reason quotes the host; keep that echo bounded too.
			reason = strings.Replace(reason, strconv.Quote(raw), strconv.Quote(truncateEntry(raw)), 1)
			return nil, &InvalidEntryError{Index: i, Entry: raw, Reason: reason}
		}
		entries[reverseLabels(host)] = InlineSourceID
	}
	return &Set{entries: entries}, nil
}

// loadOne reads one source file into the shared entries map and returns Stats.
// File handle is closed via defer on every exit path, including panics.
// entriesCount counts unique reversed-label keys parsed from this source's
// file, not raw accepted lines; a hostname that appears multiple times within
// this file is counted only once. Cross-source duplicates (the same key
// already present from a prior source) are still overwritten so that
// later-source-wins semantics are preserved, and they do increment this
// source's count because Entries is per-file, not net-new to the global set.
func loadOne(src Source, entries map[string]string) (Stats, error) {
	start := time.Now()
	f, err := os.Open(src.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Stats{}, &MissingSourceError{Path: src.Path, Err: err}
		}
		return Stats{}, fmt.Errorf("hostlist: open %q: %w — remediation: check file permissions", src.Path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("hostlist: close error (data already read)",
				"source_id", src.ID,
				"path", src.Path,
				"error", cerr.Error(),
				"remediation", "data was successfully parsed before close — investigate filesystem if this recurs",
			)
		}
	}()

	entriesCount := 0
	seenInSource := make(map[string]struct{})
	skipped := 0
	warnsEmitted := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, scanBufInitial), maxLineSizeBytes)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		host, ok, reason := parseLine(line)
		if ok {
			rev := reverseLabels(host)
			if _, exists := seenInSource[rev]; !exists {
				seenInSource[rev] = struct{}{}
				entriesCount++
			}
			if prevID, crossDup := entries[rev]; crossDup && prevID != src.ID {
				slog.Info("hostlist: hostname appears in multiple sources",
					"hostname", host,
					"previous_list_id", prevID,
					"new_list_id", src.ID,
				)
			}
			entries[rev] = src.ID
			continue
		}
		if reason == "" {
			continue // silent skip (comment, blank)
		}
		skipped++
		if warnsEmitted < warnCapPerSource {
			slog.Warn("hostlist: skipped unparsable line",
				"source_id", src.ID,
				"path", src.Path,
				"line", lineNo,
				"content", line,
				"reason", reason,
			)
			warnsEmitted++
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return Stats{}, fmt.Errorf("hostlist: read %q: %w — remediation: check the file is not truncated", src.Path, scanErr)
	}

	if entriesCount == 0 {
		return Stats{}, &EmptySourceError{ID: src.ID, Path: src.Path}
	}

	return Stats{
		ID:           src.ID,
		Path:         src.Path,
		Entries:      entriesCount,
		SkippedLines: skipped,
		LoadDuration: time.Since(start),
	}, nil
}

func checkDuplicateIDs(sources []Source) error {
	seen := make(map[string]struct{}, len(sources))
	for _, s := range sources {
		if _, dup := seen[s.ID]; dup {
			return &DuplicateIDError{ID: s.ID}
		}
		seen[s.ID] = struct{}{}
	}
	return nil
}
