// SPDX-License-Identifier: Apache-2.0

// Package hostlist parses hosts-file sources into an in-memory hash-indexed
// suffix matcher used by the dataplane to short-circuit DNS queries for listed hostnames.
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
// has no parseable entries), [DuplicateIDError] (two sources share the same ID),
// [TooManySourcesError] (more sources than a Set can attribute).
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
//   - Stats.Entries counts unique hostnames per source, not raw lines;
//     a hostname listed multiple times within one source counts as one entry.
package hostlist

import (
	"bufio"
	"errors"
	"fmt"
	"hash/maphash"
	"io/fs"
	"log/slog"
	"math"
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
	Entries      int // unique hostnames parsed from this source; duplicates within the same source count once, but a hostname also present in another source still counts here
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
// Hostnames are stored as written (normalized, forward order) in one
// concatenated byte arena. A hash-indexed table maps hash(host) to a packed
// word (arena offset, length, list index), instead of a string header and
// allocation per entry. Measured by BenchmarkLoadRetained: about 60 B/entry
// retained at 1M 22-byte names, of which roughly 38 B is the index including
// map overhead. Match probes the full name and then each label-bounded suffix,
// longest first, and verifies every candidate against the arena, so a hash
// collision can never produce a false hit. Names that cannot be packed (longer
// than 255 bytes) or that collide with a different name live in the overflow
// map.
type Set struct {
	ids   []string            // list index -> list_id (source ID, or InlineSourceID)
	hash  func(string) uint64 // per-Set seeded hash; tests may override
	index map[uint64]uint64   // hash(host) -> off<<offShift | len<<lenShift | listIdx
	arena []byte              // concatenated hostnames, forward order, no separators
	over  map[string]uint16   // hostnames that cannot use index: collisions and len > maxPackedLen
}

const (
	warnCapPerSource = 16
	scanBufInitial   = 64 * 1024       // bufio.Scanner initial buffer size
	maxLineSizeBytes = 1 * 1024 * 1024 // guard against adversarial / truncated lines (1 MiB)

	maxSources           = math.MaxUint16 // list index is 16 bits
	maxPackedLen         = math.MaxUint8  // name length is 8 bits
	lenShift             = 16
	offShift             = 24
	maxPackedOff  uint64 = 1<<(64-offShift) - 1 // arena offset is 40 bits
	listIdxMask   uint64 = 1<<lenShift - 1
	packedLenMask uint64 = 1<<(offShift-lenShift) - 1
)

// TooManySourcesError is returned by Load when more sources are configured
// than a Set can attribute matches to.
type TooManySourcesError struct {
	Count int
}

func (e *TooManySourcesError) Error() string {
	return fmt.Sprintf("hostlist: %d sources configured, the limit is %d — remediation: merge the sources in this list (blocklists[*] or allowlists[*]) into fewer files", e.Count, maxSources)
}

func newHash() func(string) uint64 {
	seed := maphash.MakeSeed()
	return func(s string) uint64 { return maphash.String(seed, s) }
}

// newSet returns an empty Set whose list indexes resolve through ids.
func newSet(ids []string, hash func(string) uint64) *Set {
	return &Set{ids: ids, hash: hash, index: make(map[uint64]uint64)}
}

// len returns the number of distinct hostnames stored.
func (s *Set) len() int { return len(s.index) + len(s.over) }

// add stores host under list index idx. existed reports whether host was
// already present, and prev is then the list index it was stored under; the
// entry is overwritten so the later source wins.
func (s *Set) add(host string, idx uint16) (prev uint16, existed bool) {
	if len(host) <= maxPackedLen {
		h := s.hash(host)
		if p, ok := s.index[h]; ok {
			if s.packedEquals(p, host) {
				s.index[h] = p&^listIdxMask | uint64(idx)
				return listIdx(p), true
			}
			return s.addOver(host, idx) // hash collision with a different name
		}
		if off := len(s.arena); off >= 0 && uint64(off) <= maxPackedOff {
			s.index[h] = uint64(off)<<offShift | uint64(len(host))<<lenShift | uint64(idx)
			s.arena = append(s.arena, host...)
			return 0, false
		}
	}
	return s.addOver(host, idx)
}

func (s *Set) addOver(host string, idx uint16) (prev uint16, existed bool) {
	if s.over == nil {
		s.over = make(map[string]uint16)
	}
	prev, existed = s.over[host]
	s.over[host] = idx
	return prev, existed
}

// listIdx extracts the list index from a packed word.
func listIdx(p uint64) uint16 {
	v := p & listIdxMask
	if v > math.MaxUint16 {
		return 0 // unreachable: the mask keeps 16 bits
	}
	return uint16(v)
}

// packedEquals reports whether the arena bytes referenced by p equal host.
func (s *Set) packedEquals(p uint64, host string) bool {
	off := p >> offShift
	n := p >> lenShift & packedLenMask
	return off+n <= uint64(len(s.arena)) && string(s.arena[off:off+n]) == host
}

// trim drops append slack from the arena.
func (s *Set) trim() {
	s.arena = append(make([]byte, 0, len(s.arena)), s.arena...)
}

func checkSourceCount(sources []Source) error {
	if len(sources) > maxSources {
		return &TooManySourcesError{Count: len(sources)}
	}
	return nil
}

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
	ids := make([]string, len(sources))
	for i, src := range sources {
		ids[i] = src.ID
	}
	set := newSet(ids, newHash())
	stats, err := set.load(sources)
	if err != nil {
		return nil, nil, err
	}
	return set, stats, nil
}

// load reads every source into s; source i gets list index i.
func (s *Set) load(sources []Source) ([]Stats, error) {
	if err := checkSourceCount(sources); err != nil {
		return nil, err
	}
	if len(s.ids) != len(sources) {
		return nil, fmt.Errorf("hostlist: internal error: %d list ids for %d sources — remediation: build the Set with one id per source (report this as a bug)", len(s.ids), len(sources))
	}
	stats := make([]Stats, 0, len(sources))
	for i, src := range sources {
		if i < 0 || i > math.MaxUint16 {
			return nil, &TooManySourcesError{Count: len(sources)}
		}
		stat, err := loadOne(src, uint16(i), s)
		if err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	s.trim()
	return stats, nil
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
	return fromEntries(names, newHash())
}

func fromEntries(names []string, hash func(string) uint64) (*Set, error) {
	set := newSet([]string{InlineSourceID}, hash)
	for i, raw := range names {
		host, ok, reason := validateHostname(raw)
		if !ok {
			// The reason quotes the host; keep that echo bounded too.
			reason = strings.Replace(reason, strconv.Quote(raw), strconv.Quote(truncateEntry(raw)), 1)
			return nil, &InvalidEntryError{Index: i, Entry: raw, Reason: reason}
		}
		set.add(host, 0)
	}
	set.trim()
	return set, nil
}

// loadOne reads one source file into the shared Set under list index idx and
// returns Stats. File handle is closed via defer on every exit path, including
// panics.
// entriesCount counts unique hostnames parsed from this source's file, not raw
// accepted lines; a hostname that appears multiple times within this file is
// counted only once (it is already stored under idx). Cross-source duplicates
// (the name already present from a prior source) are still overwritten so that
// later-source-wins semantics are preserved, and they do increment this
// source's count because Entries is per-file, not net-new to the global set.
func loadOne(src Source, idx uint16, set *Set) (Stats, error) {
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
			prev, existed := set.add(host, idx)
			switch {
			case !existed:
				entriesCount++
			case prev != idx:
				entriesCount++
				slog.Info("hostlist: hostname appears in multiple sources",
					"hostname", host,
					"previous_list_id", set.ids[prev],
					"new_list_id", src.ID,
				)
			}
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
