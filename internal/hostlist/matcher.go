// SPDX-License-Identifier: Apache-2.0

package hostlist

import "strings"

// Match probes the hash-indexed storage for the longest blocklisted suffix
// that is an ancestor (or the same as) the queried hostname. Returns the
// list_id, the matched suffix (lowercased, no trailing dot), and ok=true on
// hit; ok=false on miss. Empty / lone-dot hostnames return ok=false. Match
// folds the hostname with FoldName and does not allocate for an already
// lowercase name (a trailing dot is also free).
// A zero-value Set matches nothing.
//
// The returned matched string may be a substring of hostname and shares its
// memory, so callers must pass an immutable string (not one aliasing a
// mutable byte buffer).
//
// Algorithm: fold the hostname with FoldName (lowercase, strip one trailing
// dot, reject empty), then probe the full name and each label-bounded suffix
// after a dot, longest first. Each probe hashes the candidate, looks it up in the index and
// verifies the arena bytes, so the first hit is the longest matching suffix
// and a hash collision cannot cause a false hit.
//
// Example: list = {example.com, ads.example.com}, qname = "tracker.ads.example.com"
//
//	probes (longest first): "tracker.ads.example.com" → miss
//	                        "ads.example.com"         → hit (list_id, matched="ads.example.com")
func (s *Set) Match(hostname string) (listID, matched string, ok bool) {
	if s.index == nil && len(s.over) == 0 {
		return "", "", false
	}
	cur := FoldName(hostname)
	if cur == "" {
		return "", "", false
	}
	for {
		if idx, hit := s.lookup(cur); hit {
			return s.ids[idx], cur, true
		}
		i := strings.IndexByte(cur, '.')
		if i < 0 {
			return "", "", false
		}
		cur = cur[i+1:]
	}
}

// lookup returns the list index stored for exactly host.
func (s *Set) lookup(host string) (uint16, bool) {
	if len(host) <= maxPackedLen {
		if p, ok := s.index[s.hash(host)]; ok && s.packedEquals(p, host) {
			return listIdx(p), true
		}
	}
	if len(s.over) > 0 {
		idx, ok := s.over[host]
		return idx, ok
	}
	return 0, false
}
