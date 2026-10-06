// SPDX-License-Identifier: Apache-2.0

package hostlist

import "strings"

// reverseLabels turns "ads.example.com" into "com.example.ads".
// Empty input returns empty; single-label input returns itself.
func reverseLabels(host string) string {
	labels := strings.Split(host, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// Match probes the reversed-label storage for the longest blocklisted suffix
// that is an ancestor (or the same as) the queried hostname. Returns the
// list_id, the matched suffix (lowercased, no trailing dot), and ok=true on
// hit; ok=false on miss. Empty / lone-dot hostnames return ok=false without
// allocation.
//
// Algorithm: normalize the hostname (lowercase, strip trailing dot, reject
// empty), reverse its labels, then walk progressively shorter label-bounded
// prefixes of the reversed form. The first map hit is the longest matching
// suffix.
//
// Example: list = {example.com, ads.example.com}, qname = "tracker.ads.example.com"
//
//	rev = "com.example.ads.tracker"
//	probes (longest first): "com.example.ads.tracker" → miss
//	                        "com.example.ads"         → hit (list_id, matched="ads.example.com")
func (s *Set) Match(hostname string) (listID, matched string, ok bool) {
	host := strings.ToLower(strings.TrimSuffix(hostname, "."))
	if host == "" {
		return "", "", false
	}
	rev := reverseLabels(host)

	cur := rev
	for {
		if id, hit := s.entries[cur]; hit {
			return id, reverseLabels(cur), true
		}
		i := strings.LastIndexByte(cur, '.')
		if i < 0 {
			break
		}
		cur = cur[:i]
	}
	return "", "", false
}
