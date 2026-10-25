// SPDX-License-Identifier: Apache-2.0

package hostlist

import (
	"strconv"
	"strings"
)

// parseLine inspects a single line of a hosts file and returns the normalized
// hostname plus ok=true if the line should be loaded as a blocklist entry,
// or ok=false with a reason if the line should be skipped.
//
// Accepted shapes:
//   - "0.0.0.0 hostname"       → hostname           (/etc/hosts IPv4 sink)
//   - "127.0.0.1 hostname"     → hostname           (/etc/hosts IPv4 sink)
//   - "0 hostname"             → hostname           (AdAway abbreviated sink)
//   - "||hostname^"            → hostname           (AdGuard bare form)
//   - "#..." or "   #..."      → skip silently (reason="" → no WARN log)
//   - blank or whitespace-only → skip silently
//
// AdGuard exception rules ("@@||..."), AdGuard modifiers ("$..."), regex
// rules, and cosmetic rules are rejected with a WARN reason. AdGuard rules
// without a trailing "^" are also rejected — strict beats lenient.
//
// Anything else returns ok=false with a non-empty reason. Callers emit WARN
// logs only when reason != "" (silent skips for comments and blanks).
func parseLine(line string) (hostname string, ok bool, reason string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", false, "" // silent skip
	}
	if strings.HasPrefix(trimmed, "#") {
		return "", false, "" // silent skip
	}
	if strings.HasPrefix(trimmed, "@@") {
		return "", false, "AdGuard exception rules (@@…) are not supported; use an allowlist file"
	}
	if strings.HasPrefix(trimmed, "||") {
		body := strings.TrimPrefix(trimmed, "||")
		if strings.ContainsRune(body, '$') {
			return "", false, "AdGuard rule modifiers ($…) are not supported"
		}
		if !strings.HasSuffix(body, "^") {
			return "", false, "AdGuard rule missing trailing ^"
		}
		host := strings.TrimSuffix(body, "^")
		if strings.HasSuffix(host, "^") {
			return "", false, "AdGuard rule has more than one trailing ^"
		}
		return validateHostname(host)
	}

	fields := strings.Fields(trimmed)
	if len(fields) != 2 {
		return "", false, "expected exactly \"<ip> <hostname>\" (got " + lenWord(len(fields)) + " fields)"
	}
	ip, host := fields[0], fields[1]
	if ip == "0" {
		return validateHostname(host)
	}
	if ip != "0.0.0.0" && ip != "127.0.0.1" {
		return "", false, "leading IP must be 0.0.0.0, 127.0.0.1, or 0, got " + strconv.Quote(ip)
	}
	return validateHostname(host)
}

// validateHostname runs the shared normalize + system-alias gate that every
// accepted line shape ends with. Returns (norm, true, "") on accept, or
// ("", false, reason) with the standard normalization-failure or alias reason.
func validateHostname(host string) (string, bool, string) {
	norm, ok := NormalizeName(host)
	if !ok {
		return "", false, "hostname " + strconv.Quote(host) + " failed validation (ASCII letters, digits, hyphen and underscore; labels 1-63 bytes without a leading or trailing hyphen; name up to 253 bytes; no empty labels)"
	}
	if isSystemAlias(norm) {
		return "", false, "system alias " + strconv.Quote(norm) + " is excluded (never blocklist intent)"
	}
	return norm, true, ""
}

func lenWord(n int) string {
	switch n {
	case 0:
		return "0"
	case 1:
		return "1"
	case 2:
		return "2"
	}
	return "many"
}

// Hostname length limits from RFC 1035 section 2.3.4, as carried by a DNS query.
const (
	// MaxNameLen is the longest accepted hostname in bytes, measured after one
	// trailing dot is stripped (so a 253-byte name plus "." is valid).
	MaxNameLen = 253
	// MaxLabelLen is the longest accepted dot-separated label in bytes.
	MaxLabelLen = 63
)

// FoldName is the query-side fold: it lowercases s and strips ONE trailing
// dot. It does not trim whitespace or validate. It is byte-for-byte
// strings.ToLower(strings.TrimSuffix(s, ".")) and does not allocate when s is
// already lowercase without a trailing dot.
func FoldName(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// NormalizeName is the one list-entry normaliser and validator for hostnames
// (block/allow lists, decoy lists, inline entries). It returns the folded name
// and true, or ("", false) when s breaks any rule:
//
//   - surrounding whitespace is trimmed first (strings.TrimSpace, which also
//     trims Unicode spaces, so "\u00a0a.com" is valid and "a\u00a0b.com" is not);
//   - every remaining byte must be ASCII. The check runs BEFORE folding because
//     strings.ToLower maps U+212A (Kelvin sign) to 'k' and U+0130 to 'i', which
//     would otherwise let non-ASCII lookalikes in;
//   - the name is folded with FoldName: lowercase, ONE trailing dot stripped
//     (two trailing dots leave an empty label and are invalid);
//   - the result is non-empty and at most MaxNameLen bytes (the limit applies
//     after the trailing dot is stripped);
//   - every dot-separated label is 1 to MaxLabelLen bytes of [a-z0-9_-] and
//     neither starts nor ends with a hyphen.
//
// Underscore is allowed because DNS queries legitimately carry underscore
// labels (SRV and DMARC style names such as _ldap._tcp or _dmarc), and a name
// a query can carry must be listable.
func NormalizeName(s string) (string, bool) {
	t := strings.TrimSpace(s)
	for i := 0; i < len(t); i++ {
		if t[i] >= 0x80 {
			return "", false
		}
	}
	n := FoldName(t)
	if n == "" || len(n) > MaxNameLen {
		return "", false
	}
	start := 0
	for i := 0; i <= len(n); i++ {
		if i < len(n) && n[i] != '.' {
			c := n[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
			continue
		}
		label := n[start:i]
		if len(label) == 0 || len(label) > MaxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		start = i + 1
	}
	return n, true
}

// isSystemAlias reports whether the hostname is one of the system-level aliases
// that always appear in /etc/hosts-derived blocklists and are never blocklist intent.
// Recognized aliases: "localhost", "localhost.localdomain", "broadcasthost".
func isSystemAlias(n string) bool {
	switch n {
	case "localhost", "localhost.localdomain", "broadcasthost":
		return true
	}
	return false
}
