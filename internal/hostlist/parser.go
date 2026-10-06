// SPDX-License-Identifier: Apache-2.0

package hostlist

import (
	"regexp"
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
	norm, ok := normalizeHostname(host)
	if !ok {
		return "", false, "hostname " + strconv.Quote(host) + " failed validation (lowercase + ASCII letters/digits/dot/hyphen, no empty labels, no leading/trailing hyphen per label)"
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

// hostnameRE matches the overall character set; per-label rules are checked separately.
var hostnameRE = regexp.MustCompile(`^[a-z0-9.-]+$`)

// normalizeHostname lowercases s, strips a single trailing dot, and validates
// the result. Returns (normalized, true) on success or ("", false) on failure.
func normalizeHostname(s string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return "", false
	}
	if !hostnameRE.MatchString(n) {
		return "", false
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" {
			return "", false // consecutive dots
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
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
