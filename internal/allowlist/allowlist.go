// SPDX-License-Identifier: Apache-2.0

// Package allowlist is a thin domain-flavored wrapper around hostlist.
//
// Its sole purpose is to give attribution logs and Stats output a domain
// vocabulary ("allowlist: loaded source ...") instead of forcing the more
// generic "hostlist: ..." term on operators. The wire-level loading,
// parsing, and matching is delegated entirely to hostlist.
//
// The log-label distinction ("allowlist: ..." vs "blocklist: ...") is the
// CALLER's concern — cmd/ward/serve.go chooses the label based on which
// loader it just invoked. This package emits no logs of its own.
package allowlist

import "protocolward.ai/ward/internal/hostlist"

// Source is a configured allowlist input. Alias to hostlist.Source so the
// shape stays mechanically identical to blocklist's.
type Source = hostlist.Source

// Stats is per-source parse outcome. Alias to hostlist.Stats.
type Stats = hostlist.Stats

// Load reads each source file, parses hosts-file entries, and returns a
// compiled Set plus per-source Stats. Error contract is identical to
// hostlist.Load: *hostlist.MissingSourceError, *hostlist.EmptySourceError,
// *hostlist.DuplicateIDError.
func Load(srcs []Source) (*hostlist.Set, []Stats, error) {
	return hostlist.Load(srcs)
}
