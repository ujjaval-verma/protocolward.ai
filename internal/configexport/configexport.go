// SPDX-License-Identifier: Apache-2.0

// Package configexport is the shareable, decoy-free shape of
// `ward config export`.
//
// It exists so that the CLI (internal/config.Export) and the browser demo
// (cmd/wardwasm) share one marshaller without the wasm build linking
// internal/config, whose Load path pulls in crypto/x509 and net (about
// 1.8 MB of ward.wasm, over the 5 MB budget).
//
// # Invariant 6
//
// Document has no decoy field. The omission is structural: there is no
// way to hand a decoy source to Marshal. TestDocument_HasNoDecoyField
// pins this; internal/decoy/export_test.go asserts end-to-end that no
// decoy hostname or `decoys:` key reaches the export;
// internal/config/export_golden_test.go pins the bytes.
//
// # Imports
//
// stdlib, yaml.v3, and internal/hostlist (for Source), which must stay
// free of net/crypto.
package configexport

import (
	"gopkg.in/yaml.v3"

	"protocolward.ai/ward/internal/hostlist"
)

// Upstream is the exportable view of one DoT upstream. ca_bundle is
// always emitted (empty string when unset) to match the pre-extraction
// output byte for byte.
type Upstream struct {
	Address    string `yaml:"address"`
	ServerName string `yaml:"server_name"`
	CABundle   string `yaml:"ca_bundle"`
}

// BlockResponse is the exportable view of block_response. The caller
// leaves Document.BlockResponse nil when the configured response equals
// the address-mode defaults.
type BlockResponse struct {
	Mode string `yaml:"mode"`
	A    string `yaml:"a"`
	AAAA string `yaml:"aaaa"`
}

// Timeouts holds durations in time.Duration.String form ("3s").
type Timeouts struct {
	Dial     string `yaml:"dial"`
	Query    string `yaml:"query"`
	Shutdown string `yaml:"shutdown"`
}

// Document is the full export. Field order is YAML key order.
type Document struct {
	Listen        string            `yaml:"listen"`
	LogLevel      string            `yaml:"log_level"`
	Upstreams     []Upstream        `yaml:"upstreams"`
	Blocklists    []hostlist.Source `yaml:"blocklists,omitempty"`
	Allowlists    []hostlist.Source `yaml:"allowlists,omitempty"`
	BlockResponse *BlockResponse    `yaml:"block_response,omitempty"`
	Timeouts      Timeouts          `yaml:"timeouts"`
}

// Marshal renders d as YAML. The only error path is yaml.Marshal on a
// programming-error type, which Document cannot contain; the error is
// still returned so callers do not depend on that property.
func Marshal(d Document) ([]byte, error) {
	return yaml.Marshal(d)
}
