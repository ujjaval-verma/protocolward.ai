// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates the ward configuration from YAML.
package config

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"protocolward.ai/ward/internal/configexport"
	"protocolward.ai/ward/internal/hostlist"
)

// Upstream is a single DoT upstream resolver.
//
// CABundle, when non-empty, is the path to a PEM file containing one or more
// CA certificates that pin the upstream's TLS trust. The file is read and
// parsed by Load; the resulting *x509.CertPool is exposed via RootCAs so
// serve-time TLS construction does not need to re-touch the filesystem
// (eliminating an invariant-8 error branch). When CABundle is empty, RootCAs
// is nil and system roots are used by the upstream client (the existing
// behavior — see internal/upstream/upstream.go package doc).
type Upstream struct {
	Address    string         `yaml:"address"`
	ServerName string         `yaml:"server_name"`
	CABundle   string         `yaml:"ca_bundle"`
	RootCAs    *x509.CertPool `yaml:"-"`
}

// Timeouts holds per-operation timeout durations.
type Timeouts struct {
	Dial     time.Duration `yaml:"-"`
	Query    time.Duration `yaml:"-"`
	Shutdown time.Duration `yaml:"-"`
}

// rawTimeouts mirrors Timeouts with string fields for YAML decode.
type rawTimeouts struct {
	Dial     string `yaml:"dial"`
	Query    string `yaml:"query"`
	Shutdown string `yaml:"shutdown"`
}

// BlockResponseMode controls the shape of the DNS response returned on a
// blocklist hit. "address" returns the configured A/AAAA (with NXDOMAIN
// for other qtypes); "nxdomain" returns NXDOMAIN for every qtype.
type BlockResponseMode string

const (
	BlockResponseModeAddress  BlockResponseMode = "address"
	BlockResponseModeNXDOMAIN BlockResponseMode = "nxdomain"
)

// BlockResponseConfig is the shape of a block response. A and AAAA are
// required iff Mode == BlockResponseModeAddress; in nxdomain mode they
// must be zero (strict footgun guard).
type BlockResponseConfig struct {
	Mode BlockResponseMode
	A    netip.Addr
	AAAA netip.Addr
}

// ModelBuiltinLexical selects the in-process lexical DGA detector
// (pkg/detect). It is the only built-in detector. Its verdicts are
// flag-only — surfaced on the dashboard and in logs, never enforced.
const ModelBuiltinLexical = "lexical"

// ModelConfig is the optional slow-path stanza. Absence (Config.Model ==
// nil) means "no slow path" — ward runs fast-path-only. When present,
// exactly one of Builtin or Command must be set: Builtin names an
// in-process detector (only ModelBuiltinLexical today); Command is the argv
// for a sibling adapter process. Env applies to Command only; when nil,
// internal/model.New inherits the parent's environment per os/exec default;
// pass an explicit empty slice to spawn the child with no environment.
type ModelConfig struct {
	Command []string `yaml:"command"`
	Env     []string `yaml:"env"`
	Builtin string   `yaml:"builtin"`
}

// Config is the fully-validated ward configuration.
type Config struct {
	Listen        string
	LogLevel      string
	Upstreams     []Upstream
	Blocklists    []hostlist.Source
	Allowlists    []hostlist.Source
	Decoys        []hostlist.Source
	BlockResponse BlockResponseConfig
	Timeouts      Timeouts
	Model         *ModelConfig
}

// rawConfig mirrors Config with string timeout fields for YAML decode.
type rawConfig struct {
	Listen        string             `yaml:"listen"`
	LogLevel      string             `yaml:"log_level"`
	Upstreams     []Upstream         `yaml:"upstreams"`
	Blocklists    *[]hostlist.Source `yaml:"blocklists"`
	Allowlists    *[]hostlist.Source `yaml:"allowlists"`
	Decoys        *[]hostlist.Source `yaml:"decoys"`
	BlockResponse *rawBlockResponse  `yaml:"block_response"`
	Timeouts      rawTimeouts        `yaml:"timeouts"`
	Model         *ModelConfig       `yaml:"model"`
}

type rawBlockResponse struct {
	Mode string `yaml:"mode"`
	A    string `yaml:"a"`
	AAAA string `yaml:"aaaa"`
}

// MissingFileError is returned when the config file cannot be found.
type MissingFileError struct {
	Path string
}

func (e *MissingFileError) Error() string {
	return fmt.Sprintf("config file not found: %s — create the file or pass --config with the path", e.Path)
}

// ParseError is returned when the YAML cannot be decoded.
type ParseError struct {
	Path string
	Err  error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("config parse error in %s: %v", e.Path, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// ValidationError is returned when a parsed value fails semantic validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation error: field %q: %s", e.Field, e.Message)
}

// Export serialises c to YAML for `ward config export`. Decoys are
// deliberately omitted — see invariant 6. The omission is structural:
// configexport.Document has no decoy field. The model stanza is not
// exported either (pre-existing behaviour, pinned by TestExport_Golden).
// The output is round-trip-loadable for the remaining fields: piping it
// through Load reproduces a Config whose values equal the input minus
// decoys and minus Model. Comment/key-order preservation is NOT a
// guarantee (not required by invariant 6).
//
// Note: upstream ca_bundle filesystem paths are included verbatim in the
// output. Redacting them is deferred to the Pro tier hardening pass
// (post-v0.1) — see invariant 6's scope (hostnames only) in
// docs/engineering/invariants.md.
func Export(c Config) ([]byte, error) {
	doc := configexport.Document{
		Listen:     c.Listen,
		LogLevel:   c.LogLevel,
		Upstreams:  exportUpstreams(c.Upstreams),
		Blocklists: c.Blocklists,
		Allowlists: c.Allowlists,
		Timeouts: configexport.Timeouts{
			Dial:     c.Timeouts.Dial.String(),
			Query:    c.Timeouts.Query.String(),
			Shutdown: c.Timeouts.Shutdown.String(),
		},
	}
	// block_response is omitted entirely when it equals the address-mode
	// defaults — keeps export output minimal and round-trip-correct
	// (parseBlockResponse(nil) reproduces the same default).
	br := c.BlockResponse
	defaultA := netip.MustParseAddr("0.0.0.0")
	defaultAAAA := netip.MustParseAddr("::")
	isDefaultAddr := br.Mode == BlockResponseModeAddress && br.A == defaultA && br.AAAA == defaultAAAA
	if !isDefaultAddr {
		rb := &configexport.BlockResponse{Mode: string(br.Mode)}
		if br.Mode == BlockResponseModeAddress {
			rb.A = br.A.String()
			rb.AAAA = br.AAAA.String()
		}
		doc.BlockResponse = rb
	}
	return configexport.Marshal(doc)
}

// exportUpstreams drops the runtime-only RootCAs pool. A nil input stays
// nil; yaml.v3 renders nil and empty slices identically as `[]`.
func exportUpstreams(in []Upstream) []configexport.Upstream {
	if in == nil {
		return nil
	}
	out := make([]configexport.Upstream, 0, len(in))
	for _, u := range in {
		out = append(out, configexport.Upstream{Address: u.Address, ServerName: u.ServerName, CABundle: u.CABundle})
	}
	return out
}

// Load reads the YAML file at path, applies defaults, validates, and returns
// a Config. Errors are one of: *MissingFileError, *ParseError, *ValidationError.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, &MissingFileError{Path: path}
		}
		return Config{}, &ParseError{Path: path, Err: err}
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Config{}, &ParseError{Path: path, Err: err}
	}

	// Apply behavioral defaults. listen has no default — network bind address
	// is a deployment decision and must be explicit (see ward.example.yaml).
	if raw.LogLevel == "" {
		raw.LogLevel = "info"
	}
	if raw.Timeouts.Dial == "" {
		raw.Timeouts.Dial = "3s"
	}
	if raw.Timeouts.Query == "" {
		raw.Timeouts.Query = "2s"
	}
	if raw.Timeouts.Shutdown == "" {
		raw.Timeouts.Shutdown = "5s"
	}

	var bl []hostlist.Source
	if raw.Blocklists != nil {
		bl = *raw.Blocklists
	}

	var al []hostlist.Source
	if raw.Allowlists != nil {
		al = *raw.Allowlists
	}

	var dl []hostlist.Source
	if raw.Decoys != nil {
		dl = *raw.Decoys
	}

	br, err := parseBlockResponse(raw.BlockResponse)
	if err != nil {
		return Config{}, err
	}

	// Parse durations.
	dialDur, err := time.ParseDuration(raw.Timeouts.Dial)
	if err != nil {
		return Config{}, &ValidationError{
			Field:   "timeouts.dial",
			Message: fmt.Sprintf("invalid duration %q: %v — use Go duration syntax, e.g. \"3s\"", raw.Timeouts.Dial, err),
		}
	}
	queryDur, err := time.ParseDuration(raw.Timeouts.Query)
	if err != nil {
		return Config{}, &ValidationError{
			Field:   "timeouts.query",
			Message: fmt.Sprintf("invalid duration %q: %v — use Go duration syntax, e.g. \"2s\"", raw.Timeouts.Query, err),
		}
	}
	shutdownDur, err := time.ParseDuration(raw.Timeouts.Shutdown)
	if err != nil {
		return Config{}, &ValidationError{
			Field:   "timeouts.shutdown",
			Message: fmt.Sprintf("invalid duration %q: %v — use Go duration syntax, e.g. \"5s\"", raw.Timeouts.Shutdown, err),
		}
	}

	cfg := Config{
		Listen:        raw.Listen,
		LogLevel:      raw.LogLevel,
		Upstreams:     raw.Upstreams,
		Blocklists:    bl,
		Allowlists:    al,
		Decoys:        dl,
		BlockResponse: br,
		Timeouts: Timeouts{
			Dial:     dialDur,
			Query:    queryDur,
			Shutdown: shutdownDur,
		},
		Model: raw.Model,
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	// listen: required, must parse as host:port with port in 1–65535.
	if c.Listen == "" {
		return &ValidationError{
			Field:   "listen",
			Message: "is required — set to host:port, e.g. \"127.0.0.1:5354\" (see ward.example.yaml)",
		}
	}
	host, portStr, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return &ValidationError{
			Field:   "listen",
			Message: fmt.Sprintf("must be host:port, got %q: %v — example: \"127.0.0.1:5354\"", c.Listen, err),
		}
	}
	_ = host
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return &ValidationError{
			Field:   "listen",
			Message: fmt.Sprintf("port must be 1–65535, got %q — use a valid port number", portStr),
		}
	}

	// log_level.
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return &ValidationError{
			Field:   "log_level",
			Message: fmt.Sprintf("must be one of debug|info|warn|error, got %q", c.LogLevel),
		}
	}

	// upstreams: non-empty, each entry valid.
	if len(c.Upstreams) == 0 {
		return &ValidationError{
			Field:   "upstreams",
			Message: "at least one upstream is required — add an entry with address and server_name",
		}
	}
	for i, u := range c.Upstreams {
		if _, _, err := net.SplitHostPort(u.Address); err != nil {
			return &ValidationError{
				Field:   fmt.Sprintf("upstreams[%d].address", i),
				Message: fmt.Sprintf("must be host:port, got %q: %v — example: \"9.9.9.9:853\"", u.Address, err),
			}
		}
		if u.ServerName == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("upstreams[%d].server_name", i),
				Message: "must not be empty — set to the TLS SNI name of the upstream, e.g. \"dns.quad9.net\"",
			}
		}
		if u.CABundle != "" {
			pem, err := os.ReadFile(u.CABundle)
			if err != nil {
				return &ValidationError{
					Field:   fmt.Sprintf("upstreams[%d].ca_bundle", i),
					Message: fmt.Sprintf("cannot read PEM file %q: %v — remediation: set ca_bundle to a readable PEM file path, or omit the field to use system roots", u.CABundle, err),
				}
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return &ValidationError{
					Field:   fmt.Sprintf("upstreams[%d].ca_bundle", i),
					Message: fmt.Sprintf("file %q contains no PEM-encoded certificates — remediation: provide a file with one or more PEM CERTIFICATE blocks, or omit the field to use system roots", u.CABundle),
				}
			}
			c.Upstreams[i].RootCAs = pool
		}
	}

	// blocklists: optional; if the field was present in YAML it must have ≥1 entry.
	if c.Blocklists != nil && len(c.Blocklists) == 0 {
		return &ValidationError{
			Field:   "blocklists",
			Message: "is empty — remediation: omit the field entirely to run ward as a pure DNS forwarder",
		}
	}
	seenIDs := make(map[string]int, len(c.Blocklists))
	for i, b := range c.Blocklists {
		if b.ID == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("blocklists[%d].id", i),
				Message: "must not be empty — remediation: give each entry a unique logical name (used in attribution logs)",
			}
		}
		if b.Path == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("blocklists[%d].path", i),
				Message: "must not be empty — remediation: set to a local file path containing hosts-file entries",
			}
		}
		if prev, dup := seenIDs[b.ID]; dup {
			return &ValidationError{
				Field:   "blocklists",
				Message: fmt.Sprintf("duplicate id %q at index %d and %d — remediation: give each entry a unique id", b.ID, prev, i),
			}
		}
		seenIDs[b.ID] = i
	}

	// allowlists: optional; if present, same rules as blocklists.
	if c.Allowlists != nil && len(c.Allowlists) == 0 {
		return &ValidationError{
			Field:   "allowlists",
			Message: "is empty — remediation: omit the field entirely if you don't need allowlist overrides",
		}
	}
	seenAllowIDs := make(map[string]int, len(c.Allowlists))
	for i, a := range c.Allowlists {
		if a.ID == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("allowlists[%d].id", i),
				Message: "must not be empty — remediation: give each entry a unique logical name (used in attribution logs)",
			}
		}
		if a.Path == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("allowlists[%d].path", i),
				Message: "must not be empty — remediation: set to a local file path containing hosts-format entries (the same syntaxes as blocklists)",
			}
		}
		if prev, dup := seenAllowIDs[a.ID]; dup {
			return &ValidationError{
				Field:   "allowlists",
				Message: fmt.Sprintf("duplicate id %q at index %d and %d — remediation: give each entry a unique id", a.ID, prev, i),
			}
		}
		seenAllowIDs[a.ID] = i
	}

	// decoys: optional; if present, must have ≥1 entry. Same per-entry
	// validation as allowlists/blocklists.
	if c.Decoys != nil && len(c.Decoys) == 0 {
		return &ValidationError{
			Field:   "decoys",
			Message: "is empty — remediation: omit the field entirely if you don't have decoys configured",
		}
	}
	seenDecoyIDs := make(map[string]int, len(c.Decoys))
	for i, d := range c.Decoys {
		if d.ID == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("decoys[%d].id", i),
				Message: "must not be empty — remediation: give each entry a unique logical name (used in alert logs)",
			}
		}
		if d.Path == "" {
			return &ValidationError{
				Field:   fmt.Sprintf("decoys[%d].path", i),
				Message: "must not be empty — remediation: set to a local file path containing hosts-file or plain hostname entries",
			}
		}
		if prev, dup := seenDecoyIDs[d.ID]; dup {
			return &ValidationError{
				Field:   "decoys",
				Message: fmt.Sprintf("duplicate id %q at index %d and %d — remediation: give each entry a unique id", d.ID, prev, i),
			}
		}
		seenDecoyIDs[d.ID] = i
	}

	// model: optional. When present, exactly one of builtin / command.
	if c.Model != nil {
		if err := c.Model.validate(); err != nil {
			return err
		}
	}

	// timeouts: all > 0.
	if c.Timeouts.Dial <= 0 {
		return &ValidationError{
			Field:   "timeouts.dial",
			Message: "must be > 0 — use a positive duration, e.g. \"3s\"",
		}
	}
	if c.Timeouts.Query <= 0 {
		return &ValidationError{
			Field:   "timeouts.query",
			Message: "must be > 0 — use a positive duration, e.g. \"2s\"",
		}
	}
	if c.Timeouts.Shutdown <= 0 {
		return &ValidationError{
			Field:   "timeouts.shutdown",
			Message: "must be > 0 — use a positive duration, e.g. \"5s\"",
		}
	}

	return nil
}

// truncateEcho caps a user-supplied value echoed into an error message at
// max bytes, cutting on a rune boundary.
func truncateEcho(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && s[max]&0xC0 == 0x80 { // s[max] is a continuation byte
		max--
	}
	return s[:max] + "…"
}

// validate enforces "exactly one of builtin / command" on a present model:
// stanza. Builtin is matched exactly (lowercase) so a typo fails loudly
// instead of silently selecting something else.
func (m ModelConfig) validate() error {
	hasBuiltin := m.Builtin != ""
	hasCommand := len(m.Command) > 0
	switch {
	case hasBuiltin && hasCommand:
		return &ValidationError{
			Field:   "model",
			Message: "builtin and command are both set — remediation: keep builtin: \"lexical\" for the in-process detector, or keep command: [...] for a sibling adapter, not both",
		}
	case hasBuiltin:
		if m.Builtin != ModelBuiltinLexical {
			return &ValidationError{
				Field:   "model.builtin",
				Message: fmt.Sprintf("unknown built-in detector %q — remediation: set model.builtin to %q (the only built-in detector, lowercase), or remove it and set model.command for a sibling adapter", truncateEcho(m.Builtin, 64), ModelBuiltinLexical),
			}
		}
		if len(m.Env) > 0 {
			return &ValidationError{
				Field:   "model.env",
				Message: "applies only to model.command — remediation: remove model.env when using model.builtin (the built-in detector runs in-process and spawns nothing)",
			}
		}
		return nil
	case hasCommand:
		return nil
	default:
		return &ValidationError{
			Field:   "model.command",
			Message: "must not be empty when model: is present and model.builtin is unset — remediation: set model.builtin to \"lexical\" for the built-in detector, or model.command to the argv for the sibling adapter (e.g. [\"/usr/local/bin/llama-classifier\", \"--model\", \"/path/to/gemma.gguf\"]), or remove the model: stanza to run fast-path-only",
		}
	}
}

func parseBlockResponse(raw *rawBlockResponse) (BlockResponseConfig, error) {
	if raw == nil {
		return BlockResponseConfig{
			Mode: BlockResponseModeAddress,
			A:    netip.MustParseAddr("0.0.0.0"),
			AAAA: netip.MustParseAddr("::"),
		}, nil
	}
	var br BlockResponseConfig
	switch BlockResponseMode(raw.Mode) {
	case "", BlockResponseModeAddress:
		br.Mode = BlockResponseModeAddress
		if raw.A == "" {
			br.A = netip.MustParseAddr("0.0.0.0")
		} else {
			a, err := netip.ParseAddr(raw.A)
			if err != nil || !a.Is4() {
				return BlockResponseConfig{}, &ValidationError{
					Field:   "block_response.a",
					Message: fmt.Sprintf("must be a valid IPv4 address, got %q — e.g. \"0.0.0.0\"", raw.A),
				}
			}
			br.A = a
		}
		if raw.AAAA == "" {
			br.AAAA = netip.MustParseAddr("::")
		} else {
			a, err := netip.ParseAddr(raw.AAAA)
			if err != nil || !a.Is6() || a.Is4In6() {
				return BlockResponseConfig{}, &ValidationError{
					Field:   "block_response.aaaa",
					Message: fmt.Sprintf("must be a valid IPv6 address, got %q — e.g. \"::\"", raw.AAAA),
				}
			}
			br.AAAA = a
		}
	case BlockResponseModeNXDOMAIN:
		br.Mode = BlockResponseModeNXDOMAIN
		if raw.A != "" {
			return BlockResponseConfig{}, &ValidationError{
				Field:   "block_response.a",
				Message: "must be empty when block_response.mode = \"nxdomain\" — remediation: remove the field or switch mode to \"address\"",
			}
		}
		if raw.AAAA != "" {
			return BlockResponseConfig{}, &ValidationError{
				Field:   "block_response.aaaa",
				Message: "must be empty when block_response.mode = \"nxdomain\" — remediation: remove the field or switch mode to \"address\"",
			}
		}
	default:
		return BlockResponseConfig{}, &ValidationError{
			Field:   "block_response.mode",
			Message: fmt.Sprintf("must be \"address\" or \"nxdomain\", got %q", raw.Mode),
		}
	}
	return br, nil
}
