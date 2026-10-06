// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/config"
)

// writeFile writes content to a path under t.TempDir() with the given name and
// returns the path. Used by export tests that reference a fixture file via
// decoys[].path; symmetric with writePEM (ca_bundle) and writeYAML (root yaml).
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// helper writes a YAML string to a temp file and returns its path.
func writeYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ward*.yaml")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestLoad_ValidFull(t *testing.T) {
	path := writeYAML(t, `
listen: "127.0.0.1:5353"
log_level: "debug"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
timeouts:
  dial: "3s"
  query: "2s"
  shutdown: "5s"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen != "127.0.0.1:5353" {
		t.Errorf("listen: got %q", cfg.Listen)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("log_level: got %q", cfg.LogLevel)
	}
	if len(cfg.Upstreams) != 1 {
		t.Errorf("upstreams: got %d", len(cfg.Upstreams))
	}
}

func TestLoad_BehavioralDefaults(t *testing.T) {
	// listen is required (no default); other fields fall back to behavioral defaults.
	path := writeYAML(t, `
listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("default log_level: got %q", cfg.LogLevel)
	}
	if cfg.Timeouts.Dial.String() != "3s" {
		t.Errorf("default dial timeout: got %q", cfg.Timeouts.Dial)
	}
	if cfg.Timeouts.Query.String() != "2s" {
		t.Errorf("default query timeout: got %q", cfg.Timeouts.Query)
	}
	if cfg.Timeouts.Shutdown.String() != "5s" {
		t.Errorf("default shutdown timeout: got %q", cfg.Timeouts.Shutdown)
	}
}

func TestLoad_MissingListen_Errors(t *testing.T) {
	// listen has no in-code default; omitting it must fail validation.
	path := writeYAML(t, `
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if ve.Field != "listen" {
		t.Errorf("expected field=listen, got %q", ve.Field)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	var mfe *config.MissingFileError
	if !errors.As(err, &mfe) {
		t.Errorf("expected MissingFileError, got %T: %v", err, err)
	}
}

func TestLoad_UnparseableFile(t *testing.T) {
	// ":::not yaml:::" is valid YAML (a bare key); use a string that actually
	// triggers a yaml.v3 parse error.
	path := writeYAML(t, "key: [unclosed")
	_, err := config.Load(path)
	var pfe *config.ParseError
	if !errors.As(err, &pfe) {
		t.Errorf("expected ParseError, got %T: %v", err, err)
	}
}

func TestLoad_InvalidValue_EmptyUpstreams(t *testing.T) {
	path := writeYAML(t, `listen: "127.0.0.1:5353"`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestLoad_InvalidValue_BadLogLevel(t *testing.T) {
	path := writeYAML(t, `
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
log_level: "verbose"
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestLoad_InvalidValue_BadListenPort(t *testing.T) {
	path := writeYAML(t, `
listen: "127.0.0.1:99999"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError for out-of-range port, got %T: %v", err, err)
	}
}

func TestLoad_InvalidValue_MissingServerName(t *testing.T) {
	path := writeYAML(t, `
upstreams:
  - address: "9.9.9.9:853"
    server_name: ""
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError for missing server_name, got %T: %v", err, err)
	}
}

func TestLoad_InvalidValue_ZeroDial(t *testing.T) {
	path := writeYAML(t, `
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
timeouts:
  dial: "0s"
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError for zero dial timeout, got %T: %v", err, err)
	}
}

func TestLoad_Blocklists_Omitted(t *testing.T) {
	path := writeYAML(t, `
listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Blocklists != nil {
		t.Errorf("expected nil, got %v", cfg.Blocklists)
	}
}

func TestLoad_Blocklists_EmptyArray_Errors(t *testing.T) {
	path := writeYAML(t, `
listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists: []
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if ve.Field != "blocklists" {
		t.Errorf("field: got %q, want \"blocklists\"", ve.Field)
	}
}

func TestLoad_Blocklists_Happy(t *testing.T) {
	path := writeYAML(t, `
listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists:
  - id: "oisd"
    path: "./blocklists/oisd.txt"
  - id: "hagezi"
    path: "./blocklists/hagezi.txt"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Blocklists) != 2 {
		t.Fatalf("len: got %d, want 2", len(cfg.Blocklists))
	}
	if cfg.Blocklists[0].ID != "oisd" || cfg.Blocklists[0].Path != "./blocklists/oisd.txt" {
		t.Errorf("[0]: got %+v", cfg.Blocklists[0])
	}
}

func TestLoad_Blocklists_EmptyID_Errors(t *testing.T) {
	path := writeYAML(t, `
listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists:
  - id: ""
    path: "./blocklists/oisd.txt"
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) || ve.Field != "blocklists[0].id" {
		t.Errorf("expected ValidationError on blocklists[0].id, got %v", err)
	}
}

func TestLoad_Blocklists_EmptyPath_Errors(t *testing.T) {
	path := writeYAML(t, `
listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists:
  - id: "oisd"
    path: ""
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) || ve.Field != "blocklists[0].path" {
		t.Errorf("expected ValidationError on blocklists[0].path, got %v", err)
	}
}

func TestLoad_Blocklists_DuplicateID_Errors(t *testing.T) {
	path := writeYAML(t, `
listen: "127.0.0.1:5354"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists:
  - id: "dup"
    path: "./a.txt"
  - id: "dup"
    path: "./b.txt"
`)
	_, err := config.Load(path)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if ve.Field != "blocklists" {
		t.Errorf("field: got %q, want \"blocklists\"", ve.Field)
	}
}

// ---------------------------------------------------------------------------
// helpers for the allowlist + block_response tests (T5)
// ---------------------------------------------------------------------------

// baseYAML returns the minimum-valid config without optional sections.
func baseYAML() string {
	return `listen: "127.0.0.1:5354"
log_level: "info"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
timeouts:
  dial:     "3s"
  query:    "2s"
  shutdown: "5s"
`
}

func loadYAMLString(t *testing.T, y string) (config.Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return config.Load(p)
}

func mustLoadYAMLString(t *testing.T, y string) config.Config {
	t.Helper()
	cfg, err := loadYAMLString(t, y)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func assertValidationField(t *testing.T, err error, wantField string) {
	t.Helper()
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v; want *ValidationError", err)
	}
	if ve.Field != wantField {
		t.Errorf("ValidationError.Field = %q want %q (msg: %s)", ve.Field, wantField, ve.Message)
	}
}

// ---------------------------------------------------------------------------
// allowlist tests
// ---------------------------------------------------------------------------

func TestLoad_Allowlists_Omitted(t *testing.T) {
	cfg := mustLoadYAMLString(t, baseYAML())
	if cfg.Allowlists != nil {
		t.Errorf("expected nil Allowlists, got %v", cfg.Allowlists)
	}
}

func TestLoad_Allowlists_EmptyArray_Errors(t *testing.T) {
	y := baseYAML() + "allowlists: []\n"
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "allowlists")
}

func TestLoad_Allowlists_Happy(t *testing.T) {
	y := baseYAML() + `
allowlists:
  - id: "my"
    path: "./allow1.txt"
  - id: "vendor"
    path: "./allow2.txt"
`
	cfg := mustLoadYAMLString(t, y)
	if len(cfg.Allowlists) != 2 || cfg.Allowlists[0].ID != "my" || cfg.Allowlists[1].Path != "./allow2.txt" {
		t.Errorf("Allowlists: %+v", cfg.Allowlists)
	}
}

func TestLoad_Allowlists_DuplicateID_Errors(t *testing.T) {
	y := baseYAML() + `
allowlists:
  - id: "x"
    path: "./a.txt"
  - id: "x"
    path: "./b.txt"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "allowlists")
}

func TestLoad_Allowlists_EmptyID_Errors(t *testing.T) {
	y := baseYAML() + `
allowlists:
  - id: ""
    path: "./a.txt"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "allowlists[0].id")
}

func TestLoad_Allowlists_EmptyPath_Errors(t *testing.T) {
	y := baseYAML() + `
allowlists:
  - id: "x"
    path: ""
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "allowlists[0].path")
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *config.ValidationError, got %T: %v", err, err)
	}
	if strings.Contains(ve.Message, "plain hostname") {
		t.Errorf("allowlists path remediation names a format hostlist rejects: %s", ve.Message)
	}
	if !strings.Contains(ve.Message, "hosts-format") {
		t.Errorf("allowlists path remediation should name hosts-format entries: %s", ve.Message)
	}
}

// ---------------------------------------------------------------------------
// block_response tests
// ---------------------------------------------------------------------------

func TestLoad_BlockResponse_Omitted_Defaults(t *testing.T) {
	cfg := mustLoadYAMLString(t, baseYAML())
	if cfg.BlockResponse.Mode != config.BlockResponseModeAddress {
		t.Errorf("Mode = %q want address", cfg.BlockResponse.Mode)
	}
	if cfg.BlockResponse.A.String() != "0.0.0.0" {
		t.Errorf("A = %q want 0.0.0.0", cfg.BlockResponse.A.String())
	}
	if cfg.BlockResponse.AAAA.String() != "::" {
		t.Errorf("AAAA = %q want ::", cfg.BlockResponse.AAAA.String())
	}
}

func TestLoad_BlockResponse_AddressMode_Custom(t *testing.T) {
	y := baseYAML() + `
block_response:
  mode: "address"
  a:    "10.0.0.1"
  aaaa: "fd00::1"
`
	cfg := mustLoadYAMLString(t, y)
	if cfg.BlockResponse.A.String() != "10.0.0.1" || cfg.BlockResponse.AAAA.String() != "fd00::1" {
		t.Errorf("BlockResponse = %+v", cfg.BlockResponse)
	}
}

func TestLoad_BlockResponse_NXDOMAIN_Mode(t *testing.T) {
	y := baseYAML() + "block_response:\n  mode: \"nxdomain\"\n"
	cfg := mustLoadYAMLString(t, y)
	if cfg.BlockResponse.Mode != config.BlockResponseModeNXDOMAIN {
		t.Errorf("Mode = %q want nxdomain", cfg.BlockResponse.Mode)
	}
	if cfg.BlockResponse.A.IsValid() || cfg.BlockResponse.AAAA.IsValid() {
		t.Errorf("A/AAAA must be zero in nxdomain mode: %+v", cfg.BlockResponse)
	}
}

func TestLoad_BlockResponse_NXDOMAIN_WithIP_Errors(t *testing.T) {
	y := baseYAML() + `
block_response:
  mode: "nxdomain"
  a:    "10.0.0.1"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "block_response.a")
}

func TestLoad_BlockResponse_InvalidIP_Errors(t *testing.T) {
	y := baseYAML() + `
block_response:
  mode: "address"
  a:    "not-an-ip"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "block_response.a")
}

func TestLoad_BlockResponse_InvalidMode_Errors(t *testing.T) {
	y := baseYAML() + `
block_response:
  mode: "weird"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "block_response.mode")
}

// ---------------------------------------------------------------------------
// upstream ca_bundle tests (dns-forward slice)
// ---------------------------------------------------------------------------

// writePEM writes a minimal valid PEM-encoded self-signed cert to a temp file
// and returns the path. Used by the ca_bundle test cases.
func writePEM(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return p
}

// validPEM returns a self-signed cert PEM block sufficient to be appended to
// an *x509.CertPool. Generated once at test-package init from an ephemeral
// ECDSA key — see ca_bundle_helper_test.go.
//
// Tests use this via writePEM(t, validPEM()) so each test gets its own file.

func TestLoad_Upstream_CABundle_Omitted_OK(t *testing.T) {
	cfg := mustLoadYAMLString(t, baseYAML())
	if cfg.Upstreams[0].CABundle != "" {
		t.Errorf("CABundle should be empty when omitted, got %q", cfg.Upstreams[0].CABundle)
	}
	if cfg.Upstreams[0].RootCAs != nil {
		t.Errorf("RootCAs should be nil when ca_bundle omitted, got non-nil")
	}
}

func TestLoad_Upstream_CABundle_Happy(t *testing.T) {
	pem := writePEM(t, validPEM())
	y := `listen: "127.0.0.1:5354"
log_level: "info"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
    ca_bundle: "` + pem + `"
timeouts:
  dial:     "3s"
  query:    "2s"
  shutdown: "5s"
`
	cfg, err := loadYAMLString(t, y)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Upstreams[0].CABundle != pem {
		t.Errorf("CABundle: got %q want %q", cfg.Upstreams[0].CABundle, pem)
	}
	if cfg.Upstreams[0].RootCAs == nil {
		t.Fatal("RootCAs: expected non-nil *x509.CertPool")
	}
}

func TestLoad_Upstream_CABundle_MissingFile_Errors(t *testing.T) {
	y := `listen: "127.0.0.1:5354"
log_level: "info"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
    ca_bundle: "/nonexistent/path/to/ca.pem"
timeouts:
  dial:     "3s"
  query:    "2s"
  shutdown: "5s"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "upstreams[0].ca_bundle")
}

func TestLoad_Upstream_CABundle_NoPEMCerts_Errors(t *testing.T) {
	bogus := writePEM(t, "this is not a PEM file at all\n")
	y := `listen: "127.0.0.1:5354"
log_level: "info"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
    ca_bundle: "` + bogus + `"
timeouts:
  dial:     "3s"
  query:    "2s"
  shutdown: "5s"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "upstreams[0].ca_bundle")
}

// ---------------------------------------------------------------------------
// decoys tests (decoy-tripwire slice)
// ---------------------------------------------------------------------------

func TestLoad_Decoys_Omitted(t *testing.T) {
	cfg := mustLoadYAMLString(t, baseYAML())
	if cfg.Decoys != nil {
		t.Errorf("decoys omitted: got %v want nil", cfg.Decoys)
	}
}

func TestLoad_Decoys_EmptyArray_Errors(t *testing.T) {
	y := baseYAML() + "decoys: []\n"
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "decoys")
}

func TestLoad_Decoys_Happy(t *testing.T) {
	y := baseYAML() + `
decoys:
  - id: "primary"
    path: "/tmp/decoys.txt"
`
	cfg := mustLoadYAMLString(t, y)
	if len(cfg.Decoys) != 1 {
		t.Fatalf("decoys: got %d, want 1", len(cfg.Decoys))
	}
	if cfg.Decoys[0].ID != "primary" || cfg.Decoys[0].Path != "/tmp/decoys.txt" {
		t.Errorf("decoys[0]: got %+v", cfg.Decoys[0])
	}
}

func TestLoad_Decoys_EmptyID_Errors(t *testing.T) {
	y := baseYAML() + `
decoys:
  - id: ""
    path: "/tmp/decoys.txt"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "decoys[0].id")
}

func TestLoad_Decoys_EmptyPath_Errors(t *testing.T) {
	y := baseYAML() + `
decoys:
  - id: "primary"
    path: ""
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "decoys[0].path")
}

func TestLoad_Decoys_DuplicateID_Errors(t *testing.T) {
	y := baseYAML() + `
decoys:
  - id: "primary"
    path: "/tmp/a.txt"
  - id: "primary"
    path: "/tmp/b.txt"
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "decoys")
}

// ---------------------------------------------------------------------------
// Export tests (config-export-decoy-scrub slice)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// model tests (SP10c T1)
// ---------------------------------------------------------------------------

func TestLoad_Model_Omitted(t *testing.T) {
	cfg := mustLoadYAMLString(t, baseYAML())
	if cfg.Model != nil {
		t.Errorf("Model = %+v; want nil when stanza is absent (fast-path-only)", cfg.Model)
	}
}

func TestLoad_Model_Happy_CommandOnly(t *testing.T) {
	y := baseYAML() + `model:
  command: ["/usr/local/bin/llama-classifier", "--model", "/path/to/gemma.gguf"]
`
	cfg := mustLoadYAMLString(t, y)
	if cfg.Model == nil {
		t.Fatal("Model = nil; want populated")
	}
	want := []string{"/usr/local/bin/llama-classifier", "--model", "/path/to/gemma.gguf"}
	if len(cfg.Model.Command) != len(want) {
		t.Fatalf("Command len = %d want %d (%v)", len(cfg.Model.Command), len(want), cfg.Model.Command)
	}
	for i := range want {
		if cfg.Model.Command[i] != want[i] {
			t.Errorf("Command[%d] = %q want %q", i, cfg.Model.Command[i], want[i])
		}
	}
	if cfg.Model.Env != nil {
		t.Errorf("Env = %v; want nil when env stanza absent", cfg.Model.Env)
	}
}

func TestLoad_Model_Happy_WithEnv(t *testing.T) {
	y := baseYAML() + `model:
  command: ["/bin/echo", "hi"]
  env: ["LLAMA_THREADS=4", "TMPDIR=/var/tmp"]
`
	cfg := mustLoadYAMLString(t, y)
	if cfg.Model == nil {
		t.Fatal("Model = nil; want populated")
	}
	if len(cfg.Model.Env) != 2 || cfg.Model.Env[0] != "LLAMA_THREADS=4" || cfg.Model.Env[1] != "TMPDIR=/var/tmp" {
		t.Errorf("Env = %v; want [LLAMA_THREADS=4 TMPDIR=/var/tmp]", cfg.Model.Env)
	}
}

func TestLoad_Model_EmptyCommand_Errors(t *testing.T) {
	y := baseYAML() + `model:
  command: []
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "model.command")
}

func TestLoad_Model_PresentNoCommand_Errors(t *testing.T) {
	// `model:` present but no command key at all → still must error.
	y := baseYAML() + `model:
  env: ["FOO=bar"]
`
	_, err := loadYAMLString(t, y)
	assertValidationField(t, err, "model.command")
}

func TestLoad_Model_Builtin_Validation(t *testing.T) {
	cases := []struct {
		name      string
		stanza    string
		wantField string // "" = must load
	}{
		{"builtin_lexical", "model:\n  builtin: lexical\n", ""},
		{"builtin_lexical_quoted", "model:\n  builtin: \"lexical\"\n", ""},
		{"builtin_lexical_flow", "model: {builtin: lexical}\n", ""},
		{"builtin_and_command", "model:\n  builtin: lexical\n  command: [\"/bin/cat\"]\n", "model"},
		{"builtin_unknown", "model:\n  builtin: gemma\n", "model.builtin"},
		{"builtin_wrong_case", "model:\n  builtin: Lexical\n", "model.builtin"},
		{"builtin_with_env", "model:\n  builtin: lexical\n  env: [\"FOO=bar\"]\n", "model.env"},
		{"neither_env_only", "model:\n  env: [\"FOO=bar\"]\n", "model.command"},
		{"empty_map", "model: {}\n", "model.command"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadYAMLString(t, baseYAML()+tc.stanza)
			if tc.wantField == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if cfg.Model == nil || cfg.Model.Builtin != config.ModelBuiltinLexical || len(cfg.Model.Command) != 0 {
					t.Errorf("Model = %+v, want Builtin=%q and no Command", cfg.Model, config.ModelBuiltinLexical)
				}
				return
			}
			assertValidationField(t, err, tc.wantField)
			var ve *config.ValidationError
			if errors.As(err, &ve) && !strings.Contains(ve.Message, "remediation:") {
				t.Errorf("message lacks remediation (invariant 8): %s", ve.Message)
			}
		})
	}
}

// (i) An unknown model.builtin value is echoed in the validation message,
// but bounded so a hostile or accidental megabyte value cannot flood logs.
func TestLoad_Model_Builtin_UnknownValueEchoTruncated(t *testing.T) {
	_, err := loadYAMLString(t, baseYAML()+"model:\n  builtin: "+strings.Repeat("z", 5000)+"\n")
	assertValidationField(t, err, "model.builtin")
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want *ValidationError", err)
	}
	if len(ve.Message) > 600 {
		t.Errorf("message len = %d, want the echoed value bounded (~64 bytes)", len(ve.Message))
	}
	if strings.Contains(ve.Message, strings.Repeat("z", 100)) {
		t.Errorf("message echoes more than ~64 bytes of the value")
	}
	if !strings.Contains(ve.Message, "remediation:") {
		t.Errorf("message lacks remediation: %s", ve.Message)
	}
}

// The shipped example must stay loadable and must turn the detector on —
// new users get flags out of the box (flags are never enforced).
func TestLoad_ExampleConfig_ShipsBuiltinDetector(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "ward.example.yaml"))
	if err != nil {
		t.Fatalf("ward.example.yaml must load: %v", err)
	}
	if cfg.Model == nil || cfg.Model.Builtin != config.ModelBuiltinLexical {
		t.Errorf("example Model = %+v, want builtin %q", cfg.Model, config.ModelBuiltinLexical)
	}
}

func TestExport_OmitsDecoys(t *testing.T) {
	p := writeFile(t, "decoys.txt", "0.0.0.0 leak-sentinel.test\n")
	y := `listen: "127.0.0.1:5354"
log_level: "info"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
timeouts:
  dial: "3s"
  query: "2s"
  shutdown: "5s"
decoys:
  - id: "primary"
    path: "` + p + `"
`
	cfg, err := loadYAMLString(t, y)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out, err := config.Export(cfg)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "leak-sentinel.test") {
		t.Errorf("export leaks decoy hostname; output:\n%s", s)
	}
	if strings.Contains(s, "decoys:") {
		t.Errorf("export contains decoys: section; output:\n%s", s)
	}
}

func TestExport_RoundTrip_PreservesNonDecoyFields(t *testing.T) {
	y := `listen: "127.0.0.1:5354"
log_level: "debug"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
timeouts:
  dial: "7s"
  query: "4s"
  shutdown: "9s"
block_response:
  mode: "nxdomain"
`
	orig, err := loadYAMLString(t, y)
	if err != nil {
		t.Fatalf("Load orig: %v", err)
	}
	out, err := config.Export(orig)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	p := filepath.Join(t.TempDir(), "round.yaml")
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	reloaded, err := config.Load(p)
	if err != nil {
		t.Fatalf("Load reloaded: %v", err)
	}
	if reloaded.Listen != orig.Listen {
		t.Errorf("listen: got %q want %q", reloaded.Listen, orig.Listen)
	}
	if reloaded.LogLevel != orig.LogLevel {
		t.Errorf("log_level: got %q want %q", reloaded.LogLevel, orig.LogLevel)
	}
	if reloaded.Timeouts.Dial != orig.Timeouts.Dial {
		t.Errorf("dial: got %v want %v", reloaded.Timeouts.Dial, orig.Timeouts.Dial)
	}
	if reloaded.Timeouts.Query != orig.Timeouts.Query {
		t.Errorf("query: got %v want %v", reloaded.Timeouts.Query, orig.Timeouts.Query)
	}
	if reloaded.Timeouts.Shutdown != orig.Timeouts.Shutdown {
		t.Errorf("shutdown: got %v want %v", reloaded.Timeouts.Shutdown, orig.Timeouts.Shutdown)
	}
	if reloaded.BlockResponse.Mode != orig.BlockResponse.Mode {
		t.Errorf("block_response.mode: got %q want %q", reloaded.BlockResponse.Mode, orig.BlockResponse.Mode)
	}
}

func TestExport_DefaultBlockResponse_OmittedFromOutput(t *testing.T) {
	cfg := mustLoadYAMLString(t, baseYAML())
	out, err := config.Export(cfg)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if strings.Contains(string(out), "block_response") {
		t.Errorf("default block_response should be omitted from export; got:\n%s", string(out))
	}
}
