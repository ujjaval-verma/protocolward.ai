// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"protocolward.ai/ward/internal/config"
)

// TestLoad_ValidationMessages_Locked pins the full, exact operator-facing
// error string for every list-source (blocklists, allowlists, decoys) and
// upstream ca_bundle validation failure, so refactors cannot reword them.
func TestLoad_ValidationMessages_Locked(t *testing.T) {
	const prefix = "config validation error: field "

	type row struct {
		name string
		yaml string
		want string
	}
	rows := make([]row, 0, 14)

	lists := []struct{ field, emptyHint, idHint, pathHint string }{
		{
			"blocklists",
			"is empty — remediation: omit the field entirely to run ward as a pure DNS forwarder",
			"must not be empty — remediation: give each entry a unique logical name (used in attribution logs)",
			"must not be empty — remediation: set to a local file path containing hosts-file entries",
		},
		{
			"allowlists",
			"is empty — remediation: omit the field entirely if you don't need allowlist overrides",
			"must not be empty — remediation: give each entry a unique logical name (used in attribution logs)",
			"must not be empty — remediation: set to a local file path containing hosts-format entries (the same syntaxes as blocklists)",
		},
		{
			"decoys",
			"is empty — remediation: omit the field entirely if you don't have decoys configured",
			"must not be empty — remediation: give each entry a unique logical name (used in alert logs)",
			"must not be empty — remediation: set to a local file path containing hosts-file or plain hostname entries",
		},
	}
	const dupMsg = `duplicate id "dup" at index 0 and 1 — remediation: give each entry a unique id`
	for _, l := range lists {
		f := l.field
		rows = append(rows,
			row{
				name: f + "/empty_list",
				yaml: baseYAML() + f + ": []\n",
				want: fmt.Sprintf("%s%q: %s", prefix, f, l.emptyHint),
			},
			row{
				name: f + "/empty_id",
				yaml: baseYAML() + f + ":\n  - id: \"\"\n    path: \"./a.txt\"\n",
				want: fmt.Sprintf("%s%q: %s", prefix, f+"[0].id", l.idHint),
			},
			row{
				name: f + "/empty_path",
				yaml: baseYAML() + f + ":\n  - id: \"a\"\n    path: \"\"\n",
				want: fmt.Sprintf("%s%q: %s", prefix, f+"[0].path", l.pathHint),
			},
			row{
				name: f + "/duplicate_id",
				yaml: baseYAML() + f + ":\n  - id: \"dup\"\n    path: \"./a.txt\"\n  - id: \"dup\"\n    path: \"./b.txt\"\n",
				want: fmt.Sprintf("%s%q: %s", prefix, f, dupMsg),
			},
		)
	}

	// ca_bundle: missing file. Build the expected string from the real error.
	missing := filepath.Join(t.TempDir(), "nope.pem")
	_, rerr := os.ReadFile(missing)
	if rerr == nil {
		t.Fatalf("expected %s to be unreadable", missing)
	}
	caYAML := func(p string) string {
		return fmt.Sprintf("listen: \"127.0.0.1:5354\"\nupstreams:\n  - address: \"9.9.9.9:853\"\n    server_name: \"dns.quad9.net\"\n    ca_bundle: %q\n", p)
	}
	missingMsg := fmt.Sprintf("cannot read PEM file %q: %v — remediation: set ca_bundle to a readable PEM file path, or omit the field to use system roots", missing, rerr)
	rows = append(rows, row{
		name: "ca_bundle/missing_file",
		yaml: caYAML(missing),
		want: fmt.Sprintf("%s%q: %s", prefix, "upstreams[0].ca_bundle", missingMsg),
	})

	// ca_bundle: file with no PEM certificates.
	empty := writePEM(t, "not a certificate\n")
	noPEMMsg := fmt.Sprintf("file %q contains no PEM-encoded certificates — remediation: provide a file with one or more PEM CERTIFICATE blocks, or omit the field to use system roots", empty)
	rows = append(rows, row{
		name: "ca_bundle/no_pem_certs",
		yaml: caYAML(empty),
		want: fmt.Sprintf("%s%q: %s", prefix, "upstreams[0].ca_bundle", noPEMMsg),
	})

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadYAMLString(t, r.yaml)
			if err == nil {
				t.Fatalf("Load: want error, got nil")
			}
			if got := err.Error(); got != r.want {
				t.Errorf("error message changed\n got: %s\nwant: %s", got, r.want)
			}
		})
	}
}

// TestLoad_ValidationErrors_NameRemediation loads one YAML per reworded
// ValidationError message, plus the model.* and nxdomain-conflict messages. It
// pins the exact text and requires each to name a remediation (invariant 8)
// with non-blank text after the marker. The list-source, ca_bundle and listen
// port messages are pinned by other tests.
func TestLoad_ValidationErrors_NameRemediation(t *testing.T) {
	const marker = " — remediation: "

	_, errDial := time.ParseDuration("soon")
	_, errQuery := time.ParseDuration("later")
	_, errShutdown := time.ParseDuration("never")
	_, _, errSplit := net.SplitHostPort("nocolon")

	// swap replaces one line of baseYAML.
	swap := func(old, repl string) string {
		y := baseYAML()
		if !strings.Contains(y, old) {
			t.Fatalf("baseYAML has no %q", old)
		}
		return strings.Replace(y, old, repl, 1)
	}

	rows := []struct {
		name  string
		yaml  string
		field string
		want  string
	}{
		{
			"timeouts.dial/parse", swap(`dial:     "3s"`, `dial: "soon"`), "timeouts.dial",
			fmt.Sprintf(`invalid duration %q: %v — remediation: use Go duration syntax, e.g. "3s"`, "soon", errDial),
		},
		{
			"timeouts.query/parse", swap(`query:    "2s"`, `query: "later"`), "timeouts.query",
			fmt.Sprintf(`invalid duration %q: %v — remediation: use Go duration syntax, e.g. "2s"`, "later", errQuery),
		},
		{
			"timeouts.shutdown/parse", swap(`shutdown: "5s"`, `shutdown: "never"`), "timeouts.shutdown",
			fmt.Sprintf(`invalid duration %q: %v — remediation: use Go duration syntax, e.g. "5s"`, "never", errShutdown),
		},
		{
			"listen/empty", swap(`listen: "127.0.0.1:5354"`, `listen: ""`), "listen",
			`is required — remediation: set to host:port, e.g. "127.0.0.1:5354" (see ward.example.yaml)`,
		},
		{
			"listen/addr_error", swap(`listen: "127.0.0.1:5354"`, `listen: "nocolon"`), "listen",
			fmt.Sprintf(`must be host:port, got %q: %v — remediation: write it as host:port, e.g. "127.0.0.1:5354"`, "nocolon", errSplit),
		},
		{
			"log_level", swap(`log_level: "info"`, `log_level: "loud"`), "log_level",
			`must be one of debug|info|warn|error, got "loud" — remediation: set log_level to debug, info, warn or error, or omit it to use info`,
		},
		{
			"upstreams/empty", swap("upstreams:\n  - address: \"9.9.9.9:853\"\n    server_name: \"dns.quad9.net\"\n", "upstreams: []\n"), "upstreams",
			`at least one upstream is required — remediation: add an entry with address and server_name`,
		},
		{
			"upstreams.address", swap(`address: "9.9.9.9:853"`, `address: "nocolon"`), "upstreams[0].address",
			fmt.Sprintf(`must be host:port, got %q: %v — remediation: write it as host:port, e.g. "9.9.9.9:853"`, "nocolon", errSplit),
		},
		{
			"upstreams.server_name", swap(`server_name: "dns.quad9.net"`, `server_name: ""`), "upstreams[0].server_name",
			`must not be empty — remediation: set it to the TLS SNI name of the upstream, e.g. "dns.quad9.net"`,
		},
		{
			"timeouts.dial/nonpositive", swap(`dial:     "3s"`, `dial: "0s"`), "timeouts.dial",
			`must be > 0 — remediation: use a positive duration, e.g. "3s"`,
		},
		{
			"timeouts.query/nonpositive", swap(`query:    "2s"`, `query: "0s"`), "timeouts.query",
			`must be > 0 — remediation: use a positive duration, e.g. "2s"`,
		},
		{
			"timeouts.shutdown/nonpositive", swap(`shutdown: "5s"`, `shutdown: "0s"`), "timeouts.shutdown",
			`must be > 0 — remediation: use a positive duration, e.g. "5s"`,
		},
		{
			"block_response.a", baseYAML() + "block_response:\n  a: \"nope\"\n", "block_response.a",
			`must be a valid IPv4 address, got "nope" — remediation: use an IPv4 address such as "0.0.0.0", or omit the field`,
		},
		{
			"block_response.aaaa", baseYAML() + "block_response:\n  aaaa: \"nope\"\n", "block_response.aaaa",
			`must be a valid IPv6 address, got "nope" — remediation: use an IPv6 address such as "::", or omit the field`,
		},
		{
			"model/builtin_and_command", baseYAML() + "model:\n  builtin: \"lexical\"\n  command: [\"/bin/x\"]\n", "model",
			`builtin and command are both set — remediation: keep builtin: "lexical" for the in-process detector, or keep command: [...] for a sibling adapter, not both`,
		},
		{
			"model.builtin/unknown", baseYAML() + "model:\n  builtin: \"gpt\"\n", "model.builtin",
			`unknown built-in detector "gpt" — remediation: set model.builtin to "lexical" (the only built-in detector, lowercase), or remove it and set model.command for a sibling adapter`,
		},
		{
			"model.env/with_builtin", baseYAML() + "model:\n  builtin: \"lexical\"\n  env: [\"A=b\"]\n", "model.env",
			`applies only to model.command — remediation: remove model.env when using model.builtin (the built-in detector runs in-process and spawns nothing)`,
		},
		{
			"model.command/empty", baseYAML() + "model:\n  env: [\"A=b\"]\n", "model.command",
			`must not be empty when model: is present and model.builtin is unset — remediation: set model.builtin to "lexical" for the built-in detector, or model.command to the argv for the sibling adapter (e.g. ["/usr/local/bin/llama-classifier", "--model", "/path/to/gemma.gguf"]), or remove the model: stanza to run fast-path-only`,
		},
		{
			"block_response.a/nxdomain", baseYAML() + "block_response:\n  mode: \"nxdomain\"\n  a: \"0.0.0.0\"\n", "block_response.a",
			`must be empty when block_response.mode = "nxdomain" — remediation: remove the field or switch mode to "address"`,
		},
		{
			"block_response.aaaa/nxdomain", baseYAML() + "block_response:\n  mode: \"nxdomain\"\n  aaaa: \"::\"\n", "block_response.aaaa",
			`must be empty when block_response.mode = "nxdomain" — remediation: remove the field or switch mode to "address"`,
		},
		{
			"block_response.mode", baseYAML() + "block_response:\n  mode: \"drop\"\n", "block_response.mode",
			`must be "address" or "nxdomain", got "drop" — remediation: set block_response.mode to "address" or "nxdomain", or omit it to use "address"`,
		},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "ward.yaml")
			if err := os.WriteFile(p, []byte(r.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := config.Load(p)
			var ve *config.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("Load error = %T %v, want *config.ValidationError", err, err)
			}
			if ve.Field != r.field {
				t.Errorf("Field = %q, want %q", ve.Field, r.field)
			}
			if ve.Message != r.want {
				t.Errorf("Message = %q\nwant      %q", ve.Message, r.want)
			}
			i := strings.LastIndex(ve.Message, marker)
			if i < 0 || strings.TrimSpace(ve.Message[i+len(marker):]) == "" {
				t.Errorf("Message %q does not name a remediation after %q", ve.Message, marker)
			}
		})
	}
}
