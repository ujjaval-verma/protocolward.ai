// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
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
