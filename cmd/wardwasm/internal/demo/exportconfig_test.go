// SPDX-License-Identifier: Apache-2.0

package demo_test

import (
	"strings"
	"testing"

	"protocolward.ai/ward/cmd/wardwasm/internal/demo"
)

const wantDemoExport = `listen: 127.0.0.1:53
log_level: info
upstreams:
    - address: 9.9.9.9:853
      server_name: dns.quad9.net
      ca_bundle: ""
blocklists:
    - id: demo-blocklist
      path: blocklist.txt
allowlists:
    - id: demo-allowlist
      path: allowlist.txt
timeouts:
    dial: 3s
    query: 2s
    shutdown: 5s
`

func TestExportConfig_Golden(t *testing.T) {
	got, err := mustInit(t, fixture).ExportConfig()
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	if got != wantDemoExport {
		t.Errorf("ExportConfig\n--- got ---\n%s--- want ---\n%s", got, wantDemoExport)
	}
}

// TestInvariant6_ExportConfigNeverContainsDecoys is the demo's copy of
// invariant 6: no decoy hostname, no decoys key, not even the word.
func TestInvariant6_ExportConfigNeverContainsDecoys(t *testing.T) {
	got, err := mustInit(t, fixture).ExportConfig()
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	for _, name := range fixture.Decoys {
		if strings.Contains(got, name) {
			t.Errorf("invariant 6 violated: export contains decoy %q\n%s", name, got)
		}
	}
	if strings.Contains(strings.ToLower(got), "decoy") {
		t.Errorf("invariant 6 violated: export mentions decoys\n%s", got)
	}
}

func TestExportConfig_OmitsEmptyLists(t *testing.T) {
	got, err := mustInit(t, demo.Config{Decoys: []string{"nas-backup.home.arpa"}}).ExportConfig()
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	for _, key := range []string{"blocklists:", "allowlists:", "nas-backup"} {
		if strings.Contains(got, key) {
			t.Errorf("export contains %q with no lists configured\n%s", key, got)
		}
	}
}

func TestExportConfig_BeforeInit(t *testing.T) {
	got, err := demo.New().ExportConfig()
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	if !strings.HasPrefix(got, "listen: 127.0.0.1:53\n") {
		t.Errorf("ExportConfig before Init = %q; want a valid document", got)
	}
}

// TestInvariant6_FailedInitErrorNeverReachesExport: an Init error may echo
// a decoy name; it must not leak into ExportConfig, and a failed Init must
// not change the export.
func TestInvariant6_FailedInitErrorNeverReachesExport(t *testing.T) {
	d := mustInit(t, fixture)
	before, err := d.ExportConfig()
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	initErr := d.Init(demo.Config{
		Decoys:    []string{"secret-decoy.home.arpa", "bad decoy name"},
		Blocklist: []string{"ads.example.com"},
	})
	if initErr == nil {
		t.Fatal("Init with an invalid decoy succeeded; want error")
	}
	after, err := d.ExportConfig()
	if err != nil {
		t.Fatalf("ExportConfig: %v", err)
	}
	if after != before {
		t.Errorf("failed Init changed the export\n--- before ---\n%s--- after ---\n%s", before, after)
	}
	for _, needle := range []string{"secret-decoy", "bad decoy", initErr.Error()} {
		if strings.Contains(after, needle) {
			t.Errorf("export contains %q from a failed Init", needle)
		}
	}
	if strings.Contains(after, "decoys:") {
		t.Errorf("export has a decoys: key\n%s", after)
	}
}
