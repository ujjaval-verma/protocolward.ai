// SPDX-License-Identifier: Apache-2.0

// Package decoy_test — file named per invariants.md invariant 6 ("Tested in
// internal/decoy/export_test.go"). This test owns the regression contract:
// a config dumped via config.Export MUST NOT include any decoy hostname.
// Lives in internal/decoy because the invariant is about decoys; depends on
// internal/config (acyclic — config does not import decoy).
package decoy_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"protocolward.ai/ward/internal/config"
)

// TestInvariant6_ExportOmitsDecoyHostnames asserts the byte-level contract.
// Builds a per-test fixture under t.TempDir() (no dependency on testdata/) so
// `go test ./...` works from any working directory.
func TestInvariant6_ExportOmitsDecoyHostnames(t *testing.T) {
	const sentinel = "inv6-sentinel.invariant6.test"

	dir := t.TempDir()
	decoyPath := filepath.Join(dir, "decoys.txt")
	if err := os.WriteFile(decoyPath, []byte("0.0.0.0 "+sentinel+"\n"), 0o600); err != nil {
		t.Fatalf("write decoys: %v", err)
	}
	wardYAML := `listen: "127.0.0.1:5354"
log_level: "info"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
timeouts:
  dial: "3s"
  query: "2s"
  shutdown: "5s"
decoys:
  - id: "inv6-test"
    path: "` + decoyPath + `"
`
	yamlPath := filepath.Join(dir, "ward.yaml")
	if err := os.WriteFile(yamlPath, []byte(wardYAML), 0o600); err != nil {
		t.Fatalf("write ward.yaml: %v", err)
	}

	cfg, err := config.Load(yamlPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	// Sanity: the loaded config MUST have the decoy entry. If it doesn't, the
	// test is no longer exercising the contract.
	if len(cfg.Decoys) != 1 {
		t.Fatalf("expected 1 decoy source loaded, got %d — fixture not exercising invariant", len(cfg.Decoys))
	}

	out, err := config.Export(cfg)
	if err != nil {
		t.Fatalf("config.Export: %v", err)
	}

	// Byte-level assertion — even a `decoys: null` or a stray "inv6-sentinel"
	// substring would fail this check.
	if bytes.Contains(out, []byte(sentinel)) {
		t.Errorf("invariant 6 violated: export leaks decoy hostname %q\n--- export output ---\n%s", sentinel, out)
	}
	// Belt-and-braces: the `decoys:` key itself should be absent. A
	// structurally empty `decoys: []` would also be a defect.
	if bytes.Contains(out, []byte("decoys:")) {
		t.Errorf("invariant 6 violated: export contains decoys: key\n--- export output ---\n%s", out)
	}
}
