// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeDecoyFixture writes a hosts-file fragment and a ward.yaml referencing
// it (plus the minimum required fields). Returns the ward.yaml path and the
// sentinel hostname.
func writeDecoyFixture(t *testing.T, sentinel string) string {
	t.Helper()
	dir := t.TempDir()
	dpath := filepath.Join(dir, "decoys.txt")
	if err := os.WriteFile(dpath, []byte("0.0.0.0 "+sentinel+"\n"), 0o600); err != nil {
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
  - id: "test"
    path: "` + dpath + `"
`
	p := filepath.Join(dir, "ward.yaml")
	if err := os.WriteFile(p, []byte(wardYAML), 0o600); err != nil {
		t.Fatalf("write ward.yaml: %v", err)
	}
	return p
}

func TestConfigExportRun_Happy_OmitsDecoys(t *testing.T) {
	const sentinel = "cmd-export-sentinel.test"
	cfgPath := writeDecoyFixture(t, sentinel)

	var buf bytes.Buffer
	err := configExportRun(&buf, configExportOpts{configPath: cfgPath})
	if err != nil {
		t.Fatalf("configExportRun: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "listen: 127.0.0.1:5354") && !strings.Contains(out, "listen: \"127.0.0.1:5354\"") {
		t.Errorf("export missing listen field; got:\n%s", out)
	}
	if strings.Contains(out, sentinel) {
		t.Errorf("export leaks decoy hostname %q; got:\n%s", sentinel, out)
	}
	if bytes.Contains(buf.Bytes(), []byte("decoys:")) {
		t.Errorf("export contains decoys: key; got:\n%s", out)
	}
}

func TestConfigExportRun_MissingConfig_ExitsCode2(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nonexistent.yaml")
	var buf bytes.Buffer
	err := configExportRun(&buf, configExportOpts{configPath: missing})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	se, ok := err.(*serveError)
	if !ok {
		t.Fatalf("expected *serveError, got %T: %v", err, err)
	}
	if se.Code != 2 {
		t.Errorf("Code: got %d want 2", se.Code)
	}
	if buf.Len() != 0 {
		t.Errorf("stdout should be empty on error; got: %s", buf.String())
	}
}

func TestConfigExportRun_InvalidYAML_ExitsCode2(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(p, []byte("this is: not [valid yaml: at all\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var buf bytes.Buffer
	err := configExportRun(&buf, configExportOpts{configPath: p})
	if err == nil {
		t.Fatal("expected parse error")
	}
	se, ok := err.(*serveError)
	if !ok {
		t.Fatalf("expected *serveError, got %T: %v", err, err)
	}
	if se.Code != 2 {
		t.Errorf("Code: got %d want 2", se.Code)
	}
}
