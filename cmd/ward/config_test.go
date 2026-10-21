// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/config"
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

const unknownKeyRemediation = "fix the spelling or remove the key in ward.yaml; see ward.example.yaml for a template"

// writeExampleWithBogusKey copies ward.example.yaml and appends an unknown key.
func writeExampleWithBogusKey(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "ward.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	if !bytes.HasSuffix(b, []byte("\n")) {
		b = append(b, '\n')
	}
	b = append(b, "bogus_typo_field: 1\n"...)
	p := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestMapConfigLoadError_MultipleDocuments(t *testing.T) {
	y := "listen: \"127.0.0.1:5354\"\nlog_level: \"info\"\nupstreams:\n  - address: \"9.9.9.9:853\"\n    server_name: \"dns.quad9.net\"\ntimeouts:\n  dial: \"3s\"\n  query: \"2s\"\n  shutdown: \"5s\"\n---\nlisten: \"127.0.0.1:1\"\n"
	p := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := config.Load(p)
	if err == nil {
		t.Fatal("expected error")
	}
	se := mapConfigLoadError(p, err)
	if se.Code != 2 {
		t.Errorf("Code = %d want 2", se.Code)
	}
	if want := "config error in " + p + ": another document starts at line 10"; se.Message != want {
		t.Errorf("Message = %q want %q", se.Message, want)
	}
	if want := "ward.yaml holds exactly one YAML document; remove the extra `---` separator or merge the documents into one"; se.Remediation != want {
		t.Errorf("Remediation = %q want %q", se.Remediation, want)
	}
}

func TestMapConfigLoadError_UnknownKey(t *testing.T) {
	p := "/p/ward.yaml"
	base := &config.UnknownKeyError{Path: p, Keys: []config.UnknownKey{{Line: 3, Key: "blocklist", Section: "", Valid: []string{"listen"}}}}
	want := "config error in " + p + ": line 3: unknown key \"blocklist\" at top level (valid keys: listen)"
	for name, err := range map[string]error{"direct": base, "wrapped": fmt.Errorf("wrap: %w", base)} {
		t.Run(name, func(t *testing.T) {
			se := mapConfigLoadError(p, err)
			if se.Code != 2 {
				t.Errorf("Code = %d want 2", se.Code)
			}
			if se.Message != want {
				t.Errorf("Message = %q want %q", se.Message, want)
			}
			if se.Remediation != unknownKeyRemediation {
				t.Errorf("Remediation = %q", se.Remediation)
			}
		})
	}
}

func TestConfigExportRun_UnknownKey_ExitsCode2(t *testing.T) {
	p := writeExampleWithBogusKey(t)
	var buf bytes.Buffer
	err := configExportRun(&buf, configExportOpts{configPath: p})
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("err = %T %v; want *serveError", err, err)
	}
	if se.Code != 2 {
		t.Errorf("Code = %d want 2", se.Code)
	}
	if !strings.Contains(se.Message, `unknown key "bogus_typo_field" at top level`) {
		t.Errorf("Message = %q", se.Message)
	}
	if se.Remediation != unknownKeyRemediation {
		t.Errorf("Remediation = %q", se.Remediation)
	}
	if buf.Len() != 0 {
		t.Errorf("stdout not empty: %q", buf.String())
	}
}
