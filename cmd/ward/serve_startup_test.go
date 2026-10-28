// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/config"
)

// captureSlog swaps slog.Default() for a JSON handler at Debug level that
// writes to the returned buffer, and restores the previous default on
// cleanup. Only non-parallel tests may use it: top-level t.Parallel() tests
// resume after every sequential test has finished, so no parallel serveRun
// (which calls slog.SetDefault) runs at the same time.
func captureSlog(t *testing.T) *safeBuffer {
	t.Helper()
	buf := &safeBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// asServeError asserts err is a non-nil *serveError with the given code.
func asServeError(t *testing.T, err error, code int) *serveError {
	t.Helper()
	if err == nil {
		t.Fatalf("err = nil, want *serveError code %d", code)
	}
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("err = %T %v, want *serveError", err, err)
	}
	if se.Code != code {
		t.Fatalf("Code = %d, want %d (msg %q)", se.Code, code, se.Message)
	}
	return se
}

const startupMinimalCfg = `
upstreams:
  - address: "127.0.0.1:9999"
    server_name: "unused.test"
listen: "127.0.0.1:5354"
`

func writeStartupCfg(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "ward.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadServeConfig(t *testing.T) {
	t.Run("explicit missing path", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.yaml")
		_, err := loadServeConfig(serveOpts{configPath: missing})
		se := asServeError(t, err, 2)
		if want := "config file not found: " + missing; se.Message != want {
			t.Errorf("Message = %q, want %q", se.Message, want)
		}
	})
	t.Run("invalid listen flag", func(t *testing.T) {
		p := writeStartupCfg(t, t.TempDir(), startupMinimalCfg)
		_, err := loadServeConfig(serveOpts{configPath: p, listenAddr: "nonsense"})
		se := asServeError(t, err, 2)
		if !strings.HasPrefix(se.Message, `invalid --listen-addr "nonsense"`) {
			t.Errorf("Message = %q", se.Message)
		}
		if !strings.Contains(se.Remediation, "host:port") {
			t.Errorf("Remediation = %q, want host:port", se.Remediation)
		}
	})
	t.Run("listen flag overrides file", func(t *testing.T) {
		p := writeStartupCfg(t, t.TempDir(), startupMinimalCfg)
		cfg, err := loadServeConfig(serveOpts{configPath: p, listenAddr: "127.0.0.1:0"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "127.0.0.1:0" {
			t.Errorf("Listen = %q, want 127.0.0.1:0", cfg.Listen)
		}
	})
	t.Run("no flag keeps file listen", func(t *testing.T) {
		p := writeStartupCfg(t, t.TempDir(), startupMinimalCfg)
		cfg, err := loadServeConfig(serveOpts{configPath: p})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "127.0.0.1:5354" {
			t.Errorf("Listen = %q, want 127.0.0.1:5354", cfg.Listen)
		}
	})
	t.Run("XDG default path", func(t *testing.T) {
		xdg := t.TempDir()
		if err := os.MkdirAll(filepath.Join(xdg, "protocol-ward"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeStartupCfg(t, filepath.Join(xdg, "protocol-ward"), startupMinimalCfg)
		t.Setenv("XDG_CONFIG_HOME", xdg)
		cfg, err := loadServeConfig(serveOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "127.0.0.1:5354" {
			t.Errorf("Listen = %q", cfg.Listen)
		}
	})
	t.Run("no config found", func(t *testing.T) {
		if _, err := os.Stat("/etc/protocolward/ward.yaml"); err == nil {
			t.Skip("/etc/protocolward/ward.yaml exists on this host")
		}
		xdg := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", xdg)
		_, err := loadServeConfig(serveOpts{})
		se := asServeError(t, err, 2)
		if !strings.HasPrefix(se.Message, "no config file found; searched:") {
			t.Errorf("Message = %q", se.Message)
		}
		if want := filepath.Join(xdg, "protocol-ward", "ward.yaml"); !strings.Contains(se.Message, want) {
			t.Errorf("Message = %q, want it to name %s", se.Message, want)
		}
	})
}

func TestNewUpstreamClients(t *testing.T) {
	t.Run("two valid upstreams", func(t *testing.T) {
		buf := captureSlog(t)
		cfg := config.Config{Upstreams: []config.Upstream{
			{Address: "127.0.0.1:9991", ServerName: "a.test"},
			{Address: "127.0.0.1:9992", ServerName: "b.test"},
		}}
		clients, err := newUpstreamClients(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(clients) != 2 {
			t.Fatalf("len(clients) = %d, want 2", len(clients))
		}
		out := buf.String()
		if !strings.Contains(out, "ward serve: starting with N upstreams") || !strings.Contains(out, `"upstreams":2`) {
			t.Errorf("missing upstream-count line: %s", out)
		}
	})
	t.Run("second upstream fails", func(t *testing.T) {
		buf := captureSlog(t)
		cfg := config.Config{Upstreams: []config.Upstream{
			{Address: "127.0.0.1:9991", ServerName: "a.test"},
			{Address: "127.0.0.1:9992", ServerName: ""},
		}}
		clients, err := newUpstreamClients(cfg)
		se := asServeError(t, err, 1)
		if clients != nil {
			t.Errorf("clients = %v, want nil on failure", clients)
		}
		if !strings.HasPrefix(se.Message, `upstream "127.0.0.1:9992" construction failed:`) {
			t.Errorf("Message = %q", se.Message)
		}
		if !strings.Contains(se.Remediation, `"127.0.0.1:9992"`) {
			t.Errorf("Remediation = %q, want it to name the address", se.Remediation)
		}
		if strings.Contains(buf.String(), "starting with N upstreams") {
			t.Errorf("count line logged on failure: %s", buf.String())
		}
	})
}
