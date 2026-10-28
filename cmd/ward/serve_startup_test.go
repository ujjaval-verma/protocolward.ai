// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/dataplane"
	"protocolward.ai/ward/internal/hostlist"
	"protocolward.ai/ward/internal/policy"
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

// writeHostFile writes "0.0.0.0 <host>" lines to a new file and returns its path.
func writeHostFile(t *testing.T, name string, hosts ...string) string {
	t.Helper()
	var b strings.Builder
	for _, h := range hosts {
		b.WriteString("0.0.0.0 " + h + "\n")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadHostLists(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")

	t.Run("none", func(t *testing.T) {
		buf := captureSlog(t)
		allow, block, err := loadHostLists(config.Config{})
		if err != nil {
			t.Fatal(err)
		}
		// Interface comparison: a typed-nil *hostlist.Set would be non-nil here.
		if allow != nil || block != nil {
			t.Errorf("allow=%v block=%v, want both nil interfaces", allow, block)
		}
		if !strings.Contains(buf.String(), "policy: not configured") {
			t.Errorf("missing pure-forwarder line: %s", buf.String())
		}
	})
	t.Run("block only", func(t *testing.T) {
		buf := captureSlog(t)
		bl := writeHostFile(t, "block.txt", "blocked.test")
		allow, block, err := loadHostLists(config.Config{Blocklists: []hostlist.Source{{ID: "bl-1", Path: bl}}})
		if err != nil {
			t.Fatal(err)
		}
		if allow != nil {
			t.Errorf("allow = %v, want nil interface", allow)
		}
		if block == nil {
			t.Fatal("block = nil")
		}
		if id, _, ok := block.Match("blocked.test"); !ok || id != "bl-1" {
			t.Errorf("Match = %q, %v", id, ok)
		}
		out := buf.String()
		if !strings.Contains(out, "hostlist: loaded source") || !strings.Contains(out, "blocklist: ready") || !strings.Contains(out, `"total_entries":1`) {
			t.Errorf("log: %s", out)
		}
	})
	t.Run("allow only", func(t *testing.T) {
		buf := captureSlog(t)
		al := writeHostFile(t, "allow.txt", "allowed.test")
		allow, block, err := loadHostLists(config.Config{Allowlists: []hostlist.Source{{ID: "al-1", Path: al}}})
		if err != nil {
			t.Fatal(err)
		}
		if block != nil {
			t.Errorf("block = %v, want nil interface", block)
		}
		if allow == nil {
			t.Fatal("allow = nil")
		}
		if id, _, ok := allow.Match("allowed.test"); !ok || id != "al-1" {
			t.Errorf("Match = %q, %v", id, ok)
		}
		out := buf.String()
		if !strings.Contains(out, "allowlist: ready") || !strings.Contains(out, `"total_entries":1`) {
			t.Errorf("log: %s", out)
		}
	})
	t.Run("both", func(t *testing.T) {
		captureSlog(t)
		bl := writeHostFile(t, "block.txt", "blocked.test")
		al := writeHostFile(t, "allow.txt", "allowed.test")
		allow, block, err := loadHostLists(config.Config{
			Blocklists: []hostlist.Source{{ID: "bl-1", Path: bl}},
			Allowlists: []hostlist.Source{{ID: "al-1", Path: al}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if allow == nil || block == nil {
			t.Errorf("allow=%v block=%v, want both non-nil", allow, block)
		}
	})
	t.Run("missing blocklist", func(t *testing.T) {
		captureSlog(t)
		_, _, err := loadHostLists(config.Config{Blocklists: []hostlist.Source{{ID: "bl-1", Path: missing}}})
		se := asServeError(t, err, 1)
		if !strings.HasPrefix(se.Message, "blocklist load failed:") {
			t.Errorf("Message = %q", se.Message)
		}
		if !strings.Contains(se.Remediation, "blocklists[*].path") {
			t.Errorf("Remediation = %q", se.Remediation)
		}
	})
	t.Run("missing allowlist", func(t *testing.T) {
		captureSlog(t)
		_, _, err := loadHostLists(config.Config{Allowlists: []hostlist.Source{{ID: "al-1", Path: missing}}})
		se := asServeError(t, err, 1)
		if !strings.HasPrefix(se.Message, "allowlist load failed:") {
			t.Errorf("Message = %q", se.Message)
		}
		if !strings.Contains(se.Remediation, "allowlists[*].path") {
			t.Errorf("Remediation = %q", se.Remediation)
		}
	})
}

func TestLoadDecoys(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		set, total, err := loadDecoys(config.Config{})
		if set != nil || total != 0 || err != nil {
			t.Errorf("got %v, %d, %v; want nil, 0, nil", set, total, err)
		}
	})
	t.Run("one source two names", func(t *testing.T) {
		buf := captureSlog(t)
		p := writeHostFile(t, "decoys.txt", "decoy-a.test", "decoy-b.test")
		set, total, err := loadDecoys(config.Config{Decoys: []hostlist.Source{{ID: "d-1", Path: p}}})
		if err != nil {
			t.Fatal(err)
		}
		if set == nil {
			t.Fatal("set = nil")
		}
		for _, h := range []string{"decoy-a.test", "decoy-b.test"} {
			if _, _, ok := set.Match(h); !ok {
				t.Errorf("Match(%q) = false", h)
			}
		}
		if total != 2 {
			t.Errorf("total = %d, want 2", total)
		}
		out := buf.String()
		if !strings.Contains(out, "decoy: loaded source") || !strings.Contains(out, "decoy: ready") {
			t.Errorf("log: %s", out)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		captureSlog(t)
		set, total, err := loadDecoys(config.Config{Decoys: []hostlist.Source{{ID: "d-1", Path: filepath.Join(t.TempDir(), "missing.txt")}}})
		se := asServeError(t, err, 1)
		if set != nil || total != 0 {
			t.Errorf("got %v, %d on error", set, total)
		}
		if !strings.HasPrefix(se.Message, "decoy load failed:") {
			t.Errorf("Message = %q", se.Message)
		}
		if !strings.Contains(se.Remediation, "decoys[*].path") {
			t.Errorf("Remediation = %q", se.Remediation)
		}
	})
}

func TestLoadServePolicy(t *testing.T) {
	t.Run("allow block decoys", func(t *testing.T) {
		buf := captureSlog(t)
		bl := writeHostFile(t, "block.txt", "both.test", "blocked.test")
		al := writeHostFile(t, "allow.txt", "both.test")
		dc := writeHostFile(t, "decoys.txt", "decoy.test")
		cfg := config.Config{
			Blocklists: []hostlist.Source{{ID: "bl-1", Path: bl}},
			Allowlists: []hostlist.Source{{ID: "al-1", Path: al}},
			Decoys:     []hostlist.Source{{ID: "d-1", Path: dc}},
			BlockResponse: config.BlockResponseConfig{
				Mode: config.BlockResponseModeAddress,
				A:    netip.MustParseAddr("0.0.0.0"),
				AAAA: netip.MustParseAddr("::"),
			},
		}
		engine, decoys, err := loadServePolicy(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if engine == nil || decoys == nil {
			t.Fatalf("engine=%v decoys=%v, want both non-nil", engine, decoys)
		}
		if got := engine.Decide("both.test").Action; got != policy.ActionAllow {
			t.Errorf("both.test = %v, want Allow", got)
		}
		if got := engine.Decide("blocked.test").Action; got != policy.ActionBlock {
			t.Errorf("blocked.test = %v, want Block", got)
		}
		if got := engine.Decide("other.test").Action; got != policy.ActionForward {
			t.Errorf("other.test = %v, want Forward", got)
		}
		out := buf.String()
		if n := strings.Count(out, "policy: engine ready"); n != 1 {
			t.Fatalf("banner count = %d, want 1: %s", n, out)
		}
		for _, want := range []string{`mode":"allowlist+blocklist"`, "block_response_a", "decoys_loaded"} {
			if !strings.Contains(out, want) {
				t.Errorf("banner missing %q: %s", want, out)
			}
		}
	})
	t.Run("nothing configured", func(t *testing.T) {
		buf := captureSlog(t)
		engine, decoys, err := loadServePolicy(config.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if engine == nil {
			t.Fatal("engine = nil, want non-nil forwarder")
		}
		if decoys != nil {
			t.Errorf("decoys = %v, want nil", decoys)
		}
		if got := engine.Decide("any.test").Action; got != policy.ActionForward {
			t.Errorf("Decide = %v, want Forward", got)
		}
		if strings.Contains(buf.String(), "policy: engine ready") {
			t.Errorf("unexpected banner: %s", buf.String())
		}
	})
	t.Run("decoys only", func(t *testing.T) {
		buf := captureSlog(t)
		dc := writeHostFile(t, "decoys.txt", "decoy.test")
		engine, decoys, err := loadServePolicy(config.Config{Decoys: []hostlist.Source{{ID: "d-1", Path: dc}}})
		if err != nil {
			t.Fatal(err)
		}
		if engine == nil || decoys == nil {
			t.Fatalf("engine=%v decoys=%v, want both non-nil", engine, decoys)
		}
		if strings.Contains(buf.String(), "policy: engine ready") {
			t.Errorf("unexpected banner: %s", buf.String())
		}
	})
	t.Run("missing blocklist fails before decoys load", func(t *testing.T) {
		buf := captureSlog(t)
		dc := writeHostFile(t, "decoys.txt", "decoy.test")
		cfg := config.Config{
			Blocklists: []hostlist.Source{{ID: "bl-1", Path: filepath.Join(t.TempDir(), "missing.txt")}},
			Decoys:     []hostlist.Source{{ID: "d-1", Path: dc}},
		}
		engine, decoys, err := loadServePolicy(cfg)
		asServeError(t, err, 1)
		if engine != nil || decoys != nil {
			t.Errorf("engine=%v decoys=%v on error, want nil", engine, decoys)
		}
		if strings.Contains(buf.String(), "decoy: ready") {
			t.Errorf("decoys loaded before the list error: %s", buf.String())
		}
	})
}

func TestServeDashAddr(t *testing.T) {
	t.Run("empty uses default", func(t *testing.T) {
		got, err := serveDashAddr(serveOpts{})
		if err != nil {
			t.Fatal(err)
		}
		if got != dashboardListenAddr {
			t.Errorf("got %q, want %q", got, dashboardListenAddr)
		}
	})
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		t.Run("loopback "+addr, func(t *testing.T) {
			got, err := serveDashAddr(serveOpts{dashListenAddr: addr})
			if err != nil {
				t.Fatal(err)
			}
			if got != addr {
				t.Errorf("got %q, want %q", got, addr)
			}
		})
	}
	t.Run("non-loopback", func(t *testing.T) {
		_, err := serveDashAddr(serveOpts{dashListenAddr: "0.0.0.0:18987"})
		se := asServeError(t, err, 1)
		if !strings.Contains(se.Message, "non-loopback") {
			t.Errorf("Message = %q", se.Message)
		}
		if !strings.HasPrefix(se.Remediation, "bind 127.0.0.1, ::1, or localhost only") {
			t.Errorf("Remediation = %q", se.Remediation)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		_, err := serveDashAddr(serveOpts{dashListenAddr: "nonsense"})
		se := asServeError(t, err, 1)
		if !strings.HasPrefix(se.Message, "invalid --dash-listen-addr") {
			t.Errorf("Message = %q", se.Message)
		}
	})
}

func TestNewServeDataplane(t *testing.T) {
	t.Run("real constructor rejects empty resolvers", func(t *testing.T) {
		captureSlog(t)
		srv, err := newServeDataplane(serveOpts{}, dataplane.Config{ListenAddr: "127.0.0.1:0"})
		se := asServeError(t, err, 1)
		if srv != nil {
			t.Errorf("srv = %v, want nil", srv)
		}
		if !strings.HasPrefix(se.Message, "dataplane init failed") {
			t.Errorf("Message = %q", se.Message)
		}
		if want := "check listen address and port availability in ward.yaml"; se.Remediation != want {
			t.Errorf("Remediation = %q, want %q", se.Remediation, want)
		}
	})
	t.Run("flag remediation", func(t *testing.T) {
		captureSlog(t)
		_, err := newServeDataplane(serveOpts{listenAddr: "127.0.0.1:0"}, dataplane.Config{ListenAddr: "127.0.0.1:0"})
		se := asServeError(t, err, 1)
		if want := "check the --listen-addr address and port availability"; se.Remediation != want {
			t.Errorf("Remediation = %q, want %q", se.Remediation, want)
		}
	})
	t.Run("nil server from constructor", func(t *testing.T) {
		captureSlog(t)
		opts := serveOpts{newDataplane: func(dataplane.Config) (*dataplane.Server, error) { return nil, nil }}
		srv, err := newServeDataplane(opts, dataplane.Config{ListenAddr: "127.0.0.1:0"})
		se := asServeError(t, err, 1)
		if srv != nil {
			t.Errorf("srv = %v, want nil", srv)
		}
		if !strings.Contains(se.Message, "newDataplane returned a nil server") {
			t.Errorf("Message = %q", se.Message)
		}
		if !strings.Contains(se.Remediation, "report this as a bug") {
			t.Errorf("Remediation = %q", se.Remediation)
		}
	})
	t.Run("success returns the constructed server", func(t *testing.T) {
		want := &dataplane.Server{}
		var seen dataplane.Config
		opts := serveOpts{newDataplane: func(c dataplane.Config) (*dataplane.Server, error) {
			seen = c
			return want, nil
		}}
		got, err := newServeDataplane(opts, dataplane.Config{ListenAddr: "127.0.0.1:5354"})
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got %p, want %p", got, want)
		}
		if seen.ListenAddr != "127.0.0.1:5354" {
			t.Errorf("constructor saw ListenAddr %q", seen.ListenAddr)
		}
	})
}
