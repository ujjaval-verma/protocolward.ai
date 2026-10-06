// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/pkg/detect"
	pmodel "protocolward.ai/ward/pkg/model"
	"protocolward.ai/ward/pkg/schema"
)

// TestServeCmd_MissingConfig_ExitsWithCode2 verifies that ward serve with a
// missing config file emits a remediation message and signals exit code 2.
// We call serveRun directly to avoid os.Exit in tests; it returns a serveError
// with Code == 2 when config resolution fails.
func TestServeCmd_MissingConfig_ExitsWithCode2(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "nonexistent.yaml")

	err := serveRun(context.Background(), serveOpts{configPath: missingPath})
	if err == nil {
		t.Fatal("expected error from serve with missing config, got nil")
	}

	se, ok := err.(*serveError)
	if !ok {
		t.Fatalf("expected *serveError, got %T: %v", err, err)
	}
	if se.Code != 2 {
		t.Errorf("expected exit code 2, got %d", se.Code)
	}
	// The message must mention the missing path so the operator knows what to fix.
	if !strings.Contains(se.Error(), missingPath) {
		t.Errorf("error message does not mention config path: %q", se.Error())
	}
	// Remediation field must be non-empty (invariant #8).
	if se.Remediation == "" {
		t.Error("serveError.Remediation must not be empty (invariant #8)")
	}
}

// TestServeCmd_ValidConfig_BootsAndShutsDownOnSIGTERM boots the serve loop
// with a minimal valid config and cancels the context (simulating SIGTERM),
// asserting the function returns with exit code 0 within 200ms.
func TestServeCmd_ValidConfig_BootsAndShutsDownOnSIGTERM(t *testing.T) {
	// Pick a random available port for the test listener.
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find a free UDP port: %v", err)
	}
	addr := l.LocalAddr().String()
	l.Close()

	cfgContent := fmt.Sprintf(`
upstreams:
  - address: "127.0.0.1:9999"
    server_name: "unused.test"
listen: "%s"
timeouts:
  shutdown: "50ms"
`, addr)
	cfgPath := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serveRun(ctx, serveOpts{configPath: cfgPath, dashListenAddr: "127.0.0.1:0"})
	}()

	// Give the server a moment to start listening.
	time.Sleep(20 * time.Millisecond)

	// Cancel context — this simulates SIGTERM.
	cancel()

	select {
	case err := <-done:
		if err != nil {
			se, ok := err.(*serveError)
			if !ok {
				t.Fatalf("unexpected error: %v", err)
			}
			if se.Code != 0 {
				t.Errorf("expected clean exit (code 0), got code %d: %v", se.Code, err)
			}
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("serve did not shut down within 200ms after context cancel")
	}

	// Reference syscall.SIGTERM to confirm the import is exercised.
	_ = syscall.SIGTERM
}

// wardBin is the path to the compiled test binary, built once per test process.
// Populated by TestMain; tests that run without TestMain fall back to buildWardBin.
var wardBin string

// buildWardBin compiles the ward binary into a temp dir and returns its path.
// The dir is owned by the caller; pass t.TempDir() to auto-clean on test end.
// Pass an empty string for tempDir to create a persistent temp dir.
func buildWardBin() (string, error) {
	if wardBin != "" {
		return wardBin, nil
	}
	moduleRoot := findModuleRoot(nil)
	dir, err := os.MkdirTemp("", "ward-test-bin-*")
	if err != nil {
		return "", err
	}
	binPath := filepath.Join(dir, "ward")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/ward")
	cmd.Dir = moduleRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build ward: %w\n%s", err, out)
	}
	wardBin = binPath
	return wardBin, nil
}

// findModuleRoot walks up from the test binary's working directory until it
// finds a go.mod, then returns that directory. Falls back to the test's
// working directory. Pass nil for t to skip t.Fatal (used outside test context).
func findModuleRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		if t != nil {
			t.Helper()
			t.Fatalf("findModuleRoot: getwd: %v", err)
		}
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return dir
}

// freeUDPAddr returns a free loopback UDP address (host:port) for use in test configs.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeUDPAddr: %v", err)
	}
	addr := l.LocalAddr().String()
	l.Close()
	return addr
}

// safeBuffer is a goroutine-safe bytes.Buffer for concurrent subprocess output
// capture + reader-side polling. Without the mutex the race detector flags
// concurrent Write (by os/exec's pipe-draining goroutine) and String (by the
// poller) on the same bytes.Buffer.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runServeForBriefRun builds the ward binary (once), launches
// `ward serve --config cfgPath`, polls combined output for a startup-complete
// sentinel (then waits dur for any post-ready output to flush), sends SIGTERM,
// waits up to 5s for graceful exit, and returns combined stdout+stderr.
//
// The sentinel-poll replaces the slice-B fixed Sleep that raced subprocess
// startup under `make ci` load (TestServe_LoadsBlocklists ~2/3 flake rate).
// `dur` is now the post-ready capture window, not the total wait.
func runServeForBriefRun(t *testing.T, cfgPath string, dur time.Duration) string {
	t.Helper()
	bin, err := buildWardBin()
	if err != nil {
		t.Skipf("could not build ward binary for subprocess test: %v", err)
	}
	// Override the dashboard bind to an ephemeral port so back-to-back
	// subprocess tests don't collide on the hardcoded 127.0.0.1:18987
	// production address (Ralph B1).
	cmd := exec.Command(bin, "serve", "--config", cfgPath, "--dash-listen-addr", "127.0.0.1:0")
	combined := &safeBuffer{}
	cmd.Stdout = combined
	cmd.Stderr = combined
	if err := cmd.Start(); err != nil {
		t.Fatalf("runServeForBriefRun: start: %v", err)
	}

	// Poll for any "startup complete" sentinel. The serve binary emits one of
	// these once the dataplane has bound + the lists are loaded. Whichever
	// fires first means startup is past the racy window.
	readySentinels := []string{
		`"msg":"policy: engine ready"`,
		`"msg":"policy: not configured`,
		`"msg":"blocklist: ready"`,                     // back-compat for slice-B-style configs (now never emitted, but harmless)
		`"msg":"blocklist: not configured`,             // same
		`"msg":"ward serve: starting with N upstreams`, // earliest fallback — emitted before list load but proves the process is alive
	}
	startupDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(startupDeadline) {
		out := combined.String()
		hit := false
		for _, s := range readySentinels {
			if strings.Contains(out, s) {
				hit = true
				break
			}
		}
		if hit {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Post-ready capture window: allow remaining log lines (e.g. "blocklist:
	// loaded source" emits per-source AFTER "ward serve: starting") to flush.
	time.Sleep(dur)

	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	// Wait up to 5s for graceful exit after SIGTERM.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Log("runServeForBriefRun: process did not exit within 5s after SIGTERM; killed")
	}
	return combined.String()
}

// runServeExpectingExit builds the ward binary (once), launches
// `ward serve --config cfgPath`, waits for process exit (up to 10s), and
// returns the exit code plus stderr. Used for startup-error assertions.
func runServeExpectingExit(t *testing.T, cfgPath string) (int, string) {
	t.Helper()
	bin, err := buildWardBin()
	if err != nil {
		t.Skipf("could not build ward binary for subprocess test: %v", err)
	}
	cmd := exec.Command(bin, "serve", "--config", cfgPath, "--dash-listen-addr", "127.0.0.1:0")
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	// context-bounded run with a 10s hard limit.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmdErr := make(chan error, 1)
	if startErr := cmd.Start(); startErr != nil {
		t.Fatalf("runServeExpectingExit: start: %v", startErr)
	}
	go func() { cmdErr <- cmd.Wait() }()
	select {
	case runErr := <-cmdErr:
		code := 0
		if runErr != nil {
			if exitErr, ok := runErr.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			} else {
				code = 1
			}
		}
		return code, stderrBuf.String()
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		t.Fatal("runServeExpectingExit: process did not exit within 10s (expected startup error)")
		return 1, stderrBuf.String()
	}
}

func TestServe_LoadsBlocklists(t *testing.T) {
	dir := t.TempDir()
	bl := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(bl, []byte("0.0.0.0 blocked.test.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists:
  - id: "test-list"
    path: "` + bl + `"
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := runServeForBriefRun(t, cfg, 600*time.Millisecond)
	if !strings.Contains(stdout, `"msg":"hostlist: loaded source"`) {
		t.Errorf("expected hostlist load summary in stdout, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"id":"test-list"`) {
		t.Errorf("expected list id in load summary, got:\n%s", stdout)
	}
}

func TestServe_PureForwarderBanner(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := runServeForBriefRun(t, cfg, 600*time.Millisecond)
	if !strings.Contains(stdout, "running as pure DNS forwarder") {
		t.Errorf("expected pure-forwarder banner, got:\n%s", stdout)
	}
}

func TestServe_MissingBlocklistFile_StartupError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists:
  - id: "missing"
    path: "/nonexistent/path/to/list.txt"
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	exitCode, stderr := runServeExpectingExit(t, cfg)
	if exitCode == 0 {
		t.Errorf("expected non-zero exit on missing blocklist, got 0; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "blocklist") {
		t.Errorf("expected stderr to mention blocklist, got:\n%s", stderr)
	}
}

func TestServe_PolicyReady_Banner_AllowOnly(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(al, []byte("0.0.0.0 example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
allowlists:
  - id: "test-allow"
    path: "` + al + `"
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runServeForBriefRun(t, cfg, 200*time.Millisecond)
	if !strings.Contains(out, `"msg":"policy: engine ready"`) {
		t.Errorf("missing policy: engine ready banner; got:\n%s", out)
	}
	if !strings.Contains(out, `"mode":"allowlist-only"`) {
		t.Errorf("expected mode=allowlist-only; got:\n%s", out)
	}
}

func TestServe_PolicyReady_Banner_BlockOnly(t *testing.T) {
	dir := t.TempDir()
	bl := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(bl, []byte("0.0.0.0 example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists:
  - id: "test-block"
    path: "` + bl + `"
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runServeForBriefRun(t, cfg, 200*time.Millisecond)
	if !strings.Contains(out, `"msg":"policy: engine ready"`) {
		t.Errorf("missing policy: engine ready banner; got:\n%s", out)
	}
	if !strings.Contains(out, `"mode":"blocklist-only"`) {
		t.Errorf("expected mode=blocklist-only; got:\n%s", out)
	}
}

func TestServe_PolicyReady_Banner_Both(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.txt")
	bl := filepath.Join(dir, "block.txt")
	for _, p := range []string{al, bl} {
		if err := os.WriteFile(p, []byte("0.0.0.0 example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
blocklists:
  - id: "test-block"
    path: "` + bl + `"
allowlists:
  - id: "test-allow"
    path: "` + al + `"
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runServeForBriefRun(t, cfg, 200*time.Millisecond)
	if !strings.Contains(out, `"msg":"policy: engine ready"`) {
		t.Errorf("missing policy: engine ready banner; got:\n%s", out)
	}
	if !strings.Contains(out, `"mode":"allowlist+blocklist"`) {
		t.Errorf("expected mode=allowlist+blocklist; got:\n%s", out)
	}
}

func TestServe_PassthroughBanner_Policy(t *testing.T) {
	// Neither blocklist nor allowlist configured → pure-forwarder banner
	// (renamed from slice-B's "blocklist:" to "policy:" in the policy-engine rename).
	dir := t.TempDir()
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runServeForBriefRun(t, cfg, 200*time.Millisecond)
	if !strings.Contains(out, "policy: not configured") {
		t.Errorf("missing pure-forwarder policy: not configured banner; got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// dns-forward slice — buildUpstreamTLSConfig unit (Ralph F2)
// ---------------------------------------------------------------------------

// ───────────────────────────────────────────────────────────────────────────
// SP10c T3 — adapter wiring in serve.go
// ───────────────────────────────────────────────────────────────────────────

func TestServe_Model_MissingBinary_StartsAnyway(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
model:
  command: ["/nonexistent/path/to/llama-classifier", "--model", "x.gguf"]
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runServeForBriefRun(t, cfg, 200*time.Millisecond)
	// Adapter init failure must NOT crash ward — the slow path is optional;
	// fast-path-only fallback is the documented behavior per spec.
	if !strings.Contains(out, "policy: model unavailable") {
		t.Errorf("expected `policy: model unavailable` log on missing binary; got:\n%s", out)
	}
	// Ward must have proceeded past adapter init: a dataplane-init or later
	// log must be present. Look for the upstream-count info line emitted at
	// step 4 in serveRun.
	if !strings.Contains(out, `"upstreams":1`) {
		t.Errorf("ward did not progress past adapter init; got:\n%s", out)
	}
}

func TestServe_Model_HappyPath_LoadsAdapter(t *testing.T) {
	// /bin/cat blocks reading stdin, satisfying os/exec Start without
	// producing valid JSON verdicts. We assert only on the `policy: model
	// loaded` startup log line — the happy-path verdict round-trip is
	// covered by the DOD bullet 13 harness using cmd/wardtestmodel.
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("/bin/cat not present on this platform")
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "ward.yaml")
	cfgBody := `
listen: "` + freeUDPAddr(t) + `"
upstreams:
  - address: "9.9.9.9:853"
    server_name: "dns.quad9.net"
model:
  command: ["/bin/cat"]
`
	if err := os.WriteFile(cfg, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runServeForBriefRun(t, cfg, 300*time.Millisecond)
	if !strings.Contains(out, "policy: model loaded") {
		t.Errorf("expected `policy: model loaded` log on happy adapter path; got:\n%s", out)
	}
}

func TestBuildUpstreamTLSConfig_NoCABundle_ReturnsNil(t *testing.T) {
	u := configUpstream(t, "9.9.9.9:853", "dns.quad9.net", "")
	got := buildUpstreamTLSConfig(u)
	if got != nil {
		t.Errorf("no ca_bundle: expected nil *tls.Config, got %+v", got)
	}
}

func TestBuildUpstreamTLSConfig_WithCABundle_PinsRootCAs(t *testing.T) {
	caPath := writeSelfSignedPEM(t)
	u := configUpstream(t, "127.0.0.1:5853", "wardtestdot.test", caPath)

	got := buildUpstreamTLSConfig(u)
	if got == nil {
		t.Fatal("ca_bundle set: expected non-nil *tls.Config, got nil")
	}
	if got.RootCAs == nil {
		t.Error("RootCAs: expected non-nil *x509.CertPool")
	}
	if got.ServerName != "wardtestdot.test" {
		t.Errorf("ServerName: got %q want %q", got.ServerName, "wardtestdot.test")
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %d want %d (TLS 1.2)", got.MinVersion, tls.VersionTLS12)
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeTCPAddr: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// S2 end-to-end through the real binary: builtin config → in-process
// detector → query forwarded (upstream is dead, so the forward path's
// SERVFAIL + "all upstream resolvers failed" log prove it was forwarded,
// not answered by the block path) → hostname listed in dashboard Flags.
func TestServe_Model_Builtin_FlagsOnDashboard_StillForwarded(t *testing.T) {
	const dgaProbe = "3f9a1c7e5b2d8046af1e9c3b7d5a2e80.info"
	if a, err := detect.New().Assess(context.Background(), pmodel.Input{Hostname: dgaProbe}); err != nil || a.Verdict != schema.VerdictMalicious {
		t.Fatalf("precondition: detect.New() must flag %q, got %+v err=%v", dgaProbe, a, err)
	}
	bin, err := buildWardBin()
	if err != nil {
		t.Skipf("could not build ward binary: %v", err)
	}
	dnsAddr, dashAddr := freeUDPAddr(t), freeTCPAddr(t)
	cfgPath := filepath.Join(t.TempDir(), "ward.yaml")
	body := `listen: "` + dnsAddr + `"
upstreams:
  - address: "127.0.0.1:1"
    server_name: "unreachable.test"
timeouts:
  dial: "300ms"
  query: "500ms"
  shutdown: "2s"
model:
  builtin: lexical
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "serve", "--config", cfgPath, "--dash-listen-addr", dashAddr)
	out := &safeBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	})

	// Wait for the DNS listener: retry until any reply arrives.
	c := &dns.Client{Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dgaProbe+".", dns.TypeA)
	var resp *dns.Msg
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, _, err = c.Exchange(m, dnsAddr); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("no DNS reply within 5s: %v\nlog:\n%s", err, out.String())
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL from the forward path (flag-only, never blocked)", dns.RcodeToString[resp.Rcode])
	}

	// Poll the dashboard until the flag shows up (the fork is async). The
	// panel is extracted by its element boundaries, independent of the order
	// of the flags and decisions sections (k).
	var panel string
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hr, gerr := http.Get("http://" + dashAddr + "/"); gerr == nil {
			raw, _ := io.ReadAll(hr.Body)
			hr.Body.Close()
			panel = extractPanel(string(raw), `id="flags"`)
			if strings.Contains(panel, dgaProbe) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	// (j) Assert strings that exist only in a rendered row — the qname and a
	// reason code — not the static "flagged, not blocked" note, which the
	// empty state also renders.
	if !strings.Contains(panel, dgaProbe) || !strings.Contains(panel, "rare_ngrams") {
		t.Fatalf("dashboard flags panel missing %q row:\n%s\nlog:\n%s", dgaProbe, panel, out.String())
	}
	log := out.String()
	for _, want := range []string{
		`"msg":"policy: model loaded"`, `"builtin":"lexical"`,
		`"msg":"all upstream resolvers failed"`,
		`"msg":"policy: classified"`, `"enforced":false`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %s", want)
		}
	}
	if strings.Contains(log, "policy: model unavailable") {
		t.Errorf("builtin path must never log model unavailable:\n%s", log)
	}
}

// extractPanel returns the HTML of the dashboard panel whose opening tag
// contains marker, ending at the next `<div class="panel"` (or the end of
// the document). It does not assume which panel is rendered first.
func extractPanel(doc, marker string) string {
	i := strings.Index(doc, marker)
	if i < 0 {
		return ""
	}
	rest := doc[i+len(marker):]
	if j := strings.Index(rest, `<div class="panel"`); j >= 0 {
		return doc[i : i+len(marker)+j]
	}
	return doc[i:]
}
