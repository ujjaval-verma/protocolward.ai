// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"protocolward.ai/ward/internal/dataplane"
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

// wardBin is the ward binary built once per test process by buildWardBin.
// sync.Once makes the build safe for parallel subprocess tests.
var (
	wardBin     string
	wardBinErr  error
	wardBinOnce sync.Once
	wardBinDir  string // temp dir holding the binary; removed by TestMain
)

// TestMain removes the ward test binary directory after the run so each
// `go test` leaves nothing behind in $TMPDIR. The exit code is preserved.
func TestMain(m *testing.M) {
	code := m.Run()
	if wardBinDir != "" {
		_ = os.RemoveAll(wardBinDir)
	}
	os.Exit(code)
}

// buildWardBin compiles the ward binary into a temp dir (once per test
// process) and returns its path.
func buildWardBin() (string, error) {
	wardBinOnce.Do(func() { wardBin, wardBinErr = compileWardBin() })
	return wardBin, wardBinErr
}

func compileWardBin() (string, error) {
	moduleRoot := findModuleRoot(nil)
	dir, err := os.MkdirTemp("", "ward-test-bin-*")
	if err != nil {
		return "", err
	}
	wardBinDir = dir
	binPath := filepath.Join(dir, "ward")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/ward")
	cmd.Dir = moduleRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build ward: %w\n%s", err, out)
	}
	return binPath, nil
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
		t.Fatalf("could not build ward binary for subprocess test: %v", err)
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
		t.Fatalf("could not build ward binary for subprocess test: %v", err)
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
//
// Determinism: ward binds a kernel-assigned DNS port and dashboard port that
// it holds itself, and the test learns both from ward's own `dns: listening`
// and `dashboard: ready` log lines (startWard), so no other process can take
// the port and no retry loop is needed. It sends one query, then waits for
// the `policy: classified` line: ward records the flag before logging it and
// all log lines share one ordered pipe, so once that line is captured the
// flag is on the dashboard and every earlier line is in the capture too.
func TestServe_Model_Builtin_FlagsOnDashboard_StillForwarded(t *testing.T) {
	const dgaProbe = "3f9a1c7e5b2d8046af1e9c3b7d5a2e80.info"
	if a, err := detect.New().Assess(context.Background(), pmodel.Input{Hostname: dgaProbe}); err != nil || a.Verdict != schema.VerdictMalicious {
		t.Fatalf("precondition: detect.New() must flag %q, got %+v err=%v", dgaProbe, a, err)
	}
	w := startWard(t, deadUpstreamCfg+`model:
  builtin: lexical
`)

	c := &dns.Client{Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dgaProbe+".", dns.TypeA)
	resp, _, err := c.Exchange(m, w.dnsAddr)
	if err != nil {
		t.Fatalf("no DNS reply from %s: %v\nlog:\n%s", w.dnsAddr, err, w.out.String())
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL from the forward path (flag-only, never blocked)", dns.RcodeToString[resp.Rcode])
	}

	if _, err := w.waitFor("policy: classified"); err != nil {
		t.Fatalf("%v", err)
	}

	// The panel is extracted by its element boundaries, independent of the
	// order of the flags and decisions sections (k).
	hr, err := http.Get("http://" + w.dashAddr + "/")
	if err != nil {
		t.Fatalf("GET dashboard: %v\nlog:\n%s", err, w.out.String())
	}
	raw, err := io.ReadAll(hr.Body)
	hr.Body.Close()
	if err != nil {
		t.Fatalf("read dashboard body: %v\nlog:\n%s", err, w.out.String())
	}
	panel := extractPanel(string(raw), `id="flags"`)
	// (j) Assert strings that exist only in a rendered row — the qname and a
	// reason code — not the static "flagged, not blocked" note, which the
	// empty state also renders.
	if !strings.Contains(panel, dgaProbe) || !strings.Contains(panel, "rare_ngrams") {
		t.Fatalf("dashboard flags panel missing %q row:\n%s\nlog:\n%s", dgaProbe, panel, w.out.String())
	}
	log := w.out.String()
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

// TestServe_Healthz_ReportsClassifyDropped proves serve wires the dataplane
// drop counter into /healthz (0 on an idle server; the dataplane and web
// tests cover non-zero values).
func TestServe_Healthz_ReportsClassifyDropped(t *testing.T) {
	got := serveHealthz(t, "", nil)
	if v, ok := got["classify_dropped"]; !ok || v != float64(0) {
		t.Errorf("/healthz classify_dropped = %v (present %v); want 0", v, ok)
	}
}

// TestServe_Healthz_ReportsClassifier proves serve wires the dataplane's
// classifier state into /healthz: "none" with no model: stanza, "ok" once
// the server is up with the built-in detector.
func TestServe_Healthz_ReportsClassifier(t *testing.T) {
	if got := serveHealthz(t, "", nil); got["classifier"] != "none" {
		t.Errorf("no model: /healthz classifier = %v; want none", got["classifier"])
	}
	isOK := func(b map[string]any) bool { return b["classifier"] == "ok" }
	if got := serveHealthz(t, "model:\n  builtin: lexical\n", isOK); got["classifier"] != "ok" {
		t.Errorf("builtin model: /healthz classifier = %v; want ok", got["classifier"])
	}
}

// TestServe_Healthz_ModelStartFailed_ClassifierUnavailable: a configured
// model that fails to start leaves classification off until restart, so
// /healthz says "unavailable", not "none"; status stays "ok".
func TestServe_Healthz_ModelStartFailed_ClassifierUnavailable(t *testing.T) {
	isUnavailable := func(b map[string]any) bool { return b["classifier"] == "unavailable" }
	got := serveHealthz(t, "model:\n  command: [\"/nonexistent/ward-test-model\"]\n", isUnavailable)
	if got["classifier"] != "unavailable" {
		t.Errorf("model start failed: /healthz classifier = %v; want unavailable", got["classifier"])
	}
	if got["status"] != "ok" {
		t.Errorf("model start failed: /healthz status = %v; want ok", got["status"])
	}
}

// serveHealthz runs serveRun in-process with a minimal config plus extra
// YAML, waits for the dashboard, and returns the decoded /healthz body:
// the first one, or with until non-nil the first for which until is true
// (else the last seen at the 5 s deadline). Shutdown is bounded so a
// wedged serve fails the test instead of hanging.
func serveHealthz(t *testing.T, extra string, until func(map[string]any) bool) map[string]any {
	t.Helper()
	dnsAddr := freeUDPAddr(t)
	dashAddr := freeTCPAddr(t)
	cfgPath := filepath.Join(t.TempDir(), "ward.yaml")
	body := fmt.Sprintf("upstreams:\n  - address: \"127.0.0.1:9999\"\n    server_name: \"unused.test\"\nlisten: %q\ntimeouts:\n  shutdown: \"50ms\"\n", dnsAddr) + extra
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveRun(ctx, serveOpts{configPath: cfgPath, dashListenAddr: dashAddr}) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("serveRun did not return within 5s of cancel")
		}
	}()

	var got map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get("http://" + dashAddr + "/healthz"); err == nil {
			var body map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			got = body
			if until == nil || until(body) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got == nil {
		t.Fatal("/healthz did not answer within 5s")
	}
	return got
}

// wakeBuffer is a safeBuffer that signals a channel on every Write, so a
// reader can wait for new output without sleep polling.
type wakeBuffer struct {
	safeBuffer
	wake chan struct{} // capacity 1; a pending token means "output changed"
}

func newWakeBuffer() *wakeBuffer { return &wakeBuffer{wake: make(chan struct{}, 1)} }

func (b *wakeBuffer) Write(p []byte) (int, error) {
	n, err := b.safeBuffer.Write(p)
	select {
	case b.wake <- struct{}{}:
	default:
	}
	return n, err
}

// wardWaitBound only turns a hang into a failure; nothing passes on a timeout.
const wardWaitBound = 5 * time.Second

// placeholderListen is the listen: value launchWard writes to ward.yaml; the
// --listen-addr override must replace it.
const placeholderListen = "127.0.0.1:5354"

// wardProc is a running `ward serve` subprocess. dnsAddr and dashAddr are
// filled in by startWard from ward's own readiness log lines.
type wardProc struct {
	dnsAddr  string
	dashAddr string
	out      *wakeBuffer
	exited   chan struct{} // closed once cmd.Wait returned (pipe fully copied)
	exitCode int           // valid once exited is closed
}

// launchWard writes cfgBody (which must NOT contain a listen: key; launchWard
// adds a placeholder one that --listen-addr overrides) to a temp ward.yaml and
// starts `ward serve` with --listen-addr listenAddr and a kernel-assigned
// dashboard port. It does not wait for readiness. stdout and stderr share one
// capture buffer.
func launchWard(t *testing.T, cfgBody, listenAddr string) *wardProc {
	t.Helper()
	bin, err := buildWardBin()
	if err != nil {
		t.Fatalf("could not build ward binary: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "ward.yaml")
	full := "listen: \"" + placeholderListen + "\"\n" + cfgBody
	if err := os.WriteFile(cfgPath, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "serve", "--config", cfgPath,
		"--listen-addr", listenAddr, "--dash-listen-addr", "127.0.0.1:0")
	w := &wardProc{out: newWakeBuffer(), exited: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = w.out, w.out
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ward: %v", err)
	}
	go func() {
		_ = cmd.Wait()
		w.exitCode = cmd.ProcessState.ExitCode()
		close(w.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-w.exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-w.exited
		}
	})
	return w
}

// scan decodes the newline-terminated JSON lines captured so far and returns
// the first whose msg field equals msg. A partly written line is never decoded;
// lines that are not JSON objects (the lipgloss stderr lines) are skipped.
func (w *wardProc) scan(msg string) map[string]any {
	log := w.out.String()
	for {
		i := strings.IndexByte(log, '\n')
		if i < 0 {
			return nil
		}
		line := strings.TrimSpace(log[:i])
		log = log[i+1:]
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		if m["msg"] == msg {
			return m
		}
	}
}

// waitFor blocks until ward logs a JSON line whose msg is msg and returns it.
// It returns an error at once if ward exits first (after one last scan of the
// complete log) and after wardWaitBound if neither happens.
func (w *wardProc) waitFor(msg string) (map[string]any, error) {
	timer := time.NewTimer(wardWaitBound)
	defer timer.Stop()
	for {
		if m := w.scan(msg); m != nil {
			return m, nil
		}
		select {
		case <-w.out.wake:
		case <-w.exited:
			if m := w.scan(msg); m != nil {
				return m, nil
			}
			return nil, fmt.Errorf("ward exited before %s (exit code %d)\nlog:\n%s", msg, w.exitCode, w.out.String())
		case <-timer.C:
			return nil, fmt.Errorf("timed out after %s waiting for %s\nlog:\n%s", wardWaitBound, msg, w.out.String())
		}
	}
}

// startWard launches ward on a kernel-assigned DNS port (which ward itself
// holds) and waits for its own readiness lines to learn the real addresses.
func startWard(t *testing.T, cfgBody string) *wardProc {
	t.Helper()
	w := launchWard(t, cfgBody, "127.0.0.1:0")
	m, err := w.waitFor("dns: listening")
	if err != nil {
		t.Fatalf("%v", err)
	}
	addr, ok := m["addr"].(string)
	if !ok || addr == "" {
		t.Fatalf("dns: listening has no string addr field: %v\nlog:\n%s", m, w.out.String())
	}
	w.dnsAddr = addr
	m, err = w.waitFor("dashboard: ready")
	if err != nil {
		t.Fatalf("%v", err)
	}
	listen, ok := m["listen"].(string)
	if !ok || listen == "" {
		t.Fatalf("dashboard: ready has no string listen field: %v\nlog:\n%s", m, w.out.String())
	}
	w.dashAddr = listen
	return w
}

// deadUpstreamCfg is a ward.yaml body (no listen:) whose only upstream refuses
// connections at once, so every forwarded query SERVFAILs.
const deadUpstreamCfg = `upstreams:
  - address: "127.0.0.1:1"
    server_name: "unreachable.test"
timeouts:
  dial: "300ms"
  query: "500ms"
  shutdown: "2s"
`

func TestServe_ListenAddrOverride_KernelPort(t *testing.T) {
	w := startWard(t, deadUpstreamCfg)
	_, port, err := net.SplitHostPort(w.dnsAddr)
	if err != nil || port == "0" || port == "" {
		t.Fatalf("dns: listening addr %q must carry a kernel-assigned non-zero port (err=%v)", w.dnsAddr, err)
	}
	if w.dnsAddr == placeholderListen {
		t.Fatalf("dns: listening addr %q is the ward.yaml placeholder; --listen-addr was ignored", w.dnsAddr)
	}
	c := &dns.Client{Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeA)
	resp, _, err := c.Exchange(m, w.dnsAddr)
	if err != nil {
		t.Fatalf("query %s: %v\nlog:\n%s", w.dnsAddr, err, w.out.String())
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL (dead upstream)", dns.RcodeToString[resp.Rcode])
	}
}

// A NOERROR responder holds the port ward is told to bind. ward must exit with
// its own bind diagnosis, and the test must never mistake the squatter for
// ward: startup sends the squatter no query at all.
func TestLaunchWard_SquattedListenPort_ExitsBeforeReady(t *testing.T) {
	held, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	started := make(chan struct{})
	sq := &dns.Server{PacketConn: held, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(rw dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		_ = rw.WriteMsg(m)
	})}
	go func() { _ = sq.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = sq.Shutdown()
		_ = held.Close()
	})
	select {
	case <-started:
	case <-time.After(wardWaitBound):
		t.Fatal("squatter did not start serving")
	}
	heldAddr := held.LocalAddr().String()

	w := launchWard(t, deadUpstreamCfg, heldAddr)
	_, err = w.waitFor("dns: listening")
	if err == nil || !strings.Contains(err.Error(), "ward exited before dns: listening") {
		t.Fatalf("want error %q, got %v", "ward exited before dns: listening", err)
	}
	if !strings.Contains(err.Error(), "port already in use at "+heldAddr) {
		t.Errorf("log missing %q:\n%v", "port already in use at "+heldAddr, err)
	}
	if w.exitCode != 1 {
		t.Errorf("exit code = %d, want 1 (startup error)", w.exitCode)
	}
	se, serr := w.waitFor("startup error")
	if serr != nil {
		t.Fatalf("no startup error line: %v", serr)
	}
	rem, _ := se["remediation"].(string)
	if !strings.Contains(rem, "--listen-addr") || strings.Contains(rem, "ward.yaml") {
		t.Errorf("remediation must name --listen-addr, not ward.yaml; got %q", rem)
	}
	if n := queries.Load(); n != 0 {
		t.Errorf("squatter received %d queries; startup must never query it", n)
	}
}

func TestServe_ListenAddrOverride_Invalid_ExitsCode2(t *testing.T) {
	for _, bad := range []string{"nonsense", "127.0.0.1:70000", "127.0.0.1:+53"} {
		t.Run(bad, func(t *testing.T) {
			w := launchWard(t, deadUpstreamCfg, bad)
			_, err := w.waitFor("dashboard: ready")
			if err == nil || !strings.Contains(err.Error(), "ward exited before dashboard: ready") {
				t.Fatalf("want ward to exit before dashboard: ready, got %v", err)
			}
			if w.exitCode != 2 {
				t.Errorf("exit code = %d, want 2 (config error)\n%v", w.exitCode, err)
			}
			if !strings.Contains(err.Error(), "config error") || !strings.Contains(err.Error(), "host:port") {
				t.Errorf("want a config error whose remediation names host:port:\n%v", err)
			}
		})
	}
}

func TestBindErrRemediation_FromFlag_NamesFlag(t *testing.T) {
	const (
		addr     = "127.0.0.1:53"
		highAddr = "127.0.0.1:5353"
		setcap   = "bind to 127.0.0.1:53 requires CAP_NET_BIND_SERVICE; run `sudo setcap cap_net_bind_service=+ep ./bin/ward` or "
	)
	cases := []struct {
		name     string
		err      error
		addr     string
		wantFlag string
		wantYAML string
	}{
		{
			"in use", errors.New("listen udp: bind: address already in use"), addr,
			"port already in use at 127.0.0.1:53; stop the process using that port or change --listen-addr",
			"port already in use at 127.0.0.1:53; stop the process using that port or change listen in ward.yaml",
		},
		{
			"eacces low port", errors.New("listen udp: bind: permission denied"), addr,
			setcap + "pass --listen-addr with a port >= 1024",
			setcap + "set listen to a port >= 1024 in ward.yaml",
		},
		{
			"eacces high port", errors.New("listen udp: bind: permission denied"), highAddr,
			"bind to 127.0.0.1:5353 was refused; check sandbox or firewall rules, or pass --listen-addr with a different address",
			"bind to 127.0.0.1:5353 was refused; check sandbox or firewall rules, or change listen in ward.yaml",
		},
		{
			"fallback", errors.New("something odd"), addr,
			"check the --listen-addr address and port availability",
			"check listen address and port availability in ward.yaml",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bindErrRemediationFor(c.err, c.addr, true); got != c.wantFlag {
				t.Errorf("flag remediation = %q, want %q", got, c.wantFlag)
			}
			// The ward.yaml source: pinned through the wrapper and directly.
			if got := bindErrRemediation(c.err, c.addr); got != c.wantYAML {
				t.Errorf("bindErrRemediation = %q, want %q", got, c.wantYAML)
			}
			if got := bindErrRemediationFor(c.err, c.addr, false); got != c.wantYAML {
				t.Errorf("bindErrRemediationFor(false) = %q, want %q", got, c.wantYAML)
			}
		})
	}
}

func TestServe_DashboardReady_LogsBoundAddr(t *testing.T) {
	w := startWard(t, deadUpstreamCfg)
	_, port, err := net.SplitHostPort(w.dashAddr)
	if err != nil || port == "0" || port == "" {
		t.Fatalf("dashboard: ready listen %q must be the bound address with a non-zero port (err=%v)", w.dashAddr, err)
	}
	resp, err := http.Get("http://" + w.dashAddr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz on %s: %v\nlog:\n%s", w.dashAddr, err, w.out.String())
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200", resp.StatusCode)
	}
}

// serveMinimalCfg writes a valid ward.yaml (dead-ish upstream, kernel-picked
// DNS port, short shutdown) plus extra YAML and returns its path.
func serveMinimalCfg(t *testing.T, extra string) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "ward.yaml")
	body := fmt.Sprintf("upstreams:\n  - address: \"127.0.0.1:9999\"\n    server_name: \"unused.test\"\nlisten: %q\ntimeouts:\n  shutdown: \"50ms\"\n", freeUDPAddr(t)) + extra
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// TestServe_DataplaneInitFails_DashboardNotListening: when dataplane
// construction fails (or the constructor misbehaves and returns a nil server
// with a nil error), serveRun returns the init-failed error and leaves no
// dashboard listening.
func TestServe_DataplaneInitFails_DashboardNotListening(t *testing.T) {
	cases := []struct {
		name string
		fake func(dataplane.Config) (*dataplane.Server, error)
	}{
		{"error", func(dataplane.Config) (*dataplane.Server, error) { return nil, errors.New("boom") }},
		{"nil server and nil error", func(dataplane.Config) (*dataplane.Server, error) { return nil, nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dashAddr := freeTCPAddr(t)
			cfgPath := serveMinimalCfg(t, "")
			called := false
			err := serveRun(context.Background(), serveOpts{
				configPath:     cfgPath,
				dashListenAddr: dashAddr,
				newDataplane: func(cfg dataplane.Config) (*dataplane.Server, error) {
					called = true
					return c.fake(cfg)
				},
			})
			if !called {
				t.Fatal("fake newDataplane was not called")
			}
			var se *serveError
			if !errors.As(err, &se) || se.Code != 1 || !strings.Contains(se.Message, "dataplane init failed") {
				t.Fatalf("serveRun err = %v; want *serveError code 1 containing %q", err, "dataplane init failed")
			}
			if se.Remediation == "" {
				t.Error("serveError.Remediation is empty; invariant 8 requires one")
			}
			if conn, derr := net.DialTimeout("tcp", dashAddr, 200*time.Millisecond); derr == nil {
				conn.Close()
				t.Fatalf("dashboard still listening on %s after dataplane init failed (leak)", dashAddr)
			}
		})
	}
}

// TestServe_DashboardReadyAfterModelLoaded: the dashboard must not announce
// itself until the model is loaded (and so /healthz can report it).
func TestServe_DashboardReadyAfterModelLoaded(t *testing.T) {
	w := startWard(t, deadUpstreamCfg+"model:\n  builtin: lexical\n")
	if _, err := w.waitFor("policy: model loaded"); err != nil {
		t.Fatal(err)
	}
	log := w.out.String()
	loaded := strings.Index(log, `"msg":"policy: model loaded"`)
	ready := strings.Index(log, `"msg":"dashboard: ready"`)
	if loaded < 0 || ready < 0 {
		t.Fatalf("missing log lines (model loaded at %d, dashboard ready at %d)\nlog:\n%s", loaded, ready, log)
	}
	if loaded > ready {
		t.Errorf("dashboard: ready (offset %d) logged before policy: model loaded (offset %d)\nlog:\n%s", ready, loaded, log)
	}
}

// TestServe_DashboardPortBusy_ReapsModel: a dashboard bind failure still
// reaps the model child (it sees stdin EOF and writes the marker) before
// serveRun returns.
func TestServe_DashboardPortBusy_ReapsModel(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	marker := filepath.Join(t.TempDir(), "reaped")
	extra := fmt.Sprintf("model:\n  command:\n    - /bin/sh\n    - -c\n    - 'cat >/dev/null; : > \"$1\"'\n    - sh\n    - %q\n", marker)
	cfgPath := serveMinimalCfg(t, extra)
	serr := serveRun(context.Background(), serveOpts{configPath: cfgPath, dashListenAddr: l.Addr().String()})
	var se *serveError
	if !errors.As(serr, &se) || se.Code != 1 || !strings.Contains(se.Message, "dashboard listen failed") {
		t.Fatalf("serveRun err = %v; want *serveError code 1 containing %q", serr, "dashboard listen failed")
	}
	if !strings.Contains(se.Remediation, "--dash-listen-addr") {
		t.Errorf("remediation = %q; want it to name --dash-listen-addr", se.Remediation)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("model child was not reaped before serveRun returned: %v", err)
	}
}

// TestServe_Healthz_BuiltinModel_NeverNone pins that with a model configured
// /healthz never reports classifier "none", from the first answer on.
func TestServe_Healthz_BuiltinModel_NeverNone(t *testing.T) {
	dashAddr := freeTCPAddr(t)
	cfgPath := serveMinimalCfg(t, "model:\n  builtin: lexical\n")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveRun(ctx, serveOpts{configPath: cfgPath, dashListenAddr: dashAddr}) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("serveRun did not return within 5s of cancel")
		}
	}()
	poll := func() (string, bool) {
		resp, err := http.Get("http://" + dashAddr + "/healthz")
		if err != nil {
			return "", false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", false
		}
		var body map[string]any
		if json.NewDecoder(resp.Body).Decode(&body) != nil {
			return "", false
		}
		s, _ := body["classifier"].(string)
		return s, true
	}
	first, got := "", false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if first, got = poll(); got {
			break
		}
	}
	if !got {
		t.Fatal("/healthz did not answer 200 within 5s")
	}
	if first != "ok" {
		t.Fatalf("first /healthz classifier = %q; want ok", first)
	}
	for i := 0; i < 20; i++ {
		if c, ok := poll(); ok && c == "none" {
			t.Fatalf("poll %d: /healthz classifier = none with a model configured", i)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
