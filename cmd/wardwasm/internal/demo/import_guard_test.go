// SPDX-License-Identifier: Apache-2.0

package demo_test

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWasmClosure_NoNetworkNoConfigLoader enumerates this package's
// dependency closure as the browser build sees it (GOOS=js GOARCH=wasm)
// and fails on anything that could make a network call (invariant 4),
// spawn a process, or blow the 5 MB ward.wasm budget (internal/config and
// crypto/x509 add about 1.8 MB, measured when the demo was built). Matching
// is by suffix so the S4 module-path rewrite does not break it.
func TestWasmClosure_NoNetworkNoConfigLoader(t *testing.T) {
	// "." is this package; "../.." is the cmd/wardwasm main package (the
	// js/wasm-only bridge), which is what actually ships in ward.wasm.
	var stdout bytes.Buffer
	for _, target := range []string{".", "../.."} {
		cmd := exec.Command("go", "list", "-deps", target)
		cmd.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("go list -deps %s failed: %v\nstderr: %s", target, err, stderr.String())
		}
		// Self-check: an empty or truncated listing would pass every
		// absence assertion below vacuously.
		if !strings.Contains(out.String(), "internal/policy") {
			t.Fatalf("go list -deps %s did not list internal/policy; output:\n%s", target, out.String())
		}
		stdout.Write(out.Bytes())
	}
	exact := map[string]string{
		"net":         "invariant 4: demos make zero network calls",
		"net/http":    "invariant 4: demos make zero network calls",
		"crypto/tls":  "invariant 4: demos make zero network calls",
		"os/exec":     "no subprocesses in the browser",
		"crypto/x509": "size budget: crypto/x509 adds ~1.1 MB to ward.wasm",
	}
	suffix := map[string]string{
		"/internal/config":    "size budget: import internal/configexport instead",
		"/internal/dataplane": "the demo decides; it never serves DNS",
		"/internal/upstream":  "invariant 4: demos make zero network calls",
		"/internal/model":     "the sibling-process adapter cannot run in a browser",
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		pkg := strings.TrimSpace(line)
		if why, bad := exact[pkg]; bad {
			t.Errorf("wasm closure imports %q — %s", pkg, why)
		}
		for sfx, why := range suffix {
			if strings.HasSuffix(pkg, sfx) {
				t.Errorf("wasm closure imports %q — %s", pkg, why)
			}
		}
	}
}
