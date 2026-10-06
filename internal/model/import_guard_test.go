// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// TestInvariant1_NoDecidingPackageImports asserts that internal/model does
// not import internal/policy or internal/dataplane, directly or
// transitively. This is the structural enforcement of invariant 1 ("the
// AI is a classifier, never a decider") at the internal-package boundary
// — the public-API equivalent lives in scripts/dod.sh bullet 12 Part A,
// which greps pkg/model/ for the same forbidden imports.
//
// Uses go list -deps to enumerate the full dependency closure. Requires
// `go` on $PATH; this is true on every developer machine and in the
// pre-push hook (make ci runs `go test` which already needs `go`).
func TestInvariant1_NoDecidingPackageImports(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = "." // run from this package's directory
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list -deps failed: %v\nstderr: %s", err, stderr.String())
	}

	forbidden := []string{
		"protocolward.ai/ward/internal/policy",
		"protocolward.ai/ward/internal/dataplane",
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		pkg := strings.TrimSpace(line)
		for _, bad := range forbidden {
			if pkg == bad {
				t.Errorf("internal/model imports %q (direct or transitive) — invariant 1 violation: the AI is a classifier, never a decider", bad)
			}
		}
	}
}
