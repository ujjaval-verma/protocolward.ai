// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/update"
)

// repoFixtureDir resolves <repo-root>/testdata/update/v0.1-<variant>.
// cmd/ward/update_test.go -> ../../testdata/update.
func repoFixtureDir(tb testing.TB, variant string) string {
	tb.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller(0) failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "update", "v0.1-"+variant)
}

func TestUpdateVerifyRun_Good(t *testing.T) {
	var out bytes.Buffer
	err := updateVerifyRun(&out, []string{repoFixtureDir(t, "good")}, updateVerifyOpts{})
	if err != nil {
		t.Fatalf("updateVerifyRun(good) = %v; want nil", err)
	}
	got := out.String()
	if !strings.HasPrefix(got, "OK — verified ") {
		t.Errorf("output missing OK prefix; got %q", got)
	}
	if !strings.Contains(got, "root v1") || !strings.Contains(got, "targets v1") || !strings.Contains(got, "2050") {
		t.Errorf("output missing version detail; got %q", got)
	}
}

func TestUpdateVerifyRun_BadCosign(t *testing.T) {
	var out bytes.Buffer
	err := updateVerifyRun(&out, []string{repoFixtureDir(t, "bad-cosign")}, updateVerifyOpts{})
	if err == nil {
		t.Fatal("updateVerifyRun(bad-cosign) returned nil; want non-nil")
	}
	var se *serveError
	if !errors.As(err, &se) {
		t.Fatalf("err is not *serveError: %v", err)
	}
	if se.Code != 1 {
		t.Errorf("Code = %d; want 1", se.Code)
	}
	if !strings.Contains(se.Remediation, "cosign") {
		t.Errorf("remediation should mention cosign; got %q", se.Remediation)
	}
}

func TestUpdateVerifyRun_BadUsage(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"two args", []string{"a", "b"}},
		{"nonexistent dir", []string{"/path/that/does/not/exist/ward-update-verify-test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := updateVerifyRun(&out, tc.args, updateVerifyOpts{})
			if err == nil {
				t.Fatal("expected error")
			}
			var se *serveError
			if !errors.As(err, &se) {
				t.Fatalf("not *serveError: %v", err)
			}
			if se.Code != 2 {
				t.Errorf("Code = %d; want 2", se.Code)
			}
		})
	}
}

func TestUpdateRemediation_KnownSentinels(t *testing.T) {
	cases := []struct {
		sentinel error
		want     string // substring
	}{
		{update.ErrFixtureLayout, "layout"},
		{update.ErrCosignBundle, "cosign"},
		{update.ErrTUFRoot, "root"},
		{update.ErrTUFTargets, "targets"},
		{update.ErrTargetHash, "sha256"},
	}
	for _, tc := range cases {
		t.Run(tc.sentinel.Error(), func(t *testing.T) {
			got := updateRemediation(tc.sentinel)
			if !strings.Contains(got, tc.want) {
				t.Errorf("remediation for %v: got %q; want substring %q", tc.sentinel, got, tc.want)
			}
		})
	}
}
