// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandPrintsVersion(t *testing.T) {
	var buf bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "ward") {
		t.Errorf("version output missing 'ward': %q", got)
	}
	if !strings.Contains(got, "dev") {
		t.Errorf("version output missing 'dev' (default version): %q", got)
	}
}
