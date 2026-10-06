// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"path/filepath"
	"testing"
)

// fixtureDir resolves <repo-root>/testdata/update/v0.1-<variant>.
func fixtureDir(tb testing.TB, variantName string) string {
	tb.Helper()
	return filepath.Join(fixtureRoot(tb), "v0.1-"+variantName)
}

// TestVerify_Good is the tracer bullet: exercises the entire two-layer
// trust chain end-to-end against the canonical good fixture.
func TestVerify_Good(t *testing.T) {
	got, err := Verify(fixtureDir(t, "good"), "")
	if err != nil {
		t.Fatalf("Verify(good) error: %v", err)
	}
	if got == nil {
		t.Fatal("Verify(good) returned nil VerifiedTargets without error")
	}
	if got.RootVersion != 1 {
		t.Errorf("RootVersion = %d, want 1", got.RootVersion)
	}
	if got.TargetsVersion != 1 {
		t.Errorf("TargetsVersion = %d, want 1", got.TargetsVersion)
	}
	if _, ok := got.Targets["feed.json"]; !ok {
		t.Errorf("Targets missing feed.json; got keys: %v", keys(got.Targets))
	}
	if got.Expires.IsZero() {
		t.Errorf("Expires is zero")
	}
}

// TestVerify_FailureModes — one row per public sentinel, one fixture
// per row. Closes the spec-review B2/B4 coverage gap.
func TestVerify_FailureModes(t *testing.T) {
	cases := []struct {
		variant string
		want    error
	}{
		{"missing-trust-root", ErrFixtureLayout},
		{"bad-cosign", ErrCosignBundle},
		{"bad-root-sig", ErrTUFRoot},
		{"expired", ErrTUFTargets},
		{"tampered-target", ErrTargetHash},
	}
	for _, tc := range cases {
		t.Run(tc.variant, func(t *testing.T) {
			got, err := Verify(fixtureDir(t, tc.variant), "")
			if err == nil {
				t.Fatalf("Verify(%s) returned no error; got %+v", tc.variant, got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("Verify(%s) error = %v; want errors.Is(...%v)", tc.variant, err, tc.want)
			}
		})
	}
}

// TestVerify_TrustRootOverride verifies that passing an explicit
// trustRootPath bypasses the fixture-dir default. Cross-using the
// good fixture's trust root against the bad-cosign fixture still
// fails (the signature itself is wrong) — the override is wired but
// the chain still breaks at the cosign layer.
func TestVerify_TrustRootOverride(t *testing.T) {
	goodTrustRoot := filepath.Join(fixtureDir(t, "good"), "cosign-trust-root.pem")
	// Good fixture + explicit trust root pointing at its own file: same as default.
	if _, err := Verify(fixtureDir(t, "good"), goodTrustRoot); err != nil {
		t.Fatalf("Verify(good, explicit trustRoot) error: %v", err)
	}
	// Missing-trust-root variant + explicit override: should now succeed
	// (the missing file in the fixture dir is irrelevant when we point
	// elsewhere). This is the operator escape-hatch the spec named.
	if _, err := Verify(fixtureDir(t, "missing-trust-root"), goodTrustRoot); err != nil {
		t.Fatalf("Verify(missing-trust-root, explicit trustRoot) error: %v", err)
	}
}

func keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
