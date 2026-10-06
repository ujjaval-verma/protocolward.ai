// SPDX-License-Identifier: Apache-2.0

package demo_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"protocolward.ai/ward/cmd/wardwasm/internal/demo"
	"protocolward.ai/ward/internal/decoy"
	"protocolward.ai/ward/internal/hostlist"
)

// fixture mirrors the S5b decoys demo: plausible internal decoys, plus a
// name that is simultaneously a decoy, allowlisted and blocklisted.
var fixture = demo.Config{
	Decoys:    []string{"nas-backup.home.arpa", "printer-admin.lan", "both.example.net"},
	Blocklist: []string{"ads.example.com", "tracker.test", "both.example.net"},
	Allowlist: []string{"cdn.ads.example.com", "both.example.net"},
}

func mustInit(t *testing.T, c demo.Config) *demo.Demo {
	t.Helper()
	d := demo.New()
	if err := d.Init(c); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return d
}

// assertJSValueOfSafe fails if v contains a type js.ValueOf would panic on.
// syscall/js cannot run natively, so this is how the bridge's input
// contract is tested.
func assertJSValueOfSafe(t *testing.T, path string, v any) {
	t.Helper()
	switch x := v.(type) {
	case nil, bool, string, float64, int:
	case []any:
		for i, e := range x {
			assertJSValueOfSafe(t, fmt.Sprintf("%s[%d]", path, i), e)
		}
	case map[string]any:
		for k, e := range x {
			assertJSValueOfSafe(t, path+"."+k, e)
		}
	default:
		t.Errorf("%s: type %T would make js.ValueOf panic", path, v)
	}
}

func TestDecide_PrecedenceMirrorsDataplane(t *testing.T) {
	d := mustInit(t, fixture)
	block := func(src, m string, alert bool) demo.Decision {
		return demo.Decision{Action: demo.ActionBlock, Source: src, Matched: m, Alert: alert}
	}
	rows := []struct {
		name, q string
		want    demo.Decision
	}{
		{"decoy_exact", "nas-backup.home.arpa", block(demo.SourceDecoy, "nas-backup.home.arpa", true)},
		{"decoy_mixed_case_trailing_dot", "NAS-Backup.Home.Arpa.", block(demo.SourceDecoy, "nas-backup.home.arpa", true)},
		{"decoy_surrounding_spaces", "  printer-admin.lan  ", block(demo.SourceDecoy, "printer-admin.lan", true)},
		{"decoy_beats_allowlist_and_blocklist", "both.example.net", block(demo.SourceDecoy, "both.example.net", true)},
		{"decoy_subdomain_is_not_a_decoy", "scanner.nas-backup.home.arpa", demo.Decision{Action: demo.ActionForward, Source: demo.SourceForward}},
		{"blocklist_exact", "ads.example.com", block(demo.SourceBlocklist, "ads.example.com", false)},
		{"blocklist_suffix", "x.ads.example.com", block(demo.SourceBlocklist, "ads.example.com", false)},
		{"allowlist_beats_blocklist", "cdn.ads.example.com", demo.Decision{Action: demo.ActionForward, Source: demo.SourceAllowlist, Matched: "cdn.ads.example.com"}},
		{"unlisted_forwards", "github.com", demo.Decision{Action: demo.ActionForward, Source: demo.SourceForward}},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			got, err := d.Decide(tc.q)
			if err != nil {
				t.Fatalf("Decide(%q): %v", tc.q, err)
			}
			if got != tc.want {
				t.Errorf("Decide(%q) = %+v; want %+v", tc.q, got, tc.want)
			}
		})
	}
}

func TestDecide_OnlyDecoysAlert(t *testing.T) {
	d := mustInit(t, fixture)
	for _, q := range []string{"ads.example.com", "cdn.ads.example.com", "github.com"} {
		got, err := d.Decide(q)
		if err != nil {
			t.Fatalf("Decide(%q): %v", q, err)
		}
		if got.Alert {
			t.Errorf("Decide(%q).Alert = true; only decoy hits alert", q)
		}
	}
}

func TestDecide_BeforeInitForwards(t *testing.T) {
	got, err := demo.New().Decide("ads.example.com")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	want := demo.Decision{Action: demo.ActionForward, Source: demo.SourceForward}
	if got != want {
		t.Errorf("Decide before Init = %+v; want %+v", got, want)
	}
}

func TestDecide_RejectsInvalidHostnames(t *testing.T) {
	d := mustInit(t, fixture)
	rows := []string{
		"", "   ", ".", "a..b.com", "-bad.com", "bad-.com", "bad host.com", "exämple.com",
		strings.Repeat("a", 64) + ".com",      // label > 63
		strings.Repeat("abcdefghi.", 26),      // 259 chars after trailing-dot strip > 253
		strings.Repeat("x", demo.MaxInputLen), // oversized single label
	}
	for _, q := range rows {
		if _, err := d.Decide(q); !errors.Is(err, demo.ErrInvalidHostname) {
			t.Errorf("Decide(%.40q) err = %v; want ErrInvalidHostname", q, err)
		}
	}
}

func TestInit_ReplacesPreviousState(t *testing.T) {
	d := mustInit(t, fixture)
	if err := d.Init(demo.Config{Blocklist: []string{"other.test"}}); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	for q, want := range map[string]string{
		"ads.example.com":      demo.SourceForward,
		"nas-backup.home.arpa": demo.SourceForward,
		"other.test":           demo.SourceBlocklist,
	} {
		got, err := d.Decide(q)
		if err != nil {
			t.Fatalf("Decide(%q): %v", q, err)
		}
		if got.Source != want {
			t.Errorf("after re-Init Decide(%q).Source = %q; want %q", q, got.Source, want)
		}
	}
}

func TestInit_FailureKeepsPreviousState(t *testing.T) {
	d := mustInit(t, fixture)
	err := d.Init(demo.Config{
		Decoys:    []string{"fresh-decoy.lan"},
		Blocklist: []string{"0.0.0.0 bad.example.com"},
	})
	var iee *hostlist.InvalidEntryError
	if !errors.As(err, &iee) || !strings.Contains(err.Error(), "blocklist") {
		t.Fatalf("Init err = %v; want *hostlist.InvalidEntryError naming the blocklist", err)
	}
	if got, _ := d.Decide("nas-backup.home.arpa"); got.Source != demo.SourceDecoy {
		t.Errorf("old decoy lost after failed Init: %+v", got)
	}
	if got, _ := d.Decide("fresh-decoy.lan"); got.Source != demo.SourceForward {
		t.Errorf("failed Init half-applied its decoys: %+v", got)
	}
}

func TestInit_RejectsBadDecoyEntry(t *testing.T) {
	err := demo.New().Init(demo.Config{Decoys: []string{"two words"}})
	var iee *decoy.InvalidEntryError
	if !errors.As(err, &iee) || !strings.Contains(err.Error(), "decoys") {
		t.Fatalf("Init err = %v; want *decoy.InvalidEntryError naming decoys", err)
	}
}

func TestInit_RejectsOversizedInput(t *testing.T) {
	many := make([]string, demo.MaxEntriesPerList+1)
	for i := range many {
		many[i] = fmt.Sprintf("h%d.test", i)
	}
	if err := demo.New().Init(demo.Config{Allowlist: many}); !errors.Is(err, demo.ErrTooManyEntries) {
		t.Errorf("Init(%d allowlist entries) err = %v; want ErrTooManyEntries", len(many), err)
	}
	long := strings.Repeat("a", demo.MaxInputLen+1)
	if err := demo.New().Init(demo.Config{Decoys: []string{long}}); !errors.Is(err, demo.ErrEntryTooLong) {
		t.Errorf("Init(long decoy) err = %v; want ErrEntryTooLong", err)
	}
}

func TestDecision_MapMatchesJSSurface(t *testing.T) {
	m := demo.Decision{Action: demo.ActionBlock, Source: demo.SourceDecoy, Matched: "nas-backup.home.arpa", Alert: true}.Map()
	want := map[string]any{"action": "block", "source": "decoy", "matched": "nas-backup.home.arpa", "alert": true}
	if len(m) != len(want) {
		t.Fatalf("Map keys = %v; want exactly %v", m, want)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("Map[%q] = %v; want %v", k, m[k], v)
		}
	}
	assertJSValueOfSafe(t, "decision", m)
}

func TestErrorMessage(t *testing.T) {
	if got := demo.ErrorMessage(fmt.Errorf("wrapped: %w", demo.ErrInvalidHostname)); got != "not a valid hostname" {
		t.Errorf("ErrorMessage(invalid) = %q; want \"not a valid hostname\"", got)
	}
	if got := demo.ErrorMessage(errors.New("init: boom")); got != "init: boom" {
		t.Errorf("ErrorMessage(other) = %q; want passthrough", got)
	}
}

// A decoy that Decide's hostname gate would reject can never trip, so Init
// must refuse it (and keep the previous config).
func TestInit_RejectsUnmatchableDecoys(t *testing.T) {
	d := demo.New()
	if err := d.Init(demo.Config{Decoys: []string{"keep.lan"}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"exämple.lan", "nas!.lan", "-x.lan", strings.Repeat("a", 64) + ".lan", "a b.lan", "a\vb.lan", "a\x00b.lan"} {
		if err := d.Init(demo.Config{Decoys: []string{bad}}); err == nil {
			t.Errorf("Init(decoy %q) = nil; want error", bad)
		}
	}
	dec, err := d.Decide("keep.lan")
	if err != nil || dec.Source != demo.SourceDecoy || !dec.Alert {
		t.Errorf("previous config not kept after failed Init: %+v, %v", dec, err)
	}
}

func TestCheckListLen(t *testing.T) {
	if err := demo.CheckListLen("decoys", demo.MaxEntriesPerList); err != nil {
		t.Errorf("at limit: %v", err)
	}
	if err := demo.CheckListLen("decoys", demo.MaxEntriesPerList+1); !errors.Is(err, demo.ErrTooManyEntries) {
		t.Errorf("over limit: %v", err)
	}
}
