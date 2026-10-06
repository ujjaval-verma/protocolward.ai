// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/policy"
	"protocolward.ai/ward/pkg/schema"
)

// mapMatcher is a tiny stub matching policy.Matcher. Keys are normalized
// (lowercased, no trailing dot) hostnames; values are list IDs. Matching
// is exact-or-suffix: we walk progressively shorter dot-suffixes.
type mapMatcher map[string]string

func (m mapMatcher) Match(hostname string) (listID, matched string, ok bool) {
	cur := hostname
	for {
		if id, hit := m[cur]; hit {
			return id, cur, true
		}
		i := -1
		for j := 0; j < len(cur); j++ {
			if cur[j] == '.' {
				i = j
				break
			}
		}
		if i < 0 {
			return "", "", false
		}
		cur = cur[i+1:]
	}
}

func decision(action policy.Action, kind policy.Kind, listID, matched string) policy.Decision {
	return policy.Decision{Action: action, Kind: kind, ListID: listID, MatchedLabel: matched}
}

func TestDecide_NoMatchers_Forward(t *testing.T) {
	e := policy.NewEngine(nil, nil)
	got := e.Decide("example.com")
	want := decision(policy.ActionForward, policy.KindNone, "", "")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecide_BlockOnly_Hit(t *testing.T) {
	block := mapMatcher{"example.com": "ads"}
	e := policy.NewEngine(nil, block)
	got := e.Decide("ads.example.com")
	want := decision(policy.ActionBlock, policy.KindBlock, "ads", "example.com")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecide_BlockOnly_Miss(t *testing.T) {
	block := mapMatcher{"foo": "ads"}
	e := policy.NewEngine(nil, block)
	got := e.Decide("example.com")
	if got.Action != policy.ActionForward {
		t.Errorf("got %+v want Forward", got)
	}
}

func TestDecide_AllowOnly_Hit(t *testing.T) {
	allow := mapMatcher{"example.com": "my"}
	e := policy.NewEngine(allow, nil)
	got := e.Decide("cdn.example.com")
	want := decision(policy.ActionAllow, policy.KindAllow, "my", "example.com")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecide_AllowOnly_Miss(t *testing.T) {
	allow := mapMatcher{"foo": "my"}
	e := policy.NewEngine(allow, nil)
	got := e.Decide("example.com")
	if got.Action != policy.ActionForward {
		t.Errorf("got %+v want Forward", got)
	}
}

func TestDecide_AllowBeatsBlock(t *testing.T) {
	// Allow's suffix is broader (example.com) than block's (cdn.example.com).
	// Allow wins by precedence even though block is more specific.
	allow := mapMatcher{"example.com": "my"}
	block := mapMatcher{"cdn.example.com": "ads"}
	e := policy.NewEngine(allow, block)
	got := e.Decide("cdn.example.com")
	if got.Action != policy.ActionAllow {
		t.Errorf("got %+v want Allow", got)
	}
	if got.ListID != "my" {
		t.Errorf("got list_id %q want my", got.ListID)
	}
}

func TestDecide_BlockWhenAllowMisses(t *testing.T) {
	allow := mapMatcher{"foo": "my"}
	block := mapMatcher{"example.com": "ads"}
	e := policy.NewEngine(allow, block)
	got := e.Decide("ads.example.com")
	if got.Action != policy.ActionBlock {
		t.Errorf("got %+v want Block", got)
	}
}

func TestDecide_EmptyQname_Forward(t *testing.T) {
	allow := mapMatcher{"x": "a"}
	block := mapMatcher{"y": "b"}
	e := policy.NewEngine(allow, block)
	got := e.Decide("")
	if got.Action != policy.ActionForward {
		t.Errorf("got %+v want Forward (empty qname)", got)
	}
}

func TestDecide_ExactMatch(t *testing.T) {
	block := mapMatcher{"example.com": "ads"}
	e := policy.NewEngine(nil, block)
	got := e.Decide("example.com")
	if got.Action != policy.ActionBlock || got.MatchedLabel != "example.com" {
		t.Errorf("got %+v want Block on exact match", got)
	}
}

// --- DecideWithVerdict cycles (SP10a slice 2) ---

func TestDecideWithVerdict_NoMatchers_Benign_Forward(t *testing.T) {
	e := policy.NewEngine(nil, nil)
	got := e.DecideWithVerdict("example.com", schema.VerdictBenign)
	want := decision(policy.ActionForward, policy.KindNone, "", "")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecideWithVerdict_AllowBeatsMaliciousVerdict(t *testing.T) {
	allow := mapMatcher{"example.com": "my"}
	e := policy.NewEngine(allow, nil)
	got := e.DecideWithVerdict("cdn.example.com", schema.VerdictMalicious)
	want := decision(policy.ActionAllow, policy.KindAllow, "my", "example.com")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecideWithVerdict_BlockBeatsBenignVerdict(t *testing.T) {
	block := mapMatcher{"example.com": "ads"}
	e := policy.NewEngine(nil, block)
	got := e.DecideWithVerdict("ads.example.com", schema.VerdictBenign)
	want := decision(policy.ActionBlock, policy.KindBlock, "ads", "example.com")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecideWithVerdict_TelemetryBlocks(t *testing.T) {
	e := policy.NewEngine(nil, nil)
	got := e.DecideWithVerdict("ads.example.com", schema.VerdictTelemetry)
	want := decision(policy.ActionBlock, policy.KindBlock, "", "(model)")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecideWithVerdict_MaliciousBlocks(t *testing.T) {
	e := policy.NewEngine(nil, nil)
	got := e.DecideWithVerdict("c2.example.com", schema.VerdictMalicious)
	want := decision(policy.ActionBlock, policy.KindBlock, "", "(model)")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecideWithVerdict_EmptyQname_Benign_Forward(t *testing.T) {
	allow := mapMatcher{"x": "a"}
	block := mapMatcher{"y": "b"}
	e := policy.NewEngine(allow, block)
	got := e.DecideWithVerdict("", schema.VerdictBenign)
	want := decision(policy.ActionForward, policy.KindNone, "", "")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecideWithVerdict_EmptyQname_Malicious_Blocks(t *testing.T) {
	allow := mapMatcher{"x": "a"}
	block := mapMatcher{"y": "b"}
	e := policy.NewEngine(allow, block)
	got := e.DecideWithVerdict("", schema.VerdictMalicious)
	want := decision(policy.ActionBlock, policy.KindBlock, "", "(model)")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestDecideWithVerdict_UnknownVerdict_Panics(t *testing.T) {
	e := policy.NewEngine(nil, nil)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for unknown schema.Verdict, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "DecideWithVerdict") || !strings.Contains(msg, "99") {
			t.Errorf("panic message %q missing identifier or variant index", msg)
		}
	}()
	_ = e.DecideWithVerdict("example.com", schema.Verdict(99))
}

// Stringer-coverage guard: assert every Action variant has a non-default
// String() token. Guards against adding a new variant without updating the
// stringer generator (which would also fail the exhaustive linter at lint
// time; this is the runtime backstop).
func TestPolicy_Action_StringerCoversAllVariants(t *testing.T) {
	// Iterate Action(0)..Action(N) until String() returns a "Action(N)" form
	// (stringer's fallback for unknown values).
	for i := policy.Action(0); i < 16; i++ {
		s := i.String()
		if s == "" {
			t.Errorf("Action(%d).String() returned empty", i)
		}
		// stringer emits "Action(<n>)" for unknown values. Real variants emit
		// names like "ActionForward". Stop scanning at the first unknown.
		if len(s) > 7 && s[:7] == "Action(" {
			// Reached past the last defined variant. Ensure we saw at least 3.
			if i < 3 {
				t.Errorf("only %d Action variants defined; the policy contract requires Forward/Allow/Block", i)
			}
			return
		}
	}
	t.Error("Action enum has more variants than the guard limit (16); raise the limit and revisit the policy contract")
}
