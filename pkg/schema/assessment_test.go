// SPDX-License-Identifier: Apache-2.0

package schema_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"protocolward.ai/ward/pkg/schema"
)

func TestAssessment_JSONGolden(t *testing.T) {
	a := schema.Assessment{
		Verdict: schema.VerdictMalicious,
		Score:   0.75,
		Reasons: []schema.Reason{
			{Code: schema.ReasonRareNgrams, Detail: "rare letters", Weight: 0.45},
			{Code: schema.ReasonHighEntropy, Detail: "high entropy", Weight: 0.3},
		},
	}
	got, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal err = %v", err)
	}
	want := `{"verdict":"malicious","score":0.75,"reasons":[{"code":"rare_ngrams","detail":"rare letters","weight":0.45},{"code":"high_entropy","detail":"high entropy","weight":0.3}]}`
	if string(got) != want {
		t.Errorf("Marshal =\n %s\nwant\n %s", got, want)
	}
	var back schema.Assessment
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("Unmarshal err = %v", err)
	}
	if !reflect.DeepEqual(back, a) {
		t.Errorf("round trip = %+v, want %+v", back, a)
	}
}

func TestAssessment_QuietBenignMarshalsNullReasons(t *testing.T) {
	got, err := json.Marshal(schema.Assessment{Verdict: schema.VerdictBenign, Score: 0.1})
	if err != nil {
		t.Fatalf("Marshal err = %v", err)
	}
	if want := `{"verdict":"benign","score":0.1,"reasons":null}`; string(got) != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

func TestAssessment_RejectsUnknownVerdictOnDecode(t *testing.T) {
	var a schema.Assessment
	err := json.Unmarshal([]byte(`{"verdict":"Malicious","score":1,"reasons":null}`), &a)
	if !errors.Is(err, schema.ErrUnknownVerdict) {
		t.Fatalf("Unmarshal err = %v, want ErrUnknownVerdict", err)
	}
}

func TestReasonCodes_AreDistinctSnakeCase(t *testing.T) {
	codes := []string{
		schema.ReasonHighEntropy, schema.ReasonRareNgrams, schema.ReasonDigitHeavy,
		schema.ReasonConsonantRun, schema.ReasonLongLabel,
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate reason code %q", c)
		}
		seen[c] = true
		for _, r := range c {
			if (r < 'a' || r > 'z') && r != '_' {
				t.Errorf("reason code %q is not lower snake_case", c)
			}
		}
	}
}
