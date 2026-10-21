// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/config"
)

func TestLoad_StrictDecode_AcceptTable(t *testing.T) {
	cases := []struct {
		name      string
		yaml      string
		wantField string // non-empty: expect ValidationError on this field
	}{
		{"empty", "", "listen"},
		{"whitespace_only", "\n\n  \n", "listen"},
		{"comments_only", "# nothing here\n# still nothing\n", "listen"},
		{"null_document", "~\n", "listen"},
		{"bare_doc_marker", "---\n", "listen"},
		{"leading_doc_marker", "---\n" + baseYAML(), ""},
		{"trailing_doc_end", baseYAML() + "...\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadYAMLString(t, tc.yaml)
			if tc.wantField != "" {
				assertValidationField(t, err, tc.wantField)
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Listen != "127.0.0.1:5354" {
				t.Errorf("Listen = %q", cfg.Listen)
			}
		})
	}
}

func TestLoad_ShippedConfigsLoad(t *testing.T) {
	t.Run("ward.example.yaml", func(t *testing.T) {
		if _, err := config.Load(filepath.Join("..", "..", "ward.example.yaml")); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
	found := 0
	root := filepath.Join("..", "..", "testdata")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !(strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			return nil
		}
		found++
		t.Run(p, func(t *testing.T) {
			if _, err := config.Load(p); err != nil {
				t.Fatalf("Load: %v", err)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if found == 0 {
		t.Fatal("no YAML files found under testdata/")
	}
}

func TestUnknownKeyError_Message(t *testing.T) {
	top := config.UnknownKey{Line: 2, Key: "bogus", Section: "", Valid: []string{"listen", "log_level"}}
	nested := config.UnknownKey{Line: 5, Key: "servername", Section: "upstreams[]", Valid: []string{"address", "server_name", "ca_bundle"}}
	const topS = `line 2: unknown key "bogus" at top level (valid keys: listen, log_level)`
	const nestedS = `line 5: unknown key "servername" under upstreams[] (valid keys: address, server_name, ca_bundle)`
	const suffix = ` — remediation: fix the spelling or remove the key`
	const prefix = `config error in /p/ward.yaml: `

	exact := []struct {
		name string
		keys []config.UnknownKey
		want string
	}{
		{"top_level", []config.UnknownKey{top}, prefix + topS + suffix},
		{"nested", []config.UnknownKey{nested}, prefix + nestedS + suffix},
		{"two_keys", []config.UnknownKey{top, nested}, prefix + topS + "; " + nestedS + suffix},
	}
	for _, tc := range exact {
		t.Run(tc.name, func(t *testing.T) {
			e := &config.UnknownKeyError{Path: "/p/ward.yaml", Keys: tc.keys}
			if got := e.Error(); got != tc.want {
				t.Errorf("Error() =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}

	t.Run("long_key_truncated", func(t *testing.T) {
		e := &config.UnknownKeyError{Path: "/p", Keys: []config.UnknownKey{{Line: 1, Key: strings.Repeat("a", 100)}}}
		got := e.Error()
		if !strings.Contains(got, `"`+strings.Repeat("a", 64)+`…"`) {
			t.Errorf("missing truncated key: %s", got)
		}
		if strings.Contains(got, strings.Repeat("a", 65)) {
			t.Errorf("key not truncated: %s", got)
		}
	})
	t.Run("key_escaped", func(t *testing.T) {
		e := &config.UnknownKeyError{Path: "/p", Keys: []config.UnknownKey{{Line: 1, Key: "a\"b\nc"}}}
		got := e.Error()
		if !strings.Contains(got, `"a\"b\nc"`) {
			t.Errorf("missing escaped key: %s", got)
		}
		if strings.Contains(got, "\n") {
			t.Errorf("raw newline in message: %q", got)
		}
	})
}

func TestUnknownKey_String(t *testing.T) {
	k := config.UnknownKey{Line: 7, Key: "query_timeout", Section: "timeouts", Valid: []string{"dial", "query", "shutdown"}}
	want := `line 7: unknown key "query_timeout" under timeouts (valid keys: dial, query, shutdown)`
	if got := k.String(); got != want {
		t.Errorf("String() = %q want %q", got, want)
	}
}

var validBySection = map[string][]string{
	"":                                   {"listen", "log_level", "upstreams", "blocklists", "allowlists", "decoys", "block_response", "timeouts", "model"},
	"upstreams[]":                        {"address", "server_name", "ca_bundle"},
	"blocklists[]/allowlists[]/decoys[]": {"id", "path"},
	"timeouts":                           {"dial", "query", "shutdown"},
	"block_response":                     {"mode", "a", "aaaa"},
	"model":                              {"command", "env", "builtin"},
}

const (
	secLists = "blocklists[]/allowlists[]/decoys[]"
	hdr3     = "listen: \"127.0.0.1:5354\"\nupstreams:\n  - address: \"9.9.9.9:853\"\n    server_name: \"dns.quad9.net\"\n"
)

func TestLoad_UnknownKey_RejectTable(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		key     string
		line    int
		section string
	}{
		{"top_level_bogus", baseYAML() + "bogus_typo_field: 1\n", "bogus_typo_field", 10, ""},
		{"top_level_blocklist_singular", baseYAML() + "blocklist:\n  - id: a\n    path: b.txt\n", "blocklist", 10, ""},
		{"top_level_wrong_case", baseYAML() + "Log_Level: debug\n", "Log_Level", 10, ""},
		{"top_level_reserved_sink", baseYAML() + "sink:\n  mode: x\n", "sink", 10, ""},
		{"upstreams_entry", hdr3 + "    servername: \"x\"\n", "servername", 5, "upstreams[]"},
		{"upstreams_entry_dash_field", hdr3 + "    rootcas: \"x\"\n", "rootcas", 5, "upstreams[]"},
		{"blocklists_entry", baseYAML() + "blocklists:\n  - id: a\n    file: b.txt\n", "file", 12, secLists},
		{"allowlists_entry", baseYAML() + "allowlists:\n  - id: a\n    file: b.txt\n", "file", 12, secLists},
		{"decoys_entry", baseYAML() + "decoys:\n  - id: a\n    file: b.txt\n", "file", 12, secLists},
		{"timeouts_block", hdr3 + "timeouts:\n  dail: \"3s\"\n", "dail", 6, "timeouts"},
		{"timeouts_flow_map", hdr3 + "timeouts: {dial: \"3s\", query_timeout: \"2s\"}\n", "query_timeout", 5, "timeouts"},
		{"block_response", baseYAML() + "block_response:\n  mode: address\n  address: \"0.0.0.0\"\n", "address", 12, "block_response"},
		{"model", baseYAML() + "model:\n  built_in: lexical\n", "built_in", 11, "model"},
		{"empty_key", baseYAML() + "\"\": 1\n", "", 10, ""},
		{"null_key_top", baseYAML() + "null: 1\n", "null", 10, ""},
		{"null_key_capitalised_subtree", baseYAML() + "Null:\n  blocklists:\n    - {id: a, path: b}\n", "Null", 10, ""},
		{"null_key_tilde", baseYAML() + "~: 1\n", "~", 10, ""},
		{"null_key_nested_flow", hdr3 + "timeouts: {~: 3s}\n", "~", 5, "timeouts"},
		{"null_key_in_upstream", hdr3 + "    null: x\n", "null", 5, "upstreams[]"},
		{"null_key_in_merge_section", hdr3 + "timeouts:\n  <<: {~: 3s}\n", "~", 6, "timeouts"},
		{"null_key_in_merge_top", baseYAML() + "<<: {null: {blocklists: [{id: a, path: b}]}}\n", "null", 10, ""},
		{"null_key_in_merge_seq", baseYAML() + "<<: [{~: 1}]\n", "~", 10, ""},
		{"key_with_newline", baseYAML() + "\"a\\nb\": 1\n", "a\nb", 10, ""},
		{"anchor_reused_merge", "listen: \"127.0.0.1:5354\"\nupstreams:\n  - &u {address: \"9.9.9.9:853\", server_name: \"dns.quad9.net\", servername: \"x\"}\n  - <<: *u\n", "servername", 3, "upstreams[]"},
		{"anchor_reused_alias", "listen: \"127.0.0.1:5354\"\nupstreams:\n  - &u {address: \"9.9.9.9:853\", server_name: \"dns.quad9.net\", servername: \"x\"}\n  - *u\n", "servername", 3, "upstreams[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "ward.yaml")
			if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := config.Load(p)
			var uke *config.UnknownKeyError
			if !errors.As(err, &uke) {
				t.Fatalf("err = %v; want *UnknownKeyError", err)
			}
			if uke.Path != p {
				t.Errorf("Path = %q want %q", uke.Path, p)
			}
			if len(uke.Keys) != 1 {
				t.Fatalf("len(Keys) = %d want 1: %+v", len(uke.Keys), uke.Keys)
			}
			k := uke.Keys[0]
			if k.Key != tc.key || k.Line != tc.line || k.Section != tc.section {
				t.Errorf("got {%d %q %q} want {%d %q %q}", k.Line, k.Key, k.Section, tc.line, tc.key, tc.section)
			}
			if !reflect.DeepEqual(k.Valid, validBySection[tc.section]) {
				t.Errorf("Valid = %v want %v", k.Valid, validBySection[tc.section])
			}
			if want := fmt.Sprintf("line %d: unknown key %q", tc.line, tc.key); !strings.Contains(err.Error(), want) {
				t.Errorf("Error() = %q; want substring %q", err.Error(), want)
			}
		})
	}
}

func TestLoad_UnknownKey_ReportsAllInDocumentOrder(t *testing.T) {
	y := "bogus_top: 1\nlisten: \"127.0.0.1:5354\"\nupstreams:\n  - address: \"9.9.9.9:853\"\n    server_name: \"dns.quad9.net\"\n    servername: \"x\"\ntimeouts: {dial: \"3s\", query_timeout: \"2s\"}\n"
	_, err := loadYAMLString(t, y)
	var uke *config.UnknownKeyError
	if !errors.As(err, &uke) {
		t.Fatalf("err = %v; want *UnknownKeyError", err)
	}
	type lks struct {
		Line         int
		Key, Section string
	}
	got := make([]lks, 0, len(uke.Keys))
	for _, k := range uke.Keys {
		got = append(got, lks{k.Line, k.Key, k.Section})
	}
	want := []lks{{1, "bogus_top", ""}, {6, "servername", "upstreams[]"}, {7, "query_timeout", "timeouts"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Keys = %v want %v", got, want)
	}
	if n := strings.Count(err.Error(), "; "); n != 2 {
		t.Errorf(`"; " count = %d want 2 in %q`, n, err.Error())
	}
}

func TestLoad_UnknownKey_IssueRepro(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "ward.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	orig := string(b)
	if !strings.HasSuffix(orig, "\n") {
		orig += "\n"
	}
	p := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(p, []byte(orig+"bogus_typo_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = config.Load(p)
	var uke *config.UnknownKeyError
	if !errors.As(err, &uke) {
		t.Fatalf("err = %v; want *UnknownKeyError", err)
	}
	k := uke.Keys[0]
	if k.Line != strings.Count(orig, "\n")+1 || k.Key != "bogus_typo_field" || k.Section != "" {
		t.Errorf("Keys[0] = %+v", k)
	}
}

func TestLoad_DecodeErrors_StayParseError(t *testing.T) {
	cases := []struct {
		name, yaml string
		contains   []string
	}{
		{"mixed_type_and_unknown", "listen: [1]\nbogus: 1\n", []string{"bogus", "line 2"}},
		{"type_mismatch_only", "listen: [1]\n", []string{"line 1"}},
		{"duplicate_key", baseYAML() + "listen: \"127.0.0.1:1\"\n", []string{"already defined"}},
		{"syntax_error", "this is: not [valid yaml: at all\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAMLString(t, tc.yaml)
			var pe *config.ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v; want *ParseError", err)
			}
			var uke *config.UnknownKeyError
			if errors.As(err, &uke) {
				t.Errorf("unexpected *UnknownKeyError: %v", err)
			}
			for _, s := range tc.contains {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("Error() = %q; want substring %q", err.Error(), s)
				}
			}
		})
	}
}

func TestLoad_MultipleDocuments(t *testing.T) {
	cases := []struct {
		name        string
		yaml        string
		reject      bool
		multiDoc    bool // errors.Is ErrMultipleDocuments
		wantContain string
	}{
		{"trailing_empty_doc", baseYAML() + "---\n", false, false, ""},
		{"trailing_comment_doc", baseYAML() + "---\n# trailing comment\n", false, false, ""},
		{"trailing_null_doc", baseYAML() + "--- ~\n", false, false, ""},
		{"second_doc_with_content", baseYAML() + "---\nlisten: \"127.0.0.1:1\"\n", true, true, "another document starts at line 10"},
		{"null_first_then_content", "---\n---\n" + baseYAML(), true, true, "line 2"},
		{"syntax_error_in_second_doc", baseYAML() + "---\n: : [\n", true, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAMLString(t, tc.yaml)
			if !tc.reject {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			var pe *config.ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v; want *ParseError", err)
			}
			if got := errors.Is(err, config.ErrMultipleDocuments); got != tc.multiDoc {
				t.Errorf("Is(ErrMultipleDocuments) = %v want %v (%v)", got, tc.multiDoc, err)
			}
			if tc.wantContain != "" && !strings.Contains(err.Error(), tc.wantContain) {
				t.Errorf("Error() = %q; want substring %q", err.Error(), tc.wantContain)
			}
		})
	}
}
