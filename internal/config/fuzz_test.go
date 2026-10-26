// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"protocolward.ai/ward/internal/config"
)

// hasCABundle reports whether Load might open a file named by the input.
// Load reads upstreams[*].ca_bundle with os.ReadFile and the fuzzer controls
// that path (a device or FIFO could block), so such inputs are never fuzzed.
// The decision uses the decoded value, not the raw bytes, because YAML escapes
// and folding hide the key and the path. skip is true when the input must not
// reach Load.
//
// A YAML syntax error is rejected by Load before any file I/O, so it is not
// skipped. When the probe fails only on a type or aliasing error, the input is
// skipped only if the parsed upstreams value contains a ca_bundle key at any
// depth; otherwise Load rejects the type error in its first Decode, before any
// file I/O, and the input runs.
//
// A panic inside this function comes from yaml.v3 parsing the same bytes that
// Load would parse, so Load would hit it too: report it as a panic reachable
// through Load, not as a bug in the harness.
func hasCABundle(data []byte) (skip bool) {
	var probe struct {
		Upstreams []struct {
			CABundle string `yaml:"ca_bundle"`
		} `yaml:"upstreams"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		var doc yaml.Node
		if yaml.Unmarshal(data, &doc) != nil {
			return false // syntax error: Load fails before any file I/O
		}
		if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
			return false
		}
		seen := map[*yaml.Node]bool{}
		for _, up := range upstreamsNodes(doc.Content[0], seen) {
			if containsKey(up, "ca_bundle", seen) {
				return true
			}
		}
		return false
	}
	for _, u := range probe.Upstreams {
		if u.CABundle != "" {
			return true
		}
	}
	return false
}

// upstreamsNodes returns the value nodes of the "upstreams" key of a root
// mapping, including keys pulled in through YAML merge keys ("<<").
func upstreamsNodes(n *yaml.Node, seen map[*yaml.Node]bool) []*yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	if n.Kind != yaml.MappingNode || seen[n] {
		return nil
	}
	seen[n] = true
	defer delete(seen, n)
	var out []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch {
		case k.Value == "upstreams":
			out = append(out, v)
		case k.Value == "<<":
			if v.Kind == yaml.SequenceNode {
				for _, m := range v.Content {
					out = append(out, upstreamsNodes(m, seen)...)
				}
			} else {
				out = append(out, upstreamsNodes(v, seen)...)
			}
		}
	}
	return out
}

// containsKey reports whether any mapping under n, at any depth and through
// aliases, has the given scalar key.
func containsKey(n *yaml.Node, key string, seen map[*yaml.Node]bool) bool {
	if n == nil || seen[n] {
		return false
	}
	seen[n] = true
	defer delete(seen, n)
	if n.Kind == yaml.AliasNode {
		return containsKey(n.Alias, key, seen)
	}
	for i, c := range n.Content {
		if n.Kind == yaml.MappingNode && i%2 == 0 && c.Value == key {
			return true
		}
		if containsKey(c, key, seen) {
			return true
		}
	}
	return false
}

var (
	workDirOnce sync.Once
	workDir     string
	workDirErr  error
)

// fuzzDir returns one scratch directory per test process (a fuzz worker is a
// process), created on first use and removed by f.Cleanup where the process
// gets to run it. in.yaml and export.yaml inside it are overwritten per input.
func fuzzDir() (string, error) {
	workDirOnce.Do(func() { workDir, workDirErr = os.MkdirTemp("", "ward-fuzzload-") })
	return workDir, workDirErr
}

// FuzzLoad asserts config.Load never panics, returns only its documented
// error types, and that a loaded config exports to a fixed point.
func FuzzLoad(f *testing.F) {
	for _, p := range []string{"../../testdata/dod/ward.yaml", "../../ward.example.yaml"} {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatalf("read seed %s: %v", p, err)
		}
		f.Add(b)
	}
	for _, s := range []string{
		"listen: \"127.0.0.1:5353\"\nupstreams:\n  - address: \"1.1.1.1:853\"\n    server_name: one.one.one.one\n",
		"listen: \"127.0.0.1:5353\"\nbogus_key: 1\n",
		"listen: \"127.0.0.1:5353\"\n---\nlisten: \"127.0.0.1:5354\"\n",
		"listen: \"127.0.0.1:5353\"\ntimeouts:\n  dial: soon\n",
		"",
		// Non-mapping roots and a type error under upstreams without ca_bundle:
		// these must reach Load, which rejects them with a *ParseError.
		"foo",
		"[1]",
		"upstreams: 5\n",
		"upstreams:\n  - address: [1]\n",
		// A type error with a ca_bundle key under upstreams is skipped.
		"upstreams:\n  - ca_bundle: [1]\n",
	} {
		f.Add([]byte(s))
	}
	f.Cleanup(func() {
		if workDir != "" {
			_ = os.RemoveAll(workDir)
		}
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		if hasCABundle(data) {
			t.Skip("ca_bundle would make Load read a fuzzer-chosen path")
		}
		dir, err := fuzzDir()
		if err != nil {
			t.Fatal(err)
		}
		p1 := filepath.Join(dir, "in.yaml")
		if err := os.WriteFile(p1, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(p1)
		if err != nil {
			var (
				mf *config.MissingFileError
				pe *config.ParseError
				uk *config.UnknownKeyError
				ve *config.ValidationError
			)
			if !errors.As(err, &mf) && !errors.As(err, &pe) && !errors.As(err, &uk) && !errors.As(err, &ve) {
				t.Fatalf("Load returned an undocumented error type %T: %v", err, err)
			}
			if err.Error() == "" {
				t.Fatalf("Load returned an error with empty text (%T)", err)
			}
			return
		}
		e1, err := config.Export(cfg)
		if err != nil {
			t.Fatalf("Export of a loaded config failed: %v", err)
		}
		p2 := filepath.Join(dir, "export.yaml")
		if err := os.WriteFile(p2, e1, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg2, err := config.Load(p2)
		if err != nil {
			t.Fatalf("Load of an export failed: %v\nexport:\n%s", err, e1)
		}
		e2, err := config.Export(cfg2)
		if err != nil {
			t.Fatalf("Export of a re-loaded config failed: %v", err)
		}
		if !bytes.Equal(e1, e2) {
			t.Fatalf("export not idempotent:\nfirst:\n%s\nsecond:\n%s", e1, e2)
		}
	})
}
