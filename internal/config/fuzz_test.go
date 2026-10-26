// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"protocolward.ai/ward/internal/config"
)

// hasCABundle reports whether Load might open a file named by the input.
// Load reads upstreams[*].ca_bundle with os.ReadFile and the fuzzer controls
// that path (a device or FIFO could block), so such inputs are never fuzzed.
// The decision uses the decoded value, not the raw bytes, because YAML escapes
// and folding hide the key and the path. skip is true when the input must not
// reach Load. A YAML syntax error is rejected by Load before any file I/O, so
// it is not skipped.
func hasCABundle(data []byte) (skip bool) {
	var probe struct {
		Upstreams []struct {
			CABundle string `yaml:"ca_bundle"`
		} `yaml:"upstreams"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		// Syntax error: Load's decoder fails first. Type or aliasing error:
		// the probe could not see ca_bundle, so skip.
		return yaml.Unmarshal(data, new(yaml.Node)) == nil
	}
	for _, u := range probe.Upstreams {
		if u.CABundle != "" {
			return true
		}
	}
	return false
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
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if hasCABundle(data) {
			t.Skip("ca_bundle would make Load read a fuzzer-chosen path")
		}
		dir := t.TempDir()
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
