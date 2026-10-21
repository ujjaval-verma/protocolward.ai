// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"protocolward.ai/ward/internal/hostlist"
)

// UnknownKey is one mapping key that the config schema does not define.
type UnknownKey struct {
	Line    int      // 1-based line of the key in the file
	Key     string   // the key exactly as written
	Section string   // "" = top level; otherwise a section label
	Valid   []string // keys accepted in Section, in schema order
}

// String renders the key as "line N: unknown key "k" <where> (valid keys: ...)".
func (k UnknownKey) String() string {
	where := "at top level"
	if k.Section != "" {
		where = "under " + k.Section
	}
	return fmt.Sprintf("line %d: unknown key %q %s (valid keys: %s)",
		k.Line, truncateEcho(k.Key, 64), where, strings.Join(k.Valid, ", "))
}

// UnknownKeyError is returned by Load when the file contains one or more
// keys the schema does not define. Keys are in document order.
type UnknownKeyError struct {
	Path string
	Keys []UnknownKey
}

func (e *UnknownKeyError) Error() string {
	parts := make([]string, len(e.Keys))
	for i, k := range e.Keys {
		parts[i] = k.String()
	}
	return fmt.Sprintf("config error in %s: %s — remediation: fix the spelling or remove the key",
		e.Path, strings.Join(parts, "; "))
}

// unknownFieldRe matches yaml.v3's KnownFields(true) TypeError entries. (?s)
// lets . match the newline in a quoted key.
var unknownFieldRe = regexp.MustCompile(`(?s)^line (\d+): field (.*) not found in type (\S+)$`)

// sections maps reflect.Type.String() of every decoded struct to its
// user-facing section label.
var sections = func() map[string]struct {
	section string
	typ     reflect.Type
} {
	m := map[string]struct {
		section string
		typ     reflect.Type
	}{}
	add := func(section string, v any) {
		t := reflect.TypeOf(v)
		m[t.String()] = struct {
			section string
			typ     reflect.Type
		}{section, t}
	}
	add("", rawConfig{})
	add("upstreams[]", Upstream{})
	add("blocklists[]/allowlists[]/decoys[]", hostlist.Source{})
	add("timeouts", rawTimeouts{})
	add("block_response", rawBlockResponse{})
	add("model", ModelConfig{})
	return m
}()

// yamlKeys returns the YAML keys accepted by struct type t, in declaration
// order: the tag name if present, "-" skipped, else the lowercased field name.
func yamlKeys(t reflect.Type) []string {
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		keys = append(keys, name)
	}
	return keys
}

// classifyDecodeError turns a decode error into *UnknownKeyError when every
// entry is an unknown-field report for a known section, else *ParseError.
func classifyDecodeError(path string, err error) error {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) || len(typeErr.Errors) == 0 {
		return &ParseError{Path: path, Err: err}
	}
	type id struct {
		line    int
		key     string
		section string
	}
	seen := map[id]bool{}
	keys := make([]UnknownKey, 0, len(typeErr.Errors))
	for _, e := range typeErr.Errors {
		m := unknownFieldRe.FindStringSubmatch(e)
		if m == nil {
			return &ParseError{Path: path, Err: err}
		}
		sec, ok := sections[m[3]]
		if !ok {
			return &ParseError{Path: path, Err: err}
		}
		line, convErr := strconv.Atoi(m[1])
		if convErr != nil {
			return &ParseError{Path: path, Err: err}
		}
		k := id{line, m[2], sec.section}
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, UnknownKey{Line: line, Key: m[2], Section: sec.section, Valid: yamlKeys(sec.typ)})
	}
	return &UnknownKeyError{Path: path, Keys: keys}
}

// sectionKeys returns the valid keys for a section label.
func sectionKeys(section string) []string {
	for _, v := range sections {
		if v.section == section {
			return yamlKeys(v.typ)
		}
	}
	return nil
}

// childSection names the section a known key's value opens, if any.
func childSection(parent, key string) (string, bool) {
	if parent != "" {
		return "", false
	}
	switch key {
	case "upstreams":
		return "upstreams[]", true
	case "blocklists", "allowlists", "decoys":
		return "blocklists[]/allowlists[]/decoys[]", true
	case "timeouts", "block_response", "model":
		return key, true
	}
	return "", false
}

// nullKeys finds mapping keys tagged !!null (null, Null, NULL, ~). yaml.v3
// drops those and their subtrees before the KnownFields check, so the typed
// decode never reports them. Only the first document is inspected.
func nullKeys(data []byte) []UnknownKey {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	type id struct {
		line    int
		key     string
		section string
	}
	seen := map[id]bool{}
	var out []UnknownKey
	var walk func(n *yaml.Node, section string)
	walk = func(n *yaml.Node, section string) {
		if n.Kind == yaml.AliasNode && n.Alias != nil {
			n = n.Alias
		}
		switch n.Kind { //nolint:exhaustive // only containers can hold keys
		case yaml.SequenceNode:
			for _, item := range n.Content {
				walk(item, section)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if k.ShortTag() == "!!null" {
					key := k.Value
					if key == "" {
						key = "~"
					}
					sid := id{k.Line, key, section}
					if !seen[sid] {
						seen[sid] = true
						out = append(out, UnknownKey{Line: k.Line, Key: key, Section: section, Valid: sectionKeys(section)})
					}
					continue
				}
				if k.ShortTag() == "!!merge" {
					walk(v, section) // mapping or sequence of mappings, same section
					continue
				}
				if child, ok := childSection(section, k.Value); ok {
					walk(v, child)
				}
			}
		}
	}
	walk(doc.Content[0], "")
	return out
}
