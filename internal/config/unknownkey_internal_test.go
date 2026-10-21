// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/hostlist"
)

func TestSections_CoverEveryDecodedStruct(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		if strings.HasPrefix(typ.String(), "time.") || strings.HasPrefix(typ.String(), "x509.") {
			return
		}
		seen[typ] = true
		if _, ok := sections[typ.String()]; !ok {
			t.Errorf("struct %s has no entry in the section table", typ)
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() || f.Tag.Get("yaml") == "-" {
				continue
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(rawConfig{}))
	if len(seen) == 0 {
		t.Fatal("walked no structs")
	}
}

func TestYAMLKeys_FromTags(t *testing.T) {
	cases := []struct {
		typ  reflect.Type
		want []string
	}{
		{reflect.TypeOf(Upstream{}), []string{"address", "server_name", "ca_bundle"}},
		{reflect.TypeOf(hostlist.Source{}), []string{"id", "path"}},
		{reflect.TypeOf(rawConfig{}), []string{"listen", "log_level", "upstreams", "blocklists", "allowlists", "decoys", "block_response", "timeouts", "model"}},
	}
	for _, tc := range cases {
		if got := yamlKeys(tc.typ); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("yamlKeys(%s) = %v want %v", tc.typ, got, tc.want)
		}
	}
}
