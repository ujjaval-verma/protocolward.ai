// SPDX-License-Identifier: Apache-2.0

package configexport_test

import (
	"reflect"
	"strings"
	"testing"

	"protocolward.ai/ward/internal/configexport"
	"protocolward.ai/ward/internal/hostlist"
)

// TestDocument_HasNoDecoyField is the structural half of invariant 6: the
// only type Marshal accepts has nowhere to put a decoy. A contributor who
// adds one fails here before any byte-level test runs.
func TestDocument_HasNoDecoyField(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice ||
			typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			if typ.Kind() == reflect.Map {
				walk(path, typ.Key())
			}
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			p := path + "." + f.Name
			if strings.Contains(strings.ToLower(f.Name), "decoy") ||
				strings.Contains(strings.ToLower(f.Tag.Get("yaml")), "decoy") {
				t.Errorf("invariant 6: configexport.Document has decoy-shaped field %s (yaml %q)", p, f.Tag.Get("yaml"))
			}
			walk(p, f.Type)
		}
	}
	walk("Document", reflect.TypeOf(configexport.Document{}))
}

func TestMarshal_KeyOrderAndOmitEmpty(t *testing.T) {
	const want = `listen: 127.0.0.1:53
log_level: info
upstreams:
    - address: 9.9.9.9:853
      server_name: dns.quad9.net
      ca_bundle: ""
timeouts:
    dial: 3s
    query: 2s
    shutdown: 5s
`
	got, err := configexport.Marshal(configexport.Document{
		Listen:    "127.0.0.1:53",
		LogLevel:  "info",
		Upstreams: []configexport.Upstream{{Address: "9.9.9.9:853", ServerName: "dns.quad9.net"}},
		Timeouts:  configexport.Timeouts{Dial: "3s", Query: "2s", Shutdown: "5s"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != want {
		t.Errorf("Marshal\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestMarshal_ListsAndBlockResponse(t *testing.T) {
	const want = `listen: 127.0.0.1:53
log_level: info
upstreams: []
blocklists:
    - id: ads
      path: ads.txt
allowlists:
    - id: mine
      path: allow.txt
block_response:
    mode: nxdomain
    a: ""
    aaaa: ""
timeouts:
    dial: 3s
    query: 2s
    shutdown: 5s
`
	got, err := configexport.Marshal(configexport.Document{
		Listen:        "127.0.0.1:53",
		LogLevel:      "info",
		Blocklists:    []hostlist.Source{{ID: "ads", Path: "ads.txt"}},
		Allowlists:    []hostlist.Source{{ID: "mine", Path: "allow.txt"}},
		BlockResponse: &configexport.BlockResponse{Mode: "nxdomain"},
		Timeouts:      configexport.Timeouts{Dial: "3s", Query: "2s", Shutdown: "5s"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != want {
		t.Errorf("Marshal\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}
