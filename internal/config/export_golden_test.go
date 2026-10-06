// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"protocolward.ai/ward/internal/config"
	"protocolward.ai/ward/internal/hostlist"
)

// Golden bytes captured from config.Export before the configexport
// extraction (unchanged by it). They pin the exact `ward config export` output so the
// extraction of the marshaller into internal/configexport is provably
// behaviour-preserving. goldenBase sets Model so the pre-existing omission
// of the model stanza is pinned too (T0 B2/D2): changing it is a separate,
// deliberate decision, not a side effect of the extraction.
const (
	goldenDefaultAddress = `listen: 127.0.0.1:5354
log_level: info
upstreams:
    - address: 9.9.9.9:853
      server_name: dns.quad9.net
      ca_bundle: ""
    - address: 1.1.1.1:853
      server_name: cloudflare-dns.com
      ca_bundle: /etc/ward/ca.pem
blocklists:
    - id: ads
      path: /etc/ward/ads.txt
allowlists:
    - id: mine
      path: /etc/ward/allow.txt
timeouts:
    dial: 3s
    query: 2s
    shutdown: 5s
`
	goldenNXDOMAINNoLists = `listen: 127.0.0.1:5354
log_level: info
upstreams: []
block_response:
    mode: nxdomain
    a: ""
    aaaa: ""
timeouts:
    dial: 3s
    query: 2s
    shutdown: 5s
`
	goldenCustomAddress = `listen: 127.0.0.1:5354
log_level: info
upstreams:
    - address: 9.9.9.9:853
      server_name: dns.quad9.net
      ca_bundle: ""
    - address: 1.1.1.1:853
      server_name: cloudflare-dns.com
      ca_bundle: /etc/ward/ca.pem
blocklists:
    - id: ads
      path: /etc/ward/ads.txt
allowlists:
    - id: mine
      path: /etc/ward/allow.txt
block_response:
    mode: address
    a: 10.0.0.1
    aaaa: fd00::1
timeouts:
    dial: 3s
    query: 2s
    shutdown: 5s
`
)

func goldenBase() config.Config {
	return config.Config{
		Listen:   "127.0.0.1:5354",
		LogLevel: "info",
		Upstreams: []config.Upstream{
			{Address: "9.9.9.9:853", ServerName: "dns.quad9.net"},
			{Address: "1.1.1.1:853", ServerName: "cloudflare-dns.com", CABundle: "/etc/ward/ca.pem"},
		},
		Blocklists: []hostlist.Source{{ID: "ads", Path: "/etc/ward/ads.txt"}},
		Allowlists: []hostlist.Source{{ID: "mine", Path: "/etc/ward/allow.txt"}},
		Decoys:     []hostlist.Source{{ID: "golden-decoys", Path: "/etc/ward/golden-decoys.txt"}},
		Model:      &config.ModelConfig{Builtin: config.ModelBuiltinLexical},
		BlockResponse: config.BlockResponseConfig{
			Mode: config.BlockResponseModeAddress,
			A:    netip.MustParseAddr("0.0.0.0"),
			AAAA: netip.MustParseAddr("::"),
		},
		Timeouts: config.Timeouts{Dial: 3 * time.Second, Query: 2 * time.Second, Shutdown: 5 * time.Second},
	}
}

func TestExport_Golden(t *testing.T) {
	nx := goldenBase()
	nx.Upstreams, nx.Blocklists, nx.Allowlists = nil, nil, nil
	nx.BlockResponse = config.BlockResponseConfig{Mode: config.BlockResponseModeNXDOMAIN}

	emptyUp := nx
	emptyUp.Upstreams = []config.Upstream{}

	custom := goldenBase()
	custom.BlockResponse = config.BlockResponseConfig{
		Mode: config.BlockResponseModeAddress,
		A:    netip.MustParseAddr("10.0.0.1"),
		AAAA: netip.MustParseAddr("fd00::1"),
	}

	cases := []struct {
		name string
		in   config.Config
		want string
	}{
		{"default_address_mode_omitted", goldenBase(), goldenDefaultAddress},
		{"nxdomain_no_lists", nx, goldenNXDOMAINNoLists},
		{"empty_upstreams", emptyUp, goldenNXDOMAINNoLists},
		{"custom_address", custom, goldenCustomAddress},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := config.Export(tc.in)
			if err != nil {
				t.Fatalf("Export: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("Export bytes changed\n--- got ---\n%s--- want ---\n%s", got, tc.want)
			}
			if strings.Contains(string(got), "golden-decoys") {
				t.Errorf("invariant 6 violated: decoy source leaked into export\n%s", got)
			}
		})
	}
}
