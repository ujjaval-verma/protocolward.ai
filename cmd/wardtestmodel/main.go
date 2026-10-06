// SPDX-License-Identifier: Apache-2.0

// wardtestmodel — a minimal slow-path classifier helper used by the DOD
// acceptance harness (scripts/dod.sh bullets 13 + 14) to exercise ward's
// SP10c slow-path fork without depending on a real Gemma runtime.
//
// Wire protocol matches the SP10b adapter contract:
//
//	stdin:  newline-delimited JSON requests, one per line:
//	        {"hostname":"<qname>","client_hints":[...],"user_agent":"..."}
//	stdout: newline-delimited JSON responses, one per line:
//	        {"verdict":"benign|telemetry|malicious"}
//
// Verdict mapping is controlled by flags:
//
//	-malicious-substring   if the hostname contains the substring, return
//	                       VerdictMalicious. Empty (default) disables.
//	-telemetry-substring   same, for VerdictTelemetry.
//	Otherwise → VerdictBenign.
//
// Substring precedence: malicious is checked first (matches the user's
// security-priority intuition; the DOD harness only sets one of the two
// flags per run, so precedence rarely matters in practice).
//
// Not built by `make build` / `make dist`. The DOD harness compiles it on
// demand. No build tag — the binary reads only stdin and writes only stdout
// and stderr, and has no network surface.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"protocolward.ai/ward/pkg/schema"
)

type request struct {
	Hostname    string   `json:"hostname"`
	ClientHints []string `json:"client_hints,omitempty"`
	UserAgent   string   `json:"user_agent,omitempty"`
}

type response struct {
	Verdict schema.Verdict `json:"verdict"`
}

func main() {
	malSub := flag.String("malicious-substring", "", "hostname substring that maps to VerdictMalicious (empty disables)")
	telSub := flag.String("telemetry-substring", "", "hostname substring that maps to VerdictTelemetry (empty disables)")
	flag.Parse()

	// stderr ready line — useful when the harness wants to know the helper
	// is up before spawning the parent. The SP10c adapter doesn't probe for
	// this; the harness reads it via pgrep / process inspection. Emitting
	// it on stderr keeps stdout pure JSON for the wire protocol.
	fmt.Fprintf(os.Stderr, "wardtestmodel ready malicious=%q telemetry=%q\n", *malSub, *telSub)

	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			log.Fatalf("wardtestmodel: read: %v", err)
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			log.Fatalf("wardtestmodel: decode request: %v (line=%q)", err, line)
		}

		var v schema.Verdict
		switch {
		case *malSub != "" && strings.Contains(req.Hostname, *malSub):
			v = schema.VerdictMalicious
		case *telSub != "" && strings.Contains(req.Hostname, *telSub):
			v = schema.VerdictTelemetry
		default:
			v = schema.VerdictBenign
		}

		payload, err := json.Marshal(response{Verdict: v})
		if err != nil {
			log.Fatalf("wardtestmodel: encode response: %v", err)
		}
		payload = append(payload, '\n')
		if _, err := out.Write(payload); err != nil {
			log.Fatalf("wardtestmodel: write: %v", err)
		}
		if err := out.Flush(); err != nil {
			log.Fatalf("wardtestmodel: flush: %v", err)
		}
	}
}
