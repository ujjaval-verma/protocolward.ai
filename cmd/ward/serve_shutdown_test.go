// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// blackHoleUpstream listens on a kernel-assigned loopback TCP port, accepts
// every connection and holds it without writing, so a DoT dial to it hangs in
// the handshake. accepted is closed on the first accepted connection; the
// loop keeps accepting (the upstream retries once on a fresh dial) until the
// listener closes. Cleanup closes the listener and the held connections and
// waits for the accept goroutine.
func blackHoleUpstream(t *testing.T) (addr string, accepted <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	acc := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var conns []net.Conn
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			once.Do(func() { close(acc) })
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-loopDone
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String(), acc
}

// A second SIGINT while ward drains an in-flight query exits at once with
// code 130 and never reaches `ward serve: stopped`.
func TestServe_SecondSignalDuringDrain_Exits130(t *testing.T) {
	t.Parallel()
	upAddr, accepted := blackHoleUpstream(t)
	w := startWard(t, "upstreams:\n  - address: \""+upAddr+"\"\n    server_name: \"blackhole.test\"\n"+
		"timeouts:\n  dial: \"20s\"\n  query: \"20s\"\n  shutdown: \"20s\"\n")

	conn, err := net.Dial("udp", w.dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(packed); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatalf("upstream never saw a connection; the query is not in flight\nlog:\n%s", w.out.String())
	}

	if err := w.proc.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if _, err := w.waitFor("ward serve: shutdown signal received; draining in-flight queries"); err != nil {
		t.Fatalf("%v", err)
	}
	select {
	case <-w.exited:
		t.Fatalf("ward exited (code %d) before the second signal\nlog:\n%s", w.exitCode, w.out.String())
	default:
	}
	if err := w.proc.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.exited:
	case <-time.After(5 * time.Second):
		t.Fatalf("ward did not exit within 5s of the second signal\nlog:\n%s", w.out.String())
	}
	if w.exitCode != 130 {
		t.Errorf("exit code = %d, want 130\nlog:\n%s", w.exitCode, w.out.String())
	}
	if m := w.scan("ward serve: stopped"); m != nil {
		t.Errorf("ward logged %q on the second-signal path; want an immediate exit\nlog:\n%s", "ward serve: stopped", w.out.String())
	}
}
