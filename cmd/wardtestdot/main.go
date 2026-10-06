// SPDX-License-Identifier: Apache-2.0

// wardtestdot — a minimal in-process DoT (DNS-over-TLS) server used by the
// DOD acceptance harness (scripts/dod.sh bullet 5) to exercise ward's
// upstream forward path without depending on real network egress.
//
// Behavior: generates an ephemeral self-signed ECDSA P-256 cert for DNS SAN
// "wardtestdot.test", writes the cert PEM to the path given by -ca-out, then
// serves DoT on -listen (default 127.0.0.1:5853). Every A query is answered
// with 93.184.216.34 (example.com). All other qtypes return NOERROR with no
// answer (sufficient for the DOD assertion).
//
// Not built by `make build` / `make dist`. The DOD harness compiles it on
// demand. No build tag — the binary is innocuous and loopback-only.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const certServerName = "wardtestdot.test"

func main() {
	listen := flag.String("listen", "127.0.0.1:5853", "DoT listen address (host:port)")
	caOut := flag.String("ca-out", "", "path to write the self-signed CA PEM (required)")
	flag.Parse()

	if *caOut == "" {
		fmt.Fprintln(os.Stderr, "wardtestdot: -ca-out is required")
		os.Exit(2)
	}

	tlsCert, certPEM, err := generateSelfSignedCert(certServerName)
	if err != nil {
		log.Fatalf("wardtestdot: generate cert: %v", err)
	}
	if err := os.WriteFile(*caOut, certPEM, 0o600); err != nil {
		log.Fatalf("wardtestdot: write ca-out %q: %v", *caOut, err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", *listen, tlsCfg)
	if err != nil {
		log.Fatalf("wardtestdot: listen %s: %v", *listen, err)
	}
	defer ln.Close()

	// Print the bound address so the harness can race-free pick it up.
	fmt.Printf("wardtestdot ready addr=%s sni=%s ca=%s\n", ln.Addr().String(), certServerName, *caOut)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return
		}
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		msgBuf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			return
		}
		resp := buildResponse(req)
		out, err := resp.Pack()
		if err != nil {
			return
		}
		prefix := []byte{byte(len(out) >> 8), byte(len(out))}
		if _, err := conn.Write(append(prefix, out...)); err != nil {
			return
		}
	}
}

func buildResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = dns.RcodeSuccess
	for _, q := range req.Question {
		if q.Qtype != dns.TypeA {
			continue
		}
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			A: net.IPv4(93, 184, 216, 34),
		}
		resp.Answer = append(resp.Answer, rr)
	}
	return resp
}

func generateSelfSignedCert(serverName string) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("gen key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("X509KeyPair: %w", err)
	}
	return tlsCert, certPEM, nil
}
