// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"protocolward.ai/ward/internal/config"
)

// configUpstream builds a config.Upstream for tests. When caBundlePath is
// non-empty it is passed through the real config.Load validator so RootCAs
// is populated by the same code path serve.go consumes — no test-only
// shortcut bypassing the parser.
func configUpstream(t *testing.T, address, serverName, caBundlePath string) config.Upstream {
	t.Helper()
	yamlBody := "listen: \"127.0.0.1:5354\"\nlog_level: \"info\"\nupstreams:\n  - address: \"" + address + "\"\n    server_name: \"" + serverName + "\"\n"
	if caBundlePath != "" {
		yamlBody += "    ca_bundle: \"" + caBundlePath + "\"\n"
	}
	yamlBody += "timeouts:\n  dial: \"1s\"\n  query: \"1s\"\n  shutdown: \"1s\"\n"
	p := filepath.Join(t.TempDir(), "ward.yaml")
	if err := os.WriteFile(p, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write tmp yaml: %v", err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg.Upstreams[0]
}

// writeSelfSignedPEM writes a self-signed ECDSA P-256 cert PEM to a temp file
// and returns the path. Sufficient for AppendCertsFromPEM to accept.
func writeSelfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ward-serve-test"},
		DNSNames:     []string{"ward-serve-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return p
}
