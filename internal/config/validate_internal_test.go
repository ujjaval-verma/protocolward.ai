// SPDX-License-Identifier: Apache-2.0

package config

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
)

// internalValidPEM returns a self-signed ECDSA cert PEM. validPEM lives in
// package config_test and is not reachable from this internal test file.
func internalValidPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "validate-internal-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestValidate_NoFileIO_NoMutation pins that validate is a pure check: it
// neither reads ca_bundle files nor populates RootCAs.
func TestValidate_NoFileIO_NoMutation(t *testing.T) {
	validFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(validFile, internalValidPEM(t), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	cases := []struct {
		name     string
		caBundle string
	}{
		{"nonexistent path", filepath.Join(t.TempDir(), "missing.pem")},
		{"valid PEM file", validFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Listen:   "127.0.0.1:5354",
				LogLevel: "info",
				Upstreams: []Upstream{{
					Address:    "9.9.9.9:853",
					ServerName: "dns.quad9.net",
					CABundle:   tc.caBundle,
				}},
				Timeouts: Timeouts{Dial: time.Second, Query: time.Second, Shutdown: time.Second},
			}
			if err := cfg.validate(); err != nil {
				t.Fatalf("validate() = %v; want nil", err)
			}
			if cfg.Upstreams[0].RootCAs != nil {
				t.Errorf("validate() populated RootCAs; want nil")
			}
		})
	}
}
