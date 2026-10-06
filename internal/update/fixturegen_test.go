// SPDX-License-Identifier: Apache-2.0

// Fixture generator for internal/update tests.
//
// Regenerate with:
//
//	go test ./internal/update -run TestGenerateFixtures -update
//
// The good fixture lives at <repo-root>/testdata/update/v0.1-good and
// the five failure-mode siblings at <repo-root>/testdata/update/v0.1-*.
// All paths resolve via runtime.Caller(0) + 2-parent walk-up so the
// generator and the DOD bullet (which runs from the repo root) share
// one canonical location.
//
// The test CA cert is valid through 2050-01-01. A 2050+ rebuild needs
// regeneration; the failing happy-path test will surface this clearly.
//
// Determinism: ed25519 keys (TUF roles) come from seeded ed25519.
// GenerateKey + a math/rand-backed io.Reader. ECDSA keys + cert
// generation + ECDSA SignASN1 use the same seeded reader. With fixed
// seeds + fixed RefTime + ed25519's deterministic signing, regenerated
// fixture bytes are stable across runs on the same go-tuf version.

package update

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var regenerateFixtures = flag.Bool("update", false,
	"regenerate testdata/update/v0.1-* fixtures from this generator")

// fixtureRoot returns <repo-root>/testdata/update, resolved from this
// test file's path: internal/update/fixturegen_test.go -> ../../testdata/update.
func fixtureRoot(tb testing.TB) string {
	tb.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller(0) failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "update")
}

func detRand(seed int64) io.Reader {
	return mrand.New(mrand.NewSource(seed)) //nolint:gosec // deterministic by design
}

var (
	fixtureRefTime  = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	fixtureExpires  = time.Date(2050, time.January, 1, 0, 0, 0, 0, time.UTC)
	fixtureExpired  = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	fixtureCAExpiry = time.Date(2050, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// TestGenerateFixtures (re)builds every fixture variant. Default-skipped
// unless invoked with -update so day-to-day test runs don't churn bytes.
func TestGenerateFixtures(t *testing.T) {
	if !*regenerateFixtures {
		t.Skip("run with -update to regenerate fixtures")
	}
	root := fixtureRoot(t)
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("clean fixture root: %v", err)
	}
	for _, v := range []variant{
		variantGood,
		variantBadCosign,
		variantBadRootSig,
		variantTamperedTarget,
		variantExpired,
		variantMissingTrustRoot,
	} {
		dir := filepath.Join(root, "v0.1-"+v.suffix)
		if err := os.MkdirAll(filepath.Join(dir, "targets"), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		writeVariant(t, dir, v)
	}
}

type variant struct {
	suffix          string
	flipCosignSig   bool
	wrongRootSigner bool
	tamperTarget    bool
	targetsExpired  bool
	omitTrustRoot   bool
}

var (
	variantGood             = variant{suffix: "good"}
	variantBadCosign        = variant{suffix: "bad-cosign", flipCosignSig: true}
	variantBadRootSig       = variant{suffix: "bad-root-sig", wrongRootSigner: true}
	variantTamperedTarget   = variant{suffix: "tampered-target", tamperTarget: true}
	variantExpired          = variant{suffix: "expired", targetsExpired: true}
	variantMissingTrustRoot = variant{suffix: "missing-trust-root", omitTrustRoot: true}
)

// writeVariant produces one fixture directory from scratch. Building
// each variant independently (rather than mutating a shared in-memory
// model) keeps the failure-mode mutations one branch each — easier to
// audit than a generic mutate-and-rewrite path.
func writeVariant(t *testing.T, dir string, v variant) {
	t.Helper()

	// TUF role keys.
	rootPub, rootPriv, err := ed25519.GenerateKey(detRand(0xA0_5E_05_01))
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	targetsPub, targetsPriv, err := ed25519.GenerateKey(detRand(0xA0_5E_05_02))
	if err != nil {
		t.Fatalf("gen targets key: %v", err)
	}
	rootKeyMeta, err := metadata.KeyFromPublicKey(rootPub)
	if err != nil {
		t.Fatalf("root pub -> Key: %v", err)
	}
	targetsKeyMeta, err := metadata.KeyFromPublicKey(targetsPub)
	if err != nil {
		t.Fatalf("targets pub -> Key: %v", err)
	}

	// Target payload (opaque for v0.1). Tampering happens by writing
	// extra bytes to disk *after* targets.json is signed against the
	// pristine hash.
	feedBody := []byte(`{"placeholder":"v0.1 feed; opaque for update-verify slice"}` + "\n")
	feedOnDisk := feedBody
	if v.tamperTarget {
		feedOnDisk = append(append([]byte{}, feedBody...), '!')
	}

	// TUF targets metadata.
	targetsExpires := fixtureExpires
	if v.targetsExpired {
		targetsExpires = fixtureExpired
	}
	tgts := metadata.Targets(targetsExpires)
	tgts.Signed.Version = 1
	tf, err := metadata.TargetFile().FromBytes("feed.json", feedBody, "sha256")
	if err != nil {
		t.Fatalf("target file info: %v", err)
	}
	tgts.Signed.Targets["feed.json"] = tf

	// TUF root metadata. All four top-level role-key slots populated so
	// root.json validates structurally; this slice only ever verifies
	// root + targets, but go-tuf's root parser requires the others to
	// exist. We reuse the targets key for snapshot/timestamp slots.
	rt := metadata.Root(fixtureExpires)
	rt.Signed.Version = 1
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		key := targetsKeyMeta
		if role == metadata.ROOT {
			key = rootKeyMeta
		}
		if err := rt.Signed.AddKey(key, role); err != nil {
			t.Fatalf("add key to %s role: %v", role, err)
		}
	}

	// Sign root. For the bad-root-sig variant we sign with a DIFFERENT
	// ed25519 key — the resulting signature won't verify against any
	// key the root metadata declares for the root role, so VerifyDelegate
	// returns an "unsigned by trusted keys" error.
	signingKey := rootPriv
	if v.wrongRootSigner {
		_, signingKey, err = ed25519.GenerateKey(detRand(0xBAD_510E0))
		if err != nil {
			t.Fatalf("gen wrong root key: %v", err)
		}
	}
	rootSigner, err := signature.LoadSigner(signingKey, crypto.Hash(0))
	if err != nil {
		t.Fatalf("root signer: %v", err)
	}
	if _, err := rt.Sign(rootSigner); err != nil {
		t.Fatalf("sign root: %v", err)
	}

	// Sign targets (always with the real targets key; even the bad-cosign
	// variant has a valid TUF chain — the failure is in the cosign layer).
	targetsSigner, err := signature.LoadSigner(targetsPriv, crypto.Hash(0))
	if err != nil {
		t.Fatalf("targets signer: %v", err)
	}
	if _, err := tgts.Sign(targetsSigner); err != nil {
		t.Fatalf("sign targets: %v", err)
	}

	rootJSON, err := rt.ToBytes(true)
	if err != nil {
		t.Fatalf("marshal root: %v", err)
	}
	targetsJSON, err := tgts.ToBytes(true)
	if err != nil {
		t.Fatalf("marshal targets: %v", err)
	}

	// Cosign-style CA + leaf cert. CA self-signs; leaf is issued by CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), detRand(0xC0_51_6E_A0))
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ward-test-cosign-ca"},
		NotBefore:             fixtureRefTime,
		NotAfter:              fixtureCAExpiry,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(detRand(0xC0_51_6E_A0), caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), detRand(0xC0_51_6E_A1))
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ward-test-cosign-signer"},
		NotBefore:    fixtureRefTime,
		NotAfter:     fixtureCAExpiry,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(detRand(0xC0_51_6E_A1), leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	// Sign sha256(rootJSON) with the leaf key. Deterministic RNG.
	digest := sha256.Sum256(rootJSON)
	cosignSig, err := ecdsa.SignASN1(detRand(0xC0_51_6E_A2), leafKey, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign root.json: %v", err)
	}
	if v.flipCosignSig {
		cosignSig = append([]byte(nil), cosignSig...)
		cosignSig[len(cosignSig)-1] ^= 0xFF
	}

	// Write to disk.
	mustWriteFile(t, filepath.Join(dir, "root.json"), rootJSON)
	mustWriteFile(t, filepath.Join(dir, "targets.json"), targetsJSON)
	mustWriteFile(t, filepath.Join(dir, "targets", "feed.json"), feedOnDisk)
	if !v.omitTrustRoot {
		mustWriteFile(t, filepath.Join(dir, "cosign-trust-root.pem"), caPEM)
	}
	bundle, err := json.MarshalIndent(struct {
		Sig  string `json:"sig"`
		Cert string `json:"cert"`
	}{
		Sig:  base64.StdEncoding.EncodeToString(cosignSig),
		Cert: base64.StdEncoding.EncodeToString(leafPEM),
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal cosign bundle: %v", err)
	}
	mustWriteFile(t, filepath.Join(dir, "root.json.cosign-bundle"), bundle)
}

func mustWriteFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
