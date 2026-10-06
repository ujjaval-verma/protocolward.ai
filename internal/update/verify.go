// SPDX-License-Identifier: Apache-2.0

// Package update verifies signed update-channel metadata.
//
// The verifier implements a two-layer trust chain: a cosign signature
// pinning the TUF root metadata, then the TUF root -> targets metadata
// chain. The TUF half uses github.com/theupdateframework/go-tuf/v2's
// raw metadata primitives (Root().FromBytes + VerifyDelegate); the
// trustedmetadata client is bypassed because v0.1 deliberately omits
// the snapshot and timestamp roles (see design spec non-scope).
//
// The cosign half is implemented with stdlib crypto/ecdsa + crypto/x509
// rather than full sigstore/cosign/v2. The deviation from ADR-0001 D10
// keeps the govulncheck blast radius small (ADR-0002 §4 covers the
// policy that makes this tradeoff load-bearing). An ADR amendment to
// D10 capturing the deviation is filed at slice closeout.
package update

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Sentinel errors. Each maps 1:1 to a fixture variant under
// testdata/update/v0.1-*. Trust-root parse failures (file present but
// unparsable PEM) fold into ErrCosignBundle; they are a cosign-side
// problem, not a separate failure mode worth a dedicated sentinel
// for v0.1. (Was ErrCosignTrust in an earlier draft; collapsed
// per T0 spec-review when no fixture covered the bad-PEM path.)
var (
	ErrFixtureLayout = errors.New("update: fixture directory missing required files")
	ErrCosignBundle  = errors.New("update: cosign bundle verification failed")
	ErrTUFRoot       = errors.New("update: TUF root metadata invalid")
	ErrTUFTargets    = errors.New("update: TUF targets metadata invalid")
	ErrTargetHash    = errors.New("update: target hash mismatch")
)

// Target is one TUF-declared target file's metadata.
type Target struct {
	Length int64
	Hashes map[string]string // alg -> hex
	Path   string            // path to the target on disk; absolute or relative depending on fixtureDir
}

// VerifiedTargets is the successful return shape of Verify. Version
// fields are int64 to match go-tuf's metadata.Signed.Version type;
// callers should treat negative values as malformed (the verify path
// rejects them via TUF's own self-sign check, so the contract is
// "always >= 1 when returned").
type VerifiedTargets struct {
	Targets        map[string]Target
	RootVersion    int64
	TargetsVersion int64
	Expires        time.Time
}

// Verify walks the two-layer trust chain rooted at fixtureDir and
// returns the verified targets manifest. Returns one of the package
// sentinel errors (wrapped with %w) at the first broken link.
//
// Layout: fixtureDir must contain root.json, root.json.cosign-bundle,
// targets.json, and a targets/ directory containing every file
// referenced by targets.json. trustRootPath defaults to
// <fixtureDir>/cosign-trust-root.pem when empty.
func Verify(fixtureDir, trustRootPath string) (*VerifiedTargets, error) {
	// 1. Layout.
	rootPath := filepath.Join(fixtureDir, "root.json")
	bundlePath := filepath.Join(fixtureDir, "root.json.cosign-bundle")
	trustPath := trustRootPath
	if trustPath == "" {
		trustPath = filepath.Join(fixtureDir, "cosign-trust-root.pem")
	}
	targetsPath := filepath.Join(fixtureDir, "targets.json")
	targetsDir := filepath.Join(fixtureDir, "targets")
	for _, p := range []string{rootPath, bundlePath, trustPath, targetsPath} {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrFixtureLayout, p, err)
		}
	}
	if info, err := os.Stat(targetsDir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%w: targets/ not a directory under %s", ErrFixtureLayout, fixtureDir)
	}

	rootBytes, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read root.json: %w", ErrFixtureLayout, err)
	}
	trustBytes, err := os.ReadFile(trustPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read cosign-trust-root.pem: %w", ErrFixtureLayout, err)
	}
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("%w: read cosign bundle: %w", ErrFixtureLayout, err)
	}

	// 2. Cosign bundle verify (over sha256(rootBytes)).
	if err := verifyCosign(rootBytes, bundleBytes, trustBytes); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCosignBundle, err)
	}

	// 3. TUF root self-sign.
	root, err := metadata.Root().FromBytes(rootBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrTUFRoot, err)
	}
	if root.Signed.Type != metadata.ROOT {
		return nil, fmt.Errorf("%w: type=%q (want %q)", ErrTUFRoot, root.Signed.Type, metadata.ROOT)
	}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		return nil, fmt.Errorf("%w: self-sign: %w", ErrTUFRoot, err)
	}

	// 4. TUF targets metadata.
	targetsBytes, err := os.ReadFile(targetsPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read targets.json: %w", ErrFixtureLayout, err)
	}
	targets, err := metadata.Targets().FromBytes(targetsBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrTUFTargets, err)
	}
	if err := root.VerifyDelegate(metadata.TARGETS, targets); err != nil {
		return nil, fmt.Errorf("%w: delegate verify: %w", ErrTUFTargets, err)
	}
	if targets.Signed.IsExpired(time.Now()) {
		return nil, fmt.Errorf("%w: expired at %s", ErrTUFTargets, targets.Signed.Expires.Format(time.RFC3339))
	}

	// 5. Target file hashes.
	declared := make(map[string]Target, len(targets.Signed.Targets))
	for name, tf := range targets.Signed.Targets {
		fp := filepath.Join(targetsDir, name)
		body, err := os.ReadFile(fp)
		if err != nil {
			return nil, fmt.Errorf("%w: read target %s: %w", ErrFixtureLayout, name, err)
		}
		if int64(len(body)) != tf.Length {
			return nil, fmt.Errorf("%w: target %s length=%d (declared %d)", ErrTargetHash, name, len(body), tf.Length)
		}
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		wantBytes, ok := tf.Hashes["sha256"]
		if !ok {
			return nil, fmt.Errorf("%w: target %s: declared hashes lack sha256", ErrTargetHash, name)
		}
		want := hex.EncodeToString(wantBytes)
		if got != want {
			return nil, fmt.Errorf("%w: target %s sha256 mismatch", ErrTargetHash, name)
		}
		hashes := make(map[string]string, len(tf.Hashes))
		for alg, h := range tf.Hashes {
			hashes[alg] = hex.EncodeToString(h)
		}
		declared[name] = Target{
			Length: tf.Length,
			Hashes: hashes,
			Path:   fp,
		}
	}

	return &VerifiedTargets{
		Targets:        declared,
		RootVersion:    root.Signed.Version,
		TargetsVersion: targets.Signed.Version,
		Expires:        targets.Signed.Expires,
	}, nil
}

// verifyCosign verifies that bundleBytes is a {"sig","cert"} JSON pair
// where cert chains to a root in trustBytes and sig is a valid ECDSA
// signature over sha256(rootJSON) by cert's public key.
func verifyCosign(rootJSON, bundleBytes, trustBytes []byte) error {
	var b struct {
		Sig  string `json:"sig"`
		Cert string `json:"cert"`
	}
	if err := json.Unmarshal(bundleBytes, &b); err != nil {
		return fmt.Errorf("bundle decode: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(b.Sig)
	if err != nil {
		return fmt.Errorf("bundle sig b64: %w", err)
	}
	certPEM, err := base64.StdEncoding.DecodeString(b.Cert)
	if err != nil {
		return fmt.Errorf("bundle cert b64: %w", err)
	}
	leaf, err := parseSingleCert(certPEM)
	if err != nil {
		return fmt.Errorf("bundle cert: %w", err)
	}
	root, err := parseSingleCert(trustBytes)
	if err != nil {
		return fmt.Errorf("trust root: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// CurrentTime defaults to time.Now() — we enforce NotAfter so
		// an expired signing cert in a compromised bundle is rejected
		// (Ralph F2). Fixture test certs are NotBefore=2026 /
		// NotAfter=2050, valid for two decades of contributor machines.
	}); err != nil {
		return fmt.Errorf("cert chain: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("leaf public key not ECDSA")
	}
	digest := sha256.Sum256(rootJSON)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

func parseSingleCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM type %q (want CERTIFICATE)", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}
