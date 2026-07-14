// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A synthetic vendor PKI, so the verifier can be exercised end to end with no
// hardware: root -> intermediate -> device leaf, and a device key that signs the
// attestation.

type testPKI struct {
	rootCert *x509.Certificate
	rootDER  []byte

	interCert *x509.Certificate
	interDER  []byte

	leafCert *x509.Certificate
	leafDER  []byte
	leafKey  *ecdsa.PrivateKey

	roots *x509.CertPool
}

func newTestPKI(t *testing.T, aaguid []byte) *testPKI {
	t.Helper()

	rootKey := mustECDSAKey(t)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Vendor FIDO Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER := mustCreateCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

	interKey := mustECDSAKey(t)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Vendor FIDO Attestation Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER := mustCreateCert(t, interTmpl, mustParse(t, rootDER), &interKey.PublicKey, rootKey)

	leafKey := mustECDSAKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test Vendor Authenticator"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if aaguid != nil {
		value, err := asn1.Marshal(aaguid)
		if err != nil {
			t.Fatalf("asn1.Marshal(aaguid) = %v", err)
		}
		leafTmpl.ExtraExtensions = []pkix.Extension{{Id: oidFidoGenCeAAGUID, Value: value}}
	}
	leafDER := mustCreateCert(t, leafTmpl, mustParse(t, interDER), &leafKey.PublicKey, interKey)

	roots := x509.NewCertPool()
	roots.AddCert(mustParse(t, rootDER))

	return &testPKI{
		rootCert:  mustParse(t, rootDER),
		rootDER:   rootDER,
		interCert: mustParse(t, interDER),
		interDER:  interDER,
		leafCert:  mustParse(t, leafDER),
		leafDER:   leafDER,
		leafKey:   leafKey,
		roots:     roots,
	}
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() = %v", err)
	}
	return k
}

func mustCreateCert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() = %v", err)
	}
	return der
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() = %v", err)
	}
	return c
}

// testAuthData builds authenticator data carrying an AAGUID at the offset the
// verifier reads it from: rpIdHash(32) flags(1) signCount(4) aaguid(16).
func testAuthData(aaguid []byte) []byte {
	data := make([]byte, 53)
	copy(data[37:53], aaguid)
	return data
}

func testAAGUID() []byte {
	return []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
}

// attest builds the attestation material a genuine device would return: a packed
// statement signed by the device's leaf key over authData || clientDataHash,
// with the chain the key presents.
func (pki *testPKI) attest(t *testing.T, authData, clientDataHash []byte) EnrollResult {
	t.Helper()

	signed := append(append([]byte{}, authData...), clientDataHash...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, pki.leafKey, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1() = %v", err)
	}

	return EnrollResult{
		AttestationFormat:    packedFormat,
		AttestationAlg:       coseAlgES256,
		AttestationSignature: sig,
		AuthenticatorData:    authData,
		ClientDataHash:       clientDataHash,
		// Leaf first, then the intermediate the key presented.
		AttestationCerts: [][]byte{pki.leafDER, pki.interDER},
	}
}

// signedEnrollResult builds an EnrollResult whose attestation genuinely verifies
// against pki.roots -- the honest-hardware case.
func signedEnrollResult(t *testing.T, pki *testPKI, authData, clientDataHash []byte) EnrollResult {
	t.Helper()

	r := pki.attest(t, authData, clientDataHash)
	r.CredentialID = []byte("credential")
	return r
}

func TestAttestationAcceptsGenuineHardware(t *testing.T) {
	aaguid := testAAGUID()
	pki := newTestPKI(t, aaguid)
	r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))

	if err := verifyGenuineHardware(r, pki.roots); err != nil {
		t.Fatalf("verifyGenuineHardware() = %v, want nil", err)
	}
}

// The bundled intermediates bridge a leaf to a root when the key presents only
// its own certificate.  Here the key presents leaf-only and the intermediate is
// absent from both the x5c and our bundle, so the chain cannot be built: this
// pins that an unbridgeable chain is refused, not waved through.
func TestAttestationRefusesAnUnbridgeableChain(t *testing.T) {
	aaguid := testAAGUID()
	pki := newTestPKI(t, aaguid)

	r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))
	r.AttestationCerts = [][]byte{pki.leafDER} // no intermediate offered

	err := verifyGenuineHardware(r, pki.roots)
	if !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("verifyGenuineHardware() = %v, want ErrUntrustedAuthenticator", err)
	}
}

// A self-signed leaf is exactly what a software or virtual authenticator
// presents.  It must never enroll -- this is the check the whole file exists for.
func TestAttestationRefusesASoftwareAuthenticator(t *testing.T) {
	aaguid := testAAGUID()
	authData := testAuthData(aaguid)
	clientDataHash := []byte("client-data-hash")

	// A "software authenticator": its own key, its own self-signed certificate,
	// a perfectly valid signature over the authenticator data.  Everything is
	// internally consistent.  It simply chains to nothing we trust.
	key := mustECDSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Definitely Real Hardware"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der := mustCreateCert(t, tmpl, tmpl, &key.PublicKey, key)

	signed := append(append([]byte{}, authData...), clientDataHash...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1() = %v", err)
	}

	r := EnrollResult{
		AttestationFormat:    packedFormat,
		AttestationAlg:       coseAlgES256,
		AttestationSignature: sig,
		AuthenticatorData:    authData,
		ClientDataHash:       clientDataHash,
		AttestationCerts:     [][]byte{der},
	}

	// Against the bundled Yubico roots (nil == default), and against a test pool.
	if err := verifyGenuineHardware(r, nil); !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("verifyGenuineHardware(bundled roots) = %v, want ErrUntrustedAuthenticator", err)
	}
	pki := newTestPKI(t, aaguid)
	if err := verifyGenuineHardware(r, pki.roots); !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("verifyGenuineHardware(test roots) = %v, want ErrUntrustedAuthenticator", err)
	}
}

// A genuine certificate must not be replayable for a credential it never
// attested.  The signature covers this credential's authenticator data, so
// swapping the authenticator data under a real signature must fail.
func TestAttestationRefusesAReplayedCertificate(t *testing.T) {
	aaguid := testAAGUID()
	pki := newTestPKI(t, aaguid)

	r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))

	// Same genuine chain and signature, different credential.
	other := testAuthData(aaguid)
	other[0] ^= 0xFF // a different rpIdHash: a different credential entirely
	r.AuthenticatorData = other

	if err := verifyGenuineHardware(r, pki.roots); !errors.Is(err, ErrAttestationSignature) {
		t.Errorf("verifyGenuineHardware() = %v, want ErrAttestationSignature", err)
	}
}

func TestAttestationRefusesATamperedClientDataHash(t *testing.T) {
	aaguid := testAAGUID()
	pki := newTestPKI(t, aaguid)

	r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))
	r.ClientDataHash = []byte("different-hash!!")

	if err := verifyGenuineHardware(r, pki.roots); !errors.Is(err, ErrAttestationSignature) {
		t.Errorf("verifyGenuineHardware() = %v, want ErrAttestationSignature", err)
	}
}

func TestAttestationRefusesBadInput(t *testing.T) {
	aaguid := testAAGUID()
	pki := newTestPKI(t, aaguid)
	good := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))

	tests := []struct {
		name   string
		mutate func(*EnrollResult)
		want   error
	}{
		{
			// A format we cannot check is an opt-out with extra steps.
			name:   "fido-u2f format",
			mutate: func(r *EnrollResult) { r.AttestationFormat = "fido-u2f" },
			want:   ErrUnsupportedAttestationFormat,
		},
		{
			name:   "tpm format",
			mutate: func(r *EnrollResult) { r.AttestationFormat = "tpm" },
			want:   ErrUnsupportedAttestationFormat,
		},
		{
			// "none" is what an authenticator returns when it will not attest.
			name:   "none format",
			mutate: func(r *EnrollResult) { r.AttestationFormat = "none" },
			want:   ErrUnsupportedAttestationFormat,
		},
		{
			name:   "empty format",
			mutate: func(r *EnrollResult) { r.AttestationFormat = "" },
			want:   ErrUnsupportedAttestationFormat,
		},
		{
			name:   "no certificate chain",
			mutate: func(r *EnrollResult) { r.AttestationCerts = nil },
			want:   ErrNoAttestation,
		},
		{
			name:   "unsupported algorithm",
			mutate: func(r *EnrollResult) { r.AttestationAlg = -257 }, // RS256
			want:   ErrAttestationSignature,
		},
		{
			name:   "corrupt signature",
			mutate: func(r *EnrollResult) { r.AttestationSignature = []byte("not a signature") },
			want:   ErrAttestationSignature,
		},
		{
			name: "flipped signature bit",
			mutate: func(r *EnrollResult) {
				sig := append([]byte(nil), r.AttestationSignature...)
				sig[len(sig)-1] ^= 0x01
				r.AttestationSignature = sig
			},
			want: ErrAttestationSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good
			tt.mutate(&r)
			if err := verifyGenuineHardware(r, pki.roots); !errors.Is(err, tt.want) {
				t.Errorf("verifyGenuineHardware() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAttestationRefusesAnUnparseableCertificate(t *testing.T) {
	aaguid := testAAGUID()
	pki := newTestPKI(t, aaguid)

	t.Run("leaf", func(t *testing.T) {
		r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("hash"))
		r.AttestationCerts = [][]byte{[]byte("not a certificate")}
		if err := verifyGenuineHardware(r, pki.roots); err == nil {
			t.Error("verifyGenuineHardware() = nil, want an error")
		}
	})

	t.Run("intermediate", func(t *testing.T) {
		r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("hash"))
		r.AttestationCerts = [][]byte{pki.leafDER, []byte("not a certificate")}
		if err := verifyGenuineHardware(r, pki.roots); err == nil {
			t.Error("verifyGenuineHardware() = nil, want an error")
		}
	})
}

// A certificate must not vouch for a different authenticator model than the one
// that actually answered.
func TestAttestationRefusesAnAAGUIDMismatch(t *testing.T) {
	certAAGUID := testAAGUID()
	pki := newTestPKI(t, certAAGUID)

	// The signed authenticator data claims a different model than the certificate.
	deviceAAGUID := []byte{99, 99, 99, 99, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	r := signedEnrollResult(t, pki, testAuthData(deviceAAGUID), []byte("client-data-hash"))

	if err := verifyGenuineHardware(r, pki.roots); !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("verifyGenuineHardware() = %v, want ErrUntrustedAuthenticator", err)
	}
}

// Not every attestation certificate carries the AAGUID extension.  An absent one
// is allowed; only a present-and-mismatched one is refused.
func TestAttestationAllowsAnAbsentAAGUIDExtension(t *testing.T) {
	pki := newTestPKI(t, nil) // leaf with no AAGUID extension
	r := signedEnrollResult(t, pki, testAuthData(testAAGUID()), []byte("client-data-hash"))

	if err := verifyGenuineHardware(r, pki.roots); err != nil {
		t.Errorf("verifyGenuineHardware() = %v, want nil", err)
	}
}

// The certificate carries an AAGUID but the authenticator data is too short to
// hold one: refuse rather than index out of bounds.
func TestAttestationRefusesShortAuthenticatorData(t *testing.T) {
	aaguid := testAAGUID()
	pki := newTestPKI(t, aaguid)
	r := signedEnrollResult(t, pki, []byte("far too short"), []byte("client-data-hash"))

	if err := verifyGenuineHardware(r, pki.roots); !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("verifyGenuineHardware() = %v, want ErrUntrustedAuthenticator", err)
	}
}

// The bundled PEMs must actually parse into certificates.  If a file were
// truncated, corrupted by a line-ending rewrite, or emptied, the pool would be
// silently empty and every enrollment would fail with a confusing chain error --
// or, far worse, a future refactor that treated an empty pool as "no policy"
// would accept anything.
func TestBundledRootsAndIntermediatesParse(t *testing.T) {
	roots := parsePEMCertificates(trustedAttestationRootsPEM)
	if len(roots) == 0 {
		t.Fatal("the bundled roots PEM parsed to zero certificates")
	}
	for _, c := range roots {
		if !c.IsCA {
			t.Errorf("bundled root %q is not a CA", c.Subject.CommonName)
		}
	}

	intermediates := fidoIntermediates()
	if len(intermediates) == 0 {
		t.Fatal("the bundled intermediates PEM parsed to zero certificates")
	}

	if pool := trustedFIDORoots(); pool == nil {
		t.Fatal("trustedFIDORoots() = nil")
	}
	t.Logf("bundled: %d roots, %d intermediates", len(roots), len(intermediates))
}

// BundledRoots must hand back a copy.  If it returned the singleton, a caller
// adding their own vendor's root -- the documented way to trust a second vendor --
// would mutate the default pool for every other vault in the process.
func TestBundledRootsReturnsACopy(t *testing.T) {
	before := BundledRoots()
	countBefore := len(before.Subjects()) //nolint:staticcheck // Subjects is fine for a count in a test

	// A caller extends their copy, as the documentation tells them to.
	extended := BundledRoots()
	pki := newTestPKI(t, testAAGUID())
	extended.AddCert(pki.rootCert)

	after := BundledRoots()
	if got, want := len(after.Subjects()), countBefore; got != want { //nolint:staticcheck
		t.Errorf("the default pool changed after a caller extended their copy: %d roots, want %d", got, want)
	}

	// And the extension really did work on the caller's copy: a credential from
	// the test PKI verifies against it, and not against the default.
	aaguid := testAAGUID()
	r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))

	if err := verifyGenuineHardware(r, extended); err != nil {
		t.Errorf("verifyGenuineHardware(extended pool) = %v, want nil", err)
	}
	if err := verifyGenuineHardware(r, BundledRoots()); !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("verifyGenuineHardware(default pool) = %v, want ErrUntrustedAuthenticator", err)
	}
}

// A nil pool means the bundled roots, never "trust anything".  There must be no
// value of Options.Roots that disables attestation.
func TestNilRootsMeansBundledNotDisabled(t *testing.T) {
	pki := newTestPKI(t, testAAGUID())
	aaguid := testAAGUID()
	r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))

	// The test PKI is not Yubico, so against the default it must be refused.
	if err := verifyGenuineHardware(r, nil); !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("verifyGenuineHardware(nil roots) = %v, want ErrUntrustedAuthenticator", err)
	}
}

// An empty pool must refuse everything, not accept everything.
func TestEmptyRootsRefusesEverything(t *testing.T) {
	pki := newTestPKI(t, testAAGUID())
	aaguid := testAAGUID()
	r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))

	if err := verifyGenuineHardware(r, x509.NewCertPool()); !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("verifyGenuineHardware(empty pool) = %v, want ErrUntrustedAuthenticator", err)
	}
}

// The failure message must name the chain and the anchors, or an operator with a
// genuine key that will not enroll has nothing to go on.
func TestUntrustedErrorDescribesTheChain(t *testing.T) {
	pki := newTestPKI(t, testAAGUID())
	aaguid := testAAGUID()
	r := signedEnrollResult(t, pki, testAuthData(aaguid), []byte("client-data-hash"))

	err := verifyGenuineHardware(r, x509.NewCertPool())
	if err == nil {
		t.Fatal("verifyGenuineHardware() = nil, want an error")
	}
	for _, want := range []string{"Test Vendor Authenticator", "attestation chain presented by the key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message does not mention %q:\n%s", want, err)
		}
	}
}
