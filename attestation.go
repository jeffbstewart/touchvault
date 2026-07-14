// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

// Enrollment attestation: proof that a newly created credential lives on genuine
// hardware, not a software or virtual authenticator whose key could be exported
// or cloned.
//
// Without it, an attacker positioned at enrollment could substitute a software
// authenticator and later reproduce the derived secret off-device -- and the
// whole premise of this library, that reading a secret costs a human touch,
// would be false while every test still passed.  A software authenticator
// touches itself.
//
// The check is: the attestation's certificate chain must terminate at a trusted
// hardware-vendor root, and the attestation signature must verify over this
// credential's authenticator data, so a genuine certificate cannot be replayed
// for a credential it did not attest.
//
// # Verification lives here, in the core, not in a provider
//
// A provider returns the raw attestation material in EnrollResult and makes no
// trust decision.  That puts the required policy in one portable, testable place
// -- reachable by a fake, on every platform -- and means a future provider cannot
// quietly ship a weaker one.  A trust decision is not a transport concern.
//
// # Only "packed"
//
// Its signature is over authenticatorData || clientDataHash, which needs no
// parsing of the credential public key -- so this stays free of CBOR entirely.
// The platform decodes the attestation object; this file verifies certificates
// and one signature with the standard library.  Other formats (fido-u2f, tpm,
// none, apple) are refused rather than mis-verified.  Refusing a format we
// cannot check is the whole point: a format we merely tolerate is an opt-out
// with extra steps.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
)

//go:embed roots/yubico_fido_roots.pem
var trustedAttestationRootsPEM []byte

//go:embed roots/yubico_fido_intermediates.pem
var attestationIntermediatesPEM []byte

var (
	attestationRootsOnce sync.Once
	attestationRoots     *x509.CertPool

	attestationIntermediatesOnce sync.Once
	attestationIntermediates     []*x509.Certificate
)

// coseAlgES256 is the COSE algorithm identifier for ECDSA with P-256 and
// SHA-256, the only attestation signature algorithm accepted.
const coseAlgES256 = -7

// packedFormat is the only attestation statement format accepted.
const packedFormat = "packed"

// oidFidoGenCeAAGUID is the certificate extension carrying the authenticator's
// model identifier (AAGUID).  When present it must match the AAGUID in the
// signed authenticator data, so a certificate cannot vouch for a different model
// than the one that actually answered.
var oidFidoGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// BundledRoots returns the attestation trust anchors this package ships: the
// Yubico FIDO roots.
//
// Use it to *extend* the default rather than replace it — to trust a second
// vendor's hardware, add that vendor's root to this pool and pass the result as
// [Options.Roots]:
//
//	roots := touchvault.BundledRoots()
//	roots.AddCert(otherVendorRoot)
//	opts.Roots = roots
//
// Each call returns a fresh copy, so adding to the returned pool cannot mutate
// the default that every other vault relies on.
func BundledRoots() *x509.CertPool {
	return trustedFIDORoots().Clone()
}

// verifyGenuineHardware confirms the credential was created on hardware whose
// attestation chains to one of roots, and whose signature covers this exact
// credential.
//
// roots is a parameter, never a global read: it is how [Options.Roots] chooses
// whom to trust, and how a test supplies its own anchor.  Nil means the bundled
// roots.  There is no value of roots that means "trust anything" — attestation
// is required and this function is the only door.
func verifyGenuineHardware(r EnrollResult, roots *x509.CertPool) error {
	if roots == nil {
		roots = trustedFIDORoots()
	}
	if r.AttestationFormat != packedFormat {
		return fmt.Errorf("%w: %q", ErrUnsupportedAttestationFormat, r.AttestationFormat)
	}
	if len(r.AttestationCerts) == 0 {
		return ErrNoAttestation
	}
	if r.AttestationAlg != coseAlgES256 {
		return fmt.Errorf("%w: unsupported attestation algorithm %d", ErrAttestationSignature, r.AttestationAlg)
	}

	leaf, err := x509.ParseCertificate(r.AttestationCerts[0])
	if err != nil {
		return fmt.Errorf("touchvault: parsing attestation certificate: %w", err)
	}

	// The intermediate pool is the bundled vendor intermediates plus whatever the
	// x5c carried, so a chain can be built even when the key ships only the leaf.
	// Modern YubiKeys do not sign the device certificate directly with a root.
	intermediates := x509.NewCertPool()
	for _, c := range fidoIntermediates() {
		intermediates.AddCert(c)
	}
	for _, der := range r.AttestationCerts[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("touchvault: parsing attestation intermediate: %w", err)
		}
		intermediates.AddCert(c)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// Attestation certificates are not TLS certificates; do not require a
		// server-auth EKU.  The chain of trust to a hardware root is the point.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("%w: %v\n%s", ErrUntrustedAuthenticator, err, describeAttestation(r.AttestationCerts))
	}

	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: attestation certificate is not ECDSA", ErrAttestationSignature)
	}

	// packed signs authenticatorData || clientDataHash.  Binding the signature to
	// this credential's authenticator data is what stops a genuine certificate,
	// lifted from another credential, being replayed for one it never attested.
	signed := make([]byte, 0, len(r.AuthenticatorData)+len(r.ClientDataHash))
	signed = append(signed, r.AuthenticatorData...)
	signed = append(signed, r.ClientDataHash...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], r.AttestationSignature) {
		return ErrAttestationSignature
	}

	return checkAAGUIDMatches(leaf, r.AuthenticatorData)
}

// checkAAGUIDMatches enforces the certificate's AAGUID extension against the
// AAGUID in the signed authenticator data, when the extension is present.
//
// An absent extension is allowed — not every attestation certificate carries one
// — but a present-and-mismatched one is refused: a certificate must not vouch for
// a different authenticator model than the one that actually answered.
func checkAAGUIDMatches(leaf *x509.Certificate, authData []byte) error {
	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidFidoGenCeAAGUID) {
			ext = e.Value
			break
		}
	}
	if ext == nil {
		return nil
	}

	// The extension value is an OCTET STRING wrapping the 16-byte AAGUID.
	var certAAGUID []byte
	if _, err := asn1.Unmarshal(ext, &certAAGUID); err != nil {
		return fmt.Errorf("%w: malformed AAGUID extension: %v", ErrUntrustedAuthenticator, err)
	}

	// authenticatorData: rpIdHash(32) flags(1) signCount(4), then the attested
	// credential data, which begins with the 16-byte AAGUID.
	const aaguidStart, aaguidEnd = 37, 53
	if len(authData) < aaguidEnd {
		return fmt.Errorf("%w: authenticator data too short to carry an AAGUID", ErrUntrustedAuthenticator)
	}
	if !bytes.Equal(certAAGUID, authData[aaguidStart:aaguidEnd]) {
		return fmt.Errorf("%w: certificate AAGUID does not match the credential", ErrUntrustedAuthenticator)
	}
	return nil
}

// trustedFIDORoots is the embedded pool of hardware-vendor attestation roots.
// It is a singleton; callers who want to extend it use [BundledRoots], which
// clones.
func trustedFIDORoots() *x509.CertPool {
	attestationRootsOnce.Do(func() {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(trustedAttestationRootsPEM)
		attestationRoots = pool
	})
	return attestationRoots
}

// fidoIntermediates is the embedded set of vendor intermediate CAs, used to
// bridge a leaf to a trusted root when the key did not present the full chain.
// They are intermediates, never trust anchors: a credential that chains only to
// one of these, and no further, does not verify.
func fidoIntermediates() []*x509.Certificate {
	attestationIntermediatesOnce.Do(func() {
		attestationIntermediates = parsePEMCertificates(attestationIntermediatesPEM)
	})
	return attestationIntermediates
}

func parsePEMCertificates(pemBytes []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	return certs
}

// describeAttestation renders the chain a key presented and the anchors it was
// checked against, so a chain that does not verify can be diagnosed from the
// error alone rather than guessed at.
//
// It names subjects and issuers.  A certificate is public material and an
// enrollment failure is not a secret; the alternative is an operator holding a
// genuine key that will not enroll and no way to see why.
func describeAttestation(certs [][]byte) string {
	var b strings.Builder
	b.WriteString("  attestation chain presented by the key:\n")
	for i, der := range certs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			fmt.Fprintf(&b, "    [%d] unparseable: %v\n", i, err)
			continue
		}
		fmt.Fprintf(&b, "    [%d] subject=%q issuer=%q notAfter=%s\n",
			i, c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"))
	}
	b.WriteString("  trusted roots: ")
	b.WriteString(strings.Join(commonNames(parsePEMCertificates(trustedAttestationRootsPEM)), ", "))
	b.WriteString("\n  bundled intermediates: ")
	b.WriteString(strings.Join(commonNames(fidoIntermediates()), ", "))
	return b.String()
}

func commonNames(certs []*x509.Certificate) []string {
	names := make([]string, 0, len(certs))
	for _, c := range certs {
		names = append(names, fmt.Sprintf("%q", c.Subject.CommonName))
	}
	return names
}
