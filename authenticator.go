// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import "time"

// SaltLen is the salt size CTAP2 requires for hmac-secret.
const SaltLen = 32

// DefaultTimeout bounds how long the platform waits for the operator.  It is
// generous: a PIN prompt plus locating the key on a keychain is not fast.
const DefaultTimeout = 60 * time.Second

// UserVerification says whether the platform must verify the operator with a
// PIN or biometric, beyond the physical touch that proves presence.
//
// # This is not a preference, it selects a secret
//
// CTAP2 authenticators keep two independent per-credential secrets:
// CredRandomWithUV and CredRandomWithoutUV.  The same salt yields a different
// output depending on whether verification occurred.  A vault enrolled under
// one setting and unlocked under the other derives a valid-looking key that
// decrypts nothing.
//
// Worse, the request is advisory.  Windows performs verification for
// hmac-secret whenever the key has a PIN set, even when asked for
// [UVDiscouraged].  So touchvault records what the authenticator reported in
// [DeriveResult.UserVerified] — never what it asked for — and requests that
// same value forever after, so a change in the platform's behavior surfaces as
// [ErrUserVerificationMismatch] rather than as corrupt ciphertext.
type UserVerification int

const (
	// UVDiscouraged asks for presence only.  The platform may verify anyway.
	UVDiscouraged UserVerification = iota

	// UVRequired demands verification.  On a key with no PIN set, the platform
	// may walk the operator through creating one — a device-wide change
	// affecting every other service enrolled on that key.  Never request this
	// without knowing a PIN already exists.
	UVRequired
)

// String implements [fmt.Stringer].
func (uv UserVerification) String() string {
	if uv == UVRequired {
		return "required"
	}
	return "discouraged"
}

// Authenticator is a FIDO2 security key that can create credentials and derive
// hmac-secret outputs.
//
// touchvault never talks to hardware directly.  This is the port: a provider
// (for example touchvault/fido) implements it against a platform FIDO2 stack,
// and a fake implementation reaches every function in this library, so the
// whole package tests on every platform with no key present.
//
// # Never call a real one from a test or an agent
//
// Every method blocks on a physical gesture.  A key that blinks during
// `go test ./...` teaches the operator to touch it without reading the prompt,
// which destroys the only thing the touch was ever worth.  A provider is
// expected to refuse to open under a test binary or a coding agent's shell;
// tests inject a fake.
//
// # Context is deliberately absent
//
// The platform owns the modal dialog and its cancellation.  A Go context could
// not interrupt it without leaving the operating system's prompt on screen.
// Bound the wait with Timeout instead.
type Authenticator interface {
	// Enroll creates a credential.  It costs one gesture.
	Enroll(req EnrollRequest) (EnrollResult, error)

	// Derive computes hmac-secret over req.Salt.  It costs one gesture.
	Derive(req DeriveRequest) (DeriveResult, error)
}

// EnrollRequest creates a new non-discoverable credential.
//
// # Non-discoverable only
//
// Nothing is stored on the key.  The credential ID in [EnrollResult] is the
// vault's to persist, and it is required to derive again; the sealed vault
// carries it.  This keeps the key's passkey storage — and whatever the
// operator has enrolled there for other services — untouched.
type EnrollRequest struct {
	// RPID scopes the credential.  WebAuthn isolates credentials by relying
	// party, so a credential made here can never be seen by, nor see, the
	// operator's other credentials on the same key.
	RPID   string
	RPName string

	// UserID is an opaque handle.  It is not stored on the key for a
	// non-discoverable credential, but the platform requires one.
	UserID   []byte
	UserName string

	UV      UserVerification
	Timeout time.Duration
}

// EnrollResult is what the authenticator produced.
//
// # The provider does not judge the attestation
//
// A provider returns whatever attestation material the platform gave it and
// makes no trust decision.  The core verifies it against Options.Roots.  That
// keeps the required trust policy in one portable, testable place, and means a
// new provider cannot quietly ship a weaker one.
type EnrollResult struct {
	// CredentialID must be persisted as raw bytes.  Encoding is the
	// implementation's business: at least one library round-trips it through
	// padded base64 and would corrupt an unpadded form.
	CredentialID []byte

	// PRFEnabled is what the platform reported at creation.  It is advisory:
	// Windows has been seen to report false on credentials that then derive
	// successfully.  Only a real Derive settles it.
	PRFEnabled bool

	// ResidentKey must be false.  True means the key consumed a passkey slot.
	ResidentKey bool

	// AttestationFormat names the attestation statement format.  Only "packed"
	// is accepted, which keeps this package free of CBOR: the platform decodes
	// the statement, and packed signs AuthenticatorData || ClientDataHash.
	AttestationFormat string

	// AttestationAlg is the COSE algorithm identifier of AttestationSignature.
	AttestationAlg int32

	// AttestationSignature is the signature over
	// AuthenticatorData || ClientDataHash, made by the key whose public key is
	// certified by AttestationCerts[0].
	AttestationSignature []byte

	// AuthenticatorData is the signed authenticator data for the new
	// credential.  It is the first half of the attestation signing input.
	AuthenticatorData []byte

	// ClientDataHash is the hash of the client data the platform signed over.
	// It is the second half of the attestation signing input.
	ClientDataHash []byte

	// AttestationCerts is the certificate chain, DER-encoded, leaf first.  An
	// empty chain means the credential is self-attested or unattested, and
	// enrollment refuses it with [ErrNoAttestation].
	AttestationCerts [][]byte
}

// DeriveRequest asks the authenticator to compute hmac-secret over a salt.  It
// costs one touch, and one PIN entry when verification is performed.
type DeriveRequest struct {
	RPID string

	// CredentialIDs is an allow-list.  The platform selects whichever
	// credential belongs to a key the operator actually presents, and
	// [DeriveResult.CredentialID] says which one answered.
	//
	// This is how a primary and a backup key coexist without asking the
	// operator which one they are holding, and without spending a gesture per
	// candidate.  A credential the present key does not hold is simply not
	// selected.
	CredentialIDs [][]byte

	// Salt is the hmac-secret input, exactly [SaltLen] bytes.  Every credential
	// in the allow-list is offered the same salt; each derives a different
	// secret from it, because the secret is per-credential.
	Salt    []byte
	UV      UserVerification
	Timeout time.Duration
}

// DeriveResult carries the derived secret and what the authenticator actually
// did, read from its signed authenticator data.
type DeriveResult struct {
	// Secret is key material.  Never log it, never write it to disk.
	Secret []byte

	// CredentialID identifies which credential produced Secret, and so which of
	// several enrolled keys the operator presented.
	CredentialID []byte

	// UserPresent reports a touch.  This is the presence proof.
	UserPresent bool

	// UserVerified reports a PIN or biometric check.  It is ground truth, not
	// an echo of the request, and it selects which of the two per-credential
	// secrets produced Secret.
	UserVerified bool
}

// validate is shared by every implementation so the checks cannot drift.
func (r DeriveRequest) validate() error {
	if len(r.CredentialIDs) == 0 {
		return ErrNoCredentialID
	}
	for _, id := range r.CredentialIDs {
		if len(id) == 0 {
			return ErrNoCredentialID
		}
	}
	if len(r.Salt) != SaltLen {
		return ErrSaltLength
	}
	return nil
}

func (r DeriveRequest) timeout() time.Duration { return orDefault(r.Timeout) }
func (r EnrollRequest) timeout() time.Duration { return orDefault(r.Timeout) }

func orDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTimeout
	}
	return d
}
