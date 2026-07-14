// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import "errors"

// The sentinels below are API.  Callers distinguish failures with [errors.Is],
// so a change to which error a path returns is a breaking change.  Wrap them
// with %w; do not collapse two distinct failures into one.
//
// [ErrUserVerificationMismatch] deserves particular care: it must never reach a
// caller as a generic decryption failure.  The operator who cleared their key's
// PIN needs to be told that, not told their vault is corrupt.
var (
	// ErrNoSuchSecret means the vault holds no secret under that name.
	ErrNoSuchSecret = errors.New("touchvault: no secret by that name")

	// ErrSlotOccupied means EnrollKey was asked to enroll into a slot that
	// already holds a key.  Remove that key first, deliberately, rather than
	// have an enrollment silently displace a backup.
	ErrSlotOccupied = errors.New("touchvault: that key slot is already occupied")

	// ErrNoSuchSlot means the vault has no enrolled key in that slot.
	ErrNoSuchSlot = errors.New("touchvault: no key is enrolled in that slot")

	// ErrUnknownCredential means the security key presented is not enrolled in
	// this vault.  It is a real key that answered; it is simply not one of
	// ours.
	ErrUnknownCredential = errors.New("touchvault: the security key presented is not enrolled")

	// ErrUserVerificationMismatch means the authenticator verified the operator
	// differently than it did at enrollment, so it derived the other of its two
	// per-credential secrets.  The usual cause is a PIN added to, or cleared
	// from, the key after it was enrolled.  The vault is intact; the derivation
	// is not the one it was sealed under.
	ErrUserVerificationMismatch = errors.New("touchvault: user verification differs from enrollment")

	// ErrNotPresent means the authenticator did not assert user presence, so no
	// human touched the key.  Never assume presence that was not reported.
	ErrNotPresent = errors.New("touchvault: the authenticator did not report a human touch")

	// ErrDerivationIgnoresSalt means the authenticator returned the same
	// hmac-secret output for two salts that differ, so the full salt is not
	// reaching the key.  Enrollment refuses rather than seal a secret under a
	// key-encryption key with less entropy than intended.
	ErrDerivationIgnoresSalt = errors.New("touchvault: the security key's derivation did not depend on the full salt")

	// ErrNotEntropyVerified means a sealed vault carries no proof that its
	// derivation depends on the salt.  It cannot be trusted and must be
	// re-created.  This is checked before any touch is requested, so a vault
	// that never passed the gate cannot cost the operator a gesture.
	ErrNotEntropyVerified = errors.New("touchvault: this vault predates entropy verification and must be re-created")

	// ErrWrongFormat means the sealed bytes are not a format this code knows.
	ErrWrongFormat = errors.New("touchvault: sealed vault has an unrecognized format")
)

// Attestation sentinels.  Enrollment requires attestation and there is no
// opt-out: Options.Roots chooses whom to trust, never whether to.
var (
	// ErrNoAttestation means the authenticator returned no attestation
	// certificate chain (self-attestation, or none), so its hardware origin
	// cannot be established.
	ErrNoAttestation = errors.New("touchvault: credential carried no attestation certificate; refusing")

	// ErrUnsupportedAttestationFormat means the attestation is in a format this
	// code does not verify.  It is refused rather than trusted.
	ErrUnsupportedAttestationFormat = errors.New("touchvault: unsupported attestation format")

	// ErrUntrustedAuthenticator means the attestation certificate did not chain
	// to a trusted hardware-vendor root: the credential is not on a recognized
	// genuine authenticator.
	ErrUntrustedAuthenticator = errors.New("touchvault: attestation did not chain to a trusted authenticator root")

	// ErrAttestationSignature means the attestation signature did not verify
	// over this credential's authenticator data.
	ErrAttestationSignature = errors.New("touchvault: attestation signature is invalid")
)

// Authenticator-port sentinels.  A provider returns these; the core returns
// them from the shared request validation, so the checks cannot drift between
// implementations.
var (
	// ErrNoPRF means the authenticator returned no hmac-secret output.  The key
	// does not implement the extension, or not for this credential.
	ErrNoPRF = errors.New("touchvault: authenticator returned no hmac-secret output")

	// ErrNoAuthenticatorData means the assertion carried no signed flags, so
	// whether the operator was present cannot be established.  Never assume.
	ErrNoAuthenticatorData = errors.New("touchvault: assertion carried no authenticator data")

	// ErrSaltLength means a salt was not exactly [SaltLen] bytes.
	ErrSaltLength = errors.New("touchvault: salt must be exactly 32 bytes")

	// ErrNoCredentialID means Derive was called without a credential ID.
	ErrNoCredentialID = errors.New("touchvault: credential ID is required")
)
