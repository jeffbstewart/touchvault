// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

//go:build windows

// Package winwebauthn is the entire foreign-function boundary to Windows'
// webauthn.dll. It exposes only safe Go types; no pointer into memory the DLL
// owns escapes this package.
//
// Review map:
//   - consts_windows.go, types_windows.go: constants and WEBAUTHN_* struct
//     layouts. No `unsafe`. Check these against Microsoft's webauthn.h.
//   - syscall_windows.go: the only file that imports `unsafe`. Check pointer
//     liveness, immediate copy-out of results, and deferred free calls.
//
// "WebAuthn" is Web Authentication; "CTAP2" is Client To Authenticator Protocol
// 2; "RP" is Relying Party; "PRF" is the pseudo-random function extension,
// which at the CTAP2 layer is called hmac-secret.
package winwebauthn

// Algorithm and type identifiers.
const (
	hashAlgorithmSHA256     = "SHA-256"
	credentialTypePublicKey = "public-key"
	// COSE (CBOR Object Signing and Encryption) algorithm for ECDSA with the
	// P-256 curve and SHA-256. The only algorithm we register.
	coseAlgorithmES256 = -7
)

// Authenticator attachment. Cross-platform means a removable key, never the
// platform authenticator (Windows Hello or the Trusted Platform Module).
const (
	attachmentCrossPlatform = 2
)

// User-verification requirement.
const (
	userVerificationAny         = 0
	userVerificationRequired    = 1
	userVerificationPreferred   = 2
	userVerificationDiscouraged = 3
)

// Attestation conveyance. We ask for direct attestation so the authenticator
// returns its attestation statement, which enrollment verifies to confirm the
// credential is on genuine hardware.
const (
	attestationConveyanceDirect = 3
)

// Attestation decode type reported on the make-credential result. The DLL
// decodes packed/fido-u2f/tpm statements into a WEBAUTHN_COMMON_ATTESTATION for
// us; COMMON means that struct is populated (no CBOR parsing on our side).
const (
	attestationDecodeNone   = 0
	attestationDecodeCommon = 1
)

// The hmac-secret extension identifier, and the flag that tells GetAssertion to
// return raw hmac-secret values rather than the browser-style PRF outputs.
const (
	extensionIdentifierHMACSecret = "hmac-secret"
	// WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG.
	assertionHMACSecretValuesFlag = 0x00100000
	// CTAP2 fixes hmac-secret salts and outputs at 32 bytes.
	hmacSecretLength = 32
)

// Allow-list transport mask. Zero means "any transport", so an enrolled key
// answers however it is presented — USB, NFC, or a future one. Naming a single
// transport here would silently stop a key on a different one from being
// selected, which reads to the operator as "the key does not answer".
const (
	transportAny = 0x00000000
)

// Structure versions. The DLL reads only as many fields as the version
// declares, so each struct we pass sets dwVersion and we define exactly the
// fields through that version.
//
// VERIFY these against webauthn.h. The get-assertion salt-values field in
// particular sits at a specific, recent version; if it is wrong the salt is
// silently not applied and no hmac-secret comes back.
const (
	rpEntityInformationVersion     = 1
	userEntityInformationVersion   = 1
	clientDataVersion              = 1
	coseCredentialParameterVersion = 1
	credentialExVersion            = 1

	// WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1 carries the
	// Extensions array, which is how hmac-secret is requested at creation, so
	// version 1 suffices for make.
	makeCredentialOptionsVersion = 1

	// bResidentKey appears in WEBAUTHN_CREDENTIAL_ATTESTATION at version 3. The
	// DLL sets dwVersion to what it filled; the resident-key field is read only
	// when the reported version is at least this, so an older DLL is never read
	// past its allocation.
	credentialAttestationVersionResidentKey = 3

	// Get-assertion options versions. Version 6 carries pHmacSecretSaltValues
	// (required for derivation); version 7 additionally carries the credential
	// hints, which is how "security-key" suppresses the phone/hybrid chooser.
	// Version 7 needs webauthn.dll API version 7 or later.
	getAssertionOptionsVersionSalt  = 6
	getAssertionOptionsVersionHints = 7
	apiVersionForHints              = 7
)

// credentialHintSecurityKey tells the platform to prefer a removable security
// key, suppressing the "iPhone / iPad / Android" hybrid-transport chooser.
const credentialHintSecurityKey = "security-key"
