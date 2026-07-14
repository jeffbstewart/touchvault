// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

//go:build windows

package winwebauthn

// WEBAUTHN_* structure layouts for amd64, transcribed from Microsoft's
// webauthn.h. This file imports no `unsafe`; it only declares types.
//
// LAYOUT DISCIPLINE. Every field's order and width must match the C header
// exactly. Data-carrying pointer fields are declared as real Go pointers
// (*byte, *uint16, *someStruct) so the garbage collector keeps the pointed-to
// memory alive while the containing struct is reachable. Fields we never
// populate are declared `uintptr` and left zero — a null pointer, with no GC
// concern precisely because zero points at nothing.
//
// The two comments marked "HIGH RISK" are the layouts most likely to be wrong
// and most damaging if they are: a wrong offset there means the hmac-secret
// salt is not applied, or its result is read from the wrong address. key-probe
// validates them on real hardware; until it passes, trust nothing here.

// PCWSTR pwszId; etc. — UTF-16 string pointers are *uint16.

type rpEntityInformation struct {
	version uint32  // dwVersion
	id      *uint16 // pwszId
	name    *uint16 // pwszName
	icon    uintptr // pwszIcon — null
}

type userEntityInformation struct {
	version     uint32  // dwVersion
	idLen       uint32  // cbId
	id          *byte   // pbId
	name        *uint16 // pwszName
	icon        uintptr // pwszIcon — null
	displayName *uint16 // pwszDisplayName
}

type coseCredentialParameter struct {
	version        uint32  // dwVersion
	credentialType *uint16 // pwszCredentialType
	alg            int32   // lAlg (LONG)
}

type coseCredentialParameters struct {
	count      uint32                   // cCredentialParameters
	parameters *coseCredentialParameter // pCredentialParameters
}

type clientData struct {
	version   uint32  // dwVersion
	jsonLen   uint32  // cbClientDataJSON
	json      *byte   // pbClientDataJSON
	hashAlgID *uint16 // pwszHashAlgId
}

type extension struct {
	identifier *uint16 // pwszExtensionIdentifier
	valueLen   uint32  // cbExtension
	value      *byte   // pvExtension
}

type extensions struct {
	count      uint32     // cExtensions
	extensions *extension // pExtensions
}

// credentials is the older (v1) credential list, embedded in the options
// structs. We leave it empty and use the newer credentialList instead.
type credentials struct {
	count       uint32  // cCredentials
	credentials uintptr // pCredentials — null
}

type credentialEx struct {
	version        uint32  // dwVersion
	idLen          uint32  // cbId
	id             *byte   // pbId
	credentialType *uint16 // pwszCredentialType
	transports     uint32  // dwTransports
}

// credentialList is the newer allow-list: a pointer to an array of *credentialEx.
type credentialList struct {
	count       uint32         // cCredentials
	credentials **credentialEx // ppCredentials
}

// --- hmac-secret salt input ------------------------------------------------

type hmacSecretSalt struct {
	firstLen  uint32  // cbFirst
	first     *byte   // pbFirst
	secondLen uint32  // cbSecond — 0
	second    uintptr // pbSecond — null
}

type hmacSecretSaltValues struct {
	globalSalt *hmacSecretSalt // pGlobalHmacSalt
	listCount  uint32          // cCredWithHmacSecretSaltList — 0
	list       uintptr         // pCredWithHmacSecretSaltList — null
}

// --- make-credential options (version 1) -----------------------------------

type makeCredentialOptions struct {
	version                 uint32      // dwVersion
	timeoutMilliseconds     uint32      // dwTimeoutMilliseconds
	excludeCredentials      credentials // CredentialList (embedded, empty)
	ext                     extensions  // Extensions (embedded)
	authenticatorAttachment uint32      // dwAuthenticatorAttachment
	requireResidentKey      int32       // bRequireResidentKey (BOOL)
	userVerificationReq     uint32      // dwUserVerificationRequirement
	attestationConveyance   uint32      // dwAttestationConveyancePreference
	flags                   uint32      // dwFlags
}

// --- get-assertion options (version 6) -------------------------------------
//
// HIGH RISK. pHmacSecretSaltValues sits at version 6; the version constant and
// the field offsets below (through the v5 large-blob fields) must match
// webauthn.h, or the salt is silently not applied and no hmac-secret returns.
type getAssertionOptions struct {
	version                 uint32                // dwVersion
	timeoutMilliseconds     uint32                // dwTimeoutMilliseconds
	allowCredentials        credentials           // CredentialList (embedded, empty)
	ext                     extensions            // Extensions (embedded, empty)
	authenticatorAttachment uint32                // dwAuthenticatorAttachment
	userVerificationReq     uint32                // dwUserVerificationRequirement
	flags                   uint32                // dwFlags
	u2fAppID                uintptr               // pwszU2fAppId (v2) — null
	u2fAppIDUsed            uintptr               // pbU2fAppId (v2) — null
	cancellationID          uintptr               // pCancellationId (v3) — null
	allowCredentialList     *credentialList       // pAllowCredentialList (v4)
	credLargeBlobOperation  uint32                // dwCredLargeBlobOperation (v5)
	credLargeBlobLen        uint32                // cbCredLargeBlob (v5)
	credLargeBlob           uintptr               // pbCredLargeBlob (v5) — null
	hmacSecretSaltValues    *hmacSecretSaltValues // pHmacSecretSaltValues (v6)
	browserInPrivateMode    int32                 // bBrowserInPrivateMode (v6)
	// Version 7 tail. The DLL reads only through the version we set, so these
	// are read only when the options version is 7; at version 6 they are unread
	// zero padding. Order matches webauthn.h.
	linkedDevice         uintptr  // pLinkedDevice — null
	autoFill             int32    // bAutoFill
	jsonExtLen           uint32   // cbJsonExt
	jsonExt              uintptr  // pbJsonExt — null
	credentialHintsCount uint32   // cCredentialHints
	credentialHints      **uint16 // ppwszCredentialHints
}

// --- outputs ---------------------------------------------------------------

type credential struct {
	version        uint32  // dwVersion
	idLen          uint32  // cbId
	id             *byte   // pbId
	credentialType *uint16 // pwszCredentialType
}

// credentialAttestation is the make-credential result. We read the credential
// identifier, the signed authenticator data, the resident-key flag, and (via
// the decoded pvAttestationDecode) the attestation format, signature, and x5c
// chain that enrollment verifies.
//
// Verified against webauthn.h after the first hardware run read the credential
// id from the wrong offset: dwAttestationDecodeType is followed by a PVOID
// pvAttestationDecode (omitted in the first draft), and the attestation object
// is (cbAttestationObject, pbAttestationObject) in that order (reversed in the
// first draft). Both errors shifted pbCredentialId by 16 bytes.
//
// The version-2 and version-3 trailing fields are declared so bResidentKey can
// be read back and enforced (a resident credential would consume a passkey
// slot). They are read ONLY when dwVersion reports at least the version that
// introduced them, so an older DLL that allocated a shorter structure is never
// read past its allocation. Version-4 fields (unsigned extension outputs) are
// still not declared; we never read them.
type credentialAttestation struct {
	version               uint32             // dwVersion
	formatType            *uint16            // pwszFormatType
	authenticatorDataLen  uint32             // cbAuthenticatorData
	authenticatorData     *byte              // pbAuthenticatorData
	attestationLen        uint32             // cbAttestation
	attestation           *byte              // pbAttestation
	attestationDecodeType uint32             // dwAttestationDecodeType
	attestationDecode     *commonAttestation // pvAttestationDecode — valid only when decodeType is COMMON
	attestationObjectLen  uint32             // cbAttestationObject
	attestationObject     *byte              // pbAttestationObject
	credentialIDLen       uint32             // cbCredentialId
	credentialID          *byte              // pbCredentialId
	ext                   extensions         // Extensions (embedded) — end of version 1
	usedTransport         uint32             // dwUsedTransport (v2)
	epAtt                 int32              // bEpAtt (BOOL, v3)
	largeBlobSupported    int32              // bLargeBlobSupported (BOOL, v3)
	residentKey           int32              // bResidentKey (BOOL, v3)
}

// commonAttestation is WEBAUTHN_COMMON_ATTESTATION, the DLL's decoded form of a
// packed/fido-u2f/tpm attestation statement. We read the algorithm, signature,
// and x5c certificate chain; the TPM-only trailing fields are declared to keep
// the layout correct but are not read.
type commonAttestation struct {
	version      uint32    // dwVersion
	alg          *uint16   // pwszAlg (LPCWSTR) — unused; lAlg is authoritative
	algID        int32     // lAlg (LONG)
	signatureLen uint32    // cbSignature
	signature    *byte     // pbSignature
	x5cCount     uint32    // cX5c
	x5c          *x5cEntry // pX5c — array of x5cCount entries
	ver          *uint16   // pwszVer (tpm) — unused
	certInfoLen  uint32    // cbCertInfo (tpm) — unused
	certInfo     *byte     // pbCertInfo (tpm) — unused
	pubAreaLen   uint32    // cbPubArea (tpm) — unused
	pubArea      *byte     // pbPubArea (tpm) — unused
}

// x5cEntry is WEBAUTHN_X5C, one DER certificate in the attestation chain.
type x5cEntry struct {
	dataLen uint32 // cbData
	data    *byte  // pbData
}

// assertion is the get-assertion result.
//
// HIGH RISK for the hmacSecret offset (version 3, offset ~112 on amd64): every
// preceding field, including the two embedded structs, must match webauthn.h.
type assertion struct {
	version              uint32          // dwVersion
	authenticatorDataLen uint32          // cbAuthenticatorData
	authenticatorData    *byte           // pbAuthenticatorData
	signatureLen         uint32          // cbSignature
	signature            *byte           // pbSignature
	credential           credential      // Credential (embedded, v?)
	userIDLen            uint32          // cbUserId
	userID               *byte           // pbUserId
	ext                  extensions      // Extensions (embedded, v2)
	credLargeBlobLen     uint32          // cbCredLargeBlob (v2)
	credLargeBlob        *byte           // pbCredLargeBlob (v2)
	credLargeBlobStatus  uint32          // dwCredLargeBlobStatus (v2)
	hmacSecret           *hmacSecretSalt // pHmacSecret (v3)
}
