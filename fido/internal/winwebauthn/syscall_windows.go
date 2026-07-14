// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

//go:build windows

package winwebauthn

// The ONLY file in this program that imports `unsafe`. Review it for three
// things and nothing else:
//
//  1. Pointer liveness. Every uintptr(unsafe.Pointer(&x)) appears INSIDE the
//     proc.Call(...) argument list, never assigned to a variable first, so the
//     runtime keeps x (and everything x points to, since input structs use
//     typed pointers) alive for the duration of the call. This is the exact
//     discipline the wincred bug violated.
//  2. Copy-out. Results the DLL allocates are copied into owned Go slices by
//     `asBytes` before the structure is freed. The returned slices never alias
//     DLL memory.
//  3. Frees. Every successful make/get defers the matching DLL free.

import (
	"crypto/sha256"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	webauthnDLL = windows.NewLazySystemDLL("webauthn.dll")
	kernel32DLL = windows.NewLazySystemDLL("kernel32.dll")

	procGetApiVersionNumber       = webauthnDLL.NewProc("WebAuthNGetApiVersionNumber")
	procMakeCredential            = webauthnDLL.NewProc("WebAuthNAuthenticatorMakeCredential")
	procGetAssertion              = webauthnDLL.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeCredentialAttestation = webauthnDLL.NewProc("WebAuthNFreeCredentialAttestation")
	procFreeAssertion             = webauthnDLL.NewProc("WebAuthNFreeAssertion")

	procGetConsoleWindow = kernel32DLL.NewProc("GetConsoleWindow")
)

// asBytes copies n bytes from a DLL-owned pointer into an owned Go slice. It is
// the only use of unsafe.Slice; the copy is what lets the caller keep the bytes
// after the structure is freed.
func asBytes(p *byte, n uint32) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(p, n)...)
}

// ConsoleWindow returns a window handle to own the OS prompt. Zero is
// acceptable to the WebAuthn API (it falls back to the foreground window).
func ConsoleWindow() uintptr {
	h, _, _ := procGetConsoleWindow.Call()
	return h
}

// APIVersion returns webauthn.dll's API version number.
func APIVersion() uint32 {
	v, _, _ := procGetApiVersionNumber.Call()
	return uint32(v)
}

func uvRequirement(requireUserVerification bool) uint32 {
	if requireUserVerification {
		return userVerificationRequired
	}
	return userVerificationDiscouraged
}

// MakeCredentialRequest and result use only plain Go types.
type MakeCredentialRequest struct {
	WindowHandle            uintptr
	RPID, RPName            string
	UserID                  []byte
	UserName                string
	RequireUserVerification bool
	TimeoutMilliseconds     uint32
}

type MakeCredentialResult struct {
	CredentialID []byte

	// ResidentKey reports whether the authenticator stored the credential
	// (consuming a passkey slot). It is meaningful only when the attestation
	// reported version 3 or later; on an older DLL it is left false because the
	// state cannot be read, and ResidentKeyKnown says which case this is.
	ResidentKey      bool
	ResidentKeyKnown bool

	// AuthenticatorData is the signed authenticator data, needed to verify the
	// attestation signature (it is what the signature covers, together with the
	// client-data hash).
	AuthenticatorData []byte

	// Attestation fields, populated when the DLL returned a decoded common
	// attestation. AttestationFormat is the statement format ("packed", ...);
	// Certs is the x5c chain, leaf first.
	AttestationFormat    string
	AttestationAlg       int32
	AttestationSignature []byte
	AttestationCerts     [][]byte

	// ClientDataHash is SHA-256 of the client data the attestation signature
	// covers, computed from exactly the bytes handed to the DLL.
	ClientDataHash []byte
}

// MakeCredential creates a non-discoverable credential with the hmac-secret
// extension and returns its identifier. One gesture.
func MakeCredential(req MakeCredentialRequest) (MakeCredentialResult, error) {
	rpID, err := windows.UTF16PtrFromString(req.RPID)
	if err != nil {
		return MakeCredentialResult{}, err
	}
	rpName, err := windows.UTF16PtrFromString(req.RPName)
	if err != nil {
		return MakeCredentialResult{}, err
	}
	userName, err := windows.UTF16PtrFromString(req.UserName)
	if err != nil {
		return MakeCredentialResult{}, err
	}
	credType, err := windows.UTF16PtrFromString(credentialTypePublicKey)
	if err != nil {
		return MakeCredentialResult{}, err
	}
	hashAlg, err := windows.UTF16PtrFromString(hashAlgorithmSHA256)
	if err != nil {
		return MakeCredentialResult{}, err
	}
	hmacID, err := windows.UTF16PtrFromString(extensionIdentifierHMACSecret)
	if err != nil {
		return MakeCredentialResult{}, err
	}

	rp := rpEntityInformation{version: rpEntityInformationVersion, id: rpID, name: rpName}

	userID := req.UserID
	user := userEntityInformation{
		version:     userEntityInformationVersion,
		idLen:       uint32(len(userID)),
		id:          bytePtr(userID),
		name:        userName,
		displayName: userName,
	}

	param := coseCredentialParameter{
		version:        coseCredentialParameterVersion,
		credentialType: credType,
		alg:            coseAlgorithmES256,
	}
	params := coseCredentialParameters{count: 1, parameters: &param}

	cd := []byte("{}")
	client := clientData{
		version:   clientDataVersion,
		jsonLen:   uint32(len(cd)),
		json:      bytePtr(cd),
		hashAlgID: hashAlg,
	}

	// The hmac-secret request: a single extension whose value is a BOOL TRUE.
	hmacTrue := int32(1)
	ext := extension{
		identifier: hmacID,
		valueLen:   uint32(unsafe.Sizeof(hmacTrue)),
		value:      (*byte)(unsafe.Pointer(&hmacTrue)),
	}
	exts := extensions{count: 1, extensions: &ext}

	opts := makeCredentialOptions{
		version:                 makeCredentialOptionsVersion,
		timeoutMilliseconds:     req.TimeoutMilliseconds,
		ext:                     exts,
		authenticatorAttachment: attachmentCrossPlatform,
		requireResidentKey:      0,
		userVerificationReq:     uvRequirement(req.RequireUserVerification),
		attestationConveyance:   attestationConveyanceDirect,
		flags:                   0,
	}

	var out *credentialAttestation
	hr, _, _ := procMakeCredential.Call(
		req.WindowHandle,
		uintptr(unsafe.Pointer(&rp)),
		uintptr(unsafe.Pointer(&user)),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&client)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&out)),
	)
	if hr != 0 {
		return MakeCredentialResult{}, hresultError("MakeCredential", hr)
	}
	if out == nil {
		return MakeCredentialResult{}, fmt.Errorf("winwebauthn: MakeCredential returned no attestation")
	}
	defer procFreeCredentialAttestation.Call(uintptr(unsafe.Pointer(out)))

	clientDataHash := sha256.Sum256(cd)
	result := MakeCredentialResult{
		CredentialID:      asBytes(out.credentialID, out.credentialIDLen),
		AuthenticatorData: asBytes(out.authenticatorData, out.authenticatorDataLen),
		ClientDataHash:    clientDataHash[:],
	}
	// bResidentKey is only present from version 3; reading it on an older
	// structure would read past the DLL's allocation.
	if out.version >= credentialAttestationVersionResidentKey {
		result.ResidentKeyKnown = true
		result.ResidentKey = out.residentKey != 0
	}
	// The attestation is decoded by the DLL when present; copy the format,
	// signature, and x5c chain out of DLL memory before the deferred free.
	if out.attestationDecodeType == attestationDecodeCommon && out.attestationDecode != nil {
		att := out.attestationDecode
		if out.formatType != nil {
			result.AttestationFormat = windows.UTF16PtrToString(out.formatType)
		}
		result.AttestationAlg = att.algID
		result.AttestationSignature = asBytes(att.signature, att.signatureLen)
		if att.x5c != nil && att.x5cCount > 0 {
			for _, e := range unsafe.Slice(att.x5c, att.x5cCount) {
				result.AttestationCerts = append(result.AttestationCerts, asBytes(e.data, e.dataLen))
			}
		}
	}
	return result, nil
}

// GetAssertionRequest and result use only plain Go types.
type GetAssertionRequest struct {
	WindowHandle            uintptr
	RPID                    string
	CredentialIDs           [][]byte
	Salt                    []byte // exactly hmacSecretLength bytes
	RequireUserVerification bool
	TimeoutMilliseconds     uint32
}

type GetAssertionResult struct {
	AuthenticatorData   []byte
	AnsweringCredential []byte
	HMACSecret          []byte
}

// GetAssertion derives the hmac-secret over the salt against the allow-list.
// One gesture. It uses the raw hmac-secret salt API directly — no PRF prefix.
func GetAssertion(req GetAssertionRequest) (GetAssertionResult, error) {
	rpID, err := windows.UTF16PtrFromString(req.RPID)
	if err != nil {
		return GetAssertionResult{}, err
	}
	credType, err := windows.UTF16PtrFromString(credentialTypePublicKey)
	if err != nil {
		return GetAssertionResult{}, err
	}

	// Build the allow-list: an array of credentialEx and an array of pointers
	// to them, kept alive for the whole call.
	entries := make([]credentialEx, len(req.CredentialIDs))
	pointers := make([]*credentialEx, len(req.CredentialIDs))
	for i, id := range req.CredentialIDs {
		entries[i] = credentialEx{
			version:        credentialExVersion,
			idLen:          uint32(len(id)),
			id:             bytePtr(id),
			credentialType: credType,
			transports:     transportAny,
		}
		pointers[i] = &entries[i]
	}
	allow := credentialList{count: uint32(len(pointers)), credentials: pointerToPointers(pointers)}

	cd := []byte("{}")
	hashAlg, err := windows.UTF16PtrFromString(hashAlgorithmSHA256)
	if err != nil {
		return GetAssertionResult{}, err
	}
	client := clientData{version: clientDataVersion, jsonLen: uint32(len(cd)), json: bytePtr(cd), hashAlgID: hashAlg}

	salt := hmacSecretSalt{firstLen: uint32(len(req.Salt)), first: bytePtr(req.Salt)}
	saltValues := hmacSecretSaltValues{globalSalt: &salt}

	// Version 6 carries the salt; version 7 additionally lets us pass the
	// "security-key" hint that suppresses the phone/hybrid chooser. Use 7 only
	// when the OS supports it, so older Windows still derives (just with the
	// chooser). hintStorage is declared here so it stays alive across the call.
	optsVersion := uint32(getAssertionOptionsVersionSalt)
	var hintStorage []*uint16
	if APIVersion() >= apiVersionForHints {
		optsVersion = getAssertionOptionsVersionHints
		hint, herr := windows.UTF16PtrFromString(credentialHintSecurityKey)
		if herr != nil {
			return GetAssertionResult{}, herr
		}
		hintStorage = []*uint16{hint}
	}

	opts := getAssertionOptions{
		version:                 optsVersion,
		timeoutMilliseconds:     req.TimeoutMilliseconds,
		authenticatorAttachment: attachmentCrossPlatform,
		userVerificationReq:     uvRequirement(req.RequireUserVerification),
		flags:                   assertionHMACSecretValuesFlag,
		allowCredentialList:     &allow,
		hmacSecretSaltValues:    &saltValues,
	}
	if len(hintStorage) > 0 {
		opts.credentialHintsCount = uint32(len(hintStorage))
		opts.credentialHints = &hintStorage[0]
	}

	var out *assertion
	hr, _, _ := procGetAssertion.Call(
		req.WindowHandle,
		uintptr(unsafe.Pointer(rpID)),
		uintptr(unsafe.Pointer(&client)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&out)),
	)
	if hr != 0 {
		return GetAssertionResult{}, hresultError("GetAssertion", hr)
	}
	if out == nil {
		return GetAssertionResult{}, fmt.Errorf("winwebauthn: GetAssertion returned no assertion")
	}
	defer procFreeAssertion.Call(uintptr(unsafe.Pointer(out)))

	result := GetAssertionResult{
		AuthenticatorData:   asBytes(out.authenticatorData, out.authenticatorDataLen),
		AnsweringCredential: asBytes(out.credential.id, out.credential.idLen),
	}
	if out.hmacSecret != nil {
		result.HMACSecret = asBytes(out.hmacSecret.first, out.hmacSecret.firstLen)
	}
	return result, nil
}

// bytePtr returns a pointer to a slice's backing array, or nil for an empty
// slice. The pointer stays valid as long as the slice is referenced, which the
// caller ensures by keeping the slice alive across the syscall.
func bytePtr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}

// pointerToPointers returns a pointer to the first element of a slice of
// pointers, for the ppCredentials field. The slice must be kept alive by the
// caller across the syscall.
func pointerToPointers(p []*credentialEx) **credentialEx {
	if len(p) == 0 {
		return nil
	}
	return &p[0]
}

// hresultError renders a webauthn.dll HRESULT with the system's message text as
// well as the hex code. syscall.Errno formats it through FormatMessage, which
// names the common cases (a user cancellation, a timeout, no credentials) — a
// legible message with no pointer handling. The raw code is kept for the ones
// FormatMessage does not know.
func hresultError(op string, hr uintptr) error {
	return fmt.Errorf("winwebauthn: %s failed: %v (HRESULT 0x%08X)", op, syscall.Errno(hr), uint32(hr))
}
