// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

//go:build windows

package winwebauthn

import (
	"testing"
	"unsafe"
)

// These offsets and sizes were validated on real hardware: a wrong one silently
// applies the salt to the wrong bytes or reads the hmac-secret from the wrong
// place, which is exactly the failure that shifted pbCredentialId by 16 bytes
// and produced "no credential ID returned" during bring-up. Freezing them means
// a future edit to types_windows.go that moves a load-bearing field fails here,
// in a test that needs no key and no touch, rather than on the next enrollment.
//
// The numbers are amd64 (8-byte pointer alignment). If Go's toolchain ever
// changes struct layout under us, this test is the tripwire; do not "fix" it by
// copying the new numbers without understanding why they moved.

func TestLayout_CredentialAttestationFields(t *testing.T) {
	var s credentialAttestation
	check(t, "credentialAttestation size", unsafe.Sizeof(s), 128)
	checkOff(t, "attestationObjectLen", unsafe.Offsetof(s.attestationObjectLen), 64)
	checkOff(t, "attestationObject", unsafe.Offsetof(s.attestationObject), 72)
	checkOff(t, "credentialIDLen", unsafe.Offsetof(s.credentialIDLen), 80)
	checkOff(t, "credentialID", unsafe.Offsetof(s.credentialID), 88)
	checkOff(t, "usedTransport", unsafe.Offsetof(s.usedTransport), 112)
	checkOff(t, "residentKey", unsafe.Offsetof(s.residentKey), 124)
}

func TestLayout_AssertionFields(t *testing.T) {
	var s assertion
	checkOff(t, "authenticatorData", unsafe.Offsetof(s.authenticatorData), 8)
	checkOff(t, "credential", unsafe.Offsetof(s.credential), 32)
	checkOff(t, "hmacSecret", unsafe.Offsetof(s.hmacSecret), 112)
}

func TestLayout_GetAssertionOptionsFields(t *testing.T) {
	var s getAssertionOptions
	checkOff(t, "hmacSecretSaltValues", unsafe.Offsetof(s.hmacSecretSaltValues), 104)
	checkOff(t, "browserInPrivateMode", unsafe.Offsetof(s.browserInPrivateMode), 112)
	checkOff(t, "credentialHints", unsafe.Offsetof(s.credentialHints), 152)
}

func TestLayout_HMACSecretSaltFields(t *testing.T) {
	var s hmacSecretSalt
	check(t, "hmacSecretSalt size", unsafe.Sizeof(s), 32)
	checkOff(t, "first", unsafe.Offsetof(s.first), 8)
	checkOff(t, "second", unsafe.Offsetof(s.second), 24)
}

func TestLayout_CommonAttestationFields(t *testing.T) {
	var s commonAttestation
	check(t, "commonAttestation size", unsafe.Sizeof(s), 88)
	checkOff(t, "algID", unsafe.Offsetof(s.algID), 16)
	checkOff(t, "signature", unsafe.Offsetof(s.signature), 24)
	checkOff(t, "x5cCount", unsafe.Offsetof(s.x5cCount), 32)
	checkOff(t, "x5c", unsafe.Offsetof(s.x5c), 40)
}

func TestLayout_X5CEntryFields(t *testing.T) {
	var s x5cEntry
	check(t, "x5cEntry size", unsafe.Sizeof(s), 16)
	checkOff(t, "data", unsafe.Offsetof(s.data), 8)
}

func check(t *testing.T, name string, got uintptr, want uintptr) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", name, got, want)
	}
}

func checkOff(t *testing.T, field string, got uintptr, want uintptr) {
	t.Helper()
	if got != want {
		t.Errorf("offset of %s = %d, want %d", field, got, want)
	}
}
