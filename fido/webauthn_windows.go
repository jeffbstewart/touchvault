// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

//go:build windows

package fido

// The authenticator built directly on webauthn.dll through internal/winwebauthn,
// with no third-party dependency beyond golang.org/x/sys/windows.  This file
// contains no `unsafe`; every pointer operation lives in winwebauthn, behind a
// safe API.
//
// It uses the raw hmac-secret salt API (winwebauthn feeds the 32-byte salt
// straight to the key, with no PRF prefix), so its derivation is
// self-consistent.

import (
	"fmt"

	"github.com/jeffbstewart/touchvault"
	"github.com/jeffbstewart/touchvault/fido/internal/winwebauthn"
)

func available() bool { return true }

func newAuthenticator() (touchvault.Authenticator, error) { return windowsAuthenticator{}, nil }

type windowsAuthenticator struct{}

// Enroll creates a non-discoverable credential and returns the platform's
// attestation material verbatim.
//
// It verifies nothing.  Whether this credential lives on genuine hardware is the
// core's decision, made in one portable place against Options.Roots — see the
// package comment.  Returning the raw material unjudged is the contract.
func (windowsAuthenticator) Enroll(req touchvault.EnrollRequest) (touchvault.EnrollResult, error) {
	res, err := winwebauthn.MakeCredential(winwebauthn.MakeCredentialRequest{
		WindowHandle:            winwebauthn.ConsoleWindow(),
		RPID:                    req.RPID,
		RPName:                  req.RPName,
		UserID:                  req.UserID,
		UserName:                req.UserName,
		RequireUserVerification: req.UV == touchvault.UVRequired,
		TimeoutMilliseconds:     uint32(req.TimeoutOrDefault().Milliseconds()),
	})
	if err != nil {
		return touchvault.EnrollResult{}, err
	}
	if len(res.CredentialID) == 0 {
		return touchvault.EnrollResult{}, fmt.Errorf("fido: no credential ID returned")
	}

	return touchvault.EnrollResult{
		CredentialID: res.CredentialID,

		// PRFEnabled is not reported by the raw API in a form we parse.  It is
		// optimistic, and the immediate Derive settles whether hmac-secret really
		// works — which is why the core never trusts this field.
		PRFEnabled: true,

		// ResidentKey is read back from the attestation (when the DLL reports a
		// version that carries it), so a key that stored the credential is caught
		// by the core rather than silently consuming a passkey slot.
		ResidentKey: res.ResidentKey,

		AttestationFormat:    res.AttestationFormat,
		AttestationAlg:       res.AttestationAlg,
		AttestationSignature: res.AttestationSignature,
		AuthenticatorData:    res.AuthenticatorData,
		ClientDataHash:       res.ClientDataHash,
		AttestationCerts:     res.AttestationCerts,
	}, nil
}

// Derive computes hmac-secret over req.Salt.  It costs one touch, and one PIN
// entry when the platform verifies.
func (windowsAuthenticator) Derive(req touchvault.DeriveRequest) (touchvault.DeriveResult, error) {
	// The port's shared validation, so this provider's checks cannot drift from
	// any other's.  A salt of the wrong length must never reach the device.
	if err := req.Validate(); err != nil {
		return touchvault.DeriveResult{}, err
	}

	res, err := winwebauthn.GetAssertion(winwebauthn.GetAssertionRequest{
		WindowHandle:            winwebauthn.ConsoleWindow(),
		RPID:                    req.RPID,
		CredentialIDs:           req.CredentialIDs,
		Salt:                    req.Salt,
		RequireUserVerification: req.UV == touchvault.UVRequired,
		TimeoutMilliseconds:     uint32(req.TimeoutOrDefault().Milliseconds()),
	})
	if err != nil {
		return touchvault.DeriveResult{}, err
	}
	if len(res.HMACSecret) == 0 {
		return touchvault.DeriveResult{}, touchvault.ErrNoPRF
	}

	// The flags byte is index 32 of the authenticator data, after the 32-byte
	// relying-party-id hash.  Bit 0 is user present; bit 2 is user verified.
	//
	// These are read from the SIGNED authenticator data, never from what we
	// requested.  That is the whole discipline behind the uv trap: the device's
	// own report is ground truth, and it decides which of the two per-credential
	// secrets produced the output above.
	if len(res.AuthenticatorData) < 33 {
		return touchvault.DeriveResult{}, touchvault.ErrNoAuthenticatorData
	}
	flags := res.AuthenticatorData[32]

	answered := res.AnsweringCredential
	if len(answered) == 0 {
		// With a single-credential allow-list the answer is unambiguous.  With
		// several it is not, and guessing would tell the core that the wrong key
		// answered -- so refuse rather than guess.
		if len(req.CredentialIDs) != 1 {
			return touchvault.DeriveResult{}, fmt.Errorf(
				"fido: assertion did not say which of %d credentials answered",
				len(req.CredentialIDs))
		}
		answered = req.CredentialIDs[0]
	}

	return touchvault.DeriveResult{
		Secret:       res.HMACSecret,
		CredentialID: answered,
		UserPresent:  flags&0x01 != 0,
		UserVerified: flags&0x04 != 0,
	}, nil
}
