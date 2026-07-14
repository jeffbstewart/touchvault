// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

// Package fido implements [touchvault.Authenticator] over the platform FIDO2
// stack.
//
// On Windows it calls webauthn.dll directly through internal/winwebauthn, the
// only place unsafe is used in this module.  Other platforms return
// [ErrUnsupportedPlatform].
//
// # This is the single door to hardware
//
// Every touchvault function takes an [touchvault.Authenticator], so a fake
// reaches all of them and a real key reaches none of them by accident.  [New] is
// the only way to obtain the real thing, and it refuses to open under a test
// binary or a coding agent's shell.
//
// # It makes no trust decision
//
// Enroll returns whatever attestation material the platform hands over — format,
// algorithm, signature, authenticator data, client-data hash, certificate chain
// — and judges none of it.  The core verifies that material against
// Options.Roots.  A provider that decided for itself which hardware to trust
// would put the security policy in the transport, where it could differ between
// platforms and could not be tested without a key.
package fido

import (
	"errors"

	"github.com/jeffbstewart/touchvault"
)

// ErrUnsupportedPlatform means this build cannot reach a security key.
var ErrUnsupportedPlatform = errors.New("fido: not supported on this platform")

// New returns the platform authenticator.
//
// It refuses under a test binary or a coding-agent shell (CLAUDECODE, QWEN_CODE,
// ...), so automation cannot reach real hardware; inject a fake into touchvault
// instead.
//
// There is deliberately no Must variant.  A caller who wants one writes it — two
// lines, in their own code, where the panic is theirs to own.
func New() (touchvault.Authenticator, error) {
	if err := RefuseAutomatedContext(); err != nil {
		return nil, err
	}
	return newAuthenticator()
}

// Available reports whether this build can reach a security key at all.
//
// It answers for the build, not for the moment: true does not mean a key is
// plugged in, only that this binary could talk to one.  It also does not consult
// the refusal guards — a test binary on Windows still reports true, because the
// question is about the platform, not about who is asking.
func Available() bool { return available() }
