// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

//go:build !windows

package fido

// No security-key support outside Windows.
//
// The equivalent elsewhere is libfido2, which needs cgo and would end this
// module's pure-Go build.  That is a separate decision, taken when there is a
// reason to reach a key on macOS or Linux.  Until then the build stays green
// everywhere and the failure is explicit rather than a link error.
//
// Note what this does NOT change: the touchvault core builds and tests on every
// platform regardless, because it never imports this package.  Only a caller
// that reaches for real hardware is affected, and it is told so plainly.

import "github.com/jeffbstewart/touchvault"

func available() bool { return false }

func newAuthenticator() (touchvault.Authenticator, error) { return nil, ErrUnsupportedPlatform }
