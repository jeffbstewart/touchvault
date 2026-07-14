// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

// Package touchvault stores a set of secrets so that reading any of them
// requires a physical touch on an enrolled FIDO2 security key.
//
// A single random data key encrypts every secret.  Each enrolled security key
// wraps a copy of that data key behind a key derived from the key's
// hmac-secret output, which costs a touch to compute.  Reading therefore needs
// the key and a human; the sealed vault is inert without both.
//
// Storage is the caller's: Sealed returns bytes to persist, Open parses them.
// touchvault never talks to hardware; a provider implements Authenticator and
// a fake reaches every function in tests.  Enrollment requires and verifies
// hardware attestation, so a software or virtual authenticator cannot be
// enrolled.
package touchvault
