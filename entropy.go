// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

// The salt-dependence gate.
//
// A key-encryption key is HKDF(prf, salt), and the whole security of the vault
// rests on the authenticator's prf actually being a function of the salt we
// gave it.  If the device -- or the marshaling between us and the device --
// silently drops or truncates the salt, HKDF still returns 32 plausible bytes,
// AES-GCM still seals, and everything looks correct.  It would simply be
// derived from far less entropy than intended, and nothing downstream could
// ever notice.
//
// So enrollment proves the dependence on the actual device before it seals
// anything, and records that it did.  A vault whose gate never passed is
// refused at unlock, before a touch is asked for.

import (
	"crypto/subtle"
	"fmt"
)

// verifyDerivationDependsOnSalt confirms the authenticator's hmac-secret output
// actually depends on the whole salt.  It derives a second time over the salt
// with its final byte flipped and requires a different result.
//
// # Why the last byte, and not a random probe
//
// The failure this is really hunting is a *truncated* salt: a marshaling bug
// with a too-short length field, so the device only ever sees the first N bytes
// of the 32 we passed.  That is the plausible bug, and it is invisible — the
// derivation still varies with the salt, just with less of it.
//
// Flip the final byte and a truncating derivation returns the *same* output for
// both salts, because the byte that changed is past what it read.  Caught, for
// every N < 32.
//
// A probe that flipped the *first* byte, or a freshly random probe salt, would
// change a byte the device does read, so the two outputs would differ and the
// check would pass — with the bug fully intact.  The tail is not a stylistic
// choice; it is the only position that catches truncation.  A derivation that
// ignores the salt entirely returns a constant, and is caught the same way.
//
// # Why it runs before anything is sealed
//
// On failure the secret is simply never stored.  A marshaling bug therefore
// cannot wrap a secret under a low-entropy key: there is nothing to wrap.  Do
// not move this check after a seal, and do not make it optional.
//
// realOutput is the hmac-secret already derived over salt for the wrapping
// itself, so no derivation is wasted; this costs exactly one extra gesture.
// observedUV is what that derivation reported.  The probe must report the same,
// or the two outputs could differ for a reason other than the salt — the
// authenticator having switched to its other per-credential secret — and the
// check would pass spuriously, which is the one way this gate could lie.
func verifyDerivationDependsOnSalt(auth Authenticator, rpID string, credentialID, salt, realOutput []byte, uv UserVerification, observedUV bool) error {
	if len(salt) != SaltLen {
		return ErrSaltLength
	}
	if len(realOutput) == 0 {
		return ErrNoPRF
	}

	probe := append([]byte(nil), salt...)
	probe[len(probe)-1] ^= 0xFF

	got, err := auth.Derive(DeriveRequest{
		RPID:          rpID,
		CredentialIDs: [][]byte{credentialID},
		Salt:          probe,
		UV:            uv,
	})
	if err != nil {
		return fmt.Errorf("touchvault: proving the derivation depends on the salt: %w", err)
	}
	if !got.UserPresent {
		return ErrNotPresent
	}
	if len(got.Secret) == 0 {
		return ErrNoPRF
	}
	if got.UserVerified != observedUV {
		return fmt.Errorf(
			"%w: the entropy-check derivation reported user_verified=%v, the enrollment "+
				"derivation reported %v", ErrUserVerificationMismatch, got.UserVerified, observedUV)
	}
	if subtle.ConstantTimeCompare(got.Secret, realOutput) == 1 {
		return ErrDerivationIgnoresSalt
	}
	return nil
}
