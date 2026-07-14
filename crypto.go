// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// dataKeyLen is the size of the data key that encrypts every secret, and of
// each key-encryption key that wraps a copy of it.  AES-256.
const dataKeyLen = 32

// kekInfo domain-separates the key-encryption key.  An hmac-secret output used
// for anything else cannot collide with a KEK derived here.
const kekInfo = "touchvault/v1/kek"

// randomBytes returns n cryptographically random bytes.
//
// crypto/rand.Read never returns a short read without an error, and on any
// supported platform an error means the operating system's entropy source has
// failed.  There is no sensible fallback: a "random" key that is not random
// would seal a secret under something guessable.  Callers propagate the error.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("touchvault: reading random bytes: %w", err)
	}
	return b, nil
}

// newSalt returns a fresh hmac-secret salt.
func newSalt() ([]byte, error) { return randomBytes(SaltLen) }

// newDataKey returns a fresh data key.
func newDataKey() ([]byte, error) { return randomBytes(dataKeyLen) }

// deriveKEK turns one authenticator's hmac-secret output into a key-encryption
// key.
//
// The salt is reused as the HKDF salt.  That is sound and deliberate: the prf is
// already per-credential, so a distinct KEK per key does not depend on the HKDF
// salt varying, and reusing the vault's salt means there is exactly one salt in
// the design to reason about, store, and bind into the AAD.
func deriveKEK(prf, salt []byte) ([]byte, error) {
	if len(prf) == 0 {
		return nil, ErrNoPRF
	}
	kek, err := hkdf.Key(sha256.New, prf, salt, kekInfo, dataKeyLen)
	if err != nil {
		return nil, fmt.Errorf("touchvault: deriving key-encryption key: %w", err)
	}
	return kek, nil
}

// seal encrypts plaintext under key, binding aad, and returns a fresh nonce
// with the ciphertext.
//
// The nonce is random per seal.  GCM's nonce-reuse failure is catastrophic — two
// messages under one key and nonce leak the authentication subkey — so a nonce
// is never derived, never a counter, and never reused: every call draws a new
// one.  Every key sealed under is itself freshly random (a data key) or derived
// from a per-credential prf (a KEK), so the number of messages under any one key
// stays far inside GCM's random-nonce bound.
func seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// open decrypts and authenticates.  A failure here means the ciphertext, the
// nonce, or the AAD is not what was sealed — the caller must not distinguish
// which, and must not retry.
func open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce is %d bytes, want %d", ErrWrongFormat, len(nonce), gcm.NonceSize())
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("touchvault: authenticating: %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != dataKeyLen {
		return nil, errors.New("touchvault: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("touchvault: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("touchvault: gcm: %w", err)
	}
	return gcm, nil
}

// wrapDataKey seals the data key for one credential in one slot.  It is pure:
// the touch that produced prf has already been spent.
func (v *sealedVault) wrapDataKey(dataKey, credentialID, prf []byte, slot int, label string) (sealedKey, error) {
	kek, err := deriveKEK(prf, v.Salt)
	if err != nil {
		return sealedKey{}, err
	}
	nonce, wrapped, err := seal(kek, dataKey, v.keyAAD(slot, credentialID))
	if err != nil {
		return sealedKey{}, err
	}
	return sealedKey{
		Slot:         slot,
		Label:        label,
		CredentialID: credentialID,
		Nonce:        nonce,
		Wrapped:      wrapped,
	}, nil
}

// unwrapDataKey recovers the data key from one enrolled entry, given the prf
// that entry's credential produced.  It is pure: the touch has been spent.
func (v *sealedVault) unwrapDataKey(entry sealedKey, prf []byte) ([]byte, error) {
	kek, err := deriveKEK(prf, v.Salt)
	if err != nil {
		return nil, err
	}
	dataKey, err := open(kek, entry.Nonce, entry.Wrapped, v.keyAAD(entry.Slot, entry.CredentialID))
	if err != nil {
		return nil, fmt.Errorf("touchvault: unwrapping the data key with key %q: %w", entry.Label, err)
	}
	return dataKey, nil
}

// sealSecret encrypts one secret under the data key, bound to its name.
func (v *sealedVault) sealSecret(dataKey []byte, name string, plaintext []byte) (sealedSecret, error) {
	nonce, ciphertext, err := seal(dataKey, plaintext, v.secretAAD(name))
	if err != nil {
		return sealedSecret{}, err
	}
	return sealedSecret{Name: name, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// openSecret decrypts one secret under the data key.
func (v *sealedVault) openSecret(dataKey []byte, s sealedSecret) ([]byte, error) {
	plaintext, err := open(dataKey, s.Nonce, s.Ciphertext, v.secretAAD(s.Name))
	if err != nil {
		return nil, fmt.Errorf("touchvault: decrypting secret %q: %w", s.Name, err)
	}
	return plaintext, nil
}

// zero overwrites b.
//
// It is best-effort and must be documented as such wherever it is exposed: the
// Go runtime may have copied these bytes during garbage collection, and nothing
// in the language can reach those copies.  It narrows the window; it does not
// guarantee erasure.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
