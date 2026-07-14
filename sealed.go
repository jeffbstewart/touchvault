// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

// The sealed vault: what a caller persists, and the authenticated data every
// seal in it is bound to.
//
// # Shape
//
// A random 256-bit data key encrypts every secret.  Each enrolled security key
// then wraps a copy of that data key.  Two keys therefore mean two wrapped
// copies of one data key, not two ciphertexts of each secret — so enrolling a
// backup never re-encrypts anything and never needs a plaintext secret again.
//
//	secret_j --AES-256-GCM(dataKey)--> ciphertext_j    for each secret j
//	dataKey  --AES-256-GCM(kek_i)----> wrapped_i       for each key i
//	kek_i     = HKDF-SHA256(prf_i, salt, info)
//	prf_i     = hmac-secret(credential_i, salt)     <- requires a touch
//
// # Metadata is plaintext, and authenticated
//
// Secret names, key labels, credential IDs, and the salt are readable without a
// touch, deliberately: a vault can be inspected, listed, and audited by a
// program that cannot read a single secret.  They are all bound into the AAD of
// every seal, so readable does not mean malleable.

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
)

// formatVersion is the schema marker.  It is authenticated, so a downgrade is
// detected rather than tolerated.
//
// It starts at 1 and no earlier format was ever published, so there is nothing
// to be backward-compatible with.  Do not add a compatibility path for a format
// that never shipped.
const formatVersion = 1

// aadInfo domain-separates this AAD construction from any other use of these
// bytes.  It leads every AAD, so a seal made by a different scheme that happened
// to share our field layout still would not open here.
const aadInfo = "touchvault/v1/aad"

// The AAD kind tags.  Every seal is either a wrapped data key or a sealed
// secret, and the two must never produce the same AAD.
//
// Without a tag they could.  A per-key AAD ends in a slot number followed by a
// length-prefixed credential ID; a per-secret AAD ends in a length-prefixed
// name.  A name whose first four bytes happened to equal a slot number's
// encoding would collide with a key entry — and a collision means a wrapped data
// key could be presented as a secret's ciphertext, or the reverse.  The tag
// makes the two shapes disjoint by construction.
const (
	aadKindKey    byte = 1
	aadKindSecret byte = 2
)

// sealedKey is one enrolled security key's wrapped copy of the data key.
type sealedKey struct {
	// Slot is the operator-facing handle: enroll into a slot, list slots,
	// remove a slot.  Authenticated, so an entry cannot be moved between slots.
	Slot int `json:"slot"`

	// Label names the slot for a human.  Authenticated.
	Label string `json:"label"`

	// CredentialID is raw bytes.  Encoding it here would bake a library's
	// base64 padding convention into the stored format.
	CredentialID []byte `json:"credential_id"`

	Nonce   []byte `json:"nonce"`
	Wrapped []byte `json:"wrapped"` // the data key, sealed under this key's KEK
}

// sealedSecret is one secret, sealed under the vault's single data key.
type sealedSecret struct {
	Name       string `json:"name"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// sealedVault is the on-disk document.
type sealedVault struct {
	Format int    `json:"format"`
	RPID   string `json:"rp_id"`

	// Salt is the hmac-secret input, shared by every enrolled key.  Each key
	// derives a different prf from it, because the prf is per-credential.
	Salt []byte `json:"salt"`

	// UserVerified is what the authenticator reported at enrollment, never what
	// was requested.  See [UserVerification].
	UserVerified bool `json:"user_verified"`

	// EntropyVerified records that enrollment proved the authenticator's
	// hmac-secret output depends on the whole salt.  It is authenticated and
	// required: a vault without it is refused before any touch is asked for,
	// because its data key may have been wrapped under a key derived from a salt
	// the device silently ignored.
	EntropyVerified bool `json:"entropy_verified"`

	Keys    []sealedKey    `json:"keys"`
	Secrets []sealedSecret `json:"secrets"`
}

// appendLenPrefixed appends a 32-bit length followed by the bytes.
//
// Length prefixes, not delimiters.  The original of this code NUL-terminated its
// string fields, which was safe only because every one of them was a compile-time
// constant.  Here the RP ID and the secret names come from the caller, and a
// caller-supplied string containing a NUL byte could otherwise shift the meaning
// of every field after it while producing the same AAD.
func appendLenPrefixed(b []byte, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

// aad is the authenticated header shared by every seal in the document.
//
// Binding it everywhere means an attacker cannot replay an older format, swap
// the salt, flip the uv flag to force the wrong CredRandom, clear the
// entropy-verified marker, or move a vault's contents under a different RP ID.
// Each of those would otherwise leave the ciphertext arithmetic intact.
func (v *sealedVault) aad() []byte {
	b := []byte(aadInfo)
	b = binary.BigEndian.AppendUint32(b, uint32(v.Format))
	b = appendLenPrefixed(b, []byte(v.RPID))
	b = append(b, boolByte(v.UserVerified), boolByte(v.EntropyVerified))
	return appendLenPrefixed(b, v.Salt)
}

// keyAAD additionally binds a wrapped data key to its slot and credential.
//
// The credential binding is defense in depth, and redundant today: each wrapped
// data key is sealed under a per-credential KEK derived from that credential's
// prf, and no two distinct credentials derive the same prf, so an entry can only
// ever be opened by the KEK of its own credential.  It costs nothing and keeps
// the invariant if the KEK derivation ever changes.
//
// The slot binding is not redundant.  It stops a stored entry from being moved
// from one slot to another in the document, which would otherwise decrypt fine.
func (v *sealedVault) keyAAD(slot int, credentialID []byte) []byte {
	b := append(v.aad(), aadKindKey)
	b = binary.BigEndian.AppendUint32(b, uint32(slot))
	return appendLenPrefixed(b, credentialID)
}

// secretAAD additionally binds a secret's ciphertext to its name, so a secret
// cannot be relabeled, nor two secrets swapped, without the seal failing to
// open.  Without it, moving the bytes of "staging-token" onto the name
// "production-token" would go undetected — the data key opens both.
func (v *sealedVault) secretAAD(name string) []byte {
	b := append(v.aad(), aadKindSecret)
	return appendLenPrefixed(b, []byte(name))
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// findKey returns the entry for a credential ID.
//
// The comparison is constant-time.  A credential ID is not secret, so this is
// belt and braces rather than a defense against a real timing oracle; it costs
// nothing on a list this short.
func (v *sealedVault) findKey(credentialID []byte) (sealedKey, bool) {
	for _, k := range v.Keys {
		if subtle.ConstantTimeCompare(k.CredentialID, credentialID) == 1 {
			return k, true
		}
	}
	return sealedKey{}, false
}

func (v *sealedVault) slotOccupied(slot int) bool {
	for _, k := range v.Keys {
		if k.Slot == slot {
			return true
		}
	}
	return false
}

func (v *sealedVault) findSecret(name string) (sealedSecret, bool) {
	for _, s := range v.Secrets {
		if s.Name == name {
			return s, true
		}
	}
	return sealedSecret{}, false
}

// credentialIDs is the allow-list handed to the authenticator, so the operator
// may present any enrolled key and need not say which one they are holding.
func (v *sealedVault) credentialIDs() [][]byte {
	ids := make([][]byte, 0, len(v.Keys))
	for _, k := range v.Keys {
		ids = append(ids, k.CredentialID)
	}
	return ids
}

// uvRequirement asks for exactly what enrollment observed.  Requesting the
// recorded value means a platform that changes its behavior produces a mismatch
// we can explain, not a silently different key.
func (v *sealedVault) uvRequirement() UserVerification {
	if v.UserVerified {
		return UVRequired
	}
	return UVDiscouraged
}

// names lists the secret names, sorted.
func (v *sealedVault) names() []string {
	out := make([]string, 0, len(v.Secrets))
	for _, s := range v.Secrets {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

// slots lists the occupied slots, sorted.  It reveals no secret: a credential ID
// is a handle, not key material, and only a prefix of it is shown.
func (v *sealedVault) slots() []SlotInfo {
	out := make([]SlotInfo, 0, len(v.Keys))
	for _, k := range v.Keys {
		out = append(out, SlotInfo{
			Slot:            k.Slot,
			Label:           k.Label,
			CredentialIDHex: fmt.Sprintf("%x", k.CredentialID[:min(credentialIDPrefixLen, len(k.CredentialID))]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}

// credentialIDPrefixLen is how many bytes of a credential ID are shown in a
// listing: enough to tell two enrolled keys apart, not enough to be mistaken for
// the handle itself.
const credentialIDPrefixLen = 8

// marshal serializes the document for the caller to persist.
func (v *sealedVault) marshal() ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("touchvault: serializing the vault: %w", err)
	}
	return data, nil
}

// parseSealed parses and validates a sealed document.  It performs no
// cryptography and costs no gesture.
//
// Validation is structural only: it establishes that the document is
// self-consistent, never that it is authentic.  Authenticity is established by
// the AEAD when a seal is opened, which is the only thing that can establish it.
// A caller must not read anything into a document having parsed.
func parseSealed(data []byte) (*sealedVault, error) {
	var v sealedVault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("%w: the sealed vault is unreadable: %w", ErrWrongFormat, err)
	}
	if v.Format != formatVersion {
		return nil, fmt.Errorf("%w: %d", ErrWrongFormat, v.Format)
	}
	if len(v.Salt) != SaltLen {
		return nil, fmt.Errorf("%w: salt is %d bytes, want %d", ErrWrongFormat, len(v.Salt), SaltLen)
	}
	if v.RPID == "" {
		return nil, fmt.Errorf("%w: no RP ID", ErrWrongFormat)
	}

	// Duplicates would make the document ambiguous: which entry answers for a
	// slot, a name, or a credential?  An ambiguity an attacker chooses is a
	// vulnerability, so refuse rather than pick.
	seenSlot := make(map[int]bool, len(v.Keys))
	seenCred := make(map[string]bool, len(v.Keys))
	for _, k := range v.Keys {
		if k.Slot < 0 {
			return nil, fmt.Errorf("%w: negative slot %d", ErrWrongFormat, k.Slot)
		}
		if seenSlot[k.Slot] {
			return nil, fmt.Errorf("%w: slot %d appears twice", ErrWrongFormat, k.Slot)
		}
		seenSlot[k.Slot] = true

		if len(k.CredentialID) == 0 {
			return nil, fmt.Errorf("%w: slot %d has no credential ID", ErrWrongFormat, k.Slot)
		}
		if seenCred[string(k.CredentialID)] {
			return nil, fmt.Errorf("%w: a credential is enrolled in two slots", ErrWrongFormat)
		}
		seenCred[string(k.CredentialID)] = true
	}

	seenName := make(map[string]bool, len(v.Secrets))
	for _, s := range v.Secrets {
		if s.Name == "" {
			return nil, fmt.Errorf("%w: a secret has no name", ErrWrongFormat)
		}
		if seenName[s.Name] {
			return nil, fmt.Errorf("%w: secret %q appears twice", ErrWrongFormat, s.Name)
		}
		seenName[s.Name] = true
	}

	return &v, nil
}
