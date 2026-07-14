// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// testVault returns a vault with plausible metadata and no entries.
func testVault() *sealedVault {
	return &sealedVault{
		Format:          formatVersion,
		RPID:            "vault.example.invalid",
		Salt:            bytes.Repeat([]byte{0x5A}, SaltLen),
		UserVerified:    false,
		EntropyVerified: true,
	}
}

func mustDataKey(t *testing.T) []byte {
	t.Helper()
	k, err := newDataKey()
	if err != nil {
		t.Fatalf("newDataKey() = %v", err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := mustDataKey(t)
	plaintext := []byte("a secret worth a touch")
	aad := []byte("bound")

	nonce, ct, err := seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("seal() = %v", err)
	}
	got, err := open(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("open() = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("open() = %q, want %q", got, plaintext)
	}
}

// The ciphertext must not contain the plaintext.  This is a trivially true
// property of GCM, and exactly the kind of thing worth pinning: a refactor that
// accidentally stored plaintext would otherwise pass every round-trip test.
func TestSealDoesNotLeakPlaintext(t *testing.T) {
	key := mustDataKey(t)
	plaintext := []byte("sk-live-the-actual-secret")

	_, ct, err := seal(key, plaintext, nil)
	if err != nil {
		t.Fatalf("seal() = %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Error("ciphertext contains the plaintext")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key := mustDataKey(t)
	other := mustDataKey(t)
	plaintext := []byte("a secret worth a touch")
	aad := []byte("bound")

	nonce, ct, err := seal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("seal() = %v", err)
	}

	tests := []struct {
		name  string
		key   []byte
		nonce []byte
		ct    []byte
		aad   []byte
	}{
		{name: "wrong key", key: other, nonce: nonce, ct: ct, aad: aad},
		{name: "wrong nonce", key: key, nonce: flip(nonce, 0), ct: ct, aad: aad},
		{name: "flipped ciphertext bit", key: key, nonce: nonce, ct: flip(ct, 0), aad: aad},
		{name: "flipped tag bit", key: key, nonce: nonce, ct: flip(ct, len(ct)-1), aad: aad},
		{name: "wrong aad", key: key, nonce: nonce, ct: ct, aad: []byte("unbound")},
		{name: "absent aad", key: key, nonce: nonce, ct: ct, aad: nil},
		{name: "truncated ciphertext", key: key, nonce: nonce, ct: ct[:len(ct)-1], aad: aad},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := open(tt.key, tt.nonce, tt.ct, tt.aad); err == nil {
				t.Error("open() succeeded, want failure")
			}
		})
	}
}

func TestOpenRejectsWrongNonceSize(t *testing.T) {
	key := mustDataKey(t)
	nonce, ct, err := seal(key, []byte("x"), nil)
	if err != nil {
		t.Fatalf("seal() = %v", err)
	}
	if _, err := open(key, nonce[:len(nonce)-1], ct, nil); !errors.Is(err, ErrWrongFormat) {
		t.Errorf("open() with short nonce = %v, want ErrWrongFormat", err)
	}
}

func TestNewGCMRejectsWrongKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := newGCM(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Errorf("newGCM(%d-byte key) succeeded, want failure", n)
		}
	}
}

// A nonce must never repeat under one key.  GCM's nonce-reuse failure is
// catastrophic -- two messages under the same key and nonce leak the
// authentication subkey -- so this pins that every seal draws a fresh one.
func TestSealDrawsAFreshNonceEveryTime(t *testing.T) {
	key := mustDataKey(t)
	const n = 128

	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		nonce, _, err := seal(key, []byte("same plaintext"), []byte("same aad"))
		if err != nil {
			t.Fatalf("seal() = %v", err)
		}
		if seen[string(nonce)] {
			t.Fatalf("nonce repeated after %d seals", i)
		}
		seen[string(nonce)] = true
	}
}

// Sealing the same plaintext twice must produce different ciphertext, which
// follows from the fresh nonce.  Otherwise a vault would leak that two secrets
// have the same value.
func TestSealIsNotDeterministic(t *testing.T) {
	key := mustDataKey(t)
	_, ct1, err := seal(key, []byte("same"), nil)
	if err != nil {
		t.Fatalf("seal() = %v", err)
	}
	_, ct2, err := seal(key, []byte("same"), nil)
	if err != nil {
		t.Fatalf("seal() = %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("sealing the same plaintext twice produced identical ciphertext")
	}
}

func TestDeriveKEK(t *testing.T) {
	salt := bytes.Repeat([]byte{0x5A}, SaltLen)
	prf := bytes.Repeat([]byte{0x11}, 32)

	kek, err := deriveKEK(prf, salt)
	if err != nil {
		t.Fatalf("deriveKEK() = %v", err)
	}
	if len(kek) != dataKeyLen {
		t.Errorf("len(kek) = %d, want %d", len(kek), dataKeyLen)
	}

	// Deterministic: the same key must unwrap tomorrow what it wrapped today.
	again, err := deriveKEK(prf, salt)
	if err != nil {
		t.Fatalf("deriveKEK() = %v", err)
	}
	if !bytes.Equal(kek, again) {
		t.Error("deriveKEK is not deterministic")
	}

	// A different prf -- a different security key -- must give a different KEK,
	// or one enrolled key could unwrap another's entry.
	otherPRF, err := deriveKEK(bytes.Repeat([]byte{0x22}, 32), salt)
	if err != nil {
		t.Fatalf("deriveKEK() = %v", err)
	}
	if bytes.Equal(kek, otherPRF) {
		t.Error("a different prf produced the same KEK")
	}

	// A different salt must give a different KEK.  This is the property the
	// entropy gate exists to prove the *authenticator* also has.
	otherSalt, err := deriveKEK(prf, bytes.Repeat([]byte{0x5B}, SaltLen))
	if err != nil {
		t.Fatalf("deriveKEK() = %v", err)
	}
	if bytes.Equal(kek, otherSalt) {
		t.Error("a different salt produced the same KEK")
	}
}

// An authenticator that returned no hmac-secret output must not silently derive
// a KEK from nothing.
func TestDeriveKEKRejectsEmptyPRF(t *testing.T) {
	salt := bytes.Repeat([]byte{0x5A}, SaltLen)
	if _, err := deriveKEK(nil, salt); !errors.Is(err, ErrNoPRF) {
		t.Errorf("deriveKEK(nil) = %v, want ErrNoPRF", err)
	}
	if _, err := deriveKEK([]byte{}, salt); !errors.Is(err, ErrNoPRF) {
		t.Errorf("deriveKEK(empty) = %v, want ErrNoPRF", err)
	}
}

func TestWrapUnwrapDataKey(t *testing.T) {
	v := testVault()
	dataKey := mustDataKey(t)
	cred := []byte("credential-one")
	prf := bytes.Repeat([]byte{0x11}, 32)

	entry, err := v.wrapDataKey(dataKey, cred, prf, 0, "primary")
	if err != nil {
		t.Fatalf("wrapDataKey() = %v", err)
	}

	// The wrapped bytes must not be the data key.
	if bytes.Contains(entry.Wrapped, dataKey) {
		t.Error("the wrapped entry contains the raw data key")
	}

	got, err := v.unwrapDataKey(entry, prf)
	if err != nil {
		t.Fatalf("unwrapDataKey() = %v", err)
	}
	if !bytes.Equal(got, dataKey) {
		t.Error("unwrapDataKey did not recover the data key")
	}
}

// A second enrolled key wraps a *copy of the same data key*, not a second
// ciphertext of the secrets.  That is what makes enrolling a backup cost no
// plaintext and re-encrypt nothing.
func TestTwoKeysWrapTheSameDataKey(t *testing.T) {
	v := testVault()
	dataKey := mustDataKey(t)
	prfA := bytes.Repeat([]byte{0x11}, 32)
	prfB := bytes.Repeat([]byte{0x22}, 32)

	a, err := v.wrapDataKey(dataKey, []byte("cred-a"), prfA, 0, "primary")
	if err != nil {
		t.Fatalf("wrapDataKey(a) = %v", err)
	}
	b, err := v.wrapDataKey(dataKey, []byte("cred-b"), prfB, 1, "backup")
	if err != nil {
		t.Fatalf("wrapDataKey(b) = %v", err)
	}

	gotA, err := v.unwrapDataKey(a, prfA)
	if err != nil {
		t.Fatalf("unwrapDataKey(a) = %v", err)
	}
	gotB, err := v.unwrapDataKey(b, prfB)
	if err != nil {
		t.Fatalf("unwrapDataKey(b) = %v", err)
	}
	if !bytes.Equal(gotA, gotB) || !bytes.Equal(gotA, dataKey) {
		t.Error("the two keys did not recover the same data key")
	}

	// Neither key's prf may open the other's entry.
	if _, err := v.unwrapDataKey(a, prfB); err == nil {
		t.Error("key B's prf opened key A's entry")
	}
	if _, err := v.unwrapDataKey(b, prfA); err == nil {
		t.Error("key A's prf opened key B's entry")
	}
}

// The per-key AAD binds slot and credential ID.  Moving an entry to another slot
// in the document -- which an attacker with write access to the sealed bytes can
// trivially do -- must not decrypt.
func TestUnwrapDataKeyRejectsMovedEntry(t *testing.T) {
	v := testVault()
	dataKey := mustDataKey(t)
	cred := []byte("credential-one")
	prf := bytes.Repeat([]byte{0x11}, 32)

	entry, err := v.wrapDataKey(dataKey, cred, prf, 0, "primary")
	if err != nil {
		t.Fatalf("wrapDataKey() = %v", err)
	}

	moved := entry
	moved.Slot = 1
	if _, err := v.unwrapDataKey(moved, prf); err == nil {
		t.Error("an entry moved to another slot still unwrapped")
	}

	relabeled := entry
	relabeled.CredentialID = []byte("credential-two")
	if _, err := v.unwrapDataKey(relabeled, prf); err == nil {
		t.Error("an entry with a swapped credential ID still unwrapped")
	}
}

// The vault AAD binds the metadata.  Every one of these fields is plaintext in
// the document, so every one of them is something an attacker can edit; each
// edit must break every seal.
func TestUnwrapDataKeyRejectsTamperedMetadata(t *testing.T) {
	dataKey := mustDataKey(t)
	cred := []byte("credential-one")
	prf := bytes.Repeat([]byte{0x11}, 32)

	base := testVault()
	entry, err := base.wrapDataKey(dataKey, cred, prf, 0, "primary")
	if err != nil {
		t.Fatalf("wrapDataKey() = %v", err)
	}

	tests := []struct {
		name   string
		tamper func(*sealedVault)
	}{
		{
			name:   "format downgraded",
			tamper: func(v *sealedVault) { v.Format = 0 },
		},
		{
			name:   "rp id changed",
			tamper: func(v *sealedVault) { v.RPID = "attacker.invalid" },
		},
		{
			// Flipping this forces the wrong CredRandom on every future read.
			name:   "user_verified flipped",
			tamper: func(v *sealedVault) { v.UserVerified = !v.UserVerified },
		},
		{
			// Clearing this would let a vault that never passed the entropy gate
			// masquerade as one that did.
			name:   "entropy_verified cleared",
			tamper: func(v *sealedVault) { v.EntropyVerified = false },
		},
		{
			name:   "salt swapped",
			tamper: func(v *sealedVault) { v.Salt = bytes.Repeat([]byte{0x5B}, SaltLen) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := testVault()
			tt.tamper(v)
			if _, err := v.unwrapDataKey(entry, prf); err == nil {
				t.Error("unwrapDataKey succeeded on tampered metadata, want failure")
			}
		})
	}
}

func TestSealOpenSecret(t *testing.T) {
	v := testVault()
	dataKey := mustDataKey(t)
	plaintext := []byte("sk-live-abc123")

	s, err := v.sealSecret(dataKey, "api-key", plaintext)
	if err != nil {
		t.Fatalf("sealSecret() = %v", err)
	}
	got, err := v.openSecret(dataKey, s)
	if err != nil {
		t.Fatalf("openSecret() = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("openSecret() = %q, want %q", got, plaintext)
	}
}

// The per-secret AAD binds the name.  Renaming a secret in the document, or
// swapping two secrets' ciphertexts, must not decrypt -- the data key opens both,
// so nothing but the AAD stops it.
func TestOpenSecretRejectsRelabeling(t *testing.T) {
	v := testVault()
	dataKey := mustDataKey(t)

	staging, err := v.sealSecret(dataKey, "staging-token", []byte("harmless"))
	if err != nil {
		t.Fatalf("sealSecret() = %v", err)
	}
	production, err := v.sealSecret(dataKey, "production-token", []byte("dangerous"))
	if err != nil {
		t.Fatalf("sealSecret() = %v", err)
	}

	// Rename staging to production: the bytes are intact, the name is a lie.
	renamed := staging
	renamed.Name = "production-token"
	if _, err := v.openSecret(dataKey, renamed); err == nil {
		t.Error("a renamed secret still decrypted")
	}

	// Swap the two ciphertexts under their names.
	swapped := sealedSecret{
		Name:       staging.Name,
		Nonce:      production.Nonce,
		Ciphertext: production.Ciphertext,
	}
	if _, err := v.openSecret(dataKey, swapped); err == nil {
		t.Error("two secrets' ciphertexts swapped and still decrypted")
	}
}

// The AAD kind tag is load-bearing, and this proves it.
//
// Without a tag, a per-key AAD (slot, then a length-prefixed credential ID) and a
// per-secret AAD (a length-prefixed name) are both just bytes appended to the
// same header -- and a name can be crafted whose encoding is byte-identical to a
// slot-plus-credential encoding.  A collision would mean a wrapped data key and a
// secret's ciphertext share an AAD, so one could be presented as the other.
//
// This test constructs exactly such a collision and asserts the real AADs still
// differ.
func TestAADKindTagPreventsKeySecretCollision(t *testing.T) {
	v := testVault()

	cred := []byte("8bytecrd") // 8 bytes
	// For the untagged encodings to collide we need:
	//   u32(len(name)) == u32(slot)  and  name == u32(len(cred)) || cred
	// so len(name) = 4 + len(cred) = 12, and therefore slot = 12.
	var nameBytes []byte
	nameBytes = binary.BigEndian.AppendUint32(nameBytes, uint32(len(cred)))
	nameBytes = append(nameBytes, cred...)
	name := string(nameBytes)
	slot := len(nameBytes) // 12

	// Confirm the collision is real: without the tag byte these are identical.
	untaggedKey := binary.BigEndian.AppendUint32(v.aad(), uint32(slot))
	untaggedKey = appendLenPrefixed(untaggedKey, cred)
	untaggedSecret := appendLenPrefixed(v.aad(), []byte(name))
	if !bytes.Equal(untaggedKey, untaggedSecret) {
		t.Fatalf("test is not exercising a real collision: untagged AADs already differ")
	}

	// With the tag, they must not be.
	if bytes.Equal(v.keyAAD(slot, cred), v.secretAAD(name)) {
		t.Error("keyAAD and secretAAD collide; the kind tag is not doing its job")
	}
}

// A caller-supplied string with a NUL byte must not be able to shift the meaning
// of the fields around it.  Length prefixes, not delimiters.
func TestAADIsUnambiguousAcrossNULBytes(t *testing.T) {
	a := testVault()
	a.RPID = "a\x00b"

	b := testVault()
	b.RPID = "a"

	if bytes.Equal(a.aad(), b.aad()) {
		t.Error("two different RP IDs produced the same AAD")
	}

	// Same for secret names.
	v := testVault()
	if bytes.Equal(v.secretAAD("x\x00y"), v.secretAAD("x")) {
		t.Error("two different secret names produced the same AAD")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	zero(b)
	for i, got := range b {
		if got != 0 {
			t.Errorf("b[%d] = %d, want 0", i, got)
		}
	}
	zero(nil) // must not panic
}

// flip returns a copy of b with the bit at index i flipped.
func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}
