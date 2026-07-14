// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// populatedVault returns a vault with two enrolled keys and two secrets, whose
// seals are real: it is the fixture for round-trip and parse tests.
func populatedVault(t *testing.T) (*sealedVault, []byte) {
	t.Helper()

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
	v.Keys = []sealedKey{a, b}

	one, err := v.sealSecret(dataKey, "api-key", []byte("sk-live-abc"))
	if err != nil {
		t.Fatalf("sealSecret() = %v", err)
	}
	two, err := v.sealSecret(dataKey, "webhook-secret", []byte("whsec-xyz"))
	if err != nil {
		t.Fatalf("sealSecret() = %v", err)
	}
	v.Secrets = []sealedSecret{one, two}

	return v, dataKey
}

// The document must survive a trip through JSON and still decrypt.  This is the
// property the whole format exists for: the caller persists bytes, and the bytes
// come back.
func TestMarshalParseRoundTrip(t *testing.T) {
	v, dataKey := populatedVault(t)
	prfA := bytes.Repeat([]byte{0x11}, 32)

	data, err := v.marshal()
	if err != nil {
		t.Fatalf("marshal() = %v", err)
	}

	got, err := parseSealed(data)
	if err != nil {
		t.Fatalf("parseSealed() = %v", err)
	}

	if !reflect.DeepEqual(v, got) {
		t.Error("the parsed vault differs from the marshaled one")
	}

	// And it still decrypts, which DeepEqual alone would not prove.
	entry, ok := got.findKey([]byte("cred-a"))
	if !ok {
		t.Fatal("findKey(cred-a) not found after round trip")
	}
	unwrapped, err := got.unwrapDataKey(entry, prfA)
	if err != nil {
		t.Fatalf("unwrapDataKey() after round trip = %v", err)
	}
	if !bytes.Equal(unwrapped, dataKey) {
		t.Error("the data key did not survive the round trip")
	}

	secret, ok := got.findSecret("api-key")
	if !ok {
		t.Fatal("findSecret(api-key) not found after round trip")
	}
	plaintext, err := got.openSecret(unwrapped, secret)
	if err != nil {
		t.Fatalf("openSecret() after round trip = %v", err)
	}
	if want := []byte("sk-live-abc"); !bytes.Equal(plaintext, want) {
		t.Errorf("openSecret() = %q, want %q", plaintext, want)
	}
}

// Metadata is readable with no key and no touch.  That is a feature: a vault can
// be listed and audited by something that cannot read a secret.
func TestSealedMetadataIsReadableWithoutAKey(t *testing.T) {
	v, _ := populatedVault(t)
	data, err := v.marshal()
	if err != nil {
		t.Fatalf("marshal() = %v", err)
	}

	parsed, err := parseSealed(data)
	if err != nil {
		t.Fatalf("parseSealed() = %v", err)
	}

	if got, want := parsed.names(), []string{"api-key", "webhook-secret"}; !reflect.DeepEqual(got, want) {
		t.Errorf("names() = %v, want %v", got, want)
	}
	slots := parsed.slots()
	if len(slots) != 2 {
		t.Fatalf("len(slots()) = %d, want 2", len(slots))
	}
	if slots[0].Slot != 0 || slots[0].Label != "primary" {
		t.Errorf("slots()[0] = %+v, want slot 0 primary", slots[0])
	}
	if slots[1].Slot != 1 || slots[1].Label != "backup" {
		t.Errorf("slots()[1] = %+v, want slot 1 backup", slots[1])
	}
}

// No plaintext secret may appear in the persisted bytes.  The one test that
// would catch the worst possible bug.
func TestSealedBytesContainNoPlaintext(t *testing.T) {
	v, _ := populatedVault(t)
	data, err := v.marshal()
	if err != nil {
		t.Fatalf("marshal() = %v", err)
	}

	for _, plaintext := range []string{"sk-live-abc", "whsec-xyz"} {
		if bytes.Contains(data, []byte(plaintext)) {
			t.Errorf("the sealed bytes contain the plaintext %q", plaintext)
		}
	}
}

func TestNamesAndSlotsAreSorted(t *testing.T) {
	v := testVault()
	v.Secrets = []sealedSecret{{Name: "zebra"}, {Name: "alpha"}, {Name: "mike"}}
	v.Keys = []sealedKey{
		{Slot: 2, CredentialID: []byte("c")},
		{Slot: 0, CredentialID: []byte("a")},
		{Slot: 1, CredentialID: []byte("b")},
	}

	if got, want := v.names(), []string{"alpha", "mike", "zebra"}; !reflect.DeepEqual(got, want) {
		t.Errorf("names() = %v, want %v", got, want)
	}
	for i, s := range v.slots() {
		if s.Slot != i {
			t.Errorf("slots()[%d].Slot = %d, want %d", i, s.Slot, i)
		}
	}
}

// A credential ID shorter than the display prefix must not panic the listing.
func TestSlotsHandlesShortCredentialID(t *testing.T) {
	v := testVault()
	v.Keys = []sealedKey{{Slot: 0, Label: "primary", CredentialID: []byte{0xAB}}}

	slots := v.slots()
	if len(slots) != 1 {
		t.Fatalf("len(slots()) = %d, want 1", len(slots))
	}
	if got, want := slots[0].CredentialIDHex, "ab"; got != want {
		t.Errorf("CredentialIDHex = %q, want %q", got, want)
	}
}

func TestUVRequirementMirrorsEnrollment(t *testing.T) {
	v := testVault()

	v.UserVerified = false
	if got := v.uvRequirement(); got != UVDiscouraged {
		t.Errorf("uvRequirement() = %v, want UVDiscouraged", got)
	}

	v.UserVerified = true
	if got := v.uvRequirement(); got != UVRequired {
		t.Errorf("uvRequirement() = %v, want UVRequired", got)
	}
}

func TestCredentialIDsIsTheAllowList(t *testing.T) {
	v, _ := populatedVault(t)
	ids := v.credentialIDs()
	if len(ids) != 2 {
		t.Fatalf("len(credentialIDs()) = %d, want 2", len(ids))
	}
	if !bytes.Equal(ids[0], []byte("cred-a")) || !bytes.Equal(ids[1], []byte("cred-b")) {
		t.Errorf("credentialIDs() = %q, want [cred-a cred-b]", ids)
	}
}

func TestSlotOccupiedAndFind(t *testing.T) {
	v, _ := populatedVault(t)

	if !v.slotOccupied(0) || !v.slotOccupied(1) {
		t.Error("slots 0 and 1 should be occupied")
	}
	if v.slotOccupied(2) {
		t.Error("slot 2 should be free")
	}
	if _, ok := v.findKey([]byte("cred-a")); !ok {
		t.Error("findKey(cred-a) = not found")
	}
	if _, ok := v.findKey([]byte("cred-z")); ok {
		t.Error("findKey(cred-z) = found, want not found")
	}
	if _, ok := v.findSecret("api-key"); !ok {
		t.Error("findSecret(api-key) = not found")
	}
	if _, ok := v.findSecret("nope"); ok {
		t.Error("findSecret(nope) = found, want not found")
	}
}

// parseSealed establishes that a document is self-consistent, never that it is
// authentic.  Every one of these is a document an attacker could hand us, and
// each must be refused as ErrWrongFormat rather than half-accepted.
func TestParseSealedRejects(t *testing.T) {
	valid, _ := populatedVault(t)

	tests := []struct {
		name   string
		mutate func(*sealedVault)
		raw    []byte // used instead of mutate when non-nil
	}{
		{
			name: "not json",
			raw:  []byte("{definitely not json"),
		},
		{
			name:   "unknown format",
			mutate: func(v *sealedVault) { v.Format = 2 },
		},
		{
			name:   "format zero",
			mutate: func(v *sealedVault) { v.Format = 0 },
		},
		{
			name:   "short salt",
			mutate: func(v *sealedVault) { v.Salt = v.Salt[:SaltLen-1] },
		},
		{
			name:   "no salt",
			mutate: func(v *sealedVault) { v.Salt = nil },
		},
		{
			name:   "no rp id",
			mutate: func(v *sealedVault) { v.RPID = "" },
		},
		{
			name:   "negative slot",
			mutate: func(v *sealedVault) { v.Keys[0].Slot = -1 },
		},
		{
			name:   "duplicate slot",
			mutate: func(v *sealedVault) { v.Keys[1].Slot = v.Keys[0].Slot },
		},
		{
			name:   "duplicate credential",
			mutate: func(v *sealedVault) { v.Keys[1].CredentialID = v.Keys[0].CredentialID },
		},
		{
			name:   "key with no credential",
			mutate: func(v *sealedVault) { v.Keys[0].CredentialID = nil },
		},
		{
			name:   "duplicate secret name",
			mutate: func(v *sealedVault) { v.Secrets[1].Name = v.Secrets[0].Name },
		},
		{
			name:   "secret with no name",
			mutate: func(v *sealedVault) { v.Secrets[0].Name = "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.raw
			if data == nil {
				// Deep-copy through JSON so a mutation cannot leak between cases.
				encoded, err := json.Marshal(valid)
				if err != nil {
					t.Fatalf("json.Marshal() = %v", err)
				}
				var v sealedVault
				if err := json.Unmarshal(encoded, &v); err != nil {
					t.Fatalf("json.Unmarshal() = %v", err)
				}
				tt.mutate(&v)
				if data, err = v.marshal(); err != nil {
					t.Fatalf("marshal() = %v", err)
				}
			}

			_, err := parseSealed(data)
			if err == nil {
				t.Fatal("parseSealed() succeeded, want failure")
			}
			if !errors.Is(err, ErrWrongFormat) {
				t.Errorf("parseSealed() = %v, want ErrWrongFormat", err)
			}
		})
	}
}

// An empty vault -- no keys, no secrets -- is structurally valid.  Create makes
// one before the first Put, so parsing must not demand contents.
func TestParseSealedAcceptsAnEmptyVault(t *testing.T) {
	v := testVault()
	data, err := v.marshal()
	if err != nil {
		t.Fatalf("marshal() = %v", err)
	}
	if _, err := parseSealed(data); err != nil {
		t.Errorf("parseSealed(empty vault) = %v, want nil", err)
	}
}
