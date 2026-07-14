// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func testOptions(t *testing.T, f *fakeAuthenticator) Options {
	t.Helper()
	return Options{RPID: testRPID, RPName: "Test Vault", Roots: f.pki.roots}
}

// createVault runs the full three-gesture enrollment against a fake that attests
// as genuine hardware.
func createVault(t *testing.T) (Admin, *fakeAuthenticator, Options) {
	t.Helper()

	f, _ := newFakeHardware(t)
	opts := testOptions(t, f)
	admin, err := Create(f, opts)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	return admin, f, opts
}

func TestCreateCostsThreeGestures(t *testing.T) {
	admin, f, _ := createVault(t)

	if f.enrollCalls != 1 {
		t.Errorf("enrollCalls = %d, want 1", f.enrollCalls)
	}
	// The real derivation, plus the entropy-gate probe.
	if f.deriveCalls != 2 {
		t.Errorf("deriveCalls = %d, want 2", f.deriveCalls)
	}

	// The vault starts empty, with one key in the default slot.
	if got := admin.Names(); len(got) != 0 {
		t.Errorf("Names() = %v, want empty", got)
	}
	slots := admin.Slots()
	if len(slots) != 1 {
		t.Fatalf("len(Slots()) = %d, want 1", len(slots))
	}
	if slots[0].Slot != firstSlot || slots[0].Label != DefaultLabel {
		t.Errorf("Slots()[0] = %+v, want slot %d labeled %q", slots[0], firstSlot, DefaultLabel)
	}
}

func TestCreateRequiresAnRPID(t *testing.T) {
	f, roots := newFakeHardware(t)
	if _, err := Create(f, Options{Roots: roots}); err == nil {
		t.Error("Create() with no RPID succeeded, want an error")
	}
	if f.enrollCalls != 0 {
		t.Error("Create() reached the authenticator despite invalid options")
	}
}

// A software authenticator attests to nothing.  Create must refuse it, and must
// refuse it before spending any gesture beyond the credential creation.
func TestCreateRefusesASoftwareAuthenticator(t *testing.T) {
	f := newFake(t) // no PKI: attests to nothing
	_, err := Create(f, Options{RPID: testRPID})

	if !errors.Is(err, ErrUnsupportedAttestationFormat) && !errors.Is(err, ErrNoAttestation) {
		t.Fatalf("Create() = %v, want an attestation refusal", err)
	}
	// It never got as far as deriving: the credential was rejected on sight.
	if f.deriveCalls != 0 {
		t.Errorf("deriveCalls = %d, want 0; attestation must be checked before deriving", f.deriveCalls)
	}
}

// A key whose attestation chains to a vendor we do not trust is refused.
func TestCreateRefusesAnUntrustedVendor(t *testing.T) {
	f, _ := newFakeHardware(t)

	// Judge this key against the bundled Yubico roots, which never signed it.
	_, err := Create(f, Options{RPID: testRPID, Roots: BundledRoots()})
	if !errors.Is(err, ErrUntrustedAuthenticator) {
		t.Errorf("Create() = %v, want ErrUntrustedAuthenticator", err)
	}
}

// Nothing is sealed if the entropy gate fails.  There is no vault to return, so
// a truncating device cannot leave a secret wrapped under a low-entropy key.
func TestCreateSealsNothingWhenTheEntropyGateFails(t *testing.T) {
	f, roots := newFakeHardware(t)
	f.saltBytesRead = 16 // the device silently reads half the salt

	admin, err := Create(f, Options{RPID: testRPID, Roots: roots})
	if !errors.Is(err, ErrDerivationIgnoresSalt) {
		t.Fatalf("Create() = %v, want ErrDerivationIgnoresSalt", err)
	}
	if admin != nil {
		t.Error("Create() returned a vault despite failing the entropy gate")
	}
}

func TestCreateRefusesAResidentKey(t *testing.T) {
	f, roots := newFakeHardware(t)
	f.residentKey = true

	if _, err := Create(f, Options{RPID: testRPID, Roots: roots}); !errors.Is(err, ErrResidentKey) {
		t.Errorf("Create() = %v, want ErrResidentKey", err)
	}
}

func TestCreateRefusesAnAbsentTouch(t *testing.T) {
	f, roots := newFakeHardware(t)
	f.notPresent = true

	if _, err := Create(f, Options{RPID: testRPID, Roots: roots}); !errors.Is(err, ErrNotPresent) {
		t.Errorf("Create() = %v, want ErrNotPresent", err)
	}
}

// The whole point, end to end: put a secret, seal, re-open, unlock with a touch,
// and read it back.
func TestPutSealOpenUnlockRead(t *testing.T) {
	admin, f, opts := createVault(t)

	const name, value = "api-key", "sk-live-abc123"
	if err := admin.Put(name, strings.NewReader(value)); err != nil {
		t.Fatalf("Put() = %v", err)
	}

	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}
	admin.Lock()

	// The persisted bytes must not contain the secret.
	if bytes.Contains(sealed, []byte(value)) {
		t.Fatal("the sealed bytes contain the plaintext secret")
	}

	v, err := OpenWith(sealed, opts)
	if err != nil {
		t.Fatalf("OpenWith() = %v", err)
	}

	// Metadata reads with no touch at all.
	before := f.deriveCalls
	if got, want := v.Names(), []string{name}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("Names() = %v, want %v", got, want)
	}
	if f.deriveCalls != before {
		t.Error("reading metadata cost a gesture; it must cost none")
	}

	sess, err := v.Unlock(f)
	if err != nil {
		t.Fatalf("Unlock() = %v", err)
	}
	defer sess.Lock()

	if f.deriveCalls != before+1 {
		t.Errorf("Unlock cost %d derivations, want 1", f.deriveCalls-before)
	}

	got, err := ReadString(sess, name)
	if err != nil {
		t.Fatalf("ReadString() = %v", err)
	}
	if got != value {
		t.Errorf("ReadString() = %q, want %q", got, value)
	}

	// Further reads cost no further touch: the data key is in hand.
	after := f.deriveCalls
	if _, err := ReadString(sess, name); err != nil {
		t.Fatalf("second ReadString() = %v", err)
	}
	if f.deriveCalls != after {
		t.Error("a second read cost another gesture; the touch was spent at Unlock")
	}
}

func TestOpenCostsNoCryptographyAndNoGesture(t *testing.T) {
	admin, f, _ := createVault(t)
	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}

	before := f.deriveCalls
	if _, err := Open(sealed); err != nil {
		t.Fatalf("Open() = %v", err)
	}
	if f.deriveCalls != before {
		t.Error("Open() touched the authenticator; it must not")
	}
}

func TestPutReplacesAndDelete(t *testing.T) {
	admin, _, _ := createVault(t)

	if err := admin.Put("k", strings.NewReader("first")); err != nil {
		t.Fatalf("Put() = %v", err)
	}
	if err := admin.Put("k", strings.NewReader("second")); err != nil {
		t.Fatalf("Put() replacing = %v", err)
	}
	if got := admin.Names(); len(got) != 1 {
		t.Errorf("Names() = %v, want one entry after a replace", got)
	}
	got, err := ReadString(admin, "k")
	if err != nil {
		t.Fatalf("ReadString() = %v", err)
	}
	if got != "second" {
		t.Errorf("ReadString() = %q, want %q", got, "second")
	}

	if err := admin.Delete("k"); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	if got := admin.Names(); len(got) != 0 {
		t.Errorf("Names() = %v, want empty after Delete", got)
	}
	if err := admin.Delete("k"); !errors.Is(err, ErrNoSuchSecret) {
		t.Errorf("Delete() of an absent secret = %v, want ErrNoSuchSecret", err)
	}
	if _, err := admin.Open("k"); !errors.Is(err, ErrNoSuchSecret) {
		t.Errorf("Open() of an absent secret = %v, want ErrNoSuchSecret", err)
	}
}

func TestPutRejectsAnEmptyName(t *testing.T) {
	admin, _, _ := createVault(t)
	if err := admin.Put("", strings.NewReader("v")); err == nil {
		t.Error("Put() with an empty name succeeded, want an error")
	}
}

// Locking forgets the data key.  Everything that needs it must then refuse --
// and refuse with ErrLocked, not with an opaque decryption failure.
func TestLockForgetsTheDataKey(t *testing.T) {
	admin, _, _ := createVault(t)
	if err := admin.Put("k", strings.NewReader("v")); err != nil {
		t.Fatalf("Put() = %v", err)
	}

	admin.Lock()
	admin.Lock() // locking twice is harmless

	if _, err := admin.Open("k"); !errors.Is(err, ErrLocked) {
		t.Errorf("Open() after Lock = %v, want ErrLocked", err)
	}
	if err := admin.Put("k", strings.NewReader("v")); !errors.Is(err, ErrLocked) {
		t.Errorf("Put() after Lock = %v, want ErrLocked", err)
	}
	if err := admin.Delete("k"); !errors.Is(err, ErrLocked) {
		t.Errorf("Delete() after Lock = %v, want ErrLocked", err)
	}
	if err := admin.RemoveKey(0); !errors.Is(err, ErrLocked) {
		t.Errorf("RemoveKey() after Lock = %v, want ErrLocked", err)
	}

	// Metadata still reads: it never needed the key.
	if got := admin.Names(); len(got) != 1 {
		t.Errorf("Names() after Lock = %v, want the secret still listed", got)
	}
	// And the vault can still be persisted -- locking is in-memory only and does
	// not alter the sealed document.
	if _, err := admin.Sealed(); err != nil {
		t.Errorf("Sealed() after Lock = %v, want nil", err)
	}
}

// Closing the reader wipes the plaintext buffer.
func TestSecretReaderClose(t *testing.T) {
	admin, _, _ := createVault(t)
	if err := admin.Put("k", strings.NewReader("plaintext")); err != nil {
		t.Fatalf("Put() = %v", err)
	}

	r, err := admin.Open("k")
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	sr := r.(*secretReader)

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if string(got) != "plaintext" {
		t.Errorf("ReadAll() = %q, want %q", got, "plaintext")
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if !bytes.Equal(sr.buf, make([]byte, len(sr.buf))) {
		t.Error("Close() did not wipe the plaintext buffer")
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close() = %v, want nil", err)
	}
}

func TestEnrollBackupKey(t *testing.T) {
	admin, f, opts := createVault(t)
	if err := admin.Put("k", strings.NewReader("v")); err != nil {
		t.Fatalf("Put() = %v", err)
	}

	before := f.deriveCalls
	slot := FreeSlot(admin.Slots())
	if err := admin.EnrollKey(f, slot, "backup"); err != nil {
		t.Fatalf("EnrollKey() = %v", err)
	}

	// Three gestures on the new key: create, derive, and the entropy probe.
	if f.deriveCalls != before+2 {
		t.Errorf("EnrollKey cost %d derivations, want 2 (derive + entropy probe)", f.deriveCalls-before)
	}
	if got := admin.Slots(); len(got) != 2 {
		t.Fatalf("len(Slots()) = %d, want 2", len(got))
	}

	// The secret was never re-encrypted, and the backup opens the same vault.
	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}
	v, err := OpenWith(sealed, opts)
	if err != nil {
		t.Fatalf("OpenWith() = %v", err)
	}
	sess, err := v.Unlock(f)
	if err != nil {
		t.Fatalf("Unlock() = %v", err)
	}
	defer sess.Lock()

	got, err := ReadString(sess, "k")
	if err != nil {
		t.Fatalf("ReadString() = %v", err)
	}
	if got != "v" {
		t.Errorf("ReadString() = %q, want %q", got, "v")
	}
}

// This is the reason EnrollKey repeats the entropy gate, against the original
// design.  A backup is often enrolled on a different machine than the primary --
// and a different machine is exactly where a per-machine marshaling bug lives.
//
// Here the vault was created on a healthy machine, and the backup is enrolled on
// one whose derivation truncates the salt.  Without the gate, the backup would
// seal happily and nobody would learn until the primary was lost and the backup
// was all that was left.
func TestEnrollKeyRepeatsTheEntropyGate(t *testing.T) {
	admin, f, _ := createVault(t)

	// The vault exists and is healthy.  Now the device starts truncating.
	f.saltBytesRead = 16

	err := admin.EnrollKey(f, 1, "backup")
	if !errors.Is(err, ErrDerivationIgnoresSalt) {
		t.Fatalf("EnrollKey() = %v, want ErrDerivationIgnoresSalt", err)
	}
	if got := admin.Slots(); len(got) != 1 {
		t.Errorf("len(Slots()) = %d, want 1; the bad key must not be enrolled", len(got))
	}
}

func TestEnrollKeyRefusesAnOccupiedSlot(t *testing.T) {
	admin, f, _ := createVault(t)

	if err := admin.EnrollKey(f, firstSlot, "another"); !errors.Is(err, ErrSlotOccupied) {
		t.Errorf("EnrollKey() into an occupied slot = %v, want ErrSlotOccupied", err)
	}
}

func TestEnrollKeyRefusesANegativeSlot(t *testing.T) {
	admin, f, _ := createVault(t)
	if err := admin.EnrollKey(f, -1, "backup"); err == nil {
		t.Error("EnrollKey() into a negative slot succeeded, want an error")
	}
}

func TestEnrollKeyRefusesASoftwareAuthenticator(t *testing.T) {
	admin, _, _ := createVault(t)

	software := newFake(t) // attests to nothing
	err := admin.EnrollKey(software, 1, "backup")
	if !errors.Is(err, ErrUnsupportedAttestationFormat) && !errors.Is(err, ErrNoAttestation) {
		t.Errorf("EnrollKey(software) = %v, want an attestation refusal", err)
	}
}

// A key that verifies the operator differently than the vault was enrolled with
// would derive from the other of its two per-credential secrets, and produce a
// wrapped entry that never opens.  Refuse at enrollment rather than ship a
// backup that silently does not work.
func TestEnrollKeyRefusesAUserVerificationMismatch(t *testing.T) {
	admin, f, _ := createVault(t)

	// The vault was created with an unverified derivation.  This key now verifies.
	f.verified = true

	err := admin.EnrollKey(f, 1, "backup")
	if !errors.Is(err, ErrUserVerificationMismatch) {
		t.Errorf("EnrollKey() = %v, want ErrUserVerificationMismatch", err)
	}
}

func TestRemoveKey(t *testing.T) {
	admin, f, _ := createVault(t)
	if err := admin.EnrollKey(f, 1, "backup"); err != nil {
		t.Fatalf("EnrollKey() = %v", err)
	}

	before := f.deriveCalls
	if err := admin.RemoveKey(1); err != nil {
		t.Fatalf("RemoveKey() = %v", err)
	}
	if f.deriveCalls != before {
		t.Error("RemoveKey cost a gesture; the entry is ciphertext and needs none")
	}
	if got := admin.Slots(); len(got) != 1 {
		t.Errorf("len(Slots()) = %d, want 1", len(got))
	}
	if err := admin.RemoveKey(1); !errors.Is(err, ErrNoSuchSlot) {
		t.Errorf("RemoveKey() of an empty slot = %v, want ErrNoSuchSlot", err)
	}
}

// Removing the last key strands every secret forever.  RemoveKey refuses; the
// caller who means it says so with ForceRemoveKey.
func TestRemoveKeyRefusesTheLastKey(t *testing.T) {
	admin, _, _ := createVault(t)

	if err := admin.RemoveKey(firstSlot); !errors.Is(err, ErrLastKey) {
		t.Fatalf("RemoveKey() of the last key = %v, want ErrLastKey", err)
	}
	if got := admin.Slots(); len(got) != 1 {
		t.Error("the key was removed despite the refusal")
	}
}

func TestForceRemoveKeyRemovesTheLastKey(t *testing.T) {
	admin, _, opts := createVault(t)
	if err := admin.Put("k", strings.NewReader("v")); err != nil {
		t.Fatalf("Put() = %v", err)
	}

	if err := admin.ForceRemoveKey(firstSlot); err != nil {
		t.Fatalf("ForceRemoveKey() = %v", err)
	}
	if got := admin.Slots(); len(got) != 0 {
		t.Errorf("len(Slots()) = %d, want 0", len(got))
	}

	// The vault is now inert: the secret is still there as ciphertext, and no key
	// on earth opens it.  This is exactly what the caller asked for.
	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}
	v, err := OpenWith(sealed, opts)
	if err != nil {
		t.Fatalf("OpenWith() = %v", err)
	}
	if got := v.Names(); len(got) != 1 {
		t.Errorf("Names() = %v, want the secret still listed as ciphertext", got)
	}

	f2, _ := newFakeHardware(t)
	if _, err := v.Unlock(f2); !errors.Is(err, ErrNoKeysEnrolled) {
		t.Errorf("Unlock() of a keyless vault = %v, want ErrNoKeysEnrolled", err)
	}
}

func TestForceRemoveKeyStillChecksTheSlot(t *testing.T) {
	admin, _, _ := createVault(t)
	if err := admin.ForceRemoveKey(9); !errors.Is(err, ErrNoSuchSlot) {
		t.Errorf("ForceRemoveKey() of an empty slot = %v, want ErrNoSuchSlot", err)
	}
}

// An unknown key is a real key that answered -- it is simply not one of ours.
func TestUnlockRefusesAnUnenrolledKey(t *testing.T) {
	admin, _, opts := createVault(t)
	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}

	v, err := OpenWith(sealed, opts)
	if err != nil {
		t.Fatalf("OpenWith() = %v", err)
	}

	// A different key entirely: it holds no credential in the allow-list.
	stranger, _ := newFakeHardware(t)
	if _, err := v.Unlock(stranger); err == nil {
		t.Error("Unlock() with an unenrolled key succeeded, want an error")
	}
}

// The operator set a PIN on their key after enrolling.  The vault is intact; the
// derivation is not the one it was sealed under.  Say that, rather than report
// corrupt ciphertext.
func TestUnlockReportsAUserVerificationMismatch(t *testing.T) {
	admin, f, opts := createVault(t)
	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}

	v, err := OpenWith(sealed, opts)
	if err != nil {
		t.Fatalf("OpenWith() = %v", err)
	}

	f.verified = true // a PIN was set on the key after enrollment

	_, err = v.Unlock(f)
	if !errors.Is(err, ErrUserVerificationMismatch) {
		t.Fatalf("Unlock() = %v, want ErrUserVerificationMismatch", err)
	}
	if strings.Contains(err.Error(), "authenticat") && !strings.Contains(err.Error(), "PIN") {
		t.Errorf("the error should explain the PIN, not read as corruption: %v", err)
	}
}

func TestUnlockRefusesAnAbsentTouch(t *testing.T) {
	admin, f, opts := createVault(t)
	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}
	v, err := OpenWith(sealed, opts)
	if err != nil {
		t.Fatalf("OpenWith() = %v", err)
	}

	f.notPresent = true
	if _, err := v.Unlock(f); !errors.Is(err, ErrNotPresent) {
		t.Errorf("Unlock() = %v, want ErrNotPresent", err)
	}
}

// A vault that never passed the entropy gate is refused BEFORE a touch is asked
// for.  The operator must not spend a gesture to discover their vault is
// untrustworthy.
func TestUnlockRefusesAnUnverifiedVaultWithoutATouch(t *testing.T) {
	admin, f, opts := createVault(t)
	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}

	// Strip the marker, as an attacker with write access to the bytes would.
	doc, err := parseSealed(sealed)
	if err != nil {
		t.Fatalf("parseSealed() = %v", err)
	}
	doc.EntropyVerified = false
	stripped, err := doc.marshal()
	if err != nil {
		t.Fatalf("marshal() = %v", err)
	}

	v, err := OpenWith(stripped, opts)
	if err != nil {
		t.Fatalf("OpenWith() = %v", err)
	}

	before := f.deriveCalls
	if _, err := v.Unlock(f); !errors.Is(err, ErrNotEntropyVerified) {
		t.Fatalf("Unlock() = %v, want ErrNotEntropyVerified", err)
	}
	if f.deriveCalls != before {
		t.Error("Unlock asked for a touch before refusing an unverified vault")
	}
}

// OpenWith must not honor an RPID that disagrees with the sealed document: the
// enrolled credentials would not answer for a different relying party, so a
// caller passing the wrong one has a bug, not a preference.
func TestOpenWithRefusesAConflictingRPID(t *testing.T) {
	admin, _, _ := createVault(t)
	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}

	if _, err := OpenWith(sealed, Options{RPID: "other.invalid"}); err == nil {
		t.Error("OpenWith() with a conflicting RPID succeeded, want an error")
	}
	if _, err := OpenWith(sealed, Options{RPID: testRPID}); err != nil {
		t.Errorf("OpenWith() with the matching RPID = %v, want nil", err)
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	if _, err := Open([]byte("not a vault")); !errors.Is(err, ErrWrongFormat) {
		t.Errorf("Open() = %v, want ErrWrongFormat", err)
	}
}

func TestReadStringOnAnAbsentSecret(t *testing.T) {
	admin, _, _ := createVault(t)
	if _, err := ReadString(admin, "nope"); !errors.Is(err, ErrNoSuchSecret) {
		t.Errorf("ReadString() = %v, want ErrNoSuchSecret", err)
	}
}

// A vault with several secrets: each opens under the one data key, and each is
// bound to its own name.
func TestSeveralSecrets(t *testing.T) {
	admin, f, opts := createVault(t)

	want := map[string]string{
		"api-key":        "sk-live-abc",
		"webhook-secret": "whsec-xyz",
		"database-url":   "postgres://localhost/db",
	}
	for name, value := range want {
		if err := admin.Put(name, strings.NewReader(value)); err != nil {
			t.Fatalf("Put(%q) = %v", name, err)
		}
	}

	sealed, err := admin.Sealed()
	if err != nil {
		t.Fatalf("Sealed() = %v", err)
	}
	v, err := OpenWith(sealed, opts)
	if err != nil {
		t.Fatalf("OpenWith() = %v", err)
	}
	sess, err := v.Unlock(f)
	if err != nil {
		t.Fatalf("Unlock() = %v", err)
	}
	defer sess.Lock()

	if got := len(sess.Names()); got != len(want) {
		t.Errorf("len(Names()) = %d, want %d", got, len(want))
	}
	for name, value := range want {
		got, err := ReadString(sess, name)
		if err != nil {
			t.Fatalf("ReadString(%q) = %v", name, err)
		}
		if got != value {
			t.Errorf("ReadString(%q) = %q, want %q", name, got, value)
		}
	}
}
