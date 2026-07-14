// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

const testRPID = "vault.example.invalid"

func entropySalt() []byte { return bytes.Repeat([]byte{0x5A}, SaltLen) }

// runGate performs the enroll-and-derive a real enrollment would, then runs the
// gate against the same authenticator -- the sequence Create and EnrollKey use.
func runGate(t *testing.T, f *fakeAuthenticator) error {
	t.Helper()

	salt := entropySalt()
	cred, got := f.enrollAndDeriveForTest(t, testRPID, salt, UVDiscouraged)
	return verifyDerivationDependsOnSalt(
		f, testRPID, cred.CredentialID, salt, got.Secret, UVDiscouraged, got.UserVerified)
}

// An honest device passes, and costs exactly one extra gesture: the probe
// derivation, on top of the enroll and the real derive.
func TestGatePassesOnAnHonestDevice(t *testing.T) {
	f := newFake(t)
	if err := runGate(t, f); err != nil {
		t.Fatalf("verifyDerivationDependsOnSalt() = %v, want nil", err)
	}
	if f.enrollCalls != 1 {
		t.Errorf("enrollCalls = %d, want 1", f.enrollCalls)
	}
	if f.deriveCalls != 2 {
		t.Errorf("deriveCalls = %d, want 2 (the real derivation and the probe)", f.deriveCalls)
	}
}

// A device whose derivation does not depend on the salt at all returns a
// constant.  Refused.
func TestGateCatchesADerivationThatIgnoresTheSalt(t *testing.T) {
	f := newFake(t)
	f.ignoresSalt = true

	if err := runGate(t, f); !errors.Is(err, ErrDerivationIgnoresSalt) {
		t.Errorf("verifyDerivationDependsOnSalt() = %v, want ErrDerivationIgnoresSalt", err)
	}
}

// The bug this is really hunting: a marshaling error with a too-short length
// field, so the device only ever reads a prefix of the salt.  The derivation
// still varies with the salt -- just with less of it -- so nothing downstream
// could ever notice.  Refused, at every truncation length.
func TestGateCatchesATruncatedSalt(t *testing.T) {
	for _, readBytes := range []int{1, 2, 8, 16, 24, SaltLen - 1} {
		t.Run(namedBytes(readBytes), func(t *testing.T) {
			f := newFake(t)
			f.saltBytesRead = readBytes

			if err := runGate(t, f); !errors.Is(err, ErrDerivationIgnoresSalt) {
				t.Errorf("device reading only %d salt bytes: got %v, want ErrDerivationIgnoresSalt",
					readBytes, err)
			}
		})
	}
}

// This is the test that justifies the design, and it is the one to read.
//
// The probe flips the salt's LAST byte.  Against a device that truncates the
// salt, that byte is past what the device reads, so both derivations return the
// same output and the truncation is caught.
//
// Had the probe flipped the FIRST byte instead -- or had it used a freshly random
// salt -- it would have changed a byte the device does read.  The two outputs
// would differ, the check would pass, and the bug would survive fully intact.
//
// The tail is not a stylistic choice.  It is the only probe position that
// catches truncation, and this asserts both halves of that claim.
func TestGateProbesTheTailBecauseTheHeadWouldMissTruncation(t *testing.T) {
	const readBytes = 16 // the device silently sees only the first half

	f := newFake(t)
	f.saltBytesRead = readBytes
	salt := entropySalt()

	cred, real := f.enrollAndDeriveForTest(t, testRPID, salt, UVDiscouraged)

	derive := func(s []byte) []byte {
		t.Helper()
		got, err := f.Derive(DeriveRequest{
			RPID:          testRPID,
			CredentialIDs: [][]byte{cred.CredentialID},
			Salt:          s,
			UV:            UVDiscouraged,
		})
		if err != nil {
			t.Fatalf("Derive() = %v", err)
		}
		return got.Secret
	}

	// A head probe: flip the first byte, which this device DOES read.
	head := append([]byte(nil), salt...)
	head[0] ^= 0xFF
	if bytes.Equal(derive(head), real.Secret) {
		t.Fatal("test is not exercising the claim: the head probe already differs")
	}
	// So a gate built on a head probe would see two different outputs and
	// conclude, wrongly, that the derivation depends on the whole salt.

	// The tail probe: flip the last byte, which this device does NOT read.
	tail := append([]byte(nil), salt...)
	tail[len(tail)-1] ^= 0xFF
	if !bytes.Equal(derive(tail), real.Secret) {
		t.Fatal("test is not exercising the claim: the tail probe already differs")
	}
	// Identical outputs, so the real gate refuses.

	if err := verifyDerivationDependsOnSalt(
		f, testRPID, cred.CredentialID, salt, real.Secret, UVDiscouraged, real.UserVerified,
	); !errors.Is(err, ErrDerivationIgnoresSalt) {
		t.Errorf("verifyDerivationDependsOnSalt() = %v, want ErrDerivationIgnoresSalt", err)
	}
}

// Presence is the entire point.  A probe derivation that reported no touch
// proves nothing, whatever the arithmetic said.
func TestGateRequiresPresence(t *testing.T) {
	f := newFake(t)
	salt := entropySalt()
	cred, got := f.enrollAndDeriveForTest(t, testRPID, salt, UVDiscouraged)

	f.notPresent = true // the probe derivation answers without a touch
	err := verifyDerivationDependsOnSalt(
		f, testRPID, cred.CredentialID, salt, got.Secret, UVDiscouraged, got.UserVerified)
	if !errors.Is(err, ErrNotPresent) {
		t.Errorf("verifyDerivationDependsOnSalt() = %v, want ErrNotPresent", err)
	}
}

// The one way this gate could lie.
//
// If the probe derivation used the OTHER per-credential secret -- because the
// authenticator verified the operator this time and did not last time -- then the
// two outputs would differ for a reason that has nothing to do with the salt, and
// the gate would pass a device that truncates.
//
// So the probe must report the same user_verified as the enrollment derivation,
// and a difference is reported as a mismatch rather than quietly accepted.
func TestGateRefusesWhenVerificationChangesUnderIt(t *testing.T) {
	f := newFake(t)
	f.saltBytesRead = 16 // a truncating device, which the gate must still catch

	// Derive call 1 is the enrollment derivation (unverified).  Call 2 is the
	// probe, and this device verifies on that one -- so it uses its other
	// CredRandom and returns a different output for a reason unrelated to salt.
	f.verifiedOnCall = map[int]bool{2: true}

	err := runGate(t, f)
	if !errors.Is(err, ErrUserVerificationMismatch) {
		t.Fatalf("verifyDerivationDependsOnSalt() = %v, want ErrUserVerificationMismatch", err)
	}
	// And critically: it did NOT return nil.  Without this check the differing
	// outputs would have looked like proof of salt dependence on a device that
	// reads half the salt.
	if err == nil {
		t.Error("the gate passed a truncating device because verification changed under it")
	}
}

func TestGateRejectsBadInput(t *testing.T) {
	f := newFake(t)
	salt := entropySalt()
	cred, got := f.enrollAndDeriveForTest(t, testRPID, salt, UVDiscouraged)

	t.Run("short salt", func(t *testing.T) {
		err := verifyDerivationDependsOnSalt(
			f, testRPID, cred.CredentialID, salt[:SaltLen-1], got.Secret, UVDiscouraged, false)
		if !errors.Is(err, ErrSaltLength) {
			t.Errorf("got %v, want ErrSaltLength", err)
		}
	})

	t.Run("no real output to compare against", func(t *testing.T) {
		err := verifyDerivationDependsOnSalt(
			f, testRPID, cred.CredentialID, salt, nil, UVDiscouraged, false)
		if !errors.Is(err, ErrNoPRF) {
			t.Errorf("got %v, want ErrNoPRF", err)
		}
	})
}

// An authenticator that returns no hmac-secret output on the probe must not be
// read as "the outputs differ, therefore the salt matters".
func TestGateRejectsAnEmptyProbeOutput(t *testing.T) {
	f := newFake(t)
	salt := entropySalt()
	cred, got := f.enrollAndDeriveForTest(t, testRPID, salt, UVDiscouraged)

	f.noPRF = true
	err := verifyDerivationDependsOnSalt(
		f, testRPID, cred.CredentialID, salt, got.Secret, UVDiscouraged, got.UserVerified)
	if !errors.Is(err, ErrNoPRF) {
		t.Errorf("verifyDerivationDependsOnSalt() = %v, want ErrNoPRF", err)
	}
}

func TestGatePropagatesDeriveError(t *testing.T) {
	f := newFake(t)
	salt := entropySalt()
	cred, got := f.enrollAndDeriveForTest(t, testRPID, salt, UVDiscouraged)

	sentinel := errors.New("the key was unplugged")
	f.deriveErr = sentinel

	err := verifyDerivationDependsOnSalt(
		f, testRPID, cred.CredentialID, salt, got.Secret, UVDiscouraged, got.UserVerified)
	if !errors.Is(err, sentinel) {
		t.Errorf("verifyDerivationDependsOnSalt() = %v, want the underlying error", err)
	}
}

// A verified device is not a broken device: the gate must pass when the
// authenticator consistently verifies, which is what Windows does whenever the
// key has a PIN.
func TestGatePassesOnAConsistentlyVerifyingDevice(t *testing.T) {
	f := newFake(t)
	f.verified = true

	if err := runGate(t, f); err != nil {
		t.Errorf("verifyDerivationDependsOnSalt() = %v, want nil", err)
	}
}

func namedBytes(n int) string {
	return fmt.Sprintf("device reads %d of %d salt bytes", n, SaltLen)
}
