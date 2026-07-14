// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

// A fake authenticator that models real hmac-secret semantics, and the ways a
// real one can go wrong.
//
// This is the fixture the whole library tests against.  fido.New refuses to open
// under a test binary, so a real key can never reach these tests by accident;
// everything is reached through the port instead.  That means the fake must be
// faithful in the ways that matter:
//
//   - the prf is per-credential (two keys derive different outputs)
//   - the prf depends on the salt (that is the property the gate proves)
//   - the prf depends on whether the operator was verified, because a CTAP2
//     authenticator holds two independent per-credential secrets and returns a
//     different output depending on which one it used
//
// Each knob below turns off exactly one of those, so a test can ask what the
// library does when a device misbehaves in that specific way.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

type fakeAuthenticator struct {
	t *testing.T

	// seeds maps a credential ID to the per-credential secret that credential
	// derives from.  A real authenticator keeps this on the device and never
	// reveals it.
	seeds map[string][]byte

	// saltBytesRead is how many bytes of the salt the device actually reads.
	// Zero means all of them, which is correct behavior.  Setting it lower
	// models the bug the entropy gate exists to catch: a marshaling error with a
	// too-short length field, so the device silently sees a prefix of the salt.
	saltBytesRead int

	// ignoresSalt models a derivation that does not depend on the salt at all,
	// returning a constant per credential.
	ignoresSalt bool

	// notPresent models an authenticator that answers without a touch.
	notPresent bool

	// verified is what the authenticator reports for user verification.  It also
	// selects which per-credential secret is used, as on real hardware.
	verified bool

	// verifiedOnCall overrides `verified` for one specific Derive call (1-based),
	// modeling a device whose verification behavior changes between derivations.
	verifiedOnCall map[int]bool

	// residentKey models a key that stored the credential, consuming a passkey
	// slot.
	residentKey bool

	// noPRF models an authenticator that returns no hmac-secret output.
	noPRF bool

	enrollErr error
	deriveErr error

	enrollCalls int
	deriveCalls int
}

func newFake(t *testing.T) *fakeAuthenticator {
	t.Helper()
	return &fakeAuthenticator{t: t, seeds: make(map[string][]byte)}
}

func (f *fakeAuthenticator) Enroll(req EnrollRequest) (EnrollResult, error) {
	f.enrollCalls++
	if f.enrollErr != nil {
		return EnrollResult{}, f.enrollErr
	}

	credID := []byte(fmt.Sprintf("fake-credential-%d", f.enrollCalls))
	seed := []byte(fmt.Sprintf("fake-seed-%d", f.enrollCalls))
	f.seeds[string(credID)] = seed

	return EnrollResult{
		CredentialID: credID,
		PRFEnabled:   true,
		ResidentKey:  f.residentKey,
	}, nil
}

func (f *fakeAuthenticator) Derive(req DeriveRequest) (DeriveResult, error) {
	f.deriveCalls++
	if f.deriveErr != nil {
		return DeriveResult{}, f.deriveErr
	}
	// A real provider validates too; the fake must not be more permissive than
	// the thing it stands in for, or tests would pass against inputs hardware
	// would reject.
	if err := req.validate(); err != nil {
		return DeriveResult{}, err
	}

	// Select whichever credential in the allow-list this "device" holds, exactly
	// as a platform does when the operator presents one of several enrolled keys.
	var credID []byte
	for _, id := range req.CredentialIDs {
		if _, ok := f.seeds[string(id)]; ok {
			credID = id
			break
		}
	}
	if credID == nil {
		return DeriveResult{}, errors.New("fake: no credential in the allow-list is on this key")
	}

	verified := f.verified
	if v, ok := f.verifiedOnCall[f.deriveCalls]; ok {
		verified = v
	}

	result := DeriveResult{
		CredentialID: credID,
		UserPresent:  !f.notPresent,
		UserVerified: verified,
	}
	if !f.noPRF {
		result.Secret = f.prf(credID, req.Salt, verified)
	}
	return result, nil
}

// prf models the authenticator's hmac-secret computation.
//
// It is a function of the per-credential seed, the salt, and which of the two
// per-credential secrets the device used -- which is what real hardware does.
func (f *fakeAuthenticator) prf(credID, salt []byte, verified bool) []byte {
	mac := hmac.New(sha256.New, f.seeds[string(credID)])

	// The two CredRandoms: verified and unverified derivations return different
	// outputs for the same salt.
	mac.Write([]byte{boolByte(verified)})

	if !f.ignoresSalt {
		mac.Write(salt[:f.effectiveSaltLen(len(salt))])
	}
	return mac.Sum(nil)
}

func (f *fakeAuthenticator) effectiveSaltLen(n int) int {
	if f.saltBytesRead <= 0 || f.saltBytesRead > n {
		return n
	}
	return f.saltBytesRead
}

// enrollAndDeriveForTest is the two-gesture sequence a test needs before it can
// exercise the gate: create a credential, then derive over the real salt.
func (f *fakeAuthenticator) enrollAndDeriveForTest(t *testing.T, rpID string, salt []byte, uv UserVerification) (EnrollResult, DeriveResult) {
	t.Helper()

	cred, err := f.Enroll(EnrollRequest{RPID: rpID, UserID: []byte("u"), UV: uv})
	if err != nil {
		t.Fatalf("Enroll() = %v", err)
	}
	got, err := f.Derive(DeriveRequest{
		RPID:          rpID,
		CredentialIDs: [][]byte{cred.CredentialID},
		Salt:          salt,
		UV:            uv,
	})
	if err != nil {
		t.Fatalf("Derive() = %v", err)
	}
	return cred, got
}

// The fake must itself behave like the thing it stands in for, or every test
// built on it proves nothing.  These assertions pin the three properties the
// library actually depends on.
func TestFakeIsFaithful(t *testing.T) {
	salt := bytes.Repeat([]byte{0x5A}, SaltLen)

	t.Run("prf depends on the salt", func(t *testing.T) {
		f := newFake(t)
		cred, first := f.enrollAndDeriveForTest(t, "rp.invalid", salt, UVDiscouraged)

		other := append([]byte(nil), salt...)
		other[0] ^= 0xFF
		second, err := f.Derive(DeriveRequest{
			RPID:          "rp.invalid",
			CredentialIDs: [][]byte{cred.CredentialID},
			Salt:          other,
			UV:            UVDiscouraged,
		})
		if err != nil {
			t.Fatalf("Derive() = %v", err)
		}
		if bytes.Equal(first.Secret, second.Secret) {
			t.Error("the fake returned the same prf for two different salts")
		}
	})

	t.Run("prf is per credential", func(t *testing.T) {
		f := newFake(t)
		_, a := f.enrollAndDeriveForTest(t, "rp.invalid", salt, UVDiscouraged)
		_, b := f.enrollAndDeriveForTest(t, "rp.invalid", salt, UVDiscouraged)
		if bytes.Equal(a.Secret, b.Secret) {
			t.Error("two credentials derived the same prf")
		}
	})

	t.Run("prf depends on user verification", func(t *testing.T) {
		f := newFake(t)
		cred, unverified := f.enrollAndDeriveForTest(t, "rp.invalid", salt, UVDiscouraged)

		f.verified = true
		verified, err := f.Derive(DeriveRequest{
			RPID:          "rp.invalid",
			CredentialIDs: [][]byte{cred.CredentialID},
			Salt:          salt,
			UV:            UVDiscouraged,
		})
		if err != nil {
			t.Fatalf("Derive() = %v", err)
		}
		if bytes.Equal(unverified.Secret, verified.Secret) {
			t.Error("a verified and an unverified derivation returned the same prf; " +
				"the fake is not modeling the two CredRandoms")
		}
	})

	t.Run("prf is deterministic", func(t *testing.T) {
		f := newFake(t)
		cred, first := f.enrollAndDeriveForTest(t, "rp.invalid", salt, UVDiscouraged)
		second, err := f.Derive(DeriveRequest{
			RPID:          "rp.invalid",
			CredentialIDs: [][]byte{cred.CredentialID},
			Salt:          salt,
			UV:            UVDiscouraged,
		})
		if err != nil {
			t.Fatalf("Derive() = %v", err)
		}
		if !bytes.Equal(first.Secret, second.Secret) {
			t.Error("the same credential and salt derived two different prfs")
		}
	})
}
