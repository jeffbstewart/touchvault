// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// goodSalt is a salt of exactly the required length.
func goodSalt() []byte { return bytes.Repeat([]byte{0xA5}, SaltLen) }

func TestDeriveRequestValidate(t *testing.T) {
	cred := []byte{1, 2, 3}

	tests := []struct {
		name string
		req  DeriveRequest
		want error
	}{
		{
			name: "valid",
			req:  DeriveRequest{CredentialIDs: [][]byte{cred}, Salt: goodSalt()},
			want: nil,
		},
		{
			name: "valid with several credentials",
			req:  DeriveRequest{CredentialIDs: [][]byte{cred, {4, 5}}, Salt: goodSalt()},
			want: nil,
		},
		{
			name: "no credentials",
			req:  DeriveRequest{Salt: goodSalt()},
			want: ErrNoCredentialID,
		},
		{
			name: "empty credential among good ones",
			req:  DeriveRequest{CredentialIDs: [][]byte{cred, {}}, Salt: goodSalt()},
			want: ErrNoCredentialID,
		},
		{
			name: "nil credential among good ones",
			req:  DeriveRequest{CredentialIDs: [][]byte{cred, nil}, Salt: goodSalt()},
			want: ErrNoCredentialID,
		},
		{
			name: "salt absent",
			req:  DeriveRequest{CredentialIDs: [][]byte{cred}},
			want: ErrSaltLength,
		},
		{
			name: "salt one byte short",
			req:  DeriveRequest{CredentialIDs: [][]byte{cred}, Salt: bytes.Repeat([]byte{1}, SaltLen-1)},
			want: ErrSaltLength,
		},
		{
			name: "salt one byte long",
			req:  DeriveRequest{CredentialIDs: [][]byte{cred}, Salt: bytes.Repeat([]byte{1}, SaltLen+1)},
			want: ErrSaltLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.validate()
			if !errors.Is(err, tt.want) {
				t.Errorf("validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

// A credential ID is checked before the salt, so a request that is wrong in
// both ways names the credential.  The order is not arbitrary: a caller who
// passed no credential has a different bug than one who passed a short salt,
// and reporting the first failure found keeps the message about their bug.
func TestDeriveRequestValidateChecksCredentialBeforeSalt(t *testing.T) {
	req := DeriveRequest{} // no credentials and no salt
	if err := req.validate(); !errors.Is(err, ErrNoCredentialID) {
		t.Errorf("validate() = %v, want %v", err, ErrNoCredentialID)
	}
}

func TestTimeoutDefaults(t *testing.T) {
	tests := []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{name: "unset", set: 0, want: DefaultTimeout},
		{name: "negative", set: -time.Second, want: DefaultTimeout},
		{name: "explicit", set: 5 * time.Second, want: 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (DeriveRequest{Timeout: tt.set}).timeout(); got != tt.want {
				t.Errorf("DeriveRequest.timeout() = %v, want %v", got, tt.want)
			}
			if got := (EnrollRequest{Timeout: tt.set}).timeout(); got != tt.want {
				t.Errorf("EnrollRequest.timeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserVerificationString(t *testing.T) {
	if got, want := UVDiscouraged.String(), "discouraged"; got != want {
		t.Errorf("UVDiscouraged.String() = %q, want %q", got, want)
	}
	if got, want := UVRequired.String(), "required"; got != want {
		t.Errorf("UVRequired.String() = %q, want %q", got, want)
	}
}

// The zero value must be the safe one.  A caller who leaves UV unset asks for
// presence only, and so never triggers the PIN-creation walkthrough that
// UVRequired can start on a key that has no PIN — a device-wide change
// affecting every other service enrolled on that key.
func TestUserVerificationZeroValueIsDiscouraged(t *testing.T) {
	var uv UserVerification
	if uv != UVDiscouraged {
		t.Errorf("zero UserVerification = %v, want UVDiscouraged", uv)
	}
}

// Every sentinel must be distinct.  Callers branch on these with errors.Is, so
// two that compared equal would silently merge two different failures — and one
// of them, ErrUserVerificationMismatch, exists precisely to keep a recoverable
// condition from being reported as corruption.
func TestSentinelsAreDistinct(t *testing.T) {
	sentinels := map[string]error{
		"ErrNoSuchSecret":                 ErrNoSuchSecret,
		"ErrSlotOccupied":                 ErrSlotOccupied,
		"ErrNoSuchSlot":                   ErrNoSuchSlot,
		"ErrUnknownCredential":            ErrUnknownCredential,
		"ErrUserVerificationMismatch":     ErrUserVerificationMismatch,
		"ErrNotPresent":                   ErrNotPresent,
		"ErrDerivationIgnoresSalt":        ErrDerivationIgnoresSalt,
		"ErrNotEntropyVerified":           ErrNotEntropyVerified,
		"ErrWrongFormat":                  ErrWrongFormat,
		"ErrNoAttestation":                ErrNoAttestation,
		"ErrUnsupportedAttestationFormat": ErrUnsupportedAttestationFormat,
		"ErrUntrustedAuthenticator":       ErrUntrustedAuthenticator,
		"ErrAttestationSignature":         ErrAttestationSignature,
		"ErrNoPRF":                        ErrNoPRF,
		"ErrNoAuthenticatorData":          ErrNoAuthenticatorData,
		"ErrSaltLength":                   ErrSaltLength,
		"ErrNoCredentialID":               ErrNoCredentialID,
	}

	for aName, a := range sentinels {
		if a == nil {
			t.Errorf("%s is nil", aName)
			continue
		}
		if a.Error() == "" {
			t.Errorf("%s has an empty message", aName)
		}
		for bName, b := range sentinels {
			if aName == bName {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("errors.Is(%s, %s) is true; sentinels must be distinct", aName, bName)
			}
		}
	}
}

// A wrapped sentinel must still be recognizable, since that is how every caller
// is expected to use these.
func TestSentinelSurvivesWrapping(t *testing.T) {
	err := fmt.Errorf("unlocking vault: %w", ErrUserVerificationMismatch)
	if !errors.Is(err, ErrUserVerificationMismatch) {
		t.Errorf("errors.Is(wrapped, ErrUserVerificationMismatch) = false, want true")
	}
	if errors.Is(err, ErrNotPresent) {
		t.Errorf("errors.Is(wrapped, ErrNotPresent) = true, want false")
	}
}
