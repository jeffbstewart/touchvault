// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import "fmt"

// SlotInfo describes one enrolled security key.  It is metadata: readable
// without a touch, authenticated so it cannot be tampered with, and never
// secret.
type SlotInfo struct {
	// Slot is the slot number the key occupies.  Slots are arbitrary
	// non-negative integers chosen by the caller, not indices into a
	// fixed-size table: the vault imposes no maximum, and the numbers need not
	// be contiguous.  A caller that wants exactly a primary and a backup gets
	// that by choosing 0 and 1 and enrolling no more; that is a policy for the
	// caller, not a property of the crypto.
	Slot int

	// Label names the slot for a human, for example "primary" or
	// "backup-in-safe".  It is not interpreted.
	Label string

	// CredentialIDHex is a short prefix of the credential ID, hex-encoded.  It
	// is a handle for telling two enrolled keys apart in a listing, not a
	// secret and not enough to derive with.
	CredentialIDHex string
}

// String implements [fmt.Stringer].
func (s SlotInfo) String() string {
	return fmt.Sprintf("slot %d (%s) %s", s.Slot, s.Label, s.CredentialIDHex)
}

// Inspector reads a vault's metadata.  Every seal in the document binds this
// metadata into its AAD, so it can be read without a touch and still cannot be
// tampered with.
//
// Both [Vault] (sealed) and [Session] (unlocked) embed this, so an [Admin] —
// which is a Session — can enumerate.  That is not a convenience.  EnrollKey
// takes a slot number, and slots are arbitrary rather than a fixed pair, so an
// admin must be able to see which slots are occupied before it can choose a
// free one; an admin that could not enumerate could only guess, and a guess
// that lands on an occupied slot is exactly the collision ErrSlotOccupied
// exists to refuse.  Delete needs Names for the same reason.
type Inspector interface {
	// Names lists the secret names, sorted.  Names are metadata, not secret.
	Names() []string

	// Slots lists the enrolled security keys, sorted by slot number.  Only
	// occupied slots appear: the absence of a number means that slot is free.
	Slots() []SlotInfo
}

// FreeSlot returns the lowest non-negative slot number not present in slots.
//
// It is a convenience for the common case — "enroll a backup, I do not care
// where" — and needs no touch, since slots is metadata.  A caller that wants a
// specific slot ignores this and passes the number it wants; EnrollKey refuses
// an occupied one with [ErrSlotOccupied] either way.
func FreeSlot(slots []SlotInfo) int {
	occupied := make(map[int]bool, len(slots))
	for _, s := range slots {
		occupied[s.Slot] = true
	}
	for n := 0; ; n++ {
		if !occupied[n] {
			return n
		}
	}
}
