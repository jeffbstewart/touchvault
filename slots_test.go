// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

import "testing"

func TestFreeSlot(t *testing.T) {
	tests := []struct {
		name  string
		slots []SlotInfo
		want  int
	}{
		{
			name:  "nil",
			slots: nil,
			want:  0,
		},
		{
			name:  "empty",
			slots: []SlotInfo{},
			want:  0,
		},
		{
			name:  "one occupied",
			slots: []SlotInfo{{Slot: 0}},
			want:  1,
		},
		{
			name:  "primary and backup occupied",
			slots: []SlotInfo{{Slot: 0}, {Slot: 1}},
			want:  2,
		},
		{
			// A removed key leaves a hole, and the hole is reused.  Slot numbers
			// are not a monotonic counter; they are the identity a wrapped data
			// key is bound to, and a freed one is free.
			name:  "reuses a hole left by a removed key",
			slots: []SlotInfo{{Slot: 0}, {Slot: 2}},
			want:  1,
		},
		{
			name:  "unsorted input",
			slots: []SlotInfo{{Slot: 2}, {Slot: 0}, {Slot: 1}},
			want:  3,
		},
		{
			// Slots need not be contiguous or small.
			name:  "sparse numbering",
			slots: []SlotInfo{{Slot: 7}, {Slot: 99}},
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FreeSlot(tt.slots); got != tt.want {
				t.Errorf("FreeSlot(%v) = %d, want %d", tt.slots, got, tt.want)
			}
		})
	}
}

func TestSlotInfoString(t *testing.T) {
	s := SlotInfo{Slot: 1, Label: "backup", CredentialIDHex: "a1b2c3d4"}
	if got, want := s.String(), "slot 1 (backup) a1b2c3d4"; got != want {
		t.Errorf("SlotInfo.String() = %q, want %q", got, want)
	}
}
