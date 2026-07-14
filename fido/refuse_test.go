// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package fido

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// clearAgentMarkers unsets every agent marker for the duration of a test, and
// restores them afterwards.
//
// This is needed because the tests may well be RUN by a coding agent — as these
// were — in which case CLAUDECODE is already set in the ambient environment.
// That is the guard working as designed, but it means a test that sets one
// marker and asserts on the message would be reading a different marker's
// refusal.  Clear the field first, then set exactly the one under test.
func clearAgentMarkers(t *testing.T) {
	t.Helper()
	for _, name := range agentEnvMarkers {
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("os.Unsetenv(%s) = %v", name, err)
		}
		t.Cleanup(func() {
			if err := os.Setenv(name, value); err != nil {
				t.Errorf("restoring %s = %v", name, err)
			}
		})
	}
}

// The guard that matters most, and the one that can only be tested from inside a
// test binary: New must refuse to open real hardware here.
//
// If this ever fails, `go test ./...` on a machine with a key plugged in would
// raise a platform prompt the operator did not ask for -- and an operator who
// learns to touch their key at prompts they did not initiate has lost the only
// thing the touch was ever worth.
func TestNewRefusesUnderTest(t *testing.T) {
	auth, err := New()
	if err == nil {
		t.Fatal("New() succeeded under a test binary; it must never reach hardware from a test")
	}
	if auth != nil {
		t.Error("New() returned an authenticator despite refusing")
	}

	// Under `go test` the test guard fires first, whatever else is set.  On a
	// developer's machine an agent marker may also be present, so accept either --
	// what must never happen is a nil error.
	if !errors.Is(err, ErrUnderTest) && !errors.Is(err, ErrUnderAgent) {
		t.Errorf("New() = %v, want ErrUnderTest or ErrUnderAgent", err)
	}
}

func TestRefuseUnderTest(t *testing.T) {
	if err := RefuseUnderTest(); !errors.Is(err, ErrUnderTest) {
		t.Errorf("RefuseUnderTest() = %v, want ErrUnderTest", err)
	}
}

// Every marker must fire on its own.  A marker that was listed but never checked
// would be a guard that exists only in the documentation.
func TestRefuseUnderAgent(t *testing.T) {
	for _, marker := range agentEnvMarkers {
		t.Run(marker, func(t *testing.T) {
			clearAgentMarkers(t)
			t.Setenv(marker, "1")

			err := RefuseUnderAgent()
			if !errors.Is(err, ErrUnderAgent) {
				t.Fatalf("RefuseUnderAgent() with %s set = %v, want ErrUnderAgent", marker, err)
			}
			// The message must name which marker fired, or an operator staring at a
			// refusal has no idea which environment variable to look at.
			if got := err.Error(); !strings.Contains(got, marker) {
				t.Errorf("RefuseUnderAgent() = %q, want it to name %s", got, marker)
			}
		})
	}
}

// With no marker set, the guard must stand aside.  A guard that refused
// unconditionally would look identical in every other test here, and would make
// the library unusable by the human it exists to serve.
func TestRefuseUnderAgentAllowsAHumanShell(t *testing.T) {
	clearAgentMarkers(t)

	if err := RefuseUnderAgent(); err != nil {
		t.Errorf("RefuseUnderAgent() with no markers = %v, want nil", err)
	}
}

// An empty value still counts: `CLAUDECODE=` is set.  A guard that tested the
// value rather than the presence would wave it through.
func TestRefuseUnderAgentChecksPresenceNotValue(t *testing.T) {
	clearAgentMarkers(t)
	t.Setenv("CLAUDECODE", "")

	if err := RefuseUnderAgent(); !errors.Is(err, ErrUnderAgent) {
		t.Errorf("RefuseUnderAgent() with an empty CLAUDECODE = %v, want ErrUnderAgent", err)
	}
}

// The test guard is independent of the agent guard: even in a clean human-shell
// environment, a test binary must not reach hardware.
func TestRefuseUnderTestIsIndependentOfTheAgentGuard(t *testing.T) {
	clearAgentMarkers(t)

	if err := RefuseUnderAgent(); err != nil {
		t.Fatalf("precondition: RefuseUnderAgent() = %v, want nil", err)
	}
	if err := RefuseAutomatedContext(); !errors.Is(err, ErrUnderTest) {
		t.Errorf("RefuseAutomatedContext() = %v, want ErrUnderTest", err)
	}
	if _, err := New(); !errors.Is(err, ErrUnderTest) {
		t.Errorf("New() = %v, want ErrUnderTest", err)
	}
}

// RefuseAutomatedContext is what New calls, and it must refuse for either reason.
func TestRefuseAutomatedContext(t *testing.T) {
	if err := RefuseAutomatedContext(); err == nil {
		t.Error("RefuseAutomatedContext() = nil under a test binary, want an error")
	}
}

// Available answers for the build, not for who is asking: it reports what this
// binary could reach, and does not consult the refusal guards.  A test binary on
// Windows still reports true -- and must, or a caller could not distinguish "this
// platform has no support" from "you may not use it right now".
func TestAvailableAnswersForThePlatform(t *testing.T) {
	got := Available()
	t.Logf("Available() = %v on this platform", got)

	// Whatever Available says, New must still refuse here.
	if _, err := New(); err == nil {
		t.Error("New() succeeded under a test binary")
	}
}
