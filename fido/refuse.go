// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package fido

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

// ErrUnderTest is returned when a security key is opened from a test binary.
var ErrUnderTest = errors.New("fido: a security key must not be used under 'go test'")

// ErrUnderAgent is returned when a security key is opened from a command started
// by an AI coding agent.
var ErrUnderAgent = errors.New("fido: refusing to use a security key from an AI coding agent's shell")

// agentEnvMarkers are variables coding agents set in the environment of the
// commands they run.  Presence of any one means this process was almost
// certainly started by an agent rather than typed by a person.
//
// Claude Code sets CLAUDECODE plus a CLAUDE_CODE_* family.  Qwen Code documents
// QWEN_CODE=1.  GEMINI_CLI is included because qwen-code is a fork of gemini-cli
// and inherits the mechanism.
var agentEnvMarkers = []string{
	"CLAUDECODE",
	"CLAUDE_CODE_ENTRYPOINT",
	"CLAUDE_CODE_SESSION_ID",
	"CLAUDE_CODE_EXECPATH",
	"QWEN_CODE",
	"GEMINI_CLI",
}

// RefuseUnderTest reports an error when called from a test binary.
//
// A key that blinks during `go test ./...` teaches the operator to touch it
// without reading the prompt, which destroys the only thing the touch was ever
// worth.  Tests inject a fake [touchvault.Authenticator]; they never call [New].
func RefuseUnderTest() error {
	if testing.Testing() {
		return ErrUnderTest
	}
	return nil
}

// RefuseUnderAgent reports an error when a coding agent's markers are present.
//
// # This is not the security boundary
//
// An agent can unset these variables, and an agent that would hallucinate a
// production command could hallucinate an `unset`.  This stops the accident, not
// the adversary.  The boundary is the physical touch, which no process can
// perform.
//
// It earns its place anyway: the realistic failure is an agent running a
// production command while reasoning about something else, with the operator at
// the desk and the key plugged in.  The platform raises a generic prompt the
// operator cannot connect to any decision, and a reflexive touch spends
// something irreplaceable.  Refusing here means the agent gets an error instead
// of your finger.
func RefuseUnderAgent() error {
	for _, name := range agentEnvMarkers {
		if _, ok := os.LookupEnv(name); ok {
			return fmt.Errorf("%w: %s is set", ErrUnderAgent, name)
		}
	}
	return nil
}

// RefuseAutomatedContext refuses both test binaries and agent shells.  [New]
// calls it, so no automated context can reach a security key at all.
func RefuseAutomatedContext() error {
	if err := RefuseUnderTest(); err != nil {
		return err
	}
	return RefuseUnderAgent()
}
