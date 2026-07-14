# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

## Build and Test Commands

```bash
go build ./...      # Build
go test ./...       # Run all tests
go test -run TestName ./...
gofmt -l .          # Must print nothing
```

The core builds and tests on **every** platform with **no hardware**. If a change to the
core makes `go test ./...` require a security key, or fail on Linux, the change is wrong.

### What CI enforces

`.github/workflows/ci.yml` guards the structural invariants — the ones a well-meaning
change could break with no test failing:

- **gofmt, vet, and tests on Linux, macOS, and Windows.** The suite must pass with no key
  present, on platforms that cannot even reach one.
- **The race detector**, on Linux (it needs cgo). `Session` claims to be safe for
  concurrent use; this is what checks the claim.
- **The core has no third-party dependencies.** Enforced with
  `go list -deps -f '{{if not .Standard}}...'` — *not* a grep for a domain name, because
  the standard library vendors packages under `vendor/golang.org/x/...` and those are
  stdlib. A companion step runs the same query against `fido` and requires it to *find*
  `x/sys`, so the check cannot pass vacuously.
- **The core does not import the provider.** The dependency inverts at the port.
- **Cross-builds** for linux, darwin, and windows on amd64/arm64.

## Project Purpose

`touchvault` stores a **set of secrets** so that reading any of them requires a physical
touch on an enrolled FIDO2 security key.

One random data key encrypts every secret. Each enrolled key wraps a copy of that data key
behind a key derived from that key's `hmac-secret` output, which costs a touch to compute.
Reading therefore needs the key **and** a human. The sealed vault on disk is inert without
both.

Non-goals: it does not manage storage (the caller persists the sealed bytes), it does not
talk to hardware directly (a provider does), and it is not a general PKI or a password
manager.

## Architecture

The module is one Go module with a hard internal boundary between a platform-neutral core
and a platform-specific FIDO2 transport.

```
github.com/jeffbstewart/touchvault   (module root — portable, pure Go, stdlib only)
  vault.go            Create, Open, Vault, Session, Admin, Options, lifecycle
  slots.go            SlotInfo, Inspector (Names/Slots), FreeSlot
  sealed.go           the on-disk format: marshal/unmarshal, AAD construction
  crypto.go           data-key + KEK wrapping; AES-256-GCM seal/open; HKDF
  entropy.go          the salt-dependence enrollment gate
  attestation.go      REQUIRED attestation verification + trust pool
  authenticator.go    the Authenticator PORT: interface + request/result types
  errors.go           exported sentinels
  roots/              bundled Yubico trust anchors (go:embed)

  fido/               provider subpackage — the ONLY place that touches hardware
    fido.go           New() -> touchvault.Authenticator; refusal guards
    webauthn_windows.go
    unsupported_other.go
    internal/winwebauthn/   the unsafe FFI
```

**The dependency direction is inverted at the port.** The *core* defines `Authenticator`;
the *provider* depends on the core to implement it. The core imports no provider and no
`x/sys`, so it compiles and tests everywhere. Only `fido` pulls
`golang.org/x/sys/windows`.

Do not import `fido` from the core. Do not add a third-party dependency to the core: key
derivation uses the standard library's `crypto/hkdf` (Go 1.24+), and the core's dependency
list is deliberately empty.

## The Invariants

These are the reasons this library exists. Each was learned the hard way; none is
negotiable. Do not weaken one to make a test pass or an API convenient.

### Only the touch is a boundary

The lesser guards — a TTY check, a typed confirmation phrase, a refusal to run under
`CLAUDECODE`/`QWEN_CODE` — stop accidents, but every one of them is defeatable by the
process they guard. Only the physical touch is a real boundary, because it is the one act
no process running as the operator can perform, *including a coding agent*. Design as if
every other guard has already failed.

### A secret is sealed only under a proven salt-dependent derivation

`Create` and `EnrollKey` will not seal anything until they have **proven** the security
key's `hmac-secret` output actually depends on the salt. They derive a second time over the
salt with its **final byte flipped**, and refuse with `ErrDerivationIgnoresSalt` if the
output does not change.

The flipped *tail* is deliberate. It catches a derivation that **truncates** the salt (the
marshaling-bug shape — a too-short length field), which a random probe salt differing at
byte 0 would miss. A derivation that ignores the salt entirely returns a constant and is
caught the same way.

A successful check sets an authenticated `entropy_verified` marker, bound into the AAD.
Unwrapping refuses any vault lacking it (`ErrNotEntropyVerified`) **before asking for a
touch**. So a secret can neither be wrapped under, nor unwrapped from, a derivation whose
salt-dependence was never demonstrated on the actual device.

Do not add a path that seals without this gate. Do not make the marker optional.

This costs one extra gesture (three at enrollment). `EnrollKey` repeats it, because a new
key is a new device; the risk it guards is a per-machine marshaling bug, and a backup key
may be enrolled on a different machine than the primary.

### The `uv` trap

Windows verifies the operator with a PIN whenever the key has one, **even when the code
requests `uv=discouraged`**. A CTAP2 authenticator returns a *different* `hmac-secret`
value depending on whether it verified.

So: enrollment records what the authenticator **reported** (`DeriveResult.UserVerified`),
never what was requested. Every subsequent read requests the same. A mismatch — e.g. the
operator cleared the key's PIN — is reported as `ErrUserVerificationMismatch`, and must
never surface as corrupt ciphertext. Ground truth is what the device says it did.

### Attestation is required, and the core enforces it

Enrollment requests direct attestation and refuses unless the credential's certificate
chain terminates at a trusted vendor root **and** the attestation signature verifies over
that credential's authenticator data. This rejects software and virtual authenticators, so
a secret binds to non-exportable hardware.

Only the `packed` format is accepted, which keeps the core free of CBOR: the platform
decodes the statement, and `packed` signs `authenticatorData || clientDataHash`.

There is **no opt-out**. `Options.Roots` chooses *whom* to trust, not *whether* to. Nil
means the bundled Yubico roots. To trust another vendor, a caller adds that vendor's root
to a pool and passes it in. Do not add a flag that accepts unattested or self-attested
credentials.

Verification lives in the **core** (`attestation.go`), never in a provider. A provider
returns the raw attestation material in `EnrollResult` and makes no trust decision, so the
required policy sits in one portable, testable place and a new provider cannot quietly ship
a weaker one.

### The FFI layout is frozen by a test

`fido/internal/winwebauthn/layout_windows_test.go` freezes the `webauthn.dll` struct offsets
with `unsafe.Offsetof`/`Sizeof`. A wrong field position or length is the *other* way a salt
can be silently mis-applied. The test needs no hardware and fails in `go test` rather than
on the next enrollment. Keep it passing; do not relax it to accommodate a struct change
without understanding what moved.

### Hardware is unreachable from automation

`fido.New()` refuses under a test binary or a coding-agent shell. It is the single door to
hardware: every `touchvault` function takes an `Authenticator`, so a fake reaches all of
them and a real key reaches none of them by accident. Tests use fakes, always. Never add a
test that expects a key to be present.

## Key Conventions

### Error handling

Never ignore a returned error.

- In production code, return it to the caller, or log it with `log.Printf` on a
  cleanup/defer path. When logging a cleanup error on a short-circuit return, still return
  the original error.
- In tests, check errors with `t.Fatalf`/`t.Errorf` — including deferred `Close()` calls
  (wrap in a closure).
- Never write a bare `defer x.Close()`. Always capture and handle the error.

### Errors are sentinels

Callers distinguish failures with `errors.Is`, so the exported sentinels in `errors.go` are
API. Wrap with `%w`. Do not collapse two distinct failures into one sentinel, and do not
return a bare `fmt.Errorf` where a sentinel exists — `ErrUserVerificationMismatch` in
particular must never reach the caller as a decryption failure.

### The read side is concurrent-safe; the admin side is not

A `Session` may be read from any number of goroutines: reading a secret does not
disturb the vault.

An `Admin` may not. The implementation takes a lock, so a concurrent call cannot corrupt
memory — but that guarantee is per-call, and an administrative sequence spans several
calls (`FreeSlot(admin.Slots())` then `EnrollKey(slot, ...)` is a read-modify-write with a
gap no per-method lock can close). Do not add a mutex, or a doc comment, that makes `Admin`
*look* concurrency-safe: that would invite exactly the pattern it cannot protect. Admin
work blocks on a human touching a key, so there is nothing to win by parallelizing it.

### Secrets in memory

`Session.Lock` forgets the data key and any derived KEKs. It is **best-effort**: the Go
runtime may have copied the bytes during garbage collection, so `Lock` narrows the window
of exposure rather than guaranteeing erasure. Say so in the doc comment; do not claim
erasure.

Never log, print, or embed a secret, a data key, a KEK, or an `hmac-secret` output — not in
an error message, not in a test failure. Credential IDs and secret *names* are metadata and
may appear; the plaintext never may.

### The sealed format is authenticated metadata plus ciphertext

Plaintext metadata is readable by design (a vault can be inspected without a touch) but
bound into the AAD so it cannot be tampered with.

- **Vault AAD** binds `format`, `rp_id`, `user_verified`, `entropy_verified`, `salt`. Every
  seal in the document includes it.
- **Per-key AAD** additionally binds `slot` and `credential_id`, so a wrapped data key
  cannot be moved between slots or credentials.
- **Per-secret AAD** additionally binds `name`, so a secret's ciphertext cannot be
  relabeled or swapped with another's.

The format is natively a *set* — a `secrets` array — from the first release. `format` starts
at 1, and no earlier format was ever published, so there is nothing to be compatible with.
Do not add a backward-compatibility path for a format that never shipped.

### Testing

Standard `testing` package. A fake `Authenticator` reaches every function; full coverage
requires no hardware and no platform. A test that cannot run on Linux does not belong in
the core.

### Comments

Two spaces after a sentence-ending period.

Every Go source file carries the SPDX header:

```go
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart
```

## Version Control

This repository uses **git**, hosted at `github.com/jeffbstewart/touchvault`.

**Every change lands as a pull request.** Do not commit to `main` directly and do not merge
your own PR; the owner reviews on github.com and merges.

Line endings are LF in the repo and the working tree on every platform, enforced by
`.gitattributes` — Git for Windows sets `core.autocrlf=true` in its system config, which
these attributes override. `*.bat`/`*.cmd` are the deliberate CRLF exception. The `roots/`
PEMs are compiled in with `go:embed`, so the checked-out bytes are the shipped bytes; a
CRLF checkout would change them.
