# touchvault

[![Go Reference](https://pkg.go.dev/badge/github.com/jeffbstewart/touchvault.svg)](https://pkg.go.dev/github.com/jeffbstewart/touchvault)

Store a set of secrets so that reading any of them requires a physical touch on an enrolled
FIDO2 security key.

One random data key encrypts every secret.  Each enrolled security key wraps a copy of that
data key behind a key derived from the key's `hmac-secret` output, which costs a touch to
compute.  Reading therefore needs the key **and** a human.  The sealed vault on disk is
inert without both.

That last property is the point.  A process running as the operator — a stray script, a
compromised dependency, a coding agent — can read any file the operator can read, hold any
password the operator has typed, and defeat any check the operator's own machine performs.
It cannot press a button.  touchvault puts the secret behind the button.

## Install

```bash
go get github.com/jeffbstewart/touchvault
```

Requires Go 1.24 or later.  The core is pure Go and depends on the standard library alone.
The `fido` provider, which reaches real hardware, builds on Windows; other platforms return
`ErrUnsupportedPlatform`.

## Use

Enroll a key and store a secret:

```go
auth, err := fido.New()
if err != nil {
	return err
}
admin, err := touchvault.Create(auth, touchvault.Options{
	RPID:   "vault.example.invalid",  // stable; changing it orphans enrolled keys
	RPName: "Example Vault",
	Label:  "primary",
})
if err != nil {
	return err
}
if err := admin.Put("api-key", strings.NewReader(secret)); err != nil {
	return err
}
sealed, err := admin.Sealed()
if err != nil {
	return err
}
// Storage is yours: a file, a database row, wherever.  These bytes are ciphertext.
```

Read it back — one touch:

```go
v, err := touchvault.Open(sealed)   // no touch; parses metadata only
if err != nil {
	return err
}
sess, err := v.Unlock(auth)         // one touch
if err != nil {
	return err
}
defer sess.Lock()

key, err := touchvault.ReadString(sess, "api-key")
```

A `Session` holds the data key in memory, so further reads cost no additional touch.
`Lock` forgets it.

Enroll a backup key — do this before you need it, because a lost key with no backup is a
lost vault:

```go
admin, err := v.Administer(auth)            // one touch on an enrolled key
if err != nil {
	return err
}
err = admin.EnrollKey(auth, 1, "backup")    // touches on the new key
```

## What it guarantees, and what it does not

**Enrollment requires hardware attestation.**  A credential is accepted only if its
certificate chain terminates at a trusted vendor root and its attestation signature
verifies.  Software and virtual authenticators are rejected, so a secret binds to
non-exportable hardware.  There is no opt-out; `Options.Roots` chooses *whom* to trust, not
*whether* to.  It defaults to the bundled Yubico FIDO roots.

**Enrollment proves the derivation depends on the salt.**  Before sealing anything,
touchvault derives a second time over the salt with its final byte flipped and refuses
(`ErrDerivationIgnoresSalt`) if the output does not change.  A derivation that truncates or
ignores the salt would silently collapse the vault's security; it is caught on the actual
device, at enrollment, rather than discovered later.

**It does not manage storage.**  `Sealed()` returns bytes; persist them however you like.

**It does not hide metadata.**  Secret names, key labels, and credential-ID prefixes are
readable without a touch, by design, so a vault can be inspected.  They are authenticated —
bound into the AAD — so they cannot be tampered with, but they are not secret.  Do not put
anything sensitive in a name.

**It is for secrets, not files.**  `Put` buffers the whole value in memory before sealing
(AES-GCM is one-shot, not a streaming cipher).  API keys and tokens, yes; disk images, no.

**`Lock` is best-effort.**  The Go runtime may have copied key bytes during garbage
collection, so `Lock` narrows the window of exposure rather than guaranteeing erasure.

## Testing against it

touchvault never talks to hardware.  It defines an `Authenticator` port, and a provider
implements it — so a fake reaches every function in the library, and your tests need no key:

```go
vault, err := touchvault.Create(fakeAuthenticator{}, opts)
```

Conversely, `fido.New()` refuses to run under a test binary or a coding-agent shell, so
automation cannot reach a real key by accident.

## License

Apache 2.0.  See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The trust anchors under `roots/` are certificates published by Yubico — data, not code.
They are not covered by this module's license and confer no endorsement by their issuer.
