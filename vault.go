// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jeffrey B. Stewart

package touchvault

// The lifecycle: create a vault, open a sealed one, unlock it with a touch, read
// and administer it, and serialize it back out.
//
// # Where the gestures go
//
//	Create        3 gestures  create the credential, derive, prove salt-dependence
//	Open          0           parses metadata; no cryptography at all
//	Unlock        1           the touch that produces the data key
//	Administer    1           the same touch; you must prove presence to change
//	                          what presence protects
//	Session.Open  0           the touch was spent at Unlock
//	Put/Delete    0           the data key is already in hand
//	EnrollKey     3           on the NEW key: create, derive, prove
//	RemoveKey     0           the entry is ciphertext; deleting it needs no proof
//
// Nothing here writes to storage.  Every mutation changes in-memory state, and
// the caller persists Sealed() if and when it chooses.

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
)

// DefaultLabel names the first key's slot when Options.Label is empty.
const DefaultLabel = "primary"

// userIDLen is the length of the opaque user handle.  It is not stored on the
// key for a non-discoverable credential, but the platform requires one.
const userIDLen = 16

// Options configures a vault.
type Options struct {
	// RPID scopes the credentials on the security key (the WebAuthn
	// relying-party identifier).  Pick a stable, reserved identifier for your
	// application: two applications sharing an RPID would see each other's
	// credentials, and changing it orphans every key already enrolled.
	//
	// A reserved, permanently unresolvable domain (RFC 2606, e.g. ".invalid") is
	// correct for a relying party that is not a web origin.  Required.
	RPID string

	// RPName is human-readable and shown by some platform prompts.  Defaults to
	// RPID.
	RPName string

	// Roots is the attestation trust-anchor pool.  Nil uses the bundled Yubico
	// FIDO roots.
	//
	// Attestation is always REQUIRED; this only chooses whom to trust.  To accept
	// a second vendor's hardware, extend [BundledRoots] and pass the result.
	// There is no value of Roots that disables the check: an empty pool trusts
	// nobody, it does not trust everybody.
	Roots *x509.CertPool

	// Label names the first key's slot.  Defaults to [DefaultLabel].
	Label string
}

func (o Options) validate() error {
	if o.RPID == "" {
		return errors.New("touchvault: Options.RPID is required")
	}
	return nil
}

func (o Options) rpName() string {
	if o.RPName == "" {
		return o.RPID
	}
	return o.RPName
}

func (o Options) label() string {
	if o.Label == "" {
		return DefaultLabel
	}
	return o.Label
}

// Vault is a sealed vault opened for inspection.  It reveals only metadata until
// unlocked.
type Vault interface {
	Inspector

	// Unlock derives the data key with one touch on a presented enrolled key and
	// returns a read session.
	Unlock(auth Authenticator) (Session, error)

	// Administer unlocks with one touch and returns a session that can also
	// modify the vault.
	Administer(auth Authenticator) (Admin, error)
}

// Session is an unlocked vault.  It holds the data key in memory, so reads cost
// no further touch.  Lock forgets that key.
//
// A Session is safe for concurrent use.
type Session interface {
	Inspector

	// Open returns the plaintext of one secret as a stream.  It costs no gesture;
	// the touch was spent at Unlock.  Read it, then close it.
	//
	// Closing overwrites the buffer the plaintext was read into.  That is
	// best-effort, for the same reason [Session.Lock] is.
	Open(name string) (io.ReadCloser, error)

	// Lock forgets the session's in-memory key material — the data key and any
	// derived key-encryption keys — so the session can no longer decrypt.  It
	// does NOT read, write, or alter the sealed vault; locking is purely an
	// in-memory operation.
	//
	// It is best-effort: the Go runtime may have copied the bytes during garbage
	// collection, and nothing in the language can reach those copies.  Lock
	// narrows the window of exposure rather than guaranteeing erasure.
	//
	// Locking twice is harmless.
	Lock()
}

// Admin is an unlocked session that can also modify the vault.
//
// Every mutation changes only in-memory state; call Sealed to serialize the new
// vault to persist.  Obtaining an Admin already cost a touch: you must prove
// presence to change what presence protects.
type Admin interface {
	Session

	// Put adds or replaces a secret, sealing it under the vault's data key.
	//
	// The reader is consumed fully in memory before sealing (GCM is one-shot, not
	// a streaming cipher), so this suits secrets, not large files.
	Put(name string, secret io.Reader) error

	// Delete removes a secret.
	Delete(name string) error

	// EnrollKey enrolls another security key into an empty slot as a backup,
	// verifying its attestation.
	//
	// It costs three gestures on the NEW key: create, derive, and the
	// salt-dependence proof.  The data key is re-wrapped for it; no secret is
	// re-encrypted and no plaintext is exposed, so the vault's secrets are never
	// needed again after Create.
	//
	// The new key must report the same user-verification as the vault was
	// enrolled with, or it would derive from the other of its two per-credential
	// secrets and produce a wrapped entry that never opens.
	EnrollKey(auth Authenticator, slot int, label string) error

	// RemoveKey removes an enrolled key.  It costs no gesture: the entry is
	// ciphertext, and removing it only stops that key from unlocking the vault.
	//
	// It refuses to remove the last enrolled key with [ErrLastKey], since that
	// would strand every secret.  See [Admin.ForceRemoveKey].
	RemoveKey(slot int) error

	// ForceRemoveKey removes an enrolled key even if it is the last one.
	//
	// Removing the last key makes every secret in the vault permanently
	// unreadable.  Nothing can recover them: the data key exists only as copies
	// wrapped under the enrolled keys, and this deletes the final copy.  There is
	// no undo, and no touch is required — the ciphertext does not defend itself.
	//
	// This exists because a caller may genuinely mean it, and a refusal with no
	// escape hatch is its own bug.  It is a separate method rather than a flag so
	// that destroying a vault cannot happen by passing the wrong value to the
	// call you reach for every day.
	ForceRemoveKey(slot int) error

	// Sealed serializes the current vault to bytes for the caller to persist.
	Sealed() ([]byte, error)
}

// Create initializes a new vault and enrolls auth as its first security key.
//
// It costs three gestures: create the credential, derive from it, and prove the
// derivation depends on the whole salt.  The credential's attestation must chain
// to a trusted root (Options.Roots, default the bundled Yubico FIDO roots) or
// Create refuses.
//
// The returned Admin is unlocked and holds no secrets yet; add them with Put,
// then persist Sealed.
func Create(auth Authenticator, opts Options) (Admin, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	salt, err := newSalt()
	if err != nil {
		return nil, err
	}

	doc := &sealedVault{
		Format: formatVersion,
		RPID:   opts.RPID,
		Salt:   salt,
		// UserVerified and EntropyVerified are filled from the enrollment below,
		// once we know what the device actually did.  They are bound into the AAD,
		// so nothing may be sealed before they are correct.
	}

	cred, derived, err := enrollAndDerive(auth, doc, opts, UVDiscouraged)
	if err != nil {
		return nil, err
	}
	doc.UserVerified = derived.UserVerified // observed, never requested

	// Prove the derivation depends on the salt before wrapping anything under it.
	// On failure the vault is never returned, so nothing was sealed.
	if err := verifyDerivationDependsOnSalt(
		auth, doc.RPID, cred.CredentialID, salt, derived.Secret, UVDiscouraged, derived.UserVerified,
	); err != nil {
		return nil, err
	}
	doc.EntropyVerified = true // proven above, and bound into the AAD below

	dataKey, err := newDataKey()
	if err != nil {
		return nil, err
	}

	entry, err := doc.wrapDataKey(dataKey, cred.CredentialID, derived.Secret, firstSlot, opts.label())
	if err != nil {
		return nil, err
	}
	doc.Keys = []sealedKey{entry}

	return &session{doc: doc, opts: opts, dataKey: dataKey}, nil
}

// firstSlot is where Create enrolls.  Slots are arbitrary; this is only where
// counting starts.
const firstSlot = 0

// Open parses a sealed vault.
//
// It performs no cryptography and costs no gesture; it reads only the
// authenticated metadata.  Call Unlock or Administer to touch the key and
// decrypt.
//
// A vault opened this way enrolls new keys against the bundled trust anchors and
// uses its RP ID as the RP name.  A caller with its own trust anchors — one that
// passed Options.Roots to Create — must use [OpenWith] to enroll a backup, or
// the new key would be judged against anchors that never trusted it.
func Open(sealed []byte) (Vault, error) {
	return OpenWith(sealed, Options{})
}

// OpenWith parses a sealed vault, supplying the options that later enrollments
// need.
//
// Only the enrollment-time policy is read from opts: Roots, RPName, and Label.
// RPID is not — the sealed vault carries the RP ID its credentials were created
// under, and honoring a different one would silently orphan every enrolled key.
// A non-empty opts.RPID that disagrees with the document is an error rather than
// a preference.
func OpenWith(sealed []byte, opts Options) (Vault, error) {
	doc, err := parseSealed(sealed)
	if err != nil {
		return nil, err
	}
	if opts.RPID != "" && opts.RPID != doc.RPID {
		return nil, fmt.Errorf(
			"touchvault: Options.RPID is %q but the sealed vault was created under %q; "+
				"its enrolled keys would not answer for a different relying party",
			opts.RPID, doc.RPID)
	}
	opts.RPID = doc.RPID
	return &vault{doc: doc, opts: opts}, nil
}

// vault is a sealed, not-yet-unlocked vault.
type vault struct {
	doc  *sealedVault
	opts Options
}

func (v *vault) Names() []string   { return v.doc.names() }
func (v *vault) Slots() []SlotInfo { return v.doc.slots() }

func (v *vault) Unlock(auth Authenticator) (Session, error) {
	return v.unlock(auth)
}

func (v *vault) Administer(auth Authenticator) (Admin, error) {
	return v.unlock(auth)
}

// unlock derives the data key with one touch.  Unlock and Administer are the
// same act — the difference is only what the caller may then do — so there is one
// implementation and one place for these checks to live.
func (v *vault) unlock(auth Authenticator) (*session, error) {
	if len(v.doc.Keys) == 0 {
		return nil, ErrNoKeysEnrolled
	}

	// Refuse before asking for a touch.  A vault whose derivation was never
	// proven salt-dependent must not be used, even if the arithmetic would
	// succeed — and the operator must not spend a gesture discovering that.
	if !v.doc.EntropyVerified {
		return nil, ErrNotEntropyVerified
	}

	derived, err := auth.Derive(DeriveRequest{
		RPID:          v.doc.RPID,
		CredentialIDs: v.doc.credentialIDs(),
		Salt:          v.doc.Salt,
		UV:            v.doc.uvRequirement(),
	})
	if err != nil {
		return nil, err
	}

	// Presence is the entire point.  A derivation without it is worthless even if
	// the arithmetic succeeded.
	if !derived.UserPresent {
		return nil, ErrNotPresent
	}

	// The authenticator's two per-credential secrets differ.  If it verified
	// differently than at enrollment we hold the wrong prf, and the unwrap below
	// would fail as an opaque authentication error.  Say why instead: the vault is
	// intact, the operator changed their key's PIN.
	if derived.UserVerified != v.doc.UserVerified {
		return nil, fmt.Errorf(
			"%w: enrolled with user_verified=%v, this assertion reported %v. "+
				"Setting or clearing the key's PIN changes the derived secret",
			ErrUserVerificationMismatch, v.doc.UserVerified, derived.UserVerified)
	}

	entry, ok := v.doc.findKey(derived.CredentialID)
	if !ok {
		return nil, ErrUnknownCredential
	}

	dataKey, err := v.doc.unwrapDataKey(entry, derived.Secret)
	if err != nil {
		return nil, err
	}

	return &session{doc: v.doc, opts: v.opts, dataKey: dataKey}, nil
}

// session is an unlocked vault.  It satisfies Session and Admin: the two differ
// only in what the caller is handed, and a Session was already obtained by
// proving presence.
type session struct {
	mu      sync.Mutex
	doc     *sealedVault
	opts    Options
	dataKey []byte // nil once locked
}

func (s *session) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.names()
}

func (s *session) Slots() []SlotInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.slots()
}

func (s *session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	zero(s.dataKey)
	s.dataKey = nil
}

// key returns the data key, or ErrLocked.  Callers hold s.mu.
func (s *session) key() ([]byte, error) {
	if s.dataKey == nil {
		return nil, ErrLocked
	}
	return s.dataKey, nil
}

func (s *session) Open(name string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dataKey, err := s.key()
	if err != nil {
		return nil, err
	}
	entry, ok := s.doc.findSecret(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoSuchSecret, name)
	}
	plaintext, err := s.doc.openSecret(dataKey, entry)
	if err != nil {
		return nil, err
	}
	return &secretReader{Reader: bytes.NewReader(plaintext), buf: plaintext}, nil
}

func (s *session) Put(name string, secret io.Reader) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dataKey, err := s.key()
	if err != nil {
		return err
	}
	if name == "" {
		return errors.New("touchvault: a secret must have a name")
	}
	if secret == nil {
		return errors.New("touchvault: a secret must have a value")
	}

	// GCM is one-shot, so the whole value is buffered before sealing.  This suits
	// API keys and tokens, which is what the doc comment promises and all this
	// claims to be for.
	plaintext, err := io.ReadAll(secret)
	if err != nil {
		return fmt.Errorf("touchvault: reading the secret %q: %w", name, err)
	}
	defer zero(plaintext)

	entry, err := s.doc.sealSecret(dataKey, name, plaintext)
	if err != nil {
		return err
	}

	for i := range s.doc.Secrets {
		if s.doc.Secrets[i].Name == name {
			s.doc.Secrets[i] = entry
			return nil
		}
	}
	s.doc.Secrets = append(s.doc.Secrets, entry)
	return nil
}

func (s *session) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.key(); err != nil {
		return err
	}
	for i := range s.doc.Secrets {
		if s.doc.Secrets[i].Name == name {
			s.doc.Secrets = append(s.doc.Secrets[:i], s.doc.Secrets[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrNoSuchSecret, name)
}

func (s *session) EnrollKey(auth Authenticator, slot int, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dataKey, err := s.key()
	if err != nil {
		return err
	}
	if slot < 0 {
		return fmt.Errorf("touchvault: slot must not be negative, got %d", slot)
	}
	if s.doc.slotOccupied(slot) {
		return fmt.Errorf("%w: slot %d", ErrSlotOccupied, slot)
	}
	if label == "" {
		label = DefaultLabel
	}

	// The new key must derive under the same user-verification the vault was
	// enrolled with, so request that.
	uv := s.doc.uvRequirement()

	cred, derived, err := enrollAndDerive(auth, s.doc, s.opts, uv)
	if err != nil {
		return err
	}
	if _, exists := s.doc.findKey(cred.CredentialID); exists {
		return errors.New("touchvault: that security key is already enrolled in another slot")
	}
	if derived.UserVerified != s.doc.UserVerified {
		return fmt.Errorf(
			"%w: this key reported user_verified=%v, the vault was enrolled with %v",
			ErrUserVerificationMismatch, derived.UserVerified, s.doc.UserVerified)
	}

	// The entropy gate runs again on the new key, and this is a deliberate
	// departure from the original design, which skipped it here on the grounds
	// that the bug it guards is per-machine rather than per-key.
	//
	// But a backup key is very often enrolled on a *different machine* than the
	// primary — that is much of the point of a backup — and a different machine is
	// exactly where a per-machine marshaling bug lives.  Skip the gate and the
	// backup could seal against a truncated salt, with nobody finding out until
	// the day the primary is lost and the backup is all that is left.  It costs
	// one gesture.
	if err := verifyDerivationDependsOnSalt(
		auth, s.doc.RPID, cred.CredentialID, s.doc.Salt, derived.Secret, uv, derived.UserVerified,
	); err != nil {
		return err
	}

	entry, err := s.doc.wrapDataKey(dataKey, cred.CredentialID, derived.Secret, slot, label)
	if err != nil {
		return err
	}
	s.doc.Keys = append(s.doc.Keys, entry)
	return nil
}

func (s *session) RemoveKey(slot int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.key(); err != nil {
		return err
	}
	if !s.doc.slotOccupied(slot) {
		return fmt.Errorf("%w: slot %d", ErrNoSuchSlot, slot)
	}
	if len(s.doc.Keys) == 1 {
		return ErrLastKey
	}
	return s.removeKey(slot)
}

func (s *session) ForceRemoveKey(slot int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.key(); err != nil {
		return err
	}
	if !s.doc.slotOccupied(slot) {
		return fmt.Errorf("%w: slot %d", ErrNoSuchSlot, slot)
	}
	return s.removeKey(slot)
}

// removeKey drops the entry.  Callers hold s.mu and have checked the slot.
func (s *session) removeKey(slot int) error {
	kept := make([]sealedKey, 0, len(s.doc.Keys))
	for _, k := range s.doc.Keys {
		if k.Slot != slot {
			kept = append(kept, k)
		}
	}
	s.doc.Keys = kept
	return nil
}

func (s *session) Sealed() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Sealing does not need the data key, and deliberately does not require an
	// unlocked session to have kept it: a caller that locked early can still
	// persist what it already changed.
	return s.doc.marshal()
}

// enrollAndDerive creates a non-discoverable credential, proves it is genuine
// hardware, and immediately derives from it.
//
// The derivation is not optional: it is how the observed user-verification is
// learned, which decides which of the authenticator's two per-credential secrets
// is in use forever after.
func enrollAndDerive(auth Authenticator, doc *sealedVault, opts Options, uv UserVerification) (EnrollResult, DeriveResult, error) {
	userID, err := randomBytes(userIDLen)
	if err != nil {
		return EnrollResult{}, DeriveResult{}, err
	}

	cred, err := auth.Enroll(EnrollRequest{
		RPID:     doc.RPID,
		RPName:   opts.rpName(),
		UserID:   userID,
		UserName: doc.RPID,
		UV:       uv,
	})
	if err != nil {
		return EnrollResult{}, DeriveResult{}, err
	}
	if cred.ResidentKey {
		return EnrollResult{}, DeriveResult{}, ErrResidentKey
	}
	if len(cred.CredentialID) == 0 {
		return EnrollResult{}, DeriveResult{}, ErrNoCredentialID
	}

	// Attestation is required, and it is checked before the credential is used
	// for anything.  A software authenticator gets no further than this line.
	if err := verifyGenuineHardware(cred, opts.Roots); err != nil {
		return EnrollResult{}, DeriveResult{}, err
	}

	derived, err := auth.Derive(DeriveRequest{
		RPID:          doc.RPID,
		CredentialIDs: [][]byte{cred.CredentialID},
		Salt:          doc.Salt,
		UV:            uv,
	})
	if err != nil {
		return EnrollResult{}, DeriveResult{}, err
	}
	if !derived.UserPresent {
		return EnrollResult{}, DeriveResult{}, ErrNotPresent
	}
	if len(derived.Secret) == 0 {
		return EnrollResult{}, DeriveResult{}, ErrNoPRF
	}
	return cred, derived, nil
}

// secretReader streams one decrypted secret, and overwrites the buffer when
// closed.
type secretReader struct {
	*bytes.Reader
	buf  []byte
	once sync.Once
}

// Close overwrites the plaintext buffer.  Best-effort, for the same reason
// [Session.Lock] is: the runtime may already have copied these bytes.
func (r *secretReader) Close() error {
	r.once.Do(func() {
		zero(r.buf)
		r.Reader.Reset(nil)
	})
	return nil
}

// ReadString is a convenience for the common case of a small secret: it opens,
// reads, and closes the secret, returning it as a string.
//
// The returned string is immutable and cannot be wiped — that is what a Go string
// is.  A caller who needs to control the plaintext's lifetime uses
// [Session.Open] and closes the reader.
func ReadString(s Session, name string) (string, error) {
	r, err := s.Open(name)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := r.Close(); err != nil {
			// Close only wipes a buffer; it has nothing to fail at.  Handle it
			// anyway rather than write a bare defer.
			_ = err
		}
	}()

	value, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("touchvault: reading secret %q: %w", name, err)
	}
	defer zero(value)
	return string(value), nil
}
