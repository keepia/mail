package secrets

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/store"
)

// Keyring is the opened control secrets, held in memory by serve (CD10).
// It holds the anchor keys as crypto.Signers; nothing in it is ever
// logged.
type Keyring struct {
	kekID        KEKID
	deploymentID []byte
	createdAt    time.Time
	lastExportAt *time.Time
	m            *material
}

// KEKID is the id of the KEK the secrets are sealed under.
func (k *Keyring) KEKID() KEKID { return k.kekID }

// DeploymentID is the deployment's random 16-byte id.
func (k *Keyring) DeploymentID() []byte { return slices.Clone(k.deploymentID) }

// CreatedAt is when the secrets were created.
func (k *Keyring) CreatedAt() time.Time { return k.createdAt }

// Exported tells whether the secrets have been exported at least once
// (secret_keyring.last_export_at).
func (k *Keyring) Exported() bool { return k.lastExportAt != nil }

// LastExportAt is when the secrets were last exported, nil for never.
func (k *Keyring) LastExportAt() *time.Time { return k.lastExportAt }

// MailCryptPublicDER is the mail_crypt public key as DER (SPKI).
func (k *Keyring) MailCryptPublicDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.m.mailCrypt.Public())
}

// HasMasterPassword tells whether the store master credential is present.
func (k *Keyring) HasMasterPassword() bool { return k.m.master != "" }

// Anchor is the trust anchor name, with its key.
func (k *Keyring) Anchor(name pki.AnchorName) *pki.Anchor { return k.m.anchors[name] }

// MasterPassword is the store master credential's password (user
// MasterUser).
func (k *Keyring) MasterPassword() string { return k.m.master }

// MailCrypt is the global mail_crypt key pair: the private key as PEM
// "PRIVATE KEY" (PKCS#8) and the public key as PEM "PUBLIC KEY" (SPKI).
func (k *Keyring) MailCrypt() (private, public []byte, err error) {
	return mailCryptPEM(k.m.mailCrypt)
}

// Locked states (CD8 with C2): the reason a LockedError gives. serve stays
// up while locked, so that a restore can still run in its container; it
// never generates over existing secrets.
var (
	// ErrKEKMissing: the database holds secrets, but there is no KEK file.
	ErrKEKMissing = errors.New("KEK missing")
	// ErrKEKWithoutSecrets: a KEK file, but no secrets in the database.
	ErrKEKWithoutSecrets = errors.New("KEK without secrets")
	// ErrStrayKEKNew: a kek.new that is not the database's KEK and not
	// the KEK file's: it is kept.
	ErrStrayKEKNew = errors.New("stray kek.new")
	// ErrBootstrapInProgress: a command found the KEK not linked yet,
	// with a kek.new that matches the database; serve finishes the link.
	ErrBootstrapInProgress = errors.New("bootstrap in progress")
	// ErrNotInitialized: a command found no secrets at all.
	ErrNotInitialized = errors.New("secrets not initialized")
)

// LockedError is the error of a bootstrap or a read that found the
// secrets unusable. errors.Is matches its reason (ErrKEKMissing,
// ErrKEKWithoutSecrets, ErrWrongKEK, ErrStrayKEKNew, ErrKEKFile,
// ErrTampered, ErrSecretsIncomplete, and for commands also
// ErrBootstrapInProgress and ErrNotInitialized). Its text names the files,
// the KEK ids and what to do, never a secret.
type LockedError struct {
	Reason error
	msg    string
	cause  error
}

func (e *LockedError) Error() string { return e.msg }

// Unwrap returns the reason and the cause.
func (e *LockedError) Unwrap() []error {
	if e.cause != nil {
		return []error{e.Reason, e.cause}
	}
	return []error{e.Reason}
}

func locked(reason error, format string, args ...any) *LockedError {
	return &LockedError{Reason: reason, msg: reason.Error() + ": " + fmt.Sprintf(format, args...)}
}

// Defaults of Config.
const (
	// ServeLockTimeout bounds serve's wait for the bootstrap lock.
	ServeLockTimeout = 5 * time.Minute
	// ReadLockTimeout bounds a command's wait for the bootstrap lock
	// (C3).
	ReadLockTimeout = 30 * time.Second
)

// Config configures Bootstrap and Read.
type Config struct {
	// KEKFile is the KEK file's path (KEEPIA_KEK_FILE); its kek.new is
	// KEKFile + ".new" in the same directory.
	KEKFile string
	// LockTimeout bounds the wait for the bootstrap lock; zero is
	// ServeLockTimeout for Bootstrap and ReadLockTimeout for Read.
	LockTimeout time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	// Test seams, set only by this package's own tests (the _test.go
	// files of package secrets).
	fs           *kekFS
	beforeCommit func() error
	afterCommit  func() error
	afterLock    func()
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) kekFS() kekFS {
	if c.fs != nil {
		return *c.fs
	}
	return defaultFS()
}

func (c Config) newPath() string { return c.KEKFile + ".new" }

// Result is the outcome of a Bootstrap that did not lock.
type Result struct {
	Keyring *Keyring
	// Created: this start generated the secrets (the first start).
	Created bool
}

// Bootstrap is serve's start (CD6–CD8 with C1–C3). Under the bootstrap
// lock, held exclusively as a session lock on a connection of its own from
// before it reads anything until the KEK is linked and its directory
// synced, it decides by the KEK file, a leftover kek.new and the keyring
// row in the database:
//
//	kek               kek.new          keyring  result
//	absent            absent           empty    generate (first start)
//	absent            absent           present  locked: KEK missing
//	absent            id = keyring     present  finish the link, then load
//	absent            any              empty    remove kek.new, generate
//	absent            id ≠ keyring     present  locked; kek.new kept
//	id = keyring      absent           present  load
//	id = keyring      id = kek         present  remove kek.new, then load
//	id = keyring      id ≠ kek         present  locked; kek.new kept
//	present           any              empty    locked; kek.new kept
//	id ≠ keyring      any              present  locked, naming both ids
//
// A kek.new that does not load (a partial write, a link, wrong mode)
// counts as "id ≠". A KEK file that does not load locks too. Generating
// follows CD7's crash-safe order: kek.new with O_EXCL and fsync; one
// transaction with the keyring row and the six secrets; link kek.new to
// kek (never replacing a file), remove kek.new, fsync the directory.
//
// A locked state is a *LockedError; any other error (the database, the
// lock timeout, the file system while generating) is returned as is.
func Bootstrap(ctx context.Context, st *store.Store, c Config) (*Result, error) {
	timeout := c.LockTimeout
	if timeout == 0 {
		timeout = ServeLockTimeout
	}
	sess, err := st.LockSecrets(ctx, true, timeout)
	if err != nil {
		return nil, err
	}
	defer sess.Close(ctx)
	if c.afterLock != nil {
		c.afterLock()
	}
	s, err := readState(ctx, sess, c)
	if err != nil {
		return nil, err
	}
	switch {
	case s.kek == nil && s.kekErr == nil && s.keyring == nil:
		if s.newPresent {
			if err := removeStray(c.newPath()); err != nil {
				return nil, err
			}
		}
		k, err := generateAll(ctx, sess, c)
		if err != nil {
			return nil, err
		}
		return &Result{Keyring: k, Created: true}, nil
	case s.kek == nil && s.kekErr == nil && s.newMatchesKeyring():
		// A crash after the commit and before the link: finish it.
		if err := linkInPlace(c.newPath(), c.KEKFile); err != nil {
			return nil, err
		}
		k, err := loadKeyring(ctx, sess, s.keyring, s.kekNew)
		if err != nil {
			return nil, err
		}
		return &Result{Keyring: k}, nil
	}
	if err := s.lockedState(c); err != nil {
		return nil, err
	}
	// The KEK file matches the keyring. A kek.new identical to it is the
	// leftover of a link whose remove did not happen.
	if s.newPresent {
		if err := removeStray(c.newPath()); err != nil {
			return nil, err
		}
	}
	k, err := loadKeyring(ctx, sess, s.keyring, s.kek)
	if err != nil {
		return nil, err
	}
	return &Result{Keyring: k}, nil
}

// Read opens the secrets for a command (C3): under the bootstrap lock held
// shared, waiting at most ReadLockTimeout, it loads them as Bootstrap
// would, but never generates, links or removes anything. Where serve
// would generate it gives ErrNotInitialized, and where serve would finish
// a link ErrBootstrapInProgress, both as a *LockedError.
func Read(ctx context.Context, st *store.Store, c Config) (*Keyring, error) {
	timeout := c.LockTimeout
	if timeout == 0 {
		timeout = ReadLockTimeout
	}
	sess, err := st.LockSecrets(ctx, false, timeout)
	if err != nil {
		return nil, err
	}
	defer sess.Close(ctx)
	s, err := readState(ctx, sess, c)
	if err != nil {
		return nil, err
	}
	if err := s.readable(c); err != nil {
		return nil, err
	}
	return loadKeyring(ctx, sess, s.keyring, s.kek)
}

// readable is Read's verdict on s: nil when the KEK file matches the
// keyring, otherwise the locked state a command reports.
func (s *state) readable(c Config) error {
	switch {
	case s.kek == nil && s.kekErr == nil && s.keyring == nil:
		return locked(ErrNotInitialized, "the database holds no control secrets and %s does not exist; is keepia running?", c.KEKFile)
	case s.kek == nil && s.kekErr == nil && s.newMatchesKeyring():
		return locked(ErrBootstrapInProgress,
			"%s is not linked to %s yet; keepia serve finishes it at its next start", c.newPath(), c.KEKFile)
	}
	return s.lockedState(c)
}

// state is what the bootstrap found, under the lock.
type state struct {
	keyring *store.KeyringRow
	// kek is the loaded KEK file; nil with kekErr nil means absent.
	kek    *KEK
	kekErr error
	// newPresent: a kek.new exists in any form; kekNew is it, loaded, or
	// nil when it does not load (newErr).
	newPresent bool
	kekNew     *KEK
	newErr     error
}

func readState(ctx context.Context, sess *store.SecretsSession, c Config) (*state, error) {
	if c.KEKFile == "" {
		return nil, errors.New("no KEK file configured")
	}
	kr, err := sess.Keyring(ctx)
	if err != nil {
		return nil, err
	}
	fs := c.kekFS()
	s := &state{keyring: kr}
	s.kek, s.kekErr = fs.load(c.KEKFile)
	if errors.Is(s.kekErr, os.ErrNotExist) {
		s.kek, s.kekErr = nil, nil
	}
	if s.newPresent, err = exists(c.newPath()); err != nil {
		return nil, err
	}
	if s.newPresent {
		s.kekNew, s.newErr = fs.load(c.newPath())
	}
	return s, nil
}

func (s *state) newMatchesKeyring() bool {
	return s.keyring != nil && s.kekNew != nil && slices.Equal(s.kekNew.id[:], s.keyring.KEKID)
}

// lockedState returns the locked state for every case in which the KEK
// file is not the keyring's (or kek.new contradicts it), nil when the KEK
// file matches the keyring and kek.new is absent or identical to it. It is
// called after the cases that generate or link.
func (s *state) lockedState(c Config) error {
	newDesc := func() string {
		if s.kekNew != nil {
			return "the KEK " + s.kekNew.id.String()
		}
		return "no loadable KEK (" + s.newErr.Error() + ")"
	}
	switch {
	case s.kekErr != nil:
		// The loader's error already starts with ErrKEKFile's text.
		return &LockedError{Reason: ErrKEKFile, cause: s.kekErr,
			msg: s.kekErr.Error() + "; fix or restore the KEK file (docs/development/index.md, \"Control secrets\")"}
	case s.kek == nil && s.keyring == nil:
		// Handled by the generate case; unreachable.
		return locked(ErrNotInitialized, "no secrets")
	case s.kek == nil && !s.newPresent:
		return locked(ErrKEKMissing,
			"the database holds control secrets under the KEK %x, but %s does not exist; restore the volume keepia-kek from a backup or the KEK from an export (./km secrets restore), or restore the database that belongs to the lost KEK",
			s.keyring.KEKID, c.KEKFile)
	case s.kek == nil:
		return locked(ErrStrayKEKNew,
			"%s does not exist, and %s holds %s, not the database's KEK %x; it is kept: restore the right KEK, or remove that kek.new if it is not one",
			c.KEKFile, c.newPath(), newDesc(), s.keyring.KEKID)
	case s.keyring == nil:
		return locked(ErrKEKWithoutSecrets,
			"%s holds the KEK %s, but the database holds no control secrets; restore the matching database, or remove the volume keepia-kek for a fresh install",
			c.KEKFile, s.kek.id)
	case !slices.Equal(s.kek.id[:], s.keyring.KEKID):
		return locked(ErrWrongKEK,
			"%s holds the KEK %s, but the database's secrets are sealed under the KEK %x; restore the KEK file or the database that belongs to the other",
			c.KEKFile, s.kek.id, s.keyring.KEKID)
	case s.newPresent && (s.kekNew == nil || s.kekNew.id != s.kek.id):
		return locked(ErrStrayKEKNew,
			"%s holds %s, not the KEK %s of %s; it is kept: remove it once you know it is not needed",
			c.newPath(), newDesc(), s.kek.id, c.KEKFile)
	}
	return nil
}

// generateAll creates the keyring: CD7 steps 1–3.
func generateAll(ctx context.Context, sess *store.SecretsSession, c Config) (*Keyring, error) {
	kek, err := GenerateKEK()
	if err != nil {
		return nil, err
	}
	sl, err := newSealer(kek)
	if err != nil {
		return nil, err
	}
	m, err := generate(c.now())
	if err != nil {
		return nil, err
	}
	rows, err := m.rows(sl)
	if err != nil {
		return nil, err
	}
	// Step 1: the KEK on disk first, so a committed keyring always has
	// its KEK somewhere.
	if err := writeNew(c.newPath(), kek); err != nil {
		return nil, err
	}
	// Step 2: the keyring and the six sealed secrets in one transaction.
	if err := sess.CreateSecrets(ctx, store.KeyringRow{KEKID: kek.id[:], DeploymentID: m.deploymentID}, rows, c.beforeCommit); err != nil {
		return nil, err
	}
	if c.afterCommit != nil {
		if err := c.afterCommit(); err != nil {
			return nil, err
		}
	}
	// Step 3: link into place, never over an existing file.
	if err := linkInPlace(c.newPath(), c.KEKFile); err != nil {
		return nil, err
	}
	kr, err := sess.Keyring(ctx)
	if err != nil {
		return nil, err
	}
	return &Keyring{kekID: kek.id, deploymentID: m.deploymentID, createdAt: kr.CreatedAt, m: m}, nil
}

// loadKeyring opens the database's secrets with kek.
func loadKeyring(ctx context.Context, sess *store.SecretsSession, kr *store.KeyringRow, kek *KEK) (*Keyring, error) {
	sl, err := newSealer(kek)
	if err != nil {
		return nil, err
	}
	rows, err := sess.Secrets(ctx)
	if err != nil {
		return nil, err
	}
	m, err := openRows(sl, kr.DeploymentID, rows)
	if err != nil {
		var reason error
		switch {
		case errors.Is(err, ErrWrongKEK):
			reason = ErrWrongKEK
		case errors.Is(err, ErrTampered):
			reason = ErrTampered
		default:
			reason = ErrSecretsIncomplete
		}
		// err's text already starts with the reason's.
		return nil, &LockedError{Reason: reason, cause: err, msg: err.Error()}
	}
	return &Keyring{kekID: kek.id, deploymentID: kr.DeploymentID, createdAt: kr.CreatedAt, lastExportAt: kr.LastExportAt, m: m}, nil
}
