package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/password"
	"github.com/keepia/mail/internal/store/db"
)

// AddMailboxRequest is the mailbox that AddMailbox places and adds, in
// state active. Exactly one of Password and PasswordHash is set.
type AddMailboxRequest struct {
	Address Address
	// Password is a new password, checked by the caller against the
	// password rule (password.Check); AddMailbox hashes it with Argon2id
	// under the hash lock.
	Password string
	// PasswordHash is an imported stored hash, checked by the caller
	// (password.ValidateStored); it is stored as given.
	PasswordHash     string
	QuotaBytes       int64
	IMAP, POP3, SMTP bool
	// Store is the gate name of the store to use instead of placement; it
	// must be eligible: active, on a server that is not removed (CD5).
	Store string
}

// AddMailbox adds a mailbox on a store chosen by placement, or on
// r.Store. In order (#95 plan, section 4):
//
//  1. The domain must exist; an alias domain is refused with the name of
//     its domain.
//  2. A store must be eligible (r.Store, or any store for placement), so
//     that a command that cannot place fails before it hashes.
//  3. A new password is hashed under the hash lock (HashPassword), in a
//     transaction of its own.
//  4. The placement transaction (READ COMMITTED, the write lock timeout)
//     takes the placement lock (LockClassPlacement, 0), then chooses the
//     store and inserts the mailbox. The choice starts after the lock is
//     granted, so it sees every mailbox that an earlier holder committed:
//     two concurrent adds never choose from the same sums.
//
// The choice (#93): among eligible stores, the lowest sum of placement
// weights (a mailbox's quota, UnlimitedPlacementWeight for an unlimited
// one), then the fewest mailboxes, then the gate name in byte order.
// Disabled mailboxes count. If the chosen store's server is removed
// between the choice and the insert, T7 refuses the insert and nothing is
// added ("the store's server was removed; try again").
func (s *Store) AddMailbox(ctx context.Context, r AddMailboxRequest) (Mailbox, error) {
	if (r.Password == "") == (r.PasswordHash == "") {
		return Mailbox{}, errors.New("store: AddMailbox needs exactly one of a password and a password hash")
	}
	q := db.New(s.pool)
	if err := checkMailboxDomain(ctx, q, r.Address.Domain); err != nil {
		return Mailbox{}, err
	}
	if _, err := chooseStore(ctx, q, r.Store); err != nil {
		return Mailbox{}, err
	}
	hash := r.PasswordHash
	if r.Password != "" {
		var err error
		if hash, err = s.HashPassword(ctx, r.Password); err != nil {
			return Mailbox{}, err
		}
	}
	var m Mailbox
	err := s.write(ctx, "mailbox.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		if err := q.AdvisoryXactLock(ctx, db.AdvisoryXactLockParams{Class: LockClassPlacement, Key: 0}); err != nil {
			return audit{}, err
		}
		st, err := chooseStore(ctx, q, r.Store)
		if err != nil {
			return audit{}, err
		}
		if s.afterChoose != nil {
			s.afterChoose(st.GateName)
		}
		var a audit
		m, a, err = insertMailbox(ctx, q, NewMailbox{
			Address: r.Address, PasswordHash: hash, QuotaBytes: r.QuotaBytes,
			IMAP: r.IMAP, POP3: r.POP3, SMTP: r.SMTP, StoreID: st.ID,
		})
		return a, err
	})
	switch Rule(err) {
	case "mailbox_store_server_removed":
		return Mailbox{}, &textError{text: "the store's server was removed; try again", err: err}
	case "mailbox_store_not_active":
		return Mailbox{}, &textError{text: "the store is no longer active; try again", err: err}
	}
	if err != nil {
		return Mailbox{}, err
	}
	return m, nil
}

// HashPassword returns the stored Argon2id hash of a new password
// (password.Hash), computed under the hash lock (WithHashLock), so that
// one hash runs at a time across every keepia-mail process on the
// database. If the lock is not granted within the hash lock timeout, the
// error wraps ErrLockTimeout.
func (s *Store) HashPassword(ctx context.Context, pw string) (string, error) {
	var h string
	err := s.WithHashLock(ctx, func() error {
		var err error
		h, err = password.Hash(pw)
		return err
	})
	if errors.Is(err, ErrLockTimeout) {
		return "", &textError{text: "another keepia-mail command is hashing a password; try again", err: err}
	}
	if err != nil {
		return "", err
	}
	return h, nil
}

// SetMailboxPassword gives the mailbox at addr a new password, hashed as
// by HashPassword, together with the changes of c (UpdateMailbox; its
// PasswordHash is replaced). An unknown mailbox fails before the hash.
func (s *Store) SetMailboxPassword(ctx context.Context, addr Address, pw string, c MailboxChange) error {
	ok, err := db.New(s.pool).MailboxExists(ctx, db.MailboxExistsParams{DomainName: addr.Domain, LocalPart: addr.LocalPart})
	if err != nil {
		return err
	}
	if !ok {
		return notFound("mailbox", addr.String())
	}
	h, err := s.HashPassword(ctx, pw)
	if err != nil {
		return err
	}
	c.PasswordHash = &h
	return s.UpdateMailbox(ctx, addr, c)
}

// AliasDomainTarget returns the domain that the alias domain name points
// to, and false if name is not an alias domain.
func (s *Store) AliasDomainTarget(ctx context.Context, name string) (string, bool, error) {
	d, err := db.New(s.pool).AliasDomainTarget(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return d, true, nil
}

// checkMailboxDomain checks that domain is a domain, not an alias domain.
func checkMailboxDomain(ctx context.Context, q *db.Queries, domain string) error {
	ok, err := q.DomainExists(ctx, domain)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	target, err := q.AliasDomainTarget(ctx, domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return notFound("domain", domain)
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%s is an alias domain of %s; mailboxes are added on %s: %w", domain, target, target, ErrRefused)
}

// chosenStore is a store that placement chose or --store named.
type chosenStore struct {
	ID       int64
	GateName string
}

// chooseStore returns the eligible store with the gate name gate, or, for
// an empty gate, the store that placement chooses.
func chooseStore(ctx context.Context, q *db.Queries, gate string) (chosenStore, error) {
	if gate != "" {
		row, err := q.StoreEligibility(ctx, gate)
		if errors.Is(err, pgx.ErrNoRows) {
			return chosenStore{}, notFound("store", gate)
		}
		if err != nil {
			return chosenStore{}, err
		}
		if !row.Eligible {
			return chosenStore{}, fmt.Errorf("store %s is not active or its server was removed: %w", gate, ErrRefused)
		}
		return chosenStore{ID: row.ID, GateName: row.GateName}, nil
	}
	row, err := q.ChooseStore(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return chosenStore{}, fmt.Errorf("no store can take the mailbox: none is active on a server that is not removed: %w", ErrRefused)
	}
	if err != nil {
		return chosenStore{}, err
	}
	return chosenStore{ID: row.ID, GateName: row.GateName}, nil
}

// textError is err with a text of its own for the operator; errors.Is and
// errors.As still see err.
type textError struct {
	text string
	err  error
}

func (e *textError) Error() string { return e.text }
func (e *textError) Unwrap() error { return e.err }
