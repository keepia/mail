package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store/db"
)

// UnlimitedPlacementWeight is what an unlimited mailbox (quota 0) weighs
// in placement: 10 GiB (CD13). The migration's keepia_placement_weight
// uses the same number; a test checks that both agree.
const UnlimitedPlacementWeight int64 = 10 << 30

// The mailbox states.
const (
	MailboxActive   = "active"
	MailboxDisabled = "disabled"
)

// Address is local@domain. An empty LocalPart is the whole domain: an
// alias's catch-all or a send-as grant for the domain.
type Address struct {
	LocalPart, Domain string
}

// String is local@domain, or @domain for an empty local part.
func (a Address) String() string { return a.LocalPart + "@" + a.Domain }

// Mailbox is a mailbox on a store. Its address and store never change
// (T9). The password hash is never returned, only its scheme.
type Mailbox struct {
	ID      int64
	Address Address
	Group   string
	// Store is the store's gate name.
	Store   string
	StoreID int64
	// QuotaBytes is the quota; 0 is unlimited.
	QuotaBytes       int64
	IMAP, POP3, SMTP bool
	State            string
	// Scheme is the password hash's scheme, such as ARGON2ID.
	Scheme    string
	CreatedAt time.Time
}

// NewMailbox is the mailbox that CreateMailbox adds, in state active.
type NewMailbox struct {
	Address Address
	// PasswordHash is a stored hash with its scheme prefix, such as
	// {ARGON2ID}$argon2id$...; its format is checked by the caller.
	PasswordHash     string
	QuotaBytes       int64
	IMAP, POP3, SMTP bool
	// StoreID is an active store on a server that is not removed (T7).
	// Part 2 chooses it by placement.
	StoreID int64
}

// CreateMailbox adds a mailbox on the store n.StoreID. Its address must
// not be an alias (T5, address_taken).
func (s *Store) CreateMailbox(ctx context.Context, n NewMailbox) (Mailbox, error) {
	var m Mailbox
	err := s.write(ctx, "mailbox.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		row, err := q.InsertMailbox(ctx, db.InsertMailboxParams{
			DomainName: n.Address.Domain, LocalPart: n.Address.LocalPart, PasswordHash: n.PasswordHash,
			QuotaBytes: n.QuotaBytes, ImapAccess: n.IMAP, Pop3Access: n.POP3, SmtpAccess: n.SMTP, StoreID: n.StoreID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return audit{}, notFound("domain", n.Address.Domain)
		}
		if err != nil {
			return audit{}, err
		}
		m = Mailbox{
			ID: row.ID, Address: n.Address, Store: row.GateName, StoreID: n.StoreID, QuotaBytes: n.QuotaBytes,
			IMAP: n.IMAP, POP3: n.POP3, SMTP: n.SMTP, State: MailboxActive, Scheme: hashScheme(n.PasswordHash),
			CreatedAt: row.CreatedAt.Time,
		}
		return audit{object: n.Address.String(), details: map[string]any{
			"store": row.GateName, "quota_bytes": n.QuotaBytes, "scheme": m.Scheme,
		}}, nil
	})
	return m, err
}

// MailboxChange is the change of UpdateMailbox; a nil field is kept.
type MailboxChange struct {
	QuotaBytes       *int64
	IMAP, POP3, SMTP *bool
	State            *string
	// PasswordHash replaces the stored hash. The audit row records only
	// that the password changed and the new scheme.
	PasswordHash *string
}

// UpdateMailbox changes the mailbox at addr.
func (s *Store) UpdateMailbox(ctx context.Context, addr Address, c MailboxChange) error {
	return s.write(ctx, "mailbox.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		n, err := q.UpdateMailbox(ctx, db.UpdateMailboxParams{
			DomainName: addr.Domain, LocalPart: addr.LocalPart, QuotaBytes: c.QuotaBytes,
			ImapAccess: c.IMAP, Pop3Access: c.POP3, SmtpAccess: c.SMTP, State: c.State, PasswordHash: c.PasswordHash,
		})
		if err != nil {
			return audit{}, err
		}
		if n == 0 {
			return audit{}, notFound("mailbox", addr.String())
		}
		details := map[string]any{}
		if c.QuotaBytes != nil {
			details["quota_bytes"] = *c.QuotaBytes
		}
		if c.IMAP != nil {
			details["imap"] = *c.IMAP
		}
		if c.POP3 != nil {
			details["pop3"] = *c.POP3
		}
		if c.SMTP != nil {
			details["smtp"] = *c.SMTP
		}
		if c.State != nil {
			details["state"] = *c.State
		}
		if c.PasswordHash != nil {
			details["password"] = "changed"
			details["scheme"] = hashScheme(*c.PasswordHash)
		}
		return audit{object: addr.String(), details: details}, nil
	})
}

// MailboxFilter selects mailboxes; an empty field matches all. Store is a
// gate name.
type MailboxFilter struct {
	Domain, Group, Store string
}

// ListMailboxes lists the mailboxes that f selects, by address.
func (s *Store) ListMailboxes(ctx context.Context, f MailboxFilter) ([]Mailbox, error) {
	rows, err := db.New(s.pool).ListMailboxes(ctx, db.ListMailboxesParams{
		DomainName: optional(f.Domain), GroupName: optional(f.Group), GateName: optional(f.Store),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Mailbox, 0, len(rows))
	for _, r := range rows {
		out = append(out, Mailbox{
			ID: r.ID, Address: Address{LocalPart: r.LocalPart, Domain: r.DomainName}, Group: r.GroupName,
			Store: r.GateName, StoreID: r.StoreID, QuotaBytes: r.QuotaBytes,
			IMAP: r.ImapAccess, POP3: r.Pop3Access, SMTP: r.SmtpAccess, State: r.State, Scheme: r.Scheme,
			CreatedAt: r.CreatedAt.Time,
		})
	}
	return out, nil
}

// hashScheme is the scheme of a stored hash, the name between its braces
// ({ARGON2ID}... gives ARGON2ID), or "".
func hashScheme(hash string) string {
	rest, ok := strings.CutPrefix(hash, "{")
	if !ok {
		return ""
	}
	scheme, _, ok := strings.Cut(rest, "}")
	if !ok {
		return ""
	}
	return scheme
}
