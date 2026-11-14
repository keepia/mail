package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store/db"
)

// SendAs lets a mailbox send as another address of its group (T3), or as
// any address of a domain when As has an empty local part.
type SendAs struct {
	ID        int64
	Mailbox   Address
	Group     string
	As        Address
	Active    bool
	CreatedAt time.Time
}

// CreateSendAs lets the mailbox send as as.
func (s *Store) CreateSendAs(ctx context.Context, mailbox, as Address) (SendAs, error) {
	var g SendAs
	err := s.write(ctx, "send-as.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		row, err := q.InsertSendAs(ctx, db.InsertSendAsParams{
			MailboxDomain: mailbox.Domain, MailboxLocalPart: mailbox.LocalPart,
			DomainName: as.Domain, LocalPart: optional(as.LocalPart),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return audit{}, notFound("mailbox or domain", mailbox.String()+" "+as.String())
		}
		if err != nil {
			return audit{}, err
		}
		g = SendAs{ID: row.ID, Mailbox: mailbox, As: as, Active: row.Active, CreatedAt: row.CreatedAt.Time}
		return audit{object: mailbox.String(), details: map[string]any{"send_as": as.String()}}, nil
	})
	return g, err
}

// SetSendAsActive revokes (false) or restores (true) the grant of mailbox
// to send as as.
func (s *Store) SetSendAsActive(ctx context.Context, mailbox, as Address, active bool) error {
	return s.write(ctx, "send-as.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		n, err := q.SetSendAsActive(ctx, db.SetSendAsActiveParams{
			MailboxDomain: mailbox.Domain, MailboxLocalPart: mailbox.LocalPart,
			DomainName: as.Domain, LocalPart: optional(as.LocalPart), Active: active,
		})
		if err != nil {
			return audit{}, err
		}
		if n == 0 {
			return audit{}, notFound("send-as grant", mailbox.String()+" "+as.String())
		}
		return audit{object: mailbox.String(), details: map[string]any{"send_as": as.String(), "active": active}}, nil
	})
}

// SendAsFilter selects send-as grants; a zero field matches all.
type SendAsFilter struct {
	Mailbox Address
	Group   string
}

// ListSendAs lists the grants that f selects, by mailbox and address.
func (s *Store) ListSendAs(ctx context.Context, f SendAsFilter) ([]SendAs, error) {
	p := db.ListSendAsParams{GroupName: optional(f.Group)}
	if f.Mailbox != (Address{}) {
		p.MailboxDomain, p.MailboxLocalPart = ptr(f.Mailbox.Domain), ptr(f.Mailbox.LocalPart)
	}
	rows, err := db.New(s.pool).ListSendAs(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]SendAs, 0, len(rows))
	for _, r := range rows {
		g := SendAs{
			ID: r.ID, Mailbox: Address{LocalPart: r.MailboxLocalPart, Domain: r.MailboxDomain}, Group: r.GroupName,
			As: Address{Domain: r.DomainName}, Active: r.Active, CreatedAt: r.CreatedAt.Time,
		}
		if r.LocalPart != nil {
			g.As.LocalPart = *r.LocalPart
		}
		out = append(out, g)
	}
	return out, nil
}
