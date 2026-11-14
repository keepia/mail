package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store/db"
)

// Alias delivers to one or more mailboxes of its own group (T4). An
// Address with an empty local part is the domain's catch-all. At commit,
// every alias has at least one target (T6).
type Alias struct {
	ID        int64
	Address   Address
	Group     string
	Active    bool
	Targets   []Address
	CreatedAt time.Time
}

// CreateAlias adds the alias addr with targets, which are mailbox
// addresses. Its address must not be a mailbox (T5, address_taken).
func (s *Store) CreateAlias(ctx context.Context, addr Address, targets []Address) (Alias, error) {
	var a Alias
	err := s.write(ctx, "alias.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		row, err := q.InsertAlias(ctx, db.InsertAliasParams{DomainName: addr.Domain, LocalPart: optional(addr.LocalPart)})
		if errors.Is(err, pgx.ErrNoRows) {
			return audit{}, notFound("domain", addr.Domain)
		}
		if err != nil {
			return audit{}, err
		}
		for _, t := range targets {
			if err := addTarget(ctx, q, row.ID, t); err != nil {
				return audit{}, err
			}
		}
		a = Alias{ID: row.ID, Address: addr, Active: row.Active, Targets: targets, CreatedAt: row.CreatedAt.Time}
		return audit{object: addr.String(), details: map[string]any{"targets": addressTexts(targets)}}, nil
	})
	return a, err
}

// AliasChange is the change of UpdateAlias. Add and Remove are mailbox
// addresses; a nil Active is kept.
type AliasChange struct {
	Add, Remove []Address
	Active      *bool
}

// UpdateAlias changes the alias addr. Its first statement locks the alias
// row FOR UPDATE, before any target is inserted or deleted, so two
// concurrent updates of one alias queue instead of deadlocking in T6 (C1).
func (s *Store) UpdateAlias(ctx context.Context, addr Address, c AliasChange) error {
	return s.write(ctx, "alias.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		id, err := q.LockAlias(ctx, db.LockAliasParams{DomainName: addr.Domain, LocalPart: optional(addr.LocalPart)})
		if errors.Is(err, pgx.ErrNoRows) {
			return audit{}, notFound("alias", addr.String())
		}
		if err != nil {
			return audit{}, err
		}
		details := map[string]any{}
		if c.Active != nil {
			if err := q.SetAliasActive(ctx, db.SetAliasActiveParams{ID: id, Active: *c.Active}); err != nil {
				return audit{}, err
			}
			details["active"] = *c.Active
		}
		for _, t := range c.Add {
			if err := addTarget(ctx, q, id, t); err != nil {
				return audit{}, err
			}
		}
		for _, t := range c.Remove {
			n, err := q.DeleteAliasTarget(ctx, db.DeleteAliasTargetParams{AliasID: id, DomainName: t.Domain, LocalPart: t.LocalPart})
			if err != nil {
				return audit{}, err
			}
			if n == 0 {
				return audit{}, notFound("alias target", t.String())
			}
		}
		if len(c.Add) > 0 {
			details["add"] = addressTexts(c.Add)
		}
		if len(c.Remove) > 0 {
			details["remove"] = addressTexts(c.Remove)
		}
		return audit{object: addr.String(), details: details}, nil
	})
}

func addTarget(ctx context.Context, q *db.Queries, alias int64, t Address) error {
	n, err := q.InsertAliasTarget(ctx, db.InsertAliasTargetParams{AliasID: alias, DomainName: t.Domain, LocalPart: t.LocalPart})
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound("mailbox", t.String())
	}
	return nil
}

// AliasFilter selects aliases; an empty field matches all.
type AliasFilter struct {
	Domain, Group string
}

// ListAliases lists the aliases that f selects with their targets, by
// address (a domain's catch-all first); the targets are sorted.
func (s *Store) ListAliases(ctx context.Context, f AliasFilter) ([]Alias, error) {
	q := db.New(s.pool)
	rows, err := q.ListAliases(ctx, db.ListAliasesParams{DomainName: optional(f.Domain), GroupName: optional(f.Group)})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []Alias{}, nil
	}
	out := make([]Alias, 0, len(rows))
	index := make(map[int64]int, len(rows))
	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		a := Alias{ID: r.ID, Address: Address{Domain: r.DomainName}, Group: r.GroupName, Active: r.Active, CreatedAt: r.CreatedAt.Time}
		if r.LocalPart != nil {
			a.Address.LocalPart = *r.LocalPart
		}
		index[r.ID] = len(out)
		ids = append(ids, r.ID)
		out = append(out, a)
	}
	targets, err := q.ListAliasTargets(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, t := range targets {
		a := &out[index[t.AliasID]]
		a.Targets = append(a.Targets, Address{LocalPart: t.LocalPart, Domain: t.DomainName})
	}
	return out, nil
}

func addressTexts(as []Address) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	return out
}
