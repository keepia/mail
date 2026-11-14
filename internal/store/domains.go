package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store/db"
)

// Domain is a mail domain of a group. Its group and name never change.
type Domain struct {
	ID        int64
	Name      string
	Group     string
	Active    bool
	CreatedAt time.Time
}

// AliasDomain is a second name for a domain: l@<alias domain> is
// l@<domain>. It can be moved to another domain of the same group (T2).
type AliasDomain struct {
	ID        int64
	Name      string
	Domain    string
	Group     string
	Active    bool
	CreatedAt time.Time
}

// CreateDomain adds the domain name to group. A name that is already a
// domain or an alias domain is ErrExists (domain_name_taken).
func (s *Store) CreateDomain(ctx context.Context, name, group string) (Domain, error) {
	var d Domain
	err := s.write(ctx, "domain.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		row, err := q.InsertDomain(ctx, db.InsertDomainParams{Name: name, GroupName: group})
		if errors.Is(err, pgx.ErrNoRows) {
			return audit{}, notFound("group", group)
		}
		if err != nil {
			return audit{}, err
		}
		d = Domain{ID: row.ID, Name: row.Name, Group: group, Active: row.Active, CreatedAt: row.CreatedAt.Time}
		return audit{object: name, details: map[string]any{"group": group}}, nil
	})
	return d, err
}

// SetDomainActive switches the domain name on or off.
func (s *Store) SetDomainActive(ctx context.Context, name string, active bool) error {
	return s.write(ctx, "domain.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		n, err := q.SetDomainActive(ctx, db.SetDomainActiveParams{Name: name, Active: active})
		if err != nil {
			return audit{}, err
		}
		if n == 0 {
			return audit{}, notFound("domain", name)
		}
		return audit{object: name, details: map[string]any{"active": active}}, nil
	})
}

// ListDomains lists the domains by name, only those of group unless it
// is empty.
func (s *Store) ListDomains(ctx context.Context, group string) ([]Domain, error) {
	rows, err := db.New(s.pool).ListDomains(ctx, optional(group))
	if err != nil {
		return nil, err
	}
	out := make([]Domain, 0, len(rows))
	for _, r := range rows {
		out = append(out, Domain{ID: r.ID, Name: r.Name, Group: r.GroupName, Active: r.Active, CreatedAt: r.CreatedAt.Time})
	}
	return out, nil
}

// CreateAliasDomain adds the alias domain name for domain. A name that
// is already a domain or an alias domain is ErrExists.
func (s *Store) CreateAliasDomain(ctx context.Context, name, domain string) (AliasDomain, error) {
	var a AliasDomain
	err := s.write(ctx, "alias-domain.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		row, err := q.InsertAliasDomain(ctx, db.InsertAliasDomainParams{Name: name, DomainName: domain})
		if errors.Is(err, pgx.ErrNoRows) {
			return audit{}, notFound("domain", domain)
		}
		if err != nil {
			return audit{}, err
		}
		a = AliasDomain{ID: row.ID, Name: row.Name, Domain: domain, Active: row.Active, CreatedAt: row.CreatedAt.Time}
		return audit{object: name, details: map[string]any{"domain": domain}}, nil
	})
	return a, err
}

// AliasDomainChange is the change of UpdateAliasDomain; a nil field is
// kept.
type AliasDomainChange struct {
	// Domain is the new target, a domain of the same group (T2).
	Domain *string
	Active *bool
}

// UpdateAliasDomain changes the alias domain name.
func (s *Store) UpdateAliasDomain(ctx context.Context, name string, c AliasDomainChange) error {
	return s.write(ctx, "alias-domain.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		details := map[string]any{}
		if c.Domain != nil {
			ok, err := q.DomainExists(ctx, *c.Domain)
			if err != nil {
				return audit{}, err
			}
			if !ok {
				return audit{}, notFound("domain", *c.Domain)
			}
			details["domain"] = *c.Domain
		}
		if c.Active != nil {
			details["active"] = *c.Active
		}
		n, err := q.UpdateAliasDomain(ctx, db.UpdateAliasDomainParams{Name: name, DomainName: c.Domain, Active: c.Active})
		if err != nil {
			return audit{}, err
		}
		if n == 0 {
			return audit{}, notFound("alias domain", name)
		}
		return audit{object: name, details: details}, nil
	})
}

// AliasDomainFilter selects alias domains; an empty field matches all.
type AliasDomainFilter struct {
	Domain, Group string
}

// ListAliasDomains lists the alias domains that f selects, by name.
func (s *Store) ListAliasDomains(ctx context.Context, f AliasDomainFilter) ([]AliasDomain, error) {
	rows, err := db.New(s.pool).ListAliasDomains(ctx, db.ListAliasDomainsParams{DomainName: optional(f.Domain), GroupName: optional(f.Group)})
	if err != nil {
		return nil, err
	}
	out := make([]AliasDomain, 0, len(rows))
	for _, r := range rows {
		out = append(out, AliasDomain{ID: r.ID, Name: r.Name, Domain: r.DomainName, Group: r.GroupName, Active: r.Active, CreatedAt: r.CreatedAt.Time})
	}
	return out, nil
}

// optional is nil for "" (no filter, or SQL NULL) and &s otherwise.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
