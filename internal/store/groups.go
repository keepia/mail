package store

import (
	"context"
	"time"

	"github.com/keepia/mail/internal/store/db"
)

// Group is a customer group: the unit of isolation (§13 property 2).
type Group struct {
	ID          int64
	Name        string
	DomainCount int64
	CreatedAt   time.Time
}

// CreateGroup adds the group name (a DNS label).
func (s *Store) CreateGroup(ctx context.Context, name string) (Group, error) {
	var g Group
	err := s.write(ctx, "group.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		row, err := q.InsertGroup(ctx, name)
		if err != nil {
			return audit{}, err
		}
		g = Group{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt.Time}
		return audit{object: name}, nil
	})
	return g, err
}

// RenameGroup renames the group name to newName.
func (s *Store) RenameGroup(ctx context.Context, name, newName string) error {
	return s.write(ctx, "group.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		n, err := q.RenameGroup(ctx, db.RenameGroupParams{Name: name, NewName: newName})
		if err != nil {
			return audit{}, err
		}
		if n == 0 {
			return audit{}, notFound("group", name)
		}
		return audit{object: newName, details: map[string]any{"old_name": name}}, nil
	})
}

// ListGroups lists every group with its number of domains, by name.
func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := db.New(s.pool).ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(rows))
	for _, r := range rows {
		out = append(out, Group{ID: r.ID, Name: r.Name, DomainCount: r.DomainCount, CreatedAt: r.CreatedAt.Time})
	}
	return out, nil
}
