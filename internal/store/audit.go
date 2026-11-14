package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/keepia/mail/internal/store/db"
)

// AuditEntry is one row of audit_log: who did what to which object. Every
// write of the data model's API adds one in its own transaction, and
// purges rows older than 30 days (at most 1000 per write). In 0.2.0 the
// purge runs on writes only, so rows older than 30 days stay until the
// next write.
type AuditEntry struct {
	ID      int64
	At      time.Time
	Actor   string
	Action  string
	Object  string
	Details map[string]any
}

// ListAudit lists the newest max audit rows, newest first.
func (s *Store) ListAudit(ctx context.Context, maxRows int32) ([]AuditEntry, error) {
	rows, err := db.New(s.pool).ListAudit(ctx, maxRows)
	if err != nil {
		return nil, err
	}
	out := make([]AuditEntry, 0, len(rows))
	for _, r := range rows {
		e := AuditEntry{ID: r.ID, At: r.At.Time, Actor: r.Actor, Action: r.Action, Object: r.Object}
		if err := json.Unmarshal(r.Details, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
