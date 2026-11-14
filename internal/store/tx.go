package store

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store/db"
)

// readCommitted is the isolation of every write (N3). The checks of T1,
// T5, T6 and T8 rely on a fresh snapshot per statement after their lock,
// and they refuse any other level (read_committed_required).
var readCommitted = pgx.TxOptions{IsoLevel: pgx.ReadCommitted}

// audit is the audit_log row of one write: the object (a name or an
// address) and the details. The details never hold a password or a hash.
type audit struct {
	object  string
	details map[string]any
}

// write runs fn in one READ COMMITTED transaction with the store's lock
// timeout. When fn succeeds, the same transaction adds fn's audit row
// (action, by the store's actor) and purges audit rows older than 30
// days, then commits. A write that fails, also at the commit (T6), leaves
// no audit row. Errors are mapped by mapError.
func (s *Store) write(ctx context.Context, action string, fn func(ctx context.Context, q *db.Queries) (audit, error)) error {
	tx, err := s.pool.BeginTx(ctx, readCommitted)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op after the commit
	q := db.New(tx)
	if err := q.SetLockTimeout(ctx, pgDuration(s.lockTimeout)); err != nil {
		return mapError(err)
	}
	a, err := fn(ctx, q)
	if err != nil {
		return mapError(err)
	}
	if a.details == nil {
		a.details = map[string]any{}
	}
	details, err := json.Marshal(a.details)
	if err != nil {
		return err
	}
	if err := q.InsertAudit(ctx, db.InsertAuditParams{Actor: s.actor, Action: action, Object: a.object, Details: details}); err != nil {
		return mapError(err)
	}
	if err := q.PurgeAudit(ctx); err != nil {
		return mapError(err)
	}
	if h, ok := ctx.Value(beforeCommitKey{}).(func()); ok {
		h()
	}
	return mapError(tx.Commit(ctx))
}

// beforeCommitKey is the context key of a test seam (export_test.go): a
// func() that write calls right before COMMIT, after the audit row and
// the purge. Nothing outside tests sets it.
type beforeCommitKey struct{}

// pgDuration is d as a PostgreSQL time setting in milliseconds; 0
// disables the timeout.
func pgDuration(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
}

// ptr returns a pointer to v, for the nullable arguments of the queries.
func ptr[T any](v T) *T { return &v }
