package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/testwait"
)

// LockWaitQuery is true while a backend of the current database other
// than the asking one waits for a lock (pg_stat_activity, wait_event_type
// Lock).
const LockWaitQuery = `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
	WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock')`

// AdvisoryWaitQuery is true while a backend waits for the advisory lock
// ($1, 0) in the two-int4 form (pg_locks, granted false).
const AdvisoryWaitQuery = `SELECT EXISTS (SELECT 1 FROM pg_locks
	WHERE locktype = 'advisory' AND classid::bigint = $1 AND objid::bigint = 0 AND objsubid = 2 AND NOT granted
	AND database = (SELECT oid FROM pg_database WHERE datname = current_database()))`

// WaitFor returns once query, run on obs, is true: a state the database
// shows (go-tests.md), such as LockWaitQuery. It fails the test at once if
// done delivers first (the waiter got through without waiting), and after
// testwait.Limit. Nothing signals a lock wait, so it polls, bounded by the
// limit.
func WaitFor(tb testing.TB, obs *pgx.Conn, done <-chan error, what, query string, args ...any) {
	tb.Helper()
	deadline := time.Now().Add(testwait.Limit(tb))
	for {
		select {
		case err := <-done:
			tb.Fatalf("%s: got through without waiting for a lock (%v)", what, err)
		default:
		}
		var ok bool
		if err := obs.QueryRow(context.Background(), query, args...).Scan(&ok); err != nil {
			tb.Fatal(err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			tb.Fatalf("timed out waiting for %s", what)
		}
	}
}
