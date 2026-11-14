package store

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// PostgreSQL advisory locks of Keepia Mail, in the two-int4 form
// pg_advisory_lock(class, key) and its variants. That key space does not
// overlap goose's single-bigint migration lock (MigrationLockID): a lock
// taken with two int4 keys is a different lock tag from one taken with a
// bigint, whatever the numbers.
//
// A class is the issue number of the plan that introduced it times 100,
// plus an index, so that plans written in parallel never pick the same
// number. The key is the locked object, 0 for a global lock.
//
// Lock order. A transaction or session that takes more than one of these
// locks takes them in this order, so that no two of them can wait for
// each other:
//
//  1. LockClassBootstrap (serve's bootstrap, session-level; CLI reads take
//     it shared).
//  2. The hash lock (#95, N1; added by N1 to this file).
//  3. The servers row lock of `server remove` (SELECT … FOR UPDATE, #96
//     part 2), a row lock rather than an advisory lock.
//  4. LockClassCRL. No advisory lock is ever taken after the CRL lock.
const (
	// LockClassBootstrap serializes the control secrets' bootstrap (#96,
	// CD6 and C3): serve holds it exclusively, as a session lock on a
	// connection of its own, from before it reads the KEK files until the
	// KEK is linked into place and its directory synced; every command
	// that reads the secrets takes it shared.
	LockClassBootstrap int32 = 9601
	// LockClassCRL serializes every read of a revocation list's number or
	// revoked set with its reissue (#96 part 2, CD36).
	LockClassCRL int32 = 9602
)

// ErrLockTimeout is wrapped by the error of an operation that waited
// longer than its lock_timeout for a lock (SQLSTATE 55P03,
// lock_not_available).
var ErrLockTimeout = errors.New("lock timeout")

// lockTimeoutErr wraps err with ErrLockTimeout when it is PostgreSQL's
// lock_not_available, and returns it unchanged otherwise.
func lockTimeoutErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
		return errors.Join(ErrLockTimeout, err)
	}
	return err
}
