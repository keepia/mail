package store

import (
	"context"
	"errors"
	"runtime/debug"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/keepia/mail/internal/store/db"
)

// PostgreSQL advisory locks of Keepia Mail, in the two-int4 form
// pg_advisory_lock(class, key) and its variants. That key space does not
// overlap goose's single-bigint migration lock (MigrationLockID): a lock
// taken with two int4 keys is a different lock tag from one taken with a
// bigint, whatever the numbers.
//
// A class is the issue number of the plan that introduced it times 100,
// plus an index, so that plans written in parallel never pick the same
// number. The key is the locked object, 0 for a global lock. N1's classes
// (#95, 950201 to 950204) predate that rule and keep their values, which
// the migration's T1 and T5 also use; the lock tests prove that both agree.
//
// # Lock order
//
// A transaction or session that takes more than one of these locks takes
// them in this order, so that no two of them can wait for each other in a
// cycle (#95 plan review 6875754045, C1 and C5; #96):
//
//   - LockClassBootstrap (serve's bootstrap, session-level; CLI reads take
//     it shared) before the hash lock, never the reverse.
//   - The hash lock is a leaf: WithHashLock's fn does no database work,
//     and nothing is held while a caller waits for it.
//   - Placement, then names or addresses (T1, T5), then the servers row
//     (FOR SHARE in T7 and T8), then the stores row (FOR SHARE in T7).
//   - An alias update locks the aliases row FOR UPDATE as its first
//     statement, before any target is inserted or deleted (C1); T6 then
//     takes the same lock again at commit.
//   - The servers row lock of `server remove` (SELECT … FOR UPDATE, #96
//     part 2), then LockClassCRL, then certificate and token rows. No
//     advisory lock is ever taken after the CRL lock.
//   - Any transaction that locks both a server and a store row (N4's
//     activation and heartbeat included) locks the server first.
const (
	// LockClassNames serializes inserts of one domain or alias domain
	// name (T1); the key is hashtext(name).
	LockClassNames int32 = 950201
	// LockClassAddresses serializes inserts of one mailbox or alias
	// address (T5); the key is hashtext(domain_id || '/' || local_part).
	LockClassAddresses int32 = 950202
	// LockClassPlacement serializes mailbox placement (#95 part 2); the
	// key is 0.
	LockClassPlacement int32 = 950203
	// LockClassHash lets one Argon2id computation run at a time across
	// every keepia-mail process on the database (WithHashLock); the key
	// is 0.
	LockClassHash int32 = 950204
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

// freeOSMemory is debug.FreeOSMemory; tests replace it (export_test.go).
var freeOSMemory = debug.FreeOSMemory

// WithHashLock runs fn while it holds the hash lock (LockClassHash, 0) in
// a READ COMMITTED transaction of its own, with a lock timeout of 60 s
// (WithLockTimeout). If the lock is not granted in time, it returns
// ErrLockTimeout and fn does not run.
//
// fn computes a password hash (Argon2id, 64 MiB) and does no database
// work. Once fn returns, WithHashLock calls debug.FreeOSMemory before the
// transaction commits, so the next holder starts only after the array is
// handed back to the operating system (CD-C4). It calls it exactly once
// on every return path, also when fn fails or never ran.
func (s *Store) WithHashLock(ctx context.Context, fn func() error) error {
	freed := false
	free := func() {
		if !freed {
			freed = true
			freeOSMemory()
		}
	}
	defer free()
	tx, err := s.pool.BeginTx(ctx, readCommitted)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op after the commit
	q := db.New(tx)
	if err := q.SetLockTimeout(ctx, pgDuration(s.hashLockTimeout)); err != nil {
		return mapError(err)
	}
	if err := q.AdvisoryXactLock(ctx, db.AdvisoryXactLockParams{Class: LockClassHash, Key: 0}); err != nil {
		return mapError(err)
	}
	err = fn()
	free()
	if err != nil {
		return err
	}
	return mapError(tx.Commit(ctx))
}
