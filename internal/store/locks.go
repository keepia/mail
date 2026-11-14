package store

import (
	"context"
	"runtime/debug"

	"github.com/keepia/mail/internal/store/db"
)

// The advisory lock classes of Keepia Mail. Every lock uses PostgreSQL's
// two-int4 form, pg_advisory_xact_lock(class, key), whose key space does
// not overlap goose's single-bigint MigrationLockID. The values are fixed
// once on main and are also written in the migrations (T1, T5); the lock
// tests prove that both agree. N2 (#96, #107) adds its classes here.
//
// # Lock order
//
// Every transaction takes its locks in this order, so no two of them wait
// for each other in a cycle (plan review 6875754045, C1 and C5):
//
//   - N2's bootstrap lock before the hash lock, never the reverse.
//   - The hash lock is a leaf: WithHashLock's fn does no database work,
//     and nothing is held while a caller waits for it.
//   - Placement, then names or addresses (T1, T5), then the servers row
//     (FOR SHARE in T7 and T8), then the stores row (FOR SHARE in T7).
//   - An alias update locks the aliases row FOR UPDATE as its first
//     statement, before any target is inserted or deleted (C1); T6 then
//     takes the same lock again at commit.
//   - The servers row, then N2's CRL lock, then certificate and token rows.
//   - Any transaction that locks both a server and a store row (N4's
//     activation and heartbeat included) locks the server first.
const (
	// LockClassNames serializes inserts of one domain or alias domain
	// name (T1); the key is hashtext(name).
	LockClassNames int32 = 950201
	// LockClassAddresses serializes inserts of one mailbox or alias
	// address (T5); the key is hashtext(domain_id || '/' || local_part).
	LockClassAddresses int32 = 950202
	// LockClassPlacement serializes mailbox placement (part 2); the key
	// is 0.
	LockClassPlacement int32 = 950203
	// LockClassHash lets one Argon2id computation run at a time across
	// every keepia-mail process on the database (WithHashLock); the key
	// is 0.
	LockClassHash int32 = 950204
)

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
