package store_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

// holdMigrationLock takes the migration lock on a connection of its own to
// dbURL and returns the function that releases it. Advisory locks are per
// database, so dbURL must be the database that is migrated.
func holdMigrationLock(t *testing.T, dbURL string) (release func()) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", store.MigrationLockID); err != nil {
		_ = conn.Close(ctx)
		t.Fatal(err)
	}
	released := false
	release = func() {
		if released {
			return
		}
		released = true
		_ = conn.Close(ctx) // ends the session, which frees its lock
	}
	t.Cleanup(release)
	return release
}

// While another session holds the migration lock, Migrate gives up after
// the lock timeout with ErrMigrationLock and applies nothing; once the
// lock is free it succeeds.
func TestMigrateWaitsForLock(t *testing.T) {
	ctx := context.Background()
	dbURL := storetest.NewUnmigrated(t)
	release := holdMigrationLock(t, dbURL)
	st := open(t, dbURL, store.WithMigrationLockTimeout(1, 2))

	_, err := st.Migrate(ctx)
	if !errors.Is(err, store.ErrMigrationLock) {
		t.Fatalf("migrate with the lock held: %v, want ErrMigrationLock", err)
	}
	if id := strconv.FormatInt(store.MigrationLockID, 10); !strings.Contains(err.Error(), id) {
		t.Errorf("error %q does not name lock %s", err, id)
	}
	if n := versionRows(t, dbURL, 1); n != 0 {
		t.Fatalf("migrate with the lock held recorded version 1 (%d rows)", n)
	}

	release()
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate after release: %v", err)
	}
	if n := versionRows(t, dbURL, 1); n != 1 {
		t.Fatalf("after release: %d rows for version 1", n)
	}
}

// lockFree tells whether another session could take the migration lock
// now. It takes it with pg_try_advisory_lock, which never waits, and frees
// it again at once.
func lockFree(ctx context.Context, t *testing.T, conn *pgx.Conn) bool {
	t.Helper()
	var free bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", store.MigrationLockID).Scan(&free); err != nil {
		t.Fatal(err)
	}
	if free {
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", store.MigrationLockID); err != nil {
			t.Fatal(err)
		}
	}
	return free
}

// A connection that database/sql gave up while it held the migration lock
// goes back to goose's pool, idle and still open. closeMigrationPool frees
// its lock with pg_advisory_unlock_all before it closes the pool: the test
// checks the lock while that connection is still open (the beforeClose
// seam), so the server's asynchronous cleanup after the close cannot make
// it pass.
func TestCloseMigrationPoolFreesLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Limit(t))
	defer cancel()
	dbURL := storetest.NewUnmigrated(t)

	gp, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gp.Close) // a second Close is a no-op
	sqlDB := stdlib.OpenDBFromPool(gp)

	// Take the lock through database/sql and give the connection back
	// without unlocking: it returns to gp as an idle connection.
	sc, err := sqlDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var holderPID int32
	if err := sc.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&holderPID); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.ExecContext(ctx, "SELECT pg_advisory_lock($1)", store.MigrationLockID); err != nil {
		t.Fatal(err)
	}
	if err := sc.Close(); err != nil {
		t.Fatal(err)
	}
	if n := gp.Stat().IdleConns(); n != 1 {
		t.Fatalf("goose's pool has %d idle connections, want the lock holder", n)
	}

	other, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close(ctx) }()
	if lockFree(ctx, t, other) {
		t.Fatal("migration lock free before closeMigrationPool, want it held by the idle connection")
	}

	ran := false
	store.CloseMigrationPool(ctx, gp, sqlDB, func() {
		ran = true
		var alive bool
		if err := other.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1)", holderPID).Scan(&alive); err != nil {
			t.Errorf("look up the holder's backend: %v", err)
			return
		}
		if !alive {
			t.Errorf("the holder's backend %d is gone before the close, want it open", holderPID)
		}
		if !lockFree(ctx, t, other) {
			t.Errorf("migration lock still held before goose's pool closes, want it freed by the unlock")
		}
	})
	if !ran {
		t.Fatal("beforeClose did not run")
	}
}
