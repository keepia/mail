package store_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
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
