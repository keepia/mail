package store

import (
	"context"

	"github.com/pressly/goose/v3"
)

// CloseMigrationPool is closeMigrationPool, for the tests of package
// store_test (which can import storetest).
var CloseMigrationPool = closeMigrationPool

// MigrateUpTo applies the migrations up to and including version, under
// the migration lock.
func (s *Store) MigrateUpTo(ctx context.Context, version int64) error {
	return s.withMigrations(ctx, true, func(p *goose.Provider) error {
		_, err := p.UpTo(ctx, version)
		return err
	})
}

// MigrateDownTo rolls back the migrations above version, under the
// migration lock.
func (s *Store) MigrateDownTo(ctx context.Context, version int64) error {
	return s.withMigrations(ctx, true, func(p *goose.Provider) error {
		_, err := p.DownTo(ctx, version)
		return err
	})
}

// WithBeforeCommit returns ctx with the seam of write: f runs right
// before the write's COMMIT, after its audit row and purge.
func WithBeforeCommit(ctx context.Context, f func()) context.Context {
	return context.WithValue(ctx, beforeCommitKey{}, f)
}

// SetFreeOSMemory replaces WithHashLock's debug.FreeOSMemory with f until
// restore is called.
func SetFreeOSMemory(f func()) (restore func()) {
	old := freeOSMemory
	freeOSMemory = f
	return func() { freeOSMemory = old }
}
