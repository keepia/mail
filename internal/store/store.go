// Package store holds Keepia Mail's PostgreSQL connection pool and its
// schema migrations.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrationLockID is the PostgreSQL advisory lock that Migrate and
// MigrateDown hold while they run: goose's default lock id.
const MigrationLockID = lock.DefaultLockID

// ErrMigrationLock is wrapped by the error of Migrate and MigrateDown when
// the migration lock (MigrationLockID) could not be taken in time, because
// another session holds it.
var ErrMigrationLock = errors.New("migration lock not acquired")

// Store wraps a PostgreSQL connection pool.
type Store struct {
	pool *pgxpool.Pool
	// lockOptions configure goose's session locker (WithMigrationLockTimeout).
	lockOptions []lock.SessionLockerOption
}

// Option configures Open.
type Option func(*openConfig)

type openConfig struct {
	// settings are the SET statements run on every new connection.
	settings    []string
	lockOptions []lock.SessionLockerOption
}

// ForMigrations sets up the store so that a statement of a killed command
// does not run on for long and keep the migration lock. Every new
// connection of the pool gets:
//
//   - client_connection_check_interval = 10s: PostgreSQL 14 and later on
//     Linux check every 10 s during a running statement whether the client
//     is still there, and abort the statement about 10 s after its socket
//     closed (SIGKILL, a crashed container).
//   - TCP keepalives (idle 60 s, then every 10 s, 6 probes): if the client's
//     host or network vanishes and no FIN arrives, the server notices after
//     about 2 minutes instead of the kernel default of about 2 hours. They
//     apply to TCP connections only.
//
// Each SET is best effort: its error is ignored, so a server or proxy that
// refuses one works as before, just without that setting.
func ForMigrations() Option {
	return func(c *openConfig) {
		c.settings = append(c.settings,
			"SET client_connection_check_interval = '10s'",
			"SET tcp_keepalives_idle = 60",
			"SET tcp_keepalives_interval = 10",
			"SET tcp_keepalives_count = 6",
		)
	}
}

// WithMigrationLockTimeout sets how long Migrate and MigrateDown try to
// take the migration lock: every period seconds, up to tries more times
// after the first (goose's lock.WithLockTimeout). The default is goose's:
// every 5 s, 60 times, so about 5 minutes. Only tests set it.
func WithMigrationLockTimeout(period, tries uint64) Option {
	return func(c *openConfig) {
		c.lockOptions = append(c.lockOptions, lock.WithLockTimeout(period, tries))
	}
}

// Open connects to the database. Its error never contains the password of
// url, nor any other part of url's user information: a URL that does not
// parse, or whose host contains an '@' (an unescaped '@' in the user or
// password, which pgx splits at the first '@'), is rejected with a fixed
// text before anything connects.
func Open(ctx context.Context, url string, opts ...Option) (*Store, error) {
	var oc openConfig
	for _, o := range opts {
		o(&oc)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		// pgx's parse error quotes the URL (with the password masked,
		// but not a password fragment after an unescaped '@'); say only
		// what is wrong with it.
		return nil, errors.New("parse database URL: invalid connection string")
	}
	if hostHasAt(cfg.ConnConfig) {
		return nil, errAtInHost
	}
	if settings := oc.settings; len(settings) > 0 {
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			for _, set := range settings {
				// Best effort (see ForMigrations): a refused SET is
				// ignored. Only a connection that broke on the way is
				// not handed out.
				if _, err := conn.Exec(ctx, set); err != nil && conn.IsClosed() {
					return err
				}
			}
			return nil
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return &Store{pool: pool, lockOptions: oc.lockOptions}, nil
}

// errAtInHost is Open's error for a URL whose host contains an '@'. It
// names no part of the URL.
var errAtInHost = errors.New("parse database URL: '@' in the user name or password must be percent-encoded (%40)")

// hostHasAt tells whether the host of cfg or of one of its fallbacks
// contains an '@'. pgx splits the user information at the first '@', so
// the rest of a password with an unescaped '@' ends up in the host, and
// pgx's connect errors would print it.
func hostHasAt(cfg *pgx.ConnConfig) bool {
	if strings.Contains(cfg.Host, "@") {
		return true
	}
	for _, fb := range cfg.Fallbacks {
		if strings.Contains(fb.Host, "@") {
			return true
		}
	}
	return false
}

// Close releases all connections.
func (s *Store) Close() { s.pool.Close() }

// Ping checks that the database answers a query.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.pool.QueryRow(ctx, "SELECT 1").Scan(&one)
}

// Migrate applies all pending schema migrations under the migration lock
// (withMigrations) and returns the migrations it applied.
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	var applied []string
	err := s.withMigrations(ctx, true, func(p *goose.Provider) error {
		results, err := p.Up(ctx)
		for _, r := range results {
			applied = append(applied, r.Source.Path)
		}
		return err
	})
	return applied, err
}

// MigrateDown rolls back the most recently applied migration, under the
// migration lock as Migrate. It returns the migration that was rolled back.
func (s *Store) MigrateDown(ctx context.Context) (string, error) {
	var rolledBack string
	err := s.withMigrations(ctx, true, func(p *goose.Provider) error {
		r, err := p.Down(ctx)
		if errors.Is(err, goose.ErrNoNextVersion) {
			return errors.New("no migration to roll back")
		}
		if err != nil {
			return err
		}
		rolledBack = r.Source.Path
		return nil
	})
	return rolledBack, err
}

// MigrationStatus describes one known migration.
type MigrationStatus struct {
	Path      string
	Applied   bool
	AppliedAt time.Time
}

// MigrationStatus lists all migrations and whether they are applied. It
// does not wait for a running migration: it reads goose_db_version without
// the migration lock and sees the migrations committed so far.
func (s *Store) MigrationStatus(ctx context.Context) ([]MigrationStatus, error) {
	var out []MigrationStatus
	err := s.withMigrations(ctx, false, func(p *goose.Provider) error {
		statuses, err := p.Status(ctx)
		if err != nil {
			return err
		}
		for _, st := range statuses {
			out = append(out, MigrationStatus{
				Path:      st.Source.Path,
				Applied:   st.State == goose.StateApplied,
				AppliedAt: st.AppliedAt,
			})
		}
		return nil
	})
	return out, err
}

// withMigrations runs fn with a goose provider for the embedded migrations.
//
// With locked, the provider takes goose's Postgres session lock (the
// advisory lock MigrationLockID) for each Up or Down, on the connection
// that runs the migrations, so that two instances starting at once apply
// each version once. goose's locker polls with pg_try_advisory_lock: by
// default every 5 s, up to 60 times. When it gives up, the error wraps
// ErrMigrationLock. Status reads go without the lock, because goose's
// Status takes it too and would wait behind a running migration.
//
// goose runs on a short-lived pgx pool of its own, made from a copy of the
// store's pool config (the same server, credentials and ForMigrations
// settings) and closed before withMigrations returns, so goose never takes
// connections from the store's pool and a connection that database/sql
// gave up while it held the lock is not handed out again (see
// closeMigrationPool).
//
// When ctx has ended, the error wraps ctx's error (withCtxErr), whichever
// step of goose saw the cancel.
func (s *Store) withMigrations(ctx context.Context, locked bool, fn func(*goose.Provider) error) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	var opts []goose.ProviderOption
	if locked {
		l, err := lock.NewPostgresSessionLocker(s.lockOptions...)
		if err != nil {
			return err
		}
		opts = append(opts, goose.WithSessionLocker(namedLocker{l}))
	}
	// The copy keeps the store's pool_min_conns and pool_min_idle_conns;
	// zeroed, goose's pool opens only the connections goose asks for, not
	// idle ones in the background on ctx.
	cfg := s.pool.Config()
	cfg.MinConns = 0
	cfg.MinIdleConns = 0
	gp, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return withCtxErr(ctx, err)
	}
	sqlDB := stdlib.OpenDBFromPool(gp)
	defer closeMigrationPool(ctx, gp, sqlDB)
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, sub, opts...)
	if err != nil {
		return err
	}
	return withCtxErr(ctx, fn(provider))
}

// namedLocker is goose's session locker whose lock error wraps
// ErrMigrationLock and names the lock id: goose's own text ("failed to
// acquire lock") names neither.
type namedLocker struct{ lock.SessionLocker }

func (l namedLocker) SessionLock(ctx context.Context, conn *sql.Conn) error {
	if err := l.SessionLocker.SessionLock(ctx, conn); err != nil {
		if ctx.Err() != nil {
			return err
		}
		return fmt.Errorf("%w (PostgreSQL advisory lock %s, held by another session): %w",
			ErrMigrationLock, strconv.FormatInt(MigrationLockID, 10), err)
	}
	return nil
}

// migrationPoolUnlockLimit bounds the teardown unlock of
// closeMigrationPool, so that a vanished server cannot hang it.
const migrationPoolUnlockLimit = 5 * time.Second

// closeMigrationPool closes goose's pool gp and its database/sql handle
// sqlDB, and frees the migration lock if a connection of gp still holds it.
//
// Closing sqlDB releases its connections to gp. A connection that
// database/sql gave up while it held the lock is back in gp when it is open
// and idle; on every idle connection the teardown runs
// pg_advisory_unlock_all(), so the lock of such a connection is free when
// Migrate or MigrateDown returns. A destroyed connection keeps its lock
// until its backend exits, which the server notices asynchronously.
//
// The unlock runs without ctx's cancel, so a Ctrl-C does not skip it, and
// within migrationPoolUnlockLimit. A failed or timed-out unlock is ignored:
// gp.Close closes the connection anyway, and the server then frees the
// lock when the backend exits.
func closeMigrationPool(ctx context.Context, gp *pgxpool.Pool, sqlDB *sql.DB) {
	_ = sqlDB.Close()
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrationPoolUnlockLimit)
	defer cancel()
	for _, c := range gp.AcquireAllIdle(uctx) {
		_, _ = c.Exec(uctx, "SELECT pg_advisory_unlock_all()")
		c.Release()
	}
	gp.Close()
}

// withCtxErr returns err so that it wraps ctx's error when ctx has ended,
// keeping err's text: "context canceled (<err>)". A nil err stays nil, so
// a migration that finished just before the cancel still reports success,
// and an err that already wraps ctx's error is returned as is.
//
// It is needed because a cancel can lose ctx's error on goose's *sql.Conn:
// pgx's stdlib driver turns a context-already-done error that is safe to
// retry into a bare driver.ErrBadConn.
func withCtxErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
		return fmt.Errorf("%w (%w)", cerr, err)
	}
	return err
}
