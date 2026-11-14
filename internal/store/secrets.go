package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// KeyringRow is the single row of secret_keyring.
type KeyringRow struct {
	KEKID        []byte
	DeploymentID []byte
	CreatedAt    time.Time
	// LastExportAt is nil until the first `secrets export`.
	LastExportAt *time.Time
}

// SecretRow is one row of control_secrets: a sealed secret. Sealed is
// ciphertext only; Public is the secret's public part (a certificate or a
// public key in DER), nil for a secret without one.
type SecretRow struct {
	Name    string
	Version int
	Public  []byte
	KEKID   []byte
	Sealed  []byte
}

// SecretsSession is a connection of its own that holds the bootstrap lock
// (LockClassBootstrap) as a session lock, exclusive or shared, until Close.
// It is taken out of the store's pool, so the lock lives exactly as long as
// the session: Close unlocks and closes the connection, and a process that
// dies loses the lock with its connection.
type SecretsSession struct {
	conn *pgx.Conn
}

// LockSecrets opens a SecretsSession: a dedicated connection that takes
// the bootstrap lock, exclusively (serve's bootstrap) or shared (commands
// that only read the secrets), waiting at most lockTimeout. When the wait
// runs out, the error wraps ErrLockTimeout.
func (s *Store) LockSecrets(ctx context.Context, exclusive bool, lockTimeout time.Duration) (*SecretsSession, error) {
	pc, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect for the bootstrap lock: %w", err)
	}
	conn := pc.Hijack()
	fail := func(err error) (*SecretsSession, error) {
		_ = conn.Close(context.WithoutCancel(ctx))
		return nil, err
	}
	ms := lockTimeout.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	if _, err := conn.Exec(ctx, "SELECT set_config('lock_timeout', $1, false)", fmt.Sprintf("%dms", ms)); err != nil {
		return fail(fmt.Errorf("set lock_timeout: %w", err))
	}
	fn := "pg_advisory_lock_shared"
	if exclusive {
		fn = "pg_advisory_lock"
	}
	if _, err := conn.Exec(ctx, "SELECT "+fn+"($1, 0)", LockClassBootstrap); err != nil {
		return fail(fmt.Errorf("take the bootstrap lock (PostgreSQL advisory lock %d, 0): %w", LockClassBootstrap, lockTimeoutErr(err)))
	}
	// The statements under the lock run without a lock timeout of their
	// own.
	if _, err := conn.Exec(ctx, "SELECT set_config('lock_timeout', '0', false)"); err != nil {
		return fail(fmt.Errorf("reset lock_timeout: %w", err))
	}
	return &SecretsSession{conn: conn}, nil
}

// Close releases the bootstrap lock and closes the session's connection.
// The lock is released by the close even when the unlock fails.
func (ss *SecretsSession) Close(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	_, _ = ss.conn.Exec(ctx, "SELECT pg_advisory_unlock_all()")
	_ = ss.conn.Close(ctx)
}

// Keyring returns the keyring row, or nil when there is none (no secrets
// yet).
func (ss *SecretsSession) Keyring(ctx context.Context) (*KeyringRow, error) {
	var k KeyringRow
	err := ss.conn.QueryRow(ctx,
		`SELECT kek_id, deployment_id, created_at, last_export_at FROM secret_keyring`).
		Scan(&k.KEKID, &k.DeploymentID, &k.CreatedAt, &k.LastExportAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the keyring: %w", err)
	}
	return &k, nil
}

// Secrets returns the newest version of every sealed secret, by name.
func (ss *SecretsSession) Secrets(ctx context.Context) ([]SecretRow, error) {
	rows, err := ss.conn.Query(ctx,
		`SELECT DISTINCT ON (name) name, version, public, kek_id, sealed
		   FROM control_secrets ORDER BY name, version DESC`)
	if err != nil {
		return nil, fmt.Errorf("read the control secrets: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (SecretRow, error) {
		var s SecretRow
		err := r.Scan(&s.Name, &s.Version, &s.Public, &s.KEKID, &s.Sealed)
		return s, err
	})
	if err != nil {
		return nil, fmt.Errorf("read the control secrets: %w", err)
	}
	return out, nil
}

// CreateSecrets inserts the keyring row and the sealed secrets in one
// transaction. beforeCommit, when not nil, runs inside the transaction
// right before the commit; its error rolls everything back (a test seam
// for a crash before the commit).
func (ss *SecretsSession) CreateSecrets(ctx context.Context, k KeyringRow, secrets []SecretRow, beforeCommit func() error) error {
	tx, err := ss.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx,
		`INSERT INTO secret_keyring (kek_id, deployment_id) VALUES ($1, $2)`,
		k.KEKID, k.DeploymentID); err != nil {
		return fmt.Errorf("insert the keyring: %w", err)
	}
	for _, s := range secrets {
		if _, err := tx.Exec(ctx,
			`INSERT INTO control_secrets (name, version, public, kek_id, sealed) VALUES ($1, $2, $3, $4, $5)`,
			s.Name, s.Version, s.Public, s.KEKID, s.Sealed); err != nil {
			return fmt.Errorf("insert the control secret %s: %w", s.Name, err)
		}
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit the control secrets: %w", err)
	}
	return nil
}
