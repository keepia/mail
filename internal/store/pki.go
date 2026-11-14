package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/keepia/mail/internal/store/db"
)

// CRLChannel is the PostgreSQL notification channel of a committed list
// reissue (#96, CD34): every Reissue sends NOTIFY keepia_crl in its own
// transaction, so a listener hears of it only after the commit.
const CRLChannel = "keepia_crl"

// PKITx is one READ COMMITTED transaction of #96 part 2 (internal/pki and
// internal/join), with the store's lock timeout (30 s by default). Every
// statement after a lock gets a fresh snapshot, so it sees what the
// previous holder of that lock committed (CD36, X3). Its methods take the
// locks of the global order in locks.go: the servers row, then the CRL
// lock, then certificate and token rows.
type PKITx struct {
	q *db.Queries
}

// PKIWrite runs fn in one READ COMMITTED transaction (X3: explicitly, not
// the server's default isolation), and adds one audit_log row for action
// with fn's object and details in the same transaction (as every write of
// the data model's API does). Errors are mapped as the store's writes
// are: a refused write wraps ErrRefused, ErrExists or ErrNotFound, a lock
// wait past the timeout ErrLockTimeout.
func (s *Store) PKIWrite(ctx context.Context, action string, fn func(ctx context.Context, tx *PKITx) (object string, details map[string]any, err error)) error {
	return s.write(ctx, action, func(ctx context.Context, q *db.Queries) (audit, error) {
		object, details, err := fn(ctx, &PKITx{q: q})
		return audit{object: object, details: details}, err
	})
}

// PKITransaction is PKIWrite without an audit row: for the revocation
// lists' reissue, which runs at every generation and at least daily.
func (s *Store) PKITransaction(ctx context.Context, fn func(ctx context.Context, tx *PKITx) error) error {
	tx, err := s.pool.BeginTx(ctx, readCommitted)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() // a no-op after the commit
	q := db.New(tx)
	if err := q.SetLockTimeout(ctx, pgDuration(s.lockTimeout)); err != nil {
		return mapError(err)
	}
	if err := fn(ctx, &PKITx{q: q}); err != nil {
		return mapError(err)
	}
	return mapError(tx.Commit(ctx))
}

// LockServer reads the server name and locks its row: FOR UPDATE when
// forUpdate (server remove, a redeem), FOR SHARE otherwise (an
// issuance). A missing server wraps ErrNotFound.
func (t *PKITx) LockServer(ctx context.Context, name string, forUpdate bool) (Server, error) {
	var (
		row db.Server
		err error
	)
	if forUpdate {
		row, err = t.q.LockServerForUpdate(ctx, name)
	} else {
		row, err = t.q.LockServerForShare(ctx, name)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return Server{}, notFound("server", name)
	}
	if err != nil {
		return Server{}, err
	}
	return server(row), nil
}

// LockServerID is LockServer FOR UPDATE by id.
func (t *PKITx) LockServerID(ctx context.Context, id int64) (Server, error) {
	row, err := t.q.LockServerByIDForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Server{}, fmt.Errorf("server %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return Server{}, err
	}
	return server(row), nil
}

// InsertServer adds the server name with roles, not joined.
func (t *PKITx) InsertServer(ctx context.Context, name string, roles []string) (Server, error) {
	row, err := t.q.InsertServer(ctx, db.InsertServerParams{Name: name, Roles: roles})
	if err != nil {
		return Server{}, err
	}
	return server(row), nil
}

// LockCRL takes the CRL lock (LockClassCRL, 0) until the transaction
// ends (CD36). An advisory lock also covers the first insert into an
// empty anchor_crls, which a row lock cannot.
func (t *PKITx) LockCRL(ctx context.Context) error {
	return t.q.AdvisoryXactLock(ctx, db.AdvisoryXactLockParams{Class: LockClassCRL, Key: 0})
}

// CountServerMailboxes counts the mailboxes on the stores of the server.
func (t *PKITx) CountServerMailboxes(ctx context.Context, serverID int64) (int64, error) {
	return t.q.CountServerMailboxes(ctx, serverID)
}

// SetServerRemoved sets the server's removed_at.
func (t *PKITx) SetServerRemoved(ctx context.Context, serverID int64, at time.Time) error {
	return t.q.SetServerRemoved(ctx, db.SetServerRemovedParams{RemovedAt: tstz(at), ID: serverID})
}

// SetServerJoined sets the server's joined_at.
func (t *PKITx) SetServerJoined(ctx context.Context, serverID int64, at time.Time) error {
	return t.q.SetServerJoined(ctx, db.SetServerJoinedParams{JoinedAt: tstz(at), ID: serverID})
}

// CertificateRow is one issued certificate. ServerID is 0 only for the
// control gate's certificate (purpose control-gate, CD34); DNSName is ""
// for a client certificate.
type CertificateRow struct {
	Serial     []byte
	Anchor     string
	ServerID   int64
	Purpose    string
	DNSName    string
	SPKISHA256 []byte
	NotBefore  time.Time
	NotAfter   time.Time
	DER        []byte
}

// InsertCertificate records an issued certificate.
func (t *PKITx) InsertCertificate(ctx context.Context, c CertificateRow) error {
	p := db.InsertCertificateParams{
		Serial: c.Serial, Anchor: c.Anchor, Purpose: c.Purpose, SpkiSha256: c.SPKISHA256,
		NotBefore: tstz(c.NotBefore), NotAfter: tstz(c.NotAfter), Der: c.DER,
	}
	if c.ServerID != 0 {
		p.ServerID = ptr(c.ServerID)
	}
	if c.DNSName != "" {
		p.DnsName = ptr(c.DNSName)
	}
	return t.q.InsertCertificate(ctx, p)
}

// RevokeServerCertificates revokes every unrevoked certificate of the
// server at at with reason, and returns their serials.
func (t *PKITx) RevokeServerCertificates(ctx context.Context, serverID int64, at time.Time, reason int16) ([][]byte, error) {
	return t.q.RevokeServerCertificates(ctx, db.RevokeServerCertificatesParams{RevokedAt: tstz(at), Reason: reason, ServerID: ptr(serverID)})
}

// RevokedRow is a revoked certificate of an anchor that has not expired.
type RevokedRow struct {
	Serial    []byte
	RevokedAt time.Time
	Reason    int16
	NotAfter  time.Time
}

// RevokedCertificates lists the anchor's revoked certificates that have
// not expired at now, by serial.
func (t *PKITx) RevokedCertificates(ctx context.Context, anchor string, now time.Time) ([]RevokedRow, error) {
	rows, err := t.q.RevokedCertificates(ctx, db.RevokedCertificatesParams{Anchor: anchor, Now: tstz(now)})
	if err != nil {
		return nil, err
	}
	out := make([]RevokedRow, 0, len(rows))
	for _, r := range rows {
		var reason int16
		if r.RevocationReason != nil {
			reason = *r.RevocationReason
		}
		out = append(out, RevokedRow{Serial: r.Serial, RevokedAt: r.RevokedAt.Time, Reason: reason, NotAfter: r.NotAfter.Time})
	}
	return out, nil
}

// CRLRow is the newest revocation list of an anchor.
type CRLRow struct {
	Anchor     string
	Number     int64
	ThisUpdate time.Time
	NextUpdate time.Time
	DER        []byte
}

func crlRows(rows []db.AnchorCrl) []CRLRow {
	out := make([]CRLRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, CRLRow{Anchor: r.Anchor, Number: r.Number, ThisUpdate: r.ThisUpdate.Time, NextUpdate: r.NextUpdate.Time, DER: r.Der})
	}
	return out
}

// CRLs reads the newest list of every anchor, by anchor name.
func (t *PKITx) CRLs(ctx context.Context) ([]CRLRow, error) {
	rows, err := t.q.ListCRLs(ctx)
	if err != nil {
		return nil, err
	}
	return crlRows(rows), nil
}

// UpsertCRL stores the anchor's newest list.
func (t *PKITx) UpsertCRL(ctx context.Context, c CRLRow) error {
	return t.q.UpsertCRL(ctx, db.UpsertCRLParams{
		Anchor: c.Anchor, Number: c.Number, ThisUpdate: tstz(c.ThisUpdate), NextUpdate: tstz(c.NextUpdate), Der: c.DER,
	})
}

// NotifyCRL sends NOTIFY keepia_crl, delivered when the transaction
// commits.
func (t *PKITx) NotifyCRL(ctx context.Context) error { return t.q.NotifyCRL(ctx) }

// JoinTokenRow is a join token as stored: never the token, only the
// SHA-256 of its secret.
type JoinTokenRow struct {
	ID            []byte
	ServerID      int64
	SecretSHA256  []byte
	CreatedAt     time.Time
	ExpiresAt     time.Time
	UsedAt        *time.Time
	InvalidatedAt *time.Time
}

// InsertJoinToken stores a new token.
func (t *PKITx) InsertJoinToken(ctx context.Context, j JoinTokenRow) error {
	return t.q.InsertJoinToken(ctx, db.InsertJoinTokenParams{
		ID: j.ID, ServerID: j.ServerID, SecretSha256: j.SecretSHA256, CreatedAt: tstz(j.CreatedAt), ExpiresAt: tstz(j.ExpiresAt),
	})
}

// InvalidateServerTokens invalidates every unused, valid token of the
// server at at, and returns how many.
func (t *PKITx) InvalidateServerTokens(ctx context.Context, serverID int64, at time.Time) (int64, error) {
	return t.q.InvalidateServerTokens(ctx, db.InvalidateServerTokensParams{InvalidatedAt: tstz(at), ServerID: serverID})
}

// JoinTokenServer returns the server id of the token id, without a lock;
// a missing token wraps ErrNotFound.
func (t *PKITx) JoinTokenServer(ctx context.Context, id []byte) (int64, error) {
	sid, err := t.q.JoinTokenServer(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("join token: %w", ErrNotFound)
	}
	return sid, err
}

// LockJoinToken reads the token id FOR UPDATE; a missing token wraps
// ErrNotFound.
func (t *PKITx) LockJoinToken(ctx context.Context, id []byte) (JoinTokenRow, error) {
	r, err := t.q.LockJoinToken(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return JoinTokenRow{}, fmt.Errorf("join token: %w", ErrNotFound)
	}
	if err != nil {
		return JoinTokenRow{}, err
	}
	return JoinTokenRow{
		ID: r.ID, ServerID: r.ServerID, SecretSHA256: r.SecretSha256, CreatedAt: r.CreatedAt.Time, ExpiresAt: r.ExpiresAt.Time,
		UsedAt: optionalTime(r.UsedAt), InvalidatedAt: optionalTime(r.InvalidatedAt),
	}, nil
}

// MarkJoinTokenUsed sets the token's used_at.
func (t *PKITx) MarkJoinTokenUsed(ctx context.Context, id []byte, at time.Time) error {
	return t.q.MarkJoinTokenUsed(ctx, db.MarkJoinTokenUsedParams{UsedAt: tstz(at), ID: id})
}

// ListCRLs reads the newest list of every anchor, outside a transaction
// (the gate writer's reconcile, a redeem's response).
func (s *Store) ListCRLs(ctx context.Context) ([]CRLRow, error) {
	rows, err := db.New(s.pool).ListCRLs(ctx)
	if err != nil {
		return nil, err
	}
	return crlRows(rows), nil
}

// AgentCertificateExpiries maps each server id to the expiry of its
// newest unrevoked agent certificate.
func (s *Store) AgentCertificateExpiries(ctx context.Context) (map[int64]time.Time, error) {
	rows, err := db.New(s.pool).AgentCertificateExpiries(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]time.Time, len(rows))
	for _, r := range rows {
		out[r.ServerID] = r.NotAfter.Time
	}
	return out, nil
}

// CRLListener is a dedicated connection, held outside the pool, that
// LISTENs on CRLChannel (C11): a notification lost while it is down is
// not queued by PostgreSQL, so its user reconciles after every
// (re)connect.
type CRLListener struct {
	conn *pgx.Conn
}

// ListenCRL takes a connection out of the pool and LISTENs on it.
func (s *Store) ListenCRL(ctx context.Context) (*CRLListener, error) {
	pc, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect for LISTEN %s: %w", CRLChannel, err)
	}
	conn := pc.Hijack()
	if _, err := conn.Exec(ctx, "LISTEN "+CRLChannel); err != nil {
		_ = conn.Close(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("LISTEN %s: %w", CRLChannel, err)
	}
	return &CRLListener{conn: conn}, nil
}

// PID is the listening backend's process id.
func (l *CRLListener) PID() uint32 { return l.conn.PgConn().PID() }

// Wait returns at the next notification, or with an error when ctx ends
// or the connection breaks.
func (l *CRLListener) Wait(ctx context.Context) error {
	_, err := l.conn.WaitForNotification(ctx)
	return err
}

// Close closes the connection.
func (l *CRLListener) Close(ctx context.Context) { _ = l.conn.Close(context.WithoutCancel(ctx)) }

func tstz(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
