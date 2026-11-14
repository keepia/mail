package join

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/store"
)

// ErrRefused is wrapped by every refusal of a redeem. The reasons below
// are for control's log; N4's handler answers the agent with one fixed
// refusal.
var ErrRefused = errors.New("join refused")

// Reasons of a refused redeem.
var (
	// ErrUnknownToken: no such token, or a wrong secret. The two are not
	// told apart, and a wrong secret does not consume the token.
	ErrUnknownToken = errors.New("unknown token or wrong secret")
	ErrTokenUsed    = errors.New("the token was already used")
	// ErrTokenInvalidated: a newer token or a removal invalidated it.
	ErrTokenInvalidated = errors.New("the token was invalidated")
	ErrTokenExpired     = errors.New("the token has expired")
)

// Response is what a redeem returns to the agent (CD22): its agent
// certificate, the service anchor and the current service list, each in
// DER.
type Response struct {
	AgentCert     []byte
	ServiceAnchor []byte
	ServiceCRL    []byte
}

// Redeem is control's side of a join (CD21, X1). It takes only the
// public key of the CSR (CD15), then runs one READ COMMITTED
// transaction:
//
//  1. the token's server id, read without a lock (it never changes);
//  2. the servers row FOR UPDATE, before the token row, the same order as
//     `server remove` (X1), so the two never deadlock;
//  3. the token row FOR UPDATE, which serializes redeems of one token;
//  4. the token must be unused, valid and unexpired at now, and its server
//     neither removed nor joined;
//  5. the secret's SHA-256 is compared in constant time; a wrong secret
//     rolls back and leaves the token as it was;
//  6. used_at is set, the agent certificate issued, joined_at set.
//
// Every refusal wraps ErrRefused and one reason.
func Redeem(ctx context.Context, st *store.Store, a pki.AnchorKeys, t Token, csrDER []byte, now time.Time) (*Response, error) {
	pub, err := pki.CSRPublicKey(csrDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	h := hooksFrom(ctx)
	var resp Response
	err = st.PKIWrite(ctx, "server.join", func(ctx context.Context, tx *store.PKITx) (string, map[string]any, error) {
		sid, err := tx.JoinTokenServer(ctx, t.ID[:])
		if errors.Is(err, store.ErrNotFound) {
			return "", nil, fmt.Errorf("%w: %w", ErrRefused, ErrUnknownToken)
		}
		if err != nil {
			return "", nil, err
		}
		sv, err := tx.LockServerID(ctx, sid)
		if err != nil {
			return "", nil, err
		}
		if h.afterServerLock != nil {
			h.afterServerLock()
		}
		row, err := tx.LockJoinToken(ctx, t.ID[:])
		if err != nil {
			return "", nil, err
		}
		if h.afterLock != nil {
			h.afterLock()
		}
		switch {
		case row.UsedAt != nil:
			return "", nil, fmt.Errorf("%w: %w", ErrRefused, ErrTokenUsed)
		case row.InvalidatedAt != nil:
			return "", nil, fmt.Errorf("%w: %w", ErrRefused, ErrTokenInvalidated)
		case !now.Before(row.ExpiresAt):
			return "", nil, fmt.Errorf("%w: %w", ErrRefused, ErrTokenExpired)
		case sv.RemovedAt != nil:
			return "", nil, fmt.Errorf("%w: %w", ErrRefused, ErrRemoved)
		case sv.JoinedAt != nil:
			return "", nil, fmt.Errorf("%w: %w", ErrRefused, ErrAlreadyJoined)
		}
		got := sha256.Sum256(t.Secret[:])
		if subtle.ConstantTimeCompare(got[:], row.SecretSHA256) != 1 {
			return "", nil, fmt.Errorf("%w: %w", ErrRefused, ErrUnknownToken)
		}
		if h.beforeConsume != nil {
			h.beforeConsume()
		}
		if err := tx.MarkJoinTokenUsed(ctx, t.ID[:], now); err != nil {
			return "", nil, err
		}
		cert, err := pki.IssueInTx(ctx, tx, a, sv, pki.PurposeAgent, "", pub, now)
		if err != nil {
			return "", nil, err
		}
		if err := tx.SetServerJoined(ctx, sv.ID, now); err != nil {
			return "", nil, err
		}
		lists, err := tx.CRLs(ctx)
		if err != nil {
			return "", nil, err
		}
		for _, l := range lists {
			if l.Anchor == string(pki.AnchorService) {
				resp.ServiceCRL = l.DER
			}
		}
		if resp.ServiceCRL == nil {
			return "", nil, pki.ErrNoLists
		}
		resp.AgentCert = cert.Raw
		resp.ServiceAnchor = a.Anchor(pki.AnchorService).Cert.Raw
		return sv.Name, map[string]any{"serial": fmt.Sprintf("%x", cert.SerialNumber)}, nil
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// hooks are test seams of Redeem (export_test.go), carried in the
// context.
type hooks struct {
	// afterServerLock runs between the server row lock and the token row
	// lock (X1).
	afterServerLock func()
	// afterLock runs once the server and token rows are locked.
	afterLock func()
	// beforeConsume runs after every check, right before used_at is set.
	beforeConsume func()
}

type hooksKey struct{}

func hooksFrom(ctx context.Context) *hooks {
	if h, ok := ctx.Value(hooksKey{}).(*hooks); ok && h != nil {
		return h
	}
	return &hooks{}
}
