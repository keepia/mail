// Package join is a server's join (#96 part 2, CD20-CD24 with C5 and X1):
// the one-time join token, the commands that create it, control's redeem,
// and the agent's checks of the join listener.
package join

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/store"
)

// TokenPrefix starts every join token (CD20).
const TokenPrefix = "keepia-join-v1." //nolint:gosec // G101: the token's fixed prefix, not a credential

// Token is a join token: a 16-byte id, a 32-byte secret, and the pin, the
// SHA-256 of the service anchor's SubjectPublicKeyInfo (CD31). Control
// stores only the id and the SHA-256 of the secret.
type Token struct {
	ID     [16]byte
	Secret [32]byte
	Pin    [32]byte
}

// tokenBytes is the length of a token's binary form.
const tokenBytes = 16 + 32 + 32

// String is the token: keepia-join-v1. and base64url without padding of
// id ‖ secret ‖ pin, 107 characters after the prefix. It is printed once
// and never logged.
func (t Token) String() string {
	b := make([]byte, 0, tokenBytes)
	b = append(b, t.ID[:]...)
	b = append(b, t.Secret[:]...)
	b = append(b, t.Pin[:]...)
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ErrMalformedToken is ParseToken's one error, whatever is wrong (J9).
var ErrMalformedToken = errors.New("malformed join token")

// ParseToken parses a join token. A wrong prefix or version, length or
// encoding gives ErrMalformedToken and nothing else.
func ParseToken(s string) (Token, error) {
	rest, ok := strings.CutPrefix(s, TokenPrefix)
	if !ok || len(rest) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return Token{}, ErrMalformedToken
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(rest)
	if err != nil || len(b) != tokenBytes {
		return Token{}, ErrMalformedToken
	}
	var t Token
	copy(t.ID[:], b[:16])
	copy(t.Secret[:], b[16:48])
	copy(t.Pin[:], b[48:])
	return t, nil
}

// Pin is the SHA-256 of a certificate's SubjectPublicKeyInfo: the token's
// pin of the service anchor (CD31). A re-issued anchor certificate with
// the same key keeps the pin.
func Pin(c *x509.Certificate) [32]byte { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// pinMatches compares a certificate's pin with pin in constant time.
func pinMatches(c *x509.Certificate, pin [32]byte) bool {
	p := Pin(c)
	return subtle.ConstantTimeCompare(p[:], pin[:]) == 1
}

// Token lifetimes (CD21).
const (
	DefaultTTL = time.Hour
	MinTTL     = 5 * time.Minute
	MaxTTL     = 24 * time.Hour
)

// ErrTTL refuses a lifetime outside 5 min to 24 h.
var ErrTTL = errors.New("the token lifetime must be from 5m to 24h")

// ErrServerSpec is wrapped by the refusals of a server's name or roles.
var ErrServerSpec = errors.New("invalid server")

// CheckServerSpec checks a new server's name and roles (CD14, CD23): a
// lowercase DNS label of 1-63 characters, and at least one of control,
// edge, store, filter and groupware, each once.
func CheckServerSpec(name string, roles []string) error {
	if !pki.ValidServerName(name) {
		return fmt.Errorf("%w: the name %q must be a lowercase DNS label of 1-63 characters from a-z, 0-9 and -, without a hyphen at either end", ErrServerSpec, name)
	}
	if len(roles) == 0 {
		return fmt.Errorf("%w: at least one role (%s)", ErrServerSpec, strings.Join(pki.Roles, ", "))
	}
	for i, r := range roles {
		if !slices.Contains(pki.Roles, r) {
			return fmt.Errorf("%w: unknown role %q (want %s)", ErrServerSpec, r, strings.Join(pki.Roles, ", "))
		}
		if slices.Contains(roles[:i], r) {
			return fmt.Errorf("%w: the role %s appears twice", ErrServerSpec, r)
		}
	}
	return nil
}

func checkTTL(ttl time.Duration) error {
	if ttl < MinTTL || ttl > MaxTTL {
		return fmt.Errorf("%w (got %s)", ErrTTL, ttl)
	}
	return nil
}

// newToken draws an id and a secret for the pin.
func newToken(pin [32]byte) (Token, error) {
	t := Token{Pin: pin}
	if _, err := rand.Read(t.ID[:]); err != nil {
		return Token{}, err
	}
	if _, err := rand.Read(t.Secret[:]); err != nil {
		return Token{}, err
	}
	return t, nil
}

func insertToken(ctx context.Context, tx *store.PKITx, serverID int64, t Token, now time.Time, ttl time.Duration) error {
	h := sha256.Sum256(t.Secret[:])
	return tx.InsertJoinToken(ctx, store.JoinTokenRow{
		ID: t.ID[:], ServerID: serverID, SecretSHA256: h[:], CreatedAt: now, ExpiresAt: now.Add(ttl),
	})
}

// AddServer is `server add` (CD23): it adds the server name with roles,
// not joined, and a token valid for ttl, in one transaction, and returns
// the token. serviceAnchor is the keyring's service anchor, whose pin the
// token carries.
func AddServer(ctx context.Context, st *store.Store, serviceAnchor *x509.Certificate, name string, roles []string, ttl time.Duration, now time.Time) (Token, error) {
	if err := CheckServerSpec(name, roles); err != nil {
		return Token{}, err
	}
	if err := checkTTL(ttl); err != nil {
		return Token{}, err
	}
	t, err := newToken(Pin(serviceAnchor))
	if err != nil {
		return Token{}, err
	}
	err = st.PKIWrite(ctx, "server.add", func(ctx context.Context, tx *store.PKITx) (string, map[string]any, error) {
		sv, err := tx.InsertServer(ctx, name, roles)
		if err != nil {
			return "", nil, err
		}
		if err := insertToken(ctx, tx, sv.ID, t, now, ttl); err != nil {
			return "", nil, err
		}
		return name, map[string]any{"roles": roles, "token_expires": now.Add(ttl).UTC().Format(time.RFC3339)}, nil
	})
	if err != nil {
		return Token{}, err
	}
	return t, nil
}

// Refusals of NewToken.
var (
	// ErrAlreadyJoined: `server token` works only before the first join
	// (a rejoin is a follow-up of #96).
	ErrAlreadyJoined = errors.New("the server has already joined")
	// ErrRemoved: the server was removed.
	ErrRemoved = errors.New("the server was removed")
)

// NewToken is `server token` (CD21, CD23): a new token for a server that
// has not joined and was not removed. It locks the server row, then
// invalidates the server's older unused tokens, then stores the new one.
func NewToken(ctx context.Context, st *store.Store, serviceAnchor *x509.Certificate, name string, ttl time.Duration, now time.Time) (Token, error) {
	if err := checkTTL(ttl); err != nil {
		return Token{}, err
	}
	t, err := newToken(Pin(serviceAnchor))
	if err != nil {
		return Token{}, err
	}
	err = st.PKIWrite(ctx, "server.token", func(ctx context.Context, tx *store.PKITx) (string, map[string]any, error) {
		sv, err := tx.LockServer(ctx, name, true)
		if err != nil {
			return "", nil, err
		}
		switch {
		case sv.RemovedAt != nil:
			return "", nil, fmt.Errorf("server %s: %w", name, ErrRemoved)
		case sv.JoinedAt != nil:
			return "", nil, fmt.Errorf("server %s: %w", name, ErrAlreadyJoined)
		}
		n, err := tx.InvalidateServerTokens(ctx, sv.ID, now)
		if err != nil {
			return "", nil, err
		}
		if err := insertToken(ctx, tx, sv.ID, t, now, ttl); err != nil {
			return "", nil, err
		}
		return name, map[string]any{"invalidated_tokens": n, "token_expires": now.Add(ttl).UTC().Format(time.RFC3339)}, nil
	})
	if err != nil {
		return Token{}, err
	}
	return t, nil
}
