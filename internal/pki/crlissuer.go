package pki

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/keepia/mail/internal/store"
)

// ReissueAge is the age of the oldest current list at which
// ReissueIfDue reissues (C8): with hourly checks, no list is then older
// than 24 h.
const ReissueAge = 23 * time.Hour

// Reissue signs and stores a new list for each of the four anchors (CD16,
// CD36): at every generation (N4), after a revocation, and when a list is
// due (ReissueIfDue). It runs in one READ COMMITTED transaction:
//
//  1. SET LOCAL lock_timeout (the store's, 30 s by default);
//  2. the CRL lock (LockClassCRL, 0), before anything is read;
//  3. the numbers and the revoked, unexpired certificates of each anchor;
//  4. sign each list with number = old + 1 (1 for the first);
//  5. store them;
//  6. NOTIFY keepia_crl;
//  7. COMMIT.
//
// Step 3 starts after the lock is granted, so it sees every revocation
// the previous holder committed, and no two lists of an anchor ever share
// a number.
func Reissue(ctx context.Context, st *store.Store, a AnchorKeys, now time.Time) error {
	h := hooksFrom(ctx)
	return st.PKITransaction(ctx, func(ctx context.Context, tx *store.PKITx) error {
		if err := tx.LockCRL(ctx); err != nil {
			return err
		}
		return reissueLocked(ctx, tx, a, now, h)
	})
}

// reissueLocked is Reissue's steps 3-6, in a transaction that holds the
// CRL lock.
func reissueLocked(ctx context.Context, tx *store.PKITx, a AnchorKeys, now time.Time, h *hooks) error {
	rows, err := tx.CRLs(ctx)
	if err != nil {
		return err
	}
	numbers := map[string]int64{}
	for _, r := range rows {
		numbers[r.Anchor] = r.Number
	}
	revoked := map[AnchorName][]Revoked{}
	for _, name := range Anchors {
		rs, err := tx.RevokedCertificates(ctx, string(name), now)
		if err != nil {
			return err
		}
		for _, r := range rs {
			revoked[name] = append(revoked[name], Revoked{
				Serial: new(big.Int).SetBytes(r.Serial), RevokedAt: r.RevokedAt, Reason: int(r.Reason), NotAfter: r.NotAfter,
			})
		}
	}
	h.call(h.afterRead)
	if h.failReissue != nil {
		if err := h.failReissue(); err != nil {
			return err
		}
	}
	for _, name := range Anchors {
		anchor := a.Anchor(name)
		if anchor == nil {
			return fmt.Errorf("no anchor %s", name)
		}
		number := numbers[string(name)] + 1
		der, err := CreateCRL(anchor, number, revoked[name], now)
		if err != nil {
			return fmt.Errorf("sign the list of %s: %w", name, err)
		}
		this := now.UTC().Truncate(time.Second)
		if err := tx.UpsertCRL(ctx, store.CRLRow{Anchor: string(name), Number: number, ThisUpdate: this, NextUpdate: this.Add(CRLLifetime), DER: der}); err != nil {
			return err
		}
		if h.signed != nil {
			serials := make([]*big.Int, 0, len(revoked[name]))
			for _, r := range revoked[name] {
				if r.NotAfter.After(now) {
					serials = append(serials, r.Serial)
				}
			}
			h.signed(name, number, serials)
		}
	}
	return tx.NotifyCRL(ctx)
}

// ReissueIfDue reissues the lists (Reissue) when an anchor has none yet
// or the oldest current list is at least ReissueAge old at now, and
// tells whether it did. serve runs it at its start and at every hourly
// tick (CD16 with C8).
func ReissueIfDue(ctx context.Context, st *store.Store, a AnchorKeys, now time.Time) (bool, error) {
	rows, err := st.ListCRLs(ctx)
	if err != nil {
		return false, err
	}
	due := len(rows) < len(Anchors)
	for _, r := range rows {
		if !now.Before(r.ThisUpdate.Add(ReissueAge)) {
			due = true
		}
	}
	if !due {
		return false, nil
	}
	return true, Reissue(ctx, st, a, now)
}

// CurrentLists reads the stored list of each anchor (DER) and checks that
// all four exist.
func CurrentLists(ctx context.Context, st *store.Store) (map[AnchorName]store.CRLRow, error) {
	rows, err := st.ListCRLs(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[AnchorName]store.CRLRow, len(rows))
	for _, r := range rows {
		out[AnchorName(r.Anchor)] = r
	}
	for _, name := range Anchors {
		if _, ok := out[name]; !ok {
			return nil, fmt.Errorf("%w: no revocation list of %s yet", ErrNoLists, name)
		}
	}
	return out, nil
}

// ErrNoLists means the lists have not been issued yet (serve issues them
// at its start).
var ErrNoLists = errors.New("no revocation lists")

// hooks are test seams (export_test.go), carried in the context.
type hooks struct {
	// afterRead runs in Reissue and RevokeServer after step 3, while the
	// CRL lock is held (R4).
	afterRead func()
	// failReissue, when it returns an error, makes the reissue step fail
	// (I3: the revocation rolls back with its lists).
	failReissue func() error
	// signed sees every list as it is signed: anchor, number and serials.
	signed func(name AnchorName, number int64, serials []*big.Int)
	// afterMailboxCount runs in RevokeServer right after its mailbox
	// count, while it holds the server row and the CRL lock (C13).
	afterMailboxCount func()
}

type hooksKey struct{}

// hooksFrom returns ctx's hooks, or empty ones: never nil.
func hooksFrom(ctx context.Context) *hooks {
	if h, ok := ctx.Value(hooksKey{}).(*hooks); ok && h != nil {
		return h
	}
	return &hooks{}
}

func (h *hooks) call(f func()) {
	if f != nil {
		f()
	}
}
