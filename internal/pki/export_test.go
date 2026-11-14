package pki

import (
	"context"
	"math/big"
)

// Hooks are the test seams of Reissue and RevokeServer (crlissuer.go).
type Hooks struct {
	// AfterRead runs after the numbers and revoked sets are read, while
	// the CRL lock is held.
	AfterRead func()
	// FailReissue makes the reissue step fail when it returns an error.
	FailReissue func() error
	// Signed sees every list as it is signed.
	Signed func(name AnchorName, number int64, serials []*big.Int)
	// AfterMailboxCount runs in RevokeServer right after its mailbox
	// count, with the server row and the CRL lock held.
	AfterMailboxCount func()
}

// WithHooks returns ctx with h for Reissue and RevokeServer.
func WithHooks(ctx context.Context, h Hooks) context.Context {
	return context.WithValue(ctx, hooksKey{}, &hooks{
		afterRead: h.AfterRead, failReissue: h.FailReissue, signed: h.Signed, afterMailboxCount: h.AfterMailboxCount,
	})
}
