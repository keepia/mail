package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
)

// withCtxErr keeps ctx's error once ctx has ended, also when goose's error
// lost it (a bare driver.ErrBadConn); otherwise it changes nothing.
func TestWithCtxErr(t *testing.T) {
	live := context.Background()
	ended, cancel := context.WithCancel(context.Background())
	cancel()

	if err := withCtxErr(ended, nil); err != nil {
		t.Errorf("nil after cancel: %v, want nil", err)
	}
	err := withCtxErr(ended, driver.ErrBadConn)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, driver.ErrBadConn) {
		t.Errorf("bad conn after cancel: %v, want both context.Canceled and driver.ErrBadConn", err)
	}
	wrapped := errors.Join(context.Canceled, errors.New("x"))
	if err := withCtxErr(ended, wrapped); err != wrapped { //nolint:errorlint // the same error value is the point
		t.Errorf("already wraps ctx's error: %v, want it unchanged", err)
	}
	if err := withCtxErr(live, driver.ErrBadConn); err != driver.ErrBadConn { //nolint:errorlint // the same error value is the point
		t.Errorf("live ctx: %v, want driver.ErrBadConn unchanged", err)
	}
}
