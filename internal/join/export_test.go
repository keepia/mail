package join

import "context"

// Hooks are Redeem's test seams.
type Hooks struct {
	// AfterServerLock runs between the server and the token row locks.
	AfterServerLock func()
	// AfterLock runs once both rows are locked.
	AfterLock func()
}

// RandomToken is newToken: a token with a random id and secret for pin.
func RandomToken(pin [32]byte) (Token, error) { return newToken(pin) }

// WithHooks returns ctx with h for Redeem.
func WithHooks(ctx context.Context, h Hooks) context.Context {
	return context.WithValue(ctx, hooksKey{}, &hooks{afterServerLock: h.AfterServerLock, afterLock: h.AfterLock})
}
