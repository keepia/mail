package gate

import "time"

// Clock is the gate's time: every expiry (lists, leaves, retries, the
// handshake and dial bounds) goes through it, so tests drive it with a
// fake clock instead of waiting.
type Clock interface {
	Now() time.Time
	// AfterFunc calls f in its own goroutine once d has passed.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a pending AfterFunc.
type Timer interface {
	// Stop cancels the call; false if it has already run or was stopped.
	Stop() bool
}

// SystemClock is the real time.
type SystemClock struct{}

// Now is time.Now.
func (SystemClock) Now() time.Time { return time.Now() }

// AfterFunc is time.AfterFunc.
func (SystemClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }
