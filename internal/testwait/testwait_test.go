package testwait

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTB records Fatalf instead of ending the goroutine and has a fixed
// deadline.
type fakeTB struct {
	testing.TB
	deadline time.Time
	failed   string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatalf(format string, args ...any) { f.failed = fmt.Sprintf(format, args...) }

func (f *fakeTB) Deadline() (time.Time, bool) { return f.deadline, !f.deadline.IsZero() }

func TestNotifyWakesWaiters(t *testing.T) {
	var sig Signal
	sig.Notify() // nobody waits: nothing to wake
	var ready atomic.Bool
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() { Until(t, &sig, "ready", ready.Load) })
	}
	ready.Store(true)
	sig.Notify()
	wg.Wait()
}

func TestNotifyClosesOnlyTakenChannels(t *testing.T) {
	var sig Signal
	before := sig.C()
	sig.Notify()
	select {
	case <-before:
	default:
		t.Fatal("Notify did not close the channel taken before it")
	}
	select {
	case <-sig.C():
		t.Fatal("a channel taken after Notify is closed")
	default:
	}
}

// A change and its Notify between the check and the wait are not lost:
// cond itself makes the change after its check and notifies.
func TestNoLostWakeup(t *testing.T) {
	var sig Signal
	calls, changed := 0, false
	Until(t, &sig, "the change", func() bool {
		calls++
		ok := changed
		if !ok {
			changed = true
			sig.Notify()
		}
		return ok
	})
	if calls != 2 {
		t.Errorf("cond ran %d times, want 2", calls)
	}
}

func TestUntilFailsBeforeDeadline(t *testing.T) {
	var sig Signal
	tb := &fakeTB{TB: t, deadline: time.Now().Add(-time.Second)} // already over: no wait
	Until(tb, &sig, "nothing", func() bool { return false })
	if tb.failed != "timed out waiting for nothing" {
		t.Errorf("failure %q", tb.failed)
	}
}

func TestLimit(t *testing.T) {
	near := func(got, want time.Duration) bool { return got <= want && got > want-time.Second }
	if got := Limit(&fakeTB{TB: t}); got != noDeadline {
		t.Errorf("no deadline: %v, want %v", got, noDeadline)
	}
	if got := Limit(&fakeTB{TB: t, deadline: time.Now().Add(time.Minute)}); !near(got, time.Minute-margin) {
		t.Errorf("a minute left: %v, want %v", got, time.Minute-margin)
	}
	// Far from the deadline: a minute at most.
	if got := Limit(&fakeTB{TB: t, deadline: time.Now().Add(time.Hour)}); got != maxWait {
		t.Errorf("an hour left: %v, want %v", got, maxWait)
	}
	// Close to the deadline: half of what is left.
	if got := Limit(&fakeTB{TB: t, deadline: time.Now().Add(4 * time.Second)}); !near(got, 2*time.Second) {
		t.Errorf("4 s left: %v, want 2 s", got)
	}
}
