package storetest

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/keepia/mail/internal/testwait"
)

// fakeTB records Fatal and Skip and then ends its goroutine with
// runtime.Goexit, as the real ones do.
type fakeTB struct {
	testing.TB
	fatal, skip string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatal(args ...any) { f.fatal = fmt.Sprint(args...); runtime.Goexit() }

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (f *fakeTB) Skip(args ...any) { f.skip = fmt.Sprint(args...); runtime.Goexit() }

func (f *fakeTB) Skipf(format string, args ...any) {
	f.skip = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// runNewUnmigrated runs NewUnmigrated with a fake TB in a goroutine of its
// own, so that Goexit ends only that goroutine.
func runNewUnmigrated(t *testing.T) *fakeTB {
	t.Helper()
	f := &fakeTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewUnmigrated(f)
	}()
	select {
	case <-done:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("NewUnmigrated did not return")
	}
	return f
}

// In CI without TEST_DATABASE_URL the database tests fail, so a CI run
// cannot pass with all of them skipped; outside CI they are skipped.
func TestNewUnmigratedWithoutURL(t *testing.T) {
	t.Setenv(EnvURL, "")

	t.Setenv("CI", "true")
	if f := runNewUnmigrated(t); f.fatal == "" || f.skip != "" {
		t.Errorf("CI set: fatal %q, skip %q; want a failure", f.fatal, f.skip)
	}

	t.Setenv("CI", "")
	if f := runNewUnmigrated(t); f.skip == "" || f.fatal != "" {
		t.Errorf("CI empty: fatal %q, skip %q; want a skip", f.fatal, f.skip)
	}
}
