//go:build linux

package gate

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/keepia/mail/internal/testwait"
)

// U12: a generation renamed into place is applied by the real inotify
// watcher.
func TestWatcherAppliesRename(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	h.provide(2, h.f.bundle(RoleStore, h.f.lists(RoleStore, 2, h.fc.Now())))
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	// A write in place (close after writing) counts as well.
	h.bundle.Store(h.f.bundle(RoleStore, h.f.lists(RoleStore, 3, h.fc.Now())))
	if err := os.WriteFile(filepath.Join(h.dir, GenerationFileName), []byte("3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.log.waitFor(t, `msg="applied generation 3"`, 1)
}

// U12 (N11): a generation written between setting up the watch and the
// first read is applied.
func TestWatcherWatchesBeforeTheFirstRead(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.bundle.Store(h.f.bundle(RoleStore, h.f.lists(RoleStore, 1, h.fc.Now())))
	h.writeGen(1)
	h.g.hooks.afterWatch = func() {
		h.bundle.Store(h.f.bundle(RoleStore, h.f.lists(RoleStore, 2, h.fc.Now())))
		h.writeGen(2)
	}
	h.start()
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
}

// fakeEvents is an event source of raw inotify_event records.
type fakeEvents struct {
	ch       chan []byte
	mu       sync.Mutex
	adds     int
	addErrAt int // the add that fails (0: none)
	sig      testwait.Signal
	closed   chan struct{}
	once     sync.Once
}

func newFakeEvents() *fakeEvents {
	return &fakeEvents{ch: make(chan []byte, 8), closed: make(chan struct{})}
}

func (f *fakeEvents) addWatch() error {
	f.mu.Lock()
	f.adds++
	n := f.adds
	f.mu.Unlock()
	f.sig.Notify()
	if f.addErrAt != 0 && n >= f.addErrAt {
		return syscall.ENOENT
	}
	return nil
}

func (f *fakeEvents) read(p []byte) (int, error) {
	select {
	case b := <-f.ch:
		return copy(p, b), nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}

func (f *fakeEvents) close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeEvents) addCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds
}

// record is one raw inotify_event.
func record(mask uint32, name string) []byte {
	n := 0
	if name != "" {
		n = (len(name) + 1 + 15) / 16 * 16
	}
	b := make([]byte, syscall.SizeofInotifyEvent+n)
	binary.NativeEndian.PutUint32(b[0:4], 1)
	binary.NativeEndian.PutUint32(b[4:8], mask)
	binary.NativeEndian.PutUint32(b[12:16], uint32(n))
	copy(b[syscall.SizeofInotifyEvent:], name)
	return b
}

// fakeHarness is a store gate on a fake event source with generation 1
// applied.
func fakeHarness(t *testing.T) (*harness, *fakeEvents) {
	t.Helper()
	h := newHarness(t, RoleStore)
	fe := newFakeEvents()
	h.g.hooks.events = func(string) (eventSource, error) { return fe, fe.addWatch() }
	h.startWith()
	return h, fe
}

// U13: a queue overflow means "read again": the generation written
// without an event of its own is applied.
func TestWatcherOverflowRereads(t *testing.T) {
	h, fe := fakeHarness(t)
	h.provide(2, h.f.bundle(RoleStore, h.f.lists(RoleStore, 2, h.fc.Now())))
	// Unrelated events read nothing.
	fe.ch <- append(record(syscall.IN_CLOSE_WRITE, "bundle.pem"), record(syscall.IN_MOVED_TO, ".generation.tmp")...)
	fe.ch <- record(syscall.IN_Q_OVERFLOW, "")
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	fe.ch <- record(syscall.IN_MOVED_TO, GenerationFileName)
	h.log.waitFor(t, `msg="generation 2 ignored: already applied"`, 1)
	if n := h.log.count(`msg="applied generation`); n != 2 {
		t.Errorf("%d applies, want 2", n)
	}
}

// U14: IN_IGNORED adds the watch again, then reads.
func TestWatcherIgnoredRewatches(t *testing.T) {
	h, fe := fakeHarness(t)
	h.provide(2, h.f.bundle(RoleStore, h.f.lists(RoleStore, 2, h.fc.Now())))
	fe.ch <- record(syscall.IN_IGNORED, "")
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	if fe.addCount() != 2 {
		t.Errorf("%d watch adds, want 2", fe.addCount())
	}
}

// U14: when the watch cannot be added again, Run ends with an error, so
// the container restarts (#45 rule 9).
func TestWatcherLostWatchExits(t *testing.T) {
	h, fe := fakeHarness(t)
	fe.addErrAt = 2
	fe.ch <- record(syscall.IN_DELETE_SELF, "")
	err := h.runErr()
	if err == nil || !strings.Contains(err.Error(), "the watch on") {
		t.Fatalf("Run: %v, want the lost watch", err)
	}
}

// U14 with the real inotify: removing the directory ends Run.
func TestWatcherDirectoryRemoved(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	if err := os.Remove(filepath.Join(h.dir, GenerationFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.dir); err != nil {
		t.Fatal(err)
	}
	if err := h.runErr(); err == nil {
		t.Fatal("Run went on without its watch")
	}
	// The gate stopped every listener on its way out.
	dialRefused(t, h.addr(h.mesh, PortIMAP))
}

// U14: an event stream that fails ends Run.
func TestWatcherReadErrorExits(t *testing.T) {
	h, fe := fakeHarness(t)
	fe.ch <- []byte{1, 2, 3}
	if err := h.runErr(); err == nil || !strings.Contains(err.Error(), "truncated inotify event") {
		t.Fatalf("Run: %v", err)
	}
}

// U15: #45's rules: an equal value is ignored and logged; any other valid
// value is applied, a lower one too; invalid material is retried at 1, 2,
// 4 … 30 s, and an event resets the delay.
func TestWatcherRules(t *testing.T) {
	h := newHarness(t, RoleStore)
	armed := make(chan time.Duration, 16)
	h.g.hooks.retryArmed = func(d time.Duration) { armed <- d }
	h.startWith()
	b := h.bundle.Load()
	h.writeGen(1)
	h.log.waitFor(t, `msg="generation 1 ignored: already applied"`, 1)
	h.provide(3, b)
	h.log.waitFor(t, `msg="applied generation 3"`, 1)
	h.provide(2, b)
	h.log.waitFor(t, `msg="applied generation 2"`, 1)

	next := func() time.Duration {
		t.Helper()
		select {
		case d := <-armed:
			return d
		case <-time.After(testwait.Limit(t)):
			t.Fatal("no retry was armed")
			return 0
		}
	}
	bad := errors.New("the bundle is incomplete")
	h.loadErr.Store(&bad)
	h.writeGen(5)
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i, w := range want {
		d := next()
		if d != w*time.Second {
			t.Fatalf("retry %d after %v, want %v", i+1, d, w*time.Second)
		}
		if got := h.fc.pending(retryMax); len(got) != 1 || got[0] != d {
			t.Fatalf("armed timers %v, want [%v]", got, d)
		}
		h.fc.Advance(d)
		h.log.waitFor(t, `msg="generation 5 refused: the bundle does not load: the bundle is incomplete"`, i+2)
	}
	// The refused generation keeps the old material: still healthy.
	code, body := h.g.Health()
	if code != 200 || body != "ready" {
		t.Fatalf("health %d %s", code, body)
	}
	// An event resets the delay.
	next()
	h.writeGen(5)
	if d := next(); d != time.Second {
		t.Fatalf("after an event the retry is armed at %v, want 1s", d)
	}
	h.loadErr.Store(nil)
	h.fc.Advance(time.Second)
	h.log.waitFor(t, `msg="applied generation 5"`, 1)
}

// N5: an invalid generation file is refused without its content and
// retried; the old material keeps serving.
func TestWatcherInvalidGenerationFile(t *testing.T) {
	h := newHarness(t, RoleStore)
	armed := make(chan time.Duration, 4)
	h.g.hooks.retryArmed = func(d time.Duration) { armed <- d }
	h.startWith()
	m := marker()
	writeGenFile(t, h.dir, m)
	h.log.waitFor(t, `msg="generation file refused"`, 1)
	select {
	case <-armed:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("no retry was armed")
	}
	if strings.Contains(h.log.String(), m) {
		t.Fatal("the log quotes the refused file")
	}
	// A FIFO never blocks the read.
	fifo := filepath.Join(h.dir, ".fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fifo, filepath.Join(h.dir, GenerationFileName)); err != nil {
		t.Fatal(err)
	}
	h.log.waitFor(t, `not a regular file`, 1)
	h.health(200, "ready")
}
