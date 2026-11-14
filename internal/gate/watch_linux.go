//go:build linux

package gate

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"syscall"
)

// GenerationFileName is the file whose change means "read the material
// again" (#45 contract rule 2).
const GenerationFileName = "generation"

// watchMask is what the directory watch reports: a file closed after
// writing or renamed into it, and the directory itself going away.
const watchMask = syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF | syscall.IN_ONLYDIR

// inotify is the real event source: one non-blocking inotify instance
// read through the runtime's poller, so a blocked read wakes on close.
type inotify struct {
	f   *os.File
	dir string
	wd  int
}

func newInotify(dir string) (eventSource, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify: %w", err)
	}
	in := &inotify{f: os.NewFile(uintptr(fd), "inotify"), dir: dir, wd: -1} // #nosec G115 -- a file descriptor
	if err := in.addWatch(); err != nil {
		_ = in.f.Close()
		return nil, err
	}
	return in, nil
}

// addWatch watches the directory, again after it was replaced; a former
// watch on another inode is removed.
func (in *inotify) addWatch() error {
	rc, err := in.f.SyscallConn()
	if err != nil {
		return err
	}
	var wd int
	var werr error
	if err := rc.Control(func(fd uintptr) {
		wd, werr = syscall.InotifyAddWatch(int(fd), in.dir, watchMask) // #nosec G115 -- a file descriptor
		if werr == nil && in.wd >= 0 && in.wd != wd {
			_, _ = syscall.InotifyRmWatch(int(fd), uint32(in.wd)) // #nosec G115 -- a watch descriptor
		}
	}); err != nil {
		return err
	}
	if werr != nil {
		return fmt.Errorf("inotify watch on %s: %w", in.dir, werr)
	}
	in.wd = wd
	return nil
}

func (in *inotify) read(p []byte) (int, error) { return in.f.Read(p) }

func (in *inotify) close() error { return in.f.Close() }

// batch is what one read of events asks for.
type batch struct {
	// reread: read "generation" again; rewatch: add the watch again
	// first.
	reread, rewatch bool
	err             error
}

// parseEvents reads raw inotify_event records (G11 item 2): an event
// naming "generation", a queue overflow (events were lost) and the end of
// the watch (IN_IGNORED, IN_DELETE_SELF, IN_MOVE_SELF) all mean "read
// again", the last after the watch is added again.
func parseEvents(buf []byte) (batch, error) {
	var b batch
	const head = syscall.SizeofInotifyEvent
	for len(buf) > 0 {
		if len(buf) < head {
			return b, errors.New("a truncated inotify event")
		}
		mask := binary.NativeEndian.Uint32(buf[4:8])
		n := int(binary.NativeEndian.Uint32(buf[12:16]))
		if len(buf) < head+n {
			return b, errors.New("a truncated inotify event")
		}
		name := string(bytes.TrimRight(buf[head:head+n], "\x00"))
		buf = buf[head+n:]
		switch {
		case mask&syscall.IN_Q_OVERFLOW != 0:
			b.reread = true
		case mask&(syscall.IN_IGNORED|syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0:
			b.rewatch, b.reread = true, true
		case name == GenerationFileName && mask&(syscall.IN_CLOSE_WRITE|syscall.IN_MOVED_TO) != 0:
			b.reread = true
		}
	}
	return b, nil
}

// watch is the material watcher (G11, #45 with N11). It watches the
// directory first and only then reads "generation", so a write between
// the two is never lost. It returns an error, and Run ends, when the
// watch cannot be set up or added again, or the event stream fails: a
// dead watcher must not drop updates silently (#45 rule 9). An unreadable
// or invalid generation file is refused and retried like invalid
// material (N5).
func (g *Gate) watch(ctx context.Context) error {
	newEvents := g.hooks.events
	if newEvents == nil {
		newEvents = newInotify
	}
	src, err := newEvents(g.cfg.Dir)
	if err != nil {
		return fmt.Errorf("gate: watching %s: %w", g.cfg.Dir, err)
	}
	defer func() { _ = src.close() }()
	if h := g.hooks.afterWatch; h != nil {
		h()
	}

	done := make(chan struct{})
	defer close(done)
	batches := make(chan batch)
	go func() {
		// Room for many events; one needs at most 16 + NAME_MAX + 1 bytes.
		buf := make([]byte, 64<<10)
		for {
			n, err := src.read(buf)
			var b batch
			if err != nil {
				b.err = err
			} else if b, err = parseEvents(buf[:n]); err != nil {
				b.err = err
			}
			select {
			case batches <- b:
			case <-done:
				return
			}
			if b.err != nil {
				return
			}
		}
	}()

	delay := retryFirst
	var retry Timer
	retryC := make(chan struct{}, 1)
	var waiting Timer
	waitC := make(chan struct{}, 1)
	defer func() {
		if retry != nil {
			retry.Stop()
		}
		if waiting != nil {
			waiting.Stop()
		}
	}()
	attempt := func(fromEvent bool) {
		if retry != nil {
			retry.Stop()
			retry = nil
		}
		again, missing := g.reload(fromEvent)
		if again {
			d := delay
			retry = g.clock.AfterFunc(d, func() {
				select {
				case retryC <- struct{}{}:
				default:
				}
			})
			if h := g.hooks.retryArmed; h != nil {
				h(d)
			}
			delay = min(2*delay, retryMax)
			return
		}
		delay = retryFirst
		if missing && g.mat.Load() == nil && waiting == nil {
			g.warnWaiting()
			waiting = g.clock.AfterFunc(waitingEvery, func() { waitC <- struct{}{} })
		}
	}

	attempt(false)
	for {
		select {
		case <-ctx.Done():
			return nil
		case b := <-batches:
			if b.err != nil {
				return fmt.Errorf("gate: reading the events of %s: %w", g.cfg.Dir, b.err)
			}
			if b.rewatch {
				if err := src.addWatch(); err != nil {
					return fmt.Errorf("gate: the watch on %s is lost: %w", g.cfg.Dir, err)
				}
			}
			if b.reread {
				// An event resets the retry delay (#45 rule 5).
				delay = retryFirst
				attempt(true)
			}
		case <-retryC:
			attempt(false)
		case <-waitC:
			waiting = nil
			if code, _ := g.Health(); code == http.StatusOK && g.mat.Load() == nil {
				g.warnWaiting()
				waiting = g.clock.AfterFunc(waitingEvery, func() { waitC <- struct{}{} })
			}
			if h := g.hooks.waitHandled; h != nil {
				h()
			}
		}
	}
}

// warnWaiting is V4's line while no material has arrived.
func (g *Gate) warnWaiting() {
	g.log.Warn(fmt.Sprintf("waiting for material in %s: no generation file", g.cfg.Dir),
		"repeats every", waitingEvery.String())
}
