package gate

import (
	"log/slog"
	"sync"
	"time"
)

const (
	// rateWindow and rateLines: at most rateLines refusal lines per
	// listener per window, then one count line at the window's end (G14).
	rateWindow = time.Minute
	rateLines  = 10
)

// logRate limits the WARN lines of refusals per listener.
type logRate struct {
	log   *slog.Logger
	clock Clock
	mu    sync.Mutex
	win   map[string]*rateWin
}

type rateWin struct {
	lines      int
	suppressed int
}

func newLogRate(log *slog.Logger, clock Clock) *logRate {
	return &logRate{log: log, clock: clock, win: map[string]*rateWin{}}
}

// warn logs msg for listener unless the listener has used up its lines in
// the current window. The window starts at the first line and ends one
// minute later with a count of the lines it suppressed.
func (r *logRate) warn(listener, msg string, args ...any) {
	r.mu.Lock()
	w := r.win[listener]
	if w == nil {
		w = &rateWin{}
		r.win[listener] = w
		r.clock.AfterFunc(rateWindow, func() { r.close(listener) })
	}
	if w.lines >= rateLines {
		w.suppressed++
		r.mu.Unlock()
		return
	}
	w.lines++
	r.mu.Unlock()
	r.log.Warn(msg, append([]any{"listener", listener}, args...)...)
}

func (r *logRate) close(listener string) {
	r.mu.Lock()
	w := r.win[listener]
	delete(r.win, listener)
	r.mu.Unlock()
	if w != nil && w.suppressed > 0 {
		r.log.Warn("refusals suppressed", "listener", listener, "count", w.suppressed, "window", rateWindow.String())
	}
}
