// Package controlgate is serve's gate writer (#96 part 2, CD34 with C10
// and C11): it keeps the control gate's TLS material in the volume
// control-gate-pki current, and runs the revocation lists' schedule
// (CD16 with C8). It is the only writer of that directory, from one
// goroutine.
package controlgate

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/keepia/mail/internal/gatebundle"
	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/store"
)

// The anchors in the control gate's bundle: the agent anchor for the
// agent API, and the service anchor of its own leaf (and of the control
// listeners from 0.3.0 on).
var bundleAnchors = []pki.AnchorName{pki.AnchorAgent, pki.AnchorService}

// TickInterval is how often Run checks the lists and the bundle.
const TickInterval = time.Hour

// Writer writes the control gate's bundle into Dir.
type Writer struct {
	Store   *store.Store
	Anchors pki.AnchorKeys
	Dir     string
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger

	// Test seams (export_test.go).
	reconnectDelay func(attempt int) time.Duration
	onListen       func(pid uint32)
	onDisconnect   func()
	onReconcile    func(wrote bool, gen uint64, err error)
	onTick         func(reissued bool, err error)
}

func (w *Writer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Start runs before serve listens (CD34, C11): it issues the lists if
// they are due (at the first start, when there are none) and then
// reconciles the bundle, so the control gate has its material before any
// join.
func (w *Writer) Start(ctx context.Context) error {
	if _, err := pki.ReissueIfDue(ctx, w.Store, w.Anchors, w.now()); err != nil {
		return fmt.Errorf("revocation lists: %w", err)
	}
	if _, _, err := w.Reconcile(ctx); err != nil {
		return fmt.Errorf("control gate bundle: %w", err)
	}
	return nil
}

// Reconcile rewrites the bundle when it is missing or invalid, when its
// leaf is due for renewal (NeedsRenewal, or expired), or when its anchors
// or lists differ from the keyring's anchors and the stored lists. A
// renewal, a missing or an invalid bundle get a new key and leaf;
// otherwise the bundle's own leaf and key are kept. When nothing differs
// it writes nothing. It returns whether it wrote and the generation.
func (w *Writer) Reconcile(ctx context.Context) (wrote bool, gen uint64, err error) {
	defer func() {
		if w.onReconcile != nil {
			w.onReconcile(wrote, gen, err)
		}
	}()
	now := w.now()
	stored, err := pki.CurrentLists(ctx, w.Store)
	if err != nil {
		return false, 0, err
	}
	want := &gatebundle.Bundle{Anchors: map[pki.AnchorName]*x509.Certificate{}, Lists: map[pki.AnchorName][]byte{}}
	for _, name := range bundleAnchors {
		a := w.Anchors.Anchor(name)
		if a == nil {
			return false, 0, fmt.Errorf("no anchor %s", name)
		}
		want.Anchors[name] = a.Cert
		want.Lists[name] = stored[name].DER
	}
	cur, readErr := gatebundle.Read(w.Dir)
	switch {
	case readErr != nil && !errors.Is(readErr, fs.ErrNotExist) && !errors.Is(readErr, gatebundle.ErrRefused):
		return false, 0, readErr
	case readErr != nil && errors.Is(readErr, gatebundle.ErrRefused) && w.Log != nil:
		w.Log.Warn("control gate bundle refused; writing a new one", "err", readErr)
	}
	renew := readErr != nil || pki.NeedsRenewal(cur.Leaf(), now) || !now.Before(cur.Leaf().NotAfter) ||
		!bytes.Equal(cur.Chain[1].Raw, want.Anchors[pki.AnchorService].Raw)
	if !renew && sameMaterial(cur, want) {
		return false, 0, nil
	}
	if renew {
		leaf, key, err := pki.IssueControlGate(ctx, w.Store, w.Anchors, now)
		if err != nil {
			return false, 0, err
		}
		want.Chain = []*x509.Certificate{leaf, want.Anchors[pki.AnchorService]}
		want.Key = key
	} else {
		want.Chain, want.Key = cur.Chain, cur.Key
	}
	gen, err = gatebundle.Write(w.Dir, want)
	if err != nil {
		return false, 0, err
	}
	if w.Log != nil {
		w.Log.Info("control gate bundle written", "generation", gen, "renewed", renew,
			"leaf_not_after", want.Leaf().NotAfter.UTC().Format(time.RFC3339))
	}
	return true, gen, nil
}

// sameMaterial tells whether cur holds exactly want's anchors and lists.
func sameMaterial(cur, want *gatebundle.Bundle) bool {
	if len(cur.Anchors) != len(want.Anchors) {
		return false
	}
	for name, a := range want.Anchors {
		c, ok := cur.Anchors[name]
		if !ok || !bytes.Equal(c.Raw, a.Raw) || !bytes.Equal(cur.Lists[name], want.Lists[name]) {
			return false
		}
	}
	return true
}

// Tick is one hourly check: it reissues the lists when they are due
// (ReissueIfDue, C8) and reconciles the bundle (C11).
func (w *Writer) Tick(ctx context.Context) (err error) {
	reissued := false
	defer func() {
		if w.onTick != nil {
			w.onTick(reissued, err)
		}
	}()
	reissued, err = pki.ReissueIfDue(ctx, w.Store, w.Anchors, w.now())
	if err != nil {
		return fmt.Errorf("revocation lists: %w", err)
	}
	if reissued && w.Log != nil {
		w.Log.Info("revocation lists reissued (daily)")
	}
	_, _, err = w.Reconcile(ctx)
	return err
}

// Run is the gate writer until ctx ends. One goroutine LISTENs on its own
// connection, outside the pool, and only wakes the writer: after every
// (re)connect, once LISTEN is in place, and at every NOTIFY keepia_crl.
// The writer, the only one that writes, reconciles on each wake and runs
// Tick on each value of ticks (an hourly ticker in serve). A failed
// reconcile or tick is logged and tried again at the next wake.
func (w *Writer) Run(ctx context.Context, ticks <-chan time.Time) error {
	wake := make(chan struct{}, 1)
	listenDone := make(chan struct{})
	go func() {
		defer close(listenDone)
		w.listen(ctx, wake)
	}()
	defer func() { <-listenDone }()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
			if err := w.Tick(ctx); err != nil && ctx.Err() == nil && w.Log != nil {
				w.Log.Error("control gate tick failed", "err", err)
			}
		case <-wake:
			if _, _, err := w.Reconcile(ctx); err != nil && ctx.Err() == nil && w.Log != nil {
				w.Log.Error("control gate bundle not written", "err", err)
			}
		}
	}
}

// listen keeps a LISTEN connection and signals wake after each connect
// and each notification. A wake that is already pending absorbs the next.
func (w *Writer) listen(ctx context.Context, wake chan<- struct{}) {
	signal := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	for attempt := 0; ctx.Err() == nil; attempt++ {
		l, err := w.Store.ListenCRL(ctx)
		if err == nil {
			attempt = 0
			if w.onListen != nil {
				w.onListen(l.PID())
			}
			signal() // reconcile after every (re)connect (C11)
			for {
				if err = l.Wait(ctx); err != nil {
					break
				}
				signal()
			}
			l.Close(ctx)
		}
		if ctx.Err() != nil {
			return
		}
		if w.Log != nil {
			w.Log.Warn("LISTEN "+store.CRLChannel+" lost; reconnecting", "err", err)
		}
		if w.onDisconnect != nil {
			w.onDisconnect()
		}
		t := time.NewTimer(w.delay(attempt))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// delay is the wait before reconnect attempt n: 1 s, doubling to 30 s.
func (w *Writer) delay(attempt int) time.Duration {
	if w.reconnectDelay != nil {
		return w.reconnectDelay(attempt)
	}
	return min(time.Second<<min(attempt, 5), 30*time.Second)
}
