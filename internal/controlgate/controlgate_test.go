package controlgate

import (
	"context"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/gatebundle"
	"github.com/keepia/mail/internal/join"
	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/pki/pkitest"
	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

var start = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// clock is a fake clock that moves only when the test sets it.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *clock) set(t time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.t = t }

type env struct {
	st    *store.Store
	url   string
	keys  pkitest.Keys
	clock *clock
	w     *Writer
	// sig is notified after every reconcile and tick.
	sig testwait.Signal
	mu  sync.Mutex
	// listenPID is the LISTEN backend; ticks counts finished ticks and
	// lastTick is the last one's result.
	listenPID uint32
	ticks     int
	reissued  bool
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	e := &env{url: storetest.NewUnmigrated(t), keys: pkitest.NewKeys(t, start.Add(-time.Hour)), clock: &clock{t: start}}
	st, err := store.Open(ctx, e.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	e.st = st
	e.w = &Writer{
		Store: st, Anchors: e.keys, Dir: t.TempDir(), Now: e.clock.now,
		reconnectDelay: func(int) time.Duration { return 0 },
		onListen: func(pid uint32) {
			e.mu.Lock()
			e.listenPID = pid
			e.mu.Unlock()
			e.sig.Notify()
		},
		onReconcile: func(bool, uint64, error) { e.sig.Notify() },
		onTick: func(reissued bool, _ error) {
			e.mu.Lock()
			e.ticks++
			e.reissued = reissued
			e.mu.Unlock()
			e.sig.Notify()
		},
	}
	return e
}

func (e *env) generation(t *testing.T) uint64 {
	t.Helper()
	g, err := gatebundle.ReadGeneration(e.w.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (e *env) bundle(t *testing.T) *gatebundle.Bundle {
	t.Helper()
	b, err := gatebundle.Read(e.w.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// listNumber is the number of the bundle's list of anchor.
func listNumber(t *testing.T, b *gatebundle.Bundle, anchor pki.AnchorName) int64 {
	t.Helper()
	rl, err := x509.ParseRevocationList(b.Lists[anchor])
	if err != nil {
		t.Fatal(err)
	}
	return rl.Number.Int64()
}

// run starts Run until the test ends and waits for its first LISTEN.
func (e *env) run(t *testing.T, ticks <-chan time.Time) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = e.w.Run(ctx, ticks) }()
	t.Cleanup(func() { cancel(); <-done })
	testwait.Until(t, &e.sig, "the gate writer's LISTEN", func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.listenPID != 0
	})
}

// K1: the first start, with no servers row, writes bundle.pem (0400) and
// generation 1; Read accepts it, and a token from server add then makes
// the agent's join check pass on the bundle's leaf and anchor, with the
// token's pin and the name control.keepia.internal, and its list.
func TestFirstStartWritesTheBundle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(e.w.Dir, gatebundle.BundleFile))
	if err != nil || fi.Mode() != 0o400 {
		t.Fatalf("bundle.pem: %v, %v", fi, err)
	}
	if g := e.generation(t); g != 1 {
		t.Errorf("generation %d, want 1", g)
	}
	b := e.bundle(t)
	if len(b.Anchors) != 2 || b.Anchors[pki.AnchorAgent] == nil || b.Anchors[pki.AnchorService] == nil {
		t.Errorf("anchors %v", b.Anchors)
	}
	tok, err := join.AddServer(ctx, e.st, e.keys.Anchor(pki.AnchorService).Cert, "s1", []string{"store"}, time.Hour, start)
	if err != nil {
		t.Fatal(err)
	}
	leaf, anchor, err := join.CheckServer(b.Chain, tok.Pin, start)
	if err != nil {
		t.Fatalf("the join check on the bundle: %v", err)
	}
	crl, err := pki.VerifyCRL(b.Lists[pki.AnchorService], anchor, nil, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := join.CheckLeaf(leaf, crl); err != nil {
		t.Error(err)
	}
	if err := pki.VerifyServer(b.Chain, anchor, pki.ControlGateName, crl, start); err != nil {
		t.Errorf("VerifyServer on the bundle: %v", err)
	}
	// A second start with nothing changed writes nothing.
	if err := e.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if g := e.generation(t); g != 1 {
		t.Errorf("an unchanged start wrote generation %d", g)
	}
}

// K6: a start with the bundle deleted rewrites it, with a greater
// generation, before serve would listen.
func TestStartRewritesAMissingBundle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.w.Dir, gatebundle.BundleFile)); err != nil {
		t.Fatal(err)
	}
	if err := e.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := gatebundle.Read(e.w.Dir); err != nil {
		t.Errorf("after the second start: %v", err)
	}
	if g := e.generation(t); g != 2 {
		t.Errorf("generation %d, want 2", g)
	}
}

// K2: at NotBefore + 10 d - 1 s the bundle stays as it is; at + 10 d a
// new leaf with a new key is written and the generation rises by one.
func TestRenewal(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first := e.bundle(t).Leaf()
	e.clock.set(first.NotBefore.Add(pki.RenewAfter - time.Second))
	if wrote, _, err := e.w.Reconcile(ctx); err != nil || wrote {
		t.Fatalf("at 10 d - 1 s: wrote %v, %v", wrote, err)
	}
	if g := e.generation(t); g != 1 {
		t.Errorf("generation %d", g)
	}
	e.clock.set(first.NotBefore.Add(pki.RenewAfter))
	if wrote, gen, err := e.w.Reconcile(ctx); err != nil || !wrote || gen != 2 {
		t.Fatalf("at 10 d: wrote %v, generation %d, %v", wrote, gen, err)
	}
	renewed := e.bundle(t).Leaf()
	if renewed.Equal(first) || string(renewed.RawSubjectPublicKeyInfo) == string(first.RawSubjectPublicKeyInfo) {
		t.Error("the renewal kept the leaf or its key")
	}
}

// K3: a Reissue in this process, and a removal committed on another
// connection (a CLI process), each lead to a bundle with the new list
// numbers and generation + 1, through NOTIFY keepia_crl.
func TestNewListsReachTheBundle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	e.run(t, nil)
	waitGen := func(want uint64, what string) {
		t.Helper()
		testwait.Until(t, &e.sig, what, func() bool {
			g, err := gatebundle.ReadGeneration(e.w.Dir)
			return err == nil && g >= want
		})
	}
	if err := pki.Reissue(ctx, e.st, e.keys, start); err != nil {
		t.Fatal(err)
	}
	waitGen(2, "the bundle after a Reissue")
	if n := listNumber(t, e.bundle(t), pki.AnchorService); n != 2 {
		t.Errorf("service list number %d, want 2", n)
	}

	cli, err := store.Open(ctx, e.url)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := join.AddServer(ctx, cli, e.keys.Anchor(pki.AnchorService).Cert, "s1", []string{"store"}, time.Hour, start); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.RevokeServer(ctx, cli, e.keys, "s1", start); err != nil {
		t.Fatal(err)
	}
	waitGen(3, "the bundle after a removal on another connection")
	b := e.bundle(t)
	if n := listNumber(t, b, pki.AnchorAgent); n != 3 {
		t.Errorf("agent list number %d, want 3", n)
	}
	if g := e.generation(t); g != 3 {
		t.Errorf("generation %d, want 3", g)
	}
}

// K3b: a list committed while the LISTEN connection is down reaches the
// bundle after the reconnect, because the writer reconciles after every
// (re)connect (C11).
func TestReconnectCatchesUp(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	down, release := make(chan struct{}, 1), make(chan struct{})
	e.w.onDisconnect = func() {
		select {
		case down <- struct{}{}:
			<-release
		default:
		}
	}
	e.run(t, nil)
	// Registered after run's cleanup, so it runs first: a failed test
	// never leaves the writer blocked in its hook.
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	t.Cleanup(open)
	e.mu.Lock()
	pid := e.listenPID
	e.listenPID = 0
	e.mu.Unlock()
	obs, err := pgx.Connect(ctx, e.url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = obs.Close(ctx) }()
	if _, err := obs.Exec(ctx, "SELECT pg_terminate_backend($1)", int64(pid)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-down:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the writer did not notice the lost connection")
	}
	if err := pki.Reissue(ctx, e.st, e.keys, start); err != nil {
		t.Fatal(err)
	}
	open()
	testwait.Until(t, &e.sig, "the bundle after the reconnect", func() bool {
		g, err := gatebundle.ReadGeneration(e.w.Dir)
		return err == nil && g == 2
	})
	if n := listNumber(t, e.bundle(t), pki.AnchorService); n != 2 {
		t.Errorf("service list number %d, want 2", n)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.listenPID == 0 || e.listenPID == pid {
		t.Errorf("LISTEN backend %d after the reconnect (was %d)", e.listenPID, pid)
	}
}

// R1, C8: with a fake clock, a tick 22:59 h after the last lists does not
// reissue; a tick at 23:00 h reissues all four, each number + 1, and the
// bundle follows.
func TestHourlyTick(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ticks := make(chan time.Time)
	e.run(t, ticks)
	tick := func(at time.Time) bool {
		t.Helper()
		e.clock.set(at)
		e.mu.Lock()
		n := e.ticks
		e.mu.Unlock()
		select {
		case ticks <- at:
		case <-time.After(testwait.Limit(t)):
			t.Fatal("the writer took no tick")
		}
		var reissued bool
		testwait.Until(t, &e.sig, "the tick", func() bool {
			e.mu.Lock()
			defer e.mu.Unlock()
			reissued = e.reissued
			return e.ticks == n+1
		})
		return reissued
	}
	if tick(start.Add(22*time.Hour + 59*time.Minute)) {
		t.Error("a tick at 22:59 reissued")
	}
	if !tick(start.Add(23 * time.Hour)) {
		t.Error("a tick at 23:00 did not reissue")
	}
	rows, err := e.st.ListCRLs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Number != 2 {
			t.Errorf("%s: number %d, want 2", r.Anchor, r.Number)
		}
	}
	testwait.Until(t, &e.sig, "the bundle with the new lists", func() bool {
		b, err := gatebundle.Read(e.w.Dir)
		return err == nil && listNumber(t, b, pki.AnchorService) == 2
	})
}

// A start without lists or anchors fails before anything is written.
func TestStartNeedsAnchors(t *testing.T) {
	e := newEnv(t)
	e.w.Anchors = pkitest.Keys{}
	if err := e.w.Start(context.Background()); err == nil {
		t.Fatal("a start without anchors succeeded")
	}
	if _, err := gatebundle.ReadGeneration(e.w.Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("generation: %v", err)
	}
}
