// Package gate is Keepia Mail's role gate (#97, architecture §5a): the
// only process that listens on the mesh. Per role it runs the listeners of
// a table compiled into the binary (roles.go):
//
//   - ingress listeners terminate mTLS, verify every client certificate
//     with pki.VerifyClient against one anchor and its current list, and
//     forward the plaintext to the role's application;
//   - egress listeners pass bytes through to a fixed mesh address without
//     any key (the edge gate's store routes come from egress.json).
//
// The material (the gate's leaf and key, the anchors and their lists, the
// edge's routes) comes from a read-only directory and is swapped as a
// whole when its "generation" file changes, under the reload contract of
// #45. When a list or the gate's leaf expires, the listeners that need it
// stop and their connections close; a new generation opens them again.
// The join listener needs no list (C5). After every swap each open
// connection is checked again, and each closes at its client leaf's
// NotAfter.
package gate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// handshakeTimeout bounds an ingress TLS handshake (G4).
	handshakeTimeout = 10 * time.Second
	// dialTimeout bounds the dial of a target or remote (G7).
	dialTimeout = 5 * time.Second
	// retryFirst and retryMax are the retry delays of a refused generation
	// (#45 rule 6, G11).
	retryFirst = time.Second
	retryMax   = 30 * time.Second
	// waitingEvery repeats the WARN while no material has arrived (V4).
	waitingEvery = time.Hour
	// DefaultHealthAddr is where /healthz listens, so the image's
	// HEALTHCHECK (keepia-mail healthcheck) works unchanged (G12).
	DefaultHealthAddr = "127.0.0.1:8080"
)

// Options are a gate's dependencies.
type Options struct {
	Log   *slog.Logger
	Clock Clock
	// ReadGeneration reads the material directory's "generation" file
	// (#45 rule 3); an error wrapping fs.ErrNotExist means there is none
	// yet. Part 2 wires gatebundle.ReadGeneration (CD35).
	ReadGeneration func(dir string) (uint64, error)
	// LoadBundle reads the directory's TLS material (control and store;
	// gatebundle.Read in part 2). The edge gate never calls it.
	LoadBundle func(dir string) (*Bundle, error)
	// HealthAddr is the /healthz address (DefaultHealthAddr).
	HealthAddr string
	// Dial dials a target or remote (a net.Dialer by default).
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Gate is one running gate.
type Gate struct {
	cfg   Config
	log   *slog.Logger
	clock Clock
	opt   Options
	rate  *logRate
	conns connCap
	// mat is the applied material; nil until the first generation. It is
	// read once per handshake and replaced as a whole (G10).
	mat atomic.Pointer[material]

	mu sync.Mutex
	// ctx is Run's context, for handshakes and dials.
	ctx     context.Context
	stopped bool
	ingress []*group
	static  []*group
	routes  map[uint16]*group
	expiry  Timer
	// refused tells whether the last attempt was refused.
	refused bool
	// healthAddr is the bound /healthz address.
	healthAddr net.Addr

	wg sync.WaitGroup

	// hooks are for tests only.
	hooks struct {
		// afterWatch runs between setting up the watch and the first read.
		afterWatch func()
		// beforeSwap runs after a generation is built, before it is
		// swapped in, with the gate's lock held.
		beforeSwap func()
		// verified runs at the end of every client certificate check.
		verified func(listener string, err error)
		// events replaces inotify.
		events func(dir string) (eventSource, error)
		// retryArmed reports each armed retry delay.
		retryArmed func(time.Duration)
		// released runs after a connection's cap slot is freed.
		released func()
		// waitHandled runs after the watcher handled the hourly waiting
		// timer.
		waitHandled func()
	}
}

// eventSource is the watcher's view of inotify (watch_linux.go): raw
// inotify_event records from read, and the directory watch.
type eventSource interface {
	addWatch() error
	read(p []byte) (int, error)
	close() error
}

// group is one listener of the table, or one store route, on all of its
// addresses.
type group struct {
	spec  Spec
	addrs []netip.AddrPort
	// lns are open while the group listens; nil when it does not.
	lns []net.Listener
	// remote is an egress group's destination.
	remote netip.AddrPort
	// store names a store route's gate, for logs.
	store string
	conns map[*proxied]struct{}
}

// New checks cfg and opt and returns a gate that Run starts.
func New(cfg Config, opt Options) (*Gate, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	if opt.ReadGeneration == nil {
		return nil, errors.New("gate: no ReadGeneration")
	}
	if hasBundle(cfg.Role) && opt.LoadBundle == nil {
		return nil, errors.New("gate: no LoadBundle")
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Clock == nil {
		opt.Clock = SystemClock{}
	}
	if opt.HealthAddr == "" {
		opt.HealthAddr = DefaultHealthAddr
	}
	if opt.Dial == nil {
		var d net.Dialer
		opt.Dial = d.DialContext
	}
	g := &Gate{
		cfg: cfg, opt: opt, log: opt.Log, clock: opt.Clock,
		rate:   newLogRate(opt.Log, opt.Clock),
		conns:  connCap{max: int64(cfg.MaxConns)},
		routes: map[uint16]*group{},
		ctx:    context.Background(),
	}
	for _, s := range specs[cfg.Role] {
		grp := &group{spec: s, conns: map[*proxied]struct{}{}}
		var on []netip.Addr
		if s.on&onMesh != 0 {
			on = append(on, cfg.Mesh...)
		}
		if s.on&onPrivate != 0 {
			on = append(on, cfg.Private...)
		}
		for _, a := range on {
			grp.addrs = append(grp.addrs, netip.AddrPortFrom(a, s.Port))
		}
		if s.Mode == Ingress {
			g.ingress = append(g.ingress, grp)
		} else {
			grp.remote = netip.AddrPortFrom(cfg.Control, s.TargetPort)
			g.static = append(g.static, grp)
		}
	}
	return g, nil
}

// Run runs the gate until ctx ends (then nil) or until it cannot go on:
// /healthz or a static listener cannot bind, or the material watch is set
// up, lost or unreadable (#45 rules 4 and 9). The caller exits 1 on an
// error, and the container's restart reads the current files.
func (g *Gate) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.mu.Lock()
	g.ctx = ctx
	g.mu.Unlock()

	var lc net.ListenConfig
	hl, err := lc.Listen(ctx, "tcp", g.opt.HealthAddr)
	if err != nil {
		return fmt.Errorf("gate: /healthz: %w", err)
	}
	g.mu.Lock()
	g.healthAddr = hl.Addr()
	g.mu.Unlock()
	hs := &http.Server{
		Handler:           g.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(g.log.Handler(), slog.LevelWarn),
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		_ = hs.Serve(hl)
	}()
	err = g.startStatic()
	if err == nil {
		err = g.watch(ctx)
	}
	// In-flight handshakes and dials end with ctx; every listener and
	// open connection closes in stop.
	cancel()
	g.stop()
	_ = hs.Close()
	g.wg.Wait()
	return err
}

// startStatic binds the static egress listeners (G7): a bind failure ends
// Run.
func (g *Gate) startStatic() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, grp := range g.static {
		lns, err := g.bind(grp)
		if err != nil {
			return fmt.Errorf("gate: %s: %w", grp.spec.Name, err)
		}
		g.open(grp, lns)
	}
	return nil
}

// bind listens on every address of grp. It closes what it opened when one
// address fails.
func (g *Gate) bind(grp *group) ([]net.Listener, error) {
	var lc net.ListenConfig
	lns := make([]net.Listener, 0, len(grp.addrs))
	for _, a := range grp.addrs {
		ln, err := lc.Listen(g.ctx, "tcp", a.String())
		if err != nil {
			closeAll(lns)
			return nil, err
		}
		lns = append(lns, ln)
	}
	return lns, nil
}

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
	}
}

// open starts accepting on the bound listeners of grp (g.mu held).
func (g *Gate) open(grp *group, lns []net.Listener) {
	grp.lns = lns
	addrs := make([]string, len(lns))
	for i, ln := range lns {
		addrs[i] = ln.Addr().String()
		g.wg.Add(1)
		go g.accept(grp, ln)
	}
	args := []any{"listener", grp.spec.Name, "addrs", strings.Join(addrs, " ")}
	if grp.spec.Mode == Egress {
		args = append(args, "remote", grp.remote.String())
		if grp.store != "" {
			args = append(args, "store", grp.store)
		}
	}
	g.log.Info("listening", args...)
}

// shut stops grp listening and closes its connections (g.mu held).
func (g *Gate) shut(grp *group, reason string) {
	if grp.lns == nil {
		return
	}
	closeAll(grp.lns)
	grp.lns = nil
	for p := range grp.conns {
		p.close()
	}
	g.log.Info("stopped listening", "listener", grp.spec.Name, "reason", reason, "connections closed", len(grp.conns))
}

// stop closes every listener and connection: the end of Run.
func (g *Gate) stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped = true
	if g.expiry != nil {
		g.expiry.Stop()
	}
	for _, grp := range g.allGroups() {
		g.shut(grp, "the gate stops")
	}
}

func (g *Gate) allGroups() []*group {
	out := append(append([]*group{}, g.ingress...), g.static...)
	for _, grp := range g.routes {
		out = append(out, grp)
	}
	return out
}

// reload reads the generation file and applies its material when the
// value differs from the applied one (#45 rule 4, CD-N3-3: the writer
// writes strictly greater values, the reader applies any valid value that
// differs). It returns true when the attempt failed and is to be retried
// (#45 rule 6); the old material keeps serving meanwhile. fromEvent marks
// a read that an event caused, which logs an equal value as ignored.
func (g *Gate) reload(fromEvent bool) (retry, missing bool) {
	gen, err := g.opt.ReadGeneration(g.cfg.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		if cur := g.mat.Load(); cur != nil {
			g.log.Warn("generation file missing; the applied generation keeps serving", "generation", cur.gen)
		}
		return false, true
	}
	if err != nil {
		g.log.Warn("generation file refused", "reason", err.Error())
		g.setRefused(true)
		return true, false
	}
	if cur := g.mat.Load(); cur != nil && cur.gen == gen {
		if fromEvent {
			g.log.Info(fmt.Sprintf("generation %d ignored: already applied", gen))
		}
		g.setRefused(false)
		return false, false
	}
	m, err := g.load(gen)
	if err == nil {
		err = g.apply(m)
	}
	if err != nil {
		g.setRefused(true)
		g.log.Warn(fmt.Sprintf("generation %d refused: %s", gen, err))
		return true, false
	}
	g.setRefused(false)
	args := []any{}
	if hasBundle(g.cfg.Role) {
		args = append(args, "serial", m.leaf.SerialNumber.Text(16), "leaf valid until", m.leaf.NotAfter.UTC().Format(time.RFC3339), "lists", m.describeLists())
	} else {
		args = append(args, "routes", len(m.routes))
	}
	g.log.Info(fmt.Sprintf("applied generation %d", gen), args...)
	return false, false
}

func (g *Gate) setRefused(v bool) {
	g.mu.Lock()
	g.refused = v
	g.mu.Unlock()
}

// load builds generation gen's material (G10) against the held one.
func (g *Gate) load(gen uint64) (*material, error) {
	held := g.mat.Load()
	now := g.clock.Now()
	var m *material
	if hasBundle(g.cfg.Role) {
		b, err := g.opt.LoadBundle(g.cfg.Dir)
		if err != nil {
			return nil, fmt.Errorf("the bundle does not load: %w", err)
		}
		if m, err = buildTLS(g.cfg.Role, b, held, now); err != nil {
			return nil, err
		}
	} else {
		routes, err := readEgressFile(g.cfg.Dir, g.cfg.MeshNet)
		if err != nil {
			return nil, err
		}
		m = &material{routes: routes}
	}
	m.gen = gen
	return m, nil
}

// apply swaps m in (G10): first every listener m needs is bound, so a
// bind failure refuses the generation and keeps the old state; then one
// pointer swap; then the listeners m no longer allows stop, the routes it
// drops close, and every open connection is checked against m (G6).
func (g *Gate) apply(m *material) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return errors.New("the gate stops")
	}
	now := g.clock.Now()
	bound := map[*group][]net.Listener{}
	fail := func(name string, err error) error {
		for _, lns := range bound {
			closeAll(lns)
		}
		return fmt.Errorf("%s: %w", name, err)
	}
	for _, grp := range g.ingress {
		if grp.lns == nil && m.allows(grp.spec, now) {
			lns, err := g.bind(grp)
			if err != nil {
				return fail(grp.spec.Name, err)
			}
			bound[grp] = lns
		}
	}
	var added []*group
	keep := map[uint16]Route{}
	for _, r := range m.routes {
		keep[r.Port] = r
		if g.routes[r.Port] != nil {
			continue
		}
		grp := g.routeGroup(r)
		lns, err := g.bind(grp)
		if err != nil {
			return fail(grp.spec.Name, err)
		}
		bound[grp] = lns
		added = append(added, grp)
	}
	if h := g.hooks.beforeSwap; h != nil {
		h()
	}
	g.mat.Store(m)

	for _, grp := range g.ingress {
		if lns, ok := bound[grp]; ok {
			g.open(grp, lns)
		} else if grp.lns != nil && !m.allows(grp.spec, now) {
			g.shut(grp, m.stopReason(grp.spec, now))
		}
	}
	for port, grp := range g.routes {
		r, ok := keep[port]
		switch {
		case !ok:
			g.shut(grp, "the route was removed")
			delete(g.routes, port)
		case r.Remote != grp.remote:
			// A changed remote is a removed and re-added route (N7): its
			// connections to the old remote close; the socket stays.
			for p := range grp.conns {
				p.close()
			}
			g.log.Info("route changed", "listener", grp.spec.Name, "remote", r.Remote.String(), "store", r.Store, "connections closed", len(grp.conns))
			grp.remote, grp.store = r.Remote, r.Store
		}
	}
	for _, grp := range added {
		g.routes[grp.spec.Port] = grp
		g.open(grp, bound[grp])
	}
	g.recheck(m, now)
	g.armExpiry(m, now)
	return nil
}

// routeGroup is the listener of a store route on the private addresses.
func (g *Gate) routeGroup(r Route) *group {
	grp := &group{
		spec:   Spec{Name: fmt.Sprintf("route-%d", r.Port), Port: r.Port, on: onPrivate, Mode: Egress},
		remote: r.Remote, store: r.Store,
		conns: map[*proxied]struct{}{},
	}
	for _, a := range g.cfg.Private {
		grp.addrs = append(grp.addrs, netip.AddrPortFrom(a, r.Port))
	}
	return grp
}

// stopReason is why m does not allow s at now.
func (m *material) stopReason(s Spec, now time.Time) string {
	if !m.leafValid(now) {
		return "the gate's leaf has expired"
	}
	return "list of " + string(s.Anchor) + " expired"
}

// armExpiry sets the timer for the next leaf or list expiry of m
// (g.mu held). The per-handshake check in VerifyClient stays
// authoritative if the timer fires late (G5).
func (g *Gate) armExpiry(m *material, now time.Time) {
	if g.expiry != nil {
		g.expiry.Stop()
		g.expiry = nil
	}
	next := m.nextExpiry(now)
	if next.IsZero() {
		return
	}
	g.expiry = g.clock.AfterFunc(next.Sub(now), g.expired)
}

// expired stops the listeners whose leaf or list has expired, with their
// connections, and arms the next expiry.
func (g *Gate) expired() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return
	}
	m := g.mat.Load()
	if m == nil {
		return
	}
	now := g.clock.Now()
	for _, grp := range g.ingress {
		if grp.lns != nil && !m.allows(grp.spec, now) {
			g.shut(grp, m.stopReason(grp.spec, now))
		}
	}
	g.recheck(m, now)
	g.armExpiry(m, now)
}

// Health is the gate's state for /healthz (G12): 200 "ready" when every
// listener of the role listens, 200 "waiting for material" before any
// generation was applied or refused, and 503 with the reason otherwise.
func (g *Gate) Health() (int, string) {
	m := g.mat.Load()
	g.mu.Lock()
	refused := g.refused
	g.mu.Unlock()
	if m == nil {
		if refused {
			return http.StatusServiceUnavailable, "material refused"
		}
		return http.StatusOK, "waiting for material"
	}
	if why := m.unhealthy(g.cfg.Role, g.clock.Now()); why != "" {
		return http.StatusServiceUnavailable, why
	}
	return http.StatusOK, "ready"
}

// Handler serves GET /healthz.
func (g *Gate) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		code, body := g.Health()
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(code)
		_, _ = fmt.Fprintln(w, body)
	})
	return mux
}
