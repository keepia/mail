package gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/testwait"
)

// ---- fake clock ----

// fakeClock is the tests' clock: time moves only with Advance, which runs
// every timer that becomes due, in order, before it returns.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	sig    testwait.Signal
}

type fakeTimer struct {
	c    *fakeClock
	at   time.Time
	f    func()
	done bool
}

func newFakeClock() *fakeClock {
	// The real time, so certificates issued at it are valid for the TLS
	// client's own checks too.
	return &fakeClock{now: time.Now().UTC().Truncate(time.Second)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	t := &fakeTimer{c: c, at: c.now.Add(d), f: f}
	if d <= 0 {
		t.done = true
		c.mu.Unlock()
		go f()
		c.sig.Notify()
		return t
	}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	c.sig.Notify()
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	if t.done {
		return false
	}
	t.done = true
	for i, x := range t.c.timers {
		if x == t {
			t.c.timers = append(t.c.timers[:i], t.c.timers[i+1:]...)
			break
		}
	}
	return true
}

// Advance moves the clock by d and runs the timers due by then.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	end := c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		sort.SliceStable(c.timers, func(i, j int) bool { return c.timers[i].at.Before(c.timers[j].at) })
		if len(c.timers) == 0 || c.timers[0].at.After(end) {
			c.now = end
			c.mu.Unlock()
			return
		}
		t := c.timers[0]
		c.timers = c.timers[1:]
		t.done = true
		if t.at.After(c.now) {
			c.now = t.at
		}
		c.mu.Unlock()
		t.f()
	}
}

// AdvanceTo moves the clock to at.
func (c *fakeClock) AdvanceTo(at time.Time) { c.Advance(at.Sub(c.Now())) }

// pending is the remaining time of each armed timer up to max.
func (c *fakeClock) pending(max time.Duration) []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []time.Duration
	for _, t := range c.timers {
		if d := t.at.Sub(c.now); d <= max {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---- log capture and the U21 registry ----

// logCapture is one gate's log in slog's text format, the format the
// gate writes on stdout. Every write notifies sig.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
	sig testwait.Signal
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.buf.Write(p)
	l.mu.Unlock()
	l.sig.Notify()
	return len(p), nil
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logCapture) count(s string) int { return strings.Count(l.String(), s) }

// waitFor waits until s occurs at least n times in the log.
func (l *logCapture) waitFor(t testing.TB, s string, n int) {
	t.Helper()
	testwait.Until(t, &l.sig, fmt.Sprintf("%d× %q in the log", n, s), func() bool { return l.count(s) >= n })
}

// waitLine waits until one log line holds every one of parts.
func (l *logCapture) waitLine(t testing.TB, parts ...string) {
	t.Helper()
	testwait.Until(t, &l.sig, fmt.Sprintf("a log line with %q", parts), func() bool {
		for _, line := range strings.Split(l.String(), "\n") {
			all := true
			for _, p := range parts {
				all = all && strings.Contains(line, p)
			}
			if all {
				return true
			}
		}
		return false
	})
}

// registry is what U21 scans after every test of the package: all
// captured logs, and every key, certificate and list the tests made, and
// the markers in refused files.
var registry struct {
	mu      sync.Mutex
	logs    []*logCapture
	ders    [][]byte
	keys    []*ecdsa.PrivateKey
	markers []string
}

func newLog(t testing.TB) (*slog.Logger, *logCapture) {
	l := &logCapture{}
	registry.mu.Lock()
	registry.logs = append(registry.logs, l)
	registry.mu.Unlock()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("gate log:\n%s", l.String())
		}
	})
	return slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug})), l
}

func registerDER(b ...[]byte) {
	registry.mu.Lock()
	registry.ders = append(registry.ders, b...)
	registry.mu.Unlock()
}

func registerKey(k *ecdsa.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		panic(err)
	}
	sec1, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(err)
	}
	registry.mu.Lock()
	registry.keys = append(registry.keys, k)
	registry.ders = append(registry.ders, der, sec1)
	registry.mu.Unlock()
}

// marker is a unique string to put into a file the gate must refuse.
func marker() string {
	m := "REFUSEDMARKER" + strconv.FormatUint(randUint(), 36)
	registry.mu.Lock()
	registry.markers = append(registry.markers, m)
	registry.mu.Unlock()
	return m
}

func randUint() uint64 {
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<62))
	if err != nil {
		panic(err)
	}
	return n.Uint64()
}

// ---- PKI fixtures ----

var deploymentID = []byte("0123456789abcdef")

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registerKey(k)
	return k
}

func newAnchor(t testing.TB, name pki.AnchorName, at time.Time) *pki.Anchor {
	t.Helper()
	a, err := pki.NewAnchor(name, deploymentID, at)
	if err != nil {
		t.Fatal(err)
	}
	registerDER(a.Cert.Raw)
	if k, ok := a.Signer.(*ecdsa.PrivateKey); ok {
		registerKey(k)
	}
	return a
}

// issued is a leaf with its key.
type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// tlsCert is the leaf as a client certificate.
func (i issued) tlsCert() *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{i.cert.Raw}, PrivateKey: i.key, Leaf: i.cert}
}

func issue(t testing.TB, a *pki.Anchor, l pki.Leaf, at time.Time) issued {
	t.Helper()
	k := newKey(t)
	c, err := pki.Issue(a, l, k.Public(), at)
	if err != nil {
		t.Fatal(err)
	}
	registerDER(c.Raw)
	return issued{cert: c, key: k}
}

func clientLeaf(t testing.TB, p pki.Purpose, id int64) pki.Leaf {
	t.Helper()
	l, err := pki.ClientLeaf(p, id)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// craft signs tmpl with a's key directly, for certificates Issue never
// makes (U3, U4).
func craft(t testing.TB, a *pki.Anchor, tmpl *x509.Certificate) issued {
	t.Helper()
	k := newKey(t)
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = new(big.Int).SetUint64(randUint())
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, k.Public(), a.Signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	registerDER(c.Raw)
	return issued{cert: c, key: k}
}

func listDER(t testing.TB, a *pki.Anchor, number int64, at time.Time, revoked ...*x509.Certificate) []byte {
	t.Helper()
	var rs []pki.Revoked
	for _, c := range revoked {
		rs = append(rs, pki.Revoked{Serial: c.SerialNumber, RevokedAt: at, Reason: pki.ReasonCessationOfOperation, NotAfter: c.NotAfter})
	}
	der, err := pki.CreateCRL(a, number, rs, at)
	if err != nil {
		t.Fatal(err)
	}
	registerDER(der)
	return der
}

// fixture is one deployment's anchors and a gate leaf for a role.
type fixture struct {
	t                                testing.TB
	service, storeClient, agent, grp *pki.Anchor
	gate                             issued
	gateName                         string
}

func newFixture(t testing.TB, role Role, at time.Time) *fixture {
	t.Helper()
	f := &fixture{
		t:           t,
		service:     newAnchor(t, pki.AnchorService, at),
		storeClient: newAnchor(t, pki.AnchorStoreClient, at),
		agent:       newAnchor(t, pki.AnchorAgent, at),
		grp:         newAnchor(t, pki.AnchorGroupwareClient, at),
	}
	f.newGateLeaf(role, at)
	return f
}

// newGateLeaf issues a fresh gate leaf at at.
func (f *fixture) newGateLeaf(role Role, at time.Time) {
	var l pki.Leaf
	if role == RoleControl {
		l = pki.ControlGateLeaf()
	} else {
		var err error
		if l, err = pki.GateLeaf(pki.RoleStore, "s1", 1); err != nil {
			f.t.Fatal(err)
		}
	}
	f.gate = issue(f.t, f.service, l, at)
	f.gateName = l.DNSName
}

// bundle is the role's bundle with the given lists.
func (f *fixture) bundle(role Role, lists map[pki.AnchorName][]byte) *Bundle {
	b := &Bundle{
		Chain:   []*x509.Certificate{f.gate.cert, f.service.Cert},
		Key:     f.gate.key,
		Anchors: map[pki.AnchorName]*x509.Certificate{pki.AnchorService: f.service.Cert},
		Lists:   lists,
	}
	switch role {
	case RoleControl:
		b.Anchors[pki.AnchorAgent] = f.agent.Cert
	case RoleStore:
		b.Anchors[pki.AnchorStoreClient] = f.storeClient.Cert
	}
	return b
}

// lists is a fresh list per client anchor of role (number n, at at).
func (f *fixture) lists(role Role, n int64, at time.Time, revoked ...*x509.Certificate) map[pki.AnchorName][]byte {
	out := map[pki.AnchorName][]byte{pki.AnchorService: listDER(f.t, f.service, n, at)}
	switch role {
	case RoleControl:
		out[pki.AnchorAgent] = listDER(f.t, f.agent, n, at, revoked...)
	case RoleStore:
		out[pki.AnchorStoreClient] = listDER(f.t, f.storeClient, n, at, revoked...)
	}
	return out
}

// edgeDovecot is a right client certificate for the store's ingress.
func (f *fixture) edgeDovecot(id int64, at time.Time) issued {
	return issue(f.t, f.storeClient, clientLeaf(f.t, pki.PurposeEdgeDovecot, id), at)
}

// ---- loopback addresses ----

// testIP is a loopback address of its own for a test, so the gate's
// fixed ports never clash between tests. Linux routes all of
// 127.0.0.0/8 to the loopback interface.
func testIP(t testing.TB) netip.Addr {
	t.Helper()
	b := [4]byte{127, byte(1 + randUint()%250), byte(randUint()), byte(1 + randUint()%250)}
	a := netip.AddrFrom4(b)
	ln, err := net.Listen("tcp", netip.AddrPortFrom(a, 0).String())
	if err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) {
			t.Skip("needs the whole 127.0.0.0/8 on the loopback interface (Linux)")
		}
		t.Fatal(err)
	}
	_ = ln.Close()
	return a
}

// ---- targets ----

// target is a role application stand-in: it records every connection's
// bytes and echoes them, and closes its write side at the gate's EOF.
type target struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []*targetConn
	sig   testwait.Signal
}

type targetConn struct {
	mu  sync.Mutex
	got bytes.Buffer
	eof bool
	c   net.Conn
}

func (tc *targetConn) bytes() []byte {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return bytes.Clone(tc.got.Bytes())
}

func newTarget(t testing.TB, ip netip.Addr) *target {
	t.Helper()
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	tg := &target{ln: ln}
	t.Cleanup(func() {
		_ = ln.Close()
		tg.mu.Lock()
		defer tg.mu.Unlock()
		for _, c := range tg.conns {
			_ = c.c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := &targetConn{c: c}
			tg.mu.Lock()
			tg.conns = append(tg.conns, tc)
			tg.mu.Unlock()
			tg.sig.Notify()
			go func() {
				buf := make([]byte, 32<<10)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						tc.mu.Lock()
						tc.got.Write(buf[:n])
						tc.mu.Unlock()
						tg.sig.Notify()
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						tc.mu.Lock()
						tc.eof = errors.Is(err, io.EOF)
						tc.mu.Unlock()
						tg.sig.Notify()
						if tcp, ok := c.(*net.TCPConn); ok && errors.Is(err, io.EOF) {
							_ = tcp.CloseWrite()
						}
						return
					}
				}
			}()
		}
	}()
	return tg
}

func (tg *target) count() int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return len(tg.conns)
}

func (tg *target) conn(i int) *targetConn {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.conns[i]
}

// ---- the harness ----

// harness runs one gate on loopback with a fake clock, in-memory bundles
// and a real material directory.
type harness struct {
	t      testing.TB
	role   Role
	fc     *fakeClock
	log    *logCapture
	dir    string
	f      *fixture
	cfg    Config
	g      *Gate
	mesh   netip.Addr
	priv   netip.Addr
	ctrl   netip.Addr
	tgtIP  netip.Addr
	cancel context.CancelFunc
	done   chan error

	bundle    atomic.Pointer[Bundle]
	loadErr   atomic.Pointer[error]
	loadCalls atomic.Int32

	mu sync.Mutex
	// targets by the address the gate dials; dialHook overrides a dial.
	targets  map[netip.AddrPort]*target
	dialHook func(ctx context.Context, addr string) (net.Conn, error)
	dials    []string
}

type harnessOpt func(*harness)

func withMaxConns(n int) harnessOpt { return func(h *harness) { h.cfg.MaxConns = n } }

func newHarness(t testing.TB, role Role, opts ...harnessOpt) *harness {
	t.Helper()
	fc := newFakeClock()
	h := &harness{t: t, role: role, fc: fc, dir: t.TempDir(), targets: map[netip.AddrPort]*target{}}
	h.f = newFixture(t, role, fc.Now())
	h.mesh, h.priv, h.ctrl, h.tgtIP = testIP(t), testIP(t), testIP(t), testIP(t)
	h.cfg = Config{Role: role, Private: []netip.Addr{h.priv}, Dir: h.dir, MaxConns: DefaultMaxConns[role],
		MeshNet: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	if role != RoleEdge {
		h.cfg.Mesh = []netip.Addr{h.mesh}
		h.cfg.Target = h.tgtIP
	}
	if role != RoleControl {
		h.cfg.Control = h.ctrl
	}
	for _, o := range opts {
		o(h)
	}
	var lg *slog.Logger
	lg, h.log = newLog(t)
	g, err := New(h.cfg, Options{
		Log: lg, Clock: fc,
		ReadGeneration: readGeneration,
		LoadBundle:     h.load,
		HealthAddr:     netip.AddrPortFrom(h.mesh, 0).String(),
		Dial:           h.dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.g = g
	return h
}

func (h *harness) load(dir string) (*Bundle, error) {
	h.loadCalls.Add(1)
	if dir != h.dir {
		return nil, errors.New("wrong directory")
	}
	if e := h.loadErr.Load(); e != nil {
		return nil, *e
	}
	b := h.bundle.Load()
	if b == nil {
		return nil, errors.New("no bundle")
	}
	return b, nil
}

// target is the stand-in application at --target's port.
func (h *harness) target(port uint16) *target { return h.targetAt(netip.AddrPortFrom(h.tgtIP, port)) }

// targetAt is the stand-in behind the gate's dial of ap.
func (h *harness) targetAt(ap netip.AddrPort) *target {
	h.mu.Lock()
	defer h.mu.Unlock()
	if tg := h.targets[ap]; tg != nil {
		return tg
	}
	tg := newTarget(h.t, h.tgtIP)
	h.targets[ap] = tg
	return tg
}

// dial is the gate's dial: an address the test knows goes to its target.
func (h *harness) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	h.mu.Lock()
	h.dials = append(h.dials, addr)
	hook := h.dialHook
	h.mu.Unlock()
	if hook != nil {
		return hook(ctx, addr)
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	tg := h.targets[ap]
	h.mu.Unlock()
	if tg == nil {
		// As a closed port: refused at once.
		return nil, fmt.Errorf("dial %s: %w", addr, syscall.ECONNREFUSED)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, tg.ln.Addr().String())
}

// start runs the gate; Cleanup stops it and checks that Run returned nil.
func (h *harness) start() {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	go func() { h.done <- h.g.Run(ctx) }()
	h.t.Cleanup(func() {
		if h.cancel == nil {
			return
		}
		h.cancel()
		select {
		case err := <-h.done:
			if err != nil {
				h.t.Errorf("Run: %v", err)
			}
		case <-time.After(testwait.Limit(h.t)):
			h.t.Error("Run did not return after cancel")
		}
	})
}

// runErr waits for Run to return on its own.
func (h *harness) runErr() error {
	h.t.Helper()
	select {
	case err := <-h.done:
		h.cancel = nil
		return err
	case <-time.After(testwait.Limit(h.t)):
		h.t.Fatal("Run did not return")
		return nil
	}
}

// writeGen writes the generation file as the agent does: a temporary
// file in the directory, renamed over "generation".
func (h *harness) writeGen(n uint64) { writeGenFile(h.t, h.dir, strconv.FormatUint(n, 10)+"\n") }

func writeGenFile(t testing.TB, dir, content string) {
	t.Helper()
	tmp := filepath.Join(dir, ".generation.tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, GenerationFileName)); err != nil {
		t.Fatal(err)
	}
}

// provide sets generation n's bundle (or egress file) and then writes
// the generation file.
func (h *harness) provide(n uint64, b *Bundle) {
	h.bundle.Store(b)
	h.writeGen(n)
}

// startWith provides generation 1 with fresh lists and starts the gate.
func (h *harness) startWith(revoked ...*x509.Certificate) {
	h.t.Helper()
	h.bundle.Store(h.f.bundle(h.role, h.f.lists(h.role, 1, h.fc.Now(), revoked...)))
	h.writeGen(1)
	h.start()
	h.log.waitFor(h.t, `msg="applied generation 1"`, 1)
}

// readGeneration is the tests' generation reader in #45 rule 3's format;
// part 2 wires gatebundle.ReadGeneration.
func readGeneration(dir string) (uint64, error) {
	b, err := readBounded(filepath.Join(dir, GenerationFileName), 32)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSuffix(string(b), "\n")
	if !regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`).MatchString(s) {
		return 0, fmt.Errorf("generation file refused: not a decimal generation (%d bytes)", len(b))
	}
	return strconv.ParseUint(s, 10, 64)
}

// addr is a listener address of the gate.
func (h *harness) addr(ip netip.Addr, port uint16) string {
	return netip.AddrPortFrom(ip, port).String()
}

// clientConfig is a client of the gate's ingress with cert (nil: none).
func (h *harness) clientConfig(cert *tls.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(h.f.service.Cert)
	c := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: h.f.gateName,
		Time:       h.fc.Now,
	}
	if cert != nil {
		c.Certificates = []tls.Certificate{*cert}
	}
	return c
}

// dialTLS connects to an ingress listener and completes the client side
// of the handshake. In TLS 1.3 a client learns of its refusal only at its
// first read.
func (h *harness) dialTLS(addr string, cfg *tls.Config) (*tls.Conn, error) {
	h.t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(testwait.Limit(h.t)))
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	h.t.Cleanup(func() { _ = tc.Close() })
	return tc, nil
}

// echo writes msg and reads it back.
func echo(c net.Conn, msg string) error {
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo %q, want %q", buf, msg)
	}
	return nil
}

// refused asserts that a session through c gets no echo: the gate closed
// it or refused the handshake.
func refused(t testing.TB, c net.Conn) {
	t.Helper()
	if c == nil {
		return
	}
	if err := echo(c, "ping"); err == nil {
		t.Fatal("the session was served")
	} else if isTimeout(err) {
		t.Fatalf("the session was neither served nor closed: %v", err)
	}
}

// closed asserts that the gate closes c (a read ends without a timeout).
func closed(t testing.TB, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(testwait.Limit(t)))
	_, err := io.Copy(io.Discard, c)
	if isTimeout(err) {
		t.Fatal("the connection was not closed")
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// dialRefused asserts that nothing listens at addr.
func dialRefused(t testing.TB, addr string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err == nil {
		_ = c.Close()
		t.Fatalf("%s still listens", addr)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("dial %s: %v, want connection refused", addr, err)
	}
}
