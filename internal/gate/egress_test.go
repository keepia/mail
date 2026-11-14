package gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keepia/mail/internal/testwait"
)

// replyAtEOF is a server that answers only after the client's EOF: a
// passthrough without half-close loses the answer.
func replyAtEOF(t *testing.T, ip netip.Addr) (net.Listener, chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b, _ := io.ReadAll(c)
		got <- b
		_, _ = c.Write(append([]byte("reply:"), b...))
	}()
	return ln, got
}

// U16: the static egress passes bytes both ways unchanged, non-TLS bytes
// and a large stream included, with half-close.
func TestEgressPassthroughHalfClose(t *testing.T) {
	h := newHarness(t, RoleStore)
	ln, got := replyAtEOF(t, h.tgtIP)
	h.dialHook = func(ctx context.Context, addr string) (net.Conn, error) {
		if addr != h.addr(h.ctrl, PortAgentAPI) {
			return nil, fmt.Errorf("dial %s", addr)
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
	h.start()
	h.log.waitFor(t, `msg="waiting for material`, 1)
	c, err := net.Dial("tcp", h.addr(h.priv, PortAgentAPI))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(testwait.Limit(t)))
	payload := make([]byte, 1<<20+7)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	payload = append([]byte("\x16\x03\x01 not TLS \x00"), payload...)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(<-got, payload) {
		t.Fatal("the remote got other bytes")
	}
	if !bytes.Equal(reply, append([]byte("reply:"), payload...)) {
		t.Fatalf("the reply has %d bytes, want %d", len(reply), len(payload)+6)
	}
	h.log.waitFor(t, fmt.Sprintf(`"bytes in"=%d "bytes out"=%d`, len(payload), len(payload)+6), 1)
}

// U16: a remote that does not answer closes the client at the dial
// timeout; one that refuses closes it at once.
func TestEgressRemoteDown(t *testing.T) {
	h := newHarness(t, RoleStore)
	entered := make(chan struct{}, 1)
	hang := true
	h.dialHook = func(ctx context.Context, addr string) (net.Conn, error) {
		h.mu.Lock()
		hanging := hang
		h.mu.Unlock()
		if !hanging {
			return nil, fmt.Errorf("dial %s: %w", addr, syscall.ECONNREFUSED)
		}
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	h.start()
	h.log.waitFor(t, `msg="waiting for material`, 1)
	c, err := net.Dial("tcp", h.addr(h.priv, PortJoin))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("no dial")
	}
	h.fc.Advance(dialTimeout)
	closed(t, c)
	h.log.waitFor(t, `msg="remote unreachable"`, 1)

	h.mu.Lock()
	hang = false
	h.mu.Unlock()
	c2, err := net.Dial("tcp", h.addr(h.priv, PortJoin))
	if err != nil {
		t.Fatal(err)
	}
	closed(t, c2)
}

// writeEgress writes egress.json by write-and-rename.
func writeEgress(t *testing.T, dir string, content []byte) {
	t.Helper()
	tmp := filepath.Join(dir, ".egress.tmp")
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, EgressFileName)); err != nil {
		t.Fatal(err)
	}
}

func egressJSON(t *testing.T, routes ...egressEntry) []byte {
	t.Helper()
	if routes == nil {
		routes = []egressEntry{}
	}
	b, err := json.Marshal(egressFile{Version: 1, Listeners: routes})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var mesh8 = []netip.Prefix{netip.MustParsePrefix("10.20.8.0/24"), netip.MustParsePrefix("fd00:20:8::/64")}

// U17, V6: egress.json's checks; no refusal quotes the file.
func TestEgressFileRefuses(t *testing.T) {
	ok := egressEntry{Port: 20000, Remote: "10.20.8.40:7143", Store: "s1.store.keepia.internal"}
	if routes, err := parseEgress(egressJSON(t, ok,
		egressEntry{Port: 20001, Remote: "10.20.8.40:7110", Store: "s1.store.keepia.internal"},
		egressEntry{Port: 20006, Remote: "[fd00:20:8::40]:7024", Store: "s2.store.keepia.internal"},
	), mesh8); err != nil || len(routes) != 3 {
		t.Fatalf("a valid file: %v %v", routes, err)
	}
	m := marker()
	with := func(f func(e *egressEntry)) []byte {
		e := ok
		f(&e)
		return egressJSON(t, e)
	}
	many := make([]egressEntry, 0, 257)
	for i := 0; len(many) < 257; i++ {
		if i%4 == 3 {
			continue
		}
		many = append(many, egressEntry{Port: 20000 + i, Remote: fmt.Sprintf("10.20.8.40:%d", routeRemotePort[i%4]), Store: "s1"})
	}
	big := bytes.Repeat([]byte(" "), maxEgressFile)
	cases := map[string][]byte{
		"unknown field":      []byte(`{"version":1,"listeners":[],"` + m + `":1}`),
		"unknown entry key":  []byte(`{"version":1,"listeners":[{"port":20000,"remote":"10.20.8.40:7143","store":"s1","` + m + `":1}]}`),
		"syntax":             []byte(`{"version":1,"listeners":[` + m),
		"wrong type":         []byte(`{"version":"` + m + `","listeners":[]}`),
		"trailing data":      append(egressJSON(t), []byte(` {"`+m+`":1}`)...),
		"version 2":          []byte(`{"version":2,"listeners":[]}`),
		"port below":         with(func(e *egressEntry) { e.Port = 19996 }),
		"port above":         with(func(e *egressEntry) { e.Port = 30000 }),
		"duplicate":          egressJSON(t, ok, ok),
		"outside the mesh":   with(func(e *egressEntry) { e.Remote = "10.20.4.40:7143" }),
		"a host name":        with(func(e *egressEntry) { e.Remote = m + ".example:7143" }),
		"no port":            with(func(e *egressEntry) { e.Remote = "10.20.8.40" }),
		"control's port":     with(func(e *egressEntry) { e.Remote = "10.20.8.10:7400" }),
		"another port":       with(func(e *egressEntry) { e.Remote = "10.20.8.40:143" }),
		"offset mismatch":    with(func(e *egressEntry) { e.Remote = "10.20.8.40:7024" }),
		"offset 3":           with(func(e *egressEntry) { e.Port = 20003; e.Remote = "10.20.8.40:7143" }),
		"store not a name":   with(func(e *egressEntry) { e.Store = "s1\n" + m }),
		"257 listeners":      egressJSON(t, many...),
		"over 64 KiB":        append(egressJSON(t), big...),
		"multicast remote":   with(func(e *egressEntry) { e.Remote = "[ff02::1]:7143" }),
		"zoned remote":       with(func(e *egressEntry) { e.Remote = "[fe80::1%eth0]:7143" }),
		"mapped outside":     with(func(e *egressEntry) { e.Remote = "[::ffff:10.20.4.40]:7143" }),
		"remote port offset": egressJSON(t, egressEntry{Port: 20005, Remote: "10.20.8.40:7143", Store: "s1"}),
	}
	dir := t.TempDir()
	for name, b := range cases {
		writeEgress(t, dir, b)
		_, err := readEgressFile(dir, mesh8)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), m) || strings.Contains(err.Error(), "10.20.") {
			t.Errorf("%s: the error quotes the file: %v", name, err)
		}
	}
}

// U17: a symlink and a FIFO are refused without blocking, a missing file
// is fs.ErrNotExist.
func TestEgressFileSafeRead(t *testing.T) {
	dir := t.TempDir()
	if _, err := readEgressFile(dir, mesh8); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	real := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(real, egressJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, EgressFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := readEgressFile(dir, mesh8); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
	fifoDir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(fifoDir, EgressFileName), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readEgressFile(fifoDir, mesh8); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO: %v", err)
		}
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the read of a FIFO blocks")
	}
	sub := t.TempDir()
	if err := os.Mkdir(filepath.Join(sub, EgressFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readEgressFile(sub, mesh8); err == nil {
		t.Fatal("a directory was read")
	}
}

// edgeRoute is a route of the edge harness to a remote stand-in.
func (h *harness) edgeRoute(port int, remote netip.AddrPort) egressEntry {
	h.targetAt(remote)
	return egressEntry{Port: port, Remote: remote.String(), Store: "s1.store.keepia.internal"}
}

// passthrough opens a session through a route and checks one echo.
func (h *harness) passthrough(port uint16) net.Conn {
	h.t.Helper()
	c, err := net.Dial("tcp", h.addr(h.priv, port))
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(testwait.Limit(h.t)))
	if err := echo(c, "* OK"); err != nil {
		h.t.Fatalf("route %d: %v", port, err)
	}
	return c
}

// U17, G8, N7: the edge gate applies its routes; a removed route closes
// its listener and connections; a changed remote closes the connections
// to the old one; a bind failure keeps the old routes. The edge gate
// never loads a bundle.
func TestEdgeRoutes(t *testing.T) {
	h := newHarness(t, RoleEdge)
	a := testIP(t)
	b := testIP(t)
	r1 := h.edgeRoute(20000, netip.AddrPortFrom(a, PortIMAP))
	r2 := h.edgeRoute(20002, netip.AddrPortFrom(a, PortLMTP))
	writeEgress(t, h.dir, egressJSON(t, r1, r2))
	h.writeGen(1)
	h.start()
	h.log.waitFor(t, `msg="applied generation 1" routes=2`, 1)
	h.health(200, "ready")
	c1 := h.passthrough(20000)
	c2 := h.passthrough(20002)

	// Generation 2 drops 20000.
	writeEgress(t, h.dir, egressJSON(t, r2))
	h.writeGen(2)
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	dialRefused(t, h.addr(h.priv, 20000))
	closed(t, c1)
	if err := echo(c2, "a1 NOOP"); err != nil {
		t.Fatalf("the kept route: %v", err)
	}

	// Generation 3 points 20002 at another store gate (N7).
	r2b := h.edgeRoute(20002, netip.AddrPortFrom(b, PortLMTP))
	writeEgress(t, h.dir, egressJSON(t, r2b))
	h.writeGen(3)
	h.log.waitFor(t, `msg="applied generation 3"`, 1)
	closed(t, c2)
	h.passthrough(20002)
	if h.targetAt(netip.AddrPortFrom(b, PortLMTP)).count() != 1 {
		t.Fatal("the new remote got no connection")
	}

	// Generation 4 adds 20004, whose port is taken: refused, the old
	// routes stay.
	busy, err := net.Listen("tcp", h.addr(h.priv, 20004))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	writeEgress(t, h.dir, egressJSON(t, r2b, h.edgeRoute(20004, netip.AddrPortFrom(b, PortIMAP))))
	h.writeGen(4)
	h.log.waitFor(t, `msg="generation 4 refused: route-20004: listen tcp`, 1)
	h.passthrough(20002)

	// A refused file names no content.
	m := marker()
	writeEgress(t, h.dir, []byte(`{"version":1,"listeners":[{"port":20000,"remote":"`+m+`","store":"s"}]}`))
	h.writeGen(5)
	h.log.waitFor(t, `msg="generation 5 refused: egress.json: listener 0: the remote is not an IP address and port"`, 1)
	if h.loadCalls.Load() != 0 {
		t.Fatal("the edge gate loaded a bundle")
	}
}
