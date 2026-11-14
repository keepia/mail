package gate

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keepia/mail/internal/testwait"
)

// G6: a handshake that verified against generation N and registers after
// generation N+1 revoked its certificate is checked again at its
// registration: it is refused and never reaches the target. The re-check
// of open sessions on the swap cannot see it, because it is not
// registered yet.
func TestRegisterRechecksStaleSnapshot(t *testing.T) {
	h := newHarness(t, RoleStore)
	tg := h.target(143)
	inVerify, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var first atomic.Bool
	h.g.hooks.verified = func(_ string, err error) {
		// Hold the first accepted handshake between its check and its
		// registration.
		if err == nil && first.CompareAndSwap(false, true) {
			close(inVerify)
			<-release
		}
	}
	h.startWith()
	client := h.f.edgeDovecot(7, h.fc.Now())
	// In TLS 1.3 the client's side is done before the server checks it.
	tc, err := h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-inVerify:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the handshake was not verified")
	}
	h.provide(2, h.f.bundle(RoleStore, h.f.lists(RoleStore, 2, h.fc.Now(), client.cert)))
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	unblock()
	h.log.waitLine(t, `msg="connection refused"`, "listener=imap", "reason=revoked")
	refused(t, tc)
	if tg.count() != 0 {
		t.Fatalf("the target saw %d connections", tg.count())
	}
}

// G4, G13: a peer that sends no ClientHello holds a cap slot only until
// the 10 s handshake bound; then its connection closes, the slot is free,
// and a right client is served again.
func TestHandshakeDeadlineFreesTheCap(t *testing.T) {
	h := newHarness(t, RoleStore, withMaxConns(3))
	var released testwait.Signal
	h.g.hooks.released = released.Notify
	tg := h.target(143)
	h.startWith()
	addr := h.addr(h.mesh, PortIMAP)
	silent := make([]net.Conn, 3)
	for i := range silent {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		silent[i] = c
	}
	testwait.Until(t, &h.fc.sig, "three handshake bounds", func() bool {
		return len(h.fc.pending(handshakeTimeout)) == 3
	})
	// The cap is full: a fourth connection is closed at once.
	c4, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	closed(t, c4)
	h.log.waitLine(t, `msg="connection refused: the connection cap is reached"`, "listener=imap")

	h.fc.Advance(handshakeTimeout)
	for _, c := range silent {
		closed(t, c)
	}
	h.log.waitFor(t, `reason="handshake timeout"`, 3)
	testwait.Until(t, &released, "every cap slot released", func() bool { return h.g.conns.open.Load() == 0 })

	client := h.f.edgeDovecot(7, h.fc.Now())
	tc, err := h.dialTLS(addr, sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(tc, "a1 NOOP\r\n"); err != nil {
		t.Fatal(err)
	}
	if tg.count() != 1 {
		t.Fatalf("the target saw %d connections", tg.count())
	}
}

// A handshake that the gate's stop cuts is logged as "gate stopping",
// not as a timeout.
func TestHandshakeCancelledByStop(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	c, err := net.Dial("tcp", h.addr(h.mesh, PortIMAP))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	testwait.Until(t, &h.fc.sig, "the handshake bound", func() bool {
		return len(h.fc.pending(handshakeTimeout)) == 1
	})
	h.cancel()
	if err := h.runErr(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	log := h.log.String()
	if !strings.Contains(log, `reason="gate stopping"`) {
		t.Error(`no refusal with reason="gate stopping"`)
	}
	if strings.Contains(log, "handshake timeout") {
		t.Error("the stop is logged as a handshake timeout")
	}
}
