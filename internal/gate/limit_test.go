package gate

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/keepia/mail/internal/testwait"
)

// U20: at the cap the next connection is closed at once; 25 refusals in
// one minute give 10 WARN lines and one count line.
func TestConnectionCap(t *testing.T) {
	h := newHarness(t, RoleEdge, withMaxConns(2))
	h.targetAt(netip.AddrPortFrom(h.ctrl, PortAgentAPI))
	h.start()
	h.log.waitFor(t, `msg="waiting for material`, 1)
	addr := h.addr(h.priv, PortAgentAPI)
	for range 2 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(testwait.Limit(t)))
		if err := echo(c, "held"); err != nil {
			t.Fatal(err)
		}
	}
	for range 25 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		closed(t, c)
		_ = c.Close()
	}
	const line = `msg="connection refused: the connection cap is reached"`
	if n := h.log.count(line); n != rateLines {
		t.Fatalf("%d refusal lines, want %d", n, rateLines)
	}
	h.fc.Advance(rateWindow)
	h.log.waitFor(t, `msg="refusals suppressed" listener=egress-agent-api count=15`, 1)
	if n := h.log.count(line); n != rateLines {
		t.Fatalf("%d refusal lines, want %d", n, rateLines)
	}
}
