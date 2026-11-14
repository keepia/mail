package gate

import (
	"errors"
	"net"
	"net/netip"
)

// serveEgress passes one connection through to its group's remote (G7):
// no TLS, no key, no parsing. A remote that refuses or does not answer
// within the dial timeout closes the client at once, so the caller
// tempfails (R-TEMPFAIL).
func (g *Gate) serveEgress(grp *group, c net.Conn) {
	defer g.wg.Done()
	defer g.conns.release()
	start := g.clock.Now()
	peer := c.RemoteAddr().String()
	p := &proxied{grp: grp, raw: c}
	remote, store, err := g.registerEgress(p)
	if err != nil {
		_ = c.Close()
		return
	}
	defer g.unregister(p)
	t, err := g.dial(remote)
	if err != nil {
		p.close()
		g.rate.warn(grp.spec.Name, "remote unreachable", "peer", peer, "remote", remote.String(), "err", err.Error())
		return
	}
	if !p.setTarget(t) {
		return
	}
	_, ct := c.(*net.TCPConn)
	_, tt := t.(*net.TCPConn)
	in, out := pipe(p, c, t, ct && tt)
	args := []any{"listener", grp.spec.Name, "peer", peer, "remote", remote.String(),
		"bytes in", in, "bytes out", out, "duration", g.clock.Now().Sub(start).String()}
	if store != "" {
		args = append(args, "store", store)
	}
	g.log.Info("connection closed", args...)
}

// registerEgress adds an egress connection and returns its group's remote
// and store at this moment: a route whose remote changes closes the
// connections it holds (N7), so a connection never outlives its remote.
func (g *Gate) registerEgress(p *proxied) (netip.AddrPort, string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped || p.grp.lns == nil {
		return netip.AddrPort{}, "", errors.New("the listener has stopped")
	}
	g.add(p)
	return p.grp.remote, p.grp.store, nil
}
