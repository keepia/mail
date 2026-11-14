package gate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/proxyproto"
)

// errNoMaterial refuses a handshake that has no material to use.
var errNoMaterial = errors.New("no material for this listener")

// errHandshakeTimeout is the cause of a handshake cut at handshakeTimeout.
var errHandshakeTimeout = errors.New("handshake timeout")

// release frees a connection's slot of the cap.
func (g *Gate) release() {
	g.conns.release()
	if h := g.hooks.released; h != nil {
		h()
	}
}

// proxied is one forwarded connection.
type proxied struct {
	grp *group
	// raw is the accepted TCP connection; closing it ends the session
	// without waiting for a close_notify to be written.
	raw net.Conn
	// chain and id are an ingress client's verified certificate chain
	// and identity (nil for the join listener and egress).
	chain []*x509.Certificate
	id    pki.Identity
	// notAfter closes the connection at the client leaf's NotAfter (G6).
	notAfter Timer

	mu     sync.Mutex
	target net.Conn
	closed bool
}

// close ends the connection on both sides; it is safe to call more than
// once and from any goroutine.
func (p *proxied) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	t := p.target
	p.mu.Unlock()
	_ = p.raw.Close()
	if t != nil {
		_ = t.Close()
	}
}

func (p *proxied) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// setTarget attaches the dialled target; false (and the target closed)
// when the connection was closed meanwhile.
func (p *proxied) setTarget(t net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = t.Close()
		return false
	}
	p.target = t
	return true
}

// accept serves one listener socket until it closes.
func (g *Gate) accept(grp *group, ln net.Listener) {
	defer g.wg.Done()
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A resource error such as EMFILE: back off as net/http does.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			g.rate.warn(grp.spec.Name, "accept failed", "err", err.Error())
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		if !g.conns.acquire() {
			g.rate.warn(grp.spec.Name, "connection refused: the connection cap is reached", "peer", c.RemoteAddr().String(), "max", g.cfg.MaxConns)
			_ = c.Close()
			continue
		}
		g.wg.Add(1)
		if grp.spec.Mode == Ingress {
			go g.serveIngress(grp, c)
		} else {
			go g.serveEgress(grp, c)
		}
	}
}

// handshake is one ingress handshake's state: the material snapshot it
// took, once, and the verified client.
type handshake struct {
	g    *Gate
	spec Spec
	snap *material
	// verified: VerifyConnection ran; err is its result.
	verified bool
	err      error
	chain    []*x509.Certificate
	id       pki.Identity
}

// config is the connection's TLS configuration. By itself it completes
// no handshake (N6): it has no certificate and refuses every client.
// Only GetConfigForClient's per-generation configuration can.
func (h *handshake) config() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		ClientAuth:             tls.RequireAnyClientCert,
		GetCertificate:         func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errNoMaterial },
		VerifyConnection:       func(tls.ConnectionState) error { return errNoMaterial },
		GetConfigForClient:     h.forClient,
	}
}

// forClient takes the material snapshot of this handshake (G4): the
// served chain, the anchor and the list all come from the same
// generation.
func (h *handshake) forClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	m := h.g.mat.Load()
	if m == nil || !m.allows(h.spec, h.g.clock.Now()) {
		return nil, errNoMaterial
	}
	h.snap = m
	c := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{*m.cert},
		Time:                   h.g.clock.Now,
	}
	if h.spec.Anchor == "" {
		// The join listener: no CertificateRequest, no list (C5).
		c.ClientAuth = tls.NoClientCert
		return c, nil
	}
	// RequireAnyClientCert: Go builds no chain of its own, which would
	// read a missing EKU as any use; VerifyClient is the only check.
	c.ClientAuth = tls.RequireAnyClientCert
	c.ClientCAs = m.hints[h.spec.Anchor]
	anchor, list := m.anchors[h.spec.Anchor], m.lists[h.spec.Anchor]
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		id, err := pki.VerifyClient(cs.PeerCertificates, anchor, h.spec.Purposes, list, h.g.clock.Now())
		h.verified, h.err = true, err
		if hook := h.g.hooks.verified; hook != nil {
			hook(h.spec.Name, err)
		}
		if err != nil {
			return err
		}
		h.chain, h.id = cs.PeerCertificates, id
		return nil
	}
	return c, nil
}

// reason classifies a refused handshake for the log (G14).
func (h *handshake) reason(err, cause error) string {
	if h.verified && h.err != nil {
		return refusalClass(h.err)
	}
	switch s := err.Error(); {
	case errors.Is(cause, errHandshakeTimeout):
		return "handshake timeout"
	case cause != nil:
		// Run's context ended: the gate stops.
		return "gate stopping"
	case errors.Is(err, errNoMaterial):
		return "no material"
	case strings.Contains(s, "didn't provide a certificate"):
		return "no certificate"
	case strings.Contains(s, "unsupported versions") || strings.Contains(s, "protocol version"):
		return "TLS version"
	default:
		return "handshake failed: " + s
	}
}

// refusalClass is the log class of a VerifyClient refusal.
func refusalClass(err error) string {
	switch {
	case errors.Is(err, pki.ErrRevoked):
		return "revoked"
	case errors.Is(err, pki.ErrCRLExpired):
		return "list expired"
	default:
		return "refused: " + err.Error()
	}
}

// serveIngress terminates mTLS on raw and forwards the session (G4).
func (g *Gate) serveIngress(grp *group, raw net.Conn) {
	defer g.wg.Done()
	defer g.release()
	start := g.clock.Now()
	peer := raw.RemoteAddr().String()
	h := &handshake{g: g, spec: grp.spec}
	tc := tls.Server(raw, h.config())
	// The cause tells the handshake bound from the end of Run.
	ctx, cancel := context.WithCancelCause(g.ctx)
	t := g.clock.AfterFunc(handshakeTimeout, func() { cancel(errHandshakeTimeout) })
	err := tc.HandshakeContext(ctx)
	t.Stop()
	cause := context.Cause(ctx)
	cancel(nil)
	if err != nil {
		_ = raw.Close()
		g.rate.warn(grp.spec.Name, "handshake refused", "peer", peer, "reason", h.reason(err, cause))
		return
	}
	p := &proxied{grp: grp, raw: raw, chain: h.chain, id: h.id}
	if err := g.register(p, h.snap); err != nil {
		_ = raw.Close()
		g.rate.warn(grp.spec.Name, "connection refused", "peer", peer, "reason", err.Error())
		return
	}
	defer g.unregister(p)
	target, err := g.dial(netip.AddrPortFrom(g.cfg.Target, grp.spec.TargetPort))
	if err != nil {
		p.close()
		g.rate.warn(grp.spec.Name, "target unreachable", "peer", peer, "err", err.Error())
		return
	}
	if !p.setTarget(target) {
		return
	}
	if grp.spec.Proxy {
		if err := writeProxyHeader(target, raw, h.chain[0]); err != nil {
			p.close()
			g.rate.warn(grp.spec.Name, "PROXY header not sent", "peer", peer, "err", err.Error())
			return
		}
	}
	in, out := pipe(p, tc, target, false)
	identity, serial := "none", ""
	if h.chain != nil {
		identity = fmt.Sprintf("%s:%d", h.id.Purpose, h.id.ServerID)
		serial = h.chain[0].SerialNumber.Text(16)
	}
	g.log.Info("connection closed", "listener", grp.spec.Name, "peer", peer, "identity", identity, "serial", serial,
		"bytes in", in, "bytes out", out, "duration", g.clock.Now().Sub(start).String())
}

// writeProxyHeader sends the PROXY v2 header with the verified leaf (G9):
// the source is the client as the gate accepted it.
func writeProxyHeader(target, client net.Conn, leaf *x509.Certificate) error {
	src, ok1 := client.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := client.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return errors.New("not a TCP connection")
	}
	b, err := proxyproto.Encode(proxyproto.Header{Source: src.AddrPort(), Destination: dst.AddrPort(), LeafDER: leaf.Raw})
	if err != nil {
		return err
	}
	_, err = target.Write(b)
	return err
}

// register adds an ingress connection after its handshake. A handshake
// that took an older snapshot is verified again against the applied
// material, so a swap between the two cannot let it escape the re-check
// (G6). It arms the close at the client leaf's NotAfter.
func (g *Gate) register(p *proxied, snap *material) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped || p.grp.lns == nil {
		return errors.New("the listener has stopped")
	}
	now := g.clock.Now()
	if cur := g.mat.Load(); cur != snap && p.chain != nil {
		if err := cur.verify(p, now); err != nil {
			return errors.New(refusalClass(err))
		}
	}
	g.add(p)
	if p.chain != nil {
		p.notAfter = g.clock.AfterFunc(p.chain[0].NotAfter.Sub(now), func() {
			g.log.Info("connection closed: the client leaf expired", "listener", p.grp.spec.Name,
				"identity", fmt.Sprintf("%s:%d", p.id.Purpose, p.id.ServerID), "serial", p.chain[0].SerialNumber.Text(16))
			p.close()
		})
	}
	return nil
}

func (g *Gate) add(p *proxied) {
	p.grp.conns[p] = struct{}{}
}

// unregister removes a connection that has ended.
func (g *Gate) unregister(p *proxied) {
	p.close()
	g.mu.Lock()
	delete(p.grp.conns, p)
	g.mu.Unlock()
	if p.notAfter != nil {
		p.notAfter.Stop()
	}
}

// verify checks an open connection's client chain against m at now.
func (m *material) verify(p *proxied, now time.Time) error {
	s := p.grp.spec
	_, err := pki.VerifyClient(p.chain, m.anchors[s.Anchor], s.Purposes, m.lists[s.Anchor], now)
	return err
}

// recheck closes every open ingress connection that m refuses at now: a
// revoked certificate, another anchor, a list now missing (G6). g.mu held.
func (g *Gate) recheck(m *material, now time.Time) {
	for _, grp := range g.ingress {
		if grp.spec.Anchor == "" {
			continue
		}
		for p := range grp.conns {
			if p.isClosed() {
				continue
			}
			if err := m.verify(p, now); err != nil {
				p.close()
				g.rate.warn(grp.spec.Name, "connection closed: refused by the current material", "peer", p.raw.RemoteAddr().String(),
					"identity", fmt.Sprintf("%s:%d", p.id.Purpose, p.id.ServerID), "serial", p.chain[0].SerialNumber.Text(16),
					"reason", refusalClass(err))
			}
		}
	}
}

// dial dials a target or remote within dialTimeout of the gate's clock.
func (g *Gate) dial(addr netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	t := g.clock.AfterFunc(dialTimeout, cancel)
	defer t.Stop()
	return g.opt.Dial(ctx, "tcp", addr.String())
}

// copyBufSize is the pooled copy buffer per direction of an ingress
// session (V1). 4 KiB instead of io.Copy's 32 KiB (or one 16 KiB record)
// saves about 22 KiB per session against 16 KiB buffers; the gate then
// writes records of at most 4 KiB, 22 bytes of overhead each.
const copyBufSize = 4 << 10

var copyBufs = sync.Pool{New: func() any { b := make([]byte, copyBufSize); return &b }}

// pipe copies both ways with half-close until both directions end, then
// closes p. It returns the bytes from the client and to the client. For
// egress (splice) both sides are TCP connections and io.Copy moves the
// bytes in the kernel (G7); for ingress a pooled buffer per direction
// replaces io.Copy's 32 KiB.
func pipe(p *proxied, client, target net.Conn, splice bool) (in, out int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out = half(p, client, target, splice)
	}()
	in = half(p, target, client, splice)
	wg.Wait()
	p.close()
	return in, out
}

// half copies src to dst. At src's end it closes dst's write side, so the
// other direction goes on (half-close); on an error it ends both.
func half(p *proxied, dst, src net.Conn, splice bool) int64 {
	var n int64
	var err error
	if splice {
		n, err = io.Copy(dst, src)
	} else {
		bp := copyBufs.Get().(*[]byte)
		// The wrappers hide ReadFrom and WriteTo, which would allocate a
		// 32 KiB buffer of their own.
		n, err = io.CopyBuffer(writerOnly{dst}, readerOnly{src}, *bp)
		copyBufs.Put(bp)
	}
	if err != nil {
		p.close()
		return n
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		if cw.CloseWrite() == nil {
			return n
		}
	}
	p.close()
	return n
}

type readerOnly struct{ io.Reader }

type writerOnly struct{ io.Writer }
