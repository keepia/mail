package gate

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keepia/mail/internal/testwait"
)

// get asks the gate's bound /healthz.
func (h *harness) get() (int, string) {
	h.t.Helper()
	h.g.mu.Lock()
	addr := h.g.healthAddr.String()
	h.g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Limit(h.t))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		h.t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// G12: /healthz answers over HTTP: waiting, ready, and 503 with the
// reason.
func TestHealthEndpoint(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.start()
	h.log.waitFor(t, `msg="waiting for material`, 1)
	if code, body := h.get(); code != http.StatusOK || body != "waiting for material\n" {
		t.Fatalf("waiting: %d %q", code, body)
	}
	h.provide(1, h.f.bundle(RoleStore, h.f.lists(RoleStore, 1, h.fc.Now())))
	h.log.waitFor(t, `msg="applied generation 1"`, 1)
	if code, body := h.get(); code != http.StatusOK || body != "ready\n" {
		t.Fatalf("ready: %d %q", code, body)
	}
	h.fc.Advance(8 * 24 * time.Hour)
	if code, body := h.get(); code != http.StatusServiceUnavailable || body != "list of store-client expired\n" {
		t.Fatalf("expired: %d %q", code, body)
	}
}

// G12: a static listener that cannot bind ends Run with an error, before
// any material is read.
func TestStaticBindFailureExits(t *testing.T) {
	h := newHarness(t, RoleStore)
	busy, err := net.Listen("tcp", h.addr(h.priv, PortJoin))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	h.writeGen(1)
	h.start()
	err = h.runErr()
	if err == nil || !strings.Contains(err.Error(), "egress-join") {
		t.Fatalf("Run: %v", err)
	}
	if h.loadCalls.Load() != 0 {
		t.Error("material was read")
	}
	dialRefused(t, h.addr(h.priv, PortAgentAPI))
}

// G2: a listener binds the gate's IPv6 address as well.
func TestIngressBindsIPv6(t *testing.T) {
	v6 := netip.MustParseAddr("::1")
	ln, err := net.Listen("tcp", netip.AddrPortFrom(v6, 0).String())
	if err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) {
			t.Skip("no IPv6 loopback")
		}
		t.Fatal(err)
	}
	_ = ln.Close()
	h := newHarness(t, RoleStore, func(h *harness) {
		h.cfg.Mesh = append(h.cfg.Mesh, v6)
		h.cfg.MeshNet = append(h.cfg.MeshNet, netip.MustParsePrefix("::1/128"))
	})
	h.target(143)
	h.startWith()
	client := h.f.edgeDovecot(7, h.fc.Now())
	for _, ip := range []netip.Addr{h.mesh, v6} {
		tc, err := h.dialTLS(h.addr(ip, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
		if err != nil {
			t.Fatal(err)
		}
		if err := echo(tc, "a1 NOOP"); err != nil {
			t.Fatalf("%s: %v", ip, err)
		}
	}
}
