package gate

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/proxyproto"
)

// sendCert makes the client present cert whatever the server's
// CertificateRequest names, so the server's own check is what refuses it.
func sendCert(c *tls.Config, cert *tls.Certificate) *tls.Config {
	c.Certificates = nil
	c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	return c
}

// craftClient is a client certificate of Keepia's profile with the
// fields a test changes.
func craftClient(t testing.TB, a *pki.Anchor, uri string, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) issued {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	return craft(t, a, &x509.Certificate{
		Subject:               pkix.Name{CommonName: uri},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage:           eku,
		URIs:                  []*url.URL{u},
	})
}

var clientAuth = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

// U1: a right edge-dovecot certificate reaches each store target through
// its listener, and the close line names the identity and the serial.
func TestIngressServesRightCertificate(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	client := h.f.edgeDovecot(7, h.fc.Now())
	for _, c := range []struct {
		port, target uint16
	}{{PortIMAP, 143}, {PortPOP3, 110}, {PortLMTP, 24}} {
		tg := h.target(c.target)
		tc, err := h.dialTLS(h.addr(h.mesh, c.port), sendCert(h.clientConfig(nil), client.tlsCert()))
		if err != nil {
			t.Fatal(err)
		}
		if err := echo(tc, "a1 CAPABILITY\r\n"); err != nil {
			t.Fatalf("port %d: %v", c.port, err)
		}
		if tg.count() != 1 {
			t.Fatalf("port %d: the target saw %d connections", c.port, tg.count())
		}
		if got := tg.conn(0).bytes(); string(got) != "a1 CAPABILITY\r\n" {
			t.Errorf("port %d: the target got %q", c.port, got)
		}
		_ = tc.Close()
	}
	line := `identity=edge-dovecot:7 serial=` + client.cert.SerialNumber.Text(16)
	h.log.waitFor(t, line, 3)
	for _, l := range []string{`listener=imap`, `listener=pop3`, `listener=lmtp`} {
		if !strings.Contains(h.log.String(), l) {
			t.Errorf("no close line with %s", l)
		}
	}
}

// ingressRefuses asserts that cert is refused at the store's IMAP
// listener and that the target sees no connection.
func ingressRefuses(t *testing.T, h *harness, cert *tls.Certificate, reason string) {
	t.Helper()
	tg := h.target(143)
	cfg := h.clientConfig(nil)
	if cert != nil {
		cfg = sendCert(cfg, cert)
	}
	before := h.log.count(`msg="handshake refused"`)
	tc, err := h.dialTLS(h.addr(h.mesh, PortIMAP), cfg)
	if err == nil {
		refused(t, tc)
	}
	h.log.waitFor(t, `msg="handshake refused"`, before+1)
	if tg.count() != 0 {
		t.Fatalf("the target saw %d connections", tg.count())
	}
	if reason != "" && !strings.Contains(h.log.String(), reason) {
		t.Errorf("no refusal with %q", reason)
	}
}

// U2: a certificate of another anchor is refused: an agent certificate,
// and one from a second store-client anchor with the same subject.
func TestIngressRefusesWrongAnchor(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	agent := issue(t, h.f.agent, clientLeaf(t, pki.PurposeAgent, 7), h.fc.Now())
	ingressRefuses(t, h, agent.tlsCert(), "refused: ")
	twin := newAnchor(t, pki.AnchorStoreClient, h.fc.Now())
	if twin.Cert.Subject.String() != h.f.storeClient.Cert.Subject.String() {
		t.Fatal("the second anchor's subject differs")
	}
	other := issue(t, twin, clientLeaf(t, pki.PurposeEdgeDovecot, 7), h.fc.Now())
	ingressRefuses(t, h, other.tlsCert(), "refused: ")
}

// U3: a store-client certificate with another client purpose is refused.
func TestIngressRefusesWrongPurpose(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	now := h.fc.Now()
	c := craftClient(t, h.f.storeClient, "keepia:keepia-edge:1", now.Add(-time.Hour), now.Add(24*time.Hour), clientAuth)
	ingressRefuses(t, h, c.tlsCert(), "is not accepted here")
}

// U4: a missing or wrong EKU is refused: none, serverAuth only, and
// clientAuth with serverAuth.
func TestIngressRefusesWrongEKU(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	now := h.fc.Now()
	for name, eku := range map[string][]x509.ExtKeyUsage{
		"none":        nil,
		"server only": {x509.ExtKeyUsageServerAuth},
		"both":        {x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	} {
		t.Run(name, func(t *testing.T) {
			c := craftClient(t, h.f.storeClient, "keepia:edge-dovecot:3", now.Add(-time.Hour), now.Add(24*time.Hour), eku)
			ingressRefuses(t, h, c.tlsCert(), "")
		})
	}
}

// U5: a certificate is refused after its NotAfter and before its
// NotBefore.
func TestIngressRefusesOutsideValidity(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	now := h.fc.Now()
	early := craftClient(t, h.f.storeClient, "keepia:edge-dovecot:3", now.Add(time.Second), now.Add(24*time.Hour), clientAuth)
	ingressRefuses(t, h, early.tlsCert(), "refused: ")
	late := craftClient(t, h.f.storeClient, "keepia:edge-dovecot:3", now.Add(-time.Hour), now.Add(time.Hour), clientAuth)
	h.fc.Advance(time.Hour + time.Second)
	ingressRefuses(t, h, late.tlsCert(), "refused: ")
}

// U6: a revoked certificate is refused, and an open session of a
// certificate closes once a list that names it is applied (G6).
func TestIngressRevocation(t *testing.T) {
	h := newHarness(t, RoleStore)
	revoked := h.f.edgeDovecot(8, h.fc.Now())
	h.startWith(revoked.cert)
	ingressRefuses(t, h, revoked.tlsCert(), "reason=revoked")

	client := h.f.edgeDovecot(9, h.fc.Now())
	tc, err := h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(tc, "a1 IDLE\r\n"); err != nil {
		t.Fatal(err)
	}
	h.provide(2, h.f.bundle(RoleStore, h.f.lists(RoleStore, 2, h.fc.Now(), revoked.cert, client.cert)))
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	closed(t, tc)
	h.log.waitFor(t, `msg="connection closed: refused by the current material"`, 1)
	tc2, err := h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err == nil {
		refused(t, tc2)
	}
}

// U7: without a client certificate the handshake fails and the target
// sees nothing.
func TestIngressRefusesNoCertificate(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	ingressRefuses(t, h, nil, "reason=\"no certificate\"")
}

// U22: a TLS 1.2 client is refused.
func TestIngressRefusesTLS12(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.startWith()
	client := h.f.edgeDovecot(7, h.fc.Now())
	cfg := sendCert(h.clientConfig(nil), client.tlsCert())
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	tg := h.target(143)
	tc, err := h.dialTLS(h.addr(h.mesh, PortIMAP), cfg)
	if err == nil {
		refused(t, tc)
	}
	h.log.waitFor(t, `reason="TLS version"`, 1)
	if tg.count() != 0 {
		t.Fatalf("the target saw %d connections", tg.count())
	}
}

// health asserts the gate's /healthz.
func (h *harness) health(code int, body string) {
	h.t.Helper()
	gotCode, gotBody := h.g.Health()
	if gotCode != code || gotBody != body {
		h.t.Fatalf("health %d %q, want %d %q", gotCode, gotBody, code, body)
	}
}

// U8: at the list's ValidUntil the listener stops and its sessions close,
// health turns 503; a fresh generation opens it again.
func TestIngressStopsAtListExpiry(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.target(143)
	h.startWith()
	h.health(http.StatusOK, "ready")
	client := h.f.edgeDovecot(7, h.fc.Now())
	tc, err := h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(tc, "a1 NOOP\r\n"); err != nil {
		t.Fatal(err)
	}
	h.fc.AdvanceTo(h.f.gate.cert.NotBefore.Add(5*time.Minute + pki.CRLLifetime))
	for _, port := range []uint16{PortIMAP, PortPOP3, PortLMTP} {
		dialRefused(t, h.addr(h.mesh, port))
	}
	closed(t, tc)
	h.health(http.StatusServiceUnavailable, "list of store-client expired")

	h.provide(2, h.f.bundle(RoleStore, h.f.lists(RoleStore, 2, h.fc.Now())))
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	h.health(http.StatusOK, "ready")
	tc, err = h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(tc, "a2 NOOP\r\n"); err != nil {
		t.Fatal(err)
	}
}

// shortGateLeaf replaces the fixture's gate leaf with one that expires in
// d.
func shortGateLeaf(t *testing.T, f *fixture, now time.Time, d time.Duration) {
	t.Helper()
	f.gate = craft(t, f.service, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "keepia:gate:control"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(d),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{f.gateName},
	})
}

// U8 (G5): at the gate leaf's NotAfter every ingress listener stops, the
// join listener too.
func TestIngressStopsAtLeafExpiry(t *testing.T) {
	h := newHarness(t, RoleControl)
	shortGateLeaf(t, h.f, h.fc.Now(), time.Hour)
	h.target(8082)
	h.startWith()
	tc, err := h.dialTLS(h.addr(h.mesh, PortJoin), h.clientConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(tc, "POST /join"); err != nil {
		t.Fatal(err)
	}
	h.fc.Advance(time.Hour)
	for _, ip := range []netip.Addr{h.mesh, h.priv} {
		dialRefused(t, h.addr(ip, PortAgentAPI))
		dialRefused(t, h.addr(ip, PortJoin))
	}
	closed(t, tc)
	h.health(http.StatusServiceUnavailable, "the gate's leaf has expired")
}

// U9: the join listener asks for no certificate, forwards the bytes
// unchanged and keeps listening with every list expired (C5), while the
// agent API stops.
func TestJoinListenerNeedsNoList(t *testing.T) {
	h := newHarness(t, RoleControl)
	tg := h.target(8082)
	h.startWith()
	asked := false
	join := func(ip netip.Addr, msg string) {
		t.Helper()
		cfg := h.clientConfig(nil)
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			asked = true
			return &tls.Certificate{}, nil
		}
		tc, err := h.dialTLS(h.addr(ip, PortJoin), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := echo(tc, msg); err != nil {
			t.Fatalf("%s: %v", ip, err)
		}
		_ = tc.Close()
	}
	msg := "POST /v1/join HTTP/1.1\r\n\r\n\x00\xff"
	join(h.mesh, msg)
	join(h.priv, msg)
	if asked {
		t.Error("the join listener sent a CertificateRequest")
	}
	if got := tg.conn(0).bytes(); string(got) != msg {
		t.Errorf("the target got %q", got)
	}
	h.fc.AdvanceTo(h.f.gate.cert.NotBefore.Add(5*time.Minute + pki.CRLLifetime))
	dialRefused(t, h.addr(h.mesh, PortAgentAPI))
	dialRefused(t, h.addr(h.priv, PortAgentAPI))
	join(h.mesh, "after expiry")
	join(h.priv, "after expiry")
	h.health(http.StatusServiceUnavailable, "list of agent expired")
}

// U18 (G9): the agent API's target gets a PROXY v2 header with the
// verified leaf before any byte of the client; the join and store targets
// get the client's bytes only.
func TestProxyHeaderOnAgentAPIOnly(t *testing.T) {
	h := newHarness(t, RoleControl)
	api, join := h.target(8081), h.target(8082)
	h.startWith()
	agent := issue(t, h.f.agent, clientLeaf(t, pki.PurposeAgent, 12), h.fc.Now())
	tc, err := h.dialTLS(h.addr(h.priv, PortAgentAPI), sendCert(h.clientConfig(nil), agent.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tc, "GET /v1/lists"); err != nil {
		t.Fatal(err)
	}
	// The echo returns the header first.
	hdr, err := proxyproto.Read(tc)
	if err != nil {
		t.Fatalf("no header first: %v", err)
	}
	buf := make([]byte, len("GET /v1/lists"))
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "GET /v1/lists" {
		t.Fatalf("after the header: %q %v", buf, err)
	}
	got := api.conn(0).bytes()
	th, err := proxyproto.Read(strings.NewReader(string(got)))
	if err != nil {
		t.Fatalf("the target's first bytes are no header: %v", err)
	}
	if string(th.LeafDER) != string(agent.cert.Raw) || string(hdr.LeafDER) != string(agent.cert.Raw) {
		t.Error("the header does not carry the agent's leaf")
	}
	local := tc.NetConn().LocalAddr().(*net.TCPAddr).AddrPort()
	if th.Source != local || th.Destination != netip.MustParseAddrPort(h.addr(h.priv, PortAgentAPI)) {
		t.Errorf("header %v -> %v, want %v -> %s", th.Source, th.Destination, local, h.addr(h.priv, PortAgentAPI))
	}

	jc, err := h.dialTLS(h.addr(h.mesh, PortJoin), h.clientConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(jc, "\r\n\r\n\x00\r\nQUIT\n"); err != nil {
		t.Fatal(err)
	}
	if got := join.conn(0).bytes(); string(got) != "\r\n\r\n\x00\r\nQUIT\n" {
		t.Errorf("the join target got %q", got)
	}
}

// U18: the store's targets get no header.
func TestNoProxyHeaderOnStore(t *testing.T) {
	h := newHarness(t, RoleStore)
	tg := h.target(24)
	h.startWith()
	client := h.f.edgeDovecot(7, h.fc.Now())
	tc, err := h.dialTLS(h.addr(h.mesh, PortLMTP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(tc, "LHLO edge\r\n"); err != nil {
		t.Fatal(err)
	}
	if got := tg.conn(0).bytes(); string(got) != "LHLO edge\r\n" {
		t.Errorf("the target got %q", got)
	}
}

// U23: a session closes at its client leaf's NotAfter.
func TestIngressClosesAtClientNotAfter(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.target(143)
	h.startWith()
	now := h.fc.Now()
	c := craftClient(t, h.f.storeClient, "keepia:edge-dovecot:4", now.Add(-time.Hour), now.Add(time.Hour), clientAuth)
	tc, err := h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), c.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(tc, "a1 IDLE\r\n"); err != nil {
		t.Fatal(err)
	}
	h.fc.Advance(time.Hour)
	closed(t, tc)
	h.log.waitFor(t, `msg="connection closed: the client leaf expired"`, 1)
}
