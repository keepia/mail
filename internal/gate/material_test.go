package gate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/testwait"
)

// servedLeaf is the gate leaf a new handshake at the store's IMAP
// listener gets.
func (h *harness) servedLeaf(client issued) *x509.Certificate {
	h.t.Helper()
	tc, err := h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = tc.Close() }()
	return tc.ConnectionState().PeerCertificates[0]
}

// U10: each invalid generation is refused, logged, and the old material
// keeps serving.
func TestInvalidMaterialKeepsTheOld(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.bundle.Store(h.f.bundle(RoleStore, h.f.lists(RoleStore, 5, h.fc.Now())))
	h.writeGen(1)
	h.start()
	h.log.waitFor(t, `msg="applied generation 1"`, 1)
	held := h.bundle.Load()
	client := h.f.edgeDovecot(7, h.fc.Now())
	now := h.fc.Now()
	twin := newAnchor(t, pki.AnchorStoreClient, now)

	with := func(change func(b *Bundle)) *Bundle {
		b := h.f.bundle(RoleStore, map[pki.AnchorName][]byte{
			pki.AnchorService:     held.Lists[pki.AnchorService],
			pki.AnchorStoreClient: held.Lists[pki.AnchorStoreClient],
		})
		change(b)
		return b
	}
	expiredLeaf := craft(t, h.f.service, &x509.Certificate{
		Subject: pkix.Name{CommonName: "keepia:gate:store:1"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Second),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{h.f.gateName},
	})
	cases := []struct {
		name   string
		b      *Bundle
		reason string
	}{
		{"a key that does not match", with(func(b *Bundle) { b.Key = newKey(t) }), "the key does not belong"},
		{"a list of another anchor", with(func(b *Bundle) { b.Lists[pki.AnchorStoreClient] = listDER(t, twin, 6, now) }), "not signed by the anchor"},
		{"a lower list number", with(func(b *Bundle) { b.Lists[pki.AnchorStoreClient] = listDER(t, h.f.storeClient, 4, now) }), "rollback"},
		{"the same number, other bytes", with(func(b *Bundle) {
			b.Lists[pki.AnchorStoreClient] = listDER(t, h.f.storeClient, 5, now, client.cert)
		}), "conflict"},
		{"an expired leaf", with(func(b *Bundle) { b.Chain[0], b.Key = expiredLeaf.cert, expiredLeaf.key }), "the gate's leaf has expired"},
		{"an expired list while the held one is fresh", with(func(b *Bundle) {
			b.Lists[pki.AnchorStoreClient] = listDER(t, h.f.storeClient, 6, now.Add(-8*24*time.Hour))
		}), "has expired while the held one is valid"},
		{"no list", with(func(b *Bundle) { delete(b.Lists, pki.AnchorStoreClient) }), "no list of store-client"},
		{"no client anchor", with(func(b *Bundle) { delete(b.Anchors, pki.AnchorStoreClient) }), "no store-client anchor"},
		{"a chain without the anchor", with(func(b *Bundle) { b.Chain = b.Chain[:1] }), "the chain is not"},
	}
	for i, c := range cases {
		gen := uint64(i + 2)
		h.provide(gen, c.b)
		line := fmt.Sprintf(`msg="generation %d refused: `, gen)
		h.log.waitFor(t, line, 1)
		if !strings.Contains(h.log.String(), line) || !strings.Contains(h.log.String(), c.reason) {
			t.Errorf("%s: the refusal does not say %q", c.name, c.reason)
		}
		if got := h.servedLeaf(client); !got.Equal(h.f.gate.cert) {
			t.Fatalf("%s: the gate serves another leaf", c.name)
		}
	}
	h.health(http.StatusOK, "ready")
}

// U10: a handshake during a swap sees the old set or the new set, never
// a mix of the leaf of one and the list of the other.
func TestSwapIsAtomic(t *testing.T) {
	h := newHarness(t, RoleStore)
	inHook, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	// A failure before the release must not leave the swap blocked.
	t.Cleanup(unblock)
	h.g.hooks.beforeSwap = func() {
		if h.g.mat.Load() != nil {
			close(inHook)
			<-release
		}
	}
	verified := make(chan error, 4)
	h.g.hooks.verified = func(_ string, err error) { verified <- err }
	h.startWith()
	oldLeaf := h.f.gate.cert
	client := h.f.edgeDovecot(7, h.fc.Now())

	// Generation 2: a new leaf, and a list that revokes the client.
	h.f.newGateLeaf(RoleStore, h.fc.Now())
	newLeaf := h.f.gate.cert
	h.provide(2, h.f.bundle(RoleStore, h.f.lists(RoleStore, 2, h.fc.Now(), client.cert)))
	select {
	case <-inHook:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the swap hook did not run")
	}
	tc, err := h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	served := tc.ConnectionState().PeerCertificates[0]
	var verr error
	select {
	case verr = <-verified:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the server did not verify the client")
	}
	switch {
	case served.Equal(oldLeaf) && verr == nil:
		// The old set, whole.
	case served.Equal(newLeaf) && errors.Is(verr, pki.ErrRevoked):
		t.Fatal("the new set before the swap")
	default:
		t.Fatalf("a mix: new leaf %v, verify error %v", served.Equal(newLeaf), verr)
	}
	unblock()
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	// The session that verified against the old list is checked again.
	closed(t, tc)
	tc2, err := h.dialTLS(h.addr(h.mesh, PortIMAP), sendCert(h.clientConfig(nil), client.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if !tc2.ConnectionState().PeerCertificates[0].Equal(newLeaf) {
		t.Error("after the swap the old leaf is served")
	}
	refused(t, tc2)
}

// U11: without material no ingress listens, the static egress does, and
// health is 200 "waiting for material", with a WARN at start and hourly
// (V4).
func TestWaitingForMaterial(t *testing.T) {
	h := newHarness(t, RoleStore)
	h.start()
	warn := fmt.Sprintf(`msg="waiting for material in %s: no generation file"`, h.dir)
	h.log.waitFor(t, warn, 1)
	for _, port := range []uint16{PortIMAP, PortPOP3, PortLMTP} {
		dialRefused(t, h.addr(h.mesh, port))
	}
	for _, port := range []uint16{PortAgentAPI, PortJoin} {
		c, err := net.Dial("tcp", h.addr(h.priv, port))
		if err != nil {
			t.Fatalf("static egress %d: %v", port, err)
		}
		_ = c.Close()
	}
	h.health(http.StatusOK, "waiting for material")
	if h.loadCalls.Load() != 0 {
		t.Error("the bundle was loaded without a generation")
	}
	h.fc.Advance(time.Hour)
	h.log.waitFor(t, warn, 2)

	// The first generation ends the waiting.
	h.provide(1, h.f.bundle(RoleStore, h.f.lists(RoleStore, 1, h.fc.Now())))
	h.log.waitFor(t, `msg="applied generation 1"`, 1)
	h.health(http.StatusOK, "ready")
	h.fc.Advance(time.Hour)
	if h.log.count(warn) != 2 {
		t.Error("the WARN repeats after material arrived")
	}
}

// U11: a refused bundle at start is health 503 and no ingress.
func TestRefusedAtStart(t *testing.T) {
	h := newHarness(t, RoleStore)
	err := errors.New("bundle.pem: the key does not belong to the leaf")
	h.loadErr.Store(&err)
	h.writeGen(1)
	h.start()
	h.log.waitFor(t, `msg="generation 1 refused: the bundle does not load`, 1)
	h.health(http.StatusServiceUnavailable, "material refused")
	dialRefused(t, h.addr(h.mesh, PortIMAP))
	if strings.Contains(h.log.String(), "waiting for material") {
		t.Error("a refused bundle is reported as waiting")
	}
}

// G10, C5, N8: a gate that starts with expired lists accepts them, serves
// its join listener, keeps the agent API closed; a later generation with
// the same expired list keeps the held list (N8), and a fresh list opens
// the agent API.
func TestExpiredListsAtStart(t *testing.T) {
	h := newHarness(t, RoleControl)
	h.target(8082)
	h.target(8081)
	old := h.fc.Now().Add(-8 * 24 * time.Hour)
	stale := map[pki.AnchorName][]byte{
		pki.AnchorService: listDER(t, h.f.service, 3, old),
		pki.AnchorAgent:   listDER(t, h.f.agent, 3, old),
	}
	h.bundle.Store(h.f.bundle(RoleControl, stale))
	h.writeGen(1)
	h.start()
	h.log.waitFor(t, `msg="applied generation 1"`, 1)
	h.health(http.StatusServiceUnavailable, "list of agent expired")
	dialRefused(t, h.addr(h.mesh, PortAgentAPI))
	tc, err := h.dialTLS(h.addr(h.mesh, PortJoin), h.clientConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(tc, "GET /v1/lists"); err != nil {
		t.Fatal(err)
	}

	// No list was ever valid, so none is held: nothing to keep.
	if l := h.g.mat.Load().lists[pki.AnchorAgent]; l != nil {
		t.Fatal("an expired list became the held list")
	}
	// A fresh list #4 is held; then the same list again after it expired
	// keeps it (N8), and a lower number is still a rollback.
	fresh := h.f.lists(RoleControl, 4, h.fc.Now())
	h.provide(2, h.f.bundle(RoleControl, fresh))
	h.log.waitFor(t, `msg="applied generation 2"`, 1)
	h.health(http.StatusOK, "ready")
	agent := issue(t, h.f.agent, clientLeaf(t, pki.PurposeAgent, 3), h.fc.Now())
	ac, err := h.dialTLS(h.addr(h.mesh, PortAgentAPI), sendCert(h.clientConfig(nil), agent.tlsCert()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	h.fc.Advance(pki.CRLLifetime)
	h.provide(3, h.f.bundle(RoleControl, fresh))
	h.log.waitFor(t, `msg="applied generation 3"`, 1)
	if l := h.g.mat.Load().lists[pki.AnchorAgent]; l == nil || l.Number.Int64() != 4 {
		t.Fatalf("the held list is %v, want #4 (N8)", l)
	}
	h.provide(4, h.f.bundle(RoleControl, map[pki.AnchorName][]byte{
		pki.AnchorService: fresh[pki.AnchorService],
		pki.AnchorAgent:   listDER(t, h.f.agent, 3, h.fc.Now()),
	}))
	h.log.waitFor(t, `msg="generation 4 refused: the list of agent: revocation list rollback`, 1)
}
