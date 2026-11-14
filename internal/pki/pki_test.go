package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/keepia/mail/internal/pki"
)

// now is the tests' fixed clock.
var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

var deploymentID = []byte("0123456789abcdef")

func newAnchor(t *testing.T, name pki.AnchorName, at time.Time) *pki.Anchor {
	t.Helper()
	a, err := pki.NewAnchor(name, deploymentID, at)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func clientLeaf(t *testing.T, p pki.Purpose, id int64) pki.Leaf {
	t.Helper()
	l, err := pki.ClientLeaf(p, id)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func issue(t *testing.T, a *pki.Anchor, l pki.Leaf) *x509.Certificate {
	t.Helper()
	c, err := pki.Issue(a, l, newKey(t).Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// crl is an accepted list of a with the given revoked certificates.
func crl(t *testing.T, a *pki.Anchor, number int64, at time.Time, revoked ...*x509.Certificate) *pki.CRL {
	t.Helper()
	der := crlDER(t, a, number, at, revoked...)
	c, err := pki.VerifyCRL(der, a.Cert, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func crlDER(t *testing.T, a *pki.Anchor, number int64, at time.Time, revoked ...*x509.Certificate) []byte {
	t.Helper()
	var rs []pki.Revoked
	for _, c := range revoked {
		rs = append(rs, pki.Revoked{Serial: c.SerialNumber, RevokedAt: at, Reason: pki.ReasonCessationOfOperation, NotAfter: c.NotAfter})
	}
	der, err := pki.CreateCRL(a, number, rs, at)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// craft signs tmpl with a's key directly, bypassing Issue's profile: for
// certificates that Issue never makes.
func craft(t *testing.T, a *pki.Anchor, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = now.Add(-time.Hour), now.Add(24*time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, newKey(t).Public(), a.Signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

func critical(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Critical
		}
	}
	return false
}

// G1. The anchor profile of CD12 and C6.
func TestAnchorProfile(t *testing.T) {
	a := newAnchor(t, pki.AnchorService, now)
	c := a.Cert
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Errorf("basic constraints: CA %v, valid %v, pathlen %d, zero %v", c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, c.MaxPathLenZero)
	}
	if !critical(c, oidBasicConstraints) || !critical(c, oidKeyUsage) {
		t.Error("basic constraints or key usage not critical")
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage %v", c.KeyUsage)
	}
	if len(c.SubjectKeyId) == 0 {
		t.Error("no SubjectKeyId")
	}
	if c.Subject.CommonName != "Keepia Mail service anchor" || len(c.Subject.Organization) != 1 ||
		c.Subject.Organization[0] != "30313233343536373839616263646566" {
		t.Errorf("subject %v", c.Subject)
	}
	if !c.NotBefore.Equal(now.Add(-time.Hour)) || !c.NotAfter.Equal(now.Add(-time.Hour).Add(10*365*24*time.Hour)) {
		t.Errorf("validity %v to %v", c.NotBefore, c.NotAfter)
	}
	if c.SignatureAlgorithm != x509.ECDSAWithSHA256 || c.SerialNumber.BitLen() != 128 {
		t.Errorf("signature %v, serial of %d bits", c.SignatureAlgorithm, c.SerialNumber.BitLen())
	}
	if k, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		t.Errorf("key %T", c.PublicKey)
	}
}

// isDNSName is a host name check as OpenSSL-style CN fallbacks apply it:
// dot-separated labels of letters, digits and hyphens.
var isDNSName = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

// G4. No issued leaf's CN is a valid DNS name (C7), and its SANs follow
// CD13's rules.
func TestLeafCommonNames(t *testing.T) {
	service := newAnchor(t, pki.AnchorService, now)
	agent := newAnchor(t, pki.AnchorAgent, now)
	store := newAnchor(t, pki.AnchorStoreClient, now)
	gate, err := pki.GateLeaf(pki.RoleStore, "s1", 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		a      *pki.Anchor
		l      pki.Leaf
		wantCN string
	}{
		{agent, clientLeaf(t, pki.PurposeAgent, 7), "keepia:agent:7"},
		{store, clientLeaf(t, pki.PurposeEdgeDovecot, 7), "keepia:edge-dovecot:7"},
		{service, gate, "keepia:gate:store:7"},
		{service, pki.ControlGateLeaf(), "keepia:gate:control"},
	} {
		c := issue(t, tc.a, tc.l)
		cn := c.Subject.CommonName
		if cn != tc.wantCN || isDNSName.MatchString(cn) {
			t.Errorf("CN %q (want %q) must not be a DNS name", cn, tc.wantCN)
		}
		if tc.l.Purpose == pki.PurposeGate {
			if len(c.DNSNames) != 1 || len(c.URIs) != 0 || c.DNSNames[0] != tc.l.DNSName {
				t.Errorf("%s: SANs %v %v", cn, c.DNSNames, c.URIs)
			}
		} else if len(c.URIs) != 1 || len(c.DNSNames) != 0 || c.URIs[0].String() != cn {
			t.Errorf("%s: SANs %v %v", cn, c.DNSNames, c.URIs)
		}
	}
}

// P1, P2, P5. VerifyClient accepts the right anchor and purpose, and
// refuses another anchor's certificate and a purpose of another anchor.
func TestVerifyClient(t *testing.T) {
	store := newAnchor(t, pki.AnchorStoreClient, now)
	agent := newAnchor(t, pki.AnchorAgent, now)
	edge := issue(t, store, clientLeaf(t, pki.PurposeEdgeDovecot, 42))
	list := crl(t, store, 1, now)

	id, err := pki.VerifyClient([]*x509.Certificate{edge}, store.Cert, []pki.Purpose{pki.PurposeEdgeDovecot}, list, now)
	if err != nil || id != (pki.Identity{Purpose: pki.PurposeEdgeDovecot, ServerID: 42}) {
		t.Fatalf("P1: %+v, %v", id, err)
	}

	// P2: an agent certificate at a store-client listener.
	ag := issue(t, agent, clientLeaf(t, pki.PurposeAgent, 42))
	if _, err := pki.VerifyClient([]*x509.Certificate{ag}, store.Cert, []pki.Purpose{pki.PurposeEdgeDovecot}, list, now); !errors.Is(err, pki.ErrPeer) {
		t.Errorf("P2: agent certificate at a store-client listener: %v", err)
	}

	// P5: the store-client anchor signed a keepia-edge certificate (a test
	// profile: Issue refuses it).
	if _, err := pki.Issue(store, clientLeaf(t, pki.PurposeKeepiaEdge, 42), newKey(t).Public(), now); err == nil {
		t.Error("Issue signed keepia-edge with the store-client anchor")
	}
	ke := craft(t, store, &x509.Certificate{
		Subject: pkix.Name{CommonName: "keepia:keepia-edge:42"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
		URIs: []*url.URL{mustURL(t, "keepia:keepia-edge:42")},
	})
	if _, err := pki.VerifyClient([]*x509.Certificate{ke}, store.Cert, []pki.Purpose{pki.PurposeEdgeDovecot}, list, now); !errors.Is(err, pki.ErrPeer) {
		t.Errorf("P5: keepia-edge at an edge-dovecot listener: %v", err)
	}
	// A listener configured with purposes of two anchors is refused.
	if _, err := pki.VerifyClient([]*x509.Certificate{edge}, store.Cert, []pki.Purpose{pki.PurposeEdgeDovecot, pki.PurposeAgent}, list, now); err == nil {
		t.Error("a listener with purposes of two anchors accepted a certificate")
	}
}

// P3. Expired and not-yet-valid certificates are refused.
func TestVerifyClientValidity(t *testing.T) {
	store := newAnchor(t, pki.AnchorStoreClient, now)
	c := issue(t, store, clientLeaf(t, pki.PurposeEdgeDovecot, 1))
	purposes := []pki.Purpose{pki.PurposeEdgeDovecot}
	for _, tc := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"at NotAfter", c.NotAfter, true},
		{"NotAfter + 1 s", c.NotAfter.Add(time.Second), false},
		{"at NotBefore", c.NotBefore, true},
		{"NotBefore - 1 s", c.NotBefore.Add(-time.Second), false},
	} {
		// A list that is current at tc.at.
		list := crl(t, store, 1, tc.at)
		_, err := pki.VerifyClient([]*x509.Certificate{c}, store.Cert, purposes, list, tc.at)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// P4. A revoked certificate is refused, and so is any certificate without
// a current list of its anchor.
func TestVerifyClientRevoked(t *testing.T) {
	store := newAnchor(t, pki.AnchorStoreClient, now)
	other := newAnchor(t, pki.AnchorStoreClient, now)
	revoked := issue(t, store, clientLeaf(t, pki.PurposeEdgeDovecot, 1))
	fine := issue(t, store, clientLeaf(t, pki.PurposeEdgeDovecot, 2))
	list := crl(t, store, 2, now, revoked)
	purposes := []pki.Purpose{pki.PurposeEdgeDovecot}
	if _, err := pki.VerifyClient([]*x509.Certificate{revoked}, store.Cert, purposes, list, now); !errors.Is(err, pki.ErrRevoked) {
		t.Errorf("revoked: %v, want ErrRevoked", err)
	}
	if _, err := pki.VerifyClient([]*x509.Certificate{fine}, store.Cert, purposes, list, now); err != nil {
		t.Errorf("not revoked: %v", err)
	}
	if _, err := pki.VerifyClient([]*x509.Certificate{fine}, store.Cert, purposes, nil, now); err == nil {
		t.Error("accepted without a list")
	}
	if _, err := pki.VerifyClient([]*x509.Certificate{fine}, store.Cert, purposes, list, list.NextUpdate); !errors.Is(err, pki.ErrCRLExpired) {
		t.Errorf("list expired at use: %v, want ErrCRLExpired", err)
	}
	if _, err := pki.VerifyClient([]*x509.Certificate{fine}, store.Cert, purposes, crl(t, other, 1, now), now); err == nil {
		t.Error("accepted with another anchor's list")
	}
}

// P6. A server certificate used as a client is refused, and so are crafted
// certificates without an EKU, with two EKUs, with two URI SANs, or with a
// DNS SAN.
func TestVerifyClientShape(t *testing.T) {
	service := newAnchor(t, pki.AnchorService, now)
	list := crl(t, service, 1, now)
	purposes := []pki.Purpose{pki.PurposeStore}
	gate, err := pki.GateLeaf(pki.RoleStore, "s1", 3)
	if err != nil {
		t.Fatal(err)
	}
	server := issue(t, service, gate)
	if _, err := pki.VerifyClient([]*x509.Certificate{server}, service.Cert, purposes, list, now); !errors.Is(err, pki.ErrPeer) {
		t.Errorf("server certificate as a client: %v", err)
	}
	uri := mustURL(t, "keepia:store:3")
	base := func() *x509.Certificate {
		return &x509.Certificate{
			Subject: pkix.Name{CommonName: "keepia:store:3"}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
			URIs: []*url.URL{uri},
		}
	}
	// The crafted base itself passes, so each case fails on its one change.
	if _, err := pki.VerifyClient([]*x509.Certificate{craft(t, service, base())}, service.Cert, purposes, list, now); err != nil {
		t.Fatalf("crafted base certificate: %v", err)
	}
	cases := map[string]func(*x509.Certificate){
		"no EKU":       func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"two EKUs":     func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		"any EKU":      func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} },
		"two URI SANs": func(c *x509.Certificate) { c.URIs = append(c.URIs, mustURL(t, "keepia:store:4")) },
		"a DNS SAN":    func(c *x509.Certificate) { c.DNSNames = []string{"s1.store.keepia.internal"} },
		"CA:TRUE":      func(c *x509.Certificate) { c.IsCA = true },
		"bad URI":      func(c *x509.Certificate) { c.URIs = []*url.URL{mustURL(t, "keepia:store:03")} },
	}
	for name, change := range cases {
		tmpl := base()
		change(tmpl)
		c := craft(t, service, tmpl)
		if _, err := pki.VerifyClient([]*x509.Certificate{c}, service.Cert, purposes, list, now); !errors.Is(err, pki.ErrPeer) {
			t.Errorf("%s: %v, want ErrPeer", name, err)
		}
	}
}

// P7. A chain through an intermediate is refused: the anchor's pathlen:0.
func TestVerifyClientIntermediate(t *testing.T) {
	store := newAnchor(t, pki.AnchorStoreClient, now)
	ikey := newKey(t)
	itmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	ider, err := x509.CreateCertificate(rand.Reader, itmpl, store.Cert, ikey.Public(), store.Signer)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(ider)
	if err != nil {
		t.Fatal(err)
	}
	ltmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "keepia:edge-dovecot:1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{mustURL(t, "keepia:edge-dovecot:1")},
	}
	lder, err := x509.CreateCertificate(rand.Reader, ltmpl, inter, newKey(t).Public(), ikey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(lder)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pki.VerifyClient([]*x509.Certificate{leaf, inter}, store.Cert, []pki.Purpose{pki.PurposeEdgeDovecot}, crl(t, store, 1, now), now)
	if !errors.Is(err, pki.ErrPeer) {
		t.Errorf("chain through an intermediate: %v, want ErrPeer", err)
	}
}

// P8. Revocation lists: expiry, signer, issuer name, thisUpdate, and the
// number rule of CD37.
func TestVerifyCRL(t *testing.T) {
	a := newAnchor(t, pki.AnchorAgent, now)
	other := newAnchor(t, pki.AnchorAgent, now)
	held := crl(t, a, 5, now)

	der := crlDER(t, a, 5, now.Add(-time.Hour))
	if _, err := pki.VerifyCRL(der, a.Cert, nil, now.Add(-time.Hour).Add(7*24*time.Hour)); !errors.Is(err, pki.ErrCRLExpired) {
		t.Errorf("at nextUpdate: %v, want ErrCRLExpired", err)
	}
	if _, err := pki.VerifyCRL(der, a.Cert, nil, now.Add(-time.Hour).Add(7*24*time.Hour-time.Second)); err != nil {
		t.Errorf("one second before nextUpdate: %v", err)
	}
	if _, err := pki.VerifyCRL(crlDER(t, other, 6, now), a.Cert, held, now); !errors.Is(err, pki.ErrCRLInvalid) {
		t.Errorf("another anchor's list: %v", err)
	}
	// The same key under another subject: the signature verifies, the
	// issuer name does not match.
	renamed := &pki.Anchor{Name: a.Name, Signer: a.Signer, Cert: craftSelf(t, a, "Someone else")}
	if _, err := pki.VerifyCRL(crlDER(t, renamed, 6, now), a.Cert, held, now); !errors.Is(err, pki.ErrCRLInvalid) {
		t.Errorf("another issuer name: %v", err)
	}
	if _, err := pki.VerifyCRL(crlDER(t, a, 6, now.Add(5*time.Minute+time.Second)), a.Cert, held, now); !errors.Is(err, pki.ErrCRLInvalid) {
		t.Errorf("thisUpdate after now + 5 min: %v", err)
	}
	if _, err := pki.VerifyCRL(crlDER(t, a, 6, now.Add(5*time.Minute)), a.Cert, held, now); err != nil {
		t.Errorf("thisUpdate at now + 5 min: %v", err)
	}
	if _, err := pki.VerifyCRL(crlDER(t, a, 4, now), a.Cert, held, now); !errors.Is(err, pki.ErrCRLRollback) {
		t.Errorf("lower number: %v, want ErrCRLRollback", err)
	}
	if got, err := pki.VerifyCRL(held.Raw, a.Cert, held, now); err != nil || got.Number.Int64() != 5 {
		t.Errorf("equal number, identical bytes: %v", err)
	}
	if _, err := pki.VerifyCRL(crlDER(t, a, 5, now), a.Cert, held, now); !errors.Is(err, pki.ErrCRLConflict) {
		t.Errorf("equal number, other bytes: %v, want ErrCRLConflict", err)
	}
	if got, err := pki.VerifyCRL(crlDER(t, a, 6, now), a.Cert, held, now); err != nil || got.Number.Int64() != 6 {
		t.Errorf("higher number: %v", err)
	}
	if got := held.ValidUntil(); !got.Equal(now.Add(7 * 24 * time.Hour)) {
		t.Errorf("ValidUntil %v", got)
	}
}

// craftSelf is a self-signed CA certificate for a's key with another
// subject.
func craftSelf(t *testing.T, a *pki.Anchor, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		SubjectKeyId: a.Cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, a.Signer.Public(), a.Signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// P9. VerifyServer.
func TestVerifyServer(t *testing.T) {
	service := newAnchor(t, pki.AnchorService, now)
	gate, err := pki.GateLeaf(pki.RoleStore, "s1", 3)
	if err != nil {
		t.Fatal(err)
	}
	c := issue(t, service, gate)
	revoked := issue(t, service, gate)
	client := issue(t, service, clientLeaf(t, pki.PurposeStore, 3))
	list := crl(t, service, 1, now, revoked)
	name := "s1.store.keepia.internal"
	if err := pki.VerifyServer([]*x509.Certificate{c}, service.Cert, name, list, now); err != nil {
		t.Errorf("right name: %v", err)
	}
	if err := pki.VerifyServer([]*x509.Certificate{c}, service.Cert, "s2.store.keepia.internal", list, now); !errors.Is(err, pki.ErrPeer) {
		t.Errorf("wrong name: %v", err)
	}
	if err := pki.VerifyServer([]*x509.Certificate{c}, service.Cert, pki.ControlGateName, list, now); !errors.Is(err, pki.ErrPeer) {
		t.Errorf("a store gate as control: %v", err)
	}
	if err := pki.VerifyServer([]*x509.Certificate{client}, service.Cert, name, list, now); !errors.Is(err, pki.ErrPeer) {
		t.Errorf("client certificate: %v", err)
	}
	if err := pki.VerifyServer([]*x509.Certificate{revoked}, service.Cert, name, list, now); !errors.Is(err, pki.ErrRevoked) {
		t.Errorf("revoked: %v", err)
	}
	if err := pki.VerifyServer([]*x509.Certificate{c}, service.Cert, name, list, list.NextUpdate); !errors.Is(err, pki.ErrCRLExpired) {
		t.Errorf("stale list: %v", err)
	}
	ctl := issue(t, service, pki.ControlGateLeaf())
	if err := pki.VerifyServer([]*x509.Certificate{ctl}, service.Cert, pki.ControlGateName, list, now); err != nil {
		t.Errorf("control gate: %v", err)
	}
}

// P10. Lifetimes.
func TestLifetimes(t *testing.T) {
	a := newAnchor(t, pki.AnchorAgent, now)
	c := issue(t, a, clientLeaf(t, pki.PurposeAgent, 1))
	if d := c.NotAfter.Sub(c.NotBefore); d != 30*24*time.Hour+5*time.Minute {
		t.Errorf("leaf valid for %v", d)
	}
	if !c.NotBefore.Equal(now.Add(-5 * time.Minute)) {
		t.Errorf("NotBefore %v", c.NotBefore)
	}
	if pki.NeedsRenewal(c, c.NotBefore.Add(10*24*time.Hour-time.Second)) {
		t.Error("NeedsRenewal at 10 d - 1 s")
	}
	if !pki.NeedsRenewal(c, c.NotBefore.Add(10*24*time.Hour)) {
		t.Error("no NeedsRenewal at 10 d")
	}
	list := crl(t, a, 1, now)
	if d := list.NextUpdate.Sub(list.ThisUpdate); d != 7*24*time.Hour {
		t.Errorf("list valid for %v", d)
	}
	// An anchor that expires in 10 days clamps its leaves.
	old := newAnchor(t, pki.AnchorAgent, now.Add(-10*365*24*time.Hour+time.Hour+10*24*time.Hour))
	c = issue(t, old, clientLeaf(t, pki.PurposeAgent, 1))
	if !c.NotAfter.Equal(old.Cert.NotAfter) || !c.NotAfter.Before(now.Add(30*24*time.Hour)) {
		t.Errorf("leaf NotAfter %v, anchor NotAfter %v", c.NotAfter, old.Cert.NotAfter)
	}
}

// P11. CSRs give only their P-256 key.
func TestCSR(t *testing.T) {
	key := newKey(t)
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "control.keepia.internal"},
		DNSNames: []string{"control.keepia.internal"},
		URIs:     []*url.URL{mustURL(t, "keepia:agent:1")},
		ExtraExtensions: []pkix.Extension{{
			Id: oidBasicConstraints, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
		}},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pki.CSRPublicKey(der)
	if err != nil || !pub.Equal(key.Public()) {
		t.Fatalf("P-256 CSR: %v", err)
	}
	a := newAnchor(t, pki.AnchorAgent, now)
	c, err := pki.Issue(a, clientLeaf(t, pki.PurposeAgent, 9), pub, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsCA || len(c.DNSNames) != 0 || len(c.URIs) != 1 || c.URIs[0].String() != "keepia:agent:9" ||
		c.Subject.CommonName != "keepia:agent:9" {
		t.Errorf("issued certificate took the request's fields: CA %v, DNS %v, URIs %v, CN %q", c.IsCA, c.DNSNames, c.URIs, c.Subject.CommonName)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || c.KeyUsage != x509.KeyUsageDigitalSignature ||
		!critical(c, oidBasicConstraints) || !critical(c, oidKeyUsage) || len(c.AuthorityKeyId) == 0 {
		t.Errorf("leaf profile: EKU %v, KU %v", c.ExtKeyUsage, c.KeyUsage)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]any{"P-384": p384, "RSA": rsaKey} {
		d, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pki.CSRPublicKey(d); !errors.Is(err, pki.ErrCSR) {
			t.Errorf("%s CSR: %v, want ErrCSR", name, err)
		}
	}
	bad := append([]byte(nil), der...)
	bad[len(bad)-3] ^= 0x01
	if _, err := pki.CSRPublicKey(bad); !errors.Is(err, pki.ErrCSR) {
		t.Errorf("bad signature: %v, want ErrCSR", err)
	}
	if _, err := pki.Issue(a, clientLeaf(t, pki.PurposeAgent, 9), p384.Public(), now); !errors.Is(err, pki.ErrNotP256) {
		t.Errorf("Issue with a P-384 key: %v", err)
	}
}

// CD13's policy and CD14's names.
func TestPolicyAndNames(t *testing.T) {
	storeGate, err := pki.GateLeaf(pki.RoleStore, "s1", 1)
	if err != nil {
		t.Fatal(err)
	}
	edgeGate, err := pki.GateLeaf(pki.RoleEdge, "e1", 1)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []struct {
		l     pki.Leaf
		roles []string
	}{
		{clientLeaf(t, pki.PurposeAgent, 1), []string{"filter"}},
		{clientLeaf(t, pki.PurposeEdgeDovecot, 1), []string{"edge"}},
		{storeGate, []string{"store", "edge"}},
	}
	for _, a := range allowed {
		if err := pki.CheckPolicy(a.l, a.roles); err != nil {
			t.Errorf("%s for %v: %v", a.l.CommonName, a.roles, err)
		}
	}
	refused := []struct {
		l     pki.Leaf
		roles []string
	}{
		{clientLeaf(t, pki.PurposeEdgeDovecot, 1), []string{"store"}},
		{clientLeaf(t, pki.PurposeKeepiaEdge, 1), []string{"edge", "groupware"}},
		{clientLeaf(t, pki.PurposeStore, 1), []string{"store"}},
		{storeGate, []string{"edge"}},
		{edgeGate, []string{"edge"}},
		{pki.ControlGateLeaf(), []string{"control"}},
	}
	for _, r := range refused {
		if err := pki.CheckPolicy(r.l, r.roles); !errors.Is(err, pki.ErrPolicy) {
			t.Errorf("%s for %v: %v, want ErrPolicy", r.l.CommonName, r.roles, err)
		}
	}
	if storeGate.DNSName != "s1.store.keepia.internal" {
		t.Errorf("gate name %q", storeGate.DNSName)
	}
	for _, ok := range []string{"a", "s1", "mail-2", strings.Repeat("a", 63)} {
		if !pki.ValidServerName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A1", "a.b", "a_b", strings.Repeat("a", 64)} {
		if pki.ValidServerName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
