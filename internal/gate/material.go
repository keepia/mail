package gate

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/keepia/mail/internal/pki"
)

// Bundle is one generation's TLS material as the loader read it from the
// material directory (#108's gatebundle.Read in part 2: X108-1, X108-2).
// The gate checks it again here (G10) and verifies each list itself,
// because only the gate holds the lists it accepted before (CD37).
type Bundle struct {
	// Chain is the gate's leaf, then the service anchor (CD34).
	Chain []*x509.Certificate
	// Key is the leaf's private key.
	Key crypto.Signer
	// Anchors are the bundle's trust anchors by name.
	Anchors map[pki.AnchorName]*x509.Certificate
	// Lists are each anchor's revocation list (DER).
	Lists map[pki.AnchorName][]byte
}

// material is one applied generation: immutable once built, and swapped
// as a whole through one atomic pointer (G10), so a handshake never mixes
// the parts of two generations.
type material struct {
	gen uint64
	// cert is the served chain and key (nil for the edge gate).
	cert *tls.Certificate
	leaf *x509.Certificate
	// anchors and lists by anchor name. A list may have expired: it is
	// kept so that CD37's number check survives (N8) and so health can
	// name it. A nil list means none was ever accepted for the anchor.
	anchors map[pki.AnchorName]*x509.Certificate
	lists   map[pki.AnchorName]*pki.CRL
	// hints are the CertificateRequest's acceptable CA names per anchor;
	// verification stays in VerifyConnection (G4).
	hints map[pki.AnchorName]*x509.CertPool
	// routes are the edge gate's store routes (G8).
	routes []Route
}

// leafValid tells whether the gate's own leaf may be served at now. At its
// NotAfter it may not: every ingress listener stops then (G5).
func (m *material) leafValid(now time.Time) bool {
	return m != nil && m.leaf != nil && !now.Before(m.leaf.NotBefore) && now.Before(m.leaf.NotAfter)
}

// listValid tells whether the anchor's list is valid at now.
func (m *material) listValid(a pki.AnchorName, now time.Time) bool {
	l := m.lists[a]
	return l != nil && now.Before(l.ValidUntil())
}

// allows tells whether the ingress listener s may listen at now: the
// leaf is valid and, unless s needs no list (the join listener, C5), so
// is its anchor's list.
func (m *material) allows(s Spec, now time.Time) bool {
	if !m.leafValid(now) {
		return false
	}
	return s.Anchor == "" || m.listValid(s.Anchor, now)
}

// nextExpiry is the earliest leaf or list expiry after now, or zero.
func (m *material) nextExpiry(now time.Time) time.Time {
	var next time.Time
	consider := func(t time.Time) {
		if t.After(now) && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	if m.leaf != nil {
		consider(m.leaf.NotAfter)
	}
	for _, l := range m.lists {
		if l != nil {
			consider(l.ValidUntil())
		}
	}
	return next
}

// unhealthy is why the material does not serve every listener at now, or
// "" when it does.
func (m *material) unhealthy(r Role, now time.Time) string {
	if !hasBundle(r) {
		return ""
	}
	if !m.leafValid(now) {
		return "the gate's leaf has expired"
	}
	var expired []string
	for _, a := range requiredAnchors(r) {
		if a == pki.AnchorService {
			continue
		}
		if !m.listValid(a, now) {
			expired = append(expired, "list of "+string(a)+" expired")
		}
	}
	return strings.Join(expired, ", ")
}

// buildTLS checks a bundle for the role at now and returns its TLS part
// (G10). held is the material applied now, or nil: each list must pass
// pki.VerifyCRL against the held list of the same anchor (CD37). A list
// that has merely expired is accepted only when the held list is absent
// or expired as well, so a new generation never trades a fresh list for a
// stale one, and a gate that starts with stale lists still serves its
// join listener (C5). The held list is then kept (N8).
func buildTLS(r Role, b *Bundle, held *material, now time.Time) (*material, error) {
	if b == nil {
		return nil, errors.New("no bundle")
	}
	service := b.Anchors[pki.AnchorService]
	if service == nil {
		return nil, errors.New("the bundle has no service anchor")
	}
	if len(b.Chain) != 2 || b.Chain[0] == nil || b.Chain[1] == nil || !b.Chain[1].Equal(service) {
		return nil, errors.New("the chain is not the gate's leaf followed by the service anchor")
	}
	leaf := b.Chain[0]
	switch {
	case !now.Before(leaf.NotAfter):
		return nil, errors.New("the gate's leaf has expired")
	case now.Before(leaf.NotBefore):
		return nil, errors.New("the gate's leaf is not yet valid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(service)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, fmt.Errorf("the gate's leaf does not chain to the service anchor: %w", err)
	}
	if leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return nil, errors.New("the gate's leaf is not a serverAuth end-entity certificate")
	}
	if b.Key == nil {
		return nil, errors.New("the bundle has no key")
	}
	pub, ok := b.Key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(leaf.PublicKey) {
		return nil, errors.New("the key does not belong to the gate's leaf")
	}
	m := &material{
		cert: &tls.Certificate{
			Certificate: [][]byte{leaf.Raw, service.Raw},
			PrivateKey:  b.Key,
			Leaf:        leaf,
		},
		leaf:    leaf,
		anchors: map[pki.AnchorName]*x509.Certificate{},
		lists:   map[pki.AnchorName]*pki.CRL{},
		hints:   map[pki.AnchorName]*x509.CertPool{},
	}
	for _, a := range requiredAnchors(r) {
		if b.Anchors[a] == nil {
			return nil, fmt.Errorf("the bundle has no %s anchor", a)
		}
		if _, ok := b.Lists[a]; !ok && a != pki.AnchorService {
			return nil, fmt.Errorf("the bundle has no list of %s", a)
		}
	}
	names := make([]pki.AnchorName, 0, len(b.Lists))
	for a := range b.Lists {
		names = append(names, a)
	}
	slices.Sort(names)
	for name, cert := range b.Anchors {
		if cert == nil {
			return nil, fmt.Errorf("the anchor %s is empty", name)
		}
		m.anchors[name] = cert
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		m.hints[name] = pool
	}
	for _, name := range names {
		anchor := m.anchors[name]
		if anchor == nil {
			return nil, fmt.Errorf("the list of %s has no anchor in the bundle", name)
		}
		var prev *pki.CRL
		// A held list is compared only with a list of the same anchor:
		// the numbers of two anchors are unrelated.
		if held != nil && held.anchors[name] != nil && held.anchors[name].Equal(anchor) {
			prev = held.lists[name]
		}
		l, err := pki.VerifyCRL(b.Lists[name], anchor, prev, now)
		switch {
		case err == nil:
			m.lists[name] = l
		case errors.Is(err, pki.ErrCRLExpired):
			if prev != nil && now.Before(prev.ValidUntil()) {
				return nil, fmt.Errorf("the list of %s has expired while the held one is valid", name)
			}
			m.lists[name] = prev
		default:
			return nil, fmt.Errorf("the list of %s: %w", name, err)
		}
	}
	return m, nil
}

// describeLists is the applied lists for the log: number and valid-until
// per anchor, never their bytes.
func (m *material) describeLists() string {
	names := make([]string, 0, len(m.lists))
	for a := range m.lists {
		names = append(names, string(a))
	}
	slices.Sort(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		l := m.lists[pki.AnchorName(n)]
		if l == nil {
			parts = append(parts, n+": none")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: #%s until %s", n, l.Number, l.ValidUntil().UTC().Format(time.RFC3339)))
	}
	return strings.Join(parts, ", ")
}
