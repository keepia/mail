package join

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/keepia/mail/internal/pki"
)

// ErrServer is wrapped by every refusal of the join listener's identity.
var ErrServer = errors.New("the join listener is not control")

// CheckServer is the first step of a join on the agent (CD22, C5): among
// the certificates the join listener presents after its leaf, one must be
// the anchor the token pins (SHA-256 of its SPKI), and the leaf must chain
// to it with serverAuth, the DNS name control.keepia.internal and a
// current validity. Revocation is checked next, against the fetched list
// (VerifyFetchedLists, CheckLeaf). It returns the leaf and the pinned
// anchor.
func CheckServer(peer []*x509.Certificate, pin [32]byte, now time.Time) (leaf, anchor *x509.Certificate, err error) {
	if len(peer) < 2 {
		return nil, nil, fmt.Errorf("%w: it presents no anchor after its certificate", ErrServer)
	}
	for _, c := range peer[1:] {
		if c != nil && c.IsCA && pinMatches(c, pin) {
			anchor = c
		}
	}
	if anchor == nil {
		return nil, nil, fmt.Errorf("%w: no presented anchor matches the token's pin", ErrServer)
	}
	leaf, err = pki.VerifyServerChain(peer[:1], anchor, pki.ControlGateName, now)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrServer, err)
	}
	return leaf, anchor, nil
}

// Conn is the agent's connection to the join listener (N4 builds it on
// TLS and HTTP). The calls happen in this order, and Redeem only after the
// first two have cleared the listener.
type Conn interface {
	// PeerCertificates is the chain the listener presented, leaf first.
	PeerCertificates() []*x509.Certificate
	// FetchLists fetches the lists response, without the token or any
	// other credential.
	FetchLists(ctx context.Context) ([]byte, error)
	// Redeem sends the token and the CSR, and returns control's response.
	Redeem(ctx context.Context, token string, csrDER []byte) (*Response, error)
}

// Joined is the result of a join that passed every check.
type Joined struct {
	AgentCert     *x509.Certificate
	ServiceAnchor *x509.Certificate
	ServiceCRL    *pki.CRL
}

// Join is the agent's join (CD22 in C5's order). Any failure aborts it,
// and the caller writes nothing:
//
//  1. the listener's leaf is checked against the token's pin (CheckServer);
//  2. the lists are fetched with no token sent, and the service list is
//     accepted only through VerifyFetchedLists with the pinned anchor as
//     the held one; the leaf is checked against it (CheckLeaf);
//  3. only then are the token and the CSR sent;
//  4. the response must carry the pinned anchor, a service list that
//     passes CD37 against the fetched one and still clears the leaf, and
//     an agent certificate for key with the URI keepia:agent:<id>.
func Join(ctx context.Context, c Conn, t Token, csrDER []byte, key *ecdsa.PublicKey, now time.Time) (*Joined, error) {
	leaf, anchor, err := CheckServer(c.PeerCertificates(), t.Pin, now)
	if err != nil {
		return nil, err
	}
	body, err := c.FetchLists(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch the lists: %w", err)
	}
	held := map[pki.AnchorName]*x509.Certificate{pki.AnchorService: anchor}
	lists, err := VerifyFetchedLists(ParseLists(body), held, nil, now)
	if err != nil {
		return nil, err
	}
	if err := CheckLeaf(leaf, lists[pki.AnchorService]); err != nil {
		return nil, err
	}
	resp, err := c.Redeem(ctx, t.String(), csrDER)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(resp.ServiceAnchor, anchor.Raw) {
		return nil, fmt.Errorf("%w: the response's service anchor is not the pinned one", ErrServer)
	}
	crl, err := pki.VerifyCRL(resp.ServiceCRL, anchor, lists[pki.AnchorService], now)
	if err != nil {
		return nil, fmt.Errorf("the response's service list: %w", err)
	}
	if err := CheckLeaf(leaf, crl); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(resp.AgentCert)
	if err != nil {
		return nil, errors.New("the response's agent certificate does not parse")
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(key) {
		return nil, errors.New("the response's agent certificate is not for this key")
	}
	if len(cert.URIs) != 1 || cert.URIs[0].Scheme != "keepia" || !bytes.HasPrefix([]byte(cert.URIs[0].Opaque), []byte(string(pki.PurposeAgent)+":")) {
		return nil, errors.New("the response's certificate is not an agent certificate")
	}
	return &Joined{AgentCert: cert, ServiceAnchor: anchor, ServiceCRL: crl}, nil
}
