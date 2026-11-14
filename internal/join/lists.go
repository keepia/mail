package join

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/keepia/mail/internal/pki"
)

// ParseLists takes the revocation lists out of a lists response: the DER
// of every PEM block of type X509 CRL. Any other content of the response,
// PEM or not, is ignored (C5): the fetch yields lists and nothing else.
func ParseLists(body []byte) [][]byte {
	var out [][]byte
	rest := body
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type == "X509 CRL" {
			out = append(out, b.Bytes)
		}
	}
}

// ErrLists is wrapped by every refusal of VerifyFetchedLists.
var ErrLists = errors.New("fetched revocation lists refused")

// VerifyFetchedLists accepts lists fetched without authentication (CD30's
// exception, C5) only if each one authenticates itself: it is signed by an
// anchor the agent already holds (held), with that anchor's subject as
// its issuer, it is current at now (nextUpdate after now, thisUpdate at
// most 5 minutes ahead), and it passes CD37 against the list the agent
// holds for that anchor (heldLists, nil for none): a higher number, or
// the same number with identical bytes. One refused list, an unknown
// signer or two lists of one anchor refuse the whole fetch.
func VerifyFetchedLists(lists [][]byte, held map[pki.AnchorName]*x509.Certificate, heldLists map[pki.AnchorName]*pki.CRL, now time.Time) (map[pki.AnchorName]*pki.CRL, error) {
	out := make(map[pki.AnchorName]*pki.CRL, len(lists))
	for _, der := range lists {
		rl, err := x509.ParseRevocationList(der)
		if err != nil {
			return nil, fmt.Errorf("%w: a list does not parse", ErrLists)
		}
		var name pki.AnchorName
		for n, a := range held {
			if a != nil && bytes.Equal(rl.RawIssuer, a.RawSubject) {
				name = n
			}
		}
		if name == "" {
			return nil, fmt.Errorf("%w: a list of an anchor the agent does not hold", ErrLists)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: two lists of the anchor %s", ErrLists, name)
		}
		c, err := pki.VerifyCRL(der, held[name], heldLists[name], now)
		if err != nil {
			return nil, fmt.Errorf("%w: the list of %s: %w", ErrLists, name, err)
		}
		out[name] = c
	}
	return out, nil
}

// CheckLeaf checks the join listener's leaf against the service list the
// agent accepted (C5): no list, or a list that names the leaf, refuses.
func CheckLeaf(leaf *x509.Certificate, serviceList *pki.CRL) error {
	if serviceList == nil {
		return fmt.Errorf("%w: no service list", ErrLists)
	}
	if serviceList.IsRevoked(leaf.SerialNumber) {
		return fmt.Errorf("the join listener's certificate: %w", pki.ErrRevoked)
	}
	return nil
}
