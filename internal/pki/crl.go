package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Revocation reasons (RFC 5280 §5.3.1) that Keepia uses (CD17).
const (
	// ReasonKeyCompromise is reserved: no command revokes for it yet.
	ReasonKeyCompromise = 1
	// ReasonCessationOfOperation is the reason of a server removal.
	ReasonCessationOfOperation = 5
)

// Revoked is one revoked certificate of an anchor.
type Revoked struct {
	Serial    *big.Int
	RevokedAt time.Time
	Reason    int
	// NotAfter is the certificate's expiry: an expired certificate drops
	// out of the next list.
	NotAfter time.Time
}

// CreateCRL signs the anchor a's revocation list number (CD16): an X.509
// v2 CRL with thisUpdate = now and nextUpdate = now + 7 days, the anchor's
// AuthorityKeyId, and every entry of revoked whose certificate has not
// expired at now. The caller keeps the number strictly increasing per
// anchor.
func CreateCRL(a *Anchor, number int64, revoked []Revoked, now time.Time) ([]byte, error) {
	if number < 1 {
		return nil, fmt.Errorf("CRL number %d: want 1 or more", number)
	}
	now = now.UTC().Truncate(time.Second)
	var entries []x509.RevocationListEntry
	for _, r := range revoked {
		if !r.NotAfter.After(now) {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   r.Serial,
			RevocationTime: r.RevokedAt.UTC(),
			ReasonCode:     r.Reason,
		})
	}
	tmpl := &x509.RevocationList{
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		RevokedCertificateEntries: entries,
		Number:                    big.NewInt(number),
		ThisUpdate:                now,
		NextUpdate:                now.Add(CRLLifetime),
	}
	return x509.CreateRevocationList(rand.Reader, tmpl, a.Cert, a.Signer)
}

// Errors of VerifyCRL.
var (
	// ErrCRLExpired: now is at or after the list's nextUpdate.
	ErrCRLExpired = errors.New("revocation list expired")
	// ErrCRLRollback: the list's number is lower than the held list's.
	ErrCRLRollback = errors.New("revocation list rollback: its number is lower than the held list's")
	// ErrCRLConflict: the list has the held list's number but other bytes
	// (CD37).
	ErrCRLConflict = errors.New("revocation list conflict: the held list's number with other content")
	// ErrCRLInvalid: anything else that makes a list unacceptable.
	ErrCRLInvalid = errors.New("revocation list invalid")
)

// CRL is a revocation list that VerifyCRL accepted for one anchor.
type CRL struct {
	// Raw is the list as signed (DER).
	Raw        []byte
	Number     *big.Int
	ThisUpdate time.Time
	NextUpdate time.Time
	// anchor is the accepting anchor's certificate (DER), so a list is
	// used only with its own anchor: two anchors may share a subject.
	anchor  []byte
	revoked map[string]struct{}
}

// ValidUntil is the list's nextUpdate: a holder stops using it then (N3)
// or a margin before (N5).
func (c *CRL) ValidUntil() time.Time { return c.NextUpdate }

// IsRevoked tells whether the list names serial.
func (c *CRL) IsRevoked(serial *big.Int) bool {
	_, ok := c.revoked[string(serial.Bytes())]
	return ok
}

// VerifyCRL parses der and accepts it as the anchor's current list only if
// (CD16, CD37):
//
//   - the anchor signed it and its issuer is the anchor's subject;
//   - now is before its nextUpdate (ErrCRLExpired otherwise);
//   - its thisUpdate is at most 5 minutes after now;
//   - held is nil, or its number is greater than held's, or equal with
//     identical bytes (the same list again). An equal number with other
//     bytes is ErrCRLConflict, a lower number ErrCRLRollback.
func VerifyCRL(der []byte, anchor *x509.Certificate, held *CRL, now time.Time) (*CRL, error) {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("%w: it does not parse", ErrCRLInvalid)
	}
	if !bytes.Equal(rl.RawIssuer, anchor.RawSubject) {
		return nil, fmt.Errorf("%w: its issuer is not the anchor", ErrCRLInvalid)
	}
	if err := rl.CheckSignatureFrom(anchor); err != nil {
		return nil, fmt.Errorf("%w: not signed by the anchor", ErrCRLInvalid)
	}
	if rl.Number == nil || rl.Number.Sign() <= 0 {
		return nil, fmt.Errorf("%w: no CRL number", ErrCRLInvalid)
	}
	if rl.NextUpdate.IsZero() || !now.Before(rl.NextUpdate) {
		return nil, ErrCRLExpired
	}
	if rl.ThisUpdate.After(now.Add(CRLClockSkew)) {
		return nil, fmt.Errorf("%w: its thisUpdate is in the future", ErrCRLInvalid)
	}
	if held != nil {
		switch rl.Number.Cmp(held.Number) {
		case -1:
			return nil, ErrCRLRollback
		case 0:
			if !bytes.Equal(der, held.Raw) {
				return nil, ErrCRLConflict
			}
		}
	}
	c := &CRL{
		Raw:        bytes.Clone(der),
		Number:     rl.Number,
		ThisUpdate: rl.ThisUpdate,
		NextUpdate: rl.NextUpdate,
		anchor:     bytes.Clone(anchor.Raw),
		revoked:    make(map[string]struct{}, len(rl.RevokedCertificateEntries)),
	}
	for _, e := range rl.RevokedCertificateEntries {
		c.revoked[string(e.SerialNumber.Bytes())] = struct{}{}
	}
	return c, nil
}

// checkCurrent is the revocation check of a peer certificate: the list
// must be the anchor's, still valid at now, and must not name the serial.
func (c *CRL) checkCurrent(anchor *x509.Certificate, serial *big.Int, now time.Time) error {
	if c == nil {
		return errors.New("no revocation list: no connection without a valid list")
	}
	if !bytes.Equal(c.anchor, anchor.Raw) {
		return errors.New("the revocation list belongs to another anchor")
	}
	if !now.Before(c.NextUpdate) {
		return ErrCRLExpired
	}
	if c.IsRevoked(serial) {
		return ErrRevoked
	}
	return nil
}
