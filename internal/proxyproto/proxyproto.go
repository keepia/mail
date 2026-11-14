// Package proxyproto encodes and decodes the PROXY protocol version 2
// header that the control gate puts in front of every connection it
// forwards to the agent API (#97, G9). The header carries the address of
// the agent's connection as the gate accepted it, and one TLV of type
// TypeLeafDER: the agent's client certificate (DER), which the gate has
// verified with pki.VerifyClient.
//
// The format is the HAProxy specification's version 2 binary header. Only
// what the gate sends is accepted: the command PROXY, TCP over IPv4 or
// IPv6, and exactly one TLV, the leaf. Decode reads at most MaxHeader
// bytes, under a deadline, and never reads past the header.
//
// The leaf in the header is not a secret and proves nothing by itself:
// the receiver (serve, #98) accepts a header only from the control gate's
// fixed addresses, refuses every connection without one, and verifies the
// leaf again against its own anchor and list.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// TypeLeafDER is the TLV type of the verified client leaf (DER). It lies
// in the range the specification reserves for custom use (0xE0–0xEF).
const TypeLeafDER = 0xE0

// MaxHeader is the most bytes a header may have, the 16 fixed bytes
// included. A P-256 leaf of Keepia's profile is well under 1 KiB.
const MaxHeader = 4096

// signature is the 12-byte magic every version 2 header starts with.
var signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	fixedLen = 16
	// versionCommand: version 2 in the high nibble, PROXY in the low one.
	verCmdProxy = 0x21
	verCmdLocal = 0x20
	famTCP4     = 0x11
	famTCP6     = 0x21
	addrLen4    = 12
	addrLen6    = 36
	tlvHeadLen  = 3
)

// ErrHeader is wrapped by every refusal of Decode and Read.
var ErrHeader = errors.New("PROXY v2 header refused")

// Header is one PROXY v2 header as the gate sends it.
type Header struct {
	// Source is the client's address as the gate accepted it, Destination
	// the gate's own address of that connection. Both are IPv4 or both
	// IPv6.
	Source, Destination netip.AddrPort
	// LeafDER is the client's verified leaf certificate (DER).
	LeafDER []byte
}

// Encode returns h as a PROXY v2 header: command PROXY, TCP over the
// addresses' family, and one TLV TypeLeafDER with the leaf. It refuses
// addresses of different families, an empty leaf, and a header over
// MaxHeader.
func Encode(h Header) ([]byte, error) {
	src, dst := h.Source.Addr().Unmap(), h.Destination.Addr().Unmap()
	if !src.IsValid() || !dst.IsValid() || src.Zone() != "" || dst.Zone() != "" {
		return nil, errors.New("proxyproto: the source and destination must be IP addresses without a zone")
	}
	if src.Is4() != dst.Is4() {
		return nil, errors.New("proxyproto: the source and destination have different address families")
	}
	if len(h.LeafDER) == 0 {
		return nil, errors.New("proxyproto: no leaf")
	}
	fam, alen := byte(famTCP6), addrLen6
	if src.Is4() {
		fam, alen = famTCP4, addrLen4
	}
	rest := alen + tlvHeadLen + len(h.LeafDER)
	if fixedLen+rest > MaxHeader {
		return nil, fmt.Errorf("proxyproto: the header would have %d bytes, more than %d", fixedLen+rest, MaxHeader)
	}
	b := make([]byte, 0, fixedLen+rest)
	b = append(b, signature...)
	b = append(b, verCmdProxy, fam)
	b = binary.BigEndian.AppendUint16(b, uint16(rest)) // #nosec G115 -- rest <= MaxHeader
	b = append(b, src.AsSlice()...)
	b = append(b, dst.AsSlice()...)
	b = binary.BigEndian.AppendUint16(b, h.Source.Port())
	b = binary.BigEndian.AppendUint16(b, h.Destination.Port())
	b = append(b, TypeLeafDER)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.LeafDER))) // #nosec G115 -- bounded by MaxHeader
	b = append(b, h.LeafDER...)
	return b, nil
}

// Decode reads one header from the start of conn, with deadline as its
// read deadline, and clears the deadline afterwards. It reads exactly the
// header's bytes, at most MaxHeader, so the stream after it is untouched.
// It accepts only what Encode makes; every refusal wraps ErrHeader, and no
// error quotes the bytes read.
func Decode(conn net.Conn, deadline time.Time) (Header, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return Header{}, err
	}
	h, err := Read(conn)
	if err != nil {
		return Header{}, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return Header{}, err
	}
	return h, nil
}

// Read is Decode without the deadline, for a reader that bounds itself.
func Read(r io.Reader) (Header, error) {
	var fixed [fixedLen]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Header{}, fmt.Errorf("%w: truncated (%w)", ErrHeader, err)
	}
	if !bytes.Equal(fixed[:12], signature) {
		return Header{}, fmt.Errorf("%w: no version 2 signature", ErrHeader)
	}
	switch fixed[12] {
	case verCmdProxy:
	case verCmdLocal:
		return Header{}, fmt.Errorf("%w: the command LOCAL", ErrHeader)
	default:
		return Header{}, fmt.Errorf("%w: not version 2 with the command PROXY", ErrHeader)
	}
	var alen int
	switch fixed[13] {
	case famTCP4:
		alen = addrLen4
	case famTCP6:
		alen = addrLen6
	default:
		return Header{}, fmt.Errorf("%w: not TCP over IPv4 or IPv6", ErrHeader)
	}
	n := int(binary.BigEndian.Uint16(fixed[14:16]))
	if fixedLen+n > MaxHeader {
		return Header{}, fmt.Errorf("%w: %d bytes, more than %d", ErrHeader, fixedLen+n, MaxHeader)
	}
	if n < alen {
		return Header{}, fmt.Errorf("%w: too short for its addresses", ErrHeader)
	}
	rest := make([]byte, n)
	if _, err := io.ReadFull(r, rest); err != nil {
		return Header{}, fmt.Errorf("%w: truncated (%w)", ErrHeader, err)
	}
	var h Header
	ipLen := (alen - 4) / 2
	src, _ := netip.AddrFromSlice(rest[:ipLen])
	dst, _ := netip.AddrFromSlice(rest[ipLen : 2*ipLen])
	h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(rest[2*ipLen:]))
	h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(rest[2*ipLen+2:]))
	tlvs := rest[alen:]
	for len(tlvs) > 0 {
		if len(tlvs) < tlvHeadLen {
			return Header{}, fmt.Errorf("%w: a truncated TLV", ErrHeader)
		}
		typ, l := tlvs[0], int(binary.BigEndian.Uint16(tlvs[1:3]))
		if len(tlvs) < tlvHeadLen+l {
			return Header{}, fmt.Errorf("%w: a truncated TLV", ErrHeader)
		}
		if typ != TypeLeafDER {
			return Header{}, fmt.Errorf("%w: a TLV of type 0x%02x (only 0x%02x is accepted)", ErrHeader, typ, TypeLeafDER)
		}
		if h.LeafDER != nil {
			return Header{}, fmt.Errorf("%w: more than one leaf TLV", ErrHeader)
		}
		if l == 0 {
			return Header{}, fmt.Errorf("%w: an empty leaf TLV", ErrHeader)
		}
		h.LeafDER = bytes.Clone(tlvs[tlvHeadLen : tlvHeadLen+l])
		tlvs = tlvs[tlvHeadLen+l:]
	}
	if h.LeafDER == nil {
		return Header{}, fmt.Errorf("%w: no leaf TLV", ErrHeader)
	}
	return h, nil
}
