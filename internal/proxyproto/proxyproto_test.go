package proxyproto_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/keepia/mail/internal/proxyproto"
	"github.com/keepia/mail/internal/testwait"
)

var leaf = bytes.Repeat([]byte{0x30, 0x82}, 300)

func header(t *testing.T, src, dst string) []byte {
	t.Helper()
	b, err := proxyproto.Encode(proxyproto.Header{
		Source:      netip.MustParseAddrPort(src),
		Destination: netip.MustParseAddrPort(dst),
		LeafDER:     leaf,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// U18: a header round-trips over IPv4 and IPv6, and Read stops at its end.
func TestRoundTrip(t *testing.T) {
	for _, c := range [][2]string{
		{"10.0.1.7:40000", "10.0.1.20:7400"},
		{"[fd00:1::7]:40000", "[fd00:1::20]:7400"},
	} {
		b := header(t, c[0], c[1])
		r := bytes.NewReader(append(bytes.Clone(b), "after"...))
		h, err := proxyproto.Read(r)
		if err != nil {
			t.Fatalf("%v: %v", c, err)
		}
		if h.Source.String() != c[0] || h.Destination.String() != c[1] || !bytes.Equal(h.LeafDER, leaf) {
			t.Errorf("%v: got %v %v, leaf equal %v", c, h.Source, h.Destination, bytes.Equal(h.LeafDER, leaf))
		}
		if rest, _ := io.ReadAll(r); string(rest) != "after" {
			t.Errorf("%v: Read consumed past the header: %q left", c, rest)
		}
	}
}

func TestEncodeRefuses(t *testing.T) {
	cases := map[string]proxyproto.Header{
		"mixed families": {Source: netip.MustParseAddrPort("10.0.0.1:1"), Destination: netip.MustParseAddrPort("[fd00::1]:2"), LeafDER: leaf},
		"no leaf":        {Source: netip.MustParseAddrPort("10.0.0.1:1"), Destination: netip.MustParseAddrPort("10.0.0.2:2")},
		"too large":      {Source: netip.MustParseAddrPort("10.0.0.1:1"), Destination: netip.MustParseAddrPort("10.0.0.2:2"), LeafDER: make([]byte, proxyproto.MaxHeader)},
		"no address":     {LeafDER: leaf},
	}
	for name, h := range cases {
		if _, err := proxyproto.Encode(h); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}

// U18: Read refuses everything but what Encode makes, and no error quotes
// the bytes read.
func TestReadRefuses(t *testing.T) {
	good := header(t, "10.0.1.7:40000", "10.0.1.20:7400")
	with := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(good)) }
	setLen := func(b []byte, n int) []byte { binary.BigEndian.PutUint16(b[14:16], uint16(n)); return b }
	tlv := func(typ byte, v []byte) []byte {
		return append(binary.BigEndian.AppendUint16([]byte{typ}, uint16(len(v))), v...)
	}
	// addrs is the IPv4 address block of good.
	addrs := good[16:28]
	build := func(cmd, fam byte, body []byte) []byte {
		b := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), cmd, fam)
		b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
		return append(b, body...)
	}
	cases := map[string][]byte{
		"v1":              []byte("PROXY TCP4 10.0.1.7 10.0.1.20 40000 7400\r\n"),
		"wrong signature": with(func(b []byte) []byte { b[3] = 'X'; return b }),
		"version 1 nibble": with(func(b []byte) []byte {
			b[12] = 0x11
			return b
		}),
		"LOCAL":             with(func(b []byte) []byte { b[12] = 0x20; return b }),
		"UDP":               with(func(b []byte) []byte { b[13] = 0x12; return b }),
		"UNSPEC":            with(func(b []byte) []byte { b[13] = 0x00; return b }),
		"truncated fixed":   good[:10],
		"truncated body":    good[:len(good)-1],
		"over 4 KiB":        with(func(b []byte) []byte { return setLen(b, proxyproto.MaxHeader) }),
		"TLV over 4 KiB":    build(0x21, 0x11, append(bytes.Clone(addrs), tlv(proxyproto.TypeLeafDER, make([]byte, proxyproto.MaxHeader))...)),
		"short addresses":   with(func(b []byte) []byte { return setLen(b, 4)[:20] }),
		"no TLV":            build(0x21, 0x11, addrs),
		"other TLV":         build(0x21, 0x11, append(bytes.Clone(addrs), tlv(0x04, []byte{0})...)),
		"two leaves":        build(0x21, 0x11, append(append(bytes.Clone(addrs), tlv(proxyproto.TypeLeafDER, leaf)...), tlv(proxyproto.TypeLeafDER, leaf)...)),
		"empty leaf":        build(0x21, 0x11, append(bytes.Clone(addrs), tlv(proxyproto.TypeLeafDER, nil)...)),
		"truncated TLV":     build(0x21, 0x11, append(bytes.Clone(addrs), proxyproto.TypeLeafDER, 0x00)),
		"TLV past its body": build(0x21, 0x11, append(bytes.Clone(addrs), proxyproto.TypeLeafDER, 0x00, 0x09, 0x01)),
	}
	for name, b := range cases {
		_, err := proxyproto.Read(bytes.NewReader(b))
		if !errors.Is(err, proxyproto.ErrHeader) {
			t.Errorf("%s: got %v, want ErrHeader", name, err)
			continue
		}
		if strings.Contains(err.Error(), "QUIT") || strings.Contains(err.Error(), "10.0.1.7") {
			t.Errorf("%s: the error quotes the input: %v", name, err)
		}
	}
}

// U18: Decode gives up at its deadline on a peer that sends a partial
// header, and leaves the rest of a stream unread.
func TestDecodeDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() { _, _ = b.Write(header(t, "10.0.1.7:40000", "10.0.1.20:7400")[:20]) }()
	done := make(chan error, 1)
	// A deadline in the past: the partial header is not waited for.
	go func() { _, err := proxyproto.Decode(a, time.Now().Add(-time.Second)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Decode accepted a partial header")
		}
	case <-time.After(testwait.Limit(t)):
		t.Fatal("Decode did not return at its deadline")
	}

	c, d := net.Pipe()
	defer func() { _ = c.Close(); _ = d.Close() }()
	go func() {
		_, _ = d.Write(header(t, "[fd00:1::7]:1", "[fd00:1::20]:7400"))
		_, _ = d.Write([]byte("GET"))
	}()
	h, err := proxyproto.Decode(c, time.Now().Add(testwait.Limit(t)))
	if err != nil {
		t.Fatal(err)
	}
	if h.Source.Port() != 1 {
		t.Errorf("source %v", h.Source)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "GET" {
		t.Errorf("after the header: %q, %v", buf, err)
	}
}
