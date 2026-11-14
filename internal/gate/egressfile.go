package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// EgressFileName is the edge gate's store routes in its material
// directory (G8). The agent (#98) writes it by write-and-rename before
// "generation".
const EgressFileName = "egress.json"

const (
	// maxEgressFile bounds the file (G8, as C12's reads).
	maxEgressFile = 64 << 10
	// maxRoutes bounds the listeners in it.
	maxRoutes = 256
)

// Route is one store route of the edge gate: a port of a store's block
// on the edge-private addresses, passed through to that store gate's
// ingress port on the mesh (G3, G8).
type Route struct {
	Port   uint16
	Remote netip.AddrPort
	// Store names the store gate, for logs only.
	Store string
}

type egressFile struct {
	Version   int           `json:"version"`
	Listeners []egressEntry `json:"listeners"`
}

type egressEntry struct {
	Port   int    `json:"port"`
	Remote string `json:"remote"`
	Store  string `json:"store"`
}

// storeName is what a route's store field may hold: a DNS name, so a log
// line never carries anything else.
var storeName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// readEgressFile reads and checks dir's egress.json (G8, V6). It never
// follows a symlink, never blocks on a FIFO, reads at most 64 KiB, and no
// error quotes the file: a refusal names the listener by its index and
// the rule it breaks.
func readEgressFile(dir string, meshNet []netip.Prefix) ([]Route, error) {
	raw, err := readBounded(filepath.Join(dir, EgressFileName), maxEgressFile)
	if err != nil {
		return nil, err
	}
	return parseEgress(raw, meshNet)
}

func parseEgress(raw []byte, meshNet []netip.Prefix) ([]Route, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f egressFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %s", EgressFileName, jsonClass(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: data after the object", EgressFileName)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: version must be 1", EgressFileName)
	}
	if len(f.Listeners) > maxRoutes {
		return nil, fmt.Errorf("%s: more than %d listeners", EgressFileName, maxRoutes)
	}
	seen := map[int]bool{}
	routes := make([]Route, 0, len(f.Listeners))
	for i, e := range f.Listeners {
		bad := func(why string) error { return fmt.Errorf("%s: listener %d: %s", EgressFileName, i, why) }
		if e.Port < RouteBase || e.Port > RouteLast {
			return nil, bad(fmt.Sprintf("the port is outside %d-%d", RouteBase, RouteLast))
		}
		if seen[e.Port] {
			return nil, bad("the port is a duplicate")
		}
		seen[e.Port] = true
		offset := (e.Port - RouteBase) % 4
		if offset >= len(routeRemotePort) {
			return nil, bad("the port is offset 3 of its block, reserved until 0.4.0")
		}
		remote, err := netip.ParseAddrPort(e.Remote)
		if err != nil || remote.Addr().Zone() != "" {
			return nil, bad("the remote is not an IP address and port")
		}
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		if !inPrefixes(remote.Addr(), meshNet) || bindable(remote.Addr()) != nil {
			return nil, bad("the remote is outside the mesh subnet")
		}
		if !slices.Contains(routeRemotePort[:], remote.Port()) {
			return nil, bad("the remote port is not a store ingress port")
		}
		if remote.Port() != routeRemotePort[offset] {
			return nil, bad("the remote port does not match the port's offset in its block")
		}
		if !storeName.MatchString(e.Store) {
			return nil, bad("the store is not a DNS name")
		}
		routes = append(routes, Route{Port: uint16(e.Port), Remote: remote, Store: e.Store}) // #nosec G115 -- checked above
	}
	slices.SortFunc(routes, func(a, b Route) int { return int(a.Port) - int(b.Port) })
	return routes, nil
}

// jsonClass describes a decoding error without quoting the input: Go's
// JSON errors can quote a character or a field name of the file.
func jsonClass(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("not valid JSON (at byte %d)", syn.Offset)
	case errors.As(err, &typ):
		// Field is the path of known keys only.
		return fmt.Sprintf("a value of the wrong type for %s", typ.Field)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "not valid JSON (truncated)"
	case strings.HasPrefix(err.Error(), "json: unknown field"):
		return "an unknown field"
	}
	return "not valid JSON"
}
