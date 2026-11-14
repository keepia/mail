package gate

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Config is a gate's start configuration, from flags only (G1). Every
// address is an IP literal: the gate never resolves a name.
type Config struct {
	Role Role
	// Mesh and Private are the gate's own fixed addresses on the mesh and
	// on its role's private network: at most one IPv4 and one IPv6 each.
	Mesh    []netip.Addr
	Private []netip.Addr
	// Target is the role's application (control and store).
	Target netip.Addr
	// Control is the control gate's mesh address (store and edge).
	Control netip.Addr
	// MeshNet are the mesh subnets: the egress remotes and the gate's own
	// mesh addresses must lie in them.
	MeshNet []netip.Prefix
	// Dir is the material directory (G10).
	Dir string
	// MaxConns caps the gate's open connections (G13).
	MaxConns int
}

// DefaultMaxConns is each role's connection cap (G13, V1). After traffic
// an ingress session holds about 59 KiB of live Go memory (48 KiB heap,
// of which crypto/tls's record read buffer is about 26 KiB, and 11 KiB of
// stacks), a passthrough about 14 KiB (BenchmarkSessionMemory). So the
// store's cap is 192 rather than the plan's 256: about 11 MiB of sessions
// under GOMEMLIMIT=24MiB instead of 15 MiB, with room for the kernel's
// socket memory under the 32 MiB limit, and still well above §9's 41
// sessions per store. The edge's 512 covers every store's proxied
// sessions. Raising one goes with the 32 MiB limit.
var DefaultMaxConns = map[Role]int{RoleControl: 128, RoleStore: 192, RoleEdge: 512}

// maxConnsLimit bounds --max-conns.
const maxConnsLimit = 4096

// ParseFlags parses the gate's flags (G1) and checks them (R-BIND-PRIVATE).
// Unknown flags, positional arguments, host names and wildcard,
// unspecified, multicast or broadcast addresses are refused, so nothing
// listens on a configuration that could bind wider than the gate's own
// addresses.
func ParseFlags(args []string) (Config, error) {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	role := fs.String("role", "", "the gate's role: control, store or edge")
	mesh := fs.String("mesh", "", "the gate's mesh addresses: an IPv4 and/or an IPv6 literal, comma-separated")
	private := fs.String("private", "", "the gate's private-network addresses, the same form")
	target := fs.String("target", "", "the role application's IP address (control, store)")
	control := fs.String("control", "", "the control gate's mesh IP address (store, edge)")
	meshNet := fs.String("mesh-net", "", "the mesh subnets, comma-separated CIDR prefixes")
	dir := fs.String("dir", "", "the material directory")
	maxConns := fs.String("max-conns", "", "the cap of open connections (default: control 128, store 256, edge 512)")
	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("gate flags: %w", err)
	}
	if fs.NArg() != 0 {
		return Config{}, errors.New("gate flags: no positional arguments are accepted")
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	var c Config
	c.Role = Role(*role)
	if !slices.Contains(Roles, c.Role) {
		return Config{}, fmt.Errorf("gate flags: --role must be control, store or edge")
	}
	var err error
	if c.Mesh, err = parseAddrs("mesh", *mesh); err != nil {
		return Config{}, err
	}
	if c.Private, err = parseAddrs("private", *private); err != nil {
		return Config{}, err
	}
	if set["target"] {
		if c.Target, err = parseAddr("target", *target); err != nil {
			return Config{}, err
		}
	}
	if set["control"] {
		if c.Control, err = parseAddr("control", *control); err != nil {
			return Config{}, err
		}
	}
	if set["mesh-net"] {
		for _, s := range strings.Split(*meshNet, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil || p.Addr().Zone() != "" || p.Bits() == 0 {
				return Config{}, fmt.Errorf("gate flags: --mesh-net: %q is not a CIDR prefix of a subnet", s)
			}
			c.MeshNet = append(c.MeshNet, p.Masked())
		}
	}
	c.Dir = *dir
	c.MaxConns = DefaultMaxConns[c.Role]
	if set["max-conns"] {
		n, err := strconv.Atoi(*maxConns)
		if err != nil || n < 1 || n > maxConnsLimit {
			return Config{}, fmt.Errorf("gate flags: --max-conns must be 1 to %d", maxConnsLimit)
		}
		c.MaxConns = n
	}
	return c, c.Check()
}

// Check validates a configuration for its role.
func (c Config) Check() error {
	if !slices.Contains(Roles, c.Role) {
		return fmt.Errorf("gate: unknown role %q", c.Role)
	}
	if c.Dir == "" || !filepath.IsAbs(c.Dir) {
		return errors.New("gate: --dir must be an absolute path")
	}
	if c.MaxConns < 1 || c.MaxConns > maxConnsLimit {
		return fmt.Errorf("gate: --max-conns must be 1 to %d", maxConnsLimit)
	}
	for _, group := range [][]netip.Addr{c.Mesh, c.Private, {c.Target}, {c.Control}} {
		for _, a := range group {
			if a.IsValid() {
				if err := bindable(a); err != nil {
					return fmt.Errorf("gate: %w", err)
				}
			}
		}
	}
	if len(c.Private) == 0 {
		return errors.New("gate: --private is required")
	}
	needMesh := false
	for _, s := range specs[c.Role] {
		if s.on&onMesh != 0 {
			needMesh = true
		}
	}
	switch {
	case needMesh && len(c.Mesh) == 0:
		return fmt.Errorf("gate: --mesh is required for the role %s", c.Role)
	case !needMesh && len(c.Mesh) != 0:
		return fmt.Errorf("gate: --mesh is not used by the role %s", c.Role)
	}
	needTarget := c.Role == RoleControl || c.Role == RoleStore
	switch {
	case needTarget && !c.Target.IsValid():
		return fmt.Errorf("gate: --target is required for the role %s", c.Role)
	case !needTarget && c.Target.IsValid():
		return fmt.Errorf("gate: --target is not used by the role %s", c.Role)
	}
	needControl := c.Role == RoleStore || c.Role == RoleEdge
	switch {
	case needControl && !c.Control.IsValid():
		return fmt.Errorf("gate: --control is required for the role %s", c.Role)
	case !needControl && c.Control.IsValid():
		return fmt.Errorf("gate: --control is not used by the role %s", c.Role)
	}
	if needControl && len(c.MeshNet) == 0 {
		return fmt.Errorf("gate: --mesh-net is required for the role %s", c.Role)
	}
	if len(c.MeshNet) != 0 {
		in := append(slices.Clone(c.Mesh), c.Control)
		for _, a := range in {
			if a.IsValid() && !inPrefixes(a, c.MeshNet) {
				return fmt.Errorf("gate: the mesh address %s is outside --mesh-net", a)
			}
		}
	}
	return nil
}

// parseAddrs parses a comma-separated list of at most one IPv4 and one
// IPv6 literal; empty is no address.
func parseAddrs(name, s string) ([]netip.Addr, error) {
	if s == "" {
		return nil, nil
	}
	var out []netip.Addr
	var v4, v6 bool
	for _, part := range strings.Split(s, ",") {
		a, err := parseAddr(name, part)
		if err != nil {
			return nil, err
		}
		if (a.Is4() && v4) || (a.Is6() && v6) {
			return nil, fmt.Errorf("gate flags: --%s takes at most one IPv4 and one IPv6 address", name)
		}
		v4, v6 = v4 || a.Is4(), v6 || a.Is6()
		out = append(out, a)
	}
	return out, nil
}

// parseAddr parses one IP literal (never a host name) that a gate may
// bind or dial.
func parseAddr(name, s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("gate flags: --%s: %q is not an IP address", name, s)
	}
	a = a.Unmap()
	if err := bindable(a); err != nil {
		return netip.Addr{}, fmt.Errorf("gate flags: --%s: %w", name, err)
	}
	return a, nil
}

// bindable refuses the addresses R-BIND-PRIVATE rules out: wildcard
// (unspecified), multicast, the IPv4 broadcast address and zoned
// addresses.
func bindable(a netip.Addr) error {
	switch {
	case !a.IsValid():
		return errors.New("not an IP address")
	case a.IsUnspecified():
		return fmt.Errorf("%s is a wildcard address", a)
	case a.IsMulticast():
		return fmt.Errorf("%s is a multicast address", a)
	case a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%s is the broadcast address", a)
	case a.Zone() != "":
		return fmt.Errorf("%s has a zone", a)
	}
	return nil
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}
