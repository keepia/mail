package gate

import (
	"net/netip"
	"strings"
	"testing"
)

func storeArgs(extra ...string) []string {
	return append([]string{
		"--role", "store", "--mesh", "10.20.8.40,fd00:20:8::40", "--private", "10.20.4.20,fd00:20:4::20",
		"--target", "10.20.4.10", "--control", "10.20.8.10", "--mesh-net", "10.20.8.0/24,fd00:20:8::/64",
		"--dir", "/var/lib/keepia/gate",
	}, extra...)
}

// replace returns args with flag's value replaced.
func replace(args []string, flag, value string) []string {
	out := append([]string{}, args...)
	for i := range out {
		if out[i] == flag {
			out[i+1] = value
		}
	}
	return out
}

// drop returns args without flag and its value.
func drop(args []string, flag string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// U19: the flags of each role parse; R-BIND-PRIVATE refuses wildcard,
// multicast and broadcast addresses, host names, missing and unused flags,
// and unknown flags, before anything listens.
func TestParseFlags(t *testing.T) {
	c, err := ParseFlags(storeArgs())
	if err != nil {
		t.Fatal(err)
	}
	if c.Role != RoleStore || len(c.Mesh) != 2 || c.Target != netip.MustParseAddr("10.20.4.10") || c.MaxConns != 192 {
		t.Fatalf("parsed %+v", c)
	}
	if _, err := ParseFlags([]string{"--role", "control", "--mesh", "10.20.8.10", "--private", "10.20.1.20",
		"--target", "10.20.1.10", "--dir", "/var/lib/keepia/control-gate", "--max-conns", "64"}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if c, err := ParseFlags([]string{"--role", "edge", "--private", "10.20.2.20", "--control", "10.20.8.10",
		"--mesh-net", "10.20.8.0/24", "--dir", "/var/lib/keepia/gate"}); err != nil || c.MaxConns != 512 {
		t.Fatalf("edge: %v %+v", err, c)
	}

	refused := map[string][]string{
		"0.0.0.0":          replace(storeArgs(), "--mesh", "0.0.0.0"),
		"::":               replace(storeArgs(), "--private", "::"),
		"a host name":      replace(storeArgs(), "--target", "store-dovecot"),
		"a missing target": drop(storeArgs(), "--target"),
		"a missing dir":    drop(storeArgs(), "--dir"),
		"a missing mesh":   drop(storeArgs(), "--mesh"),
		"an unknown flag":  storeArgs("--listen", "10.20.8.40:7143"),
		"a positional":     storeArgs("extra"),
		"multicast":        replace(storeArgs(), "--control", "224.0.0.1"),
		"broadcast":        replace(storeArgs(), "--private", "255.255.255.255"),
		"a zone":           replace(storeArgs(), "--private", "fe80::1%eth0"),
		"two IPv4":         replace(storeArgs(), "--mesh", "10.20.8.40,10.20.8.41"),
		"mesh outside":     replace(storeArgs(), "--mesh", "10.20.4.40"),
		"control outside":  replace(storeArgs(), "--control", "10.20.1.10"),
		"a relative dir":   replace(storeArgs(), "--dir", "gate"),
		"a wildcard net":   replace(storeArgs(), "--mesh-net", "0.0.0.0/0"),
		"a bad cap":        storeArgs("--max-conns", "0"),
		"a huge cap":       storeArgs("--max-conns", "100000"),
		"an unknown role":  replace(storeArgs(), "--role", "filter"),
		"edge with mesh": {"--role", "edge", "--mesh", "10.20.8.20", "--private", "10.20.2.20", "--control", "10.20.8.10",
			"--mesh-net", "10.20.8.0/24", "--dir", "/d"},
		"control with control": {"--role", "control", "--mesh", "10.20.8.10", "--private", "10.20.1.20",
			"--target", "10.20.1.10", "--control", "10.20.8.10", "--dir", "/d"},
		"store without mesh-net": {"--role", "store", "--mesh", "10.20.8.40", "--private", "10.20.4.20",
			"--target", "10.20.4.10", "--control", "10.20.8.10", "--dir", "/d"},
	}
	for name, args := range refused {
		if c, err := ParseFlags(args); err == nil {
			t.Errorf("%s: accepted as %+v", name, c)
		} else if strings.Contains(name, "host") && !strings.Contains(err.Error(), "not an IP address") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// New checks the configuration too, so a Config built in code cannot
	// bind a wildcard either.
	bad := Config{Role: RoleEdge, Private: []netip.Addr{netip.IPv4Unspecified()}, Control: netip.MustParseAddr("10.20.8.10"),
		MeshNet: []netip.Prefix{netip.MustParsePrefix("10.20.8.0/24")}, Dir: "/d", MaxConns: 1}
	if _, err := New(bad, Options{ReadGeneration: readGeneration}); err == nil {
		t.Error("New accepted a wildcard address")
	}
}

// G2: the compiled table pairs each ingress listener with one anchor and
// its purposes, and the agent API alone sends the PROXY header.
func TestRoleTable(t *testing.T) {
	type row struct {
		name   string
		port   uint16
		anchor string
		target uint16
		proxy  bool
	}
	want := map[Role][]row{
		RoleControl: {{"agent-api", 7400, "agent", 8081, true}, {"join", 7401, "", 8082, false}},
		RoleStore: {{"imap", 7143, "store-client", 143, false}, {"pop3", 7110, "store-client", 110, false},
			{"lmtp", 7024, "store-client", 24, false}, {"egress-agent-api", 7400, "", 7400, false}, {"egress-join", 7401, "", 7401, false}},
		RoleEdge: {{"egress-agent-api", 7400, "", 7400, false}, {"egress-join", 7401, "", 7401, false}},
	}
	for role, rows := range want {
		got := Specs(role)
		if len(got) != len(rows) {
			t.Fatalf("%s: %d listeners", role, len(got))
		}
		for i, r := range rows {
			s := got[i]
			if s.Name != r.name || s.Port != r.port || string(s.Anchor) != r.anchor || s.TargetPort != r.target || s.Proxy != r.proxy {
				t.Errorf("%s %d: %+v, want %+v", role, i, s, r)
			}
			if s.Mode == Egress && (s.Anchor != "" || s.Purposes != nil) {
				t.Errorf("%s: egress with an anchor", s.Name)
			}
		}
	}
}
