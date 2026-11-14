package gate

import (
	"slices"

	"github.com/keepia/mail/internal/pki"
)

// Role is a gate's role (architecture §5a).
type Role string

// The roles that have a gate in 0.2.0.
const (
	RoleControl Role = "control"
	RoleStore   Role = "store"
	RoleEdge    Role = "edge"
)

// Roles lists them.
var Roles = []Role{RoleControl, RoleStore, RoleEdge}

// network is where a listener binds: the gate's mesh or private
// addresses.
type network int

const (
	onMesh network = 1 << iota
	onPrivate
)

// Mode is how a listener forwards.
type Mode int

// The modes.
const (
	// Ingress terminates mTLS (G4) and forwards the plaintext.
	Ingress Mode = iota
	// Egress is a keyless layer-4 passthrough (G7).
	Egress
)

// Spec is one listener of a role's compiled table (G1, G2). The pairing
// of anchor, purposes and target is a security property of the release,
// so it is fixed here and not configurable.
type Spec struct {
	// Name names the listener in logs and health.
	Name string
	Port uint16
	on   network
	Mode Mode
	// Anchor and Purposes are what an ingress listener accepts. An empty
	// Anchor (the join listener) asks for no client certificate and needs
	// no list (G5, C5).
	Anchor   pki.AnchorName
	Purposes []pki.Purpose
	// TargetPort is the port on --target (ingress) or on --control
	// (static egress) that the listener forwards to.
	TargetPort uint16
	// Proxy: the target gets a PROXY v2 header with the verified leaf
	// first (G9).
	Proxy bool
}

// The ports of G2 and G3.
const (
	PortAgentAPI = 7400
	PortJoin     = 7401
	PortIMAP     = 7143
	PortPOP3     = 7110
	PortLMTP     = 7024

	// RouteBase and RouteLast bound the edge gate's store routes; each
	// store has a block of four from a base that is a multiple of 4 (G3,
	// CD-N3-1).
	RouteBase = 20000
	RouteLast = 29999
)

// routeRemotePort is the store ingress port of each offset in a store's
// port block (G3, V6): IMAP, POP3, LMTP. Offset 3 is reserved for
// ManageSieve in 0.4.0 and refused until then.
var routeRemotePort = [3]uint16{PortIMAP, PortPOP3, PortLMTP}

// specs is §5a's listener table of 0.2.0 per role (G2). The edge gate's
// store routes come from egress.json (G8).
var specs = map[Role][]Spec{
	RoleControl: {
		{Name: "agent-api", Port: PortAgentAPI, on: onMesh | onPrivate, Mode: Ingress,
			Anchor: pki.AnchorAgent, Purposes: []pki.Purpose{pki.PurposeAgent}, TargetPort: 8081, Proxy: true},
		{Name: "join", Port: PortJoin, on: onMesh | onPrivate, Mode: Ingress, TargetPort: 8082},
	},
	RoleStore: {
		{Name: "imap", Port: PortIMAP, on: onMesh, Mode: Ingress,
			Anchor: pki.AnchorStoreClient, Purposes: []pki.Purpose{pki.PurposeEdgeDovecot}, TargetPort: 143},
		{Name: "pop3", Port: PortPOP3, on: onMesh, Mode: Ingress,
			Anchor: pki.AnchorStoreClient, Purposes: []pki.Purpose{pki.PurposeEdgeDovecot}, TargetPort: 110},
		{Name: "lmtp", Port: PortLMTP, on: onMesh, Mode: Ingress,
			Anchor: pki.AnchorStoreClient, Purposes: []pki.Purpose{pki.PurposeEdgeDovecot}, TargetPort: 24},
		{Name: "egress-agent-api", Port: PortAgentAPI, on: onPrivate, Mode: Egress, TargetPort: PortAgentAPI},
		{Name: "egress-join", Port: PortJoin, on: onPrivate, Mode: Egress, TargetPort: PortJoin},
	},
	RoleEdge: {
		{Name: "egress-agent-api", Port: PortAgentAPI, on: onPrivate, Mode: Egress, TargetPort: PortAgentAPI},
		{Name: "egress-join", Port: PortJoin, on: onPrivate, Mode: Egress, TargetPort: PortJoin},
	},
}

// Specs returns a copy of the role's listener table.
func Specs(r Role) []Spec {
	out := make([]Spec, len(specs[r]))
	copy(out, specs[r])
	return out
}

// requiredAnchors are the anchors a role's bundle must carry: the
// service anchor its own leaf chains to, and its client anchors.
func requiredAnchors(r Role) []pki.AnchorName {
	out := []pki.AnchorName{pki.AnchorService}
	for _, s := range specs[r] {
		if s.Anchor != "" && !slices.Contains(out, s.Anchor) {
			out = append(out, s.Anchor)
		}
	}
	return out
}

// hasBundle tells whether the role holds a leaf and a key. The edge gate
// holds neither in 0.2.0 and never opens a bundle (G10).
func hasBundle(r Role) bool { return r == RoleControl || r == RoleStore }
