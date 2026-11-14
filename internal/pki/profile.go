package pki

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Purpose is what a leaf certificate is for (CD13). It is the middle part
// of a client certificate's URI SAN, keepia:<purpose>:<server-id>.
type Purpose string

// The purposes of CD13. Only those marked "issued in 0.2.0" may be issued
// now (CheckPolicy); later milestones open their own.
const (
	// PurposeEdgeDovecot is the edge Dovecot's client certificate towards
	// the store gates (store-client anchor; issued in 0.2.0).
	PurposeEdgeDovecot Purpose = "edge-dovecot"
	// PurposeKeepiaEdge is keepia-edge's client certificate towards the
	// groupware gate (groupware-client anchor; 0.5.0).
	PurposeKeepiaEdge Purpose = "keepia-edge"
	// PurposeAgent is a server's agent certificate towards the control
	// gate (agent anchor; issued at the join in 0.2.0).
	PurposeAgent Purpose = "agent"
	// PurposeGate is a gate's server certificate (service anchor; issued
	// in 0.2.0 for store gates and, by serve, the control gate).
	PurposeGate Purpose = "gate"
	// PurposeEdge, PurposeFilter, PurposeStore, PurposeControl and
	// PurposeGroupware are the service client certificates (service
	// anchor; 0.3.0 on).
	PurposeEdge      Purpose = "edge"
	PurposeFilter    Purpose = "filter"
	PurposeStore     Purpose = "store"
	PurposeControl   Purpose = "control"
	PurposeGroupware Purpose = "groupware"
)

type profile struct {
	anchor AnchorName
	// server: serverAuth with one DNS SAN; otherwise clientAuth with one
	// URI SAN.
	server bool
	// issuedNow: may be issued in 0.2.0.
	issuedNow bool
}

var profiles = map[Purpose]profile{
	PurposeEdgeDovecot: {anchor: AnchorStoreClient, issuedNow: true},
	PurposeKeepiaEdge:  {anchor: AnchorGroupwareClient},
	PurposeAgent:       {anchor: AnchorAgent, issuedNow: true},
	PurposeGate:        {anchor: AnchorService, server: true, issuedNow: true},
	PurposeEdge:        {anchor: AnchorService},
	PurposeFilter:      {anchor: AnchorService},
	PurposeStore:       {anchor: AnchorService},
	PurposeControl:     {anchor: AnchorService},
	PurposeGroupware:   {anchor: AnchorService},
}

// Anchor is the anchor that signs the purpose's certificates; false for an
// unknown purpose.
func (p Purpose) Anchor() (AnchorName, bool) {
	pr, ok := profiles[p]
	return pr.anchor, ok
}

// Server roles (CD23).
const (
	RoleControl   = "control"
	RoleEdge      = "edge"
	RoleStore     = "store"
	RoleFilter    = "filter"
	RoleGroupware = "groupware"
)

// Roles lists the server roles.
var Roles = []string{RoleControl, RoleEdge, RoleStore, RoleFilter, RoleGroupware}

// Gate names (CD14). ICANN reserves .internal for private use.
const (
	// InternalDomain is the parent of every gate name.
	InternalDomain = "keepia.internal"
	// ControlGateName is the control gate's DNS name: there is one control
	// until 1.2.0, so a joining agent knows it without being told.
	ControlGateName = "control." + InternalDomain
	// controlGateCN is the control gate certificate's CN (C7).
	controlGateCN = "keepia:gate:control"
)

// serverName is a lowercase DNS label (CD14).
var serverName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidServerName tells whether name is a server name: a lowercase DNS
// label of 1–63 characters from [a-z0-9-], without a leading or trailing
// hyphen (CD14).
func ValidServerName(name string) bool { return serverName.MatchString(name) }

// GateName is the DNS name of the gate of role on the server serverName:
// <server-name>.<role>.keepia.internal (CD14), the value of
// stores.gate_name for a store.
func GateName(serverName, role string) (string, error) {
	if !ValidServerName(serverName) {
		return "", fmt.Errorf("server name %q: want a lowercase DNS label of 1-63 characters", serverName)
	}
	if !slices.Contains(Roles, role) {
		return "", fmt.Errorf("unknown role %q", role)
	}
	return serverName + "." + role + "." + InternalDomain, nil
}

// Leaf is what a leaf certificate says about its holder, apart from its
// key: the purpose and either the client URI or the gate's DNS name, and
// the CN. Build it with ClientLeaf, GateLeaf or ControlGateLeaf.
type Leaf struct {
	Purpose  Purpose
	ServerID int64
	// Role is the gate's role (PurposeGate only).
	Role string
	// URI is a client certificate's only SAN, keepia:<purpose>:<id>.
	URI *url.URL
	// DNSName is a server certificate's only SAN.
	DNSName string
	// CommonName is informational and never checked. It always contains
	// ':', so it never parses as a host name (C7).
	CommonName string
	// controlGate marks the control gate's certificate (CD34), which
	// serve issues itself and CheckPolicy never allows.
	controlGate bool
}

// ClientLeaf is the client certificate of purpose for the server
// serverID: the URI SAN keepia:<purpose>:<server-id> and the same string
// as CN.
func ClientLeaf(purpose Purpose, serverID int64) (Leaf, error) {
	pr, ok := profiles[purpose]
	if !ok || pr.server {
		return Leaf{}, fmt.Errorf("%q is not a client purpose", purpose)
	}
	if serverID < 1 {
		return Leaf{}, fmt.Errorf("server id %d: want a positive id", serverID)
	}
	s := "keepia:" + string(purpose) + ":" + strconv.FormatInt(serverID, 10)
	u, err := url.Parse(s)
	if err != nil {
		return Leaf{}, err
	}
	return Leaf{Purpose: purpose, ServerID: serverID, URI: u, CommonName: s}, nil
}

// GateLeaf is the server certificate of the gate of role on the server
// serverName (id serverID): the DNS SAN GateName(serverName, role) and the
// CN keepia:gate:<role>:<server-id>.
func GateLeaf(role, serverName string, serverID int64) (Leaf, error) {
	if serverID < 1 {
		return Leaf{}, fmt.Errorf("server id %d: want a positive id", serverID)
	}
	name, err := GateName(serverName, role)
	if err != nil {
		return Leaf{}, err
	}
	return Leaf{
		Purpose: PurposeGate, ServerID: serverID, Role: role, DNSName: name,
		CommonName: "keepia:gate:" + role + ":" + strconv.FormatInt(serverID, 10),
	}, nil
}

// ControlGateLeaf is the control gate's server certificate (CD34): the DNS
// SAN control.keepia.internal and the CN keepia:gate:control. Only serve
// issues it, without a join.
func ControlGateLeaf() Leaf {
	return Leaf{
		Purpose: PurposeGate, Role: RoleControl, DNSName: ControlGateName,
		CommonName: controlGateCN, controlGate: true,
	}
}

// ErrPolicy is wrapped by CheckPolicy's refusals.
var ErrPolicy = errors.New("not allowed by the issuance policy")

// CheckPolicy tells whether the leaf l may be issued to a server with the
// given roles (CD13 with CD34): only purposes issued in 0.2.0, and only to
// a server whose roles include it:
//
//   - edge-dovecot to an edge server;
//   - a gate server certificate to a store server, for its store gate;
//   - an agent certificate to every server.
//
// The control gate's certificate is never issued to a server: serve issues
// it itself (CD34).
func CheckPolicy(l Leaf, roles []string) error {
	pr, ok := profiles[l.Purpose]
	if !ok {
		return fmt.Errorf("%w: unknown purpose %q", ErrPolicy, l.Purpose)
	}
	if !pr.issuedNow {
		return fmt.Errorf("%w: the purpose %s is not issued in this release", ErrPolicy, l.Purpose)
	}
	switch l.Purpose {
	case PurposeAgent:
		return nil
	case PurposeEdgeDovecot:
		if slices.Contains(roles, RoleEdge) {
			return nil
		}
		return fmt.Errorf("%w: %s needs the role edge", ErrPolicy, l.Purpose)
	case PurposeGate:
		if l.controlGate || l.Role == RoleControl || strings.EqualFold(l.DNSName, ControlGateName) {
			return fmt.Errorf("%w: the control gate's certificate is issued by serve, never to a server", ErrPolicy)
		}
		if l.Role == RoleStore && slices.Contains(roles, RoleStore) {
			return nil
		}
		return fmt.Errorf("%w: a gate certificate for the role %q needs a store server", ErrPolicy, l.Role)
	}
	return fmt.Errorf("%w: %s", ErrPolicy, l.Purpose)
}

// parseClientURI parses keepia:<purpose>:<server-id>: a known client
// purpose and a positive decimal id without a leading zero.
func parseClientURI(u *url.URL) (Purpose, int64, error) {
	if u == nil || u.Scheme != "keepia" || u.Opaque == "" || u.Host != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", 0, errors.New("the URI SAN is not keepia:<purpose>:<server-id>")
	}
	p, id, ok := strings.Cut(u.Opaque, ":")
	if !ok {
		return "", 0, errors.New("the URI SAN is not keepia:<purpose>:<server-id>")
	}
	pr, known := profiles[Purpose(p)]
	if !known || pr.server {
		return "", 0, fmt.Errorf("the URI SAN names no client purpose (%q)", p)
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != id {
		return "", 0, errors.New("the URI SAN's server id is not a positive decimal number")
	}
	return Purpose(p), n, nil
}
