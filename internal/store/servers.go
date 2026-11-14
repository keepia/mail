package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/keepia/mail/internal/store/db"
)

// Server is a host of one or more roles. Its name (a DNS label) never
// changes. JoinedAt and RemovedAt are written by N2 (#96); nil means not
// yet.
type Server struct {
	ID        int64
	Name      string
	Roles     []string
	JoinedAt  *time.Time
	RemovedAt *time.Time
	CreatedAt time.Time
}

// The store states.
const (
	StoreJoining = "joining"
	StoreActive  = "active"
)

// MailStore is a store: a mail store on a server with the role store,
// reached through its gate. Its server and gate name never change. An
// active store has an egress port and at least one gate address.
type MailStore struct {
	ID       int64
	Server   string
	GateName string
	// GateIPv4 and GateIPv6 are the gate's addresses; the zero Addr is
	// none.
	GateIPv4, GateIPv6 netip.Addr
	// EgressPort is the store's egress port; 0 is none.
	EgressPort int32
	State      string
	CreatedAt  time.Time
}

// CreateServer adds the server name with roles (control, edge, store,
// filter, groupware; each once). For N2 and tests.
func (s *Store) CreateServer(ctx context.Context, name string, roles []string) (Server, error) {
	var sv Server
	err := s.write(ctx, "server.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		row, err := q.InsertServer(ctx, db.InsertServerParams{Name: name, Roles: roles})
		if err != nil {
			return audit{}, err
		}
		sv = server(row)
		return audit{object: name, details: map[string]any{"roles": roles}}, nil
	})
	return sv, err
}

// SetServerRoles replaces the roles of the server name. A server with
// stores keeps the role store (T8).
func (s *Store) SetServerRoles(ctx context.Context, name string, roles []string) error {
	return s.write(ctx, "server.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		n, err := q.SetServerRoles(ctx, db.SetServerRolesParams{Name: name, Roles: roles})
		if err != nil {
			return audit{}, err
		}
		if n == 0 {
			return audit{}, notFound("server", name)
		}
		return audit{object: name, details: map[string]any{"roles": roles}}, nil
	})
}

// ListServers lists every server by name.
func (s *Store) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := db.New(s.pool).ListServers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Server, 0, len(rows))
	for _, r := range rows {
		out = append(out, server(r))
	}
	return out, nil
}

func server(r db.Server) Server {
	return Server{ID: r.ID, Name: r.Name, Roles: r.Roles, JoinedAt: optionalTime(r.JoinedAt), RemovedAt: optionalTime(r.RemovedAt), CreatedAt: r.CreatedAt.Time}
}

func optionalTime(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// NewStore is the store that CreateStore adds, in state joining.
type NewStore struct {
	Server, GateName   string
	GateIPv4, GateIPv6 netip.Addr // the zero Addr is none
	EgressPort         int32      // 0 is none
}

// CreateStore adds a store in state joining on a server with the role
// store that is not removed (T8). For N4 and tests.
func (s *Store) CreateStore(ctx context.Context, n NewStore) (MailStore, error) {
	var ms MailStore
	err := s.write(ctx, "store.add", func(ctx context.Context, q *db.Queries) (audit, error) {
		row, err := q.InsertStore(ctx, db.InsertStoreParams{
			ServerName: n.Server, GateName: n.GateName,
			GateIpv4: optionalAddr(n.GateIPv4), GateIpv6: optionalAddr(n.GateIPv6), EgressPort: optionalPort(n.EgressPort),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return audit{}, notFound("server", n.Server)
		}
		if err != nil {
			return audit{}, err
		}
		ms = mailStore(row.ID, n.Server, row.GateName, row.GateIpv4, row.GateIpv6, row.EgressPort, row.State, row.CreatedAt)
		return audit{object: n.GateName, details: map[string]any{"server": n.Server}}, nil
	})
	return ms, err
}

// SetStoreState sets the state of the store with the gate name gateName
// (StoreJoining or StoreActive). An active store needs its routing
// (SetStoreRouting) first. For N4 and tests.
func (s *Store) SetStoreState(ctx context.Context, gateName, state string) error {
	return s.write(ctx, "store.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		n, err := q.SetStoreState(ctx, db.SetStoreStateParams{GateName: gateName, State: state})
		if err != nil {
			return audit{}, err
		}
		if n == 0 {
			return audit{}, notFound("store", gateName)
		}
		return audit{object: gateName, details: map[string]any{"state": state}}, nil
	})
}

// StoreRouting is where a store's gate is reached: its addresses (the
// zero Addr is none) and its egress port (0 is none).
type StoreRouting struct {
	GateIPv4, GateIPv6 netip.Addr
	EgressPort         int32
}

// SetStoreRouting replaces the routing of the store with the gate name
// gateName. An active store keeps a port and at least one address
// (stores_active_routable). For N4 and tests.
func (s *Store) SetStoreRouting(ctx context.Context, gateName string, r StoreRouting) error {
	return s.write(ctx, "store.set", func(ctx context.Context, q *db.Queries) (audit, error) {
		n, err := q.SetStoreRouting(ctx, db.SetStoreRoutingParams{
			GateName: gateName, GateIpv4: optionalAddr(r.GateIPv4), GateIpv6: optionalAddr(r.GateIPv6), EgressPort: optionalPort(r.EgressPort),
		})
		if err != nil {
			return audit{}, err
		}
		if n == 0 {
			return audit{}, notFound("store", gateName)
		}
		return audit{object: gateName, details: map[string]any{
			"gate_ipv4": addrText(r.GateIPv4), "gate_ipv6": addrText(r.GateIPv6), "egress_port": r.EgressPort,
		}}, nil
	})
}

// ListStores lists every store by gate name.
func (s *Store) ListStores(ctx context.Context) ([]MailStore, error) {
	rows, err := db.New(s.pool).ListStores(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]MailStore, 0, len(rows))
	for _, r := range rows {
		out = append(out, mailStore(r.ID, r.ServerName, r.GateName, r.GateIpv4, r.GateIpv6, r.EgressPort, r.State, r.CreatedAt))
	}
	return out, nil
}

func mailStore(id int64, server, gate string, v4, v6 *netip.Addr, port *int32, state string, created pgtype.Timestamptz) MailStore {
	ms := MailStore{ID: id, Server: server, GateName: gate, State: state, CreatedAt: created.Time}
	if v4 != nil {
		ms.GateIPv4 = *v4
	}
	if v6 != nil {
		ms.GateIPv6 = *v6
	}
	if port != nil {
		ms.EgressPort = *port
	}
	return ms
}

func optionalAddr(a netip.Addr) *netip.Addr {
	if !a.IsValid() {
		return nil
	}
	return &a
}

// addrText is a's text for the audit details, "" for none.
func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func optionalPort(p int32) *int32 {
	if p == 0 {
		return nil
	}
	return &p
}
