package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

// testHash is a placeholder stored hash: valid for the schema's CHECK,
// never a real password's.
const testHash = "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$cGxhY2Vob2xkZXJzYWx0$cGxhY2Vob2xkZXItaGFzaC1ub3QtcmVhbA"

// shortTimeout is the lock timeout of the tests that expect a lock wait to
// fail (go-tests.md: a short lock timeout and an expected error).
const shortTimeout = 50 * time.Millisecond

// testDB is a migrated test database: st with the default lock timeout,
// short with shortTimeout, and conn, a raw connection for SQL that the
// API does not offer.
type testDB struct {
	url   string
	st    *store.Store
	short *store.Store
	conn  *pgx.Conn
}

func newTestDB(t *testing.T) *testDB {
	t.Helper()
	d := &testDB{url: storetest.NewUnmigrated(t)}
	d.st = open(t, d.url)
	if _, err := d.st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	d.short = open(t, d.url, store.WithLockTimeout(shortTimeout))
	d.conn = connect(t, d.url)
	return d
}

// connect opens a raw connection to dbURL that is closed when the test
// ends.
func connect(t *testing.T, dbURL string) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })
	return c
}

// fixture is the data of seed: two groups, their domains, an alias
// domain, four servers and three stores, five mailboxes, two aliases and
// a catch-all, and a send-as grant. Its ids are for raw SQL.
type fixture struct {
	acme, other                      int64 // groups
	org, net, com                    int64 // example.org and example.net (acme), example.com (other)
	srv1, srv2, srv3, srv4           int64 // store; edge; store, removed; store without stores
	active, joining, removed         int64 // stores: srv1 active, srv1 joining, srv3 active on a removed server
	alice, bob, carol, dave, erin    int64 // mailboxes; bob is on example.com
	sales, solo, catchAll            int64 // aliases on example.org
	activeGate, joiningGate, remGate string
}

// seed fills d through the API with the fixture.
func seed(t *testing.T, d *testDB) fixture {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var f fixture
	g, err := d.st.CreateGroup(ctx, "acme")
	must(err)
	f.acme = g.ID
	g, err = d.st.CreateGroup(ctx, "other")
	must(err)
	f.other = g.ID
	for name, id := range map[string]*int64{"example.org": &f.org, "example.net": &f.net} {
		dm, err := d.st.CreateDomain(ctx, name, "acme")
		must(err)
		*id = dm.ID
	}
	dm, err := d.st.CreateDomain(ctx, "example.com", "other")
	must(err)
	f.com = dm.ID
	_, err = d.st.CreateAliasDomain(ctx, "example.info", "example.org")
	must(err)

	for name, s := range map[string]struct {
		id    *int64
		roles []string
	}{
		"srv1": {&f.srv1, []string{"store"}},
		"srv2": {&f.srv2, []string{"edge"}},
		"srv3": {&f.srv3, []string{"store"}},
		"srv4": {&f.srv4, []string{"store", "edge"}},
	} {
		sv, err := d.st.CreateServer(ctx, name, s.roles)
		must(err)
		*s.id = sv.ID
	}
	f.activeGate, f.joiningGate, f.remGate = "srv1.store.keepia.internal", "srv1b.store.keepia.internal", "srv3.store.keepia.internal"
	ms, err := d.st.CreateStore(ctx, store.NewStore{Server: "srv1", GateName: f.activeGate, GateIPv4: netip.MustParseAddr("192.0.2.10"), EgressPort: 2001})
	must(err)
	f.active = ms.ID
	must(d.st.UpdateStore(ctx, f.activeGate, store.MailStoreChange{State: ptr(store.StoreActive)}))
	ms, err = d.st.CreateStore(ctx, store.NewStore{Server: "srv1", GateName: f.joiningGate})
	must(err)
	f.joining = ms.ID
	ms, err = d.st.CreateStore(ctx, store.NewStore{Server: "srv3", GateName: f.remGate, GateIPv6: netip.MustParseAddr("2001:db8::3"), EgressPort: 2003})
	must(err)
	f.removed = ms.ID
	must(d.st.UpdateStore(ctx, f.remGate, store.MailStoreChange{State: ptr(store.StoreActive)}))
	exec(t, d.conn, "UPDATE servers SET removed_at = now() WHERE id = $1", f.srv3)

	for addr, id := range map[store.Address]*int64{
		{LocalPart: "alice", Domain: "example.org"}: &f.alice,
		{LocalPart: "bob", Domain: "example.com"}:   &f.bob,
		{LocalPart: "carol", Domain: "example.org"}: &f.carol,
		{LocalPart: "dave", Domain: "example.org"}:  &f.dave,
		{LocalPart: "erin", Domain: "example.org"}:  &f.erin,
	} {
		m, err := d.st.CreateMailbox(ctx, store.NewMailbox{Address: addr, PasswordHash: testHash, QuotaBytes: 1 << 30, IMAP: true, POP3: true, SMTP: true, StoreID: f.active})
		must(err)
		*id = m.ID
	}
	alice, erin := store.Address{LocalPart: "alice", Domain: "example.org"}, store.Address{LocalPart: "erin", Domain: "example.org"}
	a, err := d.st.CreateAlias(ctx, store.Address{LocalPart: "sales", Domain: "example.org"}, []store.Address{alice, erin})
	must(err)
	f.sales = a.ID
	a, err = d.st.CreateAlias(ctx, store.Address{LocalPart: "solo", Domain: "example.org"}, []store.Address{alice})
	must(err)
	f.solo = a.ID
	a, err = d.st.CreateAlias(ctx, store.Address{Domain: "example.org"}, []store.Address{alice})
	must(err)
	f.catchAll = a.ID
	_, err = d.st.CreateSendAs(ctx, alice, store.Address{Domain: "example.net"})
	must(err)
	return f
}

func ptr[T any](v T) *T { return &v }

// exec runs one statement on conn and fails the test on an error.
func exec(t *testing.T, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// inTx runs stmts in one transaction on conn and returns the first error.
// With commit, it commits after the last statement (the deferred T6 runs
// there); otherwise it always rolls back, so the fixture stays as it was.
func inTx(conn *pgx.Conn, commit bool, stmts ...string) error {
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	if commit {
		return tx.Commit(ctx)
	}
	return nil
}

// pgRule is the SQLSTATE and the constraint name of a PostgreSQL error,
// or "" and "" for nil.
func pgRule(err error) (code, constraint string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code, pgErr.ConstraintName
	}
	if err != nil {
		return "not a PostgreSQL error: " + err.Error(), ""
	}
	return "", ""
}

// ruleCase is one statement list that must fail with code and constraint,
// or succeed when code is "".
type ruleCase struct {
	name             string
	stmts            []string
	commit           bool
	code, constraint string
}

func runRuleCases(t *testing.T, conn *pgx.Conn, cases []ruleCase) {
	t.Helper()
	for _, c := range cases {
		err := inTx(conn, c.commit, c.stmts...)
		code, constraint := pgRule(err)
		if code != c.code || constraint != c.constraint {
			t.Errorf("%s: got %q %q (%v), want %q %q", c.name, code, constraint, err, c.code, c.constraint)
		}
	}
}

// One statement, as a ruleCase list entry.
func one(s string, args ...any) []string { return []string{fmt.Sprintf(s, args...)} }

// labels joins n labels of the letters a, b, c, ... of 63 characters each
// and one of last characters: a domain or host of 64n+last characters.
func labels(n, last int) string {
	parts := make([]string, 0, n+1)
	for i := range n {
		parts = append(parts, strings.Repeat(string(rune('a'+i)), 63))
	}
	return strings.Join(append(parts, strings.Repeat("z", last)), ".")
}

// schemaObjects lists the database objects of the public schema: every
// relation (tables, indexes, sequences) with its kind, every function
// with its signature, every trigger, constraint and type.
func schemaObjects(t *testing.T, dbURL string) []string {
	t.Helper()
	ctx := context.Background()
	c := connect(t, dbURL)
	rows, err := c.Query(ctx, `
		SELECT 'relation ' || c.relkind::text || ' ' || c.relname
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
		UNION ALL
		SELECT 'function ' || p.oid::regprocedure::text
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
		UNION ALL
		SELECT 'trigger ' || tg.tgrelid::regclass::text || ' ' || tg.tgname
		FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		UNION ALL
		SELECT 'constraint ' || co.conname
		FROM pg_constraint co JOIN pg_namespace n ON n.oid = co.connamespace WHERE n.nspname = 'public'
		UNION ALL
		SELECT 'type ' || ty.typname
		FROM pg_type ty JOIN pg_namespace n ON n.oid = ty.typnamespace WHERE n.nspname = 'public'
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return objects
}

// Test 1: every migration's Down leaves exactly the schema of the
// migration before it (relations, functions, triggers, constraints and
// types of the public schema), and Up works again.
func TestMigrationDownRestoresSchema(t *testing.T) {
	ctx := context.Background()
	dbURL := storetest.NewUnmigrated(t)
	st := open(t, dbURL)
	files := migrationFiles(t)
	prev := int64(0)
	for _, f := range files {
		v := migrationVersion(t, f)
		if prev > 0 {
			before := schemaObjects(t, dbURL)
			if err := st.MigrateUpTo(ctx, v); err != nil {
				t.Fatalf("up to %s: %v", f, err)
			}
			if err := st.MigrateDownTo(ctx, prev); err != nil {
				t.Fatalf("down from %s: %v", f, err)
			}
			if after := schemaObjects(t, dbURL); !slices.Equal(before, after) {
				t.Fatalf("down from %s left a different schema:\n%s", f, diffLists(before, after))
			}
		}
		if err := st.MigrateUpTo(ctx, v); err != nil {
			t.Fatalf("up to %s again: %v", f, err)
		}
		prev = v
	}
}

// diffLists names the entries only in a ("-") and only in b ("+").
func diffLists(a, b []string) string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, "- "+s)
		}
	}
	for _, s := range b {
		if !slices.Contains(a, s) {
			out = append(out, "+ "+s)
		}
	}
	return strings.Join(out, "\n")
}

// Test 2: every CHECK constraint refuses a bad value and accepts a good
// one next to it.
func TestCheckConstraints(t *testing.T) {
	d := newTestDB(t)
	f := seed(t, d)
	group := func(name string) []string { return one("INSERT INTO customer_groups (name) VALUES ('%s')", name) }
	domain := func(name string) []string {
		return one("INSERT INTO domains (group_id, name) VALUES (%d, '%s')", f.acme, name)
	}
	aliasDomain := func(name string) []string {
		return one("INSERT INTO alias_domains (name, domain_id) VALUES ('%s', %d)", name, f.org)
	}
	server := func(name, roles string) []string {
		return one("INSERT INTO servers (name, roles) VALUES ('%s', %s)", name, roles)
	}
	storeRow := func(gate, v4, v6, port, state string) []string {
		return one("INSERT INTO stores (server_id, gate_name, gate_ipv4, gate_ipv6, egress_port, state) VALUES (%d, '%s', %s, %s, %s, '%s')",
			f.srv4, gate, v4, v6, port, state)
	}
	mailbox := func(local, hash, quota, state string) []string {
		return one("INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, state, store_id) VALUES (%d, '%s', '%s', %s, '%s', %d)",
			f.org, local, hash, quota, state, f.active)
	}
	alias := func(local string) []string {
		return one("INSERT INTO aliases (domain_id, local_part) VALUES (%d, '%s')", f.org, local)
	}
	sendAs := func(local string) []string {
		return one("INSERT INTO send_as (mailbox_id, domain_id, local_part) VALUES (%d, %d, '%s')", f.alice, f.net, local)
	}
	audit := func(actor, action, object, details string) []string {
		return one("INSERT INTO audit_log (actor, action, object, details) VALUES ('%s', '%s', '%s', '%s')", actor, action, object, details)
	}
	const check = "23514"
	label63, label64 := strings.Repeat("g", 63), strings.Repeat("g", 64)
	runRuleCases(t, d.conn, []ruleCase{
		// Group names: a DNS label.
		{"group uppercase", group("Acme2"), false, check, "customer_groups_name_format"},
		{"group leading hyphen", group("-acme"), false, check, "customer_groups_name_format"},
		{"group trailing hyphen", group("acme-"), false, check, "customer_groups_name_format"},
		{"group dot", group("ac.me"), false, check, "customer_groups_name_format"},
		{"group 64 characters", group(label64), false, check, "customer_groups_name_format"},
		{"group 63 characters", group(label63), false, "", ""},
		{"group with digit and hyphen", group("acme-2"), false, "", ""},
		// Domain names: two or more labels, at most 253, not only digits.
		{"domain uppercase", domain("Example.biz"), false, check, "domains_name_format"},
		{"domain one label", domain("localhost"), false, check, "domains_name_format"},
		{"domain empty label", domain("example..biz"), false, check, "domains_name_format"},
		{"domain leading hyphen", domain("-example.biz"), false, check, "domains_name_format"},
		{"domain plus", domain("ex+ample.biz"), false, check, "domains_name_format"},
		{"domain star", domain("*.example.biz"), false, check, "domains_name_format"},
		{"domain IPv4", domain("192.0.2.1"), false, check, "domains_name_format"},
		{"domain 64-character label", domain(label64 + ".biz"), false, check, "domains_name_format"},
		{"domain 254 characters", domain(labels(3, 62)), false, check, "domains_name_format"},
		{"domain 253 characters", domain(labels(3, 61)), false, "", ""},
		{"domain A-label", domain("xn--bcher-kva.example"), false, "", ""},
		{"domain digits and a name", domain("1.2.3.example"), false, "", ""},
		{"alias domain one label", aliasDomain("example"), false, check, "alias_domains_name_format"},
		{"alias domain", aliasDomain("example.de"), false, "", ""},
		// Server names: one label (CD-C2); roles: known, at least one, each once.
		{"server two labels", server("srv.one", "'{edge}'"), false, check, "servers_name_format"},
		{"server uppercase", server("Srv5", "'{edge}'"), false, check, "servers_name_format"},
		{"server 64 characters", server(label64, "'{edge}'"), false, check, "servers_name_format"},
		{"server 63 characters", server(label63, "'{edge}'"), false, "", ""},
		{"roles empty", server("srv5", "'{}'"), false, check, "servers_roles_valid"},
		{"roles unknown", server("srv5", "'{store,mail}'"), false, check, "servers_roles_valid"},
		{"roles NULL element", server("srv5", "'{store,NULL}'"), false, check, "servers_roles_valid"},
		{"roles duplicate", server("srv5", "'{store,store}'"), false, check, "servers_roles_valid"},
		{"roles two", server("srv5", "'{store,edge}'"), false, "", ""},
		{"roles all five", server("srv5", "'{control,edge,store,filter,groupware}'"), false, "", ""},
		{"server joined and removed", one("INSERT INTO servers (name, roles, joined_at, removed_at) VALUES ('srv5', '{edge}', now(), now())"), false, "", ""},
		// Stores: host gate name, addresses, port, state, routable when active.
		{"gate uppercase", storeRow("Srv4.store", "NULL", "NULL", "NULL", "joining"), false, check, "stores_gate_name_format"},
		{"gate IPv4", storeRow("192.0.2.1", "NULL", "NULL", "NULL", "joining"), false, check, "stores_gate_name_format"},
		{"gate 254 characters", storeRow(labels(3, 62), "NULL", "NULL", "NULL", "joining"), false, check, "stores_gate_name_format"},
		{"gate one label", storeRow("srv4", "NULL", "NULL", "NULL", "joining"), false, "", ""},
		{"gate 253 characters", storeRow(labels(3, 61), "NULL", "NULL", "NULL", "joining"), false, "", ""},
		{"port 0", storeRow("srv4.store", "NULL", "NULL", "0", "joining"), false, check, "stores_egress_port_range"},
		{"port 65536", storeRow("srv4.store", "NULL", "NULL", "65536", "joining"), false, check, "stores_egress_port_range"},
		{"port 1", storeRow("srv4.store", "NULL", "NULL", "1", "joining"), false, "", ""},
		{"port 65535", storeRow("srv4.store", "NULL", "NULL", "65535", "joining"), false, "", ""},
		{"IPv4 in gate_ipv6", storeRow("srv4.store", "NULL", "'192.0.2.4'", "NULL", "joining"), false, check, "stores_gate_ipv6_host"},
		{"IPv6 in gate_ipv4", storeRow("srv4.store", "'2001:db8::4'", "NULL", "NULL", "joining"), false, check, "stores_gate_ipv4_host"},
		{"IPv4 /24", storeRow("srv4.store", "'192.0.2.0/24'", "NULL", "NULL", "joining"), false, check, "stores_gate_ipv4_host"},
		{"IPv6 /64", storeRow("srv4.store", "NULL", "'2001:db8::/64'", "NULL", "joining"), false, check, "stores_gate_ipv6_host"},
		{"IPv4 and IPv6 hosts", storeRow("srv4.store", "'192.0.2.4'", "'2001:db8::4'", "NULL", "joining"), false, "", ""},
		{"state unknown", storeRow("srv4.store", "NULL", "NULL", "NULL", "gone"), false, check, "stores_state_valid"},
		{"active without port", storeRow("srv4.store", "'192.0.2.4'", "NULL", "NULL", "active"), false, check, "stores_active_routable"},
		{"active without address", storeRow("srv4.store", "NULL", "NULL", "2004", "active"), false, check, "stores_active_routable"},
		{"active with IPv6 and port", storeRow("srv4.store", "NULL", "'2001:db8::4'", "2004", "active"), false, "", ""},
		// Mailboxes: local part, hash, quota, state.
		{"local part uppercase", mailbox("Frank", testHash, "0", "active"), false, check, "mailboxes_local_part_format"},
		{"local part leading dot", mailbox(".frank", testHash, "0", "active"), false, check, "mailboxes_local_part_format"},
		{"local part trailing hyphen", mailbox("frank-", testHash, "0", "active"), false, check, "mailboxes_local_part_format"},
		{"local part ..", mailbox("fr..ank", testHash, "0", "active"), false, check, "mailboxes_local_part_format"},
		{"local part +", mailbox("frank+tag", testHash, "0", "active"), false, check, "mailboxes_local_part_format"},
		{"local part *", mailbox("frank*master", testHash, "0", "active"), false, check, "mailboxes_local_part_format"},
		{"local part 65 characters", mailbox(strings.Repeat("f", 65), testHash, "0", "active"), false, check, "mailboxes_local_part_format"},
		{"local part 64 characters", mailbox(strings.Repeat("f", 64), testHash, "0", "active"), false, "", ""},
		{"local part with . _ -", mailbox("f.r_a-nk", testHash, "0", "active"), false, "", ""},
		{"hash unknown scheme", mailbox("frank", "{MD5-CRYPT}$1$placeholder", "0", "active"), false, check, "mailboxes_password_hash_format"},
		{"hash without scheme", mailbox("frank", "$2y$10$placeholder", "0", "active"), false, check, "mailboxes_password_hash_format"},
		{"hash with space", mailbox("frank", "{SSHA}place holder", "0", "active"), false, check, "mailboxes_password_hash_format"},
		{"hash 513 bytes", mailbox("frank", "{SSHA}"+strings.Repeat("p", 507), "0", "active"), false, check, "mailboxes_password_hash_format"},
		{"hash 512 bytes", mailbox("frank", "{SSHA}"+strings.Repeat("p", 506), "0", "active"), false, "", ""},
		{"hash BLF-CRYPT", mailbox("frank", "{BLF-CRYPT}$2y$10$placeholder", "0", "active"), false, "", ""},
		{"quota -1", mailbox("frank", testHash, "-1", "active"), false, check, "mailboxes_quota_bytes_range"},
		{"quota 0 (unlimited)", mailbox("frank", testHash, "0", "active"), false, "", ""},
		{"state unknown", mailbox("frank", testHash, "0", "deleting"), false, check, "mailboxes_state_valid"},
		{"state disabled", mailbox("frank", testHash, "0", "disabled"), false, "", ""},
		// Aliases and send-as: the local-part pattern; NULL is allowed.
		{"alias local part uppercase", alias("Info"), false, check, "aliases_local_part_format"},
		{"alias local part", alias("info"), false, "", ""},
		{"send-as local part +", sendAs("info+x"), false, check, "send_as_local_part_format"},
		{"send-as local part", sendAs("info"), false, "", ""},
		// Audit rows.
		{"actor uppercase", audit("CLI", "group.add", "acme", "{}"), false, check, "audit_log_actor_format"},
		{"actor leading digit", audit("1cli", "group.add", "acme", "{}"), false, check, "audit_log_actor_format"},
		{"actor with colon", audit("agent:srv1", "group.add", "acme", "{}"), false, "", ""},
		{"action without dot", audit("cli", "groupadd", "acme", "{}"), false, check, "audit_log_action_format"},
		{"action uppercase", audit("cli", "Group.add", "acme", "{}"), false, check, "audit_log_action_format"},
		{"action with hyphen", audit("cli", "alias-domain.add", "acme", "{}"), false, "", ""},
		{"object 321 characters", audit("cli", "group.add", strings.Repeat("o", 321), "{}"), false, check, "audit_log_object_length"},
		{"object 320 characters", audit("cli", "group.add", strings.Repeat("o", 320), "{}"), false, "", ""},
		{"details array", audit("cli", "group.add", "acme", "[]"), false, check, "audit_log_details_object"},
		{"details object", audit("cli", "group.add", "acme", `{"k": 1}`), false, "", ""},
	})
}

// Test 2: the placement weight in SQL equals the Go constant (CD13).
func TestPlacementWeight(t *testing.T) {
	d := newTestDB(t)
	var unlimited, five int64
	if err := d.conn.QueryRow(context.Background(), "SELECT keepia_placement_weight(0), keepia_placement_weight(5)").Scan(&unlimited, &five); err != nil {
		t.Fatal(err)
	}
	if unlimited != store.UnlimitedPlacementWeight {
		t.Errorf("keepia_placement_weight(0) = %d, UnlimitedPlacementWeight = %d, want them equal", unlimited, store.UnlimitedPlacementWeight)
	}
	if want := int64(10737418240); unlimited != want {
		t.Errorf("keepia_placement_weight(0) = %d, want 10 GiB, %d", unlimited, want)
	}
	if five != 5 {
		t.Errorf("keepia_placement_weight(5) = %d, want 5", five)
	}
}

// Test 3: every UNIQUE constraint refuses a duplicate, every foreign key an
// unknown row and a delete of a referenced one (RESTRICT), each with a
// valid case next to it.
func TestUniqueAndForeignKeys(t *testing.T) {
	d := newTestDB(t)
	f := seed(t, d)
	const unique, fk, restrict = "23505", "23503", "23001"
	const unknown = 999999
	runRuleCases(t, d.conn, []ruleCase{
		{"group", one("INSERT INTO customer_groups (name) VALUES ('acme')"), false, unique, "customer_groups_name_key"},
		{"new group", one("INSERT INTO customer_groups (name) VALUES ('acme2')"), false, "", ""},
		{"domain", one("INSERT INTO domains (group_id, name) VALUES (%d, 'example.org')", f.other), false, unique, "domains_name_key"},
		{"alias domain", one("INSERT INTO alias_domains (name, domain_id) VALUES ('example.info', %d)", f.net), false, unique, "alias_domains_name_key"},
		{"server", one("INSERT INTO servers (name, roles) VALUES ('srv1', '{edge}')"), false, unique, "servers_name_key"},
		{"gate name", one("INSERT INTO stores (server_id, gate_name) VALUES (%d, '%s')", f.srv4, f.activeGate), false, unique, "stores_gate_name_key"},
		{"egress port", one("INSERT INTO stores (server_id, gate_name, egress_port) VALUES (%d, 'srv4.store', 2001)", f.srv4), false, unique, "stores_egress_port_key"},
		{"new egress port", one("INSERT INTO stores (server_id, gate_name, egress_port) VALUES (%d, 'srv4.store', 2004)", f.srv4), false, "", ""},
		{"mailbox", one("INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) VALUES (%d, 'alice', '%s', 0, %d)", f.org, testHash, f.active), false, unique, "mailboxes_address_key"},
		{"same local part on another domain", one("INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) VALUES (%d, 'alice', '%s', 0, %d)", f.net, testHash, f.active), false, "", ""},
		{"alias", one("INSERT INTO aliases (domain_id, local_part) VALUES (%d, 'sales')", f.org), false, unique, "aliases_address_key"},
		{"second catch-all", one("INSERT INTO aliases (domain_id, local_part) VALUES (%d, NULL)", f.org), false, unique, "aliases_address_key"},
		{"catch-all on another domain", one("INSERT INTO aliases (domain_id, local_part) VALUES (%d, NULL)", f.net), false, "", ""},
		{"alias target", one("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", f.sales, f.alice), false, unique, "alias_targets_pkey"},
		{"send-as for the whole domain", one("INSERT INTO send_as (mailbox_id, domain_id, local_part) VALUES (%d, %d, NULL)", f.alice, f.net), false, unique, "send_as_grant_key"},
		{"send-as for an address", one("INSERT INTO send_as (mailbox_id, domain_id, local_part) VALUES (%d, %d, 'info')", f.alice, f.net), false, "", ""},

		{"unknown group", one("INSERT INTO domains (group_id, name) VALUES (%d, 'example.biz')", unknown), false, fk, "domains_group_id_fkey"},
		{"unknown domain of an alias domain", one("INSERT INTO alias_domains (name, domain_id) VALUES ('example.biz', %d)", unknown), false, fk, "alias_domains_domain_id_fkey"},
		{"unknown server", one("INSERT INTO stores (server_id, gate_name) VALUES (%d, 'srv9.store')", unknown), false, fk, "stores_server_id_fkey"},
		{"unknown store", one("INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) VALUES (%d, 'frank', '%s', 0, %d)", f.org, testHash, unknown), false, fk, "mailboxes_store_id_fkey"},
		{"unknown domain of a mailbox", one("INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) VALUES (%d, 'frank', '%s', 0, %d)", unknown, testHash, f.active), false, fk, "mailboxes_domain_id_fkey"},
		{"unknown domain of an alias", one("INSERT INTO aliases (domain_id, local_part) VALUES (%d, 'info')", unknown), false, fk, "aliases_domain_id_fkey"},
		{"unknown alias of a target", one("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", unknown, f.alice), false, fk, "alias_targets_alias_id_fkey"},
		{"unknown mailbox of a target", one("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", f.sales, unknown), false, fk, "alias_targets_mailbox_id_fkey"},
		{"unknown mailbox of a send-as", one("INSERT INTO send_as (mailbox_id, domain_id) VALUES (%d, %d)", unknown, f.net), false, fk, "send_as_mailbox_id_fkey"},
		{"unknown domain of a send-as", one("INSERT INTO send_as (mailbox_id, domain_id) VALUES (%d, %d)", f.alice, unknown), false, fk, "send_as_domain_id_fkey"},
		{"new target", one("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", f.sales, f.carol), false, "", ""},

		{"delete a group with domains", one("DELETE FROM customer_groups WHERE id = %d", f.acme), false, restrict, "domains_group_id_fkey"},
		{"delete a store with mailboxes", one("DELETE FROM stores WHERE id = %d", f.active), false, restrict, "mailboxes_store_id_fkey"},
		{"delete a mailbox with targets", one("DELETE FROM mailboxes WHERE id = %d", f.erin), false, restrict, "alias_targets_mailbox_id_fkey"},
		{"delete an empty group", []string{"INSERT INTO customer_groups (name) VALUES ('empty')", "DELETE FROM customer_groups WHERE name = 'empty'"}, false, "", ""},
	})
}

// Test 4: each trigger refuses what it guards and lets the valid case
// pass. T6 is TestAliasNeedsTarget.
func TestTriggers(t *testing.T) {
	d := newTestDB(t)
	f := seed(t, d)
	const check, unique = "23514", "23505"
	long189, long190 := labels(2, 61), labels(2, 62) // 189 and 190 characters
	local64 := strings.Repeat("l", 64)
	longDomain := func(name string) string {
		return fmt.Sprintf("INSERT INTO domains (group_id, name) VALUES (%d, '%s')", f.acme, name)
	}
	longMailbox := func(domain string) string {
		return fmt.Sprintf("INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) SELECT id, '%s', '%s', 0, %d FROM domains WHERE name = '%s'", local64, testHash, f.active, domain)
	}
	longAlias := func(domain string) string {
		return fmt.Sprintf("INSERT INTO aliases (domain_id, local_part) SELECT id, '%s' FROM domains WHERE name = '%s'", local64, domain)
	}
	longSendAs := func(domain string) string {
		return fmt.Sprintf("INSERT INTO send_as (mailbox_id, domain_id, local_part) SELECT %d, id, '%s' FROM domains WHERE name = '%s'", f.alice, local64, domain)
	}
	mailboxOn := func(store int64) []string {
		return one("INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) VALUES (%d, 'frank', '%s', 0, %d)", f.org, testHash, store)
	}
	storeOn := func(server int64) []string {
		return one("INSERT INTO stores (server_id, gate_name) VALUES (%d, 'new.store.keepia.internal')", server)
	}
	runRuleCases(t, d.conn, []ruleCase{
		// T1: a name is a domain or an alias domain, in both orders.
		{"T1 alias domain named as a domain", one("INSERT INTO alias_domains (name, domain_id) VALUES ('example.net', %d)", f.org), false, unique, "domain_name_taken"},
		{"T1 domain named as an alias domain", one("INSERT INTO domains (group_id, name) VALUES (%d, 'example.info')", f.acme), false, unique, "domain_name_taken"},
		{"T1 new domain", one("INSERT INTO domains (group_id, name) VALUES (%d, 'example.biz')", f.acme), false, "", ""},
		{"T1 new alias domain", one("INSERT INTO alias_domains (name, domain_id) VALUES ('example.biz', %d)", f.org), false, "", ""},
		// T2: an alias domain moves only within its group.
		{"T2 to another group", one("UPDATE alias_domains SET domain_id = %d WHERE name = 'example.info'", f.com), false, check, "alias_domain_group"},
		{"T2 within the group", one("UPDATE alias_domains SET domain_id = %d WHERE name = 'example.info'", f.net), false, "", ""},
		// T3: send-as stays in the group, for an address and a whole domain.
		{"T3 address of another group", one("INSERT INTO send_as (mailbox_id, domain_id, local_part) VALUES (%d, %d, 'info')", f.alice, f.com), false, check, "send_as_group"},
		{"T3 domain of another group", one("INSERT INTO send_as (mailbox_id, domain_id, local_part) VALUES (%d, %d, NULL)", f.alice, f.com), false, check, "send_as_group"},
		{"T3 address of the group", one("INSERT INTO send_as (mailbox_id, domain_id, local_part) VALUES (%d, %d, 'info')", f.alice, f.org), false, "", ""},
		{"T3 domain of the group", one("INSERT INTO send_as (mailbox_id, domain_id, local_part) VALUES (%d, %d, NULL)", f.carol, f.net), false, "", ""},
		// T4: targets in the group, for an alias and a catch-all.
		{"T4 alias to another group", one("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", f.sales, f.bob), false, check, "alias_target_group"},
		{"T4 catch-all to another group", one("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", f.catchAll, f.bob), false, check, "alias_target_group"},
		{"T4 alias in the group", one("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", f.sales, f.carol), false, "", ""},
		{"T4 catch-all in the group", one("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", f.catchAll, f.carol), false, "", ""},
		// T5: an address is a mailbox or an alias, in both orders; at most 254.
		{"T5 alias at a mailbox's address", one("INSERT INTO aliases (domain_id, local_part) VALUES (%d, 'alice')", f.org), false, unique, "address_taken"},
		{"T5 mailbox at an alias's address", one("INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) VALUES (%d, 'sales', '%s', 0, %d)", f.org, testHash, f.active), false, unique, "address_taken"},
		{"T5 alias at a new address", one("INSERT INTO aliases (domain_id, local_part) VALUES (%d, 'info')", f.org), false, "", ""},
		{"T5 mailbox on a catch-all domain", mailboxOn(f.active), false, "", ""},
		{"T5 mailbox of 255 characters", []string{longDomain(long190), longMailbox(long190)}, false, check, "address_too_long"},
		{"T5 alias of 255 characters", []string{longDomain(long190), longAlias(long190)}, false, check, "address_too_long"},
		{"T5 send-as of 255 characters", []string{longDomain(long190), longSendAs(long190)}, false, check, "address_too_long"},
		{"T5 mailbox of 254 characters", []string{longDomain(long189), longMailbox(long189)}, false, "", ""},
		{"T5 alias of 254 characters", []string{longDomain(long189), longAlias(long189)}, false, "", ""},
		{"T5 send-as of 254 characters", []string{longDomain(long189), longSendAs(long189)}, false, "", ""},
		// T7: active store, server not removed.
		{"T7 joining store", mailboxOn(f.joining), false, check, "mailbox_store_not_active"},
		{"T7 store on a removed server", mailboxOn(f.removed), false, check, "mailbox_store_server_removed"},
		{"T7 active store", mailboxOn(f.active), false, "", ""},
		// T8: a store's server has the role store and is not removed.
		{"T8 store on a server without the role", storeOn(f.srv2), false, check, "store_server_role"},
		{"T8 store on a removed server", storeOn(f.srv3), false, check, "store_server_removed"},
		{"T8 store on a store server", storeOn(f.srv4), false, "", ""},
		{"T8 roles without store on a server with stores", one("UPDATE servers SET roles = '{edge}' WHERE id = %d", f.srv1), false, check, "store_server_role"},
		{"T8 roles keeping store", one("UPDATE servers SET roles = '{store,edge}' WHERE id = %d", f.srv1), false, "", ""},
		{"T8 roles without store on a server without stores", one("UPDATE servers SET roles = '{edge}' WHERE id = %d", f.srv4), false, "", ""},
		{"T8 store added to roles", one("UPDATE servers SET roles = '{edge,store}' WHERE id = %d", f.srv2), false, "", ""},
		// T9: every immutable column, and any alias_targets update.
		{"T9 domains.group_id", one("UPDATE domains SET group_id = %d WHERE id = %d", f.other, f.org), false, check, "domains_group_id_immutable"},
		{"T9 domains.name", one("UPDATE domains SET name = 'example.biz' WHERE id = %d", f.org), false, check, "domains_name_immutable"},
		{"T9 alias_domains.name", one("UPDATE alias_domains SET name = 'example.biz' WHERE name = 'example.info'"), false, check, "alias_domains_name_immutable"},
		{"T9 servers.name", one("UPDATE servers SET name = 'srv9' WHERE id = %d", f.srv1), false, check, "servers_name_immutable"},
		{"T9 stores.server_id", one("UPDATE stores SET server_id = %d WHERE id = %d", f.srv4, f.active), false, check, "stores_server_id_immutable"},
		{"T9 stores.gate_name", one("UPDATE stores SET gate_name = 'x.store' WHERE id = %d", f.active), false, check, "stores_gate_name_immutable"},
		{"T9 mailboxes.domain_id", one("UPDATE mailboxes SET domain_id = %d WHERE id = %d", f.net, f.alice), false, check, "mailboxes_domain_id_immutable"},
		{"T9 mailboxes.local_part", one("UPDATE mailboxes SET local_part = 'alicia' WHERE id = %d", f.alice), false, check, "mailboxes_local_part_immutable"},
		{"T9 mailboxes.store_id", one("UPDATE mailboxes SET store_id = %d WHERE id = %d", f.removed, f.alice), false, check, "mailboxes_store_id_immutable"},
		{"T9 aliases.domain_id", one("UPDATE aliases SET domain_id = %d WHERE id = %d", f.net, f.sales), false, check, "aliases_domain_id_immutable"},
		{"T9 aliases.local_part", one("UPDATE aliases SET local_part = 'sale' WHERE id = %d", f.sales), false, check, "aliases_local_part_immutable"},
		{"T9 catch-all local_part", one("UPDATE aliases SET local_part = 'all' WHERE id = %d", f.catchAll), false, check, "aliases_local_part_immutable"},
		{"T9 send_as.mailbox_id", one("UPDATE send_as SET mailbox_id = %d WHERE mailbox_id = %d", f.carol, f.alice), false, check, "send_as_mailbox_id_immutable"},
		{"T9 send_as.domain_id", one("UPDATE send_as SET domain_id = %d WHERE mailbox_id = %d", f.org, f.alice), false, check, "send_as_domain_id_immutable"},
		{"T9 send_as.local_part", one("UPDATE send_as SET local_part = 'info' WHERE mailbox_id = %d", f.alice), false, check, "send_as_local_part_immutable"},
		{"T9 alias_targets.mailbox_id", one("UPDATE alias_targets SET mailbox_id = %d WHERE alias_id = %d AND mailbox_id = %d", f.carol, f.sales, f.alice), false, check, "alias_targets_immutable"},
		{"T9 alias_targets.created_at", one("UPDATE alias_targets SET created_at = now() WHERE alias_id = %d", f.sales), false, check, "alias_targets_immutable"},
		{"T9 mutable domain column", one("UPDATE domains SET active = false WHERE id = %d", f.org), false, "", ""},
		{"T9 immutable column set to its value", one("UPDATE domains SET name = name, group_id = group_id WHERE id = %d", f.org), false, "", ""},
		{"T9 mutable mailbox columns", one("UPDATE mailboxes SET quota_bytes = 1, state = 'disabled', imap_access = false, password_hash = '{SSHA}cGxhY2Vob2xkZXI=' WHERE id = %d", f.alice), false, "", ""},
		{"T9 mutable store columns", one("UPDATE stores SET state = 'joining', egress_port = 2009 WHERE id = %d", f.active), false, "", ""},
		{"T9 mutable server columns", one("UPDATE servers SET joined_at = now(), removed_at = NULL WHERE id = %d", f.srv3), false, "", ""},
		{"T9 mutable alias, alias domain and send-as columns", []string{
			fmt.Sprintf("UPDATE aliases SET active = false WHERE id = %d", f.sales),
			"UPDATE alias_domains SET active = false WHERE name = 'example.info'",
			fmt.Sprintf("UPDATE send_as SET active = false WHERE mailbox_id = %d", f.alice),
			"UPDATE customer_groups SET name = 'acme-renamed' WHERE name = 'acme'",
		}, false, "", ""},
	})
}

// Test 4, T6: at commit every alias has a target. An alias without one
// and removing an alias's last target are refused; removing one of two
// targets passes.
func TestAliasNeedsTarget(t *testing.T) {
	d := newTestDB(t)
	f := seed(t, d)
	runRuleCases(t, d.conn, []ruleCase{
		{"alias without a target", one("INSERT INTO aliases (domain_id, local_part) VALUES (%d, 'lonely')", f.org), true, "23514", "alias_without_target"},
		{"remove the last target", one("DELETE FROM alias_targets WHERE alias_id = %d", f.solo), true, "23514", "alias_without_target"},
		{"remove the last target, add another", []string{
			fmt.Sprintf("DELETE FROM alias_targets WHERE alias_id = %d", f.solo),
			fmt.Sprintf("INSERT INTO alias_targets (alias_id, mailbox_id) VALUES (%d, %d)", f.solo, f.carol),
		}, true, "", ""},
		{"alias with a target", []string{
			fmt.Sprintf("INSERT INTO aliases (domain_id, local_part) VALUES (%d, 'pair')", f.org),
			fmt.Sprintf("INSERT INTO alias_targets (alias_id, mailbox_id) SELECT id, %d FROM aliases WHERE local_part = 'pair'", f.alice),
		}, true, "", ""},
		{"remove one of two targets", one("DELETE FROM alias_targets WHERE alias_id = %d AND mailbox_id = %d", f.sales, f.erin), true, "", ""},
	})
	var n int
	if err := d.conn.QueryRow(context.Background(), "SELECT count(*) FROM alias_targets WHERE alias_id = $1", f.sales).Scan(&n); err != nil || n != 1 {
		t.Errorf("sales has %d targets (%v), want 1", n, err)
	}
}

// waitForLockWait returns once a backend of the test's database other
// than obs's waits for a lock (pg_stat_activity, wait_event_type Lock): a
// state the database shows (go-tests.md). It fails the test at once if
// done delivers first, that is if the waiter finished without waiting,
// and after testwait.Limit.
func waitForLockWait(t *testing.T, obs *pgx.Conn, done <-chan error, what string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(testwait.Limit(t))
	for {
		select {
		case err := <-done:
			t.Fatalf("%s finished without waiting for a lock: %v", what, err)
		default:
		}
		var waiting bool
		if err := obs.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s to wait for a lock", what)
		}
	}
}

// Test 4b: T6 under concurrency (revision 2, B1). A and B each remove one
// of an alias's two targets. A's check passes and locks the alias row; B's
// check waits for it, then sees A's committed delete and refuses. The
// alias keeps B's target.
func TestAliasLastTargetConcurrent(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	f := seed(t, d)
	a, b := connect(t, d.url), connect(t, d.url)
	txA, err := a.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txA.Rollback(ctx) }()
	txB, err := b.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txB.Rollback(ctx) }()
	if _, err := txA.Exec(ctx, "DELETE FROM alias_targets WHERE alias_id = $1 AND mailbox_id = $2", f.sales, f.alice); err != nil {
		t.Fatal(err)
	}
	if _, err := txB.Exec(ctx, "DELETE FROM alias_targets WHERE alias_id = $1 AND mailbox_id = $2", f.sales, f.erin); err != nil {
		t.Fatal(err)
	}
	if _, err := txA.Exec(ctx, "SET CONSTRAINTS alias_without_target IMMEDIATE"); err != nil {
		t.Fatalf("A's check: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := txB.Exec(ctx, "SET CONSTRAINTS alias_without_target IMMEDIATE")
		done <- err
	}()
	waitForLockWait(t, d.conn, done, "B's check")
	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("A's commit: %v", err)
	}
	var errB error
	select {
	case errB = <-done:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("B's check still waits after A's commit")
	}
	if code, constraint := pgRule(errB); code != "23514" || constraint != "alias_without_target" {
		t.Fatalf("B's check: %v, want alias_without_target", errB)
	}
	_ = txB.Rollback(ctx)
	var targets []int64
	rows, err := d.conn.Query(ctx, "SELECT mailbox_id FROM alias_targets WHERE alias_id = $1", f.sales)
	if err == nil {
		targets, err = pgx.CollectRows(rows, pgx.RowTo[int64])
	}
	if err != nil || !slices.Equal(targets, []int64{f.erin}) {
		t.Fatalf("sales targets %v (%v), want only erin %d", targets, err, f.erin)
	}
}
