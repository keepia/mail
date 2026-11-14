package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/keepia/mail/internal/store"
)

func names[T any](items []T, name func(T) string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, name(it))
	}
	return out
}

func wantNames(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s: %v, want %v", what, got, want)
	}
}

func wantKind(t *testing.T, what string, err, kind error, rule string) {
	t.Helper()
	if !errors.Is(err, kind) || store.Rule(err) != rule {
		t.Errorf("%s: %v (rule %q), want %v with rule %q", what, err, store.Rule(err), kind, rule)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Test 6: groups, domains and alias domains round-trip through the API;
// the list filters select; unknown names are ErrNotFound and duplicates
// ErrExists.
func TestGroupsAndDomains(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seed(t, d)

	groups, err := d.st.ListGroups(ctx)
	must(t, err)
	wantNames(t, "groups", names(groups, func(g store.Group) string { return fmt.Sprintf("%s:%d", g.Name, g.DomainCount) }), []string{"acme:2", "other:1"})
	must(t, d.st.RenameGroup(ctx, "other", "others"))
	wantKind(t, "rename an unknown group", d.st.RenameGroup(ctx, "nobody", "x"), store.ErrNotFound, "")
	wantKind(t, "rename to a taken name", d.st.RenameGroup(ctx, "others", "acme"), store.ErrExists, "customer_groups_name_key")
	_, err = d.st.CreateGroup(ctx, "acme")
	wantKind(t, "duplicate group", err, store.ErrExists, "customer_groups_name_key")
	_, err = d.st.CreateGroup(ctx, "Bad")
	wantKind(t, "bad group name", err, store.ErrRefused, "customer_groups_name_format")

	domainNames := func(group string) []string {
		ds, err := d.st.ListDomains(ctx, group)
		must(t, err)
		return names(ds, func(x store.Domain) string { return fmt.Sprintf("%s:%s:%v", x.Name, x.Group, x.Active) })
	}
	wantNames(t, "all domains", domainNames(""), []string{"example.com:others:true", "example.net:acme:true", "example.org:acme:true"})
	must(t, d.st.SetDomainActive(ctx, "example.net", false))
	wantNames(t, "acme's domains", domainNames("acme"), []string{"example.net:acme:false", "example.org:acme:true"})
	wantKind(t, "switch an unknown domain", d.st.SetDomainActive(ctx, "example.biz", true), store.ErrNotFound, "")
	_, err = d.st.CreateDomain(ctx, "example.biz", "nobody")
	wantKind(t, "domain in an unknown group", err, store.ErrNotFound, "")
	_, err = d.st.CreateDomain(ctx, "example.info", "acme")
	wantKind(t, "domain named as an alias domain", err, store.ErrExists, "domain_name_taken")

	aliasDomains := func(f store.AliasDomainFilter) []string {
		as, err := d.st.ListAliasDomains(ctx, f)
		must(t, err)
		return names(as, func(x store.AliasDomain) string {
			return fmt.Sprintf("%s>%s:%s:%v", x.Name, x.Domain, x.Group, x.Active)
		})
	}
	_, err = d.st.CreateAliasDomain(ctx, "example.de", "example.net")
	must(t, err)
	_, err = d.st.CreateAliasDomain(ctx, "example.fr", "example.com")
	must(t, err)
	_, err = d.st.CreateAliasDomain(ctx, "example.it", "example.biz")
	wantKind(t, "alias domain for an unknown domain", err, store.ErrNotFound, "")
	wantNames(t, "alias domains", aliasDomains(store.AliasDomainFilter{}), []string{"example.de>example.net:acme:true", "example.fr>example.com:others:true", "example.info>example.org:acme:true"})
	must(t, d.st.UpdateAliasDomain(ctx, "example.de", store.AliasDomainChange{Domain: ptr("example.org"), Active: ptr(false)}))
	wantNames(t, "example.org's alias domains", aliasDomains(store.AliasDomainFilter{Domain: "example.org"}), []string{"example.de>example.org:acme:false", "example.info>example.org:acme:true"})
	wantNames(t, "others' alias domains", aliasDomains(store.AliasDomainFilter{Group: "others"}), []string{"example.fr>example.com:others:true"})
	wantKind(t, "move to another group", d.st.UpdateAliasDomain(ctx, "example.de", store.AliasDomainChange{Domain: ptr("example.com")}), store.ErrRefused, "alias_domain_group")
	wantKind(t, "move to an unknown domain", d.st.UpdateAliasDomain(ctx, "example.de", store.AliasDomainChange{Domain: ptr("example.biz")}), store.ErrNotFound, "")
	wantKind(t, "update an unknown alias domain", d.st.UpdateAliasDomain(ctx, "example.it", store.AliasDomainChange{Active: ptr(true)}), store.ErrNotFound, "")
}

// Test 6: servers and stores round-trip through the API.
func TestServersAndStores(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	f := seed(t, d)

	servers, err := d.st.ListServers(ctx)
	must(t, err)
	wantNames(t, "servers", names(servers, func(s store.Server) string {
		return fmt.Sprintf("%s:%s:%v", s.Name, strings.Join(s.Roles, ","), s.RemovedAt != nil)
	}), []string{"srv1:store:false", "srv2:edge:false", "srv3:store:true", "srv4:store,edge:false"})
	must(t, d.st.SetServerRoles(ctx, "srv2", []string{"edge", "filter"}))
	wantKind(t, "roles of an unknown server", d.st.SetServerRoles(ctx, "srv9", []string{"edge"}), store.ErrNotFound, "")
	wantKind(t, "duplicate roles", d.st.SetServerRoles(ctx, "srv2", []string{"edge", "edge"}), store.ErrRefused, "servers_roles_valid")
	wantKind(t, "drop store from a server with stores", d.st.SetServerRoles(ctx, "srv1", []string{"edge"}), store.ErrRefused, "store_server_role")
	_, err = d.st.CreateServer(ctx, "srv1", []string{"edge"})
	wantKind(t, "duplicate server", err, store.ErrExists, "servers_name_key")

	_, err = d.st.CreateStore(ctx, store.NewStore{Server: "srv9", GateName: "srv9.store"})
	wantKind(t, "store on an unknown server", err, store.ErrNotFound, "")
	_, err = d.st.CreateStore(ctx, store.NewStore{Server: "srv2", GateName: "srv2.store"})
	wantKind(t, "store on a server without the role", err, store.ErrRefused, "store_server_role")
	ms, err := d.st.CreateStore(ctx, store.NewStore{Server: "srv4", GateName: "srv4.store.keepia.internal"})
	must(t, err)
	if ms.State != store.StoreJoining || ms.GateIPv4.IsValid() || ms.EgressPort != 0 {
		t.Errorf("new store %+v, want joining without address or port", ms)
	}
	wantKind(t, "activate without routing", d.st.SetStoreState(ctx, ms.GateName, store.StoreActive), store.ErrRefused, "stores_active_routable")
	v4, v6 := netip.MustParseAddr("192.0.2.4"), netip.MustParseAddr("2001:db8::4")
	must(t, d.st.SetStoreRouting(ctx, ms.GateName, store.GateRouting{GateIPv4: v4, GateIPv6: v6, EgressPort: 2004}))
	must(t, d.st.SetStoreState(ctx, ms.GateName, store.StoreActive))
	wantKind(t, "a taken port", d.st.SetStoreRouting(ctx, f.joiningGate, store.GateRouting{EgressPort: 2004}), store.ErrExists, "stores_egress_port_key")
	must(t, d.st.SetStoreRouting(ctx, ms.GateName, store.GateRouting{GateIPv6: v6, EgressPort: 2004}))
	wantKind(t, "clear the last address of an active store", d.st.SetStoreRouting(ctx, ms.GateName, store.GateRouting{EgressPort: 2004}), store.ErrRefused, "stores_active_routable")
	wantKind(t, "bad state", d.st.SetStoreState(ctx, f.joiningGate, "gone"), store.ErrRefused, "stores_state_valid")
	wantKind(t, "state of an unknown store", d.st.SetStoreState(ctx, "nowhere.store", store.StoreActive), store.ErrNotFound, "")
	wantKind(t, "routing of an unknown store", d.st.SetStoreRouting(ctx, "nowhere.store", store.GateRouting{}), store.ErrNotFound, "")

	stores, err := d.st.ListStores(ctx)
	must(t, err)
	wantNames(t, "stores", names(stores, func(s store.MailStore) string {
		return fmt.Sprintf("%s@%s:%s:%v:%v:%d", s.GateName, s.Server, s.State, s.GateIPv4, s.GateIPv6, s.EgressPort)
	}), []string{
		"srv1.store.keepia.internal@srv1:active:192.0.2.10:invalid IP:2001",
		"srv1b.store.keepia.internal@srv1:joining:invalid IP:invalid IP:0",
		"srv3.store.keepia.internal@srv3:active:invalid IP:2001:db8::3:2003",
		"srv4.store.keepia.internal@srv4:active:invalid IP:2001:db8::4:2004",
	})
}

// Test 6: mailboxes, aliases and send-as grants round-trip through the
// API; the list filters select; the hash is never listed.
func TestMailboxesAliasesSendAs(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	f := seed(t, d)
	org := func(local string) store.Address { return store.Address{LocalPart: local, Domain: "example.org"} }

	mailboxes := func(mf store.MailboxFilter) []string {
		ms, err := d.st.ListMailboxes(ctx, mf)
		must(t, err)
		return names(ms, func(m store.Mailbox) string {
			return fmt.Sprintf("%s:%s:%s:%d:%v%v%v:%s:%s", m.Address, m.Group, m.Store, m.QuotaBytes, m.IMAP, m.POP3, m.SMTP, m.State, m.Scheme)
		})
	}
	m, err := d.st.CreateMailbox(ctx, store.NewMailbox{Address: store.Address{LocalPart: "grace", Domain: "example.net"}, PasswordHash: "{SSHA512}cGxhY2Vob2xkZXI=", QuotaBytes: 0, IMAP: true, StoreID: f.active})
	must(t, err)
	if m.Store != f.activeGate || m.Scheme != "SSHA512" || m.State != store.MailboxActive {
		t.Errorf("new mailbox %+v", m)
	}
	must(t, d.st.UpdateMailbox(ctx, org("carol"), store.MailboxChange{QuotaBytes: ptr[int64](5), POP3: ptr(false), State: ptr(store.MailboxDisabled), PasswordHash: ptr("{BLF-CRYPT}$2y$10$placeholder")}))
	wantNames(t, "acme's mailboxes", mailboxes(store.MailboxFilter{Group: "acme"}), []string{
		"grace@example.net:acme:" + f.activeGate + ":0:truefalsefalse:active:SSHA512",
		"alice@example.org:acme:" + f.activeGate + ":1073741824:truetruetrue:active:ARGON2ID",
		"carol@example.org:acme:" + f.activeGate + ":5:truefalsetrue:disabled:BLF-CRYPT",
		"dave@example.org:acme:" + f.activeGate + ":1073741824:truetruetrue:active:ARGON2ID",
		"erin@example.org:acme:" + f.activeGate + ":1073741824:truetruetrue:active:ARGON2ID",
	})
	wantNames(t, "example.com's mailboxes", mailboxes(store.MailboxFilter{Domain: "example.com"}), []string{"bob@example.com:other:" + f.activeGate + ":1073741824:truetruetrue:active:ARGON2ID"})
	wantNames(t, "the joining store's mailboxes", mailboxes(store.MailboxFilter{Store: f.joiningGate}), []string{})
	wantKind(t, "update an unknown mailbox", d.st.UpdateMailbox(ctx, org("nobody"), store.MailboxChange{QuotaBytes: ptr[int64](1)}), store.ErrNotFound, "")
	wantKind(t, "bad state", d.st.UpdateMailbox(ctx, org("dave"), store.MailboxChange{State: ptr("gone")}), store.ErrRefused, "mailboxes_state_valid")
	_, err = d.st.CreateMailbox(ctx, store.NewMailbox{Address: store.Address{LocalPart: "x", Domain: "example.info"}, PasswordHash: testHash, StoreID: f.active})
	wantKind(t, "mailbox on an alias domain", err, store.ErrNotFound, "")
	_, err = d.st.CreateMailbox(ctx, store.NewMailbox{Address: org("sales"), PasswordHash: testHash, StoreID: f.active})
	wantKind(t, "mailbox at an alias", err, store.ErrExists, "address_taken")
	_, err = d.st.CreateMailbox(ctx, store.NewMailbox{Address: org("frank"), PasswordHash: testHash, StoreID: f.joining})
	wantKind(t, "mailbox on a joining store", err, store.ErrRefused, "mailbox_store_not_active")
	_, err = d.st.CreateMailbox(ctx, store.NewMailbox{Address: org("frank"), PasswordHash: testHash, StoreID: 999999})
	wantKind(t, "mailbox on an unknown store", err, store.ErrNotFound, "mailboxes_store_id_fkey")

	aliases := func(af store.AliasFilter) []string {
		as, err := d.st.ListAliases(ctx, af)
		must(t, err)
		return names(as, func(a store.Alias) string {
			return fmt.Sprintf("%s:%s:%v>%s", a.Address, a.Group, a.Active, strings.Join(addressTexts(a.Targets), ","))
		})
	}
	_, err = d.st.CreateAlias(ctx, store.Address{LocalPart: "team", Domain: "example.com"}, []store.Address{{LocalPart: "bob", Domain: "example.com"}})
	must(t, err)
	must(t, d.st.UpdateAlias(ctx, org("sales"), store.AliasChange{Add: []store.Address{org("dave"), org("carol")}, Remove: []store.Address{org("alice")}, Active: ptr(false)}))
	wantNames(t, "example.org's aliases", aliases(store.AliasFilter{Domain: "example.org"}), []string{
		"@example.org:acme:true>alice@example.org",
		"sales@example.org:acme:false>carol@example.org,dave@example.org,erin@example.org",
		"solo@example.org:acme:true>alice@example.org",
	})
	wantNames(t, "other's aliases", aliases(store.AliasFilter{Group: "other"}), []string{"team@example.com:other:true>bob@example.com"})
	wantNames(t, "no aliases", aliases(store.AliasFilter{Domain: "example.net"}), []string{})
	wantKind(t, "update an unknown alias", d.st.UpdateAlias(ctx, org("nobody"), store.AliasChange{Active: ptr(true)}), store.ErrNotFound, "")
	wantKind(t, "add an unknown target", d.st.UpdateAlias(ctx, org("solo"), store.AliasChange{Add: []store.Address{org("nobody")}}), store.ErrNotFound, "")
	wantKind(t, "remove a target that is none", d.st.UpdateAlias(ctx, org("solo"), store.AliasChange{Remove: []store.Address{org("dave")}}), store.ErrNotFound, "")
	wantKind(t, "add a target twice", d.st.UpdateAlias(ctx, org("solo"), store.AliasChange{Add: []store.Address{org("alice")}}), store.ErrExists, "alias_targets_pkey")
	wantKind(t, "remove the last target", d.st.UpdateAlias(ctx, org("solo"), store.AliasChange{Remove: []store.Address{org("alice")}}), store.ErrRefused, "alias_without_target")
	wantKind(t, "target in another group", d.st.UpdateAlias(ctx, store.Address{Domain: "example.org"}, store.AliasChange{Add: []store.Address{{LocalPart: "bob", Domain: "example.com"}}}), store.ErrRefused, "alias_target_group")
	_, err = d.st.CreateAlias(ctx, org("empty"), nil)
	wantKind(t, "alias without targets", err, store.ErrRefused, "alias_without_target")
	_, err = d.st.CreateAlias(ctx, org("alice"), []store.Address{org("dave")})
	wantKind(t, "alias at a mailbox", err, store.ErrExists, "address_taken")
	_, err = d.st.CreateAlias(ctx, store.Address{Domain: "example.org"}, []store.Address{org("dave")})
	wantKind(t, "second catch-all", err, store.ErrExists, "aliases_address_key")

	sendAs := func(sf store.SendAsFilter) []string {
		gs, err := d.st.ListSendAs(ctx, sf)
		must(t, err)
		return names(gs, func(g store.SendAs) string { return fmt.Sprintf("%s:%s:%s:%v", g.Mailbox, g.Group, g.As, g.Active) })
	}
	_, err = d.st.CreateSendAs(ctx, org("alice"), org("info"))
	must(t, err)
	_, err = d.st.CreateSendAs(ctx, org("dave"), store.Address{Domain: "example.org"})
	must(t, err)
	must(t, d.st.SetSendAsActive(ctx, org("alice"), store.Address{Domain: "example.net"}, false))
	wantNames(t, "alice's grants", sendAs(store.SendAsFilter{Mailbox: org("alice")}), []string{"alice@example.org:acme:@example.net:false", "alice@example.org:acme:info@example.org:true"})
	wantNames(t, "acme's grants", sendAs(store.SendAsFilter{Group: "acme"}), []string{"alice@example.org:acme:@example.net:false", "alice@example.org:acme:info@example.org:true", "dave@example.org:acme:@example.org:true"})
	wantNames(t, "other's grants", sendAs(store.SendAsFilter{Group: "other"}), []string{})
	_, err = d.st.CreateSendAs(ctx, org("alice"), store.Address{Domain: "example.com"})
	wantKind(t, "send-as across groups", err, store.ErrRefused, "send_as_group")
	_, err = d.st.CreateSendAs(ctx, org("alice"), org("info"))
	wantKind(t, "duplicate send-as", err, store.ErrExists, "send_as_grant_key")
	_, err = d.st.CreateSendAs(ctx, org("nobody"), org("info"))
	wantKind(t, "send-as of an unknown mailbox", err, store.ErrNotFound, "")
	wantKind(t, "switch an unknown grant", d.st.SetSendAsActive(ctx, org("alice"), org("nobody"), true), store.ErrNotFound, "")
}

func addressTexts(as []store.Address) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	return out
}

// auditRows is the number of rows in audit_log.
func auditRows(t *testing.T, d *testDB) int {
	t.Helper()
	var n int
	must(t, d.conn.QueryRow(context.Background(), "SELECT count(*) FROM audit_log").Scan(&n))
	return n
}

// Test 6: every write adds exactly one audit row in its transaction, with
// the actor, action, object and details; a refused write, also one
// refused at its commit, adds none; neither the audit rows nor the errors
// contain a password hash.
func TestAuditRows(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	f := seed(t, d)
	org := func(local string) store.Address { return store.Address{LocalPart: local, Domain: "example.org"} }
	newHash := "{SSHA512}cGxhY2Vob2xkZXItbmV3LWhhc2g="

	before := auditRows(t, d)
	must(t, d.st.UpdateMailbox(ctx, org("alice"), store.MailboxChange{PasswordHash: &newHash, SMTP: ptr(false)}))
	_, err := d.st.CreateMailbox(ctx, store.NewMailbox{Address: org("frank"), PasswordHash: testHash, QuotaBytes: 7, StoreID: f.active})
	must(t, err)
	if n := auditRows(t, d); n != before+2 {
		t.Fatalf("two writes added %d audit rows, want 2", n-before)
	}
	entries, err := d.st.ListAudit(ctx, 2)
	must(t, err)
	add, set := entries[0], entries[1]
	if add.Actor != "cli" || add.Action != "mailbox.add" || add.Object != "frank@example.org" ||
		add.Details["store"] != f.activeGate || add.Details["quota_bytes"] != float64(7) || add.Details["scheme"] != "ARGON2ID" {
		t.Errorf("mailbox.add row %+v", add)
	}
	if set.Action != "mailbox.set" || set.Object != "alice@example.org" || set.Details["password"] != "changed" ||
		set.Details["scheme"] != "SSHA512" || set.Details["smtp"] != false || len(set.Details) != 3 {
		t.Errorf("mailbox.set row %+v", set)
	}

	before = auditRows(t, d)
	refused := []error{}
	_, err = d.st.CreateDomain(ctx, "example.org", "acme")
	refused = append(refused, err)
	_, err = d.st.CreateAlias(ctx, org("empty"), nil) // refused at its commit (T6)
	refused = append(refused, err)
	refused = append(refused, d.st.UpdateAlias(ctx, org("solo"), store.AliasChange{Remove: []store.Address{org("alice")}}))
	_, err = d.st.CreateMailbox(ctx, store.NewMailbox{Address: org("grace"), PasswordHash: "{SSHA}" + newHash + " x", StoreID: f.active})
	refused = append(refused, err)
	for i, err := range refused {
		if err == nil {
			t.Errorf("refused write %d succeeded", i)
		}
		if err != nil && (strings.Contains(err.Error(), newHash) || strings.Contains(err.Error(), "cGxhY2Vob2xkZXI")) {
			t.Errorf("refused write %d: error %q contains the hash", i, err)
		}
	}
	if n := auditRows(t, d); n != before {
		t.Errorf("refused writes added %d audit rows, want none", n-before)
	}

	var all []string
	rows, err := d.conn.Query(ctx, "SELECT actor || ' ' || action || ' ' || object || ' ' || details::text FROM audit_log")
	must(t, err)
	for rows.Next() {
		var s string
		must(t, rows.Scan(&s))
		all = append(all, s)
	}
	must(t, rows.Err())
	for _, s := range all {
		for _, secret := range []string{testHash, newHash, "cGxhY2Vob2xkZXI", "argon2id$"} {
			if strings.Contains(s, secret) {
				t.Errorf("audit row %q contains %q", s, secret)
			}
		}
	}

	actor := open(t, d.url, store.WithAuditActor("agent:srv1"))
	_, err = actor.CreateGroup(ctx, "third")
	must(t, err)
	entries, err = d.st.ListAudit(ctx, 1)
	must(t, err)
	if entries[0].Actor != "agent:srv1" || entries[0].Action != "group.add" || entries[0].Object != "third" {
		t.Errorf("row of WithAuditActor %+v", entries[0])
	}
	if b, _ := json.Marshal(entries[0].Details); string(b) != "{}" {
		t.Errorf("group.add details %s, want {}", b)
	}
}

// Test 6: a write purges audit rows older than 30 days and keeps newer
// ones.
func TestAuditPurge(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seed(t, d)
	exec(t, d.conn, "INSERT INTO audit_log (at, actor, action, object) VALUES (now() - interval '31 days', 'cli', 'group.add', 'old'), (now() - interval '29 days', 'cli', 'group.add', 'recent')")
	_, err := d.st.CreateGroup(ctx, "third")
	must(t, err)
	var objects []string
	rows, err := d.conn.Query(ctx, "SELECT object FROM audit_log WHERE object IN ('old', 'recent') ORDER BY object")
	must(t, err)
	for rows.Next() {
		var s string
		must(t, rows.Scan(&s))
		objects = append(objects, s)
	}
	must(t, rows.Err())
	wantNames(t, "audit rows after the purge", objects, []string{"recent"})
}

// Test 6 (N4): two writes that purge at once both commit without waiting:
// the second skips the rows that the first, still open, is deleting.
func TestAuditPurgeSkipsLocked(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seed(t, d)
	exec(t, d.conn, "INSERT INTO audit_log (at, actor, action, object) VALUES (now() - interval '31 days', 'cli', 'group.add', 'old1'), (now() - interval '32 days', 'cli', 'group.add', 'old2')")
	resume, doneA := pauseWrite(t, func(ctx context.Context) error {
		_, err := d.st.CreateGroup(ctx, "first")
		return err
	})
	if _, err := d.short.CreateGroup(ctx, "second"); err != nil {
		t.Errorf("a second purge while the first is open: %v, want no wait", err)
	}
	resume()
	if err := result(t, "A", doneA); err != nil {
		t.Fatalf("A: %v", err)
	}
	var old int
	must(t, d.conn.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE object LIKE 'old%'").Scan(&old))
	if old != 0 {
		t.Errorf("%d old rows left after both purges", old)
	}
}
