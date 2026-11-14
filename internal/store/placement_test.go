package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/password"
	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/testwait"
)

// Quotas of the placement tests.
const (
	gib       int64 = 1 << 30
	unlimited int64 = 0
)

// placementDB is a test database with the group acme, its domain
// example.org and its alias domain example.info, and the stores that a
// test adds (store).
type placementDB struct {
	*testDB
	stores map[string]int64 // gate name to id
	port   int32
}

func newPlacementDB(t *testing.T) *placementDB {
	t.Helper()
	ctx := context.Background()
	p := &placementDB{testDB: newTestDB(t), stores: map[string]int64{}, port: 2000}
	_, err := p.st.CreateGroup(ctx, "acme")
	must(t, err)
	_, err = p.st.CreateDomain(ctx, "example.org", "acme")
	must(t, err)
	_, err = p.st.CreateAliasDomain(ctx, "example.info", "example.org")
	must(t, err)
	return p
}

// store adds the store gate on the server srv (created with the role
// store if needed), routable, and active unless joining is set.
func (p *placementDB) store(t *testing.T, srv, gate string, joining bool) {
	t.Helper()
	ctx := context.Background()
	var exists bool
	if err := p.conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM servers WHERE name = $1)", srv).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		_, err := p.st.CreateServer(ctx, srv, []string{"store"})
		must(t, err)
	}
	p.port++
	ms, err := p.st.CreateStore(ctx, store.NewStore{
		Server: srv, GateName: gate, GateIPv4: netip.AddrFrom4([4]byte{192, 0, 2, byte(p.port % 250)}), EgressPort: p.port,
	})
	must(t, err)
	p.stores[gate] = ms.ID
	if !joining {
		must(t, p.st.SetStoreState(ctx, gate, store.StoreActive))
	}
}

// mailbox adds local@example.org with quota directly on the store gate,
// disabled if so.
func (p *placementDB) mailbox(t *testing.T, local, gate string, quota int64, disabled bool) {
	t.Helper()
	ctx := context.Background()
	addr := store.Address{LocalPart: local, Domain: "example.org"}
	_, err := p.st.CreateMailbox(ctx, store.NewMailbox{Address: addr, PasswordHash: testHash, QuotaBytes: quota, StoreID: p.stores[gate]})
	must(t, err)
	if disabled {
		must(t, p.st.UpdateMailbox(ctx, addr, store.MailboxChange{State: ptr(store.MailboxDisabled)}))
	}
}

// removeServer marks the server srv removed, as N2's server remove does.
func (p *placementDB) removeServer(t *testing.T, srv string) {
	t.Helper()
	exec(t, p.conn, "UPDATE servers SET removed_at = now() WHERE name = $1", srv)
}

// add places local@example.org (1 GiB, an imported hash) with st, on
// gate if it is not empty.
func add(st *store.Store, local, gate string) (store.Mailbox, error) {
	return st.AddMailbox(context.Background(), store.AddMailboxRequest{
		Address: store.Address{LocalPart: local, Domain: "example.org"}, PasswordHash: testHash,
		QuotaBytes: gib, IMAP: true, POP3: true, SMTP: true, Store: gate,
	})
}

// wantPlaced checks that the add succeeded on the store want.
func wantPlaced(t *testing.T, what string, m store.Mailbox, err error, want string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if m.Store != want {
		t.Errorf("%s: placed on %s, want %s", what, m.Store, want)
	}
}

// mailboxCount is the number of mailboxes in d.
func mailboxCount(t *testing.T, d *testDB) int {
	t.Helper()
	var n int
	if err := d.conn.QueryRow(context.Background(), "SELECT count(*) FROM mailboxes").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Test 11: the ranking of #93 with the rules of revision 2. Each case has
// a database of its own, since placement looks at every store.
func TestPlacementRanking(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, p *placementDB)
		want  string
	}{
		{"the lowest sum wins", func(t *testing.T, p *placementDB) {
			p.store(t, "srv1", "store-a", false)
			p.store(t, "srv1", "store-b", false)
			p.mailbox(t, "a1", "store-a", 2*gib, false)
			p.mailbox(t, "b1", "store-b", gib, false)
		}, "store-b"},
		{"on equal sums, the fewer mailboxes win", func(t *testing.T, p *placementDB) {
			p.store(t, "srv1", "store-a", false)
			p.store(t, "srv1", "store-b", false)
			p.mailbox(t, "a1", "store-a", gib, false)
			p.mailbox(t, "a2", "store-a", gib, false)
			p.mailbox(t, "b1", "store-b", 2*gib, false)
		}, "store-b"},
		{"on equal counts, the gate name in byte order", func(t *testing.T, p *placementDB) {
			p.store(t, "srv1", "store-9", false)
			p.store(t, "srv1", "store-10", false)
		}, "store-10"},
		{"a joining store is skipped even when emptier", func(t *testing.T, p *placementDB) {
			p.store(t, "srv1", "store-a", false)
			p.store(t, "srv1", "store-b", true)
			p.mailbox(t, "a1", "store-a", 5*gib, false)
		}, "store-a"},
		{"disabled mailboxes count", func(t *testing.T, p *placementDB) {
			p.store(t, "srv1", "store-a", false)
			p.store(t, "srv1", "store-b", false)
			p.mailbox(t, "a1", "store-a", 5*gib, true)
			p.mailbox(t, "b1", "store-b", gib, false)
		}, "store-b"},
		{"a store on a removed server is skipped even when emptier", func(t *testing.T, p *placementDB) {
			p.store(t, "srv1", "store-a", false)
			p.store(t, "srv2", "store-b", false)
			p.mailbox(t, "a1", "store-a", 5*gib, false)
			p.removeServer(t, "srv2")
		}, "store-a"},
		{"an unlimited mailbox weighs 10 GiB: more than 5 GiB", func(t *testing.T, p *placementDB) {
			p.store(t, "srv1", "store-a", false)
			p.store(t, "srv1", "store-b", false)
			p.mailbox(t, "a1", "store-a", unlimited, false)
			p.mailbox(t, "b1", "store-b", 5*gib, false)
		}, "store-b"},
		{"an unlimited mailbox weighs 10 GiB: less than 20 GiB", func(t *testing.T, p *placementDB) {
			p.store(t, "srv1", "store-a", false)
			p.store(t, "srv1", "store-b", false)
			p.mailbox(t, "a1", "store-a", unlimited, false)
			p.mailbox(t, "b1", "store-b", 20*gib, false)
		}, "store-a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPlacementDB(t)
			c.setup(t, p)
			m, err := add(p.st, "new", "")
			wantPlaced(t, c.name, m, err, c.want)
		})
	}
}

// Test 11: --store places on the store it names, also a fuller one; a
// joining or unknown store, or one on a removed server, is refused and
// nothing is added.
func TestPlacementStoreOverride(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-a", false)
	p.store(t, "srv1", "store-b", false)
	p.store(t, "srv1", "store-joining", true)
	p.store(t, "srv2", "store-removed", false)
	p.removeServer(t, "srv2")
	p.mailbox(t, "a1", "store-a", 5*gib, false)

	m, err := add(p.st, "new", "store-a")
	wantPlaced(t, "--store store-a", m, err, "store-a")
	for gate, kind := range map[string]error{
		"store-joining": store.ErrRefused, "store-removed": store.ErrRefused, "store-unknown": store.ErrNotFound,
	} {
		before := mailboxCount(t, p.testDB)
		_, err := add(p.st, "x-"+gate, gate)
		if !errors.Is(err, kind) || !strings.Contains(err.Error(), gate) {
			t.Errorf("--store %s: %v, want %v naming the store", gate, err, kind)
		}
		if errors.Is(kind, store.ErrRefused) && !strings.Contains(err.Error(), "is not active or its server was removed") {
			t.Errorf("--store %s: %v", gate, err)
		}
		if after := mailboxCount(t, p.testDB); after != before {
			t.Errorf("--store %s added a mailbox", gate)
		}
	}
}

// Test 11: an add on an unknown domain or an alias domain is refused
// before anything else; the alias domain's error names its domain.
func TestPlacementDomain(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-a", false)
	_, err := p.st.AddMailbox(context.Background(), store.AddMailboxRequest{
		Address: store.Address{LocalPart: "new", Domain: "example.info"}, PasswordHash: testHash, Store: "",
	})
	if !errors.Is(err, store.ErrRefused) || !strings.Contains(err.Error(), "alias domain of example.org") {
		t.Errorf("an alias domain: %v", err)
	}
	_, err = p.st.AddMailbox(context.Background(), store.AddMailboxRequest{
		Address: store.Address{LocalPart: "new", Domain: "example.net"}, PasswordHash: testHash,
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown domain: %v", err)
	}
}

// Test 11: with no eligible store, an add with a new password fails
// before it hashes: the hash lock is never taken. A test connection holds
// the hash lock, so a hash would fail with the lock timeout instead, and
// WithHashLock's FreeOSMemory, called on each of its return paths, never
// runs.
func TestPlacementNoStoreHashesNothing(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-joining", true)
	p.store(t, "srv2", "store-removed", false)
	p.removeServer(t, "srv2")
	holdLock(t, p.testDB, store.LockClassHash, "0")
	frees := 0
	t.Cleanup(store.SetFreeOSMemory(func() { frees++ }))
	_, err := p.short.AddMailbox(context.Background(), store.AddMailboxRequest{
		Address: store.Address{LocalPart: "new", Domain: "example.org"}, Password: "placeholder-pass-1", QuotaBytes: gib,
	})
	if !errors.Is(err, store.ErrRefused) || errors.Is(err, store.ErrLockTimeout) ||
		!strings.Contains(err.Error(), "none is active on a server that is not removed") {
		t.Errorf("no eligible store: %v, want ErrRefused before the hash", err)
	}
	if frees != 0 {
		t.Errorf("WithHashLock ran %d times", frees)
	}
}

// Test 11, the lock is taken before the read: while a test connection
// holds the placement lock, an add fails with ErrLockTimeout.
func TestPlacementTakesLock(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-a", false)
	release := holdLock(t, p.testDB, store.LockClassPlacement, "0")
	_, err := add(p.short, "new", "")
	wantLockTimeout(t, "an add while the placement lock is held", err)
	if n := mailboxCount(t, p.testDB); n != 0 {
		t.Errorf("%d mailboxes after the timeout", n)
	}
	release()
	m, err := add(p.short, "new", "")
	wantPlaced(t, "the add after the release", m, err, "store-a")
}

// placementWaiting tells whether a backend of obs's database other than
// obs's own waits for the placement lock (pg_locks, granted false).
func placementWaiting(t *testing.T, obs *pgx.Conn) bool {
	t.Helper()
	var waiting bool
	if err := obs.QueryRow(context.Background(), `
		SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_database d ON d.oid = l.database
		WHERE l.locktype = 'advisory' AND l.classid::bigint = $1 AND l.objid::bigint = 0 AND l.objsubid = 2
			AND NOT l.granted AND d.datname = current_database() AND l.pid <> pg_backend_pid())`,
		store.LockClassPlacement).Scan(&waiting); err != nil {
		t.Fatal(err)
	}
	return waiting
}

// blockFirst is an afterChoose seam that blocks the first placement that
// reaches it until release is called; later ones pass. chosen delivers
// the store that the first one chose.
type blockFirst struct {
	first, released sync.Once
	chosen          chan string
	release         chan struct{}
}

func newBlockFirst(t *testing.T) *blockFirst {
	b := &blockFirst{chosen: make(chan string, 1), release: make(chan struct{})}
	t.Cleanup(b.unblock)
	return b
}

func (b *blockFirst) seam(gate string) {
	first := false
	b.first.Do(func() { first = true })
	if first {
		b.chosen <- gate
		<-b.release
	}
}

// unblock lets the blocked placement go on.
func (b *blockFirst) unblock() { b.released.Do(func() { close(b.release) }) }

// waitChosen returns the store the first placement chose, once it is
// blocked in the seam.
func (b *blockFirst) waitChosen(t *testing.T, done <-chan error) string {
	t.Helper()
	select {
	case gate := <-b.chosen:
		return gate
	case err := <-done:
		t.Fatalf("the first add finished without reaching the seam: %v", err)
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the first add never reached the seam")
	}
	return ""
}

// Test 11, two concurrent adds: A chooses a store and blocks in the seam
// with the placement lock held. B waits for the lock (pg_locks shows it
// not granted: a state the database shows). Once A commits, B chooses
// with A's mailbox counted: of two empty active stores, A and B land on
// different ones.
func TestPlacementConcurrentAdds(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-a", false)
	p.store(t, "srv1", "store-b", false)
	b := newBlockFirst(t)
	st := open(t, p.url, store.WithAfterChoose(b.seam))

	type result struct {
		m   store.Mailbox
		err error
	}
	doneA, doneB := make(chan error, 1), make(chan result, 1)
	var mA store.Mailbox
	go func() {
		var err error
		mA, err = add(st, "a", "")
		doneA <- err
	}()
	gateA := b.waitChosen(t, doneA)
	go func() {
		m, err := add(st, "b", "")
		doneB <- result{m, err}
	}()
	deadline := time.Now().Add(testwait.Limit(t))
	for !placementWaiting(t, p.conn) {
		select {
		case r := <-doneB:
			b.unblock()
			<-doneA
			t.Fatalf("B finished without waiting for the placement lock: on %s (%v); A chose %s", r.m.Store, r.err, gateA)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("B never waited for the placement lock")
		}
	}
	b.unblock()
	if err := <-doneA; err != nil {
		t.Fatalf("A: %v", err)
	}
	var r result
	select {
	case r = <-doneB:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("B did not finish")
	}
	if r.err != nil {
		t.Fatalf("B: %v", r.err)
	}
	if mA.Store != gateA || r.m.Store == mA.Store {
		t.Errorf("A on %s (chose %s), B on %s: want two different stores", mA.Store, gateA, r.m.Store)
	}
}

// C4: the window between the choice and the insert. A chooses a store and
// blocks in the seam; another connection commits removed_at for that
// store's server; A's insert is then refused by T7, A fails with "the
// store's server was removed; try again", and no mailbox row exists.
func TestPlacementServerRemovedAfterChoice(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-a", false)
	b := newBlockFirst(t)
	st := open(t, p.url, store.WithAfterChoose(b.seam))
	done := make(chan error, 1)
	go func() {
		_, err := add(st, "a", "")
		done <- err
	}()
	if gate := b.waitChosen(t, done); gate != "store-a" {
		t.Fatalf("chose %s", gate)
	}
	p.removeServer(t, "srv1")
	b.unblock()
	var err error
	select {
	case err = <-done:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("A did not finish")
	}
	if store.Rule(err) != "mailbox_store_server_removed" || !errors.Is(err, store.ErrRefused) ||
		err.Error() != "the store's server was removed; try again" {
		t.Errorf("A: %v (rule %q), want the removed server's refusal", err, store.Rule(err))
	}
	if n := mailboxCount(t, p.testDB); n != 0 {
		t.Errorf("%d mailboxes after the refusal", n)
	}
}

// Test 11, the hash lock: while a test connection holds it, an add with a
// new password fails with the lock timeout and its message, and adds
// nothing; an add with an imported hash does not take the lock and
// succeeds.
func TestPlacementHashLock(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-a", false)
	release := holdLock(t, p.testDB, store.LockClassHash, "0")
	_, err := p.short.AddMailbox(context.Background(), store.AddMailboxRequest{
		Address: store.Address{LocalPart: "new", Domain: "example.org"}, Password: "placeholder-pass-1", QuotaBytes: gib,
	})
	wantLockTimeout(t, "a password add while the hash lock is held", err)
	if err == nil || err.Error() != "another keepia-mail command is hashing a password; try again" {
		t.Errorf("the message: %v", err)
	}
	m, err := add(p.short, "imported", "")
	wantPlaced(t, "an imported hash while the hash lock is held", m, err, "store-a")
	if n := mailboxCount(t, p.testDB); n != 1 {
		t.Errorf("%d mailboxes, want only the imported one", n)
	}

	// Once the lock is free, the password add stores an Argon2id hash of
	// the section-3 format; the audit row has the scheme, never the hash.
	release()
	m, err = p.short.AddMailbox(context.Background(), store.AddMailboxRequest{
		Address: store.Address{LocalPart: "new", Domain: "example.org"}, Password: "placeholder-pass-1", QuotaBytes: gib,
	})
	wantPlaced(t, "the password add after the release", m, err, "store-a")
	var stored string
	if err := p.conn.QueryRow(context.Background(), "SELECT password_hash FROM mailboxes WHERE local_part = 'new'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	a, err := password.ParseArgon2ID(stored)
	if err != nil || a.Memory != 65536 || a.Time != 3 || a.Threads != 1 || len(a.Salt) != 16 || len(a.Key) != 32 {
		t.Errorf("stored %+v, %v", a, err)
	}
	var details string
	if err := p.conn.QueryRow(context.Background(),
		"SELECT details::text FROM audit_log WHERE action = 'mailbox.add' AND object = 'new@example.org'").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, stored) || !strings.Contains(details, `"scheme": "ARGON2ID"`) {
		t.Errorf("audit details %s", details)
	}
}

// SetMailboxPassword hashes the new password under the hash lock and
// keeps the other changes; an unknown mailbox fails before the hash.
func TestSetMailboxPassword(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-a", false)
	p.mailbox(t, "alice", "store-a", gib, false)
	frees := 0
	t.Cleanup(store.SetFreeOSMemory(func() { frees++ }))
	ctx := context.Background()
	err := p.st.SetMailboxPassword(ctx, store.Address{LocalPart: "nobody", Domain: "example.org"}, "placeholder-pass-2", store.MailboxChange{})
	if !errors.Is(err, store.ErrNotFound) || frees != 0 {
		t.Errorf("an unknown mailbox: %v, %d hashes", err, frees)
	}
	alice := store.Address{LocalPart: "alice", Domain: "example.org"}
	must(t, p.st.SetMailboxPassword(ctx, alice, "placeholder-pass-2", store.MailboxChange{QuotaBytes: ptr(2 * gib)}))
	if frees != 1 {
		t.Errorf("%d hashes, want 1", frees)
	}
	var stored string
	var quota int64
	if err := p.conn.QueryRow(ctx, "SELECT password_hash, quota_bytes FROM mailboxes WHERE local_part = 'alice'").Scan(&stored, &quota); err != nil {
		t.Fatal(err)
	}
	if _, err := password.ParseArgon2ID(stored); err != nil || quota != 2*gib {
		t.Errorf("stored scheme %q, quota %d: %v", password.Scheme(stored), quota, err)
	}
}

// The placement weight's Go constant is the SQL function's (part 1 test 2
// checks it too); here the ranking query is checked to use it: one
// unlimited mailbox against one of exactly 10 GiB is a tie that the gate
// name decides.
func TestPlacementUnlimitedTie(t *testing.T) {
	p := newPlacementDB(t)
	p.store(t, "srv1", "store-b", false)
	p.store(t, "srv1", "store-a", false)
	p.mailbox(t, "b1", "store-b", unlimited, false)
	p.mailbox(t, "a1", "store-a", store.UnlimitedPlacementWeight, false)
	m, err := add(p.st, "new", "")
	wantPlaced(t, fmt.Sprintf("unlimited against %d bytes", store.UnlimitedPlacementWeight), m, err, "store-a")
}
