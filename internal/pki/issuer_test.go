package pki_test

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/join"
	"github.com/keepia/mail/internal/pki"
	"github.com/keepia/mail/internal/pki/pkitest"
	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
	"github.com/keepia/mail/internal/testwait"
)

var dbNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// placeholderHash is a stored hash that the schema accepts, never a real
// password's.
const placeholderHash = "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$cGxhY2Vob2xkZXJzYWx0$cGxhY2Vob2xkZXItaGFzaC1ub3QtcmVhbA"

type env struct {
	st   *store.Store
	url  string
	obs  *pgx.Conn
	keys pkitest.Keys
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	e := &env{url: storetest.NewUnmigrated(t), keys: pkitest.NewKeys(t, dbNow)}
	st, err := store.Open(ctx, e.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	e.st = st
	e.obs, err = pgx.Connect(ctx, e.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.obs.Close(ctx) })
	return e
}

// addServer adds a server with a token through join.AddServer.
func (e *env) addServer(t *testing.T, name string, roles ...string) join.Token {
	t.Helper()
	tok, err := join.AddServer(context.Background(), e.st, e.keys.Anchor(pki.AnchorService).Cert, name, roles, time.Hour, dbNow)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *env) issue(t *testing.T, server string, p pki.Purpose, role string) *x509.Certificate {
	t.Helper()
	_, key := pkitest.CSR(t)
	c, err := pki.IssueForServer(context.Background(), e.st, e.keys, server, p, role, key.Public(), dbNow)
	if err != nil {
		t.Fatalf("issue %s to %s: %v", p, server, err)
	}
	return c
}

// lists reads the stored lists and verifies each with its anchor.
func (e *env) lists(t *testing.T, now time.Time) map[pki.AnchorName]*pki.CRL {
	t.Helper()
	rows, err := e.st.ListCRLs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[pki.AnchorName]*pki.CRL{}
	for _, r := range rows {
		c, err := pki.VerifyCRL(r.DER, e.keys.Anchor(pki.AnchorName(r.Anchor)).Cert, nil, now)
		if err != nil {
			t.Fatalf("list of %s: %v", r.Anchor, err)
		}
		if c.Number.Int64() != r.Number {
			t.Fatalf("list of %s: number %d stored as %d", r.Anchor, c.Number, r.Number)
		}
		out[pki.AnchorName(r.Anchor)] = c
	}
	return out
}

func (e *env) scalar(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := e.obs.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func numbers(m map[pki.AnchorName]*pki.CRL) map[pki.AnchorName]int64 {
	out := map[pki.AnchorName]int64{}
	for k, v := range m {
		out[k] = v.Number.Int64()
	}
	return out
}

// I1, P11: issuance follows the role policy and takes only the CSR's key.
func TestIssueByRole(t *testing.T) {
	e := newEnv(t)
	e.addServer(t, "s1", pki.RoleStore)
	e.addServer(t, "e1", pki.RoleEdge)
	gate := e.issue(t, "s1", pki.PurposeGate, pki.RoleStore)
	if len(gate.DNSNames) != 1 || gate.DNSNames[0] != "s1.store.keepia.internal" || len(gate.URIs) != 0 ||
		len(gate.ExtKeyUsage) != 1 || gate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("store gate: DNS %v URI %v EKU %v", gate.DNSNames, gate.URIs, gate.ExtKeyUsage)
	}
	edge := e.issue(t, "e1", pki.PurposeEdgeDovecot, "")
	var e1 int64
	if err := e.obs.QueryRow(context.Background(), "SELECT id FROM servers WHERE name = 'e1'").Scan(&e1); err != nil {
		t.Fatal(err)
	}
	if len(edge.URIs) != 1 || edge.URIs[0].String() != "keepia:edge-dovecot:"+big.NewInt(e1).String() || len(edge.DNSNames) != 0 {
		t.Errorf("edge-dovecot: URI %v DNS %v", edge.URIs, edge.DNSNames)
	}
	// The CSR asked for control.keepia.internal: only its key is used.
	agent := e.issue(t, "s1", pki.PurposeAgent, "")
	if len(agent.DNSNames) != 0 || agent.Subject.CommonName == pki.ControlGateName {
		t.Errorf("agent certificate took the CSR's names: %v %q", agent.DNSNames, agent.Subject.CommonName)
	}
	if n := e.scalar(t, "SELECT count(*) FROM certificates WHERE purpose = 'gate' AND dns_name = 's1.store.keepia.internal' AND anchor = 'service'"); n != 1 {
		t.Errorf("%d gate rows recorded", n)
	}
	// The control server's gate certificate comes from serve (CD34).
	leaf, key, err := pki.IssueControlGate(context.Background(), e.st, e.keys, dbNow)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.DNSNames[0] != pki.ControlGateName || !key.PublicKey.Equal(leaf.PublicKey) {
		t.Errorf("control gate leaf %v", leaf.DNSNames)
	}
	if n := e.scalar(t, "SELECT count(*) FROM certificates WHERE purpose = 'control-gate' AND server_id IS NULL AND dns_name = $1", pki.ControlGateName); n != 1 {
		t.Errorf("%d control-gate rows", n)
	}
}

// I2: refused are a store server asking for edge-dovecot, a purpose of a
// later release, the control gate's name, and a removed server.
func TestIssueRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addServer(t, "s1", pki.RoleStore)
	e.addServer(t, "c1", pki.RoleControl)
	_, key := pkitest.CSR(t)
	for _, c := range []struct {
		server  string
		purpose pki.Purpose
		role    string
	}{
		{"s1", pki.PurposeEdgeDovecot, ""},
		{"s1", pki.PurposeKeepiaEdge, ""},
		{"s1", pki.PurposeGate, pki.RoleEdge},
		{"c1", pki.PurposeGate, pki.RoleControl},
		{"s1", pki.PurposeStore, ""},
	} {
		if _, err := pki.IssueForServer(ctx, e.st, e.keys, c.server, c.purpose, c.role, key.Public(), dbNow); !errors.Is(err, pki.ErrPolicy) {
			t.Errorf("%s %s %s: %v, want ErrPolicy", c.server, c.purpose, c.role, err)
		}
	}
	if _, err := pki.RevokeServer(ctx, e.st, e.keys, "s1", dbNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.IssueForServer(ctx, e.st, e.keys, "s1", pki.PurposeAgent, "", key.Public(), dbNow); !errors.Is(err, pki.ErrServerRemoved) {
		t.Errorf("removed server: %v, want ErrServerRemoved", err)
	}
	if n := e.scalar(t, "SELECT count(*) FROM certificates"); n != 0 {
		t.Errorf("%d certificates recorded by refused issuances", n)
	}
}

// I3, R3: a removal revokes every certificate of the server, puts each
// serial into the next list of its anchor, raises every number by one,
// invalidates the server's tokens and sets removed_at.
func TestRevokeServer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addServer(t, "s1", pki.RoleStore)
	e.addServer(t, "s2", pki.RoleStore)
	if err := pki.Reissue(ctx, e.st, e.keys, dbNow); err != nil {
		t.Fatal(err)
	}
	before := numbers(e.lists(t, dbNow))
	agent := e.issue(t, "s1", pki.PurposeAgent, "")
	gate := e.issue(t, "s1", pki.PurposeGate, pki.RoleStore)
	other := e.issue(t, "s2", pki.PurposeAgent, "")
	n, err := pki.RevokeServer(ctx, e.st, e.keys, "s1", dbNow)
	if err != nil || n != 2 {
		t.Fatalf("remove: %d, %v", n, err)
	}
	after := e.lists(t, dbNow)
	for _, a := range pki.Anchors {
		if after[a].Number.Int64() != before[a]+1 {
			t.Errorf("%s: number %d, want %d", a, after[a].Number, before[a]+1)
		}
	}
	if !after[pki.AnchorAgent].IsRevoked(agent.SerialNumber) || !after[pki.AnchorService].IsRevoked(gate.SerialNumber) {
		t.Error("a serial of the removed server is not in its anchor's list")
	}
	if after[pki.AnchorAgent].IsRevoked(other.SerialNumber) {
		t.Error("another server's certificate was revoked")
	}
	if n := e.scalar(t, "SELECT count(*) FROM join_tokens t JOIN servers s ON s.id = t.server_id WHERE s.name = 's1' AND t.invalidated_at IS NULL"); n != 0 {
		t.Errorf("%d tokens of s1 still valid", n)
	}
	if n := e.scalar(t, "SELECT count(*) FROM join_tokens t JOIN servers s ON s.id = t.server_id WHERE s.name = 's2' AND t.invalidated_at IS NULL"); n != 1 {
		t.Errorf("s2's token: %d valid, want 1", n)
	}
	if n := e.scalar(t, "SELECT count(*) FROM servers WHERE name = 's1' AND removed_at IS NOT NULL"); n != 1 {
		t.Error("s1 has no removed_at")
	}
	if n := e.scalar(t, "SELECT count(*) FROM certificates WHERE revoked_at IS NOT NULL AND revocation_reason = 5"); n != 2 {
		t.Errorf("%d certificates revoked for cessationOfOperation, want 2", n)
	}
	if _, err := pki.RevokeServer(ctx, e.st, e.keys, "s1", dbNow); !errors.Is(err, pki.ErrServerRemoved) {
		t.Errorf("a second removal: %v", err)
	}
	if _, err := pki.RevokeServer(ctx, e.st, e.keys, "nope", dbNow); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown server: %v", err)
	}
}

// I3 (extended): when the reissue step fails, the revocation rolls back
// with it: nothing is revoked, removed_at stays empty, the tokens stay
// valid and the lists keep their numbers.
func TestRevokeServerRollsBackWithItsLists(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addServer(t, "s1", pki.RoleStore)
	if err := pki.Reissue(ctx, e.st, e.keys, dbNow); err != nil {
		t.Fatal(err)
	}
	before := numbers(e.lists(t, dbNow))
	e.issue(t, "s1", pki.PurposeAgent, "")
	boom := errors.New("reissue failed")
	hctx := pki.WithHooks(ctx, pki.Hooks{FailReissue: func() error { return boom }})
	if _, err := pki.RevokeServer(hctx, e.st, e.keys, "s1", dbNow); !errors.Is(err, boom) {
		t.Fatalf("remove: %v, want the reissue's error", err)
	}
	if n := e.scalar(t, "SELECT count(*) FROM certificates WHERE revoked_at IS NOT NULL"); n != 0 {
		t.Errorf("%d certificates revoked", n)
	}
	if n := e.scalar(t, "SELECT count(*) FROM servers WHERE removed_at IS NOT NULL"); n != 0 {
		t.Error("removed_at set")
	}
	if n := e.scalar(t, "SELECT count(*) FROM join_tokens WHERE invalidated_at IS NULL"); n != 1 {
		t.Errorf("%d valid tokens, want 1", n)
	}
	if got := numbers(e.lists(t, dbNow)); !mapsEqual(got, before) {
		t.Errorf("numbers %v, want %v", got, before)
	}
}

func mapsEqual(a, b map[pki.AnchorName]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// L2: the control server cannot be removed, nor a store server whose
// stores hold mailboxes.
func TestRevokeServerRefuses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addServer(t, "c1", pki.RoleControl, pki.RoleStore)
	if _, err := pki.RevokeServer(ctx, e.st, e.keys, "c1", dbNow); !errors.Is(err, pki.ErrRemoveControl) {
		t.Errorf("control: %v", err)
	}
	e.addServer(t, "s1", pki.RoleStore)
	mailboxStore(t, e, "s1")
	if _, err := e.st.CreateMailbox(ctx, store.NewMailbox{
		Address: store.Address{LocalPart: "alice", Domain: "example.org"}, PasswordHash: placeholderHash, StoreID: storeID(t, e, "s1"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.RevokeServer(ctx, e.st, e.keys, "s1", dbNow); !errors.Is(err, pki.ErrStoreHoldsMailboxes) {
		t.Errorf("store with a mailbox: %v", err)
	}
	if n := e.scalar(t, "SELECT count(*) FROM servers WHERE removed_at IS NOT NULL"); n != 0 {
		t.Error("a refused removal set removed_at")
	}
}

// mailboxStore gives the server an active store and the group and domain
// example.org.
func mailboxStore(t *testing.T, e *env, server string) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.st.CreateGroup(ctx, "acme"); err != nil && !errors.Is(err, store.ErrExists) {
		t.Fatal(err)
	}
	if _, err := e.st.CreateDomain(ctx, "example.org", "acme"); err != nil && !errors.Is(err, store.ErrExists) {
		t.Fatal(err)
	}
	gate := server + ".store.keepia.internal"
	if _, err := e.st.CreateStore(ctx, store.NewStore{Server: server, GateName: gate, GateIPv4: netip.MustParseAddr("192.0.2.10"), EgressPort: 2000}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetStoreState(ctx, gate, store.StoreActive); err != nil {
		t.Fatal(err)
	}
}

func storeID(t *testing.T, e *env, server string) int64 {
	t.Helper()
	return e.scalar(t, "SELECT s.id FROM stores s JOIN servers v ON v.id = s.server_id WHERE v.name = $1", server)
}

// I4: an expired revoked certificate drops out of the next list.
func TestExpiredEntryDropsOut(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addServer(t, "s1", pki.RoleStore)
	agent := e.issue(t, "s1", pki.PurposeAgent, "")
	if _, err := pki.RevokeServer(ctx, e.st, e.keys, "s1", dbNow); err != nil {
		t.Fatal(err)
	}
	if !e.lists(t, dbNow)[pki.AnchorAgent].IsRevoked(agent.SerialNumber) {
		t.Fatal("the revoked serial is not listed")
	}
	later := agent.NotAfter.Add(time.Second)
	if err := pki.Reissue(ctx, e.st, e.keys, later); err != nil {
		t.Fatal(err)
	}
	if e.lists(t, later)[pki.AnchorAgent].IsRevoked(agent.SerialNumber) {
		t.Error("an expired certificate is still listed")
	}
}

// R2, C8: Reissue raises all four numbers; ReissueIfDue reissues only
// when a list is missing or the oldest is at least 23 h old, and every
// list is valid for exactly 7 days.
func TestReissueSchedule(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if did, err := pki.ReissueIfDue(ctx, e.st, e.keys, dbNow); err != nil || !did {
		t.Fatalf("first: %v, %v", did, err)
	}
	first := e.lists(t, dbNow)
	for _, a := range pki.Anchors {
		if first[a].Number.Int64() != 1 || first[a].NextUpdate.Sub(first[a].ThisUpdate) != 7*24*time.Hour {
			t.Errorf("%s: number %d, valid %s", a, first[a].Number, first[a].NextUpdate.Sub(first[a].ThisUpdate))
		}
	}
	if did, err := pki.ReissueIfDue(ctx, e.st, e.keys, dbNow.Add(23*time.Hour-time.Second)); err != nil || did {
		t.Errorf("at 22:59:59: reissued %v, %v", did, err)
	}
	if did, err := pki.ReissueIfDue(ctx, e.st, e.keys, dbNow.Add(23*time.Hour)); err != nil || !did {
		t.Errorf("at 23:00: reissued %v, %v", did, err)
	}
	if err := pki.Reissue(ctx, e.st, e.keys, dbNow.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for a, n := range numbers(e.lists(t, dbNow.Add(24*time.Hour))) {
		if n != 3 {
			t.Errorf("%s: number %d, want 3", a, n)
		}
	}
}

// published is a list as a test hook saw it signed.
type published struct {
	by      string
	anchor  pki.AnchorName
	number  int64
	serials []*big.Int
}

type recorder struct {
	mu   sync.Mutex
	seen []published
}

func (r *recorder) hook(by string) func(pki.AnchorName, int64, []*big.Int) {
	return func(a pki.AnchorName, n int64, s []*big.Int) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.seen = append(r.seen, published{by: by, anchor: a, number: n, serials: s})
	}
}

func (r *recorder) list() []published {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

// R4: a revocation and a reissue at the same time. While A's removal
// holds the CRL lock after its read, B's Reissue waits for the lock
// (pg_locks); afterwards each anchor's numbers are distinct and rising,
// and B's lists, signed after A's commit, name A's revoked serial.
func TestRevocationAndReissueSerialize(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addServer(t, "s1", pki.RoleStore)
	if err := pki.Reissue(ctx, e.st, e.keys, dbNow); err != nil {
		t.Fatal(err)
	}
	agent := e.issue(t, "s1", pki.PurposeAgent, "")
	var rec recorder
	reached, release := make(chan struct{}), make(chan struct{})
	aCtx := pki.WithHooks(ctx, pki.Hooks{
		AfterRead: func() { close(reached); <-release },
		Signed:    rec.hook("A"),
	})
	aDone := make(chan error, 1)
	go func() { _, err := pki.RevokeServer(aCtx, e.st, e.keys, "s1", dbNow); aDone <- err }()
	select {
	case <-reached:
	case err := <-aDone:
		t.Fatalf("A returned before its hook: %v", err)
	case <-time.After(testwait.Limit(t)):
		t.Fatal("A did not reach its hook")
	}
	bDone := make(chan error, 1)
	go func() {
		bDone <- pki.Reissue(pki.WithHooks(ctx, pki.Hooks{Signed: rec.hook("B")}), e.st, e.keys, dbNow)
	}()
	storetest.WaitFor(t, e.obs, bDone, "B waiting for the CRL lock", storetest.AdvisoryWaitQuery, int64(store.LockClassCRL))
	close(release)
	for _, c := range []chan error{aDone, bDone} {
		if err := <-c; err != nil {
			t.Fatal(err)
		}
	}
	last := map[pki.AnchorName]int64{}
	for _, p := range rec.list() {
		if p.number <= last[p.anchor] {
			t.Errorf("%s published number %d after %d", p.anchor, p.number, last[p.anchor])
		}
		last[p.anchor] = p.number
		if p.by == "B" && p.anchor == pki.AnchorAgent && !slices.ContainsFunc(p.serials, func(s *big.Int) bool { return s.Cmp(agent.SerialNumber) == 0 }) {
			t.Error("B's agent list, signed after A's commit, does not name the revoked serial")
		}
	}
	if len(rec.list()) != 8 {
		t.Errorf("%d lists published, want 8", len(rec.list()))
	}
}

// R5: two Reissues on an empty anchor_crls, one held at its read: the
// other waits for the CRL lock, and the numbers are 1 and 2, never 1
// twice.
func TestFirstReissuesSerialize(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var rec recorder
	reached := make(chan struct{}, 2)
	release := make(chan struct{})
	hctx := pki.WithHooks(ctx, pki.Hooks{
		AfterRead: func() { reached <- struct{}{}; <-release },
		Signed:    rec.hook(""),
	})
	done := make(chan error, 2)
	for range 2 {
		go func() { done <- pki.Reissue(hctx, e.st, e.keys, dbNow) }()
	}
	select {
	case <-reached:
	case <-time.After(testwait.Limit(t)):
		t.Fatal("no Reissue reached its read")
	}
	second := make(chan error, 1)
	go func() {
		select {
		case <-reached:
			second <- errors.New("the second Reissue read without the lock")
		case <-release:
		}
	}()
	storetest.WaitFor(t, e.obs, second, "the second Reissue waiting for the CRL lock", storetest.AdvisoryWaitQuery, int64(store.LockClassCRL))
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	got := map[pki.AnchorName][]int64{}
	for _, p := range rec.list() {
		got[p.anchor] = append(got[p.anchor], p.number)
	}
	for _, a := range pki.Anchors {
		if !slices.Equal(got[a], []int64{1, 2}) {
			t.Errorf("%s: numbers %v, want [1 2]", a, got[a])
		}
	}
}

// X3: a mailbox insert that holds the server row (T7's FOR SHARE) when
// `server remove` starts commits while the removal waits; the removal's
// count, a fresh READ COMMITTED snapshot after its row lock, then sees
// it and refuses.
func TestRemoveCountsAMailboxCommittedWhileItWaited(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addServer(t, "s1", pki.RoleStore)
	mailboxStore(t, e, "s1")
	adder, err := pgx.Connect(ctx, e.url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adder.Close(ctx) }()
	tx, err := adder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id)
		SELECT d.id, 'alice', $1, 0, $2 FROM domains d WHERE d.name = 'example.org'`, placeholderHash, storeID(t, e, "s1")); err != nil {
		t.Fatal(err)
	}
	removeDone := make(chan error, 1)
	go func() { _, err := pki.RevokeServer(ctx, e.st, e.keys, "s1", dbNow); removeDone <- err }()
	storetest.WaitFor(t, e.obs, removeDone, "the removal waiting for the server row", storetest.LockWaitQuery)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-removeDone; !errors.Is(err, pki.ErrStoreHoldsMailboxes) {
		t.Errorf("remove: %v, want ErrStoreHoldsMailboxes", err)
	}
	if n := e.scalar(t, "SELECT count(*) FROM servers WHERE removed_at IS NOT NULL"); n != 0 {
		t.Error("the server was removed with a mailbox on it")
	}
}

// C13: `server remove` cannot race a mailbox onto the store it removes.
// The removal holds the server row after its count; a mailbox insert
// then waits for that row (T7's FOR SHARE), and after the removal's
// commit it is refused. Exactly one succeeds.
func TestRemoveRacesNoMailbox(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addServer(t, "s1", pki.RoleStore)
	mailboxStore(t, e, "s1")
	sid := storeID(t, e, "s1")
	reached, release := make(chan struct{}), make(chan struct{})
	rctx := pki.WithHooks(ctx, pki.Hooks{AfterMailboxCount: func() { close(reached); <-release }})
	removeDone := make(chan error, 1)
	go func() { _, err := pki.RevokeServer(rctx, e.st, e.keys, "s1", dbNow); removeDone <- err }()
	select {
	case <-reached:
	case err := <-removeDone:
		t.Fatalf("remove returned before its hook: %v", err)
	case <-time.After(testwait.Limit(t)):
		t.Fatal("remove did not reach its hook")
	}
	addDone := make(chan error, 1)
	go func() {
		_, err := e.st.CreateMailbox(ctx, store.NewMailbox{
			Address: store.Address{LocalPart: "alice", Domain: "example.org"}, PasswordHash: placeholderHash, StoreID: sid,
		})
		addDone <- err
	}()
	storetest.WaitFor(t, e.obs, addDone, "the mailbox insert waiting for the server row", storetest.LockWaitQuery)
	close(release)
	if err := <-removeDone; err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := <-addDone; !errors.Is(err, store.ErrRefused) || store.Rule(err) != "mailbox_store_server_removed" {
		t.Errorf("mailbox insert: %v, want mailbox_store_server_removed", err)
	}
	if n := e.scalar(t, "SELECT count(*) FROM mailboxes"); n != 0 {
		t.Errorf("%d mailboxes on the removed server", n)
	}
}
