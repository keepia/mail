package store_test

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/testwait"
)

// holdLock takes pg_advisory_xact_lock(class, key) in a transaction on a
// connection of its own to d's database and returns the function that
// ends the transaction, which frees the lock. key is an SQL expression,
// so the test computes it as the trigger does.
func holdLock(t *testing.T, d *testDB, class int32, key string, args ...any) (release func()) {
	t.Helper()
	ctx := context.Background()
	tx, err := connect(t, d.url).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1, "+key+")", append([]any{class}, args...)...); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release = func() { once.Do(func() { _ = tx.Rollback(ctx) }) }
	t.Cleanup(release)
	return release
}

// openTx begins a transaction on a connection of its own, runs stmt in it
// and leaves it open until the returned function rolls it back.
func openTx(t *testing.T, d *testDB, stmt string, args ...any) (rollback func()) {
	t.Helper()
	ctx := context.Background()
	tx, err := connect(t, d.url).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, stmt, args...); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
	var once sync.Once
	rollback = func() { once.Do(func() { _ = tx.Rollback(ctx) }) }
	t.Cleanup(rollback)
	return rollback
}

func wantLockTimeout(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, store.ErrLockTimeout) {
		t.Errorf("%s: %v, want ErrLockTimeout", what, err)
	}
}

// Test 5: T1 and T5 take their advisory locks, with the classes of
// locks.go and the trigger's key. While a test connection holds one, an
// insert of that name or address fails after the short lock timeout; once
// it is free, the insert passes.
func TestNameAndAddressLocks(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	f := seed(t, d)

	release := holdLock(t, d, store.LockClassNames, "hashtext($2)", "example.biz")
	_, err := d.short.CreateDomain(ctx, "example.biz", "acme")
	wantLockTimeout(t, "domain insert with the names lock held", err)
	_, err = d.short.CreateAliasDomain(ctx, "example.biz", "example.org")
	wantLockTimeout(t, "alias domain insert with the names lock held", err)
	if _, err := d.short.CreateDomain(ctx, "example.cc", "acme"); err != nil {
		t.Errorf("another name with the names lock held: %v", err)
	}
	release()
	if _, err := d.short.CreateDomain(ctx, "example.biz", "acme"); err != nil {
		t.Errorf("domain insert after the release: %v", err)
	}

	release = holdLock(t, d, store.LockClassAddresses, "hashtext($2::bigint || '/' || $3)", f.org, "frank")
	frank := store.Address{LocalPart: "frank", Domain: "example.org"}
	_, err = d.short.CreateMailbox(ctx, store.NewMailbox{Address: frank, PasswordHash: testHash, StoreID: f.active})
	wantLockTimeout(t, "mailbox insert with the addresses lock held", err)
	_, err = d.short.CreateAlias(ctx, frank, []store.Address{{LocalPart: "alice", Domain: "example.org"}})
	wantLockTimeout(t, "alias insert with the addresses lock held", err)
	release()
	if _, err := d.short.CreateMailbox(ctx, store.NewMailbox{Address: frank, PasswordHash: testHash, StoreID: f.active}); err != nil {
		t.Errorf("mailbox insert after the release: %v", err)
	}
}

// Test 5: T7 and T8 read their rows FOR SHARE. While a mailbox insert is
// uncommitted, a state change of its store and a remove of its server
// wait (and fail after the short lock timeout); while a store insert is
// uncommitted, a roles update of its server waits.
func TestRowShareLocks(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	f := seed(t, d)
	shortConn := connect(t, d.url)
	exec(t, shortConn, "SET lock_timeout = '50ms'")

	rollback := openTx(t, d, "INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) VALUES ($1, 'frank', $2, 0, $3)", f.org, testHash, f.active)
	err := d.short.SetStoreState(ctx, f.activeGate, store.StoreJoining)
	wantLockTimeout(t, "store state change during a mailbox insert (T7's store FOR SHARE)", err)
	_, err = shortConn.Exec(ctx, "UPDATE servers SET removed_at = now() WHERE id = $1", f.srv1)
	if code, _ := pgRule(err); code != "55P03" {
		t.Errorf("server remove during a mailbox insert (T7's server FOR SHARE): %v, want 55P03", err)
	}
	rollback()
	if err := d.short.SetStoreState(ctx, f.activeGate, store.StoreJoining); err != nil {
		t.Errorf("store state change after the rollback: %v", err)
	}
	if _, err := shortConn.Exec(ctx, "UPDATE servers SET removed_at = now() WHERE id = $1", f.srv1); err != nil {
		t.Errorf("server remove after the rollback: %v", err)
	}

	rollback = openTx(t, d, "INSERT INTO stores (server_id, gate_name) VALUES ($1, 'srv4.store.keepia.internal')", f.srv4)
	err = d.short.SetServerRoles(ctx, "srv4", []string{"edge"})
	wantLockTimeout(t, "roles update during a store insert (T8's server FOR SHARE)", err)
	rollback()
	if err := d.short.SetServerRoles(ctx, "srv4", []string{"edge"}); err != nil {
		t.Errorf("roles update after the rollback: %v", err)
	}
}

// hashLockHeld tells whether some backend holds the hash lock, read from
// pg_locks on obs (the two-int4 form shows as classid, objid, objsubid 2).
func hashLockHeld(t *testing.T, obs *pgx.Conn) bool {
	t.Helper()
	var n int
	if err := obs.QueryRow(context.Background(), `
		SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND classid::bigint = $1 AND objid::bigint = 0 AND objsubid = 2 AND granted`,
		store.LockClassHash).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// Test 5c: WithHashLock runs fn only under the hash lock, and calls
// FreeOSMemory exactly once on every return path, while it still holds
// the lock when fn ran (C6).
func TestWithHashLock(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	obs := connect(t, d.url)
	var frees int
	var heldAtFree []bool
	t.Cleanup(store.SetFreeOSMemory(func() {
		frees++
		heldAtFree = append(heldAtFree, hashLockHeld(t, obs))
	}))
	check := func(step string, wantFrees int) {
		t.Helper()
		if frees != wantFrees {
			t.Errorf("%s: FreeOSMemory called %d times in all, want %d", step, frees, wantFrees)
		}
	}

	// The lock held elsewhere: the timeout, and fn never runs.
	release := holdLock(t, d, store.LockClassHash, "0")
	ran := false
	err := d.short.WithHashLock(ctx, func() error { ran = true; return nil })
	wantLockTimeout(t, "WithHashLock with the lock held", err)
	if ran {
		t.Error("fn ran while another session held the hash lock")
	}
	check("lock timeout", 1)
	release()

	// fn runs under the lock; FreeOSMemory runs before the commit.
	err = d.short.WithHashLock(ctx, func() error {
		ran = true
		if !hashLockHeld(t, obs) {
			t.Error("fn runs without the hash lock")
		}
		if frees != 1 {
			t.Error("FreeOSMemory ran before fn")
		}
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("WithHashLock: %v, fn ran %v", err, ran)
	}
	check("success", 2)
	if !heldAtFree[1] {
		t.Error("FreeOSMemory ran after the commit, want it while the lock is held")
	}
	if hashLockHeld(t, obs) {
		t.Error("hash lock still held after WithHashLock returned")
	}

	// fn's error is returned, and FreeOSMemory still runs once.
	errFn := errors.New("placeholder failure")
	if err := d.short.WithHashLock(ctx, func() error { return errFn }); !errors.Is(err, errFn) {
		t.Errorf("WithHashLock with a failing fn: %v, want fn's error", err)
	}
	check("fn error", 3)
	if !heldAtFree[2] {
		t.Error("FreeOSMemory after a failing fn ran without the lock")
	}
	if hashLockHeld(t, obs) {
		t.Error("hash lock still held after a failing fn")
	}

	// A cancelled context: no transaction, FreeOSMemory still runs once.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := d.short.WithHashLock(cctx, func() error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("WithHashLock with a cancelled context: %v", err)
	}
	check("cancelled", 4)
}

// Test 5d: every store-API write runs READ COMMITTED, also when the
// database's default is another level; T1, T5, T6 and T8's roles branch
// refuse a write in any other level (N3, C2).
func TestReadCommittedRequired(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	f := seed(t, d)
	u, err := url.Parse(d.url)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, d.conn, "ALTER DATABASE "+pgx.Identifier{u.Path[1:]}.Sanitize()+" SET default_transaction_isolation = 'repeatable read'")
	rr := open(t, d.url) // new connections get the new default
	raw := connect(t, d.url)
	var level string
	if err := raw.QueryRow(ctx, "SHOW default_transaction_isolation").Scan(&level); err != nil || level != "repeatable read" {
		t.Fatalf("default isolation %q (%v), want repeatable read", level, err)
	}

	if _, err := rr.CreateDomain(ctx, "example.biz", "acme"); err != nil {
		t.Errorf("API domain insert under a repeatable read default: %v", err)
	}
	frank := store.Address{LocalPart: "frank", Domain: "example.biz"}
	if _, err := rr.CreateMailbox(ctx, store.NewMailbox{Address: frank, PasswordHash: testHash, StoreID: f.active}); err != nil {
		t.Errorf("API mailbox insert under a repeatable read default: %v", err)
	}
	if _, err := rr.CreateAlias(ctx, store.Address{LocalPart: "info", Domain: "example.biz"}, []store.Address{frank}); err != nil {
		t.Errorf("API alias insert under a repeatable read default: %v", err)
	}
	if err := rr.UpdateAlias(ctx, store.Address{LocalPart: "sales", Domain: "example.org"}, store.AliasChange{Remove: []store.Address{{LocalPart: "erin", Domain: "example.org"}}}); err != nil {
		t.Errorf("API target removal under a repeatable read default: %v", err)
	}
	if err := rr.SetServerRoles(ctx, "srv4", []string{"store"}); err != nil {
		t.Errorf("API roles update under a repeatable read default: %v", err)
	}

	for _, level := range []string{"REPEATABLE READ", "SERIALIZABLE"} {
		runRuleCases(t, raw, []ruleCase{
			{"T1 domain, " + level, []string{"SET TRANSACTION ISOLATION LEVEL " + level, "INSERT INTO domains (group_id, name) SELECT id, 'example.cc' FROM customer_groups WHERE name = 'acme'"}, true, "25001", "read_committed_required"},
			{"T1 alias domain, " + level, []string{"SET TRANSACTION ISOLATION LEVEL " + level, "INSERT INTO alias_domains (name, domain_id) SELECT 'example.cc', id FROM domains WHERE name = 'example.org'"}, true, "25001", "read_committed_required"},
			{"T5 mailbox, " + level, []string{"SET TRANSACTION ISOLATION LEVEL " + level, "INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, store_id) SELECT id, 'grace', '" + testHash + "', 0, (SELECT id FROM stores WHERE gate_name = 'srv1.store.keepia.internal') FROM domains WHERE name = 'example.org'"}, true, "25001", "read_committed_required"},
			{"T5 alias, " + level, []string{"SET TRANSACTION ISOLATION LEVEL " + level, "INSERT INTO aliases (domain_id, local_part) SELECT id, 'grace' FROM domains WHERE name = 'example.org'"}, true, "25001", "read_committed_required"},
			{"T6 target removal, " + level, []string{"SET TRANSACTION ISOLATION LEVEL " + level, "DELETE FROM alias_targets WHERE alias_id = (SELECT id FROM aliases WHERE local_part = 'info')"}, true, "25001", "read_committed_required"},
			{"T8 roles, " + level, []string{"SET TRANSACTION ISOLATION LEVEL " + level, "UPDATE servers SET roles = '{store,edge}' WHERE name = 'srv4'"}, true, "25001", "read_committed_required"},
			{"READ COMMITTED, " + level + " row", []string{"SET TRANSACTION ISOLATION LEVEL READ COMMITTED", "UPDATE servers SET roles = '{store,edge}' WHERE name = 'srv4'"}, false, "", ""},
		})
	}
}

// aliasTargets lists the targets of the alias addr, sorted.
func aliasTargets(t *testing.T, st *store.Store, addr store.Address) []string {
	t.Helper()
	aliases, err := st.ListAliases(context.Background(), store.AliasFilter{Domain: addr.Domain})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range aliases {
		if a.Address == addr {
			var out []string
			for _, tg := range a.Targets {
				out = append(out, tg.String())
			}
			return out
		}
	}
	t.Fatalf("no alias %s", addr)
	return nil
}

// The alias updates of the C1 tests: A adds carol and removes alice, B
// adds dave and removes erin, on sales (alice, erin).
var (
	sales   = store.Address{LocalPart: "sales", Domain: "example.org"}
	updateA = store.AliasChange{Add: []store.Address{{LocalPart: "carol", Domain: "example.org"}}, Remove: []store.Address{{LocalPart: "alice", Domain: "example.org"}}}
	updateB = store.AliasChange{Add: []store.Address{{LocalPart: "dave", Domain: "example.org"}}, Remove: []store.Address{{LocalPart: "erin", Domain: "example.org"}}}
)

// pauseWrite runs the write run in the background and returns once it is
// paused right before its COMMIT (the WithBeforeCommit seam), with all its
// statements, audit row and purge done; resume lets it commit, and its
// result arrives on done.
func pauseWrite(t *testing.T, run func(ctx context.Context) error) (resume func(), done <-chan error) {
	t.Helper()
	paused, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	ctx := store.WithBeforeCommit(context.Background(), func() {
		close(paused)
		<-release
	})
	go func() { result <- run(ctx) }()
	var once sync.Once
	resume = func() { once.Do(func() { close(release) }) }
	t.Cleanup(resume)
	select {
	case <-paused:
	case err := <-result:
		t.Fatalf("the paused write finished before its commit: %v", err)
	case <-time.After(testwait.Limit(t)):
		t.Fatal("the paused write never reached its commit")
	}
	return resume, result
}

// pauseA is pauseWrite for A's update of sales (updateA).
func pauseA(t *testing.T, st *store.Store) (resume func(), done <-chan error) {
	t.Helper()
	return pauseWrite(t, func(ctx context.Context) error { return st.UpdateAlias(ctx, sales, updateA) })
}

func result(t *testing.T, what string, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(testwait.Limit(t)):
		t.Fatalf("%s did not finish", what)
		return nil
	}
}

// C1: an alias update locks the alias row FOR UPDATE as its first
// statement. While A's update of an alias is open, B's update of the same
// alias fails with ErrLockTimeout before it changes any target, not with a
// deadlock (40P01) at its commit.
func TestAliasUpdateLocksAliasFirst(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seed(t, d)
	resume, doneA := pauseA(t, d.st)

	reachedCommit := false
	err := d.short.UpdateAlias(store.WithBeforeCommit(ctx, func() { reachedCommit = true }), sales, updateB)
	wantLockTimeout(t, "B's update while A's is open", err)
	if reachedCommit {
		t.Error("B changed its targets while A held the alias: its first statement did not lock the alias row")
	}
	resume()
	if err := result(t, "A", doneA); err != nil {
		t.Fatalf("A: %v", err)
	}
	if got := aliasTargets(t, d.st, sales); !slices.Equal(got, []string{"carol@example.org", "erin@example.org"}) {
		t.Errorf("targets after A: %v", got)
	}
}

// C1: two concurrent updates of one alias that each add and remove a
// target both succeed, one after the other. Without the first-statement
// lock, both take KEY SHARE on the alias for their inserts, and at commit
// each T6 waits for the other's: a deadlock (40P01).
func TestConcurrentAliasUpdatesDoNotDeadlock(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	seed(t, d)
	resume, doneA := pauseA(t, d.st)

	passedFirst := make(chan struct{})
	doneB := make(chan error, 1)
	go func() {
		doneB <- d.st.UpdateAlias(store.WithBeforeCommit(ctx, func() { close(passedFirst) }), sales, updateB)
	}()
	waitForLockWait(t, d.conn, doneB, "B's update")
	select {
	case <-passedFirst:
		// B changed its targets while A was open: let both commit and
		// report what happens (the deadlock).
		resume()
		errA, errB := result(t, "A", doneA), result(t, "B", doneB)
		t.Fatalf("B got past its first statement while A held the alias; A: %v, B: %v", errA, errB)
	default:
	}
	resume()
	if err := result(t, "A", doneA); err != nil {
		t.Errorf("A: %v", err)
	}
	if err := result(t, "B", doneB); err != nil {
		t.Errorf("B: %v", err)
	}
	if got := aliasTargets(t, d.st, sales); !slices.Equal(got, []string{"carol@example.org", "dave@example.org"}) {
		t.Errorf("targets after A and B: %v, want carol and dave", got)
	}
}
