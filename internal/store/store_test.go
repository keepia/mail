package store_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
)

const baseline = "00001_baseline.sql"

// versionRows is the number of applied rows for version in the database's
// goose_db_version table, 0 when the table does not exist.
func versionRows(t *testing.T, dbURL string, version int64) int {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('goose_db_version') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		return 0
	}
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM goose_db_version WHERE version_id = $1 AND is_applied`, version).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// open opens a store on dbURL that is closed when the test ends.
func open(t *testing.T, dbURL string, opts ...store.Option) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), dbURL, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

// checkStatus fails the test unless MigrationStatus lists exactly the
// baseline, applied as want says.
func checkStatus(t *testing.T, st *store.Store, step string, want bool) {
	t.Helper()
	statuses, err := st.MigrationStatus(context.Background())
	if err != nil {
		t.Fatalf("%s: status: %v", step, err)
	}
	if len(statuses) != 1 || statuses[0].Path != baseline || statuses[0].Applied != want {
		t.Fatalf("%s: status %+v, want %s applied=%v", step, statuses, baseline, want)
	}
	if want && statuses[0].AppliedAt.IsZero() {
		t.Errorf("%s: applied without a time", step)
	}
}

func TestMigrateUpDownUp(t *testing.T) {
	ctx := context.Background()
	dbURL := storetest.NewUnmigrated(t)
	st := open(t, dbURL, store.ForMigrations())

	checkStatus(t, st, "fresh", false)

	applied, err := st.Migrate(ctx)
	if err != nil || len(applied) != 1 || applied[0] != baseline {
		t.Fatalf("first migrate: applied %v, err %v", applied, err)
	}
	checkStatus(t, st, "after migrate", true)
	if n := versionRows(t, dbURL, 1); n != 1 {
		t.Fatalf("after migrate: %d rows for version 1", n)
	}

	if applied, err = st.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Fatalf("second migrate: applied %v, err %v", applied, err)
	}

	down, err := st.MigrateDown(ctx)
	if err != nil || down != baseline {
		t.Fatalf("migrate down: %q, %v", down, err)
	}
	checkStatus(t, st, "after down", false)
	if n := versionRows(t, dbURL, 1); n != 0 {
		t.Fatalf("after down: %d rows for version 1", n)
	}
	if _, err := st.MigrateDown(ctx); err == nil {
		t.Error("a second down succeeded with nothing to roll back")
	}

	if applied, err = st.Migrate(ctx); err != nil || len(applied) != 1 {
		t.Fatalf("migrate after down: applied %v, err %v", applied, err)
	}
	checkStatus(t, st, "after migrate again", true)
}

// downSection is goose's Down annotation on a line of its own.
var downSection = regexp.MustCompile(`(?m)^-- \+goose Down[ \t]*$`)

// Every migration has a Down section. goose takes a missing one as empty:
// MigrateDown would then "roll back" a migration without undoing it, which
// TestMigrateUpDownUp cannot see for the no-op baseline.
func TestMigrationsHaveDown(t *testing.T) {
	files, err := filepath.Glob("migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !downSection.Match(src) {
			t.Errorf("%s has no -- +goose Down section", f)
		}
	}
}

// Open rejects a connection string with a stray '@' (an unescaped '@' in
// the password, or in a host) before it connects, with a text that names
// no part of it: URLs (strayAt) and the keyword/value form, whose host
// and fallback hosts hostHasAt checks.
func TestOpenRejectsAtInHost(t *testing.T) {
	for _, dbURL := range []string{
		"postgres://keepia:sec@ret-not-real@127.0.0.1:1/keepia",
		"postgres://keepia:sec@127.0.0.1:1,ret@not-real:2/keepia",
		"host=sec@ret-not-real port=1 user=keepia dbname=keepia",
		"host=127.0.0.1,sec@ret-not-real port=1,2 user=keepia dbname=keepia",
	} {
		_, err := store.Open(context.Background(), dbURL)
		if err == nil || !strings.Contains(err.Error(), "%40") {
			t.Errorf("%s: %v, want the percent-encoding error", dbURL, err)
			continue
		}
		for _, s := range []string{"sec", "ret-not", "not-real", "127.0.0.1"} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("error %q contains %q", err, s)
			}
		}
	}
}

func TestPing(t *testing.T) {
	st := storetest.New(t)
	if err := st.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := st.Ping(context.Background()); err == nil {
		t.Error("ping on a closed store succeeded")
	}
}
