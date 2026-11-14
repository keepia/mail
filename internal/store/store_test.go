package store_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store"
	"github.com/keepia/mail/internal/store/storetest"
)

const baseline = "00001_baseline.sql"

// migrationFiles lists the embedded migrations (migrations/*.sql, the
// files store.go embeds) in version order, so that a new migration needs
// no test edit.
func migrationFiles(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("migrations/*.sql")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}
	files := make([]string, 0, len(paths))
	for _, p := range paths {
		files = append(files, filepath.Base(p))
	}
	if files[0] != baseline {
		t.Fatalf("first migration %s, want %s", files[0], baseline)
	}
	return files // Glob sorts, and the names start with the zero-padded version
}

// migrationVersion is the version of a migration file, its number before
// the first '_'.
func migrationVersion(t *testing.T, file string) int64 {
	t.Helper()
	num, _, _ := strings.Cut(file, "_")
	v, err := strconv.ParseInt(num, 10, 64)
	if err != nil {
		t.Fatalf("migration %s: %v", file, err)
	}
	return v
}

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
// embedded migrations in order, the first applied of them applied.
func checkStatus(t *testing.T, st *store.Store, step string, files []string, applied int) {
	t.Helper()
	statuses, err := st.MigrationStatus(context.Background())
	if err != nil {
		t.Fatalf("%s: status: %v", step, err)
	}
	if len(statuses) != len(files) {
		t.Fatalf("%s: status %+v, want %v", step, statuses, files)
	}
	for i, s := range statuses {
		want := i < applied
		if s.Path != files[i] || s.Applied != want {
			t.Fatalf("%s: status %+v, want %s applied=%v", step, s, files[i], want)
		}
		if want && s.AppliedAt.IsZero() {
			t.Errorf("%s: %s applied without a time", step, s.Path)
		}
	}
}

// tables lists the public tables of the database at dbURL.
func tables(t *testing.T, dbURL string) []string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	rows, err := conn.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'goose_db_version' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// Every migration applies, the last one rolls back, every one rolls back
// down to none, and all apply again. Down restoring the exact schema is
// TestMigrationDownRestoresSchema.
func TestMigrateUpDownUp(t *testing.T) {
	ctx := context.Background()
	files := migrationFiles(t)
	last := migrationVersion(t, files[len(files)-1])
	dbURL := storetest.NewUnmigrated(t)
	st := open(t, dbURL, store.ForMigrations())

	checkStatus(t, st, "fresh", files, 0)

	applied, err := st.Migrate(ctx)
	if err != nil || strings.Join(applied, " ") != strings.Join(files, " ") {
		t.Fatalf("first migrate: applied %v, err %v, want %v", applied, err, files)
	}
	checkStatus(t, st, "after migrate", files, len(files))
	if n := versionRows(t, dbURL, last); n != 1 {
		t.Fatalf("after migrate: %d rows for version %d", n, last)
	}

	if applied, err = st.Migrate(ctx); err != nil || len(applied) != 0 {
		t.Fatalf("second migrate: applied %v, err %v", applied, err)
	}

	down, err := st.MigrateDown(ctx)
	if err != nil || down != files[len(files)-1] {
		t.Fatalf("migrate down: %q, %v", down, err)
	}
	checkStatus(t, st, "after down", files, len(files)-1)
	if n := versionRows(t, dbURL, last); n != 0 {
		t.Fatalf("after down: %d rows for version %d", n, last)
	}
	for i := len(files) - 2; i >= 0; i-- {
		if down, err := st.MigrateDown(ctx); err != nil || down != files[i] {
			t.Fatalf("migrate down to %d: %q, %v", i, down, err)
		}
	}
	checkStatus(t, st, "after down to none", files, 0)
	if got := tables(t, dbURL); len(got) != 0 {
		t.Fatalf("after every down: tables %v", got)
	}
	if _, err := st.MigrateDown(ctx); err == nil {
		t.Error("a down succeeded with nothing to roll back")
	}

	if applied, err = st.Migrate(ctx); err != nil || len(applied) != len(files) {
		t.Fatalf("migrate after down: applied %v, err %v", applied, err)
	}
	checkStatus(t, st, "after migrate again", files, len(files))
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

// Open rejects, before it connects and with a text that names no part of
// it, a URL with a stray '@' (an unescaped '@' in the password, also with
// a fallback host) and every string that is not a URL, such as the
// keyword/value form.
func TestOpenRejectsUnsafeURL(t *testing.T) {
	for dbURL, want := range map[string]string{
		"postgres://keepia:sec@ret-not-real@127.0.0.1:1/keepia":              "%40",
		"postgres://keepia:sec@127.0.0.1:1,ret@not-real:2/keepia":            "%40",
		"host=sec@ret-not-real port=1 user=keepia dbname=keepia":             "must start with postgres://",
		"host=127.0.0.1 port=1 user=keepia password=sec host=ret-not-real":   "must start with postgres://",
		"host=127.0.0.1,sec@ret-not-real port=1,2 user=keepia dbname=keepia": "must start with postgres://",
	} {
		_, err := store.Open(context.Background(), dbURL)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error with %q", dbURL, err, want)
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
