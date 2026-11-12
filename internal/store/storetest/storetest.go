// Package storetest provides a throwaway PostgreSQL database for tests.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/keepia/mail/internal/store"
)

// EnvURL names the variable holding a PostgreSQL URL with CREATEDB rights.
const EnvURL = "TEST_DATABASE_URL"

// New creates a fresh, migrated database that is dropped when the test
// ends, and returns a store opened on it. See NewUnmigrated for when the
// test is skipped or fails.
func New(tb testing.TB) *store.Store {
	tb.Helper()
	dbURL := NewUnmigrated(tb)
	ctx := context.Background()
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		tb.Fatal(err)
	}
	// Registered after the drop, so it runs before it.
	tb.Cleanup(st.Close)
	if _, err := st.Migrate(ctx); err != nil {
		tb.Fatalf("migrate: %v", err)
	}
	return st
}

// NewUnmigrated creates a fresh, empty database named keepia_test_<hex>
// without the schema and returns its URL. It is dropped WITH (FORCE) when
// the test ends, after every cleanup registered later (stores opened on it
// close first).
//
// Without TEST_DATABASE_URL the test is skipped, except in CI (CI set, as
// GitHub Actions does): there it fails, so that a CI run can never pass
// with every database test skipped.
func NewUnmigrated(tb testing.TB) string {
	tb.Helper()
	base := os.Getenv(EnvURL)
	if base == "" {
		if os.Getenv("CI") != "" {
			tb.Fatal(EnvURL + " not set in CI: the database tests must run there")
		}
		tb.Skip(EnvURL + " not set; skipping database test")
	}
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		tb.Fatalf("connect: %v", err)
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "keepia_test_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		tb.Fatalf("create database: %v", err)
	}
	tb.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		_ = admin.Close(ctx)
	})

	u, err := url.Parse(base)
	if err != nil {
		tb.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}
