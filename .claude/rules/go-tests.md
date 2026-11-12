---
paths:
  - "**/*_test.go"
---
# Go tests
- Bound every hang guard by `testwait.Limit` (`internal/testwait`). No sleeps.
- Never assert "still waits after N ms": wait for a signal (a channel, `testwait.Signal`, a hook such as `serve`'s `ready`) or for a state the database shows.
- For a lock, prefer a short lock timeout and an expected error over watching a wait. goose's migration lock polls with `pg_try_advisory_lock`, so nothing ever shows as waiting in PostgreSQL: use `store.WithMigrationLockTimeout`. Advisory locks are per database: a test's lock holder connects to the test's own database (the URL `storetest.NewUnmigrated` returns).
- Database tests use `storetest.New` or `storetest.NewUnmigrated` (a fresh database per test). Without `TEST_DATABASE_URL` they skip locally and fail in CI, so CI never passes with them skipped.
