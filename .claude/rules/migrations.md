---
paths:
  - "internal/store/migrations/**"
  - "internal/store/store.go"
---
# Migrations
- A schema change gets the labels `db-migration` and `second-review`.
- Never edit a migration that is on `main`; add a new one.
- Before the merge, a PR's migration number is `main`'s highest + 1; the PR that merges second renames its file (goose refuses a lower version than the database's highest, `internal/gooseutil/resolve.go:62-63` in v3.29.0).
- Every constraint and trigger has a negative test and a positive counter-case (`internal/store/schema_test.go`).
- `Down` must work and is tested (`internal/store/store_test.go`: up, down, up).
- goose runs on a short-lived pgx pool of its own with `MinConns`/`MinIdleConns` zeroed, closed after each call (`closeMigrationPool`); keep it (mail-archive #274, #279).
- goose's migration lock (`store.MigrationLockID`, goose's default advisory lock id) polls every 5 s for up to 5 minutes. After that `serve` and `migrate` exit 1 with an error naming the lock, and `serve` never opens its listener.
