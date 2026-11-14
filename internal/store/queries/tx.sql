-- Transaction settings and advisory locks (internal/store/tx.go, locks.go).

-- name: SetLockTimeout :exec
SELECT set_config('lock_timeout', sqlc.arg(timeout)::text, true);

-- name: AdvisoryXactLock :exec
SELECT pg_advisory_xact_lock(sqlc.arg(class)::integer, sqlc.arg(key)::integer);
