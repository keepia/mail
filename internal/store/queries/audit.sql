-- name: InsertAudit :exec
INSERT INTO audit_log (actor, action, object, details)
VALUES (sqlc.arg(actor), sqlc.arg(action), sqlc.arg(object), sqlc.arg(details));

-- The 30-day retention, run by every write (N4). SKIP LOCKED: concurrent
-- writers skip the rows another writer is deleting, so they neither wait
-- nor deadlock.
-- name: PurgeAudit :exec
DELETE FROM audit_log
WHERE id IN (
	SELECT id FROM audit_log
	WHERE at < now() - interval '30 days'
	ORDER BY id
	LIMIT 1000
	FOR UPDATE SKIP LOCKED
);

-- name: ListAudit :many
SELECT id, at, actor, action, object, details
FROM audit_log
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);
