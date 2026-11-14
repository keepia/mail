-- name: InsertMailbox :one
WITH m AS (
	INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_bytes, imap_access, pop3_access, smtp_access, store_id)
	SELECT d.id, sqlc.arg(local_part), sqlc.arg(password_hash), sqlc.arg(quota_bytes),
		sqlc.arg(imap_access), sqlc.arg(pop3_access), sqlc.arg(smtp_access), sqlc.arg(store_id)
	FROM domains d WHERE d.name = sqlc.arg(domain_name)
	RETURNING id, store_id, created_at
)
SELECT m.id, m.created_at, s.gate_name
FROM m JOIN stores s ON s.id = m.store_id;

-- A NULL argument keeps the column.
-- name: UpdateMailbox :execrows
UPDATE mailboxes m
SET quota_bytes = coalesce(sqlc.narg(quota_bytes), m.quota_bytes),
	imap_access = coalesce(sqlc.narg(imap_access), m.imap_access),
	pop3_access = coalesce(sqlc.narg(pop3_access), m.pop3_access),
	smtp_access = coalesce(sqlc.narg(smtp_access), m.smtp_access),
	state = coalesce(sqlc.narg(state), m.state),
	password_hash = coalesce(sqlc.narg(password_hash), m.password_hash)
FROM domains d
WHERE d.id = m.domain_id AND d.name = sqlc.arg(domain_name) AND m.local_part = sqlc.arg(local_part);

-- The scheme only, never the hash.
-- name: ListMailboxes :many
SELECT m.id, m.local_part, d.name AS domain_name, g.name AS group_name, s.gate_name, m.store_id,
	m.quota_bytes, m.imap_access, m.pop3_access, m.smtp_access, m.state,
	substring(m.password_hash FROM '^\{([A-Z0-9-]+)\}')::text AS scheme, m.created_at
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
JOIN customer_groups g ON g.id = d.group_id
JOIN stores s ON s.id = m.store_id
WHERE (sqlc.narg(domain_name)::text IS NULL OR d.name = sqlc.narg(domain_name))
	AND (sqlc.narg(group_name)::text IS NULL OR g.name = sqlc.narg(group_name))
	AND (sqlc.narg(gate_name)::text IS NULL OR s.gate_name = sqlc.narg(gate_name))
ORDER BY d.name COLLATE "C", m.local_part COLLATE "C";
