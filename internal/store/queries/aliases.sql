-- A NULL local part is the domain's catch-all.
-- name: InsertAlias :one
INSERT INTO aliases (domain_id, local_part)
SELECT d.id, sqlc.narg(local_part) FROM domains d WHERE d.name = sqlc.arg(domain_name)
RETURNING id, active, created_at;

-- The first statement of every alias update (C1): the alias row FOR
-- UPDATE, before any target is inserted or deleted.
-- name: LockAlias :one
SELECT a.id
FROM aliases a
JOIN domains d ON d.id = a.domain_id
WHERE d.name = sqlc.arg(domain_name) AND a.local_part IS NOT DISTINCT FROM sqlc.narg(local_part)
FOR UPDATE OF a;

-- name: SetAliasActive :exec
UPDATE aliases SET active = sqlc.arg(active) WHERE id = sqlc.arg(id);

-- name: InsertAliasTarget :execrows
INSERT INTO alias_targets (alias_id, mailbox_id)
SELECT sqlc.arg(alias_id), m.id
FROM mailboxes m JOIN domains d ON d.id = m.domain_id
WHERE d.name = sqlc.arg(domain_name) AND m.local_part = sqlc.arg(local_part);

-- name: DeleteAliasTarget :execrows
DELETE FROM alias_targets t
USING mailboxes m, domains d
WHERE t.alias_id = sqlc.arg(alias_id) AND t.mailbox_id = m.id
	AND m.domain_id = d.id AND d.name = sqlc.arg(domain_name) AND m.local_part = sqlc.arg(local_part);

-- name: ListAliases :many
SELECT a.id, a.local_part, d.name AS domain_name, g.name AS group_name, a.active, a.created_at
FROM aliases a
JOIN domains d ON d.id = a.domain_id
JOIN customer_groups g ON g.id = d.group_id
WHERE (sqlc.narg(domain_name)::text IS NULL OR d.name = sqlc.narg(domain_name))
	AND (sqlc.narg(group_name)::text IS NULL OR g.name = sqlc.narg(group_name))
ORDER BY d.name COLLATE "C", a.local_part COLLATE "C" NULLS FIRST;

-- name: ListAliasTargets :many
SELECT t.alias_id, m.local_part, d.name AS domain_name
FROM alias_targets t
JOIN mailboxes m ON m.id = t.mailbox_id
JOIN domains d ON d.id = m.domain_id
WHERE t.alias_id = ANY (sqlc.arg(alias_ids)::bigint[])
ORDER BY t.alias_id, d.name COLLATE "C", m.local_part COLLATE "C";
