-- name: InsertDomain :one
INSERT INTO domains (group_id, name)
SELECT g.id, sqlc.arg(name) FROM customer_groups g WHERE g.name = sqlc.arg(group_name)
RETURNING id, name, active, created_at;

-- name: SetDomainActive :execrows
UPDATE domains SET active = sqlc.arg(active) WHERE name = sqlc.arg(name);

-- name: ListDomains :many
SELECT d.id, d.name, g.name AS group_name, d.active, d.created_at
FROM domains d
JOIN customer_groups g ON g.id = d.group_id
WHERE (sqlc.narg(group_name)::text IS NULL OR g.name = sqlc.narg(group_name))
ORDER BY d.name COLLATE "C";

-- name: InsertAliasDomain :one
INSERT INTO alias_domains (name, domain_id)
SELECT sqlc.arg(name), d.id FROM domains d WHERE d.name = sqlc.arg(domain_name)
RETURNING id, name, active, created_at;

-- name: UpdateAliasDomain :execrows
UPDATE alias_domains a
SET domain_id = coalesce((SELECT d.id FROM domains d WHERE d.name = sqlc.narg(domain_name)), a.domain_id),
	active = coalesce(sqlc.narg(active), a.active)
WHERE a.name = sqlc.arg(name);

-- name: ListAliasDomains :many
SELECT a.id, a.name, d.name AS domain_name, g.name AS group_name, a.active, a.created_at
FROM alias_domains a
JOIN domains d ON d.id = a.domain_id
JOIN customer_groups g ON g.id = d.group_id
WHERE (sqlc.narg(domain_name)::text IS NULL OR d.name = sqlc.narg(domain_name))
	AND (sqlc.narg(group_name)::text IS NULL OR g.name = sqlc.narg(group_name))
ORDER BY a.name COLLATE "C";

-- name: DomainExists :one
SELECT EXISTS (SELECT 1 FROM domains WHERE name = sqlc.arg(name));
