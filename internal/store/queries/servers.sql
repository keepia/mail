-- name: InsertServer :one
INSERT INTO servers (name, roles) VALUES (sqlc.arg(name), sqlc.arg(roles)::text[])
RETURNING id, name, roles, joined_at, removed_at, created_at;

-- name: SetServerRoles :execrows
UPDATE servers SET roles = sqlc.arg(roles)::text[] WHERE name = sqlc.arg(name);

-- name: ListServers :many
SELECT id, name, roles, joined_at, removed_at, created_at
FROM servers
ORDER BY name COLLATE "C";

-- name: InsertStore :one
INSERT INTO stores (server_id, gate_name, gate_ipv4, gate_ipv6, egress_port)
SELECT sv.id, sqlc.arg(gate_name), sqlc.narg(gate_ipv4)::inet, sqlc.narg(gate_ipv6)::inet, sqlc.narg(egress_port)::integer
FROM servers sv WHERE sv.name = sqlc.arg(server_name)
RETURNING id, gate_name, gate_ipv4, gate_ipv6, egress_port, state, created_at;

-- A NULL argument keeps the column; clear_* sets it to NULL.
-- name: UpdateStore :execrows
UPDATE stores
SET state = coalesce(sqlc.narg(state), state),
	gate_ipv4 = CASE WHEN sqlc.arg(clear_ipv4)::boolean THEN NULL ELSE coalesce(sqlc.narg(gate_ipv4)::inet, gate_ipv4) END,
	gate_ipv6 = CASE WHEN sqlc.arg(clear_ipv6)::boolean THEN NULL ELSE coalesce(sqlc.narg(gate_ipv6)::inet, gate_ipv6) END,
	egress_port = CASE WHEN sqlc.arg(clear_port)::boolean THEN NULL ELSE coalesce(sqlc.narg(egress_port)::integer, egress_port) END
WHERE gate_name = sqlc.arg(gate_name);

-- name: ListStores :many
SELECT s.id, sv.name AS server_name, s.gate_name, s.gate_ipv4, s.gate_ipv6, s.egress_port, s.state, s.created_at
FROM stores s
JOIN servers sv ON sv.id = s.server_id
ORDER BY s.gate_name COLLATE "C";
