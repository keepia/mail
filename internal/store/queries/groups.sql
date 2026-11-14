-- name: InsertGroup :one
INSERT INTO customer_groups (name) VALUES (sqlc.arg(name))
RETURNING id, name, created_at;

-- name: RenameGroup :execrows
UPDATE customer_groups SET name = sqlc.arg(new_name) WHERE name = sqlc.arg(name);

-- name: ListGroups :many
SELECT g.id, g.name, g.created_at, count(d.id) AS domain_count
FROM customer_groups g
LEFT JOIN domains d ON d.group_id = g.id
GROUP BY g.id
ORDER BY g.name COLLATE "C";
