-- Placement of a new mailbox (#95 part 2; internal/store/placement.go).
-- A store is eligible when it is active and its server is not removed
-- (CD5, CD-C2); every check below uses that same predicate.

-- The ranking (#93): the lowest sum of placement weights (an unlimited
-- mailbox weighs keepia_placement_weight(0), 10 GiB), then the fewest
-- mailboxes, then the gate name in byte order; the id breaks any tie.
-- Disabled mailboxes count: they still occupy the store.
-- name: ChooseStore :one
SELECT s.id, s.gate_name
FROM stores s
JOIN servers sv ON sv.id = s.server_id
LEFT JOIN mailboxes m ON m.store_id = s.id
WHERE s.state = 'active' AND sv.removed_at IS NULL
GROUP BY s.id
ORDER BY coalesce(sum(keepia_placement_weight(m.quota_bytes)), 0), count(m.id), s.gate_name COLLATE "C", s.id
LIMIT 1;

-- The store that --store names, and whether it is eligible.
-- name: StoreEligibility :one
SELECT s.id, s.gate_name, (s.state = 'active' AND sv.removed_at IS NULL)::boolean AS eligible
FROM stores s
JOIN servers sv ON sv.id = s.server_id
WHERE s.gate_name = sqlc.arg(gate_name);

-- The domain an alias domain points to.
-- name: AliasDomainTarget :one
SELECT d.name
FROM alias_domains a
JOIN domains d ON d.id = a.domain_id
WHERE a.name = sqlc.arg(name);

-- name: MailboxExists :one
SELECT EXISTS (
	SELECT 1 FROM mailboxes m JOIN domains d ON d.id = m.domain_id
	WHERE d.name = sqlc.arg(domain_name) AND m.local_part = sqlc.arg(local_part));
