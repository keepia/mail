-- A NULL local part grants the whole domain.
-- name: InsertSendAs :one
INSERT INTO send_as (mailbox_id, domain_id, local_part)
SELECT m.id, sd.id, sqlc.narg(local_part)
FROM mailboxes m
JOIN domains md ON md.id = m.domain_id
CROSS JOIN domains sd
WHERE md.name = sqlc.arg(mailbox_domain) AND m.local_part = sqlc.arg(mailbox_local_part)
	AND sd.name = sqlc.arg(domain_name)
RETURNING id, active, created_at;

-- name: SetSendAsActive :execrows
UPDATE send_as s
SET active = sqlc.arg(active)
FROM mailboxes m, domains md, domains sd
WHERE s.mailbox_id = m.id AND m.domain_id = md.id AND s.domain_id = sd.id
	AND md.name = sqlc.arg(mailbox_domain) AND m.local_part = sqlc.arg(mailbox_local_part)
	AND sd.name = sqlc.arg(domain_name) AND s.local_part IS NOT DISTINCT FROM sqlc.narg(local_part);

-- name: ListSendAs :many
SELECT s.id, m.local_part AS mailbox_local_part, md.name AS mailbox_domain, g.name AS group_name,
	s.local_part, sd.name AS domain_name, s.active, s.created_at
FROM send_as s
JOIN mailboxes m ON m.id = s.mailbox_id
JOIN domains md ON md.id = m.domain_id
JOIN domains sd ON sd.id = s.domain_id
JOIN customer_groups g ON g.id = md.group_id
WHERE (sqlc.narg(mailbox_domain)::text IS NULL
		OR (md.name = sqlc.narg(mailbox_domain) AND m.local_part = sqlc.narg(mailbox_local_part)))
	AND (sqlc.narg(group_name)::text IS NULL OR g.name = sqlc.narg(group_name))
ORDER BY md.name COLLATE "C", m.local_part COLLATE "C", sd.name COLLATE "C", s.local_part COLLATE "C" NULLS FIRST;
