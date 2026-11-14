-- Certificates, revocation lists and join tokens (#96 part 2;
-- internal/store/pki.go). The transactions and their lock order are in
-- internal/pki (issuer.go, crlissuer.go) and internal/join (redeem.go).

-- The servers row FOR UPDATE: the first lock of `server remove` (C13) and
-- of a join's redeem (X1).
-- name: LockServerForUpdate :one
SELECT id, name, roles, joined_at, removed_at, created_at
FROM servers WHERE name = sqlc.arg(name)
FOR UPDATE;

-- name: LockServerByIDForUpdate :one
SELECT id, name, roles, joined_at, removed_at, created_at
FROM servers WHERE id = sqlc.arg(id)
FOR UPDATE;

-- FOR SHARE: an issuance waits for a concurrent removal and then sees
-- removed_at.
-- name: LockServerForShare :one
SELECT id, name, roles, joined_at, removed_at, created_at
FROM servers WHERE name = sqlc.arg(name)
FOR SHARE;

-- name: CountServerMailboxes :one
SELECT count(*) FROM mailboxes m JOIN stores s ON s.id = m.store_id
WHERE s.server_id = sqlc.arg(server_id);

-- name: SetServerRemoved :exec
UPDATE servers SET removed_at = sqlc.arg(removed_at) WHERE id = sqlc.arg(id);

-- name: SetServerJoined :exec
UPDATE servers SET joined_at = sqlc.arg(joined_at) WHERE id = sqlc.arg(id);

-- name: InsertCertificate :exec
INSERT INTO certificates (serial, anchor, server_id, purpose, dns_name, spki_sha256, not_before, not_after, der)
VALUES (sqlc.arg(serial), sqlc.arg(anchor), sqlc.narg(server_id), sqlc.arg(purpose), sqlc.narg(dns_name),
	sqlc.arg(spki_sha256), sqlc.arg(not_before), sqlc.arg(not_after), sqlc.arg(der));

-- name: RevokeServerCertificates :many
UPDATE certificates SET revoked_at = sqlc.arg(revoked_at), revocation_reason = sqlc.arg(reason)::smallint
WHERE server_id = sqlc.arg(server_id) AND revoked_at IS NULL
RETURNING serial;

-- The revoked certificates of an anchor that have not expired at now:
-- the entries of its next list (CD16).
-- name: RevokedCertificates :many
SELECT serial, revoked_at, revocation_reason, not_after
FROM certificates
WHERE anchor = sqlc.arg(anchor) AND revoked_at IS NOT NULL AND not_after > sqlc.arg(now)
ORDER BY serial;

-- name: ListCRLs :many
SELECT anchor, number, this_update, next_update, der FROM anchor_crls ORDER BY anchor;

-- name: UpsertCRL :exec
INSERT INTO anchor_crls (anchor, number, this_update, next_update, der)
VALUES (sqlc.arg(anchor), sqlc.arg(number), sqlc.arg(this_update), sqlc.arg(next_update), sqlc.arg(der))
ON CONFLICT (anchor) DO UPDATE
SET number = EXCLUDED.number, this_update = EXCLUDED.this_update, next_update = EXCLUDED.next_update, der = EXCLUDED.der;

-- Delivered at the commit, and only then (CD34).
-- name: NotifyCRL :exec
SELECT pg_notify('keepia_crl', '');

-- The expiry of each server's newest unrevoked agent certificate.
-- name: AgentCertificateExpiries :many
SELECT server_id::bigint AS server_id, max(not_after)::timestamptz AS not_after
FROM certificates
WHERE purpose = 'agent' AND revoked_at IS NULL
GROUP BY server_id;

-- name: InsertJoinToken :exec
INSERT INTO join_tokens (id, server_id, secret_sha256, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(server_id), sqlc.arg(secret_sha256), sqlc.arg(created_at), sqlc.arg(expires_at));

-- Every token of the server that is neither used nor invalidated.
-- name: InvalidateServerTokens :execrows
UPDATE join_tokens SET invalidated_at = sqlc.arg(invalidated_at)
WHERE server_id = sqlc.arg(server_id) AND used_at IS NULL AND invalidated_at IS NULL;

-- A token's server, read without a lock: server_id never changes, and a
-- redeem locks the server row before the token row (X1).
-- name: JoinTokenServer :one
SELECT server_id FROM join_tokens WHERE id = sqlc.arg(id);

-- name: LockJoinToken :one
SELECT id, server_id, secret_sha256, created_at, expires_at, used_at, invalidated_at
FROM join_tokens WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: MarkJoinTokenUsed :exec
UPDATE join_tokens SET used_at = sqlc.arg(used_at) WHERE id = sqlc.arg(id);
