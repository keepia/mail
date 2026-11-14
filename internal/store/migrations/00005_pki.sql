-- Certificates, revocation lists and join tokens (#96 part 2, CD13-CD24,
-- CD34, CD36). Every leaf that control issues is recorded here, so a
-- revocation list can name it; the newest list of each anchor is kept for
-- the gates and the joining agents; a join token is stored only as the
-- SHA-256 of its secret, never as the token.
--
-- Foreign keys go to #95's servers (00004); servers are never deleted,
-- only marked removed_at, so the default RESTRICT holds and the rows stay
-- for the lists. Nothing here alters #95's tables (CD-C2).

-- +goose Up
CREATE TABLE certificates (
	-- The certificate's serial number, as its unsigned big-endian bytes.
	serial bytea PRIMARY KEY
		CONSTRAINT certificates_serial_length CHECK (octet_length(serial) BETWEEN 1 AND 20),
	anchor text NOT NULL
		CONSTRAINT certificates_anchor_valid CHECK (anchor IN ('store-client', 'groupware-client', 'agent', 'service')),
	-- NULL only for the control gate's certificate, which serve issues
	-- itself (CD34).
	server_id bigint NULL
		CONSTRAINT certificates_server_id_fkey REFERENCES servers ON DELETE RESTRICT,
	purpose text NOT NULL
		CONSTRAINT certificates_purpose_valid CHECK (purpose IN (
			'edge-dovecot', 'keepia-edge', 'agent', 'gate', 'control-gate',
			'edge', 'filter', 'store', 'control', 'groupware')),
	-- The only DNS SAN of a server certificate; NULL for a client one.
	dns_name text NULL,
	spki_sha256 bytea NOT NULL
		CONSTRAINT certificates_spki_sha256_length CHECK (octet_length(spki_sha256) = 32),
	not_before timestamptz NOT NULL,
	not_after timestamptz NOT NULL,
	der bytea NOT NULL,
	revoked_at timestamptz NULL,
	revocation_reason smallint NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT certificates_validity CHECK (not_after > not_before),
	CONSTRAINT certificates_revocation CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
	CONSTRAINT certificates_control_gate CHECK ((server_id IS NULL) = (purpose = 'control-gate')),
	CONSTRAINT certificates_server_dns_name CHECK ((dns_name IS NULL) = (purpose NOT IN ('gate', 'control-gate')))
);
CREATE INDEX certificates_server_id_idx ON certificates (server_id);
CREATE INDEX certificates_revoked_idx ON certificates (anchor, not_after) WHERE revoked_at IS NOT NULL;

-- The newest revocation list of each anchor. Its number only rises: every
-- reissue writes old + 1 under the CRL lock (LockClassCRL, CD36).
CREATE TABLE anchor_crls (
	anchor text PRIMARY KEY
		CONSTRAINT anchor_crls_anchor_valid CHECK (anchor IN ('store-client', 'groupware-client', 'agent', 'service')),
	number bigint NOT NULL
		CONSTRAINT anchor_crls_number_positive CHECK (number >= 1),
	this_update timestamptz NOT NULL,
	next_update timestamptz NOT NULL,
	der bytea NOT NULL,
	CONSTRAINT anchor_crls_validity CHECK (next_update > this_update)
);

CREATE TABLE join_tokens (
	id bytea PRIMARY KEY
		CONSTRAINT join_tokens_id_length CHECK (octet_length(id) = 16),
	server_id bigint NOT NULL
		CONSTRAINT join_tokens_server_id_fkey REFERENCES servers ON DELETE RESTRICT,
	secret_sha256 bytea NOT NULL
		CONSTRAINT join_tokens_secret_sha256_length CHECK (octet_length(secret_sha256) = 32),
	created_at timestamptz NOT NULL,
	expires_at timestamptz NOT NULL,
	used_at timestamptz NULL,
	invalidated_at timestamptz NULL,
	CONSTRAINT join_tokens_lifetime CHECK (expires_at > created_at)
);
CREATE INDEX join_tokens_server_id_idx ON join_tokens (server_id);

-- +goose Down
DROP TABLE join_tokens;
DROP TABLE anchor_crls;
DROP TABLE certificates;
