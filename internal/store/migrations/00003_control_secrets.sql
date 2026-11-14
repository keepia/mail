-- Control secrets (#96 part 1, CD4 and CD5): the keyring row and the
-- sealed secrets. Only ciphertext is stored here: each value is sealed
-- with AES-256-GCM under a key derived from the key-encryption key (KEK),
-- which lives in a file on the volume keepia-kek and never in the
-- database, so a dump alone reveals no secret.
--
-- 00002 is #95's data model (cross-plan decision CD-C1); this migration has
-- no foreign key to it, and goose accepts the gap while 00002 is not yet on
-- main.

-- +goose Up
-- One row: the KEK id that every sealed row must carry, and the
-- deployment id that goes into the anchors' subjects.
CREATE TABLE secret_keyring (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    kek_id bytea NOT NULL CHECK (octet_length(kek_id) = 16),
    deployment_id bytea NOT NULL CHECK (octet_length(deployment_id) = 16),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_export_at timestamptz
);

-- Rows are never updated: a rotation adds a new version, and the newest
-- version of a name is the active one.
CREATE TABLE control_secrets (
    name text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9/-]{0,62}$'),
    version integer NOT NULL CHECK (version >= 1),
    -- The anchor certificate or the mail_crypt public key (DER); NULL for
    -- a secret without a public part (store-master).
    public bytea,
    kek_id bytea NOT NULL CHECK (octet_length(kek_id) = 16),
    -- nonce (12 bytes) || ciphertext || tag (16 bytes)
    sealed bytea NOT NULL CHECK (octet_length(sealed) >= 28),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (name, version)
);

-- +goose Down
DROP TABLE control_secrets;
DROP TABLE secret_keyring;
