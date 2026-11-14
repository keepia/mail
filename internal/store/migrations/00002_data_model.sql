-- Data model (#95, part 1): customer groups, domains, alias domains,
-- servers, stores, mailboxes, aliases with their targets, send-as grants
-- and the audit log, with the triggers T1-T9 of the plan.
--
-- Conventions: bigint identity ids, created_at on every table, every
-- foreign key ON DELETE RESTRICT, names in lowercase ASCII (IDNs as
-- A-labels). Every trigger raises a fixed message with an SQLSTATE and a
-- CONSTRAINT name, which internal/store maps without parsing text.
--
-- Advisory locks use the two-int4 form pg_advisory_xact_lock(class, key);
-- its key space does not overlap goose's single-bigint lock. The classes
-- are the constants of internal/store/locks.go (LockClassNames 950201,
-- LockClassAddresses 950202); the lock tests prove that both agree.

-- +goose Up

-- Name patterns, used by the CHECK constraints below.
-- +goose StatementBegin
CREATE FUNCTION keepia_is_label(s text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
	SELECT s ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
$$;
-- +goose StatementEnd

-- Two or more labels, at most 253 characters, not only digits and dots.
-- +goose StatementBegin
CREATE FUNCTION keepia_is_domain(s text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
	SELECT char_length(s) <= 253
		AND s ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
		AND s !~ '^[0-9.]+$'
$$;
-- +goose StatementEnd

-- One or more labels, at most 253 characters, not only digits and dots.
-- +goose StatementBegin
CREATE FUNCTION keepia_is_host(s text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
	SELECT char_length(s) <= 253
		AND s ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
		AND s !~ '^[0-9.]+$'
$$;
-- +goose StatementEnd

-- At most 64 characters of [a-z0-9._-], starting and ending with a letter
-- or digit, without "..". No '+' (a later recipient delimiter) and no '*'
-- (Dovecot's master-user separator).
-- +goose StatementBegin
CREATE FUNCTION keepia_is_local_part(s text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
	SELECT s ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$' AND strpos(s, '..') = 0
$$;
-- +goose StatementEnd

-- No element twice. A CHECK cannot hold a subquery, but it can call this.
-- +goose StatementBegin
CREATE FUNCTION keepia_distinct(a text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
	SELECT cardinality(a) = (SELECT count(DISTINCT x) FROM unnest(a) AS x)
$$;
-- +goose StatementEnd

-- The weight of a mailbox in placement: its quota, and for an unlimited
-- mailbox (0) a fixed 10 GiB, store.UnlimitedPlacementWeight (CD13).
-- +goose StatementBegin
CREATE FUNCTION keepia_placement_weight(quota_bytes bigint) RETURNS bigint
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
	SELECT CASE WHEN quota_bytes = 0 THEN 10737418240 ELSE quota_bytes END
$$;
-- +goose StatementEnd

CREATE TABLE customer_groups (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	name text NOT NULL
		CONSTRAINT customer_groups_name_key UNIQUE
		CONSTRAINT customer_groups_name_format CHECK (keepia_is_label(name)),
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE domains (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	group_id bigint NOT NULL
		CONSTRAINT domains_group_id_fkey REFERENCES customer_groups ON DELETE RESTRICT,
	name text NOT NULL
		CONSTRAINT domains_name_key UNIQUE
		CONSTRAINT domains_name_format CHECK (keepia_is_domain(name)),
	active boolean NOT NULL DEFAULT true,
	created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX domains_group_id_idx ON domains (group_id);

CREATE TABLE alias_domains (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	name text NOT NULL
		CONSTRAINT alias_domains_name_key UNIQUE
		CONSTRAINT alias_domains_name_format CHECK (keepia_is_domain(name)),
	domain_id bigint NOT NULL
		CONSTRAINT alias_domains_domain_id_fkey REFERENCES domains ON DELETE RESTRICT,
	active boolean NOT NULL DEFAULT true,
	created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX alias_domains_domain_id_idx ON alias_domains (domain_id);

-- joined_at and removed_at are written by N2 (#96). They carry no CHECK:
-- a revocation must never be refused.
CREATE TABLE servers (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	name text NOT NULL
		CONSTRAINT servers_name_key UNIQUE
		CONSTRAINT servers_name_format CHECK (keepia_is_label(name)),
	roles text[] NOT NULL
		CONSTRAINT servers_roles_valid CHECK (
			cardinality(roles) >= 1
			AND roles <@ '{control,edge,store,filter,groupware}'::text[]
			AND keepia_distinct(roles)),
	joined_at timestamptz NULL,
	removed_at timestamptz NULL,
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE stores (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	server_id bigint NOT NULL
		CONSTRAINT stores_server_id_fkey REFERENCES servers ON DELETE RESTRICT,
	gate_name text NOT NULL
		CONSTRAINT stores_gate_name_key UNIQUE
		CONSTRAINT stores_gate_name_format CHECK (keepia_is_host(gate_name)),
	gate_ipv4 inet NULL
		CONSTRAINT stores_gate_ipv4_host CHECK (family(gate_ipv4) = 4 AND masklen(gate_ipv4) = 32),
	gate_ipv6 inet NULL
		CONSTRAINT stores_gate_ipv6_host CHECK (family(gate_ipv6) = 6 AND masklen(gate_ipv6) = 128),
	egress_port integer NULL
		CONSTRAINT stores_egress_port_key UNIQUE
		CONSTRAINT stores_egress_port_range CHECK (egress_port BETWEEN 1 AND 65535),
	state text NOT NULL DEFAULT 'joining'
		CONSTRAINT stores_state_valid CHECK (state IN ('joining', 'active')),
	created_at timestamptz NOT NULL DEFAULT now(),
	-- An active store is always routable.
	CONSTRAINT stores_active_routable CHECK (
		state <> 'active'
		OR (egress_port IS NOT NULL AND (gate_ipv4 IS NOT NULL OR gate_ipv6 IS NOT NULL)))
);
CREATE INDEX stores_server_id_idx ON stores (server_id);

CREATE TABLE mailboxes (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	domain_id bigint NOT NULL
		CONSTRAINT mailboxes_domain_id_fkey REFERENCES domains ON DELETE RESTRICT,
	local_part text NOT NULL
		CONSTRAINT mailboxes_local_part_format CHECK (keepia_is_local_part(local_part)),
	-- A known scheme prefix and printable ASCII without spaces; the full
	-- format is checked in Go.
	password_hash text NOT NULL
		CONSTRAINT mailboxes_password_hash_format CHECK (
			octet_length(password_hash) <= 512
			AND password_hash ~ '^\{(ARGON2ID|BLF-CRYPT|SHA256-CRYPT|SHA512-CRYPT|SSHA|SSHA256|SSHA512)\}[!-~]+$'),
	-- 0 is unlimited.
	quota_bytes bigint NOT NULL
		CONSTRAINT mailboxes_quota_bytes_range CHECK (quota_bytes >= 0),
	imap_access boolean NOT NULL DEFAULT true,
	pop3_access boolean NOT NULL DEFAULT true,
	smtp_access boolean NOT NULL DEFAULT true,
	state text NOT NULL DEFAULT 'active'
		CONSTRAINT mailboxes_state_valid CHECK (state IN ('active', 'disabled')),
	store_id bigint NOT NULL
		CONSTRAINT mailboxes_store_id_fkey REFERENCES stores ON DELETE RESTRICT,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT mailboxes_address_key UNIQUE (domain_id, local_part)
);
CREATE INDEX mailboxes_store_id_idx ON mailboxes (store_id);

-- A NULL local part is the domain's catch-all; NULLS NOT DISTINCT allows
-- one per domain.
CREATE TABLE aliases (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	domain_id bigint NOT NULL
		CONSTRAINT aliases_domain_id_fkey REFERENCES domains ON DELETE RESTRICT,
	local_part text NULL
		CONSTRAINT aliases_local_part_format CHECK (keepia_is_local_part(local_part)),
	active boolean NOT NULL DEFAULT true,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT aliases_address_key UNIQUE NULLS NOT DISTINCT (domain_id, local_part)
);

-- Rows are inserted or deleted, never updated (T9).
CREATE TABLE alias_targets (
	alias_id bigint NOT NULL
		CONSTRAINT alias_targets_alias_id_fkey REFERENCES aliases ON DELETE RESTRICT,
	mailbox_id bigint NOT NULL
		CONSTRAINT alias_targets_mailbox_id_fkey REFERENCES mailboxes ON DELETE RESTRICT,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT alias_targets_pkey PRIMARY KEY (alias_id, mailbox_id)
);
CREATE INDEX alias_targets_mailbox_id_idx ON alias_targets (mailbox_id);

-- A NULL local part grants the whole domain.
CREATE TABLE send_as (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	mailbox_id bigint NOT NULL
		CONSTRAINT send_as_mailbox_id_fkey REFERENCES mailboxes ON DELETE RESTRICT,
	domain_id bigint NOT NULL
		CONSTRAINT send_as_domain_id_fkey REFERENCES domains ON DELETE RESTRICT,
	local_part text NULL
		CONSTRAINT send_as_local_part_format CHECK (keepia_is_local_part(local_part)),
	active boolean NOT NULL DEFAULT true,
	created_at timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT send_as_grant_key UNIQUE NULLS NOT DISTINCT (mailbox_id, domain_id, local_part)
);
CREATE INDEX send_as_domain_id_idx ON send_as (domain_id);

CREATE TABLE audit_log (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	at timestamptz NOT NULL DEFAULT now(),
	actor text NOT NULL
		CONSTRAINT audit_log_actor_format CHECK (actor ~ '^[a-z][a-z0-9:._-]{0,63}$'),
	action text NOT NULL
		CONSTRAINT audit_log_action_format CHECK (action ~ '^[a-z-]+[.][a-z-]+$'),
	object text NOT NULL
		CONSTRAINT audit_log_object_length CHECK (char_length(object) <= 320),
	details jsonb NOT NULL DEFAULT '{}'
		CONSTRAINT audit_log_details_object CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX audit_log_at_idx ON audit_log (at);

-- The isolation guard of T1, T5, T6 and T8's roles branch (N3, C2): their
-- checks rely on a fresh snapshot per statement after a lock, which only
-- READ COMMITTED gives.
-- +goose StatementBegin
CREATE FUNCTION keepia_require_read_committed() RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
	IF current_setting('transaction_isolation') <> 'read committed' THEN
		RAISE EXCEPTION 'this write must run in a READ COMMITTED transaction'
			USING ERRCODE = '25001', CONSTRAINT = 'read_committed_required';
	END IF;
END
$$;
-- +goose StatementEnd

-- T1: a name is a domain or an alias domain, never both. The lock
-- (names, hashtext(name)) serializes inserts of the same name across both
-- tables; a hash collision only serializes, it never refuses wrongly.
-- +goose StatementBegin
CREATE FUNCTION keepia_t1_domain_name() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
	PERFORM keepia_require_read_committed();
	PERFORM pg_advisory_xact_lock(950201, hashtext(NEW.name));
	IF TG_TABLE_NAME = 'domains' THEN
		PERFORM 1 FROM alias_domains WHERE name = NEW.name;
	ELSE
		PERFORM 1 FROM domains WHERE name = NEW.name;
	END IF;
	IF FOUND THEN
		RAISE EXCEPTION 'the name is already a domain or an alias domain'
			USING ERRCODE = '23505', CONSTRAINT = 'domain_name_taken';
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER domains_t1_name BEFORE INSERT ON domains
	FOR EACH ROW EXECUTE FUNCTION keepia_t1_domain_name();
CREATE TRIGGER alias_domains_t1_name BEFORE INSERT ON alias_domains
	FOR EACH ROW EXECUTE FUNCTION keepia_t1_domain_name();

-- T2: an alias domain moves only within its group. An unknown target is
-- left to the foreign key.
-- +goose StatementBegin
CREATE FUNCTION keepia_t2_alias_domain_group() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
	new_group bigint;
BEGIN
	IF NEW.domain_id IS NOT DISTINCT FROM OLD.domain_id THEN
		RETURN NEW;
	END IF;
	SELECT group_id INTO new_group FROM domains WHERE id = NEW.domain_id;
	IF FOUND AND new_group IS DISTINCT FROM (SELECT group_id FROM domains WHERE id = OLD.domain_id) THEN
		RAISE EXCEPTION 'an alias domain can only point to a domain of the same group'
			USING ERRCODE = '23514', CONSTRAINT = 'alias_domain_group';
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER alias_domains_t2_group BEFORE UPDATE OF domain_id ON alias_domains
	FOR EACH ROW EXECUTE FUNCTION keepia_t2_alias_domain_group();

-- T3: a send-as grant stays inside the mailbox's group. With a local part,
-- the address is at most 254 characters (T5's rule for send_as). An
-- unknown mailbox or domain is left to the foreign keys.
-- +goose StatementBegin
CREATE FUNCTION keepia_t3_send_as() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
	mailbox_group bigint;
	grant_group bigint;
	grant_domain text;
BEGIN
	SELECT d.group_id INTO mailbox_group FROM mailboxes m JOIN domains d ON d.id = m.domain_id WHERE m.id = NEW.mailbox_id;
	IF NOT FOUND THEN
		RETURN NEW;
	END IF;
	SELECT group_id, name INTO grant_group, grant_domain FROM domains WHERE id = NEW.domain_id;
	IF NOT FOUND THEN
		RETURN NEW;
	END IF;
	IF mailbox_group <> grant_group THEN
		RAISE EXCEPTION 'a mailbox can only send as an address of its own group'
			USING ERRCODE = '23514', CONSTRAINT = 'send_as_group';
	END IF;
	IF NEW.local_part IS NOT NULL AND char_length(NEW.local_part) + 1 + char_length(grant_domain) > 254 THEN
		RAISE EXCEPTION 'the address is longer than 254 characters'
			USING ERRCODE = '23514', CONSTRAINT = 'address_too_long';
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER send_as_t3_group BEFORE INSERT ON send_as
	FOR EACH ROW EXECUTE FUNCTION keepia_t3_send_as();

-- T4: an alias (catch-alls included) delivers only to mailboxes of its
-- own group. An unknown alias or mailbox is left to the foreign keys.
-- +goose StatementBegin
CREATE FUNCTION keepia_t4_alias_target_group() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
	alias_group bigint;
	mailbox_group bigint;
BEGIN
	SELECT d.group_id INTO alias_group FROM aliases a JOIN domains d ON d.id = a.domain_id WHERE a.id = NEW.alias_id;
	IF NOT FOUND THEN
		RETURN NEW;
	END IF;
	SELECT d.group_id INTO mailbox_group FROM mailboxes m JOIN domains d ON d.id = m.domain_id WHERE m.id = NEW.mailbox_id;
	IF NOT FOUND THEN
		RETURN NEW;
	END IF;
	IF alias_group <> mailbox_group THEN
		RAISE EXCEPTION 'an alias can only point to a mailbox of its own group'
			USING ERRCODE = '23514', CONSTRAINT = 'alias_target_group';
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER alias_targets_t4_group BEFORE INSERT ON alias_targets
	FOR EACH ROW EXECUTE FUNCTION keepia_t4_alias_target_group();

-- T5: an address is a mailbox or an alias, never both, and at most 254
-- characters. The lock (addresses, hashtext(domain_id || '/' ||
-- local_part)) serializes inserts of the same address across both tables.
-- +goose StatementBegin
CREATE FUNCTION keepia_t5_address() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
	PERFORM keepia_require_read_committed();
	IF NEW.local_part IS NULL THEN
		RETURN NEW;
	END IF;
	IF char_length(NEW.local_part) + 1 + (SELECT char_length(name) FROM domains WHERE id = NEW.domain_id) > 254 THEN
		RAISE EXCEPTION 'the address is longer than 254 characters'
			USING ERRCODE = '23514', CONSTRAINT = 'address_too_long';
	END IF;
	PERFORM pg_advisory_xact_lock(950202, hashtext(NEW.domain_id || '/' || NEW.local_part));
	IF TG_TABLE_NAME = 'mailboxes' THEN
		PERFORM 1 FROM aliases WHERE domain_id = NEW.domain_id AND local_part = NEW.local_part;
	ELSE
		PERFORM 1 FROM mailboxes WHERE domain_id = NEW.domain_id AND local_part = NEW.local_part;
	END IF;
	IF FOUND THEN
		RAISE EXCEPTION 'the address is already a mailbox or an alias'
			USING ERRCODE = '23505', CONSTRAINT = 'address_taken';
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER mailboxes_t5_address BEFORE INSERT ON mailboxes
	FOR EACH ROW EXECUTE FUNCTION keepia_t5_address();
CREATE TRIGGER aliases_t5_address BEFORE INSERT ON aliases
	FOR EACH ROW EXECUTE FUNCTION keepia_t5_address();

-- T6: at commit, every alias has at least one target. The alias row is
-- locked FOR UPDATE in a statement of its own before the count, so a
-- concurrent removal of another target waits and then sees this
-- transaction's committed delete (revision 2, B1).
-- +goose StatementBegin
CREATE FUNCTION keepia_t6_alias_has_target() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
	checked bigint;
BEGIN
	PERFORM keepia_require_read_committed();
	IF TG_TABLE_NAME = 'aliases' THEN
		checked := NEW.id;
	ELSE
		checked := OLD.alias_id;
	END IF;
	PERFORM 1 FROM aliases WHERE id = checked FOR UPDATE;
	IF NOT FOUND THEN
		RETURN NULL;
	END IF;
	PERFORM 1 FROM alias_targets WHERE alias_id = checked;
	IF NOT FOUND THEN
		RAISE EXCEPTION 'an alias needs at least one target'
			USING ERRCODE = '23514', CONSTRAINT = 'alias_without_target';
	END IF;
	RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER alias_without_target AFTER INSERT ON aliases
	DEFERRABLE INITIALLY DEFERRED
	FOR EACH ROW EXECUTE FUNCTION keepia_t6_alias_has_target();
CREATE CONSTRAINT TRIGGER alias_without_target AFTER DELETE ON alias_targets
	DEFERRABLE INITIALLY DEFERRED
	FOR EACH ROW EXECUTE FUNCTION keepia_t6_alias_has_target();

-- T7: a mailbox is placed only on an active store whose server is not
-- removed. The server row is read FOR SHARE first, then the store row,
-- the same order as T8; the share locks make a concurrent remove or state
-- change wait for this insert to commit. stores.server_id is immutable
-- (T9), so it is read without a lock.
-- +goose StatementBegin
CREATE FUNCTION keepia_t7_mailbox_store() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
	store_server bigint;
	removed timestamptz;
	store_state text;
BEGIN
	SELECT server_id INTO store_server FROM stores WHERE id = NEW.store_id;
	IF NOT FOUND THEN
		RETURN NEW; -- the foreign key refuses it
	END IF;
	SELECT removed_at INTO removed FROM servers WHERE id = store_server FOR SHARE;
	IF removed IS NOT NULL THEN
		RAISE EXCEPTION 'the store''s server was removed'
			USING ERRCODE = '23514', CONSTRAINT = 'mailbox_store_server_removed';
	END IF;
	SELECT state INTO store_state FROM stores WHERE id = NEW.store_id FOR SHARE;
	IF store_state IS DISTINCT FROM 'active' THEN
		RAISE EXCEPTION 'the store is not active'
			USING ERRCODE = '23514', CONSTRAINT = 'mailbox_store_not_active';
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER mailboxes_t7_store BEFORE INSERT ON mailboxes
	FOR EACH ROW EXECUTE FUNCTION keepia_t7_mailbox_store();

-- T8: a store's server has the role store and is not removed, read FOR
-- SHARE; a server keeps the role store while it has stores. A roles
-- update runs after its row lock, so it waits for an uncommitted store
-- insert and then sees it (READ COMMITTED, C2).
-- +goose StatementBegin
CREATE FUNCTION keepia_t8_store_server() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
	server_roles text[];
	removed timestamptz;
BEGIN
	IF TG_TABLE_NAME = 'stores' THEN
		SELECT roles, removed_at INTO server_roles, removed FROM servers WHERE id = NEW.server_id FOR SHARE;
		IF NOT FOUND THEN
			RETURN NEW; -- the foreign key refuses it
		END IF;
		IF removed IS NOT NULL THEN
			RAISE EXCEPTION 'the server was removed'
				USING ERRCODE = '23514', CONSTRAINT = 'store_server_removed';
		END IF;
		IF NOT 'store' = ANY (server_roles) THEN
			RAISE EXCEPTION 'a store needs a server with the role store'
				USING ERRCODE = '23514', CONSTRAINT = 'store_server_role';
		END IF;
		RETURN NEW;
	END IF;
	PERFORM keepia_require_read_committed();
	IF 'store' = ANY (OLD.roles) AND NOT 'store' = ANY (NEW.roles) THEN
		PERFORM 1 FROM stores WHERE server_id = NEW.id;
		IF FOUND THEN
			RAISE EXCEPTION 'a server with stores keeps the role store'
				USING ERRCODE = '23514', CONSTRAINT = 'store_server_role';
		END IF;
	END IF;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER stores_t8_server BEFORE INSERT ON stores
	FOR EACH ROW EXECUTE FUNCTION keepia_t8_store_server();
CREATE TRIGGER servers_t8_roles BEFORE UPDATE OF roles ON servers
	FOR EACH ROW EXECUTE FUNCTION keepia_t8_store_server();

-- T9: immutable columns, named in TG_ARGV; without arguments every update
-- is refused. The constraint is <table>_<column>_immutable, or
-- <table>_immutable.
-- +goose StatementBegin
CREATE FUNCTION keepia_refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
	col text;
BEGIN
	IF TG_NARGS = 0 THEN
		RAISE EXCEPTION 'rows of this table cannot be changed'
			USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_immutable';
	END IF;
	FOREACH col IN ARRAY TG_ARGV LOOP
		IF (to_jsonb(NEW) -> col) IS DISTINCT FROM (to_jsonb(OLD) -> col) THEN
			RAISE EXCEPTION 'this column cannot be changed'
				USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_' || col || '_immutable';
		END IF;
	END LOOP;
	RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER domains_t9_immutable BEFORE UPDATE ON domains
	FOR EACH ROW EXECUTE FUNCTION keepia_refuse_change('group_id', 'name');
CREATE TRIGGER alias_domains_t9_immutable BEFORE UPDATE ON alias_domains
	FOR EACH ROW EXECUTE FUNCTION keepia_refuse_change('name');
CREATE TRIGGER servers_t9_immutable BEFORE UPDATE ON servers
	FOR EACH ROW EXECUTE FUNCTION keepia_refuse_change('name');
CREATE TRIGGER stores_t9_immutable BEFORE UPDATE ON stores
	FOR EACH ROW EXECUTE FUNCTION keepia_refuse_change('server_id', 'gate_name');
CREATE TRIGGER mailboxes_t9_immutable BEFORE UPDATE ON mailboxes
	FOR EACH ROW EXECUTE FUNCTION keepia_refuse_change('domain_id', 'local_part', 'store_id');
CREATE TRIGGER aliases_t9_immutable BEFORE UPDATE ON aliases
	FOR EACH ROW EXECUTE FUNCTION keepia_refuse_change('domain_id', 'local_part');
CREATE TRIGGER send_as_t9_immutable BEFORE UPDATE ON send_as
	FOR EACH ROW EXECUTE FUNCTION keepia_refuse_change('mailbox_id', 'domain_id', 'local_part');
CREATE TRIGGER alias_targets_t9_immutable BEFORE UPDATE ON alias_targets
	FOR EACH ROW EXECUTE FUNCTION keepia_refuse_change();

-- +goose Down
-- Dropping a table drops its triggers. The functions go after the tables
-- whose constraints and triggers use them.
DROP TABLE audit_log;
DROP TABLE send_as;
DROP TABLE alias_targets;
DROP TABLE aliases;
DROP TABLE mailboxes;
DROP TABLE stores;
DROP TABLE servers;
DROP TABLE alias_domains;
DROP TABLE domains;
DROP TABLE customer_groups;
DROP FUNCTION keepia_refuse_change();
DROP FUNCTION keepia_t8_store_server();
DROP FUNCTION keepia_t7_mailbox_store();
DROP FUNCTION keepia_t6_alias_has_target();
DROP FUNCTION keepia_t5_address();
DROP FUNCTION keepia_t4_alias_target_group();
DROP FUNCTION keepia_t3_send_as();
DROP FUNCTION keepia_t2_alias_domain_group();
DROP FUNCTION keepia_t1_domain_name();
DROP FUNCTION keepia_require_read_committed();
DROP FUNCTION keepia_placement_weight(bigint);
DROP FUNCTION keepia_distinct(text[]);
DROP FUNCTION keepia_is_local_part(text);
DROP FUNCTION keepia_is_host(text);
DROP FUNCTION keepia_is_domain(text);
DROP FUNCTION keepia_is_label(text);
