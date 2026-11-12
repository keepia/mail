# Migration from mailcow to Keepia Mail

This runbook moves the reference installation from mailcow-dockerized to
Keepia Mail. It is a skeleton: it holds the outline and the facts known
today, and each milestone fills its sections. It is complete and tested for
1.0.0. Plan: [#13, plan comment](https://github.com/keepia/mail/issues/13#issuecomment-6812732814)
(Revision 2), approved in
[the plan review](https://github.com/keepia/mail/issues/13#issuecomment-6813102334).

## 0. About this runbook

**Status:** Complete (part 1, #28).

**Audience.** The maintainer's reference installation only, not a general
guide for every mailcow operator (maintainer decision, 2026-11-11). Where the
reference installation needs a choice, this runbook makes it; other mailcow
setups may need other steps.

**How it grows.** Every section starts with a status line:

- "Facts only": the facts are here, the steps follow with the milestone named;
- "Filled by 0.X.0": the milestone that writes the steps;
- "Pending MQ1": waits for the maintainer decision on folder renames and the
  way back (#13).

The milestone tickets of 0.2.0 to 0.6.0 fill their sections in their own pull
requests ("Refs #13"). Part 5 (#32) checks that every section is complete.

| Section | Status | Filled by |
|---|---|---|
| [0. About this runbook](#0-about-this-runbook) | complete | part 1 (#28) |
| [1. Inventory](#1-inventory) | facts only | part 3 (#30) |
| [2.1 Mail, home data and keys](#21-mail-home-data-and-keys) | facts only | 0.2.0, part 3 (#30) |
| [2.2 Domains, mailboxes, aliases and send-as](#22-domains-mailboxes-aliases-and-send-as) | facts only | 0.2.0, part 3 (#30) |
| [2.3 Hashes and app passwords](#23-hashes-and-app-passwords) | facts only | 0.2.0, 0.4.0, part 3 (#30) |
| [2.4 Folder names and indexes](#24-folder-names-and-indexes) | pending MQ1 | parts 3 (#30) and 5 (#32) |
| [3.1 Sieve](#31-sieve) | facts only | 0.4.0, part 4 (#31) |
| [3.2 DKIM](#32-dkim) | facts only | 0.3.0, part 4 (#31) |
| [3.3 Bayes](#33-bayes) | facts only | 0.3.0, part 4 (#31) |
| [3.4 MTA-STS](#34-mta-sts) | facts only | 0.4.0, part 4 (#31) |
| [3.5 Outbound TLS policies](#35-outbound-tls-policies) | facts only | 0.4.0, part 4 (#31) |
| [3.6 BCC and journaling](#36-bcc-and-journaling) | facts only | 0.6.0, part 4 (#31) |
| [4. SOGo data](#4-sogo-data) | facts only | 0.5.0, part 4 (#31) |
| [5.1 Rehearsal](#51-rehearsal) | outline | part 3 (#30), part 5 (#32) |
| [5.2 Timeline](#52-timeline) | outline, predicted | part 5 (#32) |
| [5.3 DNS](#53-dns) | outline | 0.4.0, part 5 (#32) |
| [5.4 Checks afterwards](#54-checks-afterwards) | outline | parts 3 (#30) and 5 (#32) |
| [5.5 Way back to mailcow](#55-way-back-to-mailcow) | pending MQ1 | part 5 (#32) |
| [5.6 After the window](#56-after-the-window) | outline | part 5 (#32) |
| [6. Not migrated](#6-not-migrated) | facts only | part 3 (#30) |
| [7. Facts and sources](#7-facts-and-sources) | facts only | later pull requests add rows |

### Placeholders

This runbook is public. It uses placeholders only. Real domains, host names,
addresses, mailbox counts, sizes, dates, paths, volume names or the name of
the reference installation never go into the repository or onto GitHub. The
maintainer fills the placeholders in a local copy that is never committed.

| Placeholder | Meaning |
|---|---|
| `<domain>`, `<alias-domain>` | a domain, an alias domain |
| `<local>@<domain>` | a mailbox; `<local>` is its local part |
| `<user>` | a mailbox's full address, `<local>@<domain>` (Dovecot's `%u`) |
| `<prefix>` | a mailbox's `mailbox_path_prefix` (default `/var/vmail/`) |
| `<mail-host>` | public host name of the mail service |
| `<mailcow-dir>` | the mailcow-dockerized checkout |
| `<export-dir>` | the export bundle (part 2, #29) |
| `<keepia-dir>` | the Keepia Compose project |
| `<old-ipv4>`, `<old-ipv6>` | mailcow's public addresses |
| `<edge-ipv4>`, `<edge-ipv6>` | the Keepia edge's public addresses (`EDGE_IPV4`, `EDGE_IPV6`, #5) |
| `<selector>` | a DKIM selector |
| `<window-start>`, `<window-end>` | the downtime window; the end of the way-back window (MQ1) |
| `<denylist-file>` | the maintainer's local list of real values, outside the repository |

Example values use only `example.test` (RFC 2606, RFC 6761) and the
documentation ranges `192.0.2.0/24` (RFC 5737) and `2001:db8::/32`
(RFC 3849).

### Rules for the text

These hold for every pull request of #13:

- Placeholders only, as above.
- Every fact has its label and its source (section 7). Prototype files are
  cited as permalinks to commit `2a9743d`, because `prototypes/mail-crypt/`
  is removed later (#5). mailcow files are cited as text, `path:line` at the
  mailcow-dockerized tag `2026-11` (commit `88fbaa4`), not as links.
- Every mailcow command in this runbook is read-only. The maintainer runs it
  locally and never posts its output; only "yes" or "no", "none" or "some"
  goes onto GitHub.
- Headings are ASCII and unique, without underscores (the limits of
  `scripts/check-links.sh`).

### Placeholder check

The reviewer of every pull request of #13 runs the placeholder greps of the
plan ("Placeholder check (Done-when 3)" in the
[plan comment](https://github.com/keepia/mail/issues/13#issuecomment-6812732814))
on the added lines, the commit messages and the pull request body, and on any
transcript before it is posted. From part 2 (#29) on, they run as
`scripts/check-placeholders.sh` with a self-test.

No grep covers these; they depend on the reviewer reading the diff:

- relative paths (a path without a leading `/`);
- single-label host names (a name without a dot);
- addresses written with `_` between the numbers.

The backstop is the maintainer's optional local check,
`git grep -i -f <denylist-file>`, with a file outside the repository that
agents never see.

## 1. Inventory

**Status:** Facts only. Part 3 (#30) adds `keepia-mail import mailcow --dry-run`
as the full inventory.

Read-only, run locally on the mailcow host. Only "yes" or "no" ever goes onto
GitHub. The commands follow upstream at tag `2026-11` and have not been run
yet (predicted; the fixture of part 2, #29, runs them).

```sh
cd <mailcow-dir>
git describe --tags      # the facts in this runbook hold for 2026-11
grep -E '^MAILDIR_SUB=' mailcow.conf
docker compose exec -T dovecot-mailcow doveconf -n |
  grep -E 'mail_crypt|zlib|mail_location|listescape|mail_attachment'
docker compose exec -T mysql-mailcow \
  sh -c 'exec mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' <<'SQL'
SELECT JSON_VALUE(attributes, '$.mailbox_format'), COUNT(*) FROM mailbox GROUP BY 1;
SELECT mailbox_path_prefix, COUNT(*) FROM mailbox GROUP BY 1;
SQL
```

- The `doveconf` line is #4 M2: it shows whether mail_crypt, compression,
  `listescape` and attachment detection are configured as F1, F2 and F9
  assume.
- `MAILDIR_SUB` and `mailbox_path_prefix` are the path rule (F8). Any value
  other than `Maildir` and `/var/vmail/` changes F8 and the mapping
  (section 7.2).
- The database credentials stay inside the container's environment; the
  commands never print `mailcow.conf`.
- Before any step, mailcow's own `helper-scripts/backup_and_restore.sh`
  (lines 151-195 back up the volumes) makes a safety copy. It is not the
  import's input.

## 2. Mail and accounts

**Status:** Facts only. Filled by 0.2.0, 0.4.0 and part 3 (#30), per
subsection.

### 2.1 Mail, home data and keys

**Status:** Facts only. Filled by 0.2.0 and part 3 (#30).

Facts: F1, F2, F3, F6, F7, F8, F9. Mapping rows: maildirs, indexes, home
data, keys.

- Mail, its index and the home data (`dovecot-attributes`) move together
  (F7, F8).
- The global mail_crypt key pair is carried over; Keepia reads the old mail
  with it (F1, F2).
- Integrity is checked by comparing IMAP `BODY[]` sha256 with the source,
  not by "Dovecot read it without errors" (F6).

### 2.2 Domains, mailboxes, aliases and send-as

**Status:** Facts only. Filled by 0.2.0 and part 3 (#30).

Facts: F10, F11. Mapping rows: domains and quotas, alias domains, mailboxes,
aliases, send-as. Attributes Keepia does not support are reported by the dry
run, not dropped silently.

### 2.3 Hashes and app passwords

**Status:** Facts only. Filled by 0.2.0, 0.4.0 and part 3 (#30).

Facts: F12, F13, F13a. Mapping rows: hashes, app passwords. Weak hash
schemes, if the dry run finds any, are MQ7.

### 2.4 Folder names and indexes

**Status:** Pending MQ1. Filled by parts 3 (#30) and 5 (#32).

Facts: F4, F5, F7. Dovecot 2.4 renames folder directories with `~` at the
start of a non-first hierarchy part, and stores new ones in that form; 2.3
opens them only after a rename back by rule. Indexes move with the mail, or
QRESYNC clients keep stale state. How migration and the way back treat this
is MQ1 on #13. The dry run lists the affected folders locally; only "none" or
"some" is posted.

## 3. Filters and security

**Status:** Facts only. Filled by 0.3.0, 0.4.0, 0.6.0 and part 4 (#31), per
subsection.

### 3.1 Sieve

**Status:** Facts only. Filled by 0.4.0 and part 4 (#31).

Facts: F14, F4. Mapping row: Sieve. The dry run compiles every script with
2.4's `sievec`. Postfilters in use are MQ6.

### 3.2 DKIM

**Status:** Facts only. Filled by 0.3.0 and part 4 (#31).

Facts: F15. The same key and selector move over, so no new DNS records are
needed.

### 3.3 Bayes

**Status:** Facts only. Filled by 0.3.0 and part 4 (#31).

Facts: F16. Copied logically from Redis to Valkey, with TTLs kept.

### 3.4 MTA-STS

**Status:** Facts only. Filled by 0.4.0 and part 4 (#31).

Facts: F17 (the published policy, #2 M3).

### 3.5 Outbound TLS policies

**Status:** Facts only. Filled by 0.4.0 and part 4 (#31).

Facts: F17 (`tls_policy_override`).

### 3.6 BCC and journaling

**Status:** Facts only. Filled by 0.6.0 and part 4 (#31).

Facts: F18.

## 4. SOGo data

**Status:** Facts only. Filled by 0.5.0 and part 4 (#31).

Facts: F19. Contacts, calendars and settings move with `sogo-tool backup` on
mailcow's SOGo and `sogo-tool restore` on Keepia's (predicted; 0.5.0
measures it).

## 5. Operation and switch-over

**Status:** Outline. Filled by 0.4.0 and parts 3 (#30) and 5 (#32), per
subsection.

### 5.1 Rehearsal

**Status:** Outline. Filled by part 3 (#30); part 5 (#32) runs it on the
fixture.

- A dry run, then a full import into a throwaway Keepia.
- A rehearsal export runs on the live mailcow and is marked as such in the
  bundle.

### 5.2 Timeline

**Status:** Outline, predicted. Filled by part 5 (#32).

Between `<window-start>` and the switch:

1. Lower the DNS TTLs in advance.
2. Freeze admin changes in mailcow.
3. mailcow's Postfix answers 4xx; its outbound queue drains.
4. Stop every mailcow login, then Dovecot itself: IMAP, POP3, ManageSieve,
   SOGo and the admin UI. Only then is the source stable for a consistent
   copy.
5. Final export to `<export-dir>`, final dry run (no conflicts), final
   import.
6. Verification (section 5.4).
7. DNS change (section 5.3).
8. Keepia accepts mail.

### 5.3 DNS

**Status:** Outline. Filled by 0.4.0 and part 5 (#32).

- A and AAAA of `<mail-host>` from `<old-ipv4>` and `<old-ipv6>` to
  `<edge-ipv4>` and `<edge-ipv6>`. MX stays the same if the name is kept.
- PTR of the new addresses.
- SPF covers the new addresses before the switch.
- DKIM unchanged (F15).
- The MTA-STS `id`, only if the policy changes.
- TLSA records before any key change (predicted). mailcow's certificate and
  key are carried over for the switch.

### 5.4 Checks afterwards

**Status:** Outline. Filled by parts 3 (#30) and 5 (#32).

- The hash report has no mismatch (F6).
- A login per protocol.
- Inbound and outbound mail.
- A DKIM signature verifies.
- No 5xx in the edge queue.
- Per folder, UIDVALIDITY is unchanged and HIGHESTMODSEQ is not below
  mailcow's (F7).

### 5.5 Way back to mailcow

**Status:** Pending MQ1. Filled by part 5 (#32).

The options and the recommendation are MQ1 on #13. Under every option,
mailcow's volumes stay untouched until a way back writes to them: the import
works on the bundle. The way-back window ends at `<window-end>`.

### 5.6 After the window

**Status:** Outline. Filled by part 5 (#32).

- Raise `dovecot_storage_version` (F3). After that, the way back is closed.
- Take mailcow down.
- Delete the bundle and every key copy outside Keepia.

## 6. Not migrated

**Status:** Facts only. Filled by part 3 (#30): its dry run reports each item
below that is in use.

These are the 1.0 gaps and the limits of the scope, listed so that nothing is
left behind silently. Table names refer to `data/web/inc/init_db.inc.php`.

- ActiveSync and `eas_access`.
- Domain admins and `da_acl`.
- Relay hosts, `transports`, `forwarding_hosts` (line 1340) and
  `recipient_maps` (line 1301).
- `settingsmap` (line 920).
- Per-user spam settings, `filterconf` (line 901).
- Rate limits held in Redis.
- imapsync jobs, Pushover and OAuth (F11).
- `spamalias` and domain-wide footers (F11).
- Tags, `fido2`, `tfa` and `user_acl`.
- Mailbox `kind` (SOGo resources).
- Quarantine (F11).
- Netfilter bans.
- Quota usage counters (`quota2`); Dovecot recounts them (predicted).
- Pending MQ6: Sieve postfilters, shared folders and IMAP ACLs
  (`acl = vfile`, `data/conf/dovecot/dovecot.conf:194`), mailbox groups, and
  mailboxes whose `authsource` is not `mailcow`.

## 7. Facts and sources

**Status:** Facts only. Later pull requests add rows.

### 7.1 Facts

**Status:** Facts only. Every later pull request of #13 adds the facts it
measures or reads.

Labels: **measured** = observed in #3 or #4, their reviews, the plan review
of #13 or the probe of the plan's Revision 2, with the source. **upstream** =
read in source, not run. **predicted** = an estimate, with the part that
checks it.

mailcow paths are relative to the mailcow-dockerized checkout at tag
`2026-11`: `dovecot.conf` is `data/conf/dovecot/dovecot.conf`,
`docker-entrypoint.sh` is `data/Dockerfiles/dovecot/docker-entrypoint.sh`,
`Dockerfile` is `data/Dockerfiles/dovecot/Dockerfile`, `init_db.inc.php`,
`functions.inc.php`, `functions.mailbox.inc.php` and `functions.dkim.inc.php`
are in `data/web/inc/`.

| # | Fact | Label, source |
|---|---|---|
| F1 | Dovecot 2.4.5 reads mailcow's 2.3 mail_crypt mail (one global P-256 key pair) byte-identically: plain, encrypted only, encrypted with gz, zstd and lz4. This also holds after 2.4 has written into the mailboxes and without indexes. 2.3.21.1 reads a crypt-only file written by 2.4.5 with the same content. | measured, #4 [results](https://github.com/keepia/mail/issues/4#issuecomment-6808759590); probe of the plan's Revision 2 on #13 |
| F2 | The 2.4 settings are the "migration settings" block of [`conf24/dovecot.conf`](https://github.com/keepia/mail/blob/2a9743d/prototypes/mail-crypt/conf24/dovecot.conf#L28-L59): `mailbox_list_layout = maildir++`, only `mailbox_list_storage_escape_char = "\\"` (with `mailbox_list_visible_escape_char` unset), an empty `mail_attachment_detection_options`, and the keys as file paths. Its line `mail_compress_write_method = lz4` depends on #2 M5; the default "crypt only" leaves it out. | measured, #4 F1 and F4; #2 plan §8 |
| F3 | `dovecot_storage_version = 2.4.0` during the migration window. From 2.4.5, raising it switches the thread index format; a way back after raising it is untested. | decision #4 T6 ([comment](https://github.com/keepia/mail/issues/4#issuecomment-6807158047)); upstream, Dovecot `NEWS` (#4 plan); measured as untested, #4 F3 |
| F4 | On the first mailbox listing (also a client's IMAP `LIST`, but not a bare `SELECT`), 2.4.5 renames folder directories that have `~` at the start of a non-first hierarchy part (`.x.\7ey` becomes `.x.~y`), and creates an index directory under the new name. No setting avoids it. The names clients list do not change. Sieve `fileinto` with the old names keeps working (predicted; part 4, #31, tests it). | measured, #4 F3 and F4, [decision](https://github.com/keepia/mail/issues/4#issuecomment-6807467630); upstream, #4 plan B2 |
| F5 | After that, 2.3 lists such a folder but cannot `SELECT` it (`NO Mailbox doesn't exist`). Renaming the directory back restores access, and 2.3 reads everything 2.4 left ([`rollback-rename.sh`](https://github.com/keepia/mail/blob/2a9743d/prototypes/mail-crypt/rollback-rename.sh)). A folder created in 2.4 as `Projekte/~alt` is stored as `.Projekte.~alt`, the same form 2.3 cannot open. | measured, #4 F3 (phases E1 and E2); [plan review](https://github.com/keepia/mail/issues/13#issuecomment-6812936556) on #13 |
| F6 | Corruption of encrypted and lz4-compressed mail is not reliably detected on read: a flipped bit can come back silently. Integrity is checked by comparing IMAP `BODY[]` sha256 with the source. | measured, [comment](https://github.com/keepia/mail/issues/13#issuecomment-6808912017) on #13; #2 plan §8 |
| F7 | Without indexes, 2.4 rebuilds UIDs, UIDVALIDITY, flags, keywords, METADATA and GUIDs. But HIGHESTMODSEQ restarts low (9 became 2 in the probe), and a QRESYNC client with a cached state then gets no VANISHED for an expunge, so it keeps showing deleted mail and stale flags. Indexes therefore move with the mail, both ways (MQ1). 2.4.5 uses 2.3's indexes, and 2.3 reads with 2.4-written ones. | measured, #4 F2, phases B and E; [plan review](https://github.com/keepia/mail/issues/13#issuecomment-6812936556) on #13 (2.4 index); for a 2.3 index, predicted (part 3, #30) |
| F8 | mailcow's layout: `mail_home = /var/vmail/%d/%n` (`dovecot.conf:22`); the home holds `dovecot-attributes` (METADATA) and, with the default prefix, the Maildir. The mail path comes from the userdb query: `<prefix><domain>/<local>/<MAILDIR_SUB>`, index `/var/vmail_index/<user>`, uid and gid 5000; defaults `/var/vmail/` and `Maildir`, and an empty `MAILDIR_SUB` is handled separately. Volumes: `vmail-vol-1`, `vmail-index-vol-1`, and the keys in `crypt-vol-1` (`ecprivkey.pem`, `ecpubkey.pem`; P-256, PKCS#8, no password). Keepia: user `vmail` with uid 1000, mail at `/srv/vmail`, index on the `store-index` volume. | upstream, `docker-entrypoint.sh:131,180-183`, `generate_config.sh:422`, `init_db.inc.php:348`, `docker-compose.yml:277-279`, `Dockerfile:48,54`; #5 plan |
| F9 | The format of a message depends on its age: plain before 2017-04, then encrypted only, with gz from 2018-06, with zstd from 2023-05 to 2023-10, with lz4 otherwise. Reading compressed mail stays enabled in Keepia. | upstream, #4 plan; #2 plan §8 |
| F10 | `domain` has `quota`, `maxquota` and `defquota` in MiB. `alias_domain`. `mailbox` has `quota` in bytes; `active` 1, 0, or 2 (login disabled, mail still accepted); `authsource` `mailcow`, `keycloak`, `generic-oidc` or `ldap`; `attributes` with the `*_access` flags. `alias.goto` may be `null@localhost` (discard), `spam@localhost` or `ham@localhost` (Bayes training); `alias` also has `internal` and `sender_allowed`. `sender_acl` has `external`. | upstream, `init_db.inc.php:230-239,341-356,680-700,719-730,865`; `docker-entrypoint.sh:131`; `functions.mailbox.inc.php:551-557,954`; `data/web/lang/lang.en-gb.json:54` |
| F11 | Out of scope but present in the schema: mailbox groups (lines 392-624), imapsync (1091-1279), `tfa` (1320), `pushover` (1533), `oauth_*` (1565-1619), `spamalias` (884), `domain_wide_footer` (256), `quarantine` (312). | upstream, `init_db.inc.php` |
| F12 | Password hashes are stored with a `{SCHEME}` prefix; the default scheme is `BLF-CRYPT`. `hash_password` writes `SSHA`, `SSHA256`, `SSHA512` or `BLF-CRYPT` and accepts many pre-hashed schemes; `verify_hash` accepts them too. mailcow's `MD5` is a salted crypt hash. | upstream, `generate_config.sh:180`, `functions.inc.php:130-155,866-959` |
| F13 | `app_passwd` has one hash, `active`, and a flag per protocol (`imap`, `smtp`, `dav`, `eas`, `pop3`, `sieve`). | upstream, `init_db.inc.php:776-812` |
| F13a | A Keepia app password has exactly one protocol. | #2 plan §10 |
| F14 | Sieve: the active script is `/var/vmail/sieve/<user>.sieve`, outside the home. ManageSieve keeps scripts in the home's default storage, with that path as the active link (predicted; part 4, #31, checks it on the fixture). `sieve_filters` holds pre- and postfilters. The extensions include `+notify +imapflags +vacation-seconds +editheader`. SOGo writes filters and vacation through ManageSieve. Keepia has prefilters only. | upstream, `dovecot.conf:198,218,228-231`, `init_db.inc.php:746-775`, `data/conf/sogo/sogo.conf:80`; #2 plan §10 |
| F15 | DKIM keys are in Redis: `DKIM_PRIV_KEYS` (field `<selector>.<domain>`), `DKIM_SELECTORS`, `DKIM_PUB_KEYS`. The same key and selector need no DNS change. | upstream, `data/conf/rspamd/local.d/dkim_signing.conf:26-30`, `functions.dkim.inc.php:59-60,74` |
| F16 | Bayes data is in Redis, `new_schema`, `expire = 7776000`. Both sides pin rspamd 4.2.3. | upstream, `data/conf/rspamd/local.d/statistic.conf:4,8,11`, `docker-compose.yml:90`; #5 plan |
| F17 | `mta_sts` holds the published MTA-STS policy. `tls_policy_override` is queried before the `postfix-tlspol` socketmap (outbound MTA-STS). | upstream, `init_db.inc.php:292-311,813-829`, `data/conf/postfix/main.cf:153` |
| F18 | `bcc_maps` has `local_dest`, `bcc_dest`, `type` and `active`. | upstream, `init_db.inc.php:1280-1300` |
| F19 | SOGo 5.12.13 keeps its data in MariaDB (`sogo_*` tables, `sogo_user_profile`), with a nightly `sogo-tool backup` of all users. Keepia's SOGo uses its own Postgres database. | upstream, `init_db.inc.php:1353-1532,1552-1564`, `docker-compose.yml:210,243,252-253`; #2 plan §6 |

### 7.2 Mapping

**Status:** Facts only. Filled by parts 3 (#30) and 4 (#31).

The first three columns are the mapping; the last names the part of #13 that
implements the row and fills in its details.

| Scope item | mailcow source | Keepia target | Part |
|---|---|---|---|
| Maildirs | `<prefix><domain>/<local>/<MAILDIR_SUB>` in `vmail-vol-1` | `store-mail` of the mailbox's store, uid 1000 | 3 (#30) |
| Indexes | `vmail-index-vol-1/<user>` | `store-index` (F7) | 3 (#30) |
| Home data | `/var/vmail/<domain>/<local>/dovecot-attributes` | the store home | 3 (#30) |
| Keys | `crypt-vol-1` | control, under the key-encryption key, then agent, then stores (#2 M1) | 3 (#30) |
| Domains, quotas | `domain` (`quota`, `maxquota`, `defquota`) | `domains`; the limits are reported as unsupported unless 0.2.0 adds domain limits | 3 (#30) |
| Alias domains | `alias_domain` | `alias_domains` | 3 (#30) |
| Mailboxes | `mailbox` | `mailboxes`: quota; protocols from `*_access`; `active` 1 to active, 0 to disabled, 2 to active with every login protocol removed; `authsource` other than `mailcow` reported as unsupported (MQ6) | 3 (#30) |
| Aliases | `alias` | `aliases`: `null@localhost` to a discard target, or unsupported if 0.2.0 has none; `spam@localhost` and `ham@localhost` reported as unsupported (0.3.0 may add training addresses); `internal` reported as unsupported; `sender_allowed` to a `send_as` row | 3 (#30) |
| Send-as | `sender_acl` | `send_as`; `external` = 1 or another customer group reported as unsupported | 3 (#30) |
| Hashes | `mailbox.password` | `mailboxes` (F12) | 3 (#30) |
| App passwords | `app_passwd` | one row per enabled protocol; `active` = 0 not imported, reported (F13, F13a) | 3 (#30) |
| Sieve | `/var/vmail/sieve/<user>.sieve`, the home's script storage, `sieve_filters` | the store's Sieve storage; `sieve_prefilters` | 4 (#31) |
| DKIM | Redis `DKIM_*` | `dkim_keys` | 4 (#31) |
| Bayes | Redis | Valkey | 4 (#31) |
| MTA-STS, TLS policies, BCC maps | `mta_sts`, `tls_policy_override`, `bcc_maps` | `mta_sts_policies`, `tls_policies`, `bcc_maps` | 4 (#31) |
| SOGo | `sogo-tool backup` | SOGo's database | 4 (#31) |
