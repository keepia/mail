# Prototype: Dovecot 2.4 reads mail encrypted by mailcow's mail_crypt

Throwaway prototype for #4; not shipped, not part of any image; removed when the import ticket has its own tests.

Issue: [keepia/mail#4](https://github.com/keepia/mail/issues/4); plan: [comment 6807140165](https://github.com/keepia/mail/issues/4#issuecomment-6807140165). It answers one question: can Dovecot 2.4 read the mail that mailcow's Dovecot 2.3 stored with `mail_crypt` (one global P-256 key pair) and compression, with the same keys? It does not run in CI.

## Images

| Role | Image (pinned by digest) |
|---|---|
| writer (phase A), rollback reader (E1, E2), key generation | `dovecot/dovecot:2.3.21.1@sha256:547d28f9a893c93a1d2f6dc164880cd7bfa74009106dfa46b36a6a2ee636d921` (`2.3.21.1 (d492236fa0)`) |
| reader and writer (B, C, D, CP1-CP3) | `dovecot/dovecot:2.4.5@sha256:43c14def08a57f25107593cbcf64a0a6fbae84a7b9de7aa038513c9b21e91914` (`2.4.5 (0cbb641)`) |

mailcow's own image (`ghcr.io/mailcow/dovecot:2.3.21.1-4`) could not be pulled from the planning environment; see F7.

## Files

| File | Purpose |
|---|---|
| [`run.sh`](run.sh) | Runs phases 0, A-E, CP1-CP3 and the hygiene checks; prints every command and result; ends with `PASS` or `FAIL (n)`. |
| [`make-mail.py`](make-mail.py) | Writes the synthetic messages p01-p15, p20, p21 (`example.test` only, deterministic) and `src.tsv`: id, mailbox, variant, sha256, size, phase, 2.3 directory. |
| [`imap-hashes.py`](imap-hashes.py) | Builds the IMAP commands for `doveadm exec imap` and turns the transcript into `mailbox uid sha256 size flags` lines; reads literals by byte count. |
| [`rollback-rename.sh`](rollback-rename.sh) | Test tool for phase E2 only, not a migration proposal: renames `.x.~y`-style folder directories back to the 2.3 form `.x.\7ey`. |
| [`conf23/dovecot.conf`](conf23/dovecot.conf) | 2.3 writer: mailcow's mail_crypt, zlib, listescape, attribute and maildir settings. |
| [`conf24/dovecot.conf`](conf24/dovecot.conf) | 2.4 configuration; the "migration settings" block is the result (F1). |
| [`conf24/cp-no-compress.conf`](conf24/cp-no-compress.conf) | CP1: the 2.4 configuration without `mail_compress`. |
| [`conf24/cp-visible-escape.conf`](conf24/cp-visible-escape.conf) | CP3: the 2.4 configuration plus `mailbox_list_visible_escape_char`. |

## Run

Needs Docker with the two images above already pulled, Python 3 and about 25 MB in `work/`. As root (the containers write as uid 1000 into `work/`):

```sh
prototypes/mail-crypt/run.sh
```

- Every container runs with `--rm --network none`, a literal `keepia-proto4-*` name, bind mounts for `/etc/dovecot`, `/data` and `/mail_crypt`, and a tmpfs on the image's other VOLUME path (`/srv/mail` in 2.3, `/srv/vmail` in 2.4), so no Docker volume is created. `run.sh` checks the mounts of every Dovecot container.
- Keys are generated per run into `work/mail_crypt/` and `work/mail_crypt-other/` with mailcow's commands. `work/` and `*.pem` are git-ignored; nothing in `work/` is ever committed.
- `run.sh` refuses to start when `work/` exists and never deletes anything. The transcript is `work/transcript.txt`; the hash files, listings and IMAP transcripts are in `work/out/` and `work/imap/`.

Cleanup after a run or an aborted run (replace the path with the literal absolute path of your checkout):

```sh
docker rm -f -v keepia-proto4-d23 keepia-proto4-d24 keepia-proto4-conf keepia-proto4-keys
rm -rf /absolute/path/to/checkout/prototypes/mail-crypt/work
```

## Phases

| Phase | What happens | Check |
|---|---|---|
| 0 | P-256 key pairs (mailcow's `openssl ecparam … \| openssl pkey` commands); `doveconf -n` of every configuration; versions. | keys differ and are git-ignored; `doveconf -n` exits 0 |
| A | 2.3 creates 7 folders and saves p01-p15: plain, encrypted only, encrypted + gz, + zstd, + lz4 (UTF-8 8-bit, CRLF, 300 KiB attachment, 2 MB); flags `\Seen`, `$label1`; METADATA `/private/comment`. | per folder: file count and `CRYPTED` count from `src.tsv`; 2.3's IMAP hashes = `src.tsv` |
| B | 2.4 opens the mailbox, indexes carried over. | hashes, flags, `mailbox status` (messages, uidvalidity, uidnext, guid), folder list and METADATA equal A; maildir diff is exactly `.x.\7ey` → `.x.~y` |
| C | 2.4 saves p20, p21, sets `\Flagged` on p03, expunges p08; two fresh 2.4 containers read. | expected hash set; p20/p21 start with `CRYPTED`; UIDVALIDITY kept, UIDNEXT +1 in both folders |
| D | Copy without `vmail_index/`; 2.4 rebuilds. | hashes, UIDs, flags, keywords, uidvalidity, uidnext, METADATA equal C; GUIDs recorded |
| E1 | Copy with indexes; 2.3 reads as 2.4 left it. | everything except `x/~y` equals C; `x/~y` → `NO Mailbox doesn't exist` (expected finding) |
| E2 | Copy; `rollback-rename.sh`; 2.3 reads. | the rename is exactly `.x.~y -> .x.\7ey`; all hashes equal C |
| CP1 | 2.4 without `mail_compress`, one `UID FETCH` per session, no index. | every compressed message differs (raw gz/zstd/lz4 bytes or a short literal); p01/p02 same |
| CP2 | 2.4 with the other key pair. | every encrypted message fails with `Decryption error: no private key available`; p01 same |
| CP3 | 2.4 with `mailbox_list_visible_escape_char = "\\"`. | lists `back\5cslash` instead of `back\slash`, so the folder-name check detects it |
| 9 | Hygiene. | no `keepia-proto4` container, no new anonymous volume, no `.pem` in git |

Every phase greps the master log and the doveadm/imap stderr for `Error:`, `Panic:`, `Fatal:` and `corrupt` and expects none. CP1 and CP2 log errors by design: there the check expects the error instead (CP1 `Error: `, CP2 `no private key available`) and still fails on `Panic:`/`Fatal:`.

Flags are compared without `\Recent`: Dovecot 2.3 and 2.4.5 both report it only to the first session that sees a message, so it depends on which version read first, not on the stored data.

## Results (runs of 2026-11-11, `PASS`)

Message hashes as IMAP returns them (sha256 of the CRLF form; identical in 2.3 phase A, 2.4 phase B, C, D and 2.3 phase E2). On-disk size is the file in the maildir, written by 2.3 (p20/p21 by 2.4):

| id | mailbox | variant | size | on disk | sha256 |
|---|---|---|---:|---:|---|
| p01 | INBOX | plain | 1942 | 1894 | `388a0e348a7a6f631bc7e2938157d2c3967ee970b8fe7a4f525ffaee63202e48` |
| p02 | INBOX | crypt | 1942 | 2165 | `f6423f8f1a3abacf1dcf7c0c66c0a5c3a33df372f8927f038726cfb2215d7a37` |
| p03 | INBOX | crypt+gz | 2065 | 598 | `a70898314ee8841f92e0f1f17c3a9072adfe3e2e9453537bae4ba9dfa84e6e72` |
| p04 | INBOX | crypt+zstd | 2147 | 601 | `efc8170606ad317b97717bd549be5b8d6d320f323dbe29760949086db711be48` |
| p05 | INBOX | crypt+lz4, UTF-8 8-bit | 3496 | 803 | `1e381ee7fec44600a9ef3c404bd10a3da49382ec7251c60ff345e624198b99fa` |
| p06 | INBOX | crypt+lz4, CRLF | 1106 | 721 | `c12069baea765c2190ca1c9fe6dfaa8e556a29b559e7f905b2320e374de2cdcb` |
| p07 | INBOX | crypt+lz4, 300 KiB attachment | 420928 | 417350 | `a14c9c393fd9a0d5096a2d289b67860c5a70a1b37e5e54cbcb2b601688635d14` |
| p08 | INBOX | crypt+lz4, 2 MB (expunged in C) | 2129659 | 1973725 | `9255d0fe58edcf99424888a581c494ec9ae7478f6033bbb6358744ff33a2924f` |
| p09 | Archiv/2025 | crypt+lz4 | 2106 | 735 | `b869c6765a80622f7cc239196e932ee281bc6fd44a175794ca2e1e9848a8c532` |
| p10 | a.b | crypt+lz4 | 2106 | 735 | `c4a91366c9f26284123a0cf99f9d6d0fbc9ec229df2d123f6e70bebe473cc17d` |
| p11 | ~tilde | crypt+lz4 | 2106 | 735 | `ac6cc863c46d8ffb3f4cedeb8b8eef437924d1686032172075e20171ae5581f5` |
| p12 | x/~y | crypt+lz4 | 2106 | 735 | `b54aca372cad322c543a23b0e8c50d4fce5e25bb0566fa7f40843253d0a4682e` |
| p13 | back\slash | crypt+lz4 | 2106 | 735 | `a1147aa6c3c28661119fba62c49ad1a785f137f4bec2e012df0e514cbe1816cc` |
| p14 | Entwürfe | crypt+lz4 | 2106 | 735 | `aeb524a40e8a5e593e14c35c8e54bf70636b4809ad2f295b81b1686f20a6d366` |
| p15 | Sent & Co | crypt+lz4 | 2106 | 735 | `f9370196b3d1032c01c5480220704c28b2d49a0b375330a111cfc62e056f66b3` |
| p20 | INBOX | crypt+lz4 (2.4) | 2106 | 735 | `090d749c339025ce5d2f7255da2549c57fc4e2e2f644e2ae6f11643566ddf6ff` |
| p21 | Archiv/2025 | crypt+lz4 (2.4) | 2106 | 735 | `6754575136196b6041dc1e9b5ee112c86ae2655940c171bba45a8a668016bd7f` |

### F1: the 2.4 configuration for mailcow's global keys

The "migration settings" block of [`conf24/dovecot.conf`](conf24/dovecot.conf), as run:

```
dovecot_storage_version = 2.4.0
mail_driver = maildir
mail_path = ~/Maildir
mail_index_path = /data/vmail_index/%{user}
mail_volatile_path = /data/volatile/%{user}
mailbox_list_layout = maildir++
maildir_very_dirty_syncs = yes
mail_attachment_detection_options =
mailbox_list_storage_escape_char = "\\"
namespace inbox {
  inbox = yes
  separator = /
}
mail_attribute {
  dict file {
    path = %{home}/dovecot-attributes
  }
}
mail_plugins {
  mail_compress = yes
  mail_crypt = yes
}
mail_compress_write_method = lz4
crypt_global_public_key_file = /mail_crypt/ecpubkey.pem
crypt_global_private_key main {
  crypt_private_key_file = /mail_crypt/ecprivkey.pem
}
```

- The key files are mailcow's `/mail_crypt/ecprivkey.pem` and `ecpubkey.pem` unchanged (PKCS#8 PEM, P-256, no password). 2.4 takes paths (no `<`).
- `mail_crypt_save_version = 2` has no 2.4 equivalent; 2.4 writes format v2 (`CRYPTED\003\007\002`), and 2.3 read the 2.4-written p20/p21 in E2.
- `mailbox_list_visible_escape_char` must stay unset (CP3).

### F2: indexes

2.4.5 used the 2.3 index files without errors (phase B), and rebuilt them from the maildir alone with the same UIDs, UIDVALIDITY, UIDNEXT, flags, keywords, METADATA and mailbox GUIDs (phase D: the GUIDs come from the `dovecot-uidlist` header). The import does not have to carry the index volume for correctness.

### F3: rollback (`dovecot_storage_version = 2.4.0`)

- E1: 2.3 reads every message 2.4 left behind, including p20/p21 written and p03 flagged by 2.4, byte-identically, except folder `x/~y`: `SELECT "x/~y"` returns `NO Mailbox doesn't exist: x/~y`, although 2.3 still lists it and the message is on disk under `.x.~y`.
- E2: after renaming `.x.~y` back to `.x.\7ey`, 2.3 reads every mailbox byte-identically, with no log errors. The 2.4 index directory `.x.~y` stays as an orphan next to the old one.

### F4: folder escaping

- 2.4 needs `mailbox_list_storage_escape_char = "\\"` and no visible escape char. With it, 2.4 lists the same names as 2.3: `Archiv`, `Archiv/2025`, `Entwürfe`, `INBOX`, `Sent & Co`, `a.b`, `back\slash`, `x`, `x/~y`, `~tilde`.
- On-disk changes made by 2.4.5 (phase B, the first 2.4 run that listed mailboxes): maildir `.x.\7ey` → `.x.~y` (renamed); index directory `.x.~y` created next to `.x.\7ey`. No other folder directory changed: `.\7etilde`, `.back\5cslash`, `.a\2eb`, `.Entw&APw-rfe`, `.Sent &- Co`, `.Archiv.2025` stay.
- Phases C and D made no further maildir directory changes (D rebuilt the index directories from scratch).

### F5: compression variants

2.4.5 read gz, zstd and lz4 messages written by 2.3, and the encrypted-only and plain ones, byte-identically. CP1 shows each compressed message reaches 2.4 compressed: without `mail_compress` the body starts with `1f8b` (gz), `28b52ffd` (zstd) or `446f7665` (`Dove`, Dovecot's lz4 header), and the literal ends short of the announced size.

### F6: memory and time (this host, not a benchmark)

- Peak memory of one Dovecot container per phase (cgroup `memory.max_usage_in_bytes`, master plus one doveadm or imap process): 13 MiB (2.3, A), 18 MiB (2.4, B), 14-15 MiB (2.4, C and D).
- Reading the 2 MB message p08 in one `doveadm exec imap` session, including `docker exec` and the start of the imap process: 104-122 ms in 2.3 and 106-139 ms in 2.4 over three runs, so roughly 15-20 MB/s for decrypt + lz4 + IMAP.
- The whole `run.sh` takes about 40 s.

### F7: limitations

- Writer is upstream `dovecot/dovecot:2.3.21.1` (Debian 11, OpenSSL 1.1.1w), not mailcow's Alpine build; same Dovecot release `d492236fa0`.
- `mail_attachment_fs` (sdbox/mdbox only) is not tested; mailcow mailboxes are maildir.
- The containers use uid 1000 (`vmail`) instead of mailcow's 5000; this matters for the import's file ownership, not for the format.
- The Dovecot 2.3 → 2.4 upgrade notes on doc.dovecot.org could not be fetched from this environment (proxy `CONNECT` answered 403); the 2.4 settings come from the 2.4.5 source and `doveconf` (plan).
