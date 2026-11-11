# Dovecot 2.4 proxy prototype (#3)

**Throwaway prototype for #3; not shipped, not part of any image; removed when #5's Dovecot image and Compose template cover the proxy.**

Dovecot 2.4 has no director. This prototype checks the replacement for the architecture plan (#2): one edge Dovecot in proxy mode routes IMAP, POP3, ManageSieve and LMTP to the mail store named by the passdb lookup (`proxy`, `host`). Postfix delivers through the edge over LMTP. The findings (F1–F8) and the chosen edge configuration are also posted on [issue #3](https://github.com/keepia/mail/issues/3).

Plaintext without TLS (`ssl = no`, `auth_allow_cleartext = yes`) is fine on a private Compose network in a prototype. **It is not a production setting.** All data is synthetic `example.test` data. The passwords are throwaway literals.

## Layout

| Service | Image | Address | Role |
|---|---|---|---|
| `edge` | `dovecot/dovecot:2.4.5` | 172.30.3.10 | Proxy for IMAP 143, POP3 110, ManageSieve 4190 and LMTP 24. **No mail storage.** |
| `store-a` | same | 172.30.3.21 | Mail store (maildir) with marker mailbox `store-a`. |
| `store-b` | same | 172.30.3.22 | Mail store with marker mailbox `store-b`. |
| `postfix` | built from [postfix/Dockerfile](postfix/Dockerfile) | 172.30.3.30 | Delivers `example.test` over `lmtp:inet:172.30.3.10:24`. Also carries the check clients. |

No port is published. Each Dovecot container replaces the image's `dovecot.conf` wholesale.

| File | Content |
|---|---|
| [compose.yml](compose.yml) | Project `keepia-proto3` (network, named volumes, `mem_limit` 128 MiB, healthchecks). |
| [edge/dovecot.conf](edge/dovecot.conf) | The edge. |
| [edge/routing/routing.passwd](edge/routing/routing.passwd) | Routing lookup: extra fields after the **seventh** colon. |
| [store/common.conf](store/common.conf), [store-a/dovecot.conf](store-a/dovecot.conf), [store-b/dovecot.conf](store-b/dovecot.conf) | The stores. |
| [store/users.passwd](store/users.passwd) | Store passdb; the same file on both stores. |
| [postfix/main.cf](postfix/main.cf), [postfix/vmailbox](postfix/vmailbox) | Postfix. |
| [run.sh](run.sh) | Checks 0–8 with counter-proofs and the cleanup. |

`run.sh` works on untracked copies in `.run/`: the routing file, the store users file, and an empty include directory `.run/edge.d/` for the edge. That way a failed run never leaves a tracked file edited. The edge mounts `.run/routing/` as a **directory**.

## Versions (measured)

- Dovecot: `dovecot/dovecot:2.4.5@sha256:43c14def08a57f25107593cbcf64a0a6fbae84a7b9de7aa038513c9b21e91914`, `2.4.5 (0cbb641)`, Pigeonhole 2.4.5 (742bb89), Debian 13.7 base.
- Postfix base: `debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2` (pulled through `mirror.gcr.io/library/debian`).
- Packages: `postfix 3.10.13-0+deb13u1`, `curl 8.14.1-2+deb13u7`, `netcat-openbsd 1.229-1`.
- Tools: Docker 29.9.2, Compose v5.6.1.

## Build and run

```sh
./run.sh            # build, checks 0-8, cleanup
./run.sh --keep     # leave the project running afterwards
```

`run.sh` builds the Postfix image itself, outside Compose, with `docker build -q -t keepia-proto3-postfix ./postfix`. Compose then uses that image. The reason: Compose v5 always builds through bake, and bake asks for an explicit `--allow=fs.read=…` grant before it passes a secret file to the build.

Behind a TLS-inspecting proxy, set `PROTO3_CA_BUNDLE` to a CA bundle file. In the sandbox that is:

```sh
PROTO3_CA_BUNDLE=/root/.ccr/ca-bundle.crt ./run.sh
```

`run.sh` then builds with this exact command:

```sh
docker build -q --network host --build-arg HTTPS_PROXY \
  --secret id=ca,src="$PROTO3_CA_BUNDLE" -t keepia-proto3-postfix ./postfix
```

- The bundle reaches the build only as a BuildKit secret (mode 0444, because apt fetches as `_apt`), so it is never part of the image.
- `HTTPS_PROXY` is a predefined build argument, which Docker documents as left out of the image history (not checked here).

**Cleanup.** On exit, also after a FAIL, `run.sh` runs these steps:
1. `docker compose -p keepia-proto3 down -v --rmi local`;
2. `docker image rm keepia-proto3-postfix`, because an image built outside Compose is not removed by `--rmi local`;
3. removes its `.run/` files and directories by literal path.

The base images (`dovecot/dovecot:2.4.5`, `debian:trixie-slim`) and BuildKit's layer cache stay.

**Waits.** Every wait is a bounded poll on a signal (a log line, a queue entry, an open port, a lookup result, a protocol reply), with a deadline that fails the check. The longest is LMTP against a paused store, which takes 30 s.

## Checks

`E` is `docker compose -p keepia-proto3 exec -T postfix`. Each check prints the commands, their output and PASS/FAIL; the full transcript is on the PR. All results below were **measured** on 2.4.5 with this configuration.

| Check | Result | Counter-proof |
|---|---|---|
| 0 Start | `up --wait` 0; `2.4.5 (0cbb641)`; no `mail_*` on the edge; `doveadm auth lookup` gives `proxy : y` and the right `host` | A routing line with 6 colons gives no `proxy`/`host` |
| 1 IMAP | alice lists `store-a`, bob `store-b`; edge `proxy(<user>,172.30.3.2x:143): Started`; store logs `Logged in` on the right store only | Wrong password: `a NO [AUTHENTICATIONFAILED]`, edge `(proxy_dest_auth_failed)` |
| 2 POP3 | Same, on `:110` | Wrong password: `-ERR [AUTH] Authentication failed.`, `(proxy_dest_auth_failed)` |
| 3 LMTP | `status=sent (250 2.0.0 <user> … Saved)` via `172.30.3.10:24`; the Message-ID exactly once on the right store, `messages=0` on the other | Check 5: after re-routing, the same "other store" count reads 1 |
| 4 ManageSieve | `OK "Logged in."`, `OK "Listscripts completed."`; edge `proxy(alice…,172.30.3.21:4190)` | Wrong password: `NO "Authentication failed."`, `(proxy_dest_auth_failed)` |
| 5 Store change | Edge sees the edit within 0.2–0.9 s, no restart; the next IMAP login lists `store-b` (`…22:143`); the next mail lands on store-b; the old session keeps listing `store-a` until `doveadm proxy kick` (`Disconnected by proxy: Kicked by admin`) | The session opened before the edit still lists `store-a` under the same LIST assertion; the planned auth-cache counter-proof does not reproduce (F2) |
| 6a stopped store | IMAP `a NO [UNAVAILABLE] Account is temporarily unavailable.` after 7.2–7.3 s; POP3 `-ERR [SYS/TEMP] …` after 7.3 s; LMTP `451 4.4.0 Proxy failed (connect, …) (in reply to RCPT TO command)` after 3.1 s, `dsn=4.4.0, status=deferred`; `postqueue -j` `delay_reason` matches `said: 4xx`; 0 bounces; after `start` and `postqueue -f`, exactly once on store-b | 6c |
| 6b paused store | IMAP and POP3 the same after 5.1–5.2 s (`Login timed out … after 5 secs`); LMTP 451 at RCPT after 30 s (`Connection timed out after 30 seconds`); queued, 0 bounces; delivered once after `unpause` | 6c |
| 6c (last, review N8) | — | Store without bob: the edge relays `550 5.1.1 <bob@example.test> User doesn't exist: bob@example.test` and Postfix logs `status=bounced` (2 bounces: the mail and the bounce notice to `sender@`) |
| 7 carol, no `proxy`/`host` | IMAP `NO [AUTHENTICATIONFAILED]`, not proxied; LMTP `451 4.3.0 <carol@example.test> Temporary internal error (in reply to end of DATA command)`, deferred, 0 bounces; edge `Failed to initialize user: mail_driver not set …`, no `Saved`; `find` on the `edge-vmail` volume finds no file; `docker diff` shows only `/run` and the two mount points | Edge with `mail_driver`/`mail_home`/`mail_path` added: `250 2.0.0 <carol@example.test> … Saved` and the mail is a file on the edge's `/srv/vmail` |
| 8 unknown user | `550 5.1.1 <nobody@example.test> User doesn't exist: nobody@example.test` from the edge itself (neither store logs it); Postfix bounces, which is correct | With a routing line for nobody, store-a logs `passwd-file: unknown user` and gives the same 550, so "no store saw it" tells the two apart |

## Findings

**F1, chosen edge configuration.** The verbatim `doveconf -n` of the edge (measured):

```
dovecot_config_version = 2.4.3
auth_allow_cleartext = yes
auth_verbose = yes
default_internal_group = vmail
default_internal_user = vmail
default_login_user = vmail
dovecot_storage_version = 2.4.3
listen = *
lmtp_proxy = yes
log_path = /dev/stdout
login_proxy_timeout = 5s
protocols = imap pop3 lmtp sieve
ssl = no
state_dir = /run/dovecot
passdb passwd-file {
  passwd_file_path = /etc/dovecot/routing/routing.passwd
}
service lmtp {
  inet_listener lmtp {
    port = 24
  }
}
```

A routing line: `alice@example.test:::::::proxy=y host=172.30.3.21 nopassword=y` (seven colons). `auth_cache_size = 0` is in [edge/dovecot.conf](edge/dovecot.conf) but is the default, so `doveconf -n` does not list it.

**F2, store change and existing sessions** (measured):
- The edge rereads the passwd-file about once a second (0.2–0.9 s after the edit), without a restart. The next login and the next delivery follow the new `host`.
- Open sessions stay on the old store until `doveadm proxy kick <user>` ends them. `doveadm proxy list` shows only the client IP, never the backend; the edge log line `proxy(<user>,<host>:<port>)` is the place to see the backend. The 1.1.0 mailbox move must kick the user after the switch.
- **Auth cache.** On 2.4.5, with `auth_cache_size = 1M` and `auth_debug = yes`, every login still logs `passwd-file: Performing passdb lookup` (2 lookups for 2 logins). `run.sh` shows this for the `nopassword=y` line. In development runs it also held with a password in the line and with a `%{…}` path. So the plan's counter-proof "the cache keeps the old route" cannot be produced with passwd-file. The plan review's stale route was most likely the one-second reread interval: a login right after the edit can still see the old file.
  - For #2 (predicted, not observed): SQL or Lua backends use the auth cache, so a cached entry would keep the old route for `auth_cache_ttl`. Either keep the cache off on the edge, or run `doveadm auth cache flush <user>` as part of a move.
- **A mis-route is silent.** Both stores accept every user, because they share one users file. In one development run, a routing edit that also changed bob's line sent bob to store-a: he logged in and saw an empty INBOX, with no error. Requirement for #2/#5: a store accepts only the users it holds, so a mis-route fails as a login error or LMTP 550 instead of showing an empty mailbox. Note that LMTP 550 bounces, so a move must update the store's user list and the routing in an order that never routes a user to a store that does not know them yet.
- **Directory mount.** The plan chose a directory mount because a single-file mount would keep the old inode after `sed -i`. In this sandbox, one test with a single-file mount saw the edit too (measured once, not in `run.sh`). The directory mount is kept because it does not depend on that.

**F3, requirement for #2 and #5: the edge never has mail storage, and every routing entry carries `proxy` and `host`** (measured). `lmtp_proxy` falls back to local delivery for a user without `proxy`:
- Without storage on the edge, carol's mail gets `451 4.3.0 … Temporary internal error` after DATA and stays queued.
- With `mail_driver`/`mail_home`/`mail_path` on the edge, it gets `250 … Saved` and is stored **on the edge** (counter-proof 7). That breaks security property 3.

So the edge config must replace the image config wholesale (the image sets `mail_driver = maildir`, `mail_home = /srv/vmail/%{user | lower}`), and the routing data must not hold entries without `proxy`/`host`.

**F4, lookup-backend failure** (not tested here). When the routing lookup itself fails (SQL down, Go service down), the edge must answer with a tempfail (IMAP `[UNAVAILABLE]`, LMTP 4xx), never 5xx. This is a requirement for #2's backend choice and has to be tested there.

**F5, tempfail texts and timings** (measured):

| | stopped store (6a) | paused store (6b) |
|---|---|---|
| IMAP | `NO [UNAVAILABLE] Account is temporarily unavailable.` after 7.2–7.3 s | same, after 5.1 s |
| POP3 | `-ERR [SYS/TEMP] Account is temporarily unavailable.` after 7.3 s | same, after 5.1–5.2 s |
| LMTP | `451 4.4.0 Proxy failed (connect, …)` at RCPT after 3.1 s | same, after 30 s |
| Postfix | `dsn=4.4.0, status=deferred`, queued, 0 bounces | same |

- 6a: `connect … failed: No route to host (after 3 secs)` is followed by one reconnect, which also fails, at 7 s. `login_proxy_timeout = 5s` does not cut this short. The plan expected 5.0 s.
- 6b: the timeout is `login_proxy_timeout`, logged as `Login timed out in state=/none` (IMAP) or `state=banner` (POP3).
- LMTP does not use `login_proxy_timeout`. The paused case is the smtp-client connect default of 30 s (`lmtp-client: … Connection timed out after 30 seconds`).
- From the plan review's source reading (not observed here): passdb `proxy_timeout` only sets LMTP's DATA timeout (default 125 s). Postfix's `lmtp_rcpt_timeout` (300 s default) must stay above the edge's 30 s.

**F6, password forwarding** (measured). The edge holds no passwords (`nopassword=y`). It sees only the store's verdict and logs `Login aborted: … (proxy_dest_auth_failed)`, with the reason text, for IMAP, POP3 and ManageSieve.
- After a failed login, the next login from the same client IP took about 4 s longer: `Started proxying … (4.02 secs)` against 0.015 s otherwise. That is presumably the edge's auth-failure penalty. The cause is inferred, not checked.
- So edge-side throttling works with forwarding. #2 decides whether shared bans (Redis/Valkey) use this log line or the store's result.

**F7, resources** (measured, `docker stats --no-stream` after the run):
- Memory, over three runs: edge 9.7–11.0 MiB, store-a 9.8–10.2 MiB, store-b 9.8–10.3 MiB, Postfix 9.7–9.8 MiB, about 40 MiB in total. CPU 0.00–0.02 %.
- Images: Dovecot 267 MB (shared by three containers), Postfix 198 MB. Mail data is under 1 MB.
- The edge proxy role is about 10 MiB idle, plus login processes per connection. This is well within 4 GB RAM / 2 cores.

**F8, image and configuration facts for #5** (measured):
- Image runtime: user `vmail`, `tini` entrypoint, `/dovecot/sbin/dovecot -F`. Default listeners 31024/31110/31143/31587/31993/31995/34190, plus 8080/9090.
- Image contents: `VOLUME /srv/vmail`, no healthcheck. `sh`, `nc` and `doveadm` are present; `sed`, `find`, `cat` and `ls` are not. Size 267 MB.
- `dovecot_config_version` (2.4.3) must be the **first setting of `dovecot.conf`**, so a shared `!include` file cannot carry it: `The first setting must be dovecot_config_version`. The stores therefore set it in their own `dovecot.conf`.
- POP3 is not in the image's default `protocols`. `listen = *` is needed on hosts without IPv6 (`listen(::, 143) failed`).
- Compose healthcheck: `nc -z 127.0.0.1 143` works, but every probe logs `Login aborted … (no_auth_attempts)` or `(auth_process_not_ready)`. Compose therefore probes every second only while starting (`start_interval`), then every 300 s.
- Store logins log as `<proto>-login: Info: Logged in: user=<…>` with `rip` = the edge.
- ManageSieve does not answer commands sent before the greeting (pipelined). Clients have to wait for `OK "Dovecot ready."`; measured during development.
- `curl -v` does not print the server's final `NO`/`-ERR` line of a failed IMAP/POP3 login. `run.sh` uses a line-by-line `nc` dialog for failure texts.
- netcat-openbsd keeps running after the server closes while its stdin is open, so a kicked session shows up as a command with no reply plus the edge's log line.
