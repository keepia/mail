---
paths:
  - "Dockerfile"
  - ".dockerignore"
  - "images/**"
  - "docker-bake.hcl"
  - "docker-compose.yml"
  - "deploy/**"
  - "scripts/image-test.sh"
  - "tools/check-image-pins/**"
---
# Docker
- **Pins** (`tools/check-image-pins`, `make image-pins`): `# syntax=` is `name:X.Y.Z@sha256:<64 hex>`; every `FROM`, `COPY --from=` and `RUN --mount=…,from=` is an earlier stage or `name:tag@sha256:<64 hex>`; Compose's upstream images are `tag@sha256`; own images are built from local contexts; workflow `container`/`services` images are pinned by digest. Write every `--flag` on the instruction's first line, ADD sources literally (no `$VAR`), no here-documents, no `ONBUILD`, no bake `contexts`. The bake rule reads `docker buildx bake --print`, so `make image-pins` needs Docker with buildx.
- **Downloads only by `ADD --checksum=sha256:`**, one URL per `ADD`, from a source the plan lists. No `curl`, `wget`, `pip install` from an index, `git clone` or any other download in `RUN`: the check cannot see them, so review must. Debian packages come from the Debian archive through `images/common/keepia-apt-install`, which records them in `/usr/share/keepia/packages.txt` (recorded, not pinned).
- A new registry, base image, package source or action is a new external service: the maintainer's OK first.
- **Privileges:** `cap_drop: [ALL]`, `no-new-privileges`, and exactly the capabilities the plan lists per container (Postfix: `CHOWN DAC_OVERRIDE FOWNER SETUID SETGID`, with `chroot = n` for every `master.cf` service; Dovecot: `SYS_CHROOT`; all others none). Fixed non-zero uids; only Postfix's master runs as root. No `privileged`, host network or Docker socket.
- **R-BIND-PRIVATE:** every listener binds the container's fixed private address or loopback, never `0.0.0.0` or `::`.
- **Healthchecks need a protocol reply** (an SMTP `220 `, `unbound-control status`, `/healthz`), never only a process or an open port, and each is measured red with the service broken or stopped (`scripts/image-test.sh`).
- Reloads: Postfix and Unbound reload through `images/common/keepia-reload-watch` (architecture section 5); keep its tests in `scripts/image-test.sh` green.
- Changes here are container privileges or networking: `second-review`.
