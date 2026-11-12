# Keepia Mail

Keepia Mail is a mail server for several servers working together. It builds
on Postfix, Dovecot, rspamd, ClamAV, olefy, Unbound and SOGo, and runs as
Docker Compose projects, one per server. Each server takes one or more roles:
control, edge, store, filter and groupware. Keepia places mailboxes on mail
stores and routes all traffic to them, so servers can be added without
changing how mail reaches a mailbox.

**Status: In development, not ready for production use.**

Keepia Mail is developed with AI assistance; every change goes through
independent reviews and automated checks.

## Development

How work is planned, reviewed and merged is described in
[docs/development/process.md](docs/development/process.md). The checks that
run on every pull request are in
[docs/development/index.md](docs/development/index.md).

## Operations

Moving the reference installation from mailcow to Keepia Mail:
[docs/operations/mailcow-migration.md](docs/operations/mailcow-migration.md)
(a skeleton that grows with the milestones).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
