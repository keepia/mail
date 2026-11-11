# Security Policy

## Reporting a vulnerability

Please report security problems **privately** through
[GitHub's private vulnerability reporting](https://github.com/keepia/mail/security/advisories/new).
Do not open a public issue.

Include what you found, how to reproduce it and what an attacker could do with it.

## Supported versions

Only the latest state of the `main` branch is supported until the first
release. There are no maintained older versions.

## What to expect

We acknowledge a report within 7 days. We then assess it and fix it by
severity; there is no fixed deadline for the fix. You are credited in the
advisory unless you prefer otherwise.

CI scans every pull request and every push to `main` for committed
credentials (gitleaks, check `secret-scan`), and CodeQL (default setup)
analyses the code.

## Scope

In scope, for example:

- Bypassing authentication for IMAP, POP3, SMTP, the admin interface, 2FA or passkeys
- Accessing another mailbox or another customer group
- An open relay
- Reading mail at rest without the keys
- Bypassing the mutual TLS between the control plane and the agents

Out of scope:

- Setups that go against the security documentation
- Vulnerabilities in dependencies without a demonstrated impact on this project
