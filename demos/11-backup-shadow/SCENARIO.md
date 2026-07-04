# Demo 11 — Misplaced /etc backup tarball

## Where this came from

A text listing of an `/etc` backup tarball discovered on a public file share —
a classic exposure. An `/etc` backup leaks the two most damaging things a host
holds: the password-hash database (`/etc/shadow`) and the server's private TLS
key (`/etc/ssl/private/server.key`).

## What to expect

`keyhound` reports **4 findings**:

| Detector | Severity | What |
|---|---|---|
| `private-key` | critical | EC TLS private key (`server.key`) |
| `unix-shadow-hash` | high | `root` SHA-512 (`$6$`) hash |
| `unix-shadow-hash` | high | `admin` SHA-512 (`$6$`) hash |
| `unix-shadow-hash` | high | `backup` MD5 (`$1$`) hash |

Locked/disabled accounts (`daemon:*`, `sshd:!`) carry no hash and are correctly
**not** flagged.

## Run it

```sh
keyhound scan demos/11-backup-shadow
keyhound scan demos/11-backup-shadow --format json | jq '.findings[].detector'
```

## How to act

Pull the backup off the public share immediately. Treat the private key as
compromised: reissue the certificate and revoke the old one. Force a password
reset for every account with an exposed hash (the `$1$` MD5 account is
especially urgent — that algorithm is trivially crackable).
