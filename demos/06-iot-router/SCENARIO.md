# Demo 06 — Consumer router firmware root filesystem

## Where this came from

A SquashFS root filesystem carved out of a consumer router image with
`binwalk`. This is keyhound's headline use case: point it at extracted firmware
and surface the credentials baked into millions of identical devices.

## What to expect

`keyhound` reports **4 findings**:

| Detector | Severity | What |
|---|---|---|
| `private-key` | critical | Dropbear OpenSSH host private key (shared across the fleet) |
| `telnet-default-cred` | high | a `telnetd`/`busybox` factory backdoor shell (login = `/bin/sh`) |
| `slack-token` | high | `xoxb-…` token in the cloud-notify script |
| `hardcoded-password` | high | factory `admin_password` |

The `guest_password="changeme"` line is intentionally present and is **not**
flagged — keyhound suppresses common placeholders to keep signal high.

## Run it

```sh
keyhound scan demos/06-iot-router
keyhound scan demos/06-iot-router --show-secrets   # full values during triage
```

## How to act

A shared host key means one extracted device compromises SSH trust for the
whole product line — these must be generated per-device on first boot. Remove
the telnet backdoor, rotate the Slack token, and force a password change on
first login.
