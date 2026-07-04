# Demo 09 — Leaked application source (Django settings)

## Where this came from

A `settings.py` from a leaked source archive where secrets were hardcoded "for
convenience" and never moved to environment variables. The Django `SECRET_KEY`
is especially dangerous — it signs every session cookie and password-reset
token, so leaking it enables session forgery.

## What to expect

`keyhound` reports **3 findings**:

| Detector | Severity | What |
|---|---|---|
| `hardcoded-password` | high | `EMAIL_HOST_PASSWORD` literal |
| `api-key-assignment` | medium | `SECRET_KEY` (Django signing key) |
| `api-key-assignment` | medium | `SENTRY_AUTH_TOKEN` |

## Run it

```sh
keyhound scan demos/09-source-leak
keyhound scan demos/09-source-leak --severity high   # only high+ in this view
```

## How to act

Rotate the `SECRET_KEY` (forces re-login for all users, which is the point),
rotate the SMTP and Sentry credentials, and load all of them from the
environment. Add `keyhound scan .` as a pre-commit hook so this never lands
again.
