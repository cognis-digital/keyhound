# Demo 07 — Live credentials in a docker-compose file

## Where this came from

A staging `docker-compose.yml` committed with real connection strings inline
instead of referencing an untracked `.env`. Connection URIs are a high-value
target because one string leaks the host, port, database, username, and
password together.

## What to expect

`keyhound` reports **3 findings**:

| Detector | Severity | What |
|---|---|---|
| `hardcoded-password` | high | `POSTGRES_PASSWORD` literal |
| `connection-uri-password` | high | password inside `DATABASE_URL` (postgres) |
| `connection-uri-password` | high | password inside `AMQP_URL` (rabbitmq) |

Note keyhound extracts the **password** out of each URI, not the whole string,
so the finding points straight at the secret to rotate.

## Run it

```sh
keyhound scan demos/07-docker-compose
keyhound scan demos/07-docker-compose --format json \
  | jq '.findings[] | {detector, secret, line}'
```

## How to act

Move every credential into a `.env` referenced via `${VAR}` interpolation (and
`.gitignore` it), or a secrets manager. Rotate the Postgres and RabbitMQ
passwords since they were exposed in version control.
