# Demo 01 - Basic firmware credential scan

## What this shows

A tiny stand-in for an *extracted router firmware* filesystem: a busybox
config snippet and a web-admin script with the kind of secrets that get
baked into consumer IoT images.

The sample file `firmware_dump.txt` contains, mixed in with realistic noise:

- a hardcoded admin password assignment
- a default telnet/busybox login (`telnetd -l ...`)
- an embedded private key block
- an AWS access key id
- a database connection URI with an inline password
- an `/etc/shadow`-style hashed password line

## Run it

```sh
# Human-readable
python -m keyhound scan demos/01-basic/firmware_dump.txt

# JSON for CI / jq
python -m keyhound scan demos/01-basic/firmware_dump.txt --format json
```

## Expected result

KEYHOUND reports **6 findings** across `critical` and `high` severities
(private key, AWS key, hardcoded password, telnet default login, connection
URI password, shadow hash). Secrets are redacted by default.

Because secrets were found, the process exits with code **1** - so dropping
`keyhound scan` into a CI pipeline will fail the build when creds leak into a
build artifact. Pass `--show-secrets` to see full values during triage.
