# Demo 10 — Clean config (false-positive resistance)

## Where this came from

A well-maintained `config.env.example` template. Every secret-shaped value is
either a known placeholder (`changeme`, `<password>`, `your_password`,
`placeholder`) or an environment reference (`${VAR}`, `$VAR`) — i.e. there is
no actual literal secret present.

## What to expect

`keyhound` reports **0 findings** and exits **0**.

This demo is the control case: a secret scanner that cries wolf on good hygiene
is one people turn off. keyhound suppresses common placeholders and does not
treat environment indirection (`${AWS_ACCESS_KEY_ID}`) as a literal value.

## Run it

```sh
keyhound scan demos/10-clean-config            # prints "No secrets found.", exits 0
keyhound scan demos/10-clean-config --format json
echo "exit code: $?"                          # 0 — safe to gate CI on
```

## How to act

Nothing to fix. Use this file as a reference for how to keep example/template
configs scanner-clean: placeholders and `${ENV}` references only, never a real
value.
