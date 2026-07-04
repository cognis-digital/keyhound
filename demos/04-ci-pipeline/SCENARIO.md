# Demo 04 — Secrets committed to a CI pipeline file

## Where this came from

A developer forked an internal service to a public repo and pasted cloud
credentials straight into `.gitlab-ci.yml` instead of using masked CI
variables. This is one of the most common real-world leak paths: the secret
isn't in application code, it's in the build configuration.

## What to expect

`keyhound` reports **4 critical/high findings**:

| Detector | Severity | What |
|---|---|---|
| `aws-access-key` | critical | `AKIA…` access key id |
| `aws-secret-key` | critical | 40-char AWS secret access key |
| `github-token` | critical | `ghp_…` personal access token |
| `gcp-api-key` | high | `AIza…` Google API key |

> The AWS values are AWS's own published documentation examples; treat any
> real match as live and rotate immediately.

## Run it

```sh
keyhound scan demos/04-ci-pipeline

# CI gate: fail the build only on high+ severity, emit SARIF for code-scanning
keyhound scan demos/04-ci-pipeline --format sarif --out keyhound.sarif --fail-on high
```

## How to act

Rotate all four credentials, purge them from git history (`git filter-repo`),
and move them to masked CI variables or a secrets manager. The exit code is
`1`, so the pipeline step fails and blocks the merge.
