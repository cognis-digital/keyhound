# Demo 08 — Helm chart values with hardcoded secrets

## Where this came from

A Helm `values.yaml` checked into a chart repository. During an incident,
someone pasted a payment-processor API key and a service credential directly
into the chart to "just get it working," and it was never removed.

## What to expect

`keyhound` reports **3 findings**:

| Detector | Severity | What |
|---|---|---|
| `connection-uri-password` | high | password inside `mongodb_uri` |
| `api-key-assignment` | medium | `payment_api_key` (high-entropy token) |
| `api-key-assignment` | medium | `client_secret` (high-entropy hex) |

The token values here are synthetic demo strings; treat any real
processor-key match in your own scans as live and rotate it.

## Run it

```sh
keyhound scan demos/08-k8s-secrets

# Only fail CI on high+; medium api-key findings are reported but don't gate
keyhound scan demos/08-k8s-secrets --fail-on high
```

## How to act

Move production overrides into a sealed-secret or an external secret store
(External Secrets Operator, Vault), keep `values.yaml` placeholder-only, and
rotate the MongoDB and Stripe credentials.
