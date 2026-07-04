# Demo 05 — Decompiled mobile app (APK) secrets

## Where this came from

A released Android APK was unpacked with `apktool`/`baksmali`. Mobile apps
routinely ship backend keys inside `res/values/strings.xml` and in `const-string`
Dalvik instructions, on the false assumption that compiled bytecode hides them.
It does not — anyone can decompile a shipped APK.

## What to expect

`keyhound` reports **3 findings** across the two extracted artifacts:

| File | Detector | Severity |
|---|---|---|
| `strings.xml` | `gcp-api-key` | high |
| `strings.xml` | `jwt` | medium |
| `ApiClient.smali` | `connection-uri-password` | high |

The JWT here is an unsigned demo token; the Google Maps key is a syntactically
valid `AIza…` key shape.

## Run it

```sh
keyhound scan demos/05-mobile-app
keyhound scan demos/05-mobile-app --format json | jq '.findings[].detector'
```

## How to act

Move the API key behind a server-side proxy with key restrictions, stop
embedding long-lived JWTs in resources, and never ship basic-auth fallback
URIs in client code. Add `keyhound scan` to the mobile release pipeline.
