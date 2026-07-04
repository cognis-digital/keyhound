# Ports of keyhound

The same secret-scanning logic, ported across languages so you can drop keyhound
into any stack or ship a single static binary. **Every port mirrors the core
detector set, emits the same JSON shape, redacts secrets by default, and uses
the same CI-friendly exit codes** (`0` clean, `1` secrets found, `2` usage error).

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | [`../keyhound/`](../keyhound/) | `keyhound scan .` | `pytest` |
| Node / JavaScript | [`javascript/`](javascript/) | `node ports/javascript/index.js .` | `node --test` |
| Go | [`go/`](go/) | `cd ports/go && go run . ..` | `go test ./...` |
| Rust | [`rust/`](rust/) | `cd ports/rust && cargo run -- ..` | `cargo test` |

## Shared output shape

```json
{
  "tool": "keyhound",
  "version": "1.2.9",
  "count": 1,
  "findings": [
    {
      "detector": "aws-access-key",
      "description": "AWS access key id",
      "severity": "critical",
      "path": "dump/upload.sh",
      "line": 11,
      "column": 19,
      "secret": "AKIA************MPLE"
    }
  ]
}
```

## Detector coverage

All ports detect the high-confidence, fixed-format secret families: PEM private
keys, AWS access keys, Google API keys, GitHub tokens, and hardcoded password
assignments. The Python (reference) and Node ports additionally cover AWS secret
keys, Slack tokens, JWTs, connection-URI passwords, generic high-entropy
api/secret assignments (with the same entropy gate and placeholder
suppression), `/etc/shadow` hashes, and telnet/busybox default logins. Use the
**Python reference implementation for the full 12-detector surface**; the
compiled ports favour the formats that benefit most from a single static binary.

## CI

`.github/workflows/ports.yml` builds and tests the Node, Go, and Rust ports on
every push — so these are real, verifiable binaries, not vaporware, even on
machines without the toolchains installed locally.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
[../CONTRIBUTING.md](../CONTRIBUTING.md).
