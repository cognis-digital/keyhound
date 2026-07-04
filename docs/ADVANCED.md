# keyhound — Advanced usage

## CI gate (fail the build on findings)
```yaml
- run: pip install keyhound
- run: keyhound scan . --format sarif --out keyhound.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: keyhound.sarif }
```

## Pipe into a SIEM / webhook
```bash
keyhound scan . --format json | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"
```

## Drive it from an AI agent (MCP)
```jsonc
// claude_desktop_config.json
{ "mcpServers": { "keyhound": { "command": "keyhound", "args": ["mcp"] } } }
```

## Run a language port instead of Python
```bash
node ports/javascript/index.js .     # Node
( cd ports/go && go run . .. )        # Go single binary
( cd ports/rust && cargo run -- .. )  # Rust
```

## Query the bundled offline vulnerability DB
```bash
keyhound vulndb --count                       # 262351 (no network)
keyhound vulndb CVE-2021-44228                 # Log4Shell record
keyhound vulndb --package log4j-core           # all vulns for a package
keyhound vulndb --search "deserialization"     # summary search
```

## Refresh / air-gap the edge data feeds
```bash
keyhound feeds list --domain vuln              # CISA KEV / EPSS / OSV / NVD ...
keyhound feeds update cisa-kev epss            # fetch + cache (online)
keyhound feeds get cisa-kev --offline          # serve cache only, no network
keyhound feeds snapshot-export feeds.tar.gz    # sneakernet to an air gap
keyhound feeds snapshot-import feeds.tar.gz    # restore inside the enclave
```

## Ports & services
Default service/forward ports: **8000** (HTTP API), **8080** (alt), **3000** (UI), **9090** (metrics).
