<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=KEYHOUND&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="KEYHOUND"/>

# KEYHOUND

### Scan firmware blobs and filesystem dumps for hardcoded private keys, API tokens, default creds, and weak RSA/ECC material.

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Scan+firmware+blobs+and+filesystem+dumps+for+hardcoded+priva;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/keyhound.svg?color=6b46c1)](https://pypi.org/project/keyhound/) [![CI](https://github.com/cognis-digital/keyhound/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/keyhound/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*IoT / OT / Embedded — firmware, buses, and device security.*

</div>

```bash
pip install keyhound
keyhound scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ keyhound-emit --version
keyhound 1.2.9
```

```console
$ keyhound-emit --help
usage: keyhound [-h] [--version] [--format {table,json,sarif}]
               {scan,vulndb,feeds,mcp} ...

Scan firmware / filesystem dumps for hardcoded keys, tokens, and default credentials.

positional arguments:
  {scan,vulndb,feeds,mcp}
    scan                scan a file or directory tree for secrets
    vulndb              query the bundled offline vulnerability database (OSV,
                        262k records)
    feeds               list/refresh the keyless edge data-feed catalog
                        (offline-capable)
    mcp                 run keyhound as an MCP stdio server (requires the 'mcp'
                        extra)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --format {table,json,sarif}
                        output format (default: table)

Point it at a router firmware extraction and get hardcoded creds. Exit code 1 means secrets were found (CI-friendly).
```

> Blocks above are real `keyhound` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"findings": [
    {
        "id": "1234567890",
        "title": "Suspicious Network Traffic",
        "description": "Potential malicious activity detected on network interface 192.168.1.100",
        "created": "2023-02-20T14:30:00Z",
        "modified": "2023-02-20T14:30:00Z",
        "objects": [
            {
                "id": "1234567890-object-1",
                "type": "indicator",
                "name": "Suspicious IP Address",
                "description": "Potential malicious activity detected on network interface 192.168.1.100"
            }
        ]
    },
    {
        "id": "2345678901",
        "title": "Unusual File Access",
        "description": "Potential unauthorized access to file C:\\Windows\\System32\\drivers\\etc\\hosts",
        "created": "2023-02-20T14:30:00Z",
        "modified": "2023-02-20T14:30:00Z",
        "objects": [
            {
                "id": "2345678901-object-1",
                "type": "indicator",
                "name": "Unusual File Access",
                "description": "Potential unauthorized access to file C:\\Windows\\System32\\drivers\\etc\\hosts"
            }
        ]
    }
]
}
```

<!-- cognis:example:end -->

## Usage — step by step

1. **Install** the scanner:

   ```bash
   pip install keyhound
   ```

2. **Scan a tree** (e.g. an extracted firmware image or filesystem dump) for hardcoded keys, tokens, and default creds:

   ```bash
   keyhound scan /tmp/firmware_extracted
   ```

3. **Filter by severity** and emit JSON for CI or `jq`:

   ```bash
   keyhound scan ./dump --severity high --format json | jq '.findings[] | select(.severity=="critical")'
   ```

4. **Read the result.** Secrets are redacted by default; pass `--show-secrets` to print full values. Exit code `0` = no findings, `1` = one or more secrets found, `2` = usage/runtime error.

5. **Gate a build.** keyhound's exit code makes it a drop-in CI check:

   ```bash
   keyhound scan ./build --severity high || { echo 'hardcoded secrets found'; exit 1; }
   ```

## Contents

- [Why keyhound?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Output formats](#output-formats) · [Vulnerability database](#vulndb) · [Edge data feeds](#feeds) · [Scope & safety](#scope) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why keyhound?

Instant gratification — point at any router firmware and get 'hardcoded root SSH key shared across 2M devices.' Universal hardcoded-cred findings are reliably front-page.

`keyhound` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ 12 detectors — PEM private keys, AWS access/secret keys, Google API keys, GitHub & Slack tokens, JWTs, connection-URI passwords, `/etc/shadow` hashes, hardcoded passwords, generic high-entropy api/secret assignments, telnet/busybox default logins
- ✅ Secrets **redacted by default** (safe to paste into tickets/CI logs); `--show-secrets` to reveal
- ✅ Placeholder + entropy filtering keeps the false-positive rate low (see [`demos/10-clean-config`](demos/10-clean-config/))
- ✅ Output as `table`, `json`, or **SARIF 2.1.0**; `--out FILE`, `--severity`, and `--fail-on` for CI gating
- ✅ 9 real-world [demo scenarios](#demos), each verified by a test
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ **Passive & offline by design** — keyhound only ever *reads* files; it makes no network connections and runs air-gapped
- ✅ Real ports in **Python, Node/JavaScript, Go, and Rust** (`ports/`) — each mirrors the core detector set, emits the same JSON shape, and ships with a test suite + CI
- ✅ Bundled **262,351-record offline OSV vulnerability database** (`keyhound vulndb`) — no network, no key (see [Vulnerability database](#vulndb))
- ✅ Keyless **edge / air-gap data-feed ingester** (`keyhound feeds`) for CISA KEV · EPSS · OSV · NVD · MITRE ATT&CK · NIST OSCAL · abuse.ch (see [Edge data feeds](#feeds))

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install keyhound
keyhound --version
keyhound scan .                       # scan current project
keyhound scan . --format json         # machine-readable
keyhound scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ keyhound scan demos/06-iot-router
Found 4 secret(s): 1 critical, 3 high

[CRITICAL] private-key              demos/06-iot-router/rootfs_dump.txt:4:1
             PEM private key block
             secret: ----************************-----
[HIGH    ] telnet-default-cred     demos/06-iot-router/rootfs_dump.txt:10:20
             Default/embedded telnet or busybox login
             secret: /******
[HIGH    ] slack-token             demos/06-iot-router/rootfs_dump.txt:13:21
             Slack token
             secret: xoxb**********************************************uVwX
[HIGH    ] hardcoded-password      demos/06-iot-router/rootfs_dump.txt:17:17
             Hardcoded password assignment
             secret: Admi*********tory
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="demos"></a>
## Demos — real-world scenarios

Every folder in [`demos/`](demos/) is a self-contained scenario: a realistic
input in keyhound's real input format plus a `SCENARIO.md` that explains where
the data came from, what keyhound reports, and how to remediate. Each one is
covered by a test, so the findings stay reproducible.

| Demo | Scenario | Fires |
|---|---|---|
| [`01-basic`](demos/01-basic/) | Extracted router firmware filesystem | private key, AWS key, telnet backdoor, shadow hash, URI password, hardcoded password |
| [`04-ci-pipeline`](demos/04-ci-pipeline/) | Secrets pasted into `.gitlab-ci.yml` | AWS access + secret key, GitHub token, Google API key |
| [`05-mobile-app`](demos/05-mobile-app/) | Decompiled Android APK (`strings.xml` + smali) | Google API key, JWT, connection-URI password |
| [`06-iot-router`](demos/06-iot-router/) | Carved SquashFS rootfs | OpenSSH host key, telnet backdoor, Slack token, factory password |
| [`07-docker-compose`](demos/07-docker-compose/) | Live creds in `docker-compose.yml` | Postgres password, two connection-URI passwords |
| [`08-k8s-secrets`](demos/08-k8s-secrets/) | Helm `values.yaml` with hardcoded secrets | MongoDB URI, Stripe key, client secret |
| [`09-source-leak`](demos/09-source-leak/) | Leaked Django `settings.py` | SMTP password, Django `SECRET_KEY`, Sentry token |
| [`10-clean-config`](demos/10-clean-config/) | Clean template (placeholders + `${ENV}`) | **nothing** — false-positive control, exits 0 |
| [`11-backup-shadow`](demos/11-backup-shadow/) | Misplaced `/etc` backup tarball | EC TLS private key, three `/etc/shadow` hashes |

```bash
keyhound scan demos/06-iot-router            # see the firmware findings
keyhound scan demos/10-clean-config          # confirm a clean tree exits 0
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="output-formats"></a>
## Output formats & CI gating

```bash
keyhound scan ./dump                                  # table (default)
keyhound scan ./dump --format json                    # machine-readable
keyhound scan ./dump --format sarif --out keyhound.sarif   # SARIF 2.1.0 for code-scanning
keyhound scan ./dump --severity high                  # only report high+ findings
keyhound scan ./dump --fail-on high                   # exit 1 only on high+ (CI gate)
```

The SARIF output is a valid 2.1.0 log (one rule per detector, one result per
finding, secrets redacted) and uploads directly via
`github/codeql-action/upload-sarif`. `--fail-on` lets you report everything
while gating the build on a chosen severity; `--out` writes to a file instead
of stdout.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="vulndb"></a>
## Vulnerability database — bundled, offline, 262k records

keyhound ships a consolidated **OSV corpus** at `keyhound/cognis_vulndb.jsonl.gz`:
**262,351 real vulnerabilities** across PyPI, npm, Go, Maven, RubyGems,
crates.io, and NuGet, each with `id`, CVE/GHSA aliases, ecosystem, summary,
severity, affected packages, and publish/modify dates. The loader is pure
standard library, so it works **fully offline / air-gapped — no network, no key**.

```bash
keyhound vulndb --count                       # -> 262351
keyhound vulndb CVE-2021-44228                 # Log4Shell record (JSON)
keyhound vulndb --package log4j-core           # all vulns affecting a package
keyhound vulndb --search "deserialization"     # summary substring search
```

```text
$ keyhound vulndb CVE-2021-44228
{
  "query": "CVE-2021-44228",
  "count": 1,
  "records": [
    {
      "id": "GHSA-jfh8-c2jp-5v3q",
      "aliases": ["CVE-2021-44228"],
      "ecosystem": "Maven",
      "summary": "Remote code injection in Log4j",
      "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
      "packages": ["org.apache.logging.log4j:log4j-core", "..."]
    }
  ]
}
```

From Python:

```python
from keyhound.vulndb_local import VulnDB
db = VulnDB()                       # lazy-loads the bundled gz
db.count()                          # 262351
db.by_cve("CVE-2021-44228")         # list of records
db.by_package("log4j-core")         # records affecting that package
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="feeds"></a>
## Edge data feeds — keyless, offline-capable refresh

For deployments that want fresher intelligence than the bundled snapshot,
keyhound includes a stdlib-only ingester (`keyhound feeds`) over a catalog of
**real, mostly-keyless feeds** — CISA KEV, FIRST EPSS, OSV, NVD, MITRE ATT&CK
(STIX), NIST SP 800-53 (OSCAL), and abuse.ch (Feodo/ThreatFox/URLhaus/SSLBL).

It is built for the edge / air gap:

- **Standard library only** (`urllib`) — no pip dependencies.
- **Explicit fetches.** Nothing is downloaded until you run `feeds update`.
- **`--offline` serves cache only** and never touches the network.
- **Snapshot export/import** tars the cache for sneakernet transfer into a
  disconnected enclave.

```bash
keyhound feeds list                              # show the catalog + cache age
keyhound feeds list --domain vuln                # filter by domain
keyhound feeds update cisa-kev epss              # fetch + cache (online)
keyhound feeds get cisa-kev --offline            # serve from cache, no network
keyhound feeds snapshot-export feeds.tar.gz      # for air-gap transfer
keyhound feeds snapshot-import feeds.tar.gz      # restore inside the enclave
```

The catalog lives at `keyhound/data_feeds_2026.json`; the cache directory is
`COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`). All feeds are
defensive / authorized-use intelligence only.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="scope"></a>
## Scope, authorization & safety

keyhound is a **defensive, authorized-use** tool.

- **Passive and offline.** keyhound only *reads* files you point it at — extracted
  firmware, filesystem dumps, config trees, source. It performs **no active
  scanning, no network probing, and no exploitation**. There is nothing to gate
  behind a `--authorized` flag because the tool never reaches out.
- **Use it on assets you own or are authorized to assess.** Recovering secrets
  from third-party firmware/dumps you have no right to inspect may be illegal.
- **Findings are redacted by default** so reports, tickets, and CI logs stay
  safe to share; `--show-secrets` reveals full values and should be used only
  on trusted output sinks.
- **No fabricated intelligence.** Every record in the bundled DB and every entry
  in the feed catalog is a real, attributable upstream source.
- **Responsible disclosure.** If a scan reveals a live secret in someone else's
  product, follow the vendor's disclosure process — see [SECURITY.md](SECURITY.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[keyhound<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`keyhound` is interoperable with every popular way of using AI:

- **MCP server** — `keyhound mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `keyhound scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis keyhound** | trufflehog + EAPOL |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **trufflehog + EAPOL/binwalk extract**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`keyhound mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/keyhound.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/keyhound.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/keyhound.git" # uv
pip install keyhound                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/keyhound:latest --help        # Docker
brew install cognis-digital/tap/keyhound                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/keyhound/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/keyhound` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`fwxray`](https://github.com/cognis-digital/fwxray) — Diff two firmware images and surface exactly what changed: new binaries, flipped config flags, added certs, and shifted entropy regions.
- [`canzap`](https://github.com/cognis-digital/canzap) — Replay, fuzz, and assert on CAN bus traffic from a .pcap or SocketCAN interface with a tiny YAML DSL.
- [`sbomb`](https://github.com/cognis-digital/sbomb) — Generate a CycloneDX SBOM directly from an unpacked firmware root filesystem and flag components with known CVEs and EOL kernels.
- [`mqttspy`](https://github.com/cognis-digital/mqttspy) — Passively map an MQTT broker: enumerate topics, detect unauthenticated writes, spot PII/secrets in payloads, and emit a risk report.
- [`uefiscan`](https://github.com/cognis-digital/uefiscan) — Audit UEFI firmware dumps for missing Secure Boot keys, unsigned modules, S3 boot-script vulns, and known SMM threats.
- [`modpot`](https://github.com/cognis-digital/modpot) — Spin up a high-interaction Modbus/DNP3 ICS honeypot that logs attacker register reads/writes as structured JSON.

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `keyhound` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`keyhound` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>

## Bundled offline data

- **Vulnerability DB** — `keyhound/cognis_vulndb.jsonl.gz`: **262,351 real
  vulnerabilities** (OSV across 7 ecosystems) with detailed metadata; offline
  stdlib loader `vulndb_local.VulnDB`, air-gap ready. See
  [Vulnerability database](#vulndb).
- **Edge feed catalog** — `keyhound/data_feeds_2026.json` + `keyhound/datafeeds.py`:
  keyless, offline-capable refresh of CISA KEV / EPSS / OSV / NVD / ATT&CK /
  OSCAL / abuse.ch, with snapshot export/import for sneakernet to an air gap.
  See [Edge data feeds](#feeds).
