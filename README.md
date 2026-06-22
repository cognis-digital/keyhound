<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=KEYHUNT&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="KEYHUNT"/>

# KEYHUNT

### Scan firmware blobs and filesystem dumps for hardcoded private keys, API tokens, default creds, and weak RSA/ECC material.

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Scan+firmware+blobs+and+filesystem+dumps+for+hardcoded+priva;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-keyhunt.svg?color=6b46c1)](https://pypi.org/project/cognis-keyhunt/) [![CI](https://github.com/cognis-digital/keyhunt/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/keyhunt/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*IoT / OT / Embedded — firmware, buses, and device security.*

</div>

```bash
pip install cognis-keyhunt
keyhunt scan .            # → prioritized findings in seconds
```

## Usage — step by step

1. **Install** the scanner:

   ```bash
   pip install cognis-keyhunt
   ```

2. **Scan a tree** (e.g. an extracted firmware image or filesystem dump) for hardcoded keys, tokens, and default creds:

   ```bash
   keyhunt scan /tmp/firmware_extracted
   ```

3. **Filter by severity** and emit JSON for CI or `jq`:

   ```bash
   keyhunt scan ./dump --severity high --format json | jq '.findings[] | select(.severity=="critical")'
   ```

4. **Read the result.** Secrets are redacted by default; pass `--show-secrets` to print full values. Exit code `0` = no findings, `1` = one or more secrets found, `2` = usage/runtime error.

5. **Gate a build.** keyhunt's exit code makes it a drop-in CI check:

   ```bash
   keyhunt scan ./build --severity high || { echo 'hardcoded secrets found'; exit 1; }
   ```

## Contents

- [Why keyhunt?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Output formats](#output-formats) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why keyhunt?

Instant gratification — point at any router firmware and get 'hardcoded root SSH key shared across 2M devices.' Universal hardcoded-cred findings are reliably front-page.

`keyhunt` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ 12 detectors — PEM private keys, AWS access/secret keys, Google API keys, GitHub & Slack tokens, JWTs, connection-URI passwords, `/etc/shadow` hashes, hardcoded passwords, generic high-entropy api/secret assignments, telnet/busybox default logins
- ✅ Secrets **redacted by default** (safe to paste into tickets/CI logs); `--show-secrets` to reveal
- ✅ Placeholder + entropy filtering keeps the false-positive rate low (see [`demos/10-clean-config`](demos/10-clean-config/))
- ✅ Output as `table`, `json`, or **SARIF 2.1.0**; `--out FILE`, `--severity`, and `--fail-on` for CI gating
- ✅ 9 real-world [demo scenarios](#demos), each verified by a test
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-keyhunt
keyhunt --version
keyhunt scan .                       # scan current project
keyhunt scan . --format json         # machine-readable
keyhunt scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ keyhunt scan demos/06-iot-router
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
input in keyhunt's real input format plus a `SCENARIO.md` that explains where
the data came from, what keyhunt reports, and how to remediate. Each one is
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
keyhunt scan demos/06-iot-router            # see the firmware findings
keyhunt scan demos/10-clean-config          # confirm a clean tree exits 0
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="output-formats"></a>
## Output formats & CI gating

```bash
keyhunt scan ./dump                                  # table (default)
keyhunt scan ./dump --format json                    # machine-readable
keyhunt scan ./dump --format sarif --out keyhunt.sarif   # SARIF 2.1.0 for code-scanning
keyhunt scan ./dump --severity high                  # only report high+ findings
keyhunt scan ./dump --fail-on high                   # exit 1 only on high+ (CI gate)
```

The SARIF output is a valid 2.1.0 log (one rule per detector, one result per
finding, secrets redacted) and uploads directly via
`github/codeql-action/upload-sarif`. `--fail-on` lets you report everything
while gating the build on a chosen severity; `--out` writes to a file instead
of stdout.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[keyhunt<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`keyhunt` is interoperable with every popular way of using AI:

- **MCP server** — `keyhunt mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `keyhunt scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis keyhunt** | trufflehog + EAPOL |
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

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`keyhunt mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/keyhunt.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/keyhunt.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/keyhunt.git" # uv
pip install cognis-keyhunt                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/keyhunt:latest --help        # Docker
brew install cognis-digital/tap/keyhunt                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/keyhunt/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/keyhunt` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

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

> ### ⭐ If `keyhunt` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>

## Bundled vulnerability database

Ships `keyhunt/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV across 7 ecosystems) with detailed metadata; offline stdlib loader `vulndb_local.VulnDB`, air-gap ready.
