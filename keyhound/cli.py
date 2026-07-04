"""KEYHOUND command-line interface.

Examples:
  # Scan an extracted firmware tree, human-readable table
  keyhound scan /tmp/firmware_extracted

  # Emit JSON for CI / piping into jq
  keyhound scan ./dump --format json | jq '.findings[] | select(.severity=="critical")'

  # Show full (unredacted) secrets - use with care
  keyhound scan ./dump --show-secrets

Exit codes:
  0  no findings
  1  one or more secrets found (use as a CI gate)
  2  usage / runtime error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Finding, scan_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Scan firmware / filesystem dumps for hardcoded keys, "
        "tokens, and default credentials.",
        epilog="Point it at a router firmware extraction and get hardcoded "
        "creds. Exit code 1 means secrets were found (CI-friendly).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default="table",
        help="output format (default: table)",
    )

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="scan a file or directory tree for secrets",
        description="Recursively scan a path for hardcoded secrets.",
    )
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default=None,
        help="output format (overrides global --format)",
    )
    scan.add_argument(
        "--severity",
        choices=("critical", "high", "medium", "low"),
        default="low",
        help="minimum severity to report (default: low = report everything)",
    )
    scan.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low"),
        default=None,
        help="exit non-zero only when a finding at or above this severity exists "
        "(default: any finding fails)",
    )
    scan.add_argument(
        "--out",
        metavar="FILE",
        default=None,
        help="write output to FILE instead of stdout (e.g. results.sarif)",
    )
    scan.add_argument(
        "--show-secrets",
        action="store_true",
        help="print full secret values instead of redacting them",
    )

    # --- vuln database (offline, bundled) ---------------------------------
    vdb = sub.add_parser(
        "vulndb",
        help="query the bundled offline vulnerability database (OSV, 262k records)",
        description="Look up CVEs/GHSAs or affected packages in the bundled, "
        "air-gap-ready OSV corpus. No network, no key.",
    )
    vdb.add_argument(
        "query",
        nargs="?",
        help="CVE/GHSA id (e.g. CVE-2021-44228), package name, or omit with --count",
    )
    vdb.add_argument("--package", metavar="NAME",
                     help="treat the query as a package name lookup")
    vdb.add_argument("--search", metavar="TEXT",
                     help="substring search over vulnerability summaries")
    vdb.add_argument("--count", action="store_true",
                     help="print the number of records in the bundled DB and exit")
    vdb.add_argument("--limit", type=int, default=20,
                     help="max records to print for searches (default: 20)")

    # --- edge / air-gap data feeds ----------------------------------------
    feeds = sub.add_parser(
        "feeds",
        help="list/refresh the keyless edge data-feed catalog (offline-capable)",
        description="Manage the bundled Cognis data-feed catalog (CISA KEV, EPSS, "
        "OSV, NVD, ATT&CK, OSCAL, abuse.ch ...). Fetches are explicit; --offline "
        "serves cache only and never touches the network.",
    )
    feeds.add_argument("action", choices=("list", "update", "get", "snapshot-export",
                                          "snapshot-import"),
                       help="catalog action")
    feeds.add_argument("args", nargs="*", help="feed ids or snapshot path")
    feeds.add_argument("--domain", default=None,
                       help="filter `list` by domain (vuln/threat-intel/compliance/...)")
    feeds.add_argument("--offline", action="store_true",
                       help="serve cache only; never reach the network")

    # --- MCP server (for AI agents) ---------------------------------------
    sub.add_parser(
        "mcp",
        help="run keyhound as an MCP stdio server (requires the 'mcp' extra)",
        description="Expose keyhound's scan() as an MCP tool for Claude Desktop, "
        "Cursor, or Cognis.Studio. Install with: pip install 'keyhound[mcp]'.",
    )
    return parser


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _filter_severity(findings: List[Finding], minimum: str) -> List[Finding]:
    cutoff = _SEV_RANK.get(minimum, 3)
    return [f for f in findings if _SEV_RANK.get(f.severity, 9) <= cutoff]


def _render_table(findings: List[Finding], show_secrets: bool) -> str:
    if not findings:
        return "No secrets found."
    lines = []
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        value = f.secret if show_secrets else f.redacted()
        loc = f"{f.path}:{f.line}:{f.column}"
        lines.append(
            f"[{f.severity.upper():8}] {f.detector:24} {loc}\n"
            f"             {f.description}\n"
            f"             secret: {value}"
        )
    summary_parts = [
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if s in counts
    ]
    header = f"Found {len(findings)} secret(s): " + ", ".join(summary_parts)
    return header + "\n\n" + "\n\n".join(lines)


def _render_json(findings: List[Finding], show_secrets: bool) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "count": len(findings),
        "findings": [f.to_dict(redact=not show_secrets) for f in findings],
    }
    return json.dumps(payload, indent=2)


# SARIF 2.1.0 maps keyhound severities onto the spec's "level" enum.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _render_sarif(findings: List[Finding], show_secrets: bool) -> str:
    """Render findings as a SARIF 2.1.0 log (github/codeql-action ingestible).

    One SARIF `rule` per detector that fired; one `result` per finding. Secrets
    are redacted in the message unless --show-secrets is set, so the SARIF file
    is safe to upload to code-scanning dashboards.
    """
    rules: dict = {}
    results: List[dict] = []
    for f in findings:
        if f.detector not in rules:
            rules[f.detector] = {
                "id": f.detector,
                "name": f.detector.replace("-", " ").title().replace(" ", ""),
                "shortDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity, "warning")
                },
                "properties": {"keyhound-severity": f.severity, "tags": ["security"]},
            }
        value = f.secret if show_secrets else f.redacted()
        results.append(
            {
                "ruleId": f.detector,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.description} (secret: {value})"},
                "properties": {"keyhound-severity": f.severity},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path.replace("\\", "/")},
                            "region": {
                                "startLine": max(f.line, 1),
                                "startColumn": max(f.column, 1),
                            },
                        }
                    }
                ],
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/cognis-digital/keyhound",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "scan":
        # subcommand --format overrides global; fall back to global default.
        fmt = args.format or "table"

        if not os.path.exists(args.path):
            print(f"{TOOL_NAME}: error: path not found: {args.path}", file=sys.stderr)
            return 2

        try:
            findings = scan_path(args.path)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
            return 2

        findings = _filter_severity(findings, args.severity)

        if fmt == "json":
            output = _render_json(findings, args.show_secrets)
        elif fmt == "sarif":
            output = _render_sarif(findings, args.show_secrets)
        else:
            output = _render_table(findings, args.show_secrets)

        if args.out:
            try:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(output + "\n")
            except OSError as exc:
                print(f"{TOOL_NAME}: error: cannot write {args.out}: {exc}",
                      file=sys.stderr)
                return 2
        else:
            print(output)

        # CI gate: --fail-on raises the bar; by default any finding fails.
        if args.fail_on:
            gating = _filter_severity(findings, args.fail_on)
            return 1 if gating else 0
        return 1 if findings else 0

    if args.command == "vulndb":
        return _run_vulndb(args)

    if args.command == "feeds":
        return _run_feeds(args)

    if args.command == "mcp":
        from .mcp_server import serve
        return serve()

    parser.print_help()
    return 2


def _run_vulndb(args) -> int:
    """Query the bundled offline vulnerability database. Stdlib only, no network."""
    try:
        from .vulndb_local import VulnDB
    except Exception as exc:  # pragma: no cover - defensive
        print(f"{TOOL_NAME}: error: vulndb unavailable: {exc}", file=sys.stderr)
        return 2
    db = VulnDB()
    if args.count:
        print(db.count())
        return 0
    if args.search:
        hits = db.search(args.search, limit=args.limit)
    elif args.package:
        hits = db.by_package(args.package)
    elif args.query:
        q = args.query
        # CVE/GHSA ids contain a dash + digits; otherwise treat as package.
        if q.upper().startswith(("CVE-", "GHSA-", "RUSTSEC-", "PYSEC-", "GO-")):
            hits = db.by_cve(q)
        else:
            hits = db.by_package(q) or db.by_cve(q)
    else:
        print(f"{TOOL_NAME}: error: provide a query, --package, --search, or --count",
              file=sys.stderr)
        return 2
    print(json.dumps({"query": args.query or args.package or args.search,
                      "count": len(hits),
                      "records": hits[: args.limit]}, indent=2))
    return 0 if hits else 1


def _run_feeds(args) -> int:
    """Drive the edge/air-gap data-feed ingester. All network access is explicit."""
    try:
        from . import datafeeds
    except Exception as exc:  # pragma: no cover - defensive
        print(f"{TOOL_NAME}: error: datafeeds unavailable: {exc}", file=sys.stderr)
        return 2
    action = args.action
    if action == "list":
        feeds = datafeeds.list_feeds(domain=args.domain)
        for f in feeds:
            age = datafeeds.cached_age_hours(f["id"])
            tag = f"[{age:.1f}h old]" if age is not None else "[uncached]"
            print(f"  {f['id']:30} {f.get('domain', ''):14} {tag:12} "
                  f"{f.get('name', f.get('description', ''))}")
        print(f"\n{len(feeds)} feed(s).  Refresh: keyhound feeds update <id> ; "
              f"offline serve: keyhound feeds get <id> --offline")
        return 0
    if action == "update":
        if not args.args:
            print(f"{TOOL_NAME}: error: feeds update needs one or more feed ids",
                  file=sys.stderr)
            return 2
        rc = 0
        for fid in args.args:
            try:
                datafeeds.update(fid)
                print(f"updated {fid}")
            except Exception as exc:
                print(f"{TOOL_NAME}: warn: {fid}: {exc}", file=sys.stderr)
                rc = 1
        return rc
    if action == "get":
        if not args.args:
            print(f"{TOOL_NAME}: error: feeds get needs a feed id", file=sys.stderr)
            return 2
        data = datafeeds.get(args.args[0], offline=args.offline)
        print(json.dumps(data, indent=2)[:8000] if isinstance(data, (dict, list))
              else str(data)[:8000])
        return 0
    if action == "snapshot-export":
        if not args.args:
            print(f"{TOOL_NAME}: error: snapshot-export needs a path", file=sys.stderr)
            return 2
        datafeeds.snapshot_export(args.args[0])
        print(f"exported feed cache to {args.args[0]}")
        return 0
    if action == "snapshot-import":
        if not args.args:
            print(f"{TOOL_NAME}: error: snapshot-import needs a path", file=sys.stderr)
            return 2
        datafeeds.snapshot_import(args.args[0])
        print(f"imported feed cache from {args.args[0]}")
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
