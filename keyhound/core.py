"""Core scanning engine for KEYHOUND.

No third-party imports. Works on raw firmware dumps, extracted filesystems,
config files, scripts, and binaries.

Design:
- A list of DETECTORS, each a compiled regex plus metadata (id, description,
  severity, and the regex group that holds the secret value).
- Detectors run on decoded text. Binary blobs are decoded latin-1 so byte
  offsets map to characters and printable runs are preserved.
- Findings carry enough context to triage (file, line, column, snippet) and
  redact the secret by default so output is safe to paste into tickets/CI logs.
- A lightweight entropy check reduces obvious false positives for the generic
  high-entropy token detector.
"""
from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable, Iterator, List, Optional

# ---------------------------------------------------------------------------
# Tool identity
# ---------------------------------------------------------------------------

TOOL_NAME = "keyhound"


def _read_version() -> str:
    """Read the version from the repo VERSION file, falling back to a default.

    Keeping the version in one place (the VERSION file) means the CLI banner,
    SARIF driver, JSON payload, and package metadata never drift apart.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, "VERSION"),
        os.path.join(os.path.dirname(here), "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                v = fh.read().strip()
            if v:
                return v
        except OSError:
            continue
    return "1.2.9"


TOOL_VERSION = _read_version()

# ---------------------------------------------------------------------------
# Detector definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Detector:
    id: str
    description: str
    severity: str  # "critical" | "high" | "medium" | "low"
    regex: re.Pattern
    secret_group: int = 0  # which capture group holds the sensitive value
    min_entropy: float = 0.0  # if > 0, secret_group value must exceed this


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Order matters only for readability; all detectors run on every chunk.
DETECTORS: List[Detector] = [
    Detector(
        id="private-key",
        description="PEM private key block",
        severity="critical",
        regex=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
    ),
    Detector(
        id="aws-access-key",
        description="AWS access key id",
        severity="critical",
        regex=re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16})\b"),
        secret_group=1,
    ),
    Detector(
        id="aws-secret-key",
        description="AWS secret access key",
        severity="critical",
        regex=re.compile(
            r"(?i)aws_?secret_?(?:access_?)?key\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9/+=]{40})"
        ),
        secret_group=1,
    ),
    Detector(
        id="gcp-api-key",
        description="Google API key",
        severity="high",
        regex=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        secret_group=1,
    ),
    Detector(
        id="github-token",
        description="GitHub personal access / app token",
        severity="critical",
        regex=re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255})\b"),
        secret_group=1,
    ),
    Detector(
        id="slack-token",
        description="Slack token",
        severity="high",
        regex=re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        secret_group=1,
    ),
    Detector(
        id="jwt",
        description="JSON Web Token",
        severity="medium",
        regex=re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
        ),
        secret_group=1,
    ),
    Detector(
        id="connection-uri-password",
        description="Credentials embedded in a connection URI",
        severity="high",
        regex=re.compile(
            r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s:/@]+)@[^\s/]+",
            re.IGNORECASE,
        ),
        secret_group=1,
    ),
    Detector(
        id="unix-shadow-hash",
        description="Hashed password in /etc/shadow style entry",
        severity="high",
        regex=re.compile(
            r"^([A-Za-z0-9_\-.]+):(\$[1256][aby]?\$[^:]+):",
            re.MULTILINE,
        ),
        secret_group=2,
    ),
    Detector(
        id="hardcoded-password",
        description="Hardcoded password assignment",
        severity="high",
        regex=re.compile(
            r"(?i)(?:^|[^A-Za-z0-9])(?:[a-z0-9]*_)?(?:passwd|password|pwd|pass)"
            r"\s*[:=]\s*['\"]([^'\"\n]{3,64})['\"]"
        ),
        secret_group=1,
    ),
    Detector(
        id="api-key-assignment",
        description="Generic api/secret/token assignment",
        severity="medium",
        regex=re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-./+=]{12,128})['\"]"
        ),
        secret_group=1,
        min_entropy=3.0,
    ),
    Detector(
        id="telnet-default-cred",
        description="Default/embedded telnet or busybox login",
        severity="high",
        # -l takes the login *program* (e.g. /bin/sh = direct root shell) or a name
        regex=re.compile(
            r"(?i)(?:telnetd|busybox)\b[^\n]*?-l\s+['\"]?([A-Za-z0-9_/.\-]{3,40})"
        ),
        secret_group=1,
    ),
]

# Placeholder values that are almost never real secrets - suppress them.
_PLACEHOLDERS = {
    "", "changeme", "password", "passwd", "example", "your_password",
    "xxxxxxxx", "none", "null", "undefined", "redacted", "********",
    "<password>", "yourpasswordhere", "placeholder",
}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    detector: str
    description: str
    severity: str
    path: str
    line: int
    column: int
    match: str  # the full matched text (may include surrounding key name)
    secret: str  # the extracted sensitive value

    def redacted(self) -> str:
        """Return the secret with the middle masked, keeping enough to verify."""
        s = self.secret
        if len(s) <= 8:
            return s[:1] + "*" * (len(s) - 1) if s else ""
        return f"{s[:4]}{'*' * (len(s) - 8)}{s[-4:]}"

    def to_dict(self, redact: bool = True) -> dict:
        d = asdict(self)
        if redact:
            d["secret"] = self.redacted()
            d.pop("match", None)
        return d


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

# Skip these file types entirely - they bloat scans and rarely hold creds.
_SKIP_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".ogg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".gz", ".xz", ".bz2", ".zip", ".7z", ".lz4",
}

DEFAULT_MAX_BYTES = 8 * 1024 * 1024  # 8 MiB per file


def _decode(data: bytes) -> str:
    """Decode bytes to text losslessly for offset math.

    latin-1 maps every byte 1:1 to a code point, so regex offsets equal byte
    offsets and printable ASCII inside binaries is preserved.
    """
    return data.decode("latin-1")


def _line_col(text: str, pos: int) -> tuple[int, int]:
    line = text.count("\n", 0, pos) + 1
    last_nl = text.rfind("\n", 0, pos)
    col = pos - last_nl  # 1-based column
    return line, col


def scan_bytes(data: bytes, path: str = "<bytes>") -> List[Finding]:
    """Run all detectors against a byte buffer. Returns a list of Finding."""
    text = _decode(data)
    findings: List[Finding] = []
    seen: set = set()
    for det in DETECTORS:
        for m in det.regex.finditer(text):
            secret = m.group(det.secret_group) if det.secret_group else m.group(0)
            secret = secret.strip()
            if secret.lower() in _PLACEHOLDERS:
                continue
            if det.min_entropy and _shannon_entropy(secret) < det.min_entropy:
                continue
            start = m.start(det.secret_group) if det.secret_group else m.start(0)
            line, col = _line_col(text, start)
            # Dedupe identical secret on the same line for the same detector.
            key = (det.id, path, line, secret)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector=det.id,
                    description=det.description,
                    severity=det.severity,
                    path=path,
                    line=line,
                    column=col,
                    match=m.group(0)[:200],
                    secret=secret,
                )
            )
    return findings


def scan_file(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> List[Finding]:
    """Scan a single file. Reads at most max_bytes."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except (OSError, IOError):
        return []
    return scan_bytes(data, path=path)


def iter_files(
    root: str,
    skip_ext: Optional[set] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Iterator[str]:
    """Yield candidate file paths under root (recursively).

    Skips known binary media types and oversized files. If root is a file,
    yields it directly.
    """
    skip_ext = _SKIP_EXT if skip_ext is None else skip_ext
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            ext = os.path.splitext(name)[1].lower()
            if ext in skip_ext:
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
            except OSError:
                continue
            yield full


def scan_path(
    root: str,
    skip_ext: Optional[set] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> List[Finding]:
    """Scan a file or directory tree and return all findings."""
    findings: List[Finding] = []
    for path in iter_files(root, skip_ext=skip_ext, max_bytes=max_bytes):
        findings.extend(scan_file(path, max_bytes=max_bytes))
    # Stable, useful ordering: severity then path then line.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (sev_rank.get(f.severity, 9), f.path, f.line))
    return findings


# ---------------------------------------------------------------------------
# Convenience API (used by the MCP server and downstream callers)
# ---------------------------------------------------------------------------


def scan(target: str, redact: bool = True) -> dict:
    """Scan a file/dir and return a JSON-serializable result dict.

    Mirrors the CLI JSON payload so the MCP tool and library callers share the
    exact shape the CLI emits. Secrets are redacted by default.
    """
    findings = scan_path(target)
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": target,
        "count": len(findings),
        "severity_counts": counts,
        "findings": [f.to_dict(redact=redact) for f in findings],
    }


def to_json(result: dict, indent: int = 2) -> str:
    """Serialize a scan() result (or any dict) to a JSON string."""
    return json.dumps(result, indent=indent)
