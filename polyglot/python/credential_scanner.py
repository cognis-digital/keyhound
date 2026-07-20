#!/usr/bin/env python3
"""
polyglot/python/credential_scanner.py

Credential Scanner - Scans firmware blobs and filesystem dumps for hardcoded
private keys, API tokens, default creds, and weak RSA/ECC material.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, List, Optional, TextIO

# =============================================================================
# CONFIGURATION & CONSTANTS
# =============================================================================

DEFAULT_CHUNK_SIZE = 65536
MAX_LINE_LENGTH = 4096
MIN_RSA_MODULUS_BITS = 1024
WEAK_RSA_THRESHOLD_BITS = 512


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Finding:
    """Represents a single credential finding."""
    source: str
    offset: int
    severity: Severity
    category: str
    name: str
    value: str
    context: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.severity.name}] {self.category}: {self.name} in '{self.source}' @ {self.offset}"


@dataclass
class ScanResult:
    """Aggregated results from a scan."""
    findings: List[Finding] = field(default_factory=list)
    summary_stats: dict = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def get_by_category(self, category: str) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def get_severity_counts(self) -> dict:
        counts = defaultdict(int)
        for f in self.findings:
            counts[f.severity.name] += 1
        return dict(counts)


# =============================================================================
# PATTERN MATCHERS
# =============================================================================

class PatternMatcher:
    """Base class for pattern matchers."""

    def __init__(self, name: str):
        self.name = name

    def matches(self, text: str, offset: int) -> Optional[Finding]:
        raise NotImplementedError


class Base64Decoder:
    """Handles various base64 encoding variants."""

    @staticmethod
    def decode_variants(data: bytes) -> Iterator[bytes]:
        """Try to decode multiple base64 variants."""
        # Standard base64
        try:
            yield base64.b64decode(data, validate=True)
        except Exception:
            pass

        # URL-safe base64
        try:
            decoded = data.replace(b'-', b'+').replace(b'_', b'/')
            yield base64.b64decode(decoded, validate=True)
        except Exception:
            pass

        # Base64 with padding issues
        for pad in [b'', b'=', b'==']:
            try:
                padded = data.rstrip() + pad
                yield base64.b64decode(padded, validate=False)
            except Exception:
                continue


class KeyPatternMatcher(PatternMatcher):
    """Matches private key formats (PEM, DER, PKCS#8)."""

    def __init__(self):
        super().__init__("Private Key")
        self.pem_patterns = [
            re.compile(rb'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
            re.compile(rb'-----BEGIN PRIVATE KEY-----'),
            re.compile(rb'-----BEGIN RSA PRIVATE KEY-----'),
            re.compile(rb'-----BEGIN EC PRIVATE KEY-----'),
        ]

    def matches(self, text: str, offset: int) -> Optional[Finding]:
        for pattern in self.pem_patterns:
            match = pattern.search(text.encode())
            if match:
                key_type = match.group(1).decode().strip() or "PRIVATE"
                return Finding(
                    source=text[:200],
                    offset=offset,
                    severity=Severity.HIGH,
                    category="Private Key",
                    name=f"{key_type} Private Key (PEM)",
                    value=match.group(0).decode().strip(),
                    context=f"Found at offset {offset}",
                )

        # Check for DER format by magic bytes
        if text.startswith(b'-----BEGIN'):
            return None  # Already PEM, checked above

        # Look for common key headers in binary data
        headers = [
            b'SSv3',  # OpenSSH private key
            b'ssh-rsa',
            b'ssh-dss',
            b'ssh-ed25519',
            b'ecdsa-sha2-',
        ]

        for header in headers:
            if header in text.encode():
                return Finding(
                    source=text[:200],
                    offset=offset,
                    severity=Severity.HIGH,
                    category="Private Key",
                    name=f"OpenSSH {header.decode().strip()!r} Key (DER)",
                    value=header.decode(),
                    context=f"Found at offset {offset}",
                )

        return None


class TokenPatternMatcher(PatternMaker):
    """Matches common API tokens and secrets."""

    def __init__(self):
        super().__init__("API Token")
        self.token_patterns = [
            # GitHub Personal Access Tokens
            re.compile(rb'ghp_[A-Za-z0-9]{36}'),
            re.compile(rb'gho_[A-Za-z0-9]{36}'),
            re.compile(rb'ghu_[A-Za-z0-9]{36}'),

            # GitLab Personal Access Tokens
            re.compile(rb'glpat-[A-Za-z0-9_-]{20,40}'),

            # Slack tokens
            re.compile(rb'slsk_[A-Za-z0-9_/-]{38,50}'),

            # Generic JWT patterns (without proper header/claims)
            re.compile(rb'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),

            # AWS-style access keys
            re.compile(rb'(AKIA|ABIA|ACCA|ADAA|AEPA)[A-Z0-9]{16}'),

            # Generic API key patterns
            re.compile(r'api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
                       re.IGNORECASE),
        ]

    def matches(self, text: str, offset: int) -> Optional[Finding]:
        for pattern in self.token_patterns:
            match = pattern.search(text.encode())
            if match and len(match.group(1)) > 20:
                token_value = match.group(1).decode().strip()

                # Additional validation
                if self._is_valid_token(token_value):
                    return Finding(
                        source=text[:200],
                        offset=offset,
                        severity=Severity.CRITICAL,
                        category="API Token",
                        name=self._get_token_name(match.group(1)),
                        value=token_value,
                        context=f"Found at offset {offset}",
                    )

        return None

    def _is_valid_token(self, token: str) -> bool:
        """Basic validation to reduce false positives."""
        # Check for reasonable length
        if len(token) < 20 or len(token) > 100:
            return False

        # Check character composition
        alpha_ratio = sum(1 for c in token if c.isalpha()) / len(token)
        digit_ratio = sum(1 for c in token if c.isdigit()) / len(token)

        # Most tokens are alphanumeric with some special chars
        if 0.7 < alpha_ratio < 0.95 and 0.05 < digit_ratio < 0.4:
            return True

        return False

    def _get_token_name(self, token_bytes: bytes) -> str:
        """Try to identify the token type."""
        if b'ghp_' in token_bytes or b'gho_' in token_bytes or b'ghu_' in token_bytes:
            prefix = {b'ghp_': 'GitHub Personal', b'gho_': 'GitHub Org',
                      b'ghu_': 'GitHub User'}.get(token_bytes[:4], "GitHub")
            return f"{prefix} Access Token"

        if b'glpat-' in token_bytes:
            return "GitLab Personal Access Token"

        if b'slsk_' in token_bytes:
            return "Slack Token"

        if b'AKIA' in token_bytes or b'ABIA' in token_bytes:
            return "AWS Access Key ID"

        if b'eyJ' in token_bytes:
            try:
                header, _, _ = token_bytes.split(b'.', 2)
                decoded_header = base64.urlsafe_b64decode(header).decode()
                if 'github' in decoded_header.lower():
                    return "GitHub JWT Token"
            except Exception:
                pass

        return "Generic API Token"


class CredentialPatternMatcher(PatternMatcher):
    """Matches hardcoded credentials."""

    def __init__(self):
        super().__init__("Hardcoded Credential")
        self.credential_patterns = [
            # Common default passwords in various formats
            re.compile(r'(password|passwd|pwd)\s*[=:]\s*["\']?([A-Za-z0-9_@!$%^&]{4,})["\']?',
                       re.IGNORECASE),

            # Base64 encoded credentials
            re.compile(rb'(?i)(pass|secret|key|token)\s*[=:]\s*["\']?(?:[A-Za-z0-9+/=]{20,})["\']?'),

            # URL-encoded credentials (common in web apps)
            re.compile(r'(pass|secret|auth)\s*[=:]\s*%([A-Fa-f0-9]{40,})',
                       re.IGNORECASE),

            # Hex encoded credentials
            re.compile(r'(?i)(password|secret|key)\s*[=:]\s*0x?([0-9A-Fa-f]{32,64})'),

            # Common weak passwords (case-insensitive)
            re.compile(r'(?:default|admin|root|guest|test|demo|user|pass|1234|qwerty)'
                       r'\s*[=:]\s*["\']?(?i)(?:default|admin|root|guest|test|demo|user|'
                       r'password|1234|qwerty|letmein|welcome|monkey|dragon|master|login|'
                       r'abc123|shadow|sunshine|princess|michael|football|iloveyou|admin)'
                       r'["\']?', re.IGNORECASE),

            # Environment variable style credentials
            re.compile(r'(?:ENV|env)\s*\[\s*"(?i)(PASS|SECRET|KEY|TOKEN)"\s*=\s*["\']?'
                       r'([A-Za-z0-9_\-]{12,})["\']?', re.IGNORECASE),

            # Command-line style credentials
            re.compile(r'(?:--pass|--password|--secret|--key)\s*[=:]\s*["\']?([A-Za-z0-9_@!$%^&]{8,})'
                       r'["\']?', re.IGNORECASE),
        ]

    def matches(self, text: str, offset: int) -> Optional[Finding]:
        for pattern in self.credential_patterns:
            match = pattern.search(text.encode())
            if match and len(match.group(2)) > 8:
                cred_value = match.group(2).decode().strip()

                # Check if it's a weak password
                is_weak = self._is_weak_password(cred_value)

                severity = Severity.MEDIUM
                name = "Potential Hardcoded Password"

                if is_weak:
                    severity = Severity.HIGH
                    name = "Weak/Default Password"

                return Finding(
                    source=text[:200],
                    offset=offset,
                    severity=severity,
                    category="Hardcoded Credential",
                    name=name,
                    value=cred_value,
                    context=f"Found at offset {offset}",
                    metadata={"is_weak": is_weak},
                )

        return None

    def _is_weak_password(self, password: str) -> bool:
        """Check if password matches common weak patterns."""
        lower = password.lower()

        # Common weak passwords list (sample)
        weak_list = {
            'default', 'admin', 'root', 'guest', 'test', 'demo', 'user',
            'password', '1234', 'qwerty', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'login', 'abc123', 'shadow', 'sunshine',
            'princess', 'michael', 'football', 'iloveyou'
        }

        if lower in weak_list:
            return True

        # Check for simple patterns
        if len(password) < 8:
            return True

        # All same character
        if len(set(password)) == 1 and len(password) > 4:
            return True

        # Sequential characters
        seq_patterns = [
            'abc', 'bcd', 'cde', 'def', 'ghi', 'jkl', 'mno', 'pqr',
            'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz'
        ]

        for seq in seq_patterns:
            if seq in lower or seq[::-1] in lower:
                return True

        # Repeated characters
        import re as regex
        pattern = r'(.)\1{2,}'
        if regex.search(pattern, password):
            return True

        return False


class RSAWeaknessMatcher(PatternMatcher):
    """Detects weak RSA/ECC parameters."""

    def __init__(self):
        super().__init__("Weak Cryptographic Material")

    def matches(self, text: str, offset: int) -> Optional[Finding]:
        # Look for RSA modulus in hex or decimal
        hex_match = re.search(r'(?:rsa|modulus)\s*[=:]\s*0x?([0-9A-Fa-f]{128,})',
                             text.encode(), re.IGNORECASE)

        if hex_match:
            try:
                modulus_bytes = bytes.fromhex(hex_match.group(1))
                modulus_bits = len(modulus_bytes) * 8

                severity = Severity.LOW
                name = "RSA Modulus"

                if modulus_bits < MIN_RSA_MODULUS_BITS:
                    severity = Severity.MEDIUM
                    name = f"Small RSA Modulus ({modulus_bits} bits)"

                elif modulus_bits <= WEAK_RSA_THRESHOLD_BITS:
                    severity = Severity.HIGH
                    name = f"Weak RSA Modulus ({modulus_bits} bits, min {MIN_RSA_MODULUS_BITS})"

                return Finding(
                    source=text[:200],
                    offset=offset,
                    severity=severity,
                    category="Weak Cryptographic Material",
                    name=name,
                    value=f"{hex_match.group(1)[:64]}...",
                    context=f"Found at offset {offset}, {modulus_bits} bits",
                )

            except Exception:
                pass

        # Look for EC curve parameters
        ec_patterns = [
            re.compile(rb'(?i)(ec|elliptic)\s*curve\s*[=:]\s*(?:([A-Za-z0-9_\-]{1,32})|)'),
            re.compile(rb'?(?:x962|prime|secp)[A-Z]+(?:\d+)?'),
        ]

        for pattern in ec_patterns:
            match = pattern.search(text.encode())
            if match:
                curve_name = match.group(1).decode().strip() if match.lastindex >= 1 else "Unknown"

                # Known weak curves
                weak_curves = {
                    'secp521r1': (521, Severity.MEDIUM),
                    'secp384r1': (384, Severity.LOW),
                    'secp256r1': (256, Severity.INFO),  # NIST P-256
                    'prime192v1': (192, Severity.MEDIUM),
                }

                if curve_name.lower() in weak_curves:
                    bits, sev = weak_curves[curve_name.lower()]
                    return Finding(
                        source=text[:200],
                        offset=offset,
                        severity=sev,
                        category="Weak Cryptographic Material",
                        name=f"EC Curve {curve_name}",
                        value=curve_name,
                        context=f"Found at offset {offset}, {bits} bits",
                    )

        return None


class DefaultConfigMatcher(PatternMatcher):
    """Detects default configuration values."""

    def __init__(self):
        super().__init__("Default Configuration")

    def matches(self, text: str, offset: int) -> Optional[Finding]:
        defaults = [
            # Common database credentials
            (r'(?:mysql|postgres|redis)\s*user\s*[=:]\s*["\']?(root|admin|sa|master)["\']?',
             "Database User"),

            # Default API endpoints
            (r'(?i)(api[_-]?baseurl|endpoint)\s*[=:]\s*["\']?(/api/v1|/default|http://localhost:8080)["\']?',