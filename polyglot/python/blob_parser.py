import os
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import BinaryIO, Dict, List, Optional, Tuple, Any


@dataclass
class FoundSecret:
    category: str
    value: str
    offset: int
    length: int
    context: str = ""

    def __str__(self) -> str:
        return f"[{self.category}] {self.value[:60]}{'...' if len(self.value) > 60 else ''} @ 0x{self.offset:x}"


class BlobParser:
    """Multi-format blob parser for secrets and crypto material extraction."""

    # Magic bytes for format detection
    MAGIC = {
        b'\x4d\x5a': ('PE32', 'Windows PE'),
        b'\x7f\x45\x4c\x46': ('ELF', 'Linux/Unix ELF'),
        b'\xca\xfe\xba\xbe': ('MACH_O_FAT', 'Fat Mach-O'),
        b'\xca\xfe\x00\x01': ('MACH_O_LITTLE', 'Little-endian Mach-O'),
        b'\xca\xfe\x02\x00': ('MACH_O_BIG', 'Big-endian Mach-O'),
    }

    # Common secret patterns (compiled for speed)
    PATTERNS = [
        # API Keys and Tokens
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{16,})', 'API Key'),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'Secret Key'),
        (r'(?i)(access[_-]?token|accesstoken)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{15,})', 'Access Token'),
        (r'(?i)(auth[_-]?token|authtoken)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'Auth Token'),
        
        # AWS/Azure/GCP Credentials
        (r'(AWS[Aa]WS[Aa]WS)?[Aa]ccessKeyId\s*[=:]\s*"([^"]+)"', 'AWS Access Key ID'),
        (r'(?i)(aws[_-]?secret)[Aa]ccessKey\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', 'AWS Secret Access Key'),
        (r'(Google)?[Gg]oogle[Aa]pp[Cc]lientId\s*[=:]\s*"([^"]+)"', 'GCP Client ID'),
        (r'(?i)(azure[_-]?client)[Cc]lientId\s*[=:]\s*["\']?([A-Za-z0-9_-]{32,})', 'Azure Client ID'),
        
        # OAuth/Session tokens
        (r'(?i)(oauth[_-]?token|oauth_token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{15,})', 'OAuth Token'),
        (r'(?i)(session[_-]?id|session_id)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'Session ID'),
        
        # Private keys in PEM format
        (rb'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key'),
        (rb'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key'),
        (rb'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key'),
        (rb'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key'),
        
        # Default/Weak credentials
        (r'(?i)(default[_-]?password|defaultpass)\s*[=:]\s*["\']?(\w{4,})', 'Default Password'),
        (r'(?i)(admin[_-]?password|admpass)\s*[=:]\s*["\']?(\w{4,})', 'Admin Password'),
        
        # Common weak passwords
        (r'(?i)password\s*[=:]\s*["\']?(123456|password|admin|root|master|guest)', 'Weak Password'),
    ]

    def __init__(self):
        self.secrets: List[FoundSecret] = []
        self.metadata: Dict[str, Any] = {}

    def parse(self, data: bytes) -> List[FoundSecret]:
        """Parse blob and return found secrets."""
        self.secrets.clear()
        
        # Detect format
        fmt_name, fmt_desc = self._detect_format(data[:16])
        if fmt_name:
            self.metadata['format'] = fmt_name
            self.metadata['description'] = fmt_desc
        
        # Extract strings
        strings = self._extract_strings(data)
        
        # Check for PEM keys (binary scan)
        pem_keys = self._find_pem_keys(data)
        
        # Scan string data against patterns
        for s in strings:
            for pattern, category in self.PATTERNS:
                if isinstance(pattern, bytes):
                    matches = re.finditer(pattern, s[1])  # (offset, content)
                else:
                    matches = re.finditer(pattern, s[1].decode('utf-8', errors='ignore'))
                
                for match in matches:
                    groups = match.groups()
                    value = groups[-1] if groups else match.group(0).strip()
                    
                    # Filter by minimum length
                    if len(value) < 8:
                        continue
                    
                    self.secrets.append(FoundSecret(
                        category=category,
                        value=value,
                        offset=s[0],
                        length=len(s[1]),
                        context=f"Format: {fmt_name or 'Unknown'}"
                    ))

        # Add PEM keys with proper offsets
        for key in pem_keys:
            self.secrets.append(FoundSecret(
                category='RSA/EC/DSA Private Key',
                value=key[:60],
                offset=key[1],
                length=len(key),
                context=f"Format: {fmt_name or 'Unknown'}"
            ))

        # Deduplicate and sort
        self.secrets = self._deduplicate()
        
        return self.secrets

    def _detect_format(self, header: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Detect file format from magic bytes."""
        for magic, (name, desc) in self.MAGIC.items():
            if header[:4] == magic:
                return name, desc
        return None, None

    def _extract_strings(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Extract printable strings from blob."""
        strings = []
        
        # ASCII strings (printable range 32-126)
        ascii_pattern = rb'[\x20-\x7e]{8,}'
        for match in re.finditer(ascii_pattern, data):
            s = match.group()
            if self._is_printable(s) and len(s) >= 8:
                strings.append((match.start(), s))
        
        # UTF-16 LE (common in Windows PE resources)
        utf16_pattern = rb'[\x00\x20-\x7e]{4,}'
        for match in re.finditer(utf16_pattern, data):
            s = match.group()
            if len(s) >= 8 and self._is_printable(s[:len(s)//2]):
                strings.append((match.start(), s))

        return strings

    def _is_printable(self, data: bytes) -> bool:
        """Check if string is mostly printable."""
        count = sum(1 for b in data if 32 <= b < 127)
        return count >= len(data) * 0.8

    def _find_pem_keys(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Find PEM-formatted private keys."""
        pem_markers = [
            (b'-----BEGIN RSA PRIVATE KEY-----', 27),
            (b'-----BEGIN EC PRIVATE KEY-----', 25),
            (b'-----BEGIN DSA PRIVATE KEY-----', 26),
            (b'-----BEGIN OPENSSH PRIVATE KEY-----', 38),
        ]
        
        results = []
        for marker, min_len in pem_markers:
            pos = data.find(marker)
            while pos != -1:
                end_pos = data.find(b'-----END', pos + len(marker))
                if end_pos == -1:
                    break
                
                # Check minimum key length (RSA keys are typically 274+ bytes)
                length = end_pos - pos
                if length >= min_len and length < 5000:
                    results.append((pos, data[pos:end_pos + 30]))
                
                pos = data.find(marker, pos + len(marker))
        
        return results

    def _deduplicate(self) -> List[FoundSecret]:
        """Remove near-duplicate secrets."""
        seen: Dict[str, int] = {}  # (category, value_hash) -> offset
        
        result = []
        for secret in self.secrets:
            key = (secret.category, hash(secret.value))
            
            if key not in seen or abs(seen[key] - secret.offset) > 100:
                result.append(secret)
                seen[key] = secret.offset
        
        # Sort by offset
        return sorted(result, key=lambda s: s.offset)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        if not self.secrets:
            return {'total': 0}
        
        by_category: Dict[str, int] = defaultdict(int)
        for s in self.secrets:
            by_category[s.category] += 1
        
        categories = dict(sorted(by_category.items()))
        
        # Check for critical findings
        critical = [s for s in self.secrets 
                   if 'Key' in s.category or 'Password' in s.category]
        
        return {
            'total': len(self.secrets),
            'critical': len(critical),
            'categories': categories,
            'format': self.metadata.get('format'),
        }


def main():
    """Demo entry point."""
    import sys
    
    parser = BlobParser()
    
    # Default: read from stdin if no args provided
    if not sys.argv[1:]:
        print("Reading from stdin...")
        data = sys.stdin.buffer.read()
    else:
        for path in sys.argv[1:]:
            print(f"\n{'='*60}")
            print(f"Scanning: {path}")
            print('='*60)
            
            with open(path, 'rb') as f:
                data = f.read()
            
            secrets = parser.parse(data)
            
            summary = parser.get_summary()
            fmt = summary.get('format', 'Unknown')
            
            print(f"Format: {fmt}")
            print(f"Total findings: {summary['total']}")
            print(f"Critical items: {summary['critical']}")
            
            if secrets:
                print("\n--- FOUND SECRETS ---")
                for s in secrets[:50]:  # Limit output
                    print(s)
                
                if len(secrets) > 50:
                    print(f"\n... and {len(secrets) - 50} more items")
            else:
                print("No secrets found.")


if __name__ == '__main__':
    main()