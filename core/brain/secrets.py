"""Secret-pattern detection and redaction for brain content.

Findings carry the pattern name and line number — never the matched value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{12,}\b")),
    ("slack_token", re.compile(r"\bxox[bpars]-[0-9A-Za-z-]{8,}")),
    ("github_token", re.compile(r"\b(?:ghp_|github_pat_)[0-9A-Za-z_]{16,}")),
    ("api_secret_key", re.compile(r"\bsk-[0-9A-Za-z_-]{16,}")),
    ("password_assignment", re.compile(r"(?i)\bpassword\s*=\s*\S+")),
    ("api_key_assignment", re.compile(r"(?i)\bapi_key\s*=\s*\S+")),
    ("access_token_assignment", re.compile(r"(?i)\baccess_token\s*=\s*\S+")),
    ("refresh_token_assignment", re.compile(r"(?i)\brefresh_token\s*=\s*\S+")),
    ("client_secret_assignment", re.compile(r"(?i)\bclient_secret\s*=\s*\S+")),
    # DFIR additions: patterns that show up in traces and reviewer text.
    ("bearer_token", re.compile(r"(?i)\bAuthorization:\s*Bearer\s+\S+")),
    ("net_use_password", re.compile(r"(?i)\bnet use\b[^\n]*/user:\S+\s+\S+")),
    ("cli_password_flag", re.compile(r"(?<=\s)-p\s+'[^']{4,}'")),
]


@dataclass
class SecretFinding:
    pattern: str
    line: int


def scan_text(text: str) -> list[SecretFinding]:
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in _PATTERNS:
            if pattern.search(line):
                findings.append(SecretFinding(pattern=name, line=lineno))
    return findings


def redact(text: str) -> tuple[str, list[SecretFinding]]:
    """Replace secret-like matches with [REDACTED:<pattern>] markers."""
    findings = scan_text(text)
    for name, pattern in _PATTERNS:
        text = pattern.sub(f"[REDACTED:{name}]", text)
    return text, findings
