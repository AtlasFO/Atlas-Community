"""Case-specific identifier / IOC / PII detection for the public boundary.

A companion to ``secrets.py``. Where ``secrets.py`` catches credential-shaped
material, this catches the *identifiers* that make a note case-specific and
therefore unsafe to publish to the public GitHub remote: customer infra
hostnames, IP addresses, password hashes, LDAP DNs, e-mail addresses, crypto
addresses, evidence file hashes, and workstation names.

Design rules that MUST hold — this file is PUBLIC code:
  * Patterns only, never literal secret values. Embedding a burned credential
    (or a customer id) here would itself leak it onto GitHub.
  * Findings carry the class name and line number, never the matched value.
  * Used by three enforcers that share this one definition: the approve() gate
    (``core/brain/approve.py``), the pre-push guard (``.githooks/pre-push``),
    and the CI leak-gate (``.github/workflows/ci.yml``). Scope those scanners
    to the *generalized* trees (brain/wiki, brain/indexes) — public case
    evidence legitimately contains IOCs and is excluded elsewhere.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Host identifiers of any OS convention.
#
# ``windows_hostname`` below only knows the WIN-/DESKTOP-/LAPTOP- convention,
# so a Linux/network host (``ab1-fw1``-shaped) would sail through the
# public-wiki gate. These two patterns close that gap, and they are tuned for
# PRECISION rather than recall: the gate they feed is a hard block, and a
# generalized wiki note is dense with hyphenated technical vocabulary (tool
# names, artifact names, MITRE IDs, CLI flags, hyphenated English) that must
# never trip it. Every knob below closes one class of false positive:
#   * a role segment is required — plain hyphenated English never matches;
#   * an English stop-word segment disqualifies the token (``the-app-c994c7``,
#     the brain's own candidate-slug convention);
#   * the digit must be *host-shaped* — fused into letters (``fw1``),
#     zero-padded (``-03``), or in a 3-segment name — because a bare trailing
#     number is far more often a port/count/section (``stage-2``, ``web-8080``);
#   * whole-token anchoring on ``[\w.-]`` keeps ISO dates, run-ids and
#     ``*.md`` slugs from matching a sub-span;
#   * ``test`` is deliberately NOT a role word (RFC 5737 ``TEST-NET-3``), and a
#     single-label internal FQDN needs 3+ chars (``/etc/rc.local``).
# Recall boundaries, accepted knowingly — each one is a shape whose only other
# reading is ordinary vocabulary, so a hard block cannot own it:
#   * a bare-numeric two-segment name (``host-1234``) — in a generalized note
#     that shape is nearly always a port, a count or an identifier;
#   * a single unhyphenated token (``websrv01``) — indistinguishable from a
#     variable or label without context;
#   * a digitless name (``srv-db-prod``) — the digit is the precision anchor
#     that keeps hyphenated English out.
# Widening any of these means re-running the corpus scan in
# ``test_committed_public_wiki_notes_are_clean``, not just adding a pattern.
# Role words that host names are commonly built from (vendor and service
# names included): a naming convention, not any environment's hosts.
_HOST_ROLE = (
    r"srv|server|host|vm|node|db|sql|web|www|app|api|dc|ldap|fw|gw|rtr|router"
    r"|switch|lb|proxy|vpn|bastion|jump|nas|san|esx|esxi|hv|hyperv|mail|smtp"
    r"|exch|dns|dhcp|ntp|ipa|pdc|bdc|wks|term|citrix|kube|k8s|ora|pg"
    r"|redis|elk|siem|bkp|backup|nfs|smb|edge|core|prod|stg|stage|dev|qa|uat"
)
# Hyphenated English that would otherwise ride in on a role word.
_HOST_STOP = (
    r"the|a|an|and|or|of|to|in|on|at|for|with|without|not|no|is|are|be|by"
    r"|from|via|per|vs|it|its|this|that|then|than|but|if|when|only|all"
    r"|any|each|both|into|over|under|after|before|first|last|new|old"
)
# Suffixes reserved for private/internal namespaces — never public DNS.
_INTERNAL_TLD = (
    r"local|internal|intranet|intra|corp|lan|localdomain|home|priv|private"
)
_SEG = r"[a-z0-9]{1,15}"
_END = r"(?:-|(?![\w.-]))"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?"

_HOST_IDENTIFIER = re.compile(
    r"(?<![\w.-])"
    r"(?=[a-z0-9-]{3,24}(?![\w.-]))"                        # bounded whole token
    rf"(?!(?:{_SEG}-)*(?:{_HOST_STOP}){_END})"              # not English prose
    rf"(?=(?:{_SEG}-)*(?:{_HOST_ROLE})\d{{0,3}}{_END})"     # carries a role
    r"(?="                                                  # host-shaped digit
    rf"(?:{_SEG}-)*[a-z]+\d[a-z0-9]*{_END}"                 #   fused:  fw1
    rf"|(?:{_SEG}-)*0\d+{_END}"                             #   padded: -03
    rf"|{_SEG}(?:-{_SEG}){{2}}(?![\w.-])"                   #   3 segments
    r")"
    r"(?=[a-z0-9-]*\d)"                                     # a digit at all
    rf"{_SEG}(?:-{_SEG}){{1,2}}"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_INTERNAL_FQDN = re.compile(
    r"(?<![\w.-])"
    r"(?:"
    rf"{_LABEL}(?:\.{_LABEL})+"        # 2+ labels: web01.corp.local
    r"|[a-z0-9]{3,}[a-z0-9-]*"         # 1 label, 3+ chars (spares rc.local)
    r")"
    rf"\.(?:{_INTERNAL_TLD})(?![\w.-])",
    re.IGNORECASE,
)

# Ordered so the most specific patterns match first; redact() applies them all.
# NOTE: patterns are GENERIC by design — no customer/site literals (hostnames,
# domains, org codes) live here, since this file is public. Site-specific
# strings belong in a private term list, never in the public scanner.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Directory / identity artifacts.
    ("ldap_dn", re.compile(
        r"\b(?:dc|ou|cn|uid)=[^,\s]+(?:\s*,\s*(?:dc|ou|cn|uid)=[^,\s]+)+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("windows_hostname",
     re.compile(r"\b(?:WIN|DESKTOP|LAPTOP)-[A-Z0-9]{2,}\b")),
    # Hosts of any other OS convention. internal_fqdn first: it spans the whole
    # dotted name, so redact() replaces srv-01.corp.local in one piece instead
    # of leaving a dangling suffix behind.
    ("internal_fqdn", _INTERNAL_FQDN),
    ("host_identifier", _HOST_IDENTIFIER),
    # Password hashes.
    ("cisco_type8_hash", re.compile(r"\$8\$[./A-Za-z0-9]{10,}")),
    ("unix_crypt_hash", re.compile(r"\$[1656]\$[^\s$]{4,}\$[./A-Za-z0-9]{10,}")),
    # File / evidence hashes (order: longest first so sha256 wins over md5).
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    # Crypto address.
    ("bitcoin_address", re.compile(r"\bbc1[ac-hj-np-z02-9]{20,}\b")),
    # Network address (kept last of the network group: broadest).
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]


@dataclass
class IdentifierFinding:
    kind: str
    line: int


def scan_text(text: str) -> list[IdentifierFinding]:
    """Return one finding per (class, line) — value is never captured."""
    findings: list[IdentifierFinding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in _PATTERNS:
            if pattern.search(line):
                findings.append(IdentifierFinding(kind=name, line=lineno))
    return findings


def redact(text: str) -> tuple[str, list[IdentifierFinding]]:
    """Replace each match with a ``[REDACTED:<class>]`` placeholder."""
    findings = scan_text(text)
    for name, pattern in _PATTERNS:
        text = pattern.sub(f"[REDACTED:{name}]", text)
    return text, findings


def kinds(text: str) -> list[str]:
    """Sorted, de-duplicated class names present in ``text``."""
    return sorted({f.kind for f in scan_text(text)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan files for case-specific identifiers/IOCs/PII. "
                    "Exit 1 if any file trips (for hooks/CI).")
    parser.add_argument("paths", nargs="+", help="files to scan")
    parser.add_argument("--scan", action="store_true",
                        help="accepted for symmetry; scanning is the default")
    args = parser.parse_args(argv)
    tripped = False
    for path in args.paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print(f"identifiers: cannot read {path}: {e}", file=sys.stderr)
            tripped = True
            continue
        found = scan_text(text)
        if found:
            tripped = True
            classes = ", ".join(sorted({f.kind for f in found}))
            lines = ", ".join(str(f.line) for f in found[:20])
            print(f"{path}: case-specific identifiers ({classes}) "
                  f"at line(s) {lines}", file=sys.stderr)
    return 1 if tripped else 0


if __name__ == "__main__":
    raise SystemExit(main())
