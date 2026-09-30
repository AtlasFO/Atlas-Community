"""The case-specific identifier / IOC / PII scanner used at the public boundary.

Synthetic, documentation-range examples only — never real secrets (this file is
public code, same rule as identifiers.py itself).
"""

import pytest

from core.brain import identifiers, store

# (label, sample text, expected class). Synthetic, generic examples only.
_POSITIVE = [
    ("email", "contact user@example.com for access", "email"),
    ("ipv4", "block traffic to 203.0.113.9 now", "ipv4"),
    ("cisco_type8_hash", "secret $8$AbCdEf0123456789xyz stored", "cisco_type8_hash"),
    ("unix_crypt_hash", "hash $6$rounds$AbCdEf0123456789 seen", "unix_crypt_hash"),
    ("ldap_dn", "base uid=jdoe,ou=users,dc=example,dc=com found", "ldap_dn"),
    ("windows_hostname", "host WIN-AB12CD3 rebooted", "windows_hostname"),
    # Non-Windows host names must be flagged too, or an internal Linux host
    # name reaches a wiki/concepts candidate un-flagged.
    ("host_identifier_fused", "baseline check on xy1-srv1 found nothing new",
     "host_identifier"),
    ("host_identifier_padded", "pivoted to srv-db-03 over ssh",
     "host_identifier"),
    ("host_identifier_segments", "the app-server-02 box was rebuilt",
     "host_identifier"),
    ("internal_fqdn", "resolved web01.corp.local internally", "internal_fqdn"),
    ("internal_fqdn_single_label", "shipped logs to syslog01.internal",
     "internal_fqdn"),
    ("bitcoin_address", "pay bc1qw508d6qejxtdg4y5r3zarvary0c5xw7k address",
     "bitcoin_address"),
    ("sha256", "hash " + "a" * 64 + " matched", "sha256"),
]


@pytest.mark.parametrize("label,text,expected", _POSITIVE,
                         ids=[p[0] for p in _POSITIVE])
def test_scan_flags_each_class(label, text, expected):
    kinds = identifiers.kinds(text)
    assert expected in kinds, f"{label}: expected {expected}, got {kinds}"


@pytest.mark.parametrize("label,text,expected", _POSITIVE,
                         ids=[p[0] for p in _POSITIVE])
def test_redact_replaces_and_reports(label, text, expected):
    redacted, findings = identifiers.redact(text)
    assert findings, f"{label}: expected a finding"
    assert f"[REDACTED:{expected}]" in redacted
    # The raw value must not survive redaction (spot-check the distinctive token).
    for token in ("example.com", "203.0.113.9", "WIN-AB12CD3",
                  "bc1qw508", "jdoe", "xy1-srv1", "srv-db-03",
                  "app-server-02", "web01.corp.local", "syslog01.internal"):
        if token in text:
            assert token not in redacted


# The host patterns are a HARD block on the public-wiki boundary, so their
# precision is the thing worth testing. Every entry below is vocabulary that
# legitimately appears in a generalized wiki note; each one either tripped a
# draft of the pattern or guards a shape that nearly did.
_HOST_NEGATIVE = [
    # Artifact / file names — the classic Linux persistence artifact rc.local
    # matched an early draft of the internal-FQDN pattern.
    "check wtmp and btmp for login accounting gaps",
    "compare /etc/pam.d/system-auth against the package baseline",
    "persistence planted in rc.local survives reboot",
    "inspect /etc/rc.local and /etc/init.d before tiering",
    "parse $MFT and Security.evtx for the window",
    # Tool names and CLI flags.
    "evtx-dump fails on large Security.evtx; use evtxecmd instead",
    "ntfs-3g mounts read-only; bulk-extractor needs a scratch dir",
    "run with --no-brain and --show-redacted to preview",
    "mft-rule-hunt and vol.pslist disagree on the process list",
    # MITRE / CVE / standards vocabulary.
    "map the wipe to T1070.004 rather than T1059.001",
    "CVE-2031-0001 was hypothesized but never confirmed",
    "strings-grep is ASCII-only; UTF-16LE needs yara wide",
    "x86-64 payload, base64-wrapped, sha-256 verified",
    "TEST-NET-3 is the RFC 5737 documentation range",
    # Hyphenated English carrying a digit — the nastiest false-positive class.
    "at stage-2 the run had used 25-turn of its budget",
    "tier-1 findings in part-2 cover step-3 and rule-4",
    "the report contract is R1-R5 from section-7 of the guide",
    "an ad-hoc check of the top-5 findings",
    # The brain's own slug / run-id conventions.
    "staged as 2031-02-04-0900-case-a-train",
    "see case-a-workflow-retry-the-app-a1b2c3.md",
    "vendor-plc-protocol-function-code-forensics-0a1b2c",
    # Case ids already carried by approved public notes.
    "reviewed on CASE-A and CASE-E-COMPROMISE",
    "NITROBA-2008, SCHARDT-2002, MEMLABS-LAB2, M57-JEAN",
    # Dotted non-hosts.
    "host01.raw and hyperv.raw are the same host",
    "image.vmdk converted to raw; snapshot.db untouched",
]


@pytest.mark.parametrize("text", _HOST_NEGATIVE)
def test_host_patterns_spare_technical_vocabulary(text):
    """Generalized-note vocabulary must not trip the host patterns."""
    hits = [f.kind for f in identifiers.scan_text(text)
            if f.kind in ("host_identifier", "internal_fqdn")]
    assert hits == [], f"false positive {hits} on: {text!r}"


def test_committed_public_wiki_notes_are_clean():
    """Real-data regression: no committed public-wiki note may trip the gate.

    wiki/{concepts,techniques,tools,actors} is the only brain content that
    reaches the public GitHub remote. This is the same invariant the CI
    leak-gate enforces, asserted here so a pattern widening that would break
    the published tree fails fast in the unit suite.
    """
    root = store.brain_root()
    notes = [p for d in ("wiki/concepts", "wiki/techniques", "wiki/tools",
                         "wiki/actors")
             for p in sorted((root / d).glob("*.md"))]
    if not notes:
        pytest.skip("no public wiki notes in this checkout")
    offenders = []
    for note in notes:
        text = note.read_text(encoding="utf-8", errors="replace")
        for finding in identifiers.scan_text(text):
            offenders.append(f"{note.name}:{finding.line} [{finding.kind}]")
    assert offenders == [], (
        f"{len(offenders)} identifier hit(s) in the published wiki tree — "
        f"either a real leak to redact or a pattern to tune: {offenders[:10]}")


def test_clean_generalized_text_passes():
    text = ("Run a coverage report every run and re-tier findings that carry "
            "directly-captured evidence. Generalize before promoting.")
    assert identifiers.scan_text(text) == []
    assert identifiers.kinds(text) == []


def test_cli_scan_exit_codes(tmp_path, capsys):
    dirty = tmp_path / "dirty.md"
    dirty.write_text("auth as user@example.com from 10.1.2.3", encoding="utf-8")
    clean = tmp_path / "clean.md"
    clean.write_text("generalized lesson, no identifiers", encoding="utf-8")
    assert identifiers.main([str(clean)]) == 0
    assert identifiers.main([str(dirty)]) == 1
    err = capsys.readouterr().err
    # Reports the class + line, never the matched value.
    assert "email" in err and "ipv4" in err
    assert "user@example.com" not in err and "10.1.2.3" not in err
