"""Tests for tools/coverage.py."""
import pytest


@pytest.fixture
def log(tmp_path):
    from core.execution_log import log as _log
    _log.configure("COV-TEST", str(tmp_path / "trace.json"))
    return _log


def _seed_finding(log, description, confidence="CONFIRMED",
                  validated_techniques=None):
    entry = {
        "call_id": log._next_id(),
        "type": "finding",
        "ts": "2031-02-04T12:00:00+00:00",
        "description": description,
        "confidence": confidence,
        "source": "test",
    }
    if validated_techniques is not None:
        entry["validated_techniques"] = validated_techniques
    log._entries.append(entry)
    log._index_version += 1


def test_coverage_empty_trace(log):
    from tools.coverage import coverage_report
    r = coverage_report()
    assert r["success"] is True
    assert r["checked"] == []
    assert r["found"] == []


def test_no_attack_findings_marks_breadth_not_applicable(log):
    """0/0 breadth on an ICS/memory-CTF case (no attack-shaped findings) must be
    flagged NOT APPLICABLE, so the reviewer doesn't misread it as a satisfied
    coverage target."""
    from tools.coverage import coverage_report
    _seed_finding(log, "budget.xlsx present in the recycle bin", confidence="LIKELY")
    log._flush()
    r = coverage_report()
    assert "NOT APPLICABLE" in r["summary"]


def test_attack_findings_do_not_get_not_applicable_note(log):
    from tools.coverage import coverage_report
    _seed_finding(log, "Used T1003.001 to dump LSASS")
    log._flush()
    r = coverage_report()
    assert "NOT APPLICABLE" not in r["summary"]


def test_coverage_categorises_tiers(log):
    from tools.coverage import coverage_report
    _seed_finding(log, "Used T1003.001 to dump LSASS")
    _seed_finding(log, "Saw T1059.001 powershell usage", confidence="LIKELY")
    _seed_finding(log, "Possibly T1027 obfuscation", confidence="SUSPECTED")
    log._flush()
    r = coverage_report()
    assert "T1003.001" in r["checked"]
    assert "T1003.001" in r["found"]
    assert "T1027" in r["checked"]
    # Breadth is tier-independent: an
    # honestly under-tiered run must not read as "no TTP coverage". The
    # summary still reports the CONFIRMED/LIKELY subset separately.
    assert "T1027" in r["found"]
    assert "on findings of any tier (2 on CONFIRMED/LIKELY)" in r["summary"]


def test_coverage_counts_stamped_validated_techniques(log):
    # Techniques attached via record_finding's mitre_techniques
    # channel (stamped as validated_techniques) must count, even when the
    # description carries no literal T-ID; otherwise such a run reports
    # "0 TTPs" although its findings carry techniques.
    from tools.coverage import coverage_report
    _seed_finding(
        log, "Attacker exploited the public-facing management API",
        confidence="LIKELY",
        validated_techniques=[{"technique_id": "T1190",
                               "name": "Exploit Public-Facing Application",
                               "tactic": "Initial Access"}])
    log._flush()
    r = coverage_report()
    assert "T1190" in r["checked"]
    assert "T1190" in r["found"]


def test_coverage_markdown_includes_summary(log):
    from tools.coverage import coverage_report
    _seed_finding(log, "T1003 credential dumping")
    log._flush()
    r = coverage_report()
    assert "Detection Coverage Report" in r["markdown"]
    assert "T1003" in r["markdown"]
