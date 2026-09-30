"""misc.write_projected_final_report + current_investigation_state."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from core.claim_graph import add_claim
from core.execution_log import ExecutionLog
from core.incremental import plane_a_scan
from core.investigation_state import project_report_from_state


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "analysis").mkdir(parents=True)
    (case / "reports").mkdir(parents=True)
    (case / "CASE.md").write_text("**Case ID** StateTest\n", encoding="utf-8")
    (case / "evidence" / "a.txt").write_bytes(b"x")
    return case


def _ready_log(case: Path) -> ExecutionLog:
    l = ExecutionLog()
    l.configure("StateTest", str(case / "analysis" / "StateTest_trace.json"))
    l._case_dir = str(case)
    l.record_dair_call("Report", "", False, "", "", "stay", "")
    l.record_reason_call(
        "reason_pre_report_check", True,
        "READY_TO_REPORT: true\nBLOCKING_ISSUES (0): none", {},
    )
    return l


def _seed_timeline_claim(case: Path) -> None:
    (case / "analysis" / "master_timeline.tsv").write_text(
        "Timestamp\tMachine\tUser\tEvent\tSource\tDescription\tLine\tRecordRef\n"
        "2031-02-04T12:00:00Z\tSRV01\tAdministrator\tRDP Logon\t"
        "Security.evtx\tLogonType 10\t42\tSecurity.evtx:42:4624\n",
        encoding="utf-8",
    )
    add_claim(
        case,
        "Interactive RDP session as Administrator from 203.0.113.10",
        confidence="CONFIRMED",
        temporal_qualifier="first interactive session",
        host="SRV01",
        evidence=[{
            "artifact": "analysis/master_timeline.tsv",
            "locator": "record_ref=Security.evtx:42:4624",
        }],
    )


def test_current_investigation_state_tool(tmp_path: Path):
    from tools.misc import current_investigation_state

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Successful RDP logon as Administrator from 203.0.113.10",
        confidence="CONFIRMED",
        temporal_qualifier="first interactive session",
    )
    r = current_investigation_state(case_dir=str(case))
    assert r["success"]
    assert r["has_beliefs"] is True
    assert r["label"] == "Current Investigation State"


def test_write_projected_degraded_without_beliefs(tmp_path: Path):
    """Layer 4: empty CIS must still produce a partial exit artifact."""
    from tools.misc import write_projected_final_report

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    l = _ready_log(case)
    out = case / "reports" / "out.md"
    with patch("core.execution_log.log", l):
        r = write_projected_final_report(
            str(out),
            regenerate_stale=False,
            case_dir=str(case),
        )
    assert r["success"] is True, r
    assert r.get("degraded") is True
    assert r.get("reporting_model") == "investigation-driven-degraded"
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert "Timeline unavailable" in text or "Limitations" in text
    assert r.get("fallback") != "write_final_report"


def test_write_final_report_refuses_when_beliefs_exist(tmp_path: Path):
    from tools.misc import write_final_report

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    add_claim(
        case,
        "Interactive RDP session as Administrator",
        confidence="CONFIRMED",
        temporal_qualifier="first interactive session",
    )
    l = _ready_log(case)
    with patch("core.execution_log.log", l):
        r = write_final_report(
            str(case / "reports" / "freeform.md"),
            "# Freeform report\n\nInvented timeline.\n",
        )
    assert r["success"] is False
    assert r.get("gate") == "projection_required"
    assert r.get("redirect") == "misc.write_projected_final_report"
    assert r.get("alt_redirect") == "misc.write_case_document"
    assert "write_case_document" in (r.get("error") or "")


def test_write_projected_degraded_without_timeline_evidence(tmp_path: Path):
    """Layer 4: findings without timeline refs → degraded write, not hard-block."""
    from tools.misc import write_projected_final_report

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    # Claim without evidence refs → no Attack Timeline
    add_claim(
        case,
        "Interactive RDP session as Administrator",
        confidence="CONFIRMED",
        temporal_qualifier="first interactive session",
    )
    l = _ready_log(case)
    out = case / "reports" / "out.md"
    with patch("core.execution_log.log", l):
        r = write_projected_final_report(
            str(out),
            regenerate_stale=False,
            case_dir=str(case),
        )
    assert r["success"] is True, r
    assert r.get("degraded") is True
    assert r.get("reporting_model") == "investigation-driven-degraded"
    assert (r.get("projection") or {}).get("degraded") is True
    text = out.read_text(encoding="utf-8")
    assert "Timeline unavailable" in text
    assert "## Limitations" in text


def test_write_projected_uses_commit_gates(tmp_path: Path):
    from tools.misc import write_projected_final_report

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _seed_timeline_claim(case)

    def fake_gen(ctx, sec):
        return (
            f"## {ctx['title']}\n\n"
            "Interactive RDP session as Administrator observed.\n"
        )

    projected = project_report_from_state(
        case, regenerate_stale=True, generator=fake_gen,
    )
    assert projected["success"]

    l = _ready_log(case)
    out = case / "reports" / "StateTest_investigation_report.md"

    def fake_project(case_dir, **kwargs):
        return projected

    with patch("core.execution_log.log", l):
        with patch(
            "core.investigation_state.project_report_from_state",
            fake_project,
        ):
            r = write_projected_final_report(
                str(out), regenerate_stale=True, case_dir=str(case),
            )
            if not r.get("success") and r.get("gate") == "report_lint":
                r = write_projected_final_report(
                    str(out), regenerate_stale=True, case_dir=str(case),
                )

    assert r.get("success") is True, r
    assert r.get("reporting_model") == "investigation-driven"
    assert out.is_file()
    # The projected report (not the write_final_report fallback) was written.
    # Exact English wording on purpose: this is report_i18n's "projection_note"
    # under the default language, so a loose match would stop proving that the
    # projection path ran.
    text = out.read_text(encoding="utf-8")
    assert "Projection from Current Investigation State" in text
    # Either the seeded timeline rendered, or the raw-event fallback did.
    assert "Cited records" in text or "Attack Timeline" in text
    assert r.get("investigation_state_deliverable") or r.get("projection")


def test_estate_completeness_is_checked_before_sections_are_written(tmp_path: Path):
    """Missing per-host reports are known from the trace and the reports
    directory alone; the estate write must defer on them before it spends
    a model call per section on prose that is thrown away."""
    from tools.misc import write_projected_final_report

    case = _case(tmp_path)
    plane_a_scan(case, persist=True)
    _seed_timeline_claim(case)
    l = _ready_log(case)
    l.record_finding("finding on srv01", "LIKELY", source="x", host="srv01")
    out = case / "reports" / "estate_report.md"

    def no_projection(case_dir, **kwargs):
        raise AssertionError("sections were generated before the completeness check")

    with patch("core.execution_log.log", l):
        with patch("core.investigation_state.project_report_from_state",
                   no_projection):
            r = write_projected_final_report(str(out), case_dir=str(case))
    assert r["success"] is False
    assert r["gate"] == "report_lint"
    assert any("missing_per_host_reports" in w and "srv01" in w
               for w in r["lint_warnings"])
    assert not out.exists()


def test_section_calls_do_not_stale_the_pre_report_check(tmp_path: Path):
    """Every narrative section leaves a tool_call in the trace; a multi-host
    report cycle writes dozens of them after the pre-report check, and they
    are report work, not new evidence."""
    from tools.misc import PRE_REPORT_STALE_TOOL_CALLS, _pre_report_ready_gate

    case = _case(tmp_path)
    l = _ready_log(case)
    for i in range(PRE_REPORT_STALE_TOOL_CALLS + 1):
        l.record_tool_call(cmd="<py>:report_section:gaps", success=True,
                           truncated=False, retries=0, exit_code=0)
    with patch("core.execution_log.log", l):
        assert _pre_report_ready_gate() is None
