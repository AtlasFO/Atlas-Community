"""Claim Graph auth coverage gaps."""
from __future__ import annotations

from pathlib import Path

from core.auth_coverage import auth_success_coverage_gaps
from core.auth_observations import ingest_auth_observations_from_trace
from core.claim_graph import add_claim
from core.execution_log import log


def test_ingest_and_gap(tmp_path: Path):
    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / "CASE.md").write_text("auth\n")
    log.configure("AC", str(case / "analysis" / "t.json"), save_session=False)
    log._entries.clear()
    ip = "203.0.113.70"
    blob = (
        f'{{"level":"AUDIT_FAILURE","eventID":"4625","ipAddress":"{ip}",'
        f'"timestamp":"2031-02-04T00:00:00Z"}}\n'
        f'{{"level":"AUDIT_SUCCESS","eventID":"4624","ipAddress":"{ip}",'
        f'"logonType":"3","timestamp":"2031-02-04T12:00:00Z"}}'
    )
    log._entries.append({
        "type": "tool_call", "call_id": 1, "success": True,
        "mcp_tool": "ez_evtxecmd", "stdout_excerpt": blob,
    })
    ing = ingest_auth_observations_from_trace(case)
    assert ing["created_count"] >= 2
    gaps = auth_success_coverage_gaps(case)
    assert gaps["unreported_count"] == 1
    assert gaps["unreported"][0]["endpoint"] == ip

    add_claim(
        case,
        f"Successful network logon from {ip} on 2031-02-04",
        confidence="LIKELY",
        enforce_validation=False,
    )
    gaps2 = auth_success_coverage_gaps(case)
    assert gaps2["unreported_count"] == 0
