"""What a rerun may write: a context id that names no entry is refused before
anything is fingerprinted or written, a dry run writes nothing, and a rerun
that starts no session leaves the session beacon to the run that owns it."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest


def _case(tmp_path: Path, *, with_atlas: bool = True) -> Path:
    case = tmp_path / "CASE-A"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "auth.log").write_text(
        "2031-03-01T04:12:30Z CORP-WS01 sshd: accepted password for jane.doe from 10.0.0.15\n",
        encoding="utf-8")
    (case / "CASE.md").write_text(
        "**Case ID:** CASE-A\n\n## Investigation Requests\n\n- Who logged on to CORP-WS01?\n\n"
        "## What you already know\n\n- The workstation belongs to jane.doe.\n",
        encoding="utf-8")
    if with_atlas:
        from core.incremental import plane_a_scan
        plane_a_scan(case, persist=True)
        (case / ".atlas" / "run_status.json").write_text(json.dumps(
            {"stopped_reason": "closed_out", "finish_status": "complete"}), encoding="utf-8")
        (case / "reports").mkdir(exist_ok=True)
        (case / "reports" / "CASE-A_investigation_report.md").write_text("# report\n", encoding="utf-8")
    return case


def _tree(root: Path, *, lock_only_atlas: bool = False) -> dict:
    """Every path under ``root`` with its content hash or link target. The run
    lock is left out: taking it is what every rerun does first, and on a case
    without .atlas/ it is the only thing there."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            rel = str(p.relative_to(root))
            if rel == os.path.join(".atlas", "run.lock"):
                continue
            if lock_only_atlas and rel == ".atlas" and os.listdir(p) == ["run.lock"]:
                continue
            if p.is_symlink():
                out[rel] = "link:" + os.readlink(p)
            elif p.is_dir():
                out[rel] = "dir"
            else:
                out[rel] = (p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
    return out


# ── a context id that names no entry ─────────────────────────────────────────

def test_a_context_id_that_names_no_entry_changes_nothing(tmp_path, capsys):
    from agent import cli
    case = _case(tmp_path)
    before = _tree(case)
    with patch("core.evidence_catalog.scan_evidence",
               side_effect=AssertionError("the evidence was fingerprinted")), \
         pytest.raises(SystemExit) as ended:
        cli.main(["rerun", "--case", str(case), "--withdraw-context", "ac-0099", "--no-agent"])
    assert ended.value.code == 2
    assert "analyst context id not found: ac-0099" in capsys.readouterr().err
    assert _tree(case) == before
    assert not (case / "reports" / "initial_report").exists()


@pytest.mark.parametrize("argv", [
    ["--no-agent", "-L", "de", "--withdraw-context", "ac-0099"],
    ["--list-runs", "-L", "de"],
    ["--diff", "run-0001..run-0002", "-L", "de"],
])
def test_a_refused_or_read_only_rerun_writes_no_language(tmp_path, argv):
    from agent import cli
    case = _case(tmp_path)
    before = _tree(case)
    try:
        cli.main(["rerun", "--case", str(case), *argv])
    except SystemExit:
        pass
    assert _tree(case) == before
    assert not (case / ".atlas" / "case_config.json").exists()


def test_plane_a_refuses_an_unknown_context_id_before_it_scans(tmp_path):
    from core.incremental import plane_a_scan
    case = _case(tmp_path)
    with patch("core.incremental.scan_evidence",
               side_effect=AssertionError("the evidence was fingerprinted")):
        r = plane_a_scan(case, persist=True, correct_context_id="ac-0099",
                         analyst_feedback="The workstation belongs to john.roe.")
    assert r["success"] is False and "ac-0099" in r["error"]


def test_a_known_context_id_is_still_withdrawn(tmp_path):
    from core.analyst_context import list_context
    from core.incremental import plane_a_scan
    case = _case(tmp_path)
    entry = list_context(case, active_only=True)[0]
    r = plane_a_scan(case, persist=True, withdraw_context_id=entry["id"])
    assert r["success"] is True
    assert {e["id"]: e["status"] for e in list_context(case)}[entry["id"]] == "withdrawn"


# ── a dry run writes nothing ─────────────────────────────────────────────────

@pytest.mark.parametrize("with_atlas", [True, False])
def test_a_dry_run_writes_nothing(tmp_path, with_atlas):
    from agent import cli
    case = _case(tmp_path, with_atlas=with_atlas)
    before = _tree(case)
    cli.main(["rerun", "--case", str(case), "--dry-run", "-L", "de"])
    assert _tree(case, lock_only_atlas=not with_atlas) == before


def test_a_dry_plan_reads_the_evidence_links_without_writing_them(tmp_path):
    from core.incremental import plane_a_scan
    case = _case(tmp_path)
    links = case / ".atlas" / "evidence_links.json"
    links.unlink(missing_ok=True)
    plane_a_scan(case, persist=False)
    assert not links.exists()


# ── the session beacon ───────────────────────────────────────────────────────

def test_a_rerun_without_a_session_leaves_the_beacon_alone(tmp_path):
    import core.execution_log as elog
    from agent import cli
    case = _case(tmp_path)
    other = tmp_path / "CASE-B" / "analysis"
    other.mkdir(parents=True)
    (other / "CASE-B_trace.json").write_text('{"case_id": "CASE-B", "entries": []}', encoding="utf-8")
    beacon = json.dumps({"case_id": "CASE-B", "path": str(other / "CASE-B_trace.json")})
    Path(elog._SESSION_FILE).write_text(beacon, encoding="utf-8")
    for extra in (["--no-agent"], ["--assemble-report"]):
        try:
            cli.main(["rerun", "--case", str(case), *extra])
        except SystemExit:
            pass
        assert Path(elog._SESSION_FILE).read_text(encoding="utf-8") == beacon, extra


def test_review_picks_the_one_live_run_over_the_beacon(tmp_path, capsys):
    from agent import cli
    live = tmp_path / "CASE-B"
    live.mkdir()
    seen = {}

    def _resolve(case_dir, case_explicit):
        seen["case"], seen["explicit"] = Path(case_dir), case_explicit
        return None, ""

    with patch("core.run_state.live_runs", return_value=[str(live)]), \
         patch("agent.review.resolve_review_trace", _resolve), \
         pytest.raises(SystemExit):
        cli.main(["review", "--live"])
    assert seen == {"case": live, "explicit": True}
    assert f"reviewing the live run of {live}" in capsys.readouterr().err
