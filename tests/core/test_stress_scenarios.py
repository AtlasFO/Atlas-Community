"""Stress and hostile-input scenarios for the analysis pipeline.

Each scenario drives the deterministic pipeline (profile → inventory →
ledger → claims → report → questions → IOCs) on a synthetic case that is
unusual in one way, and asserts two things: nothing raises, and the output
is honest about what the case holds. Hosts, users and files are invented.
"""
import json
import os
import re
from pathlib import Path

import pytest

from core.claim_graph import add_claim, load_graph, save_graph, upsert_claim_from_finding
from core.coverage_ledger import build_coverage_ledger, coverage_stats, exit_block_reason
from core.evidence_catalog import iter_case_files
from core.evidence_inventory_gate import mark_inventory_complete
from core.evidence_profile import build_evidence_profile, ensure_evidence_profile
from core.ioc_catalog import build_catalog
from core.report_assemble import assemble_client_report
from dashboard.read_models import questions_projection


def _case(tmp_path: Path, name: str = "C") -> Path:
    case = tmp_path / name
    for d in (".atlas", "evidence", "analysis", "exports", "reports"):
        (case / d).mkdir(parents=True)
    (case / "CASE.md").write_text(
        "# Case\n\n**Case ID:** STRESS\n\n## Investigation Requests\n\n"
        "- What happened on the host?\n- Was data exfiltrated?\n")
    return case


def _pipeline(case: Path) -> dict:
    """Run every deterministic stage and return what each produced."""
    out = {}
    out["profile"] = ensure_evidence_profile(str(case), refresh=True)
    mark_inventory_complete(case, summary={"present_classes": out["profile"]["present_classes"]})
    out["ledger"] = build_coverage_ledger(case)
    out["exit_reason"] = exit_block_reason(case)
    out["report"] = assemble_client_report(case, report_scope="estate")
    out["questions"] = questions_projection(str(case))
    out["iocs"] = build_catalog(case)
    return out


# ── evidence sets nobody planned for ─────────────────────────────────────

def test_empty_case_is_honest_not_broken(tmp_path):
    case = _case(tmp_path)
    out = _pipeline(case)
    assert out["profile"]["present_classes"] == []
    assert out["ledger"]["meta"]["unit_count"] == 0
    assert "No investigation questions" not in out["report"]      # CASE.md has two
    assert out["iocs"]["total"] == 0


def test_single_delimited_log_is_a_full_case(tmp_path):
    case = _case(tmp_path)
    (case / "evidence" / "fw-2031-02-04.log").write_text(
        "num;date;time;orig;type;action;src;dst\n" +
        "\n".join(f"{i};4Feb2031;00:00:{i:02d};10.0.0.1;log;accept;10.0.0.{i};8.8.8.8"
                  for i in range(1, 200)))
    out = _pipeline(case)
    assert "tabular" in out["profile"]["present_classes"]
    assert any("fw-2031-02-04.log" in u["path"] for u in out["ledger"]["units"].values())


def test_zero_byte_and_header_only_evtx(tmp_path):
    case = _case(tmp_path)
    (case / "evidence" / "Security.evtx").write_bytes(b"")
    (case / "evidence" / "System.evtx").write_bytes(b"ElfFile\0" + b"\0" * 65528)
    out = _pipeline(case)
    assert "windows_eventlog" in out["profile"]["present_classes"]
    from core.artifact_value import looks_empty
    assert looks_empty("System.evtx", 65536)


def test_hostile_file_names_do_not_break_anything(tmp_path):
    case = _case(tmp_path)
    names = ["weird name with spaces.csv", "ünïcödé-日本.csv", "..hidden.csv",
             "a" * 200 + ".csv", "semi;colon|pipe.csv", "$MFT", "quote'\".csv"]
    for n in names:
        (case / "evidence" / n).write_text("a,b\n1,2\n")
    out = _pipeline(case)
    assert out["profile"]["file_count"] == len(names)
    assert out["ledger"]["meta"]["unit_count"] >= 1


def test_symlink_to_the_operating_system_is_not_evidence(tmp_path):
    """A case may point at evidence; it may not point at the machine."""
    case = _case(tmp_path)
    (case / "evidence" / "t.csv").write_text("a,b\n1,2\n")
    (case / "evidence" / "etc").symlink_to("/etc")
    (case / "evidence" / "root").symlink_to("/")
    (case / "evidence" / "self").symlink_to(case)
    (case / "evidence" / "parent").symlink_to(tmp_path)
    rels = [r for r, _ in iter_case_files(case)]
    assert rels == ["evidence/t.csv"], rels[:5]


def test_symlinked_evidence_outside_the_case_is_still_evidence(tmp_path):
    """…but a symlink to an attached collection is the normal way in."""
    case = _case(tmp_path)
    coll = tmp_path / "kape_collection" / "C" / "Windows"
    coll.mkdir(parents=True)
    (coll / "Security.evtx").write_bytes(b"ElfFile\0" * 64)
    (case / "evidence" / "HOST01").symlink_to(tmp_path / "kape_collection")
    rels = [r for r, _ in iter_case_files(case)]
    assert "evidence/HOST01/C/Windows/Security.evtx" in rels


# ── hostile content on the way to the report ─────────────────────────────

HOSTILE = ("Attacker ran evil.exe on HOST01 | <script>alert(1)</script> | "
           "**bold** \n## Injected heading\n- [x](javascript:alert(1)) "
           "on 2031-02-04 10:00:00.")


def test_hostile_claim_text_cannot_restructure_the_report(tmp_path):
    case = _case(tmp_path)
    r = upsert_claim_from_finding(case, statement=HOSTILE, confidence="LIKELY",
                                  host="HOST01")
    assert r["success"]
    out = _pipeline(case)
    md = out["report"]
    assert "\n## Injected heading" not in md          # no new section
    table = md.split("## 3. Key Findings", 1)[1].split("## 4.", 1)[0]
    row = [ln for ln in table.splitlines() if ln.startswith("| [F-001]")]
    assert row and len(re.split(r"(?<!\\)\|", row[0])) == 7     # cells intact, pipes escaped
    q = out["questions"]["questions"][0]["answer"]
    assert isinstance(q, dict)                       # projection survived


# ── malformed state ──────────────────────────────────────────────────────

def test_malformed_claim_graph_nodes_are_skipped(tmp_path):
    case = _case(tmp_path)
    add_claim(case, "Good claim on HOST01 at 2031-02-04 10:00:00.",
              confidence="LIKELY", enforce_validation=False)
    g = load_graph(case)
    g["nodes"]["C9990"] = None
    g["nodes"]["C9991"] = {"id": "C9991"}                       # no kind/statement
    g["nodes"]["C9992"] = {"id": "C9992", "kind": "claim", "statement": 42,
                           "confidence": "MAYBE", "status": "new"}
    g["nodes"]["C9993"] = "not a dict"
    save_graph(case, g)
    out = _pipeline(case)
    assert "F-001" in out["report"]
    assert out["iocs"]["schema_version"]


def test_task_store_with_unknown_status_and_missing_fields(tmp_path):
    case = _case(tmp_path)
    (case / ".atlas" / "investigation_tasks.json").write_text(json.dumps({
        "schema_version": "1.0", "case_id": "STRESS", "next_id": 3,
        "tasks": [{"id": "task-0001", "text": "Q1", "status": "bogus_status"},
                  {"id": "task-0002"}, "garbage", None]}))
    out = _pipeline(case)
    assert out["questions"]["total_visible"] >= 1
    assert "Answers to the Investigation Questions" in out["report"]


def test_three_hundred_findings_stay_bounded(tmp_path):
    case = _case(tmp_path)
    for i in range(300):
        add_claim(case, f"Event {4000 + i} on HOST{i % 7:02d} at 2031-02-04 "
                        f"{i % 24:02d}:{i % 60:02d}:00 involving user u{i}.",
                  confidence=("CONFIRMED", "LIKELY", "SUSPECTED")[i % 3],
                  enforce_validation=False)
    out = _pipeline(case)
    md = out["report"]
    assert md.count("\n### F-") == 300
    tl = md.split("## 5. Attack Timeline", 1)[1].split("## 6.", 1)[0]
    assert tl.count("\n| 20") <= 120                 # timeline cap holds
    assert len(md) < 2_000_000


def test_tools_refuse_input_paths_outside_the_case(tmp_path):
    """A tool reads the case's evidence; it is not a file browser."""
    from unittest.mock import MagicMock, patch
    from core.middleware import _find_outside_case_arg
    case = _case(tmp_path)
    (case / "evidence" / "a.csv").write_text("a,b\n1,2\n")
    stub = MagicMock(); stub.case_dir.return_value = str(case)
    with patch("core.execution_log.log", stub):
        assert _find_outside_case_arg("table_grep", {"path": "/etc/passwd"}) == "/etc/passwd"
        assert _find_outside_case_arg("table_grep", {"path": str(case / "evidence" / "a.csv")}) is None
        assert _find_outside_case_arg("table_grep", {"path": "evidence/a.csv"}) is None   # relative: resolved elsewhere
        assert _find_outside_case_arg("table_grep", {"path": "/nonexistent/x.csv"}) is None  # missing: discovery gate's job
        assert _find_outside_case_arg("misc_start_execution_log", {"output_path": "/etc/passwd"}) is None
