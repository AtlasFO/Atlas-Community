"""Tests for context budget + input scale gates."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_context_budget_compact_for_small_window(tmp_path, monkeypatch):
    from core import context_budget as cb

    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_TOKENS", "16000")
    monkeypatch.delenv("ATLAS_AGENT_CONTEXT_CHARS", raising=False)
    (tmp_path / "CASE.md").write_text("# Case\n- investigate RDP\n")
    (tmp_path / ".atlas").mkdir()
    snap = cb.compute(tmp_path, model="gpt-4.1-mini", persist=True)
    assert snap["window_tokens"] == 16000
    assert snap["detail_policy"] == "compact"
    assert snap["disk_first"] is True
    assert snap["max_bulk_dir_files"] >= 1
    assert (tmp_path / ".atlas" / "context_budget.json").is_file()


def test_input_scale_refuses_winevt_directory(tmp_path):
    from core.input_scale import check

    logs = tmp_path / "winevt" / "logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"x" * 1000)
    (logs / "System.evtx").write_bytes(b"x" * 1000)
    (logs / "Diagnostic.evtx").write_bytes(b"x" * 5000)
    refusal = check(
        "ez_ez_evtxecmd",
        {"evtx_path": str(logs), "output_dir": str(tmp_path / "out")},
        case_dir=str(tmp_path),
        available_tool_tokens=8000,
        max_dir_files=1,
    )
    assert refusal is not None
    assert refusal["gate"] in ("input_scale", "context_budget")
    assert refusal["shards"]
    # Security should rank at or near the top without focus text
    top = refusal["shards"][0]["path"]
    assert top.endswith("Security.evtx") or "Security" in top


def test_input_scale_allows_single_evtx(tmp_path):
    from core.input_scale import check

    f = tmp_path / "Security.evtx"
    f.write_bytes(b"x" * 1000)
    refusal = check(
        "ez_ez_evtxecmd",
        {"evtx_path": str(f), "output_dir": str(tmp_path / "out")},
        available_tool_tokens=50_000,
        max_dir_files=1,
    )
    assert refusal is None


def test_input_scale_huge_file_disk_first_not_refused(tmp_path):
    from core.input_scale import check, should_force_artifact_only

    f = tmp_path / "Security.evtx"
    f.write_bytes(b"x" * 5000)
    refusal = check(
        "ez_ez_evtxecmd",
        {"evtx_path": str(f), "output_dir": str(tmp_path / "out")},
        available_tool_tokens=100,  # tiny remaining room
        max_dir_files=1,
    )
    assert refusal is None
    assert should_force_artifact_only(
        "ez_ez_evtxecmd",
        {"evtx_path": str(f), "output_dir": str(tmp_path / "out")},
        available_tool_tokens=100,
    ) is True

    # Narrowing filter means no forced compact requirement
    assert should_force_artifact_only(
        "ez_ez_evtxecmd",
        {
            "evtx_path": str(f),
            "output_dir": str(tmp_path / "out"),
            "event_ids": "4624,4625",
        },
        available_tool_tokens=100,
    ) is False


def test_affinity_rdp_prefers_terminal_services(tmp_path):
    from core.input_scale import rank_shards

    d = tmp_path / "logs"
    d.mkdir()
    (d / "Security.evtx").write_bytes(b"a")
    (d / "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx").write_bytes(b"b")
    (d / "Diagnostic.evtx").write_bytes(b"c" * 100)
    shards = rank_shards(
        list(d.iterdir()),
        focus_text="Investigate RDP logons on the fileserver",
    )
    assert "TerminalServices" in shards[0]["path"]


def test_artifact_ready_compaction(tmp_path):
    from core.tool_result_view import compact_if_artifact_ready

    out = tmp_path / "evtx.csv"
    out.write_text(
        "TimeCreated,EventID,User\n"
        "2024-01-01T00:00:00,4624,alice\n"
        "2024-01-02T00:00:00,4625,bob\n"
    )
    data = {
        "success": True,
        "truncated": True,
        "stdout": "x" * 20_000,
        "output_dir": str(tmp_path),
        "output_file": "evtx.csv",
    }
    compact = compact_if_artifact_ready(data)
    assert compact is not None
    assert compact["gate"] == "artifact_ready"
    assert compact["artifact_paths"] == [str(out)]
    assert compact["stats"].get("profiles")


def test_artifact_ready_force_without_truncation(tmp_path):
    from core.tool_result_view import compact_if_artifact_ready

    out = tmp_path / "mft.csv"
    # Header only — no data rows, so normal compact skips; force still packs.
    out.write_text("Entry,Path\n")
    data = {
        "success": True,
        "truncated": False,
        "stdout": "ok",
        "csv_path": str(out),
    }
    assert compact_if_artifact_ready(data) is None
    forced = compact_if_artifact_ready(data, force=True)
    assert forced is not None
    assert forced["mode"] == "disk_first"


def test_artifact_ready_raw_disk_does_not_advertise_table(tmp_path):
    from core.tool_result_view import compact_if_artifact_ready

    raw = tmp_path / "host.raw"
    # Binary-ish payload with newlines — previously counted as "data rows".
    raw.write_bytes(b"\x00\x01\nNOT_A_CSV\n" + b"\xff" * 64)
    data = {
        "success": True,
        "truncated": False,
        "stdout": "converted",
        "output_path": str(raw),
        "note": "Next: tsk.mmls → tsk.fls",
        "recommended_next_tool": "tsk.mmls",
        "mount_plan_registered": True,
    }
    compact = compact_if_artifact_ready(data)
    assert compact is not None
    assert compact["gate"] == "artifact_ready"
    assert compact["recommended_next_tool"] == "tsk.mmls"
    assert "Do NOT query this path with table" in compact["summary"]
    assert "tsk.mmls" in compact["hint"]
    assert compact["stats"].get("artifact_kind") == "disk_media"


def test_coverage_tabular_windows(tmp_path):
    from core.coverage import plan_tabular_coverage, profile_tabular

    csv_path = tmp_path / "big.csv"
    rows = ["TimeCreated,EventID\n"]
    for i in range(5000):
        rows.append(f"2024-01-01T{i % 24:02d}:00:00,{4624 + (i % 3)}\n")
    csv_path.write_text("".join(rows))
    prof = profile_tabular(str(csv_path))
    assert prof["rows"] == 5000
    chunks = plan_tabular_coverage(str(csv_path), available_tool_tokens=4000)
    assert len(chunks) >= 2
    assert chunks[0]["tool_hint"] == "table.table_query"


def test_full_coverage_offered_when_dark(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_TOKENS", "32000")
    from core.investigation_tasks import save_tasks
    from core.investigation_plan import build_investigation_plan

    (tmp_path / ".atlas").mkdir()
    (tmp_path / "CASE.md").write_text("# Case\n- who logged in?\n")
    (tmp_path / "analysis").mkdir()
    (tmp_path / "analysis" / "Security.csv").write_text(
        "TimeCreated,EventID\n2024-01-01T00:00:00,4624\n"
        + "\n".join(f"2024-01-01T01:00:00,{i}" for i in range(3000))
        + "\n"
    )
    save_tasks(tmp_path, {
        "schema_version": "1.0",
        "case_id": tmp_path.name,
        "tasks": [{
            "id": "task-0001",
            "text": "who logged in?",
            "status": "open",
            "related_claim_ids": [],
        }],
    })
    plan = build_investigation_plan(
        tmp_path,
        plane_a_result={"case_id": tmp_path.name, "evidence_diff": {}},
        persist=True,
    )
    assert plan.get("coverage", {}).get("mode") == "full_coverage_last_resort"
    assert plan["coverage"]["chunks"]
    assert any(
        s.get("action") == "full_coverage_table_windows"
        for s in plan.get("steps") or []
    )

def test_classify_ignores_artifact_ready():
    from agent.tool_investigate import classify_tool_result

    payload = json.dumps({
        "success": True,
        "gate": "artifact_ready",
        "truncated": True,
        "artifact_paths": ["/tmp/x.csv"],
    })
    assert classify_tool_result("ez_ez_evtxecmd", payload) is None


def test_truncated_critical_exhausts():
    from agent.tool_investigate import (
        IDENTICAL_FAIL_LIMIT,
        merge_investigate_debt,
        finish_blocking_issues,
    )

    issue = {
        "tool": "ez_ez_evtxecmd",
        "kind": "truncated_critical",
        "summary": "ez_ez_evtxecmd truncated=true",
        "blocking_finish": True,
    }
    debt = []
    for _ in range(IDENTICAL_FAIL_LIMIT):
        debt = merge_investigate_debt(debt, [issue])
    assert debt[0].get("exhausted") is True
    assert finish_blocking_issues(debt) == []


def test_investigation_plan_includes_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_TOKENS", "32000")
    from core.investigation_tasks import save_tasks
    from core.investigation_plan import build_investigation_plan

    (tmp_path / ".atlas").mkdir()
    (tmp_path / "CASE.md").write_text(
        "# CASE-A\n\n## Investigation Requests\n"
        "- What RDP activity happened on FILESRV01?\n"
    )
    store = {
        "schema_version": "1.0",
        "case_id": tmp_path.name,
        "tasks": [{
            "id": "task-0001",
            "text": "What RDP activity happened on FILESRV01?",
            "status": "open",
            "related_claim_ids": [],
        }],
    }
    save_tasks(tmp_path, store)
    logs = tmp_path / "evidence" / "winevt" / "logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"x")
    (logs / "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx").write_bytes(b"y")

    plan = build_investigation_plan(
        tmp_path,
        plane_a_result={
            "case_id": tmp_path.name,
            "evidence_diff": {
                "added": [{"path": str(logs)}],
                "changed": [],
                "removed": [],
            },
        },
        persist=True,
    )
    assert plan.get("context_budget")
    assert "detail_policy" in plan["context_budget"]
    assert isinstance(plan.get("candidates"), list)
    assert plan.get("resources", {}).get("orchestrator") == (
        "investigation_resource_manager"
    )
    if plan["candidates"]:
        c0 = plan["candidates"][0]
        assert "tool_hint" in c0
        assert "score" in c0
        assert "capability_id" in c0


def test_orchestrator_persistence_prefers_registry_capability():
    from core.investigation_orchestrator import suggest_tools_for_path

    tools = suggest_tools_for_path(
        "/case/evidence/Windows/System32/config/SOFTWARE",
        focus_text="Investigate persistence via Run keys",
    )
    assert tools
    assert tools[0]["capability_id"] == "windows_registry_identity"


def test_orchestrator_rdp_evtx_prefers_event_logs():
    from core.investigation_orchestrator import score_candidate

    scored = score_candidate(
        path="/case/evidence/winevt/logs/Security.evtx",
        affinity=5.0,
        est_tokens=50_000,
        detail_level="artifact_only",
        tool_room=4_000,
        focus_text="Investigate RDP logons",
    )
    assert scored["capability_id"] == "windows_event_logs"
    assert scored["tool_hint"] == "ez.evtxecmd"
    assert scored["score"] > 0
    assert scored["cost_class"] == "high"


def test_scores_are_flat_and_llm_reorder():
    from core.investigation_orchestrator import (
        apply_llm_order,
        llm_refine_ranking,
        scores_are_flat,
    )
    from agent.llm import ChatResponse

    flat = [
        {"path": f"/a/{i}.evtx", "score": 10.0, "status": "ready",
         "tool_hint": "ez.evtxecmd", "capability_id": "windows_event_logs"}
        for i in range(4)
    ]
    assert scores_are_flat(flat) is True
    spread = [
        {"path": "/a/1.evtx", "score": 20.0, "status": "ready"},
        {"path": "/a/2.evtx", "score": 5.0, "status": "ready"},
    ]
    assert scores_are_flat(spread) is False

    reordered = apply_llm_order(flat, [2, 0, 1, 3])
    assert reordered[0]["path"].endswith("2.evtx")
    assert reordered[0]["ranking_source"] == "llm"

    class _FakeClient:
        def chat(self, messages, tools=None, max_tokens=256, temperature=0.0):
            return ChatResponse(content="[3,1,0,2]")

    refined = llm_refine_ranking(
        flat,
        focus_text="persistence",
        llm_client=_FakeClient(),
    )
    assert refined[0]["path"].endswith("3.evtx")


def test_refresh_orchestration_and_dirty(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_TOKENS", "32000")
    monkeypatch.setenv("ATLAS_ORCH_LLM_RANK", "off")
    from core.investigation_tasks import save_tasks
    from core.investigation_orchestrator import (
        is_state_dirty,
        mark_state_dirty,
        refresh_orchestration,
    )

    (tmp_path / ".atlas").mkdir()
    (tmp_path / "CASE.md").write_text("# Case\n- check auth\n")
    save_tasks(tmp_path, {
        "schema_version": "1.0",
        "case_id": tmp_path.name,
        "tasks": [{
            "id": "task-0001",
            "text": "check auth",
            "status": "open",
            "related_claim_ids": [],
        }],
    })
    # save_tasks marks dirty
    assert is_state_dirty(tmp_path) is True
    mark_state_dirty(tmp_path, reason="test")
    result = refresh_orchestration(
        tmp_path,
        turn=1,
        persist=True,
        llm_client=None,
    )
    assert result["plan"].get("schema_version")
    assert result["live"].get("ctx_policy")
    assert is_state_dirty(tmp_path) is False


def test_refresh_keeps_conversation_tokens(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_TOKENS", "32000")
    monkeypatch.setenv("ATLAS_ORCH_LLM_RANK", "off")
    from core.investigation_tasks import save_tasks
    from core.investigation_orchestrator import refresh_orchestration

    (tmp_path / ".atlas").mkdir()
    (tmp_path / "CASE.md").write_text("# Case\n- check auth\n")
    save_tasks(tmp_path, {
        "schema_version": "1.0",
        "case_id": tmp_path.name,
        "tasks": [{
            "id": "task-0001",
            "text": "check auth",
            "status": "open",
            "related_claim_ids": [],
        }],
    })
    messages = [
        {"role": "system", "content": "gates"},
        {"role": "user", "content": "x" * 4000},
    ]
    result = refresh_orchestration(
        tmp_path,
        messages=messages,
        turn=2,
        persist=True,
        llm_client=None,
    )
    budget = result["plan"].get("context_budget") or {}
    assert budget.get("conversation_included") is True
    assert int(budget.get("conversation_tokens") or 0) > 0


def test_small_window_disk_first_forces_artifact(tmp_path):
    from core.input_scale import should_force_artifact_only
    from core.llm_check import apply_session_window, reset_session

    apply_session_window(16_000)
    f = tmp_path / "Security.evtx"
    f.write_bytes(b"x" * 100)
    try:
        assert should_force_artifact_only(
            "ez_ez_evtxecmd",
            {
                "evtx_path": str(f),
                "output_dir": str(tmp_path / "out"),
                "event_ids": "4624,4625",
            },
            available_tool_tokens=50_000,
        ) is True
    finally:
        reset_session()


def test_a_detector_keeps_its_verdict_when_it_only_read_the_csv(tmp_path):
    """An analysis tool that reports the CSV it read is not a parser.

    ``csv_path`` means "file I wrote" in one tool and "file I read" in
    another, so a detector's answer — was the event log cleared? — was being
    replaced by "Parse/write succeeded; do NOT re-run this parser", and the
    model asked again and again without ever getting the verdict.
    """
    from core.tool_result_view import compact_if_artifact_ready

    csv = tmp_path / "ws_example_security.csv"
    csv.write_text("EventId,TimeCreated\n1102,2026-01-01 00:00:00\n",
                   encoding="utf-8")

    verdict = {
        "success": True,
        "data_source": "csv",
        "csv_path": str(csv),          # the input it READ
        "events_examined": 60000,
        "clear_events_found": 1,
        "events": [{"eid": 1102, "log": "Security"}],
    }
    assert compact_if_artifact_ready(verdict) is None, \
        "a small, complete verdict must reach the model intact"

    parser = {
        "success": True,
        "stdout": "parsed",
        "output_path": str(csv),       # a file it WROTE
    }
    compacted = compact_if_artifact_ready(parser)
    assert compacted is not None and compacted["gate"] == "artifact_ready"

    # Context protection is unchanged: a truncated payload still compacts,
    # whichever key names the artifact.
    truncated = dict(verdict, truncated=True)
    assert compact_if_artifact_ready(truncated) is not None
