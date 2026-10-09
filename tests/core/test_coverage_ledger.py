"""Coverage ledger + exit floor."""
from __future__ import annotations

import json
from pathlib import Path

from core.coverage_ledger import (
    build_coverage_ledger,
    is_noise_path,
    load_ledger,
    mark_paths,
    ready_for_degraded_exit,
    coverage_stats,
)
from core import run_budget as rb
from core.run_budget import StallState, messages_for_turn


def test_an_integrity_hash_is_not_a_probe():
    """Hashing reads every byte to compare and examines nothing, and a call
    that only identifies an image (its partition table, its volume, its
    symbols) reads no file in it; only a tool that opens or parses the unit
    moves it off unseen, whichever spelling of its name the call carries."""
    from core.coverage_ledger import is_probe_tool
    assert not is_probe_tool("hash_verify_evidence_hash")
    assert not is_probe_tool("hash_hash_file")
    assert not is_probe_tool("misc_inventory_evidence")
    assert not is_probe_tool("strings_stat_file")
    for name in ("tsk_mmls", "tsk_tsk_mmls", "tsk.mmls", "<py>:tsk_tsk_mmls",
                 "tsk_mmstat", "tsk_fsstat", "vol_symbol_check"):
        assert not is_probe_tool(name), name
    assert is_probe_tool("tsk_tsk_fls")
    assert is_probe_tool("tsk_resolve_path")
    assert is_probe_tool("vol_netscan")
    assert is_probe_tool("table_table_query")


def test_unseen_units_of_one_kind(tmp_path: Path):
    from core.coverage_ledger import (CONTAINER_KIND, empty_ledger, save_ledger,
                                      unseen_container_units,
                                      unseen_unit_paths_of_kind)
    data = empty_ledger("c")
    data["units"] = {
        "a": {"path": "evidence/one.dd", "kind": CONTAINER_KIND, "status": "unseen"},
        "b": {"path": "evidence/two.dd", "kind": CONTAINER_KIND, "status": "probed"},
        "c": {"path": "evidence/log.csv", "kind": "tabular", "status": "unseen"},
    }
    save_ledger(tmp_path, data)
    assert unseen_unit_paths_of_kind(tmp_path, CONTAINER_KIND) == ["evidence/one.dd"]
    assert unseen_container_units(tmp_path) == ["evidence/one.dd"]
    assert unseen_container_units(None) == []


def test_the_ledger_labels_disk_images_as_containers(tmp_path: Path):
    """The director's disk guard reads the ledger's own label; a disk image
    taken in from the evidence profile must carry it."""
    from core.coverage_ledger import CONTAINER_KIND, build_coverage_ledger
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "host.vmdk").write_bytes(b"\x00" * 16)
    (case / ".atlas").mkdir()
    profile = {"schema_version": "1.0", "evidence_root": str(case / "evidence"),
               "present_classes": ["disk"],
               "files": [{"path": "evidence/host.vmdk", "class": "disk", "size": 16}]}
    (case / ".atlas" / "evidence_profile.json").write_text(json.dumps(profile), encoding="utf-8")
    ledger = build_coverage_ledger(case)
    kinds = {u.get("path"): u.get("kind") for u in (ledger.get("units") or {}).values()}
    assert kinds.get("evidence/host.vmdk") == CONTAINER_KIND, kinds


def test_a_split_image_is_one_container_unit(tmp_path: Path):
    """The segments of a split image are read through the first one; a
    unit per segment stayed unseen after the set was opened."""
    from core.coverage_ledger import (CONTAINER_KIND, build_coverage_ledger,
                                      coverage_stats, mark_paths)
    case = tmp_path / "case"
    (case / "evidence" / "host").mkdir(parents=True)
    names = ["host.E01", "host.E02", "host.E03", "host.e04", "host.Ex05"]
    for n in names:
        (case / "evidence" / "host" / n).write_bytes(b"\x00" * 16)
    (case / ".atlas").mkdir()
    profile = {"schema_version": "1.0", "evidence_root": str(case / "evidence"),
               "present_classes": ["disk"],
               "files": [{"path": f"evidence/host/{n}", "class": "disk", "size": 16}
                         for n in names]}
    (case / ".atlas" / "evidence_profile.json").write_text(json.dumps(profile), encoding="utf-8")
    ledger = build_coverage_ledger(case)
    containers = sorted(u["path"] for u in ledger["units"].values()
                        if u.get("kind") == CONTAINER_KIND)
    assert containers == ["evidence/host/host.E01"], containers
    mark_paths(case, ["evidence/host/host.E01"])
    assert coverage_stats(mark_paths(case, []))["unseen"] == 0


def test_noise_path_filter():
    assert is_noise_path(
        "evidence/modules/Collect/tools_temp_dir/foo/bar.js")
    assert is_noise_path("evidence/x/node_modules/pkg/index.js")
    assert is_noise_path("evidence/foo.csv:Zone.Identifier")
    assert not is_noise_path("evidence/edr_lateral_20310205.csv")
    assert not is_noise_path(
        "evidence/raw_extract/host/Windows/System32/winevt/logs/Security.evtx")


def test_ledger_build_and_exit_floor(tmp_path: Path):
    case = tmp_path / "CaseA"
    evid = case / "evidence"
    evid.mkdir(parents=True)
    (case / ".atlas").mkdir()
    (evid / "edr_lateral.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (evid / "vpn_logons.csv").write_text("u,t\n", encoding="utf-8")
    # junk that must not become a unit
    junk = evid / "modules" / "Collect" / "tools_temp_dir" / "x"
    junk.mkdir(parents=True)
    (junk / "log.js").write_text("x", encoding="utf-8")

    # inventory stamp required for ready_for_degraded_exit
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {
            "high_value_parsed": [
                "evidence/edr_lateral.csv",
                "evidence/vpn_logons.csv",
            ],
            "already_processed_count": 2,
        }}),
        encoding="utf-8",
    )
    # minimal profile so builder can also scan
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "schema_version": "1.0",
            "files": [
                {"path": "evidence/edr_lateral.csv", "class": "tabular"},
                {"path": "evidence/vpn_logons.csv", "class": "tabular"},
            ],
            "file_count": 2,
            "counts": {"tabular": 2},
            "absent_classes": ["disk", "memory"],
            "present_classes": ["tabular"],
            "samples": {},
        }),
        encoding="utf-8",
    )

    ledger = build_coverage_ledger(case)
    assert ledger["units"]
    for u in ledger["units"].values():
        assert "tools_temp_dir" not in u["path"]
        assert "node_modules" not in u["path"]
    assert not ready_for_degraded_exit(case)

    paths = [u["path"] for u in ledger["units"].values()]
    mark_paths(case, paths, status="probed")
    # still unseen? probed counts as covered for exit floor
    assert ready_for_degraded_exit(case)
    stats = coverage_stats(load_ledger(case))
    assert stats["unseen"] == 0
    assert stats["probed"] + stats["answered"] + stats["blocked"] == stats["total"]


def test_force_report_blocked_when_ledger_open(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(rb, "STALL_SOFT_TURNS", 2)
    monkeypatch.setattr(rb, "STALL_HARD_TURNS", 3)
    monkeypatch.setattr(rb, "STALL_FORCE_REPORT_GRACE", 1)
    monkeypatch.setattr(rb, "TURN_ADVISORY", 0)

    case = tmp_path / "CaseB"
    (case / "evidence").mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / "evidence" / "vpn_auth.csv").write_text("x\n", encoding="utf-8")
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {
            "high_value_parsed": ["evidence/vpn_auth.csv"],
        }}),
        encoding="utf-8",
    )
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "files": [{"path": "evidence/vpn_auth.csv", "class": "tabular"}],
            "file_count": 1, "counts": {"tabular": 1},
            "absent_classes": [], "present_classes": ["tabular"], "samples": {},
        }),
        encoding="utf-8",
    )
    build_coverage_ledger(case)

    state = StallState(no_progress_streak=5, hard_injected=True)
    msgs = messages_for_turn(
        state, turn=20, report_written=False, case_dir=case)
    assert any("coverage-redirect" in m["content"] for m in msgs)
    assert not any("[stall force-report]" in m["content"] for m in msgs)
    assert not state.force_report_injected
    assert not state.allow_synthesize_escape

    # After probing, force-report allowed
    mark_paths(case, ["evidence/vpn_auth.csv"], status="probed")
    state2 = StallState(no_progress_streak=5, hard_injected=True)
    msgs2 = messages_for_turn(
        state2, turn=21, report_written=False, case_dir=case)
    assert any("[stall force-report]" in m["content"] for m in msgs2)
    assert state2.allow_synthesize_escape


# ──: coverage integrity ────────────────────────────────────

def _two_host_case(tmp_path: Path) -> Path:
    """Case with canonical Security.evtx on TWO hosts + inventory stamp."""
    case = tmp_path / "CaseMulti"
    for host in ("WS01", "WS02"):
        logs = (case / "evidence" / host / "Windows" / "System32"
                / "winevt" / "Logs")
        logs.mkdir(parents=True)
        (logs / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    (case / ".atlas").mkdir()
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({
            "files": [], "file_count": 0, "counts": {},
            "absent_classes": [], "present_classes": [], "samples": {},
        }),
        encoding="utf-8",
    )
    return case


def test_multi_host_evtx_floor(tmp_path: Path):
    """EVERY host's canonical EVTX is a floor unit — not just the first tree."""
    case = _two_host_case(tmp_path)
    ledger = build_coverage_ledger(case)
    paths = {u["path"] for u in ledger["units"].values()}
    assert any("WS01" in p for p in paths), paths
    assert any("WS02" in p for p in paths), paths


def test_mark_paths_no_basename_crosstalk(tmp_path: Path):
    """Probing WS01's Security.evtx must NOT mark WS02's identically named
    file — bare-basename matching forged multi-host coverage."""
    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)
    mark_paths(
        case,
        ["evidence/WS01/Windows/System32/winevt/Logs/Security.evtx"],
        status="probed",
    )
    ledger = load_ledger(case)
    by_path = {u["path"]: u["status"] for u in ledger["units"].values()}
    ws01 = [s for p, s in by_path.items() if "WS01" in p and "Security" in p]
    ws02 = [s for p, s in by_path.items() if "WS02" in p and "Security" in p]
    assert ws01 == ["probed"], by_path
    assert ws02 == ["unseen"], by_path
    assert not ready_for_degraded_exit(case)


def test_mark_paths_absolute_input_matches_exact_unit(tmp_path: Path):
    """Absolute tool-arg paths still resolve to the exact unit."""
    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)
    abs_path = str(
        case / "evidence" / "WS02" / "Windows" / "System32"
        / "winevt" / "Logs" / "Security.evtx")
    mark_paths(case, [abs_path], status="probed")
    by_path = {u["path"]: u["status"]
               for u in load_ledger(case)["units"].values()}
    assert by_path[
        "evidence/WS02/Windows/System32/winevt/Logs/Security.evtx"] == "probed"
    assert by_path[
        "evidence/WS01/Windows/System32/winevt/Logs/Security.evtx"] == "unseen"


def test_observe_tool_paths_ignores_discovery_tools(tmp_path: Path):
    """Listing/inventory tools never mark coverage — a directory listing that
    mentions Security.evtx is not a probe (forged-floor regression)."""
    from core.coverage_ledger import observe_tool_paths
    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)
    observe_tool_paths(
        case,
        tool_name="misc_list_evidence_dir",
        cmd_or_args=(
            '{"path": "evidence/WS01/Windows/System32/winevt/Logs"} '
            "evidence/WS01/Windows/System32/winevt/Logs/Security.evtx"),
        success=True,
    )
    stats = coverage_stats(load_ledger(case))
    assert stats["probed"] == 0
    assert not ready_for_degraded_exit(case)


def test_observe_tool_paths_marks_from_real_tool_args(tmp_path: Path):
    from core.coverage_ledger import observe_tool_paths
    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)
    observe_tool_paths(
        case,
        tool_name="ez_evtxecmd",
        cmd_or_args=(
            '{"file_path": "evidence/WS01/Windows/System32/winevt/Logs/'
            'Security.evtx"}'),
        success=True,
    )
    by_path = {u["path"]: u["status"]
               for u in load_ledger(case)["units"].values()}
    assert by_path[
        "evidence/WS01/Windows/System32/winevt/Logs/Security.evtx"] == "probed"
    assert by_path[
        "evidence/WS02/Windows/System32/winevt/Logs/Security.evtx"] == "unseen"


def test_observe_skips_table_unknown_columns(tmp_path: Path):
    """Wrong-column table_query must not forge coverage probes."""
    from core.coverage_ledger import observe_tool_paths, build_coverage_ledger
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    csv = ev / "edr_user01.csv"
    csv.write_text("Timestamp,DeviceName\n2031-02-05,host\n", encoding="utf-8")
    (case / "CASE.md").write_text("# c\n", encoding="utf-8")
    # Build a ledger that includes the CSV if the builder picks it up;
    # otherwise mark_paths still exercises the contact gate.
    try:
        build_coverage_ledger(case)
    except Exception:
        pass
    observe_tool_paths(
        case,
        tool_name="table_table_query",
        cmd_or_args='{"path": "evidence/edr_user01.csv"}',
        success=True,
        result_text=(
            '{"success": false, "gate": "unknown_columns", '
            '"error": "Unknown column(s)"}'
        ),
    )
    # Even if unit exists, it must stay unseen
    from core.coverage_ledger import load_ledger
    led = load_ledger(case)
    units = led.get("units") or {}
    for u in (units.values() if isinstance(units, dict) else units):
        if "edr_user01" in str(u.get("path") or ""):
            assert u.get("status") == "unseen"


def test_observe_table_valid_zero_does_not_probe(tmp_path: Path):
    """Zero-match filtered queries must not forge coverage probes (X8)."""
    from core.coverage_ledger import (
        observe_tool_paths, build_coverage_ledger, load_ledger, mark_paths,
    )
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    csv = ev / "events.csv"
    csv.write_text("user,host\na,b\n", encoding="utf-8")
    build_coverage_ledger(case)
    mark_paths(case, ["evidence/events.csv"], status="unseen")
    observe_tool_paths(
        case,
        tool_name="table_table_query",
        cmd_or_args='{"path": "evidence/events.csv"}',
        success=True,
        result_text='{"success": true, "matched_rows": 0, "valid_zero": true}',
    )
    by_path = {u["path"]: u["status"]
               for u in load_ledger(case)["units"].values()}
    assert by_path.get("evidence/events.csv") == "unseen"


def test_observe_table_valid_contact_probes(tmp_path: Path):
    from core.coverage_ledger import (
        observe_tool_paths, build_coverage_ledger, load_ledger, mark_paths,
    )
    case = tmp_path / "case"
    ev = case / "evidence"
    ev.mkdir(parents=True)
    csv = ev / "events.csv"
    csv.write_text("user,host\na,b\n", encoding="utf-8")
    build_coverage_ledger(case)
    # Ensure unit exists even if builder heuristics skip small CSVs
    mark_paths(case, ["evidence/events.csv"], status="unseen")
    observe_tool_paths(
        case,
        tool_name="table_table_query",
        cmd_or_args='{"path": "evidence/events.csv"}',
        success=True,
        result_text='{"success": true, "matched_rows": 2, "valid_zero": false}',
    )
    by_path = {u["path"]: u["status"]
               for u in load_ledger(case)["units"].values()}
    assert by_path.get("evidence/events.csv") == "probed"


def test_mark_unit_blocked_requires_real_attempt(tmp_path: Path):
    """blocked counts toward the exit floor — the agent may not assert it
    without a prior tool call that targeted the path."""
    from core.coverage_ledger import mark_unit_blocked
    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)
    rel = "evidence/WS02/Windows/System32/winevt/Logs/Security.evtx"

    r = mark_unit_blocked(
        case, rel, reason="file is corrupt, EvtxECmd refused",
        trace_entries=[])
    assert r["success"] is False
    assert "attempt" in r["error"].lower() or "probe" in r["error"].lower()

    # short/empty reason refused
    r2 = mark_unit_blocked(case, rel, reason="bad", trace_entries=[
        {"type": "tool_call", "cmd": f"ez_evtxecmd {rel}", "success": False}])
    assert r2["success"] is False

    r3 = mark_unit_blocked(
        case, rel, reason="EvtxECmd failed: file header corrupt",
        trace_entries=[
            {"type": "tool_call", "cmd": f"ez_evtxecmd {rel}",
             "success": False},
        ])
    assert r3["success"] is True
    assert r3["unit"]["status"] == "blocked"
    by_path = {u["path"]: u["status"]
               for u in load_ledger(case)["units"].values()}
    assert by_path[rel] == "blocked"


def test_mark_unit_blocked_refuses_a_unit_read_in_part(tmp_path: Path):
    """blocked records a failed examination. A directory whose members
    were partly read is demonstrably readable, so the label would only
    close the unread rest — refuse and name them; once a read of every
    member has failed, blocked records that."""
    from core.coverage_ledger import mark_unit_blocked, register_derived_outputs
    case = _two_host_case(tmp_path)
    streams = case / "analysis" / "streams"
    streams.mkdir(parents=True)
    for i in range(4):
        (streams / f"{i:08d}.jpg").write_bytes(b"\xff\xd8\xff" + bytes([i]))
    build_coverage_ledger(case)
    assert register_derived_outputs(
        case, tool_name="net_tcpxtract_streams",
        arguments={"output_dir": "analysis/streams"}, result_text="{}",
    ) == ["analysis/streams"]

    def _read(n: int, success: bool = True) -> list[dict]:
        rows = [{"type": "tool_call", "mcp_tool": "steg_extract",
                 "cmd": f"steg_extract analysis/streams/{i:08d}.jpg",
                 "success": success}
                for i in range(n)]
        (case / "analysis" / "T_trace.json").write_text(
            json.dumps(rows), encoding="utf-8")
        return rows

    one = _read(1)
    r = mark_unit_blocked(
        case, "analysis/streams",
        reason="looked at the large one; the rest are web assets",
        trace_entries=one)
    assert r["success"] is False
    assert "1 of 4" in r["error"]
    assert "analysis/streams/00000003.jpg" in r["unexamined"]
    by_path = {u["path"]: u["status"]
               for u in load_ledger(case)["units"].values()}
    assert by_path["analysis/streams"] != "blocked"

    every = _read(4, success=False)
    r2 = mark_unit_blocked(
        case, "analysis/streams",
        reason="every member fails to parse: truncated JPEG headers",
        trace_entries=every)
    assert r2["success"] is True and r2["unit"]["status"] == "blocked"


def test_mark_unit_blocked_no_basename_crosstalk(tmp_path: Path):
    """Probing host A's Security.evtx must not authorize blocking host B's."""
    from core.coverage_ledger import mark_unit_blocked
    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)
    ws01 = "evidence/WS01/Windows/System32/winevt/Logs/Security.evtx"
    ws02 = "evidence/WS02/Windows/System32/winevt/Logs/Security.evtx"

    # Same basename only — must refuse
    r_base = mark_unit_blocked(
        case, ws02,
        reason="EvtxECmd failed: file header corrupt",
        trace_entries=[
            {"type": "tool_call", "cmd": "ez_evtxecmd Security.evtx",
             "success": False},
        ],
    )
    assert r_base["success"] is False

    # Probe of the other host's twin — must refuse
    r_other = mark_unit_blocked(
        case, ws02,
        reason="EvtxECmd failed: file header corrupt",
        trace_entries=[
            {"type": "tool_call", "cmd": f"ez_evtxecmd {ws01}",
             "success": False},
        ],
    )
    assert r_other["success"] is False
    assert "path identity" in r_other["error"].lower()

    by_path = {u["path"]: u["status"]
               for u in load_ledger(case)["units"].values()}
    assert by_path[ws01] == "unseen"
    assert by_path[ws02] == "unseen"


def test_reset_unit_statuses_for_fresh_run(tmp_path: Path):
    """clear_case_run semantics: a fresh run re-earns its floor."""
    from core.coverage_ledger import reset_unit_statuses
    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)
    all_paths = [u["path"] for u in load_ledger(case)["units"].values()]
    mark_paths(case, all_paths, status="probed")
    assert ready_for_degraded_exit(case)

    n = reset_unit_statuses(case)
    assert n >= 2
    stats = coverage_stats(load_ledger(case))
    assert stats["probed"] == 0 and stats["unseen"] == stats["total"]
    assert not ready_for_degraded_exit(case)


def test_task_linked_floor_still_requires_disposition(
        tmp_path: Path):
    """B8: claim links do not waive unseen HV — disposition still required."""
    from core.investigation_tasks import reconcile_case_md, update_task

    case = tmp_path / "CaseTasks"
    evid = case / "evidence"
    evid.mkdir(parents=True)
    (case / ".atlas").mkdir()
    (evid / "events.csv").write_text("user,host\na,b\n", encoding="utf-8")
    (evid / "other.csv").write_text("x,y\n1,2\n", encoding="utf-8")
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Was user01 used for lateral movement?\n",
        encoding="utf-8",
    )
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {
            "high_value_parsed": [
                "evidence/events.csv", "evidence/other.csv",
            ],
            "already_processed_count": 2,
            "file_count": 2,
            "counts": {"tabular": 2},
            "absent_classes": ["disk", "memory"],
            "present_classes": ["tabular"],
            "samples": {},
        }}),
        encoding="utf-8",
    )
    build_coverage_ledger(case)
    r = reconcile_case_md(case, persist=True)
    tid = r["added"][0]
    assert not ready_for_degraded_exit(case)  # open task, unseen units
    update_task(case, tid, related_claim_ids=["C0001"])
    assert not ready_for_degraded_exit(case)  # B8: claims ≠ disposition
    stats = coverage_stats(load_ledger(case))
    assert stats["unseen"] >= 1
    mark_paths(case, [
        "evidence/events.csv", "evidence/other.csv",
    ], status="probed")
    assert ready_for_degraded_exit(case)


def test_inbox_empty_does_not_waive_unseen(tmp_path: Path):
    """B8: answered inbox alone must not unlock soft floor with unseen HV."""
    from core.investigation_tasks import reconcile_case_md, update_task

    case = tmp_path / "CaseInbox"
    evid = case / "evidence"
    evid.mkdir(parents=True)
    (case / ".atlas").mkdir()
    (evid / "vpn_logons.csv").write_text("u,t\na,b\n", encoding="utf-8")
    (evid / "other.csv").write_text("x,y\n1,2\n", encoding="utf-8")
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n"
        "- What suspicious activity is in the VPN gateway logs?\n",
        encoding="utf-8",
    )
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {
            "high_value_parsed": [
                "evidence/vpn_logons.csv", "evidence/other.csv",
            ],
        }}),
        encoding="utf-8",
    )
    build_coverage_ledger(case)
    # Narrow VPN task: only vpn_logons.csv is relevant — mark it probed so
    # answered is allowed, leave other.csv unseen.
    mark_paths(case, ["evidence/vpn_logons.csv"], status="probed")
    r = reconcile_case_md(case, persist=True)
    tid = r["added"][0]
    from core.claim_graph import add_claim
    cid = add_claim(case, "VPN gateway logons from an unusual source were "
                    "observed.", confidence="LIKELY",
                    enforce_validation=False)["node_id"]
    upd = update_task(case, tid, status="answered", related_claim_ids=[cid])
    assert upd.get("success") is True
    assert not ready_for_degraded_exit(case)
    mark_paths(case, ["evidence/other.csv"], status="probed")
    assert ready_for_degraded_exit(case)


def test_score_candidate_boosts_unseen_over_probed(tmp_path: Path):
    """B5: unseen HV + task-token overlap outranks sticky probed re-touch."""
    from core.investigation_orchestrator import score_candidate
    from core.investigation_tasks import reconcile_case_md

    case = tmp_path / "CaseOrch"
    evid = case / "evidence"
    evid.mkdir(parents=True)
    (case / ".atlas").mkdir()
    (evid / "user01_lateral.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (evid / "noise_noise.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (case / "CASE.md").write_text(
        "## Investigation Requests\n\n- Investigate user01 lateral movement\n",
        encoding="utf-8",
    )
    (case / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {
            "high_value_parsed": [
                "evidence/user01_lateral.csv",
                "evidence/noise_noise.csv",
            ],
        }}),
        encoding="utf-8",
    )
    build_coverage_ledger(case)
    reconcile_case_md(case, persist=True)
    mark_paths(case, ["evidence/noise_noise.csv"], status="probed")

    sticky = score_candidate(
        path="evidence/noise_noise.csv",
        affinity=3.0,
        est_tokens=100,
        detail_level="artifact_only",
        tool_room=8000,
        focus_text="user01 lateral",
        case_dir=case,
    )
    unseen = score_candidate(
        path="evidence/user01_lateral.csv",
        affinity=3.0,
        est_tokens=100,
        detail_level="artifact_only",
        tool_room=8000,
        focus_text="user01 lateral",
        case_dir=case,
    )
    assert unseen["score"] > sticky["score"]


def test_redirect_rearms_and_allows_force_report_later(
        monkeypatch, tmp_path: Path):
    """After a coverage-redirect, the valve re-arms: once the ledger becomes
    ready, force-report fires on a later turn of the SAME streak (previously
    the first redirect disabled the valve until wall clock)."""
    monkeypatch.setattr(rb, "STALL_SOFT_TURNS", 2)
    monkeypatch.setattr(rb, "STALL_HARD_TURNS", 3)
    monkeypatch.setattr(rb, "STALL_FORCE_REPORT_GRACE", 1)
    monkeypatch.setattr(rb, "TURN_ADVISORY", 0)

    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)

    state = StallState(no_progress_streak=5, hard_injected=True)
    msgs = messages_for_turn(
        state, turn=20, report_written=False, case_dir=case)
    assert any("coverage-redirect" in m["content"] for m in msgs)
    assert state.coverage_redirect_injected
    assert not state.force_report_injected

    # Streak continues; not yet past the re-arm window → silence, no valve.
    state.no_progress_streak = 5
    assert messages_for_turn(
        state, turn=21, report_written=False, case_dir=case) == []

    # Ledger becomes ready (agent probed the gaps); streak passed the re-arm
    # window → force-report now fires instead of staying locked out.
    all_paths = [u["path"] for u in load_ledger(case)["units"].values()]
    mark_paths(case, all_paths, status="probed")
    state.no_progress_streak = 5 + rb.STALL_FORCE_REPORT_GRACE
    msgs3 = messages_for_turn(
        state, turn=22, report_written=False, case_dir=case)
    assert any("[stall force-report]" in m["content"] for m in msgs3)
    assert state.allow_synthesize_escape


def test_redirect_repeats_with_open_ledger(monkeypatch, tmp_path: Path):
    """Still-open ledger after the re-arm window → the redirect repeats with
    current gaps instead of going silent."""
    monkeypatch.setattr(rb, "STALL_SOFT_TURNS", 2)
    monkeypatch.setattr(rb, "STALL_HARD_TURNS", 3)
    monkeypatch.setattr(rb, "STALL_FORCE_REPORT_GRACE", 1)
    monkeypatch.setattr(rb, "TURN_ADVISORY", 0)

    case = _two_host_case(tmp_path)
    build_coverage_ledger(case)

    state = StallState(no_progress_streak=5, hard_injected=True)
    messages_for_turn(state, turn=20, report_written=False, case_dir=case)
    state.no_progress_streak = 5 + rb.STALL_FORCE_REPORT_GRACE
    msgs = messages_for_turn(
        state, turn=21, report_written=False, case_dir=case)
    assert any("coverage-redirect" in m["content"] for m in msgs)
    assert not state.force_report_injected


def test_score_candidate_rejects_noise():
    from core.investigation_orchestrator import score_candidate
    scored = score_candidate(
        path="evidence/modules/x/node_modules/foo/log.js",
        affinity=9.0,
        est_tokens=100,
        detail_level="artifact_only",
        tool_room=8000,
        focus_text="user01 logon lateral",
    )
    assert scored.get("score", 1) == 0.0
    assert scored.get("filtered") is True

    good = score_candidate(
        path="evidence/edr_lateral.csv",
        affinity=3.0,
        est_tokens=100,
        detail_level="artifact_only",
        tool_room=8000,
        focus_text="user01 lateral movement",
    )
    assert good["score"] > scored["score"]
    assert "table" in (good.get("tool_hint") or "") or good["score"] > 3


def test_a_relative_read_under_the_mount_probes_the_image_and_a_stat_does_not(tmp_path: Path):
    """The analyst names a mounted file the way the case names everything,
    relative to its root (mnt/<stem>/fs/...); that read is contact with the
    image exactly like the absolute form the test below uses. A stat of
    the image reads none of it and is not."""
    from core.coverage_ledger import (
        CONTAINER_KIND, _norm_rel, build_coverage_ledger, observe_tool_paths,
    )
    from core.mount_plan import save_mount_plan
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "host.E01").write_bytes(b"EVF" * 16)
    (case / ".atlas").mkdir()
    profile = {"schema_version": "1.0", "evidence_root": str(case / "evidence"),
               "present_classes": ["disk"],
               "files": [{"path": "evidence/host.E01", "class": "disk", "size": 48}]}
    (case / ".atlas" / "evidence_profile.json").write_text(json.dumps(profile), encoding="utf-8")
    dev = case / "mnt" / "host" / "ewf" / "ewf1"
    dev.parent.mkdir(parents=True)
    dev.write_bytes(b"\x00" * 512)
    save_mount_plan(case, {"images": [{"path": str(case / "evidence" / "host.E01"), "stem": "host",
                                        "mount_result": {"success": True, "mount_point": str(case / "mnt" / "host" / "fs"),
                                                         "ewf_device": str(dev)}}]})
    build_coverage_ledger(case)

    def status() -> str:
        return next(u for u in load_ledger(case)["units"].values()
                    if u.get("kind") == CONTAINER_KIND)["status"]

    assert status() == "unseen"
    observe_tool_paths(case, tool_name="strings_stat_file",
                       cmd_or_args=json.dumps({"file_path": "evidence/host.E01"}), success=True)
    assert status() == "unseen"
    observe_tool_paths(case, tool_name="tsk_fls",
                       cmd_or_args=json.dumps({"image_path": "mnt/host/ewf/ewf1", "offset": 63}),
                       success=True)
    assert status() == "probed"
    # The case-relative form of a mount read, and an image's own analysis/
    # folder left where it is.
    assert _norm_rel("mnt/host/fs/Users/u/notes.txt") == "mnt/host/fs/Users/u/notes.txt"
    assert _norm_rel(f"{case}/mnt/host/fs/analysis/report.txt") == "mnt/host/fs/analysis/report.txt"


def test_a_read_under_the_mounted_filesystem_probes_the_image(tmp_path: Path):
    """Once its filesystem is mounted a run never names the image again: every
    read targets a file under the mount point. That read is contact with the
    image; a directory listing there still is not."""
    from core.coverage_ledger import CONTAINER_KIND, build_coverage_ledger, observe_tool_paths
    from core.mount_plan import save_mount_plan
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "host.E01").write_bytes(b"EVF" * 16)
    (case / ".atlas").mkdir()
    profile = {"schema_version": "1.0", "evidence_root": str(case / "evidence"),
               "present_classes": ["disk"],
               "files": [{"path": "evidence/host.E01", "class": "disk", "size": 48}]}
    (case / ".atlas" / "evidence_profile.json").write_text(json.dumps(profile), encoding="utf-8")
    fs = case / "mnt" / "host" / "fs" / "Users" / "u"
    fs.mkdir(parents=True)
    (fs / "notes.txt").write_text("x", encoding="utf-8")
    save_mount_plan(case, {"images": [{"path": str(case / "evidence" / "host.E01"), "stem": "host",
                                        "mount_result": {"success": True, "mount_point": str(case / "mnt" / "host" / "fs"),
                                                         "ewf_device": str(case / "mnt" / "host" / "ewf" / "ewf1")}}]})
    build_coverage_ledger(case)
    unit = next(u for u in load_ledger(case)["units"].values() if u.get("kind") == CONTAINER_KIND)
    assert unit["status"] == "unseen"
    observe_tool_paths(case, tool_name="misc_list_evidence_dir",
                       cmd_or_args=f'{{"path": "{fs}"}}', success=True)
    assert next(u for u in load_ledger(case)["units"].values() if u.get("kind") == CONTAINER_KIND)["status"] == "unseen"
    observe_tool_paths(case, tool_name="strings_read_text",
                       cmd_or_args=f'{{"file_path": "{fs / "notes.txt"}"}}', success=True)
    assert next(u for u in load_ledger(case)["units"].values() if u.get("kind") == CONTAINER_KIND)["status"] == "probed"


import pytest  # noqa: E402


@pytest.mark.parametrize("question, catch_all, broad", [
    ("Which accounts are visible in the evidence logs of the VPN gateway?", False, False),
    ("Look at further activity by this account.", False, False),
    ("Identify any other attacker activity in the evidence.", True, None),
    ("How did the VPN sessions change over time?", None, False),
    ("How did the malware persist?", None, False),
    ("How did the attacker get in?", None, True),
    ("Reconstruct the timeline of the intrusion.", None, False),
    ("Was the fileserver compromised?", None, True),
    ("What happened on HOST01?", None, True),
])
def test_question_breadth_phrases(question, catch_all, broad):
    from core.coverage_ledger import _BROAD_SYSTEM_RE, _CATCH_ALL_TASK_RE
    if catch_all is not None:
        assert bool(_CATCH_ALL_TASK_RE.search(question)) is catch_all
    if broad is not None:
        assert bool(_BROAD_SYSTEM_RE.search(question)) is broad
