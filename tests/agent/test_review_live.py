"""Tests for the in-flight / stuck-run reviewer (`atlas review --live`)."""
import argparse
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.llm import ChatResponse
from agent.review import (Reviewer, detect_stall, load_trace_from_disk,
                          active_trace_path)
from agent.tui import UI


class StubClient:
    def __init__(self, content: str, model: str = "reviewer-model"):
        self.content = content
        self.model = model
        self.api_key = "x"
        self.messages = None

    def chat(self, messages, **kw) -> ChatResponse:
        self.messages = messages
        return ChatResponse(content=self.content)


# ── detect_stall (pure) ──────────────────────────────────────────────────

def _tool_call(cid, cmd, success=True, mcp_tool="misc_batch_run"):
    # A shell verb run through the generic batch executor (misc_batch_run) is a
    # real raw-shell bypass; the same verb as a typed tool's internal subprocess
    # (mcp_tool="strings_strings_grep" etc.) is not. Default to the generic
    # executor so bypass fixtures read as raw shell.
    e = {"call_id": cid, "type": "tool_call", "cmd": cmd, "success": success}
    if mcp_tool is not None:
        e["mcp_tool"] = mcp_tool
    return e


def _stalled_trace_entries():
    """A stalled trace: many openssl calls, high failure rate, stuck in
    Triage despite DAIR recommending Collect, zero findings."""
    entries = []
    cid = 1
    for i in range(60):
        entries.append(_tool_call(
            cid, f"openssl enc -aes-128-cbc -d -k pass{i} -in x.bin",
            success=(i % 3 != 0)))  # ~33% failures
        cid += 1
    for _ in range(3):
        entries.append({"type": "dair_call", "current_phase": "Triage",
                        "next_phase": "Collect"})
    return entries


def _healthy_entries():
    entries = []
    cid = 1
    tools = ["ez_mftecmd", "vol_pslist", "tsk_fls", "yara_scan_file",
             "net_tcpdump_read", "misc_record_finding"]
    for i in range(24):
        entries.append(_tool_call(cid, [tools[i % len(tools)], "arg"]))
        cid += 1
    entries += [
        {"type": "dair_call", "current_phase": "Triage", "next_phase": "Collect"},
        {"type": "dair_call", "current_phase": "Collect", "next_phase": "Analyze"},
        {"type": "dair_call", "current_phase": "Analyze", "next_phase": "Report"},
        {"type": "finding", "confidence": "LIKELY", "description": "x",
         "linked_call_id": 1},
        {"type": "finding", "confidence": "CONFIRMED", "description": "y",
         "linked_call_id": 2},
    ]
    return entries


def test_detect_stall_fires_on_stalled_trace():
    r = detect_stall(_stalled_trace_entries())
    assert r["stalled"] is True
    assert r["severity"] in ("medium", "high")
    assert "findings_starved" in r["hits"]
    assert "dair_transition_ignored" in r["hits"]
    assert "command_loop" in r["hits"]
    assert r["signals"]["command_loop"]["repeats"] >= 8
    assert "openssl" in r["signals"]["command_loop"]["signature"]
    assert "high_failure_rate" in r["hits"]
    assert "rawbash_dominance" in r["hits"]


def test_escaped_command_loop_does_not_flag_live_run():
    # An early strings loop must not keep command_loop firing on live polls
    # long after the run has moved on to varied, productive work. Loops are
    # only a stall signal while they are still happening (trailing window).
    entries = []
    cid = 1
    for _ in range(20):  # the escaped early loop
        entries.append(_tool_call(cid, "strings -a -n 4 exports/mft.csv"))
        cid += 1
    varied = ["ez_mftecmd x", "vol_pslist y", "tsk_fls z", "regripper -r h",
              "misc_parse_email a", "pdf-parser.py b", "evtx_filter c",
              "yara scan d", "vol_netscan e", "tsk_icat f", "exiftool g",
              "hash_file i", "vol_pstree j", "tsk_mmls k", "capa m",
              "zeek n"]
    for i in range(64):  # later healthy, varied work fills the window
        entries.append(_tool_call(cid, f"{varied[i % len(varied)]} {i}"))
        cid += 1
    entries.append({"type": "dair_call", "current_phase": "Triage",
                    "next_phase": "Collect"})
    r = detect_stall(entries)
    assert "command_loop" not in r["hits"]


def test_active_finding_pipeline_damps_findings_starved():
    # Zero recorded findings with the hypothesize/evaluate chain actively
    # running is not starvation: a first record attempt refused as
    # CHALLENGED while evidence work is healthy must not read as STALLED.
    entries = [_tool_call(i, f"ez_mftecmd run {i}", mcp_tool="ez_ez_mftecmd")
               for i in range(45)]
    entries.append({"type": "reason_call", "tool": "reason_evaluate_finding",
                    "success": True, "conclusion": "VERDICT: CHALLENGED"})
    r = detect_stall(entries)
    assert "findings_starved" not in r["hits"]
    assert r["signals"]["findings_starved"]["pipeline_active"] is True


def test_findings_starved_still_fires_without_pipeline():
    entries = [_tool_call(i, f"ez_mftecmd run {i}", mcp_tool="ez_ez_mftecmd")
               for i in range(45)]
    r = detect_stall(entries)
    assert "findings_starved" in r["hits"]


def test_typed_tool_subprocess_does_not_count_as_rawbash():
    # A typed wrapper logs its internal subprocess cmd ("strings -a …" from
    # strings_strings_grep); a verb-only heuristic misreads an all-typed run
    # as raw bash and fires false stalls. With mcp_tool stamped, typed-tool
    # subprocesses must not count.
    entries = [_tool_call(i, f"strings -a -n 4 /evidence/img.mem | grep x{i}",
                          mcp_tool="strings_strings_grep")
               for i in range(50)]
    entries.append({"type": "dair_call", "current_phase": "Collect",
                    "next_phase": "Collect"})
    entries.append({"type": "finding", "confidence": "LIKELY",
                    "description": "x", "linked_call_id": 1})
    r = detect_stall(entries)
    assert "rawbash_dominance" not in r["hits"]
    assert r["signals"]["rawbash_dominance"]["raw"] == 0


def test_shell_verbs_via_batch_run_do_count_as_rawbash():
    # Shell verbs (cat/grep/ls/find) run through the generic misc_batch_run
    # executor instead of typed tools are a raw-shell bypass the signal must
    # catch.
    cmds = ["cat /ev/f", "grep x /ev/f", "ls -laR /ev", "find /ev -name x"]
    entries = [_tool_call(i, cmds[i % len(cmds)], mcp_tool="misc_batch_run")
               for i in range(50)]
    entries.append({"type": "dair_call", "current_phase": "Collect",
                    "next_phase": "Collect"})
    r = detect_stall(entries)
    assert "rawbash_dominance" in r["hits"]


def test_routed_command_loop_named_and_not_framed_as_rawbash():
    # A command_loop over a routed tool (strings_strings_grep) carries a bare
    # `strings` signature that a live LLM reviewer can misread as raw-shell
    # looping and answer with advice to route through MCP, although the run
    # already is routed. The loop signal must carry the routed tool name and
    # the stall report must say the loop is already routed.
    entries = [_tool_call(i, f"strings -a -n 4 /ev/img.dd | grep host{i}",
                          mcp_tool="strings_strings_grep")
               for i in range(40)]
    entries.append({"type": "dair_call", "current_phase": "Collect",
                    "next_phase": "Collect"})
    r = detect_stall(entries)
    assert "command_loop" in r["hits"]
    assert r["signals"]["command_loop"]["routed_tool"] == "strings_strings_grep"
    assert "rawbash_dominance" not in r["hits"]
    text = Reviewer._stall_report_text(r)
    assert "strings_strings_grep" in text
    assert "already MCP-routed" in text
    assert "do not advise re-routing" in text


def test_batch_run_command_loop_keeps_plain_framing():
    # The same verb looped through the generic executor is genuinely raw
    # shell — no routed-tool label, plain rabbit-hole framing stays.
    entries = [_tool_call(i, f"grep attacker /ev/log{i % 2}",
                          mcp_tool="misc_batch_run")
               for i in range(40)]
    entries.append({"type": "dair_call", "current_phase": "Collect",
                    "next_phase": "Collect"})
    r = detect_stall(entries)
    assert "command_loop" in r["hits"]
    assert r["signals"]["command_loop"]["routed_tool"] is None
    text = Reviewer._stall_report_text(r)
    assert "COMMAND LOOP: `grep" in text
    assert "already MCP-routed" not in text


def test_legacy_command_loop_without_mcp_tool_keeps_plain_framing():
    # Traces predating mcp_tool stamping: no routed label, old framing.
    entries = [_tool_call(i, "strings -a /ev/img.dd", mcp_tool=None)
               for i in range(40)]
    entries.append({"type": "dair_call", "current_phase": "Collect",
                    "next_phase": "Collect"})
    r = detect_stall(entries)
    assert "command_loop" in r["hits"]
    assert r["signals"]["command_loop"]["routed_tool"] is None


def test_legacy_trace_without_mcp_tool_uses_verb_fallback():
    # Traces predating mcp_tool stamping: verb-only fallback still works.
    entries = [_tool_call(i, f"grep x{i} /ev/f", mcp_tool=None)
               for i in range(50)]
    entries.append({"type": "dair_call", "current_phase": "Collect",
                    "next_phase": "Collect"})
    r = detect_stall(entries)
    assert "rawbash_dominance" in r["hits"]
    assert r["signals"]["rawbash_dominance"]["raw"] == 50


def test_detect_stall_quiet_on_healthy_trace():
    r = detect_stall(_healthy_entries())
    assert r["stalled"] is False
    assert r["hits"] == []
    assert r["severity"] == "none"


def test_detect_stall_young_run_not_flagged():
    # 10 failing raw-bash calls, no findings — but too young to call stalled.
    entries = [_tool_call(i, "grep x y", success=False) for i in range(10)]
    r = detect_stall(entries)
    assert r["young"] is True
    assert r["stalled"] is False
    # findings_starved needs >= 40 calls; failure/rawbash suppressed while young
    assert "high_failure_rate" not in r["hits"]


def test_gate_refusals_do_not_trip_high_failure_rate():
    """Protective gate refusals counted as tool failures push a healthy run
    to a high "failure" rate. Failures tagged failure_class=gate_refusal by
    the middleware must not count."""
    entries = [_tool_call(i, f"vol pslist {i}", mcp_tool="vol_vol_pslist")
               for i in range(1, 31)]
    for i in range(31, 41):
        e = _tool_call(i, "<py>:misc_record_finding", success=False,
                       mcp_tool="misc_record_finding")
        e["failure_class"] = "gate_refusal"
        entries.append(e)
    r = detect_stall(entries)
    assert "high_failure_rate" not in r["hits"]
    assert r["signals"]["high_failure_rate"]["failures"] == 0


def test_expected_nonzero_does_not_trip_high_failure_rate():
    """An expected non-zero exit (cmp/diff exit 1 for 'files differ') is a
    result, not a tool failure. Counted as failures, such comparisons push a
    healthy run over the failure-rate threshold and fire a false STALLED.
    expected_nonzero must not count."""
    entries = [_tool_call(i, f"strings_grep {i}", mcp_tool="strings_strings_grep")
               for i in range(1, 31)]
    for i in range(31, 46):
        e = _tool_call(i, f"cmp dump{i}.bin dump{i+1}.bin", success=False,
                       mcp_tool="strings_hexdump")
        e["failure_class"] = "expected_nonzero"
        entries.append(e)
    r = detect_stall(entries)
    assert "high_failure_rate" not in r["hits"]
    assert r["signals"]["high_failure_rate"]["failures"] == 0


def test_disk_floor_refusals_do_not_trip_high_failure_rate():
    """Fail-safe refusals of the disk-space guard are infrastructure
    protection, not tool failures — they must not inflate the rate."""
    entries = [_tool_call(i, f"vol pslist {i}", mcp_tool="vol_vol_pslist")
               for i in range(1, 31)]
    for i in range(31, 45):
        e = _tool_call(i, "vol netscan", success=False, mcp_tool="vol_vol_netscan")
        e["failure_class"] = "disk_floor"
        entries.append(e)
    r = detect_stall(entries)
    assert "high_failure_rate" not in r["hits"]
    assert r["signals"]["high_failure_rate"]["failures"] == 0


def test_analyst_and_untagged_failures_still_count_toward_failure_rate():
    entries = [_tool_call(i, f"vol pslist {i}", mcp_tool="vol_vol_pslist")
               for i in range(1, 31)]
    # 5 analyst errors (tagged) + 5 legacy failures (no failure_class)
    for i in range(31, 36):
        e = _tool_call(i, "<py>:misc_record_self_correction", success=False,
                       mcp_tool="misc_record_self_correction")
        e["failure_class"] = "analyst_error"
        entries.append(e)
    entries += [_tool_call(i, "openssl enc -d x", success=False)
                for i in range(36, 41)]
    r = detect_stall(entries)
    assert r["signals"]["high_failure_rate"]["hit"] is True
    assert r["signals"]["high_failure_rate"]["failures"] == 10


def test_completed_run_with_a_loop_is_not_stalled():
    """A run that finished through several phases with real
    findings must not be flagged as stalled just because a tool was
    repeated."""
    entries = []
    cid = 1
    # a repeated tool (would trip command_loop) but the run is productive
    for _ in range(20):
        entries.append(_tool_call(cid, "strings -a memory.dmp"))
        cid += 1
    for _ in range(20):
        entries.append(_tool_call(cid, ["vol_pslist", "arg"]))
        cid += 1
    entries += [
        {"type": "dair_call", "current_phase": "Triage", "next_phase": "Collect"},
        {"type": "dair_call", "current_phase": "Collect", "next_phase": "Report"},
        {"type": "dair_call", "current_phase": "Report", "next_phase": ""},
    ]
    entries += [{"type": "finding", "confidence": "LIKELY",
                 "description": f"f{i}", "linked_call_id": i} for i in range(7)]
    r = detect_stall(entries)
    assert r["stalled"] is False
    assert r["progressed"] is True
    assert r["findings"] == 7
    # command_loop may still be reported, but only as an advisory low signal
    assert r["severity"] in ("none", "low")


def test_dair_ignored_alone_is_a_stall():
    entries = [_tool_call(i, ["ez_mftecmd", "a"]) for i in range(35)]
    entries += [{"type": "dair_call", "current_phase": "Triage",
                 "next_phase": "Collect"} for _ in range(3)]
    r = detect_stall(entries)
    assert "dair_transition_ignored" in r["hits"]
    assert r["stalled"] is True


# ── disk helpers ─────────────────────────────────────────────────────────

def test_load_trace_from_disk(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"case_id": "C1", "entries": [{"type": "x"}]}),
                 encoding="utf-8")
    cid, entries = load_trace_from_disk(p)
    assert cid == "C1"
    assert entries == [{"type": "x"}]


def test_active_trace_path_reads_session(tmp_path, monkeypatch):
    home = tmp_path
    cache = home / ".cache" / "atlas"
    cache.mkdir(parents=True)
    (cache / "session.json").write_text(
        json.dumps({"case_id": "C", "path": "/some/trace.json"}),
        encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    assert active_trace_path() == Path("/some/trace.json")


# ── review_live ──────────────────────────────────────────────────────────

LIVE_OUT = ("STATUS: STALLED\n\n## Diagnosis\nStuck in Triage.\n\n"
            "## Unstick actions\n1. Call dair_assess and move to Collect.\n")


@pytest.fixture
def case_dir(tmp_path):
    (tmp_path / "reports").mkdir()
    return tmp_path


def _write_trace(tmp_path, entries, case_id="CASE-C"):
    p = tmp_path / "trace.json"
    p.write_text(json.dumps({"case_id": case_id, "entries": entries}),
                 encoding="utf-8")
    return p


def test_review_live_writes_file_and_feeds_stall_evidence(case_dir):
    trace = _write_trace(case_dir, _stalled_trace_entries())
    client = StubClient(LIVE_OUT)
    result = Reviewer(client, case_dir, UI(quiet=True)).review_live(
        trace_path=trace, question="find the password")
    assert result["status"] == "STALLED"
    assert result["stalled"] is True
    out = Path(result["path"])
    assert out == case_dir / "reports" / "CASE-C_live_review.md"
    assert "Unstick actions" in out.read_text(encoding="utf-8")
    # the deterministic stall report must reach the model
    user_msg = client.messages[1]["content"]
    assert "Stall report" in user_msg
    assert "COMMAND LOOP" in user_msg
    assert "DAIR TRANSITION IGNORED" in user_msg
    assert "INDEPENDENT" in client.messages[0]["content"]


def test_review_live_healthy_trace_not_stalled(case_dir):
    trace = _write_trace(case_dir, _healthy_entries(), case_id="OK-1")
    client = StubClient("STATUS: HEALTHY\n\n## Diagnosis\nFine.\n\n"
                        "## Unstick actions\nNone needed.\n")
    result = Reviewer(client, case_dir, UI(quiet=True)).review_live(
        trace_path=trace)
    assert result["stalled"] is False
    assert result["status"] == "HEALTHY"
    assert "No stall signals fired" in client.messages[1]["content"]


def test_review_live_missing_trace_returns_error(case_dir):
    result = Reviewer(StubClient(LIVE_OUT), case_dir, UI(quiet=True)).review_live(
        trace_path=case_dir / "nope.json")
    assert "error" in result


# ── CLI wiring ───────────────────────────────────────────────────────────

def test_review_parser_wiring():
    import agent.cli as cli
    with patch.object(cli, "_bootstrap_env"), \
         patch.object(cli, "cmd_review") as fake:
        cli.main(["review", "--live", "--trace", "/t/x.json",
                  "--review-model", "rm", "--json"])
    ns = fake.call_args.args[0]
    assert ns.live is True
    assert ns.trace == "/t/x.json"
    assert ns.review_model == "rm"
    assert ns.json is True


def test_cmd_review_exits_3_when_stalled(case_dir, monkeypatch, capsys):
    import agent.cli as cli
    trace = _write_trace(case_dir, _stalled_trace_entries())
    args = argparse.Namespace(live=True, case=str(case_dir), trace=str(trace),
                              question="", review_model="", json=True)
    monkeypatch.setattr(cli, "_build_reviewer_client",
                        lambda *a, **k: StubClient(LIVE_OUT))
    with pytest.raises(SystemExit) as exc:
        cli.cmd_review(args)
    assert exc.value.code == 3
    # the selected trace must be announced up front, even in --json mode
    assert f"reviewing trace: {trace}" in capsys.readouterr().err


# ── resolve_review_trace: explicit --case beats a foreign beacon ─────────

def _beacon(tmp_path, monkeypatch, trace: Path):
    cache = tmp_path / ".cache" / "atlas"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "session.json").write_text(
        json.dumps({"case_id": "X", "path": str(trace)}), encoding="utf-8")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))


def test_explicit_case_rejects_foreign_beacon(tmp_path, monkeypatch):
    from agent.review import resolve_review_trace
    case = tmp_path / "cases" / "case-c"
    (case / "analysis").mkdir(parents=True)
    own_trace = case / "analysis" / "CASE-C_trace.json"
    own_trace.write_text("{}", encoding="utf-8")
    foreign = tmp_path / "cases" / "case-b" / "analysis" / "CASE-B_trace.json"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("{}", encoding="utf-8")
    _beacon(tmp_path, monkeypatch, foreign)
    trace, warn = resolve_review_trace(case, case_explicit=True)
    assert trace == own_trace
    assert "outside --case" in warn


def test_explicit_case_accepts_own_beacon(tmp_path, monkeypatch):
    from agent.review import resolve_review_trace
    case = tmp_path / "cases" / "case-c"
    (case / "analysis").mkdir(parents=True)
    own_trace = case / "analysis" / "CASE-C_trace.json"
    own_trace.write_text("{}", encoding="utf-8")
    _beacon(tmp_path, monkeypatch, own_trace)
    trace, warn = resolve_review_trace(case, case_explicit=True)
    assert trace == own_trace
    assert warn == ""


def test_no_explicit_case_keeps_beacon(tmp_path, monkeypatch):
    from agent.review import resolve_review_trace
    somewhere = tmp_path / "cases" / "case-b" / "analysis" / "T_trace.json"
    somewhere.parent.mkdir(parents=True)
    somewhere.write_text("{}", encoding="utf-8")
    _beacon(tmp_path, monkeypatch, somewhere)
    trace, warn = resolve_review_trace(tmp_path / "elsewhere",
                                       case_explicit=False)
    assert trace == somewhere
    assert warn == ""


def test_missing_beacon_falls_back_to_case_trace(tmp_path, monkeypatch):
    from agent.review import resolve_review_trace
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    case = tmp_path / "cases" / "case-c"
    (case / "analysis").mkdir(parents=True)
    own_trace = case / "analysis" / "CASE-C_trace.json"
    own_trace.write_text("{}", encoding="utf-8")
    trace, warn = resolve_review_trace(case, case_explicit=True)
    assert trace == own_trace
    assert "beacon missing" in warn


# ── resolve_review_trace: a stale beacon must not hijack the review ──────
# `atlas review --live` from the repo root, while another run is in flight,
# must not silently review a finished trace the beacon still points at.

def _make_trace(root: Path, case: str, cid: str, age_seconds: float = 0.0) -> Path:
    p = root / "cases" / case / "analysis" / f"{cid}_trace.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{}", encoding="utf-8")
    if age_seconds:
        old = time.time() - age_seconds
        os.utime(p, (old, old))
    return p


def test_stale_beacon_loses_to_fresher_running_trace(tmp_path, monkeypatch):
    from agent.review import resolve_review_trace
    monkeypatch.chdir(tmp_path)
    stale = _make_trace(tmp_path, "case-b", "CASE-B", age_seconds=3600)
    fresh = _make_trace(tmp_path, "case-a", "CASE-A")
    _beacon(tmp_path, monkeypatch, stale)
    # repo-root invocation: case_dir has no analysis/ of its own
    trace, warn = resolve_review_trace(tmp_path, case_explicit=False)
    assert trace == fresh
    assert "stale" in warn
    assert str(stale) in warn and str(fresh) in warn


def test_stale_beacon_kept_with_warning_when_nothing_fresher(tmp_path, monkeypatch):
    from agent.review import resolve_review_trace
    monkeypatch.chdir(tmp_path)
    stale = _make_trace(tmp_path, "case-b", "CASE-B", age_seconds=3600)
    _beacon(tmp_path, monkeypatch, stale)
    trace, warn = resolve_review_trace(tmp_path, case_explicit=False)
    assert trace == stale
    assert "stale" in warn and "finished or died" in warn


def test_beacon_pointing_at_deleted_trace_falls_back(tmp_path, monkeypatch):
    from agent.review import resolve_review_trace
    monkeypatch.chdir(tmp_path)
    fresh = _make_trace(tmp_path, "case-a", "CASE-A")
    _beacon(tmp_path, monkeypatch,
            tmp_path / "cases" / "gone" / "analysis" / "GONE_trace.json")
    trace, warn = resolve_review_trace(tmp_path, case_explicit=False)
    assert trace == fresh
    assert "missing trace" in warn


# ── review without --live: the grade, for a run not in this process ────────

GRADE_OK = "VERDICT: STRONG\n\n## Assessment\nSolid run.\n"
GRADE_NEEDS_WORK = "VERDICT: NEEDS WORK\n\n## Assessment\nStalled in Triage.\n"


def _case_with_trace(tmp_path: Path, case_id: str = "CASE-A") -> tuple[Path, Path]:
    case = tmp_path / "cases" / "case-a"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.md").write_text("# Case CASE-A\n", encoding="utf-8")
    entries = _healthy_entries() + [{
        "type": "finding", "call_id": 900, "confidence": "LIKELY",
        "description": "jane.doe logged on to CORP-DC01 at 2031-03-04 10:02 UTC."}]
    trace = case / "analysis" / f"{case_id}_trace.json"
    trace.write_text(json.dumps({"case_id": case_id, "entries": entries}), encoding="utf-8")
    return case, trace


def _args(trace=None, case=None, live=False):
    return argparse.Namespace(live=live, case=case, trace=str(trace) if trace else None,
                              question="", review_model="", json=False)


def test_review_grades_the_run_into_the_traces_case(tmp_path, monkeypatch):
    import agent.cli as cli
    case, trace = _case_with_trace(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "analysis").mkdir(parents=True)   # looks like a case to the old fallback
    monkeypatch.chdir(elsewhere)
    monkeypatch.setattr(cli, "_build_reviewer_client", lambda *a, **k: StubClient(GRADE_OK))
    cli.cmd_review(_args(trace=trace))
    assert (case / "reports" / "CASE-A_run_review.md").is_file()
    assert not (elsewhere / "reports").exists()


def test_a_graded_run_that_needs_work_exits_3(tmp_path, monkeypatch):
    import agent.cli as cli
    case, trace = _case_with_trace(tmp_path)
    monkeypatch.setattr(cli, "_build_reviewer_client", lambda *a, **k: StubClient(GRADE_NEEDS_WORK))
    with pytest.raises(SystemExit) as stop:
        cli.cmd_review(_args(trace=trace, case=str(case)))
    assert stop.value.code == 3


def test_the_grade_never_binds_the_process_log(tmp_path, monkeypatch):
    from core.execution_log import log
    case, trace = _case_with_trace(tmp_path)
    _beacon(tmp_path, monkeypatch, trace)     # a beacon naming that very trace
    before_path, before_bytes = log._path, trace.read_bytes()
    client = StubClient(GRADE_OK)
    from agent.review import run_stats_from_disk
    _cid, entries = load_trace_from_disk(trace)
    result = Reviewer(client, case, UI(quiet=True)).review(
        run_stats_from_disk(case, entries), trace_path=trace)
    assert result["verdict"] == "STRONG"
    assert log._path == before_path
    assert trace.read_bytes() == before_bytes
    context = client.messages[1]["content"]
    assert "findings_recorded: 3" in context        # counted from the trace file
    assert "TTP coverage: " in context and "not computed" not in context   # read from the file


def test_a_trace_outside_any_case_is_refused(tmp_path, monkeypatch):
    import agent.cli as cli
    loose = tmp_path / "loose"
    loose.mkdir()
    trace = _write_trace(loose, _healthy_entries())
    monkeypatch.setattr(cli, "_build_reviewer_client", lambda *a, **k: StubClient(GRADE_OK))
    with pytest.raises(SystemExit) as stop:
        cli.cmd_review(_args(trace=trace))
    assert "pass --case" in str(stop.value)


def test_a_live_review_without_case_lands_in_the_traces_case(tmp_path, monkeypatch):
    import agent.cli as cli
    case, trace = _case_with_trace(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "analysis").mkdir(parents=True)
    monkeypatch.chdir(elsewhere)
    monkeypatch.setattr(cli, "_build_reviewer_client", lambda *a, **k: StubClient(LIVE_OUT))
    try:
        cli.cmd_review(_args(trace=trace, live=True))
    except SystemExit:
        pass
    assert (case / "reports" / "CASE-A_live_review.md").is_file()
    assert not (elsewhere / "reports").exists()


def test_the_grade_reads_nothing_of_the_process_log(tmp_path, monkeypatch):
    """Any read of the process log from the trace-file grade is a failure:
    the log may belong to another run, and binding it rewrites a trace."""
    import core.execution_log as el
    from agent.review import run_stats_from_disk

    class _Untouchable:
        def __getattr__(self, name):
            raise AssertionError(f"the review read the process log ({name})")

    case, trace = _case_with_trace(tmp_path)
    _cid, entries = load_trace_from_disk(trace)
    monkeypatch.setattr(el, "log", _Untouchable())
    result = Reviewer(StubClient(GRADE_OK), case, UI(quiet=True)).review(
        run_stats_from_disk(case, entries), trace_path=trace)
    assert result["verdict"] == "STRONG"
