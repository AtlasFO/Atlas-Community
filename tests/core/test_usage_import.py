"""Runs from before the usage ledger, added from their case folders: which
calls a run's transcript and trace give, under which key, and that a run the
ledger knows (recorded live, added before, or deleted) is never added."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core import usage_import as imp
from core import usage_ledger as ledger

URL = "https://gw.example/v2"
PROVIDERS = [("gw", URL, "m-analyst")]
ROLES = {"analyst": "m-analyst", "reason": "m-reason", "dair": "m-dair",
         "report": "m-analyst", "review": "m-analyst"}


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    monkeypatch.setattr(imp, "configured", lambda: list(PROVIDERS))


def _jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _case(root: Path, name: str = "CASE-A", case_id: str = "A-1") -> Path:
    case = root / name
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.md").write_text(f"**Case ID:** {case_id}\n", encoding="utf-8")
    return case


def _run(folder: Path, stamp: str, start: str, turns: list[str], roles=ROLES) -> Path:
    first = {"event": "run_start", "model": "m-analyst", "base_url": URL, "ts": start}
    if roles is not None:
        first["roles"] = roles
    path = folder / f"agent_transcript_{stamp}.jsonl"
    _jsonl(path, [first] + [
        {"event": "assistant", "turn": i + 1, "input_tokens": 1000 * (i + 1),
         "output_tokens": 10, "cached_tokens": 5, "reasoning_tokens": 3, "ts": ts,
         "cut_reason": ""}
        for i, ts in enumerate(turns)])
    return path


def _trace(folder: Path, entries: list[dict]) -> None:
    _jsonl(folder / "A-1_trace.jsonl",
           [{"seq": i, "entry": {"call_id": i, **e}} for i, e in enumerate(entries)])


def _calls():
    rows = ledger.daily_rows("2000-01-01")
    return {(r["run_id"], r["provider"], r["model"]): r for r in rows}


class TestOneRun:
    def test_turns_and_the_trace_calls_in_the_window_become_rows(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00.400000+00:00",
             ["2031-02-03T10:01:00+00:00", "2031-02-03T10:05:00+00:00"])
        _trace(case / "analysis", [
            # the trace keeps seconds: a call in the run's first second counts
            {"type": "dair_call", "ts": "2031-02-03T10:00:00+00:00",
             "input_tokens": 70, "output_tokens": 7},
            {"type": "reason_call", "tool": "reason_evaluate_finding",
             "ts": "2031-02-03T10:02:00+00:00", "input_tokens": 50,
             "output_tokens": 20, "reasoning_tokens": 9},
            # a gate entry that made no model call
            {"type": "reason_call", "tool": "hash_verify_evidence_hash",
             "ts": "2031-02-03T10:03:00+00:00", "input_tokens": 0, "output_tokens": 0},
            {"type": "tool_call", "ts": "2031-02-03T10:03:30+00:00"},
            # after the run's last event: not this run's
            {"type": "dair_call", "ts": "2031-02-03T11:00:00+00:00",
             "input_tokens": 99, "output_tokens": 9},
        ])
        (case / ".atlas" / "run_history").mkdir(parents=True)
        (case / ".atlas" / "run_history" / "run-0001.json").write_text(json.dumps(
            {"started_at": "2031-02-03T09:58:00Z", "finished_at": "2031-02-03T09:59:58Z",
             "trigger": "cli-train"}), encoding="utf-8")

        assert imp.import_history(str(tmp_path)) == {"runs": 1, "calls": 4}
        calls = _calls()
        agent = calls[("20310203T100000Z", "gw", "m-analyst")]
        assert agent["case_id"] == "A-1" and agent["command"] == "train"
        assert agent["started_by"] == "" and agent["calls"] == 2
        assert (agent["input"], agent["output"], agent["cached"], agent["reasoning"]) == (3000, 20, 10, 6)
        assert calls[("20310203T100000Z", "gw", "m-reason")]["input"] == 50
        assert calls[("20310203T100000Z", "gw", "m-dair")]["input"] == 70
        assert agent["day"] == "2031-02-03"

    def test_a_second_pass_adds_nothing(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00"])
        assert imp.import_history(str(tmp_path))["runs"] == 1
        assert imp.import_history(str(tmp_path)) == {"runs": 0, "calls": 0}
        assert len(ledger.daily_rows("2000-01-01")) == 1

    def test_a_transcript_without_the_role_map_is_left_out(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00"], roles=None)
        assert imp.import_history(str(tmp_path)) == {"runs": 0, "calls": 0}
        assert ledger.run_keys() == set()

    def test_the_command_is_run_without_a_matching_history_record(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00"])
        (case / ".atlas" / "run_history").mkdir(parents=True)
        (case / ".atlas" / "run_history" / "run-0001.json").write_text(json.dumps(
            {"finished_at": "2031-01-03T09:00:00Z", "trigger": "cli-train"}), encoding="utf-8")
        imp.import_history(str(tmp_path))
        assert {r["command"] for r in ledger.daily_rows("2000-01-01")} == {"run"}


class TestKnownRuns:
    def test_a_run_recorded_live_is_not_added(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00", "2031-02-03T10:02:00+00:00"])
        ledger.configure(case_id="A-1", run_id="20310203T100000Z", command="run")
        ledger.record(role="agent", provider="gw", model="m-analyst",
                      input_tokens=1, output_tokens=1)
        ledger.reset()
        assert imp.import_history(str(tmp_path))["runs"] == 0
        assert sum(r["calls"] for r in ledger.daily_rows("2000-01-01")) == 1

    def test_a_deleted_run_never_comes_back(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00"])
        imp.import_history(str(tmp_path))
        assert ledger.clear(None) == 1
        assert imp.import_history(str(tmp_path))["runs"] == 0
        assert ledger.daily_rows("2000-01-01") == []

    def test_a_live_run_deleted_before_any_pass_is_not_added_either(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00"])
        ledger.configure(case_id="A-1", run_id="20310203T100000Z", command="run")
        ledger.record(role="agent", provider="gw", model="m-analyst",
                      input_tokens=1, output_tokens=1)
        ledger.reset()
        ledger.clear(None)
        assert imp.import_history(str(tmp_path))["runs"] == 0

    def test_the_newest_run_of_a_working_case_waits(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00"])
        _run(case / "analysis", "20310204T100000Z", "2031-02-04T10:00:00+00:00",
             ["2031-02-04T10:01:00+00:00"])
        assert imp.import_history(str(tmp_path), busy=lambda _c: True)["runs"] == 1
        assert {r["run_id"] for r in ledger.daily_rows("2000-01-01")} == {"20310203T100000Z"}
        assert imp.import_history(str(tmp_path))["runs"] == 1


class TestSharedAndArchivedTraces:
    def test_runs_sharing_a_trace_take_the_calls_in_their_own_window(self, tmp_path):
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:10:00+00:00"])
        _run(case / "analysis", "20310203T120000Z", "2031-02-03T12:00:00+00:00",
             ["2031-02-03T12:10:00+00:00"])
        _trace(case / "analysis", [
            {"type": "dair_call", "ts": "2031-02-03T10:05:00+00:00", "input_tokens": 11, "output_tokens": 1},
            {"type": "dair_call", "ts": "2031-02-03T11:00:00+00:00", "input_tokens": 22, "output_tokens": 1},
            {"type": "dair_call", "ts": "2031-02-03T12:05:00+00:00", "input_tokens": 33, "output_tokens": 1},
        ])
        imp.import_history(str(tmp_path))
        calls = _calls()
        assert calls[("20310203T100000Z", "gw", "m-dair")]["input"] == 11
        assert calls[("20310203T120000Z", "gw", "m-dair")]["input"] == 33

    def test_an_archived_run_reads_the_trace_archived_with_it(self, tmp_path):
        case = _case(tmp_path)
        archived = case / ".atlas" / "run_history" / "trace-20310203T110000Z"
        _run(archived, "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00"])
        _trace(archived, [{"type": "dair_call", "ts": "2031-02-03T10:00:30+00:00",
                           "input_tokens": 5, "output_tokens": 1}])
        assert imp.import_history(str(tmp_path)) == {"runs": 1, "calls": 2}


class TestLabels:
    def test_the_provider_at_the_host_serving_the_model_wins(self):
        known = [("a", URL, "m1"), ("b", URL + "/", "m2"), ("c", "https://other/v1", "m2")]
        assert imp.provider_for(URL, "m2", known) == "b"
        assert imp.provider_for("gw.example", "m1", known) == "a"
        # two providers at the host, neither serving the model: no guess
        assert imp.provider_for(URL, "m3", known) == ""
        assert imp.provider_for("https://nowhere/v1", "m1", known) == ""

    def test_the_only_provider_at_the_host_takes_any_model(self):
        assert imp.provider_for(URL, "older-model", [("gw", URL, "m1")]) == "gw"

    def test_the_role_names_match_what_the_transport_records(self):
        from agent.llm import _AGENT_ROLE
        from tools.dair import _DAIR_ROLE
        assert (imp.AGENT_ROLE, imp.DAIR_ROLE) == (_AGENT_ROLE, _DAIR_ROLE)


class TestWhatTheHistoryCannotTell:
    def test_a_chat_call_inside_a_run_span_counts_with_the_run_and_outside_is_left_out(
            self, tmp_path):
        """The trace does not say which process made a call: a run takes the
        calls made within its own span, a chat's included."""
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00", "2031-02-03T10:30:00+00:00"])
        _jsonl(case / "analysis" / "chat_transcript_20310203T101000Z.jsonl",
               [{"event": "run_start", "model": "m-analyst", "roles": ROLES,
                 "base_url": URL, "ts": "2031-02-03T10:10:00+00:00"}])
        _trace(case / "analysis", [
            {"type": "reason_call", "tool": "reason_hypothesize",
             "ts": "2031-02-03T10:12:00+00:00", "input_tokens": 40, "output_tokens": 4},
            {"type": "reason_call", "tool": "reason_hypothesize",
             "ts": "2031-02-03T11:00:00+00:00", "input_tokens": 80, "output_tokens": 8},
        ])
        assert imp.import_history(str(tmp_path)) == {"runs": 1, "calls": 3}
        assert _calls()[("20310203T100000Z", "gw", "m-reason")]["input"] == 40

    def test_two_providers_at_one_host_serving_one_model_leave_the_host(self, tmp_path, monkeypatch):
        monkeypatch.setattr(imp, "configured", lambda: [("gw", URL, "m-analyst"),
                                                        ("gw-2", URL, "m-analyst")])
        assert imp.provider_for(URL, "m-analyst") == ""
        case = _case(tmp_path)
        _run(case / "analysis", "20310203T100000Z", "2031-02-03T10:00:00+00:00",
             ["2031-02-03T10:01:00+00:00"])
        imp.import_history(str(tmp_path))
        assert {r["provider"] for r in ledger.daily_rows("2000-01-01")} == {"gw.example"}
