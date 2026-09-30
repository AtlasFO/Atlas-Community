"""claim.revalidate holds the re-check to the citation test: the cited
calls exist, read evidence (not the run's own words), postdate the review
that questioned the belief, and show what the belief names."""
from __future__ import annotations

from unittest.mock import patch

from core.claim_graph import add_claim, get_node, load_graph, save_graph
from core.dependency_index import mark_needs_review
from tools.claim_tools import revalidate

STATEMENT = ("The scheduled task Updater ran C:\\Windows\\Temp\\ps.exe as SYSTEM "
             "at 2031-02-04 10:54:25")
ROW = "Updater | C:\\Windows\\Temp\\ps.exe | SYSTEM | 2031-02-04 10:54:25 | Ready"
OTHER = ("GoogleUpdateTaskMachineUA | C:\\Program Files\\Google\\Update\\GoogleUpdate.exe "
         "| SYSTEM | 2031-03-01 08:00:00 | Ready")


def _case(tmp_path, *, reviewed=True):
    case = tmp_path / "CASE"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    c = add_claim(case, statement=STATEMENT, confidence="LIKELY", host="WS01")["node_id"]
    if reviewed:
        mark_needs_review(case, [c], reason="upstream evidence added/changed/removed")
    return case, c


def _log(case):
    from core.execution_log import ExecutionLog
    log = ExecutionLog()
    log.configure("T", str(case / "analysis" / "trace.json"), save_session=False)
    log._entries.clear()
    return log


def _read(log, excerpt, cmd="<py>:table_table_query", ref="analysis/ws01_tasks.csv",
          rows=None):
    cid = log.record_tool_call(cmd, True, False, 0, 0, evidence_ref=ref,
                               stdout_excerpt=excerpt)
    if rows is not None:
        log.annotate_tool_call(cid, result_meta={"matched_rows": rows, "returned_rows": rows})
    return cid


def _reviewed_at(case, c, when):
    g = load_graph(case)
    g["nodes"][c]["invalidated_at"] = when
    save_graph(case, g)


def _call(case, log, c, ids):
    with patch("core.execution_log.log", log):
        return revalidate(c, ids, note="task list re-read", case_dir=str(case))


class TestTheGate:
    def test_a_re_read_showing_the_belief_is_accepted(self, tmp_path):
        case, c = _case(tmp_path)
        _reviewed_at(case, c, "2020-01-01T00:00:00Z")
        log = _log(case)
        cid = _read(log, ROW)
        r = _call(case, log, c, [cid])
        assert r["success"], r
        assert get_node(load_graph(case), c)["status"] == "unchanged"

    def test_the_runs_own_words_do_not_count(self, tmp_path):
        case, c = _case(tmp_path)
        _reviewed_at(case, c, "2020-01-01T00:00:00Z")
        log = _log(case)
        cid = _read(log, ROW, cmd="<py>:claim_snapshot")
        r = _call(case, log, c, [cid])
        assert not r["success"] and r["gate"] == "revalidation_citation"
        assert "own words" in r["error"]
        assert get_node(load_graph(case), c)["status"] == "needs_review"

    def test_a_read_made_before_the_review_does_not_count(self, tmp_path):
        case, c = _case(tmp_path)
        log = _log(case)
        cid = _read(log, ROW)
        _reviewed_at(case, c, "2099-01-01T00:00:00Z")
        r = _call(case, log, c, [cid])
        assert not r["success"] and "before the review" in r["error"]

    def test_a_read_showing_nothing_the_belief_names_is_refused(self, tmp_path):
        case, c = _case(tmp_path)
        _reviewed_at(case, c, "2020-01-01T00:00:00Z")
        log = _log(case)
        cid = _read(log, OTHER)
        r = _call(case, log, c, [cid])
        assert not r["success"] and "shows nothing the belief names" in r["error"]
        assert "claim.supersede" in r["error"]

    def test_an_unknown_call_and_a_missing_list_are_refused(self, tmp_path):
        case, c = _case(tmp_path)
        log = _log(case)
        _read(log, ROW)
        assert not _call(case, log, c, [999])["success"]
        r = _call(case, log, c, [])
        assert not r["success"] and "call_ids required" in r["error"]

    def test_a_belief_not_under_review_is_refused(self, tmp_path):
        case, c = _case(tmp_path, reviewed=False)
        log = _log(case)
        cid = _read(log, ROW)
        r = _call(case, log, c, [cid])
        assert not r["success"] and "only a belief under review" in r["error"]

    def test_a_re_read_that_found_nothing_is_refused(self, tmp_path):
        case, c = _case(tmp_path)
        _reviewed_at(case, c, "2020-01-01T00:00:00Z")
        log = _log(case)
        cid = _read(log, '{"where": "run_time = \'2031-02-04 10:54:25\'", "rows": []}', rows=0)
        r = _call(case, log, c, [cid])
        assert not r["success"] and "found nothing" in r["error"]

    def test_a_row_sharing_only_the_timestamp_is_refused(self, tmp_path):
        """The belief names ps.exe; a logon row at the same second shows an
        identifier but not the artifact."""
        case, c = _case(tmp_path)
        _reviewed_at(case, c, "2020-01-01T00:00:00Z")
        log = _log(case)
        cid = _read(log, "4624 | WS01 | jdoe | 2031-02-04 10:54:25 | Interactive",
                    ref="analysis/ws01_security.csv", rows=1)
        r = _call(case, log, c, [cid])
        assert not r["success"] and "ps.exe" in r["error"]

    def test_the_evidence_that_raised_the_review_must_be_read(self, tmp_path):
        from core.claim_graph import load_graph, save_graph
        case, c = _case(tmp_path, reviewed=False)
        mark_needs_review(case, [c], reason="upstream evidence added/changed/removed",
                          dirty={"changed": ["analysis/ws01_tasks.csv"]})
        _reviewed_at(case, c, "2020-01-01T00:00:00Z")
        log = _log(case)
        elsewhere = _read(log, ROW, ref="analysis/ws01_tasks_old.csv", rows=1)
        r = _call(case, log, c, [elsewhere])
        assert not r["success"] and "added or changed" in r["error"]
        fresh = _read(log, ROW, rows=1)
        assert _call(case, log, c, [fresh])["success"]

    def test_a_legacy_node_falls_back_to_its_update_time(self, tmp_path):
        from core.claim_graph import load_graph, save_graph
        case, c = _case(tmp_path)
        log = _log(case)
        cid = _read(log, ROW, rows=1)
        g = load_graph(case)
        g["nodes"][c].pop("invalidated_at", None)
        g["nodes"][c]["updated_at"] = "2099-01-01T00:00:00Z"
        save_graph(case, g)
        r = _call(case, log, c, [cid])
        assert not r["success"] and "before the review" in r["error"]

    def test_a_naive_timestamp_is_read_as_utc(self, tmp_path):
        case, c = _case(tmp_path)
        _reviewed_at(case, c, "2020-01-01T00:00:00")
        log = _log(case)
        cid = _read(log, ROW, rows=1)
        assert _call(case, log, c, [cid])["success"]

    def test_an_unknown_call_is_named_in_the_verbs_own_words(self, tmp_path):
        case, c = _case(tmp_path)
        log = _log(case)
        _read(log, ROW)
        r = _call(case, log, c, [999])
        assert not r["success"] and "not in the trace" in r["error"] and r["unknown_cids"] == [999]

    def test_a_windows_spelled_path_in_the_call_still_counts(self, tmp_path):
        case, c = _case(tmp_path, reviewed=False)
        mark_needs_review(case, [c], reason="upstream evidence added/changed/removed",
                          dirty={"changed": ["analysis/ws01_tasks.csv"]})
        _reviewed_at(case, c, "2020-01-01T00:00:00Z")
        log = _log(case)
        cid = _read(log, ROW, ref="analysis\\ws01_tasks.csv", rows=1)
        assert _call(case, log, c, [cid])["success"]

