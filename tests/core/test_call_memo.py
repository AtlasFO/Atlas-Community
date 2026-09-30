"""The run-wide call memo: one key per question, answers kept for the run."""
import json
import os

from core.call_memo import (
    CallMemo, call_key, canonical_args, memoable, render_index,
)


def _case(tmp_path):
    case = tmp_path / "case"
    (case / "evidence").mkdir(parents=True)
    (case / "evidence" / "disk.dd").write_bytes(b"\x00" * 64)
    return case


def test_relative_and_absolute_spellings_share_one_key(tmp_path):
    case = _case(tmp_path)
    rel = call_key("strings_strings_grep",
                   {"path": "evidence/disk.dd", "pattern": "x"}, case)
    absolute = call_key("strings_strings_grep",
                        {"path": str(case / "evidence" / "disk.dd"), "pattern": "x"}, case)
    dotted = call_key("strings_strings_grep",
                      {"path": str(case / "evidence" / ".." / "evidence" / "disk.dd"),
                       "pattern": "x "}, case)
    assert rel == absolute == dotted


def test_different_pattern_is_a_different_key(tmp_path):
    case = _case(tmp_path)
    a = call_key("strings_strings_grep", {"path": "evidence/disk.dd", "pattern": "x"}, case)
    b = call_key("strings_strings_grep", {"path": "evidence/disk.dd", "pattern": "y"}, case)
    assert a != b


def test_changed_input_file_is_a_new_question(tmp_path):
    case = _case(tmp_path)
    before = call_key("table_table_query", {"csv_path": "evidence/disk.dd"}, case)
    target = case / "evidence" / "disk.dd"
    target.write_bytes(b"\x00" * 65)
    os.utime(target, ns=(1, 1))
    after = call_key("table_table_query", {"csv_path": "evidence/disk.dd"}, case)
    assert before != after


def test_private_and_empty_arguments_do_not_matter(tmp_path):
    case = _case(tmp_path)
    a = call_key("tsk_tsk_fls", {"image_path": "evidence/disk.dd",
                                 "_atlas_call_id": 4, "offset": ""}, case)
    b = call_key("tsk_tsk_fls", {"image_path": "evidence/disk.dd"}, case)
    assert a == b


def test_nonexistent_paths_are_kept_verbatim(tmp_path):
    canon, paths = canonical_args({"path": "evidence/missing.bin", "pattern": "a/b"},
                                  tmp_path)
    assert canon == {"path": "evidence/missing.bin", "pattern": "a/b"}
    assert paths == []


def test_a_tools_own_output_file_does_not_change_the_question(tmp_path):
    case = _case(tmp_path)
    (case / "analysis").mkdir()
    args = {"storage_file": "evidence/disk.dd", "output_path": "analysis/timeline.csv"}
    before = call_key("plaso_psort", args, case)
    (case / "analysis" / "timeline.csv").write_text("produced")
    after = call_key("plaso_psort", args, case)
    assert before == after


def test_directory_reads_are_not_kept(tmp_path):
    case = _case(tmp_path)
    memo = CallMemo(case)
    args = {"path": "evidence"}
    assert memo.put(memo.key("misc_list_evidence_dir", args), turn=1,
                    tool_call_id="t1", tool="misc_list_evidence_dir",
                    args=args, result="{}") is None
    assert len(memo) == 0


def test_a_refusal_is_remembered_by_call_and_gate(tmp_path):
    case = _case(tmp_path)
    memo = CallMemo(case)
    args = {"description": "x", "input_call_ids": [3]}
    key = memo.key("misc_record_finding", args)
    first = memo.refused(key, "some_gate", turn=4)
    assert first.hits == 1 and first.turn == 4
    again = memo.refused(memo.key("misc_record_finding", dict(args)),
                         "some_gate", turn=9)
    assert again is first and again.hits == 2 and again.turn == 4
    # Another gate, or other arguments, is another refusal.
    assert memo.refused(key, "other_gate", turn=10).hits == 1
    assert memo.refused(memo.key("misc_record_finding", {"description": "y"}),
                        "some_gate", turn=11).hits == 1
    assert len(memo) == 0   # refusals are not successful answers


def test_volatile_namespaces_are_not_memoable():
    for name in ("live_live_processes", "monitor_check_alerts", "job_job_wait",
                 "search_search_evidence", "correlate_process_to_file",
                 "enrich_enrichment_status", "export_export_iocs",
                 "misc_list_findings"):
        assert not memoable(name), name
    for name in ("strings_strings_grep", "net_ngrep_search", "tsk_tsk_fls",
                 "table_table_query", "hash_hash_file", "enrich_vt_lookup_hash",
                 "misc_evtx_filter"):
        assert memoable(name), name


def test_memo_keeps_every_call_and_reads_the_trace_call_id(tmp_path):
    case = _case(tmp_path)
    memo = CallMemo(case)
    for i in range(200):
        args = {"path": "evidence/disk.dd", "pattern": f"p{i}"}
        memo.put(memo.key("strings_strings_grep", args), turn=i,
                 tool_call_id=f"tc{i}", tool="strings_strings_grep", args=args,
                 result=json.dumps({"success": True, "_atlas_call_id": 100 + i}))
    assert len(memo) == 200
    hit = memo.get(memo.key("strings_strings_grep",
                            {"path": str(case / "evidence" / "disk.dd"), "pattern": "p7"}))
    assert hit is not None and hit.turn == 7 and hit.trace_call_id == "107"
    assert hit.target == "evidence/disk.dd" and "pattern=p7" in hit.detail


def test_index_is_bounded_and_names_open_questions(tmp_path):
    case = _case(tmp_path)
    memo = CallMemo(case)
    for i in range(50):
        args = {"image_path": "evidence/disk.dd", "inode": i}
        memo.put(memo.key("tsk_tsk_icat", args), turn=i, tool_call_id=f"tc{i}",
                 tool="tsk_tsk_icat", args=args, result="{}")
    memo.replays = 3
    text = render_index(memo, findings=4, limit=10,
                        tasks=[{"id": "T-001", "status": "answered"},
                               {"id": "T-002", "status": "open"}],
                        pivots_open=2)
    lines = text.splitlines()
    assert sum(1 for line in lines if line.startswith("  call")) == 10
    assert "40 earlier calls" in text
    assert "inode=49" in lines[3]
    assert "questions closed: 1/2" in text and "open: T-002" in text
    assert "findings recorded: 4" in text
    assert "indicators not yet searched: 2" in text
    assert "repeats answered from memory: 3" in text


class TestTheIndexCarriesTheBeliefs:
    """A compacted conversation stops carrying what the run concluded, and a
    count of beliefs is not the beliefs: a model holding only the number
    rebuilds the statements from prose that no longer contains them, while
    the statements themselves sit unread in the claim graph."""

    def _memo(self):
        from core.call_memo import CallMemo
        return CallMemo()

    def test_statements_are_restated_not_just_counted(self):
        from core.call_memo import render_index
        claims = [
            {"id": "C0001", "confidence": "CONFIRMED",
             "statement": "Account gnome authenticated from 137.30.122.253"},
            {"id": "C0002", "confidence": "LIKELY",
             "statement": "Archive transferred over FTP"},
        ]
        text = render_index(self._memo(), findings=2, claims=claims)
        assert "C0001" in text and "C0002" in text
        assert "Account gnome authenticated" in text
        assert "[CONFIRMED]" in text and "[LIKELY]" in text

    def test_a_belief_stays_challengeable(self):
        """Rendered with its id and tier, so it reads as something recorded
        that can be revisited, not as a settled fact gaining authority by
        being repeated every few turns."""
        from core.call_memo import render_index
        text = render_index(self._memo(),
                            claims=[{"id": "C0009", "statement": "Drive wiped",
                                     "confidence": "SUSPECTED"}])
        line = next(ln for ln in text.splitlines() if "C0009" in ln)
        assert "[SUSPECTED]" in line
        assert "your own beliefs" in text

    def test_the_list_is_bounded_and_says_where_the_rest_is(self):
        from core.call_memo import render_index
        claims = [{"id": "C%04d" % i, "statement": "belief %d" % i,
                   "confidence": "LIKELY"} for i in range(40)]
        text = render_index(self._memo(), claims=claims, claims_limit=5)
        assert sum(1 for ln in text.splitlines() if ln.startswith("  C")) == 5
        assert "35 more in misc.current_investigation_state" in text

    def test_a_long_statement_is_trimmed(self):
        from core.call_memo import render_index, _CLAIM_CHARS
        text = render_index(self._memo(),
                            claims=[{"id": "C1", "statement": "x" * 900,
                                     "confidence": "LIKELY"}])
        line = next(ln for ln in text.splitlines() if ln.startswith("  C1"))
        assert len(line) < _CLAIM_CHARS + 40
        assert line.endswith("…")

    def test_no_claims_renders_no_belief_block(self):
        from core.call_memo import render_index
        text = render_index(self._memo(), findings=0, claims=[])
        assert "your own beliefs" not in text

    def test_state_is_named_before_evidence_search(self):
        """After a compaction the run's own state is the first thing needed,
        and it is on disk. Naming only an evidence search sent one run to
        search many times and read its own state none."""
        from core.call_memo import render_index
        text = render_index(self._memo(), findings=1)
        assert "misc.current_investigation_state" in text
        assert (text.index("misc.current_investigation_state")
                < text.index("search.search_evidence"))


def test_the_trace_id_is_read_from_the_tail_of_a_long_result(tmp_path):
    """The executor stamps its call id after the tool's output; a listing
    that leads with several thousand characters of stdout used to leave the
    memo without the id, so a later pointer could name no trace call."""
    from core.call_memo import CallMemo
    memo = CallMemo(str(tmp_path))
    result = '{"success": true, "stdout": "' + ("r/r 1-128-1: a.txt\\n" * 300) + \
             '", "truncated": true, "_atlas_call_id": 157}'
    entry = memo.put(memo.key("tsk_fls", {"image": "mnt/x/ewf1", "inode": 344}),
                     turn=51, tool_call_id="c1", result=result, tool="tsk_fls",
                     args={"image": "mnt/x/ewf1", "inode": 344})
    assert entry is not None and entry.trace_call_id == "157"
