"""Belief-starvation latch — formalise hits before more gathering."""
from __future__ import annotations

from agent.belief_starvation import (
    classify_result_as_contact,
    findings_recorded,
    format_starvation_message,
    is_substantive_contact,
    starvation_latched,
    starvation_refusal,
    substantive_contact_count,
    tool_allowed_while_latched,
)


def _table_hit(call_id: int = 1, rows: int = 5) -> dict:
    return {
        "type": "tool_call",
        "call_id": call_id,
        "mcp_tool": "table_table_query",
        "cmd": "table_table_query path=evidence/events.csv",
        "success": True,
        "output": {
            "success": True,
            "matched_rows": rows,
            "returned_rows": min(rows, 50),
            "path": "evidence/events.csv",
        },
    }


def test_substantive_contact_requires_hits():
    assert is_substantive_contact(_table_hit(rows=3))
    zero = _table_hit(rows=0)
    zero["output"] = {
        "success": True, "matched_rows": 0, "valid_zero": True,
    }
    assert not is_substantive_contact(zero)


def test_unknown_columns_is_not_a_contact():
    e = {
        "type": "tool_call",
        "mcp_tool": "table_table_query",
        "success": False,
        "output": {"success": False, "gate": "unknown_columns"},
    }
    assert not is_substantive_contact(e)


def test_parser_success_counts_without_row_field():
    e = {
        "type": "tool_call",
        "mcp_tool": "ez_evtxecmd",
        "cmd": "ez_evtxecmd --file evidence/host/Security.evtx",
        "success": True,
        "output": {"success": True, "csv": "analysis/out.csv"},
    }
    assert is_substantive_contact(e)


def test_latch_engages_after_threshold_with_zero_findings():
    entries = [_table_hit(i, rows=2) for i in range(1, 4)]
    assert substantive_contact_count(entries) == 3
    assert findings_recorded(entries) == 0
    assert starvation_latched(entries) is True


def test_latch_clears_when_finding_recorded():
    entries = [_table_hit(i, rows=2) for i in range(1, 4)]
    entries.append({
        "type": "finding",
        "call_id": 99,
        "description": "user01 created a file on WS01",
        "confidence": "LIKELY",
    })
    assert starvation_latched(entries) is False


def test_successful_record_finding_tool_clears_via_count():
    entries = [_table_hit(i, rows=2) for i in range(1, 4)]
    entries.append({
        "type": "tool_call",
        "mcp_tool": "misc_record_finding",
        "success": True,
        "output": {"success": True},
    })
    assert findings_recorded(entries) >= 1
    assert starvation_latched(entries) is False


def test_multi_host_paths_are_irrelevant_to_latch():
    """Latch is about finding formalisation, not host basenames."""
    a = _table_hit(1, rows=4)
    a["cmd"] = "table_table_query path=evidence/WS01/logs.csv"
    b = _table_hit(2, rows=4)
    b["cmd"] = "table_table_query path=evidence/WS02/logs.csv"
    c = _table_hit(3, rows=4)
    c["cmd"] = "table_table_query path=evidence/WS03/logs.csv"
    assert starvation_latched([a, b, c]) is True


def test_allowed_tools_while_latched():
    assert tool_allowed_while_latched("misc_record_finding")
    assert tool_allowed_while_latched("misc.update_investigation_task")
    assert tool_allowed_while_latched("table_table_schema")
    assert tool_allowed_while_latched("dair_dair_assess")
    assert not tool_allowed_while_latched("table_table_query")
    assert not tool_allowed_while_latched("tsk_tsk_fls")
    assert not tool_allowed_while_latched("img_vmdk_export_raw")


def test_refusal_payload_is_protocol_gate():
    import json
    raw = starvation_refusal("table_table_query", contacts=3)
    data = json.loads(raw)
    assert data["gate"] == "belief_starvation"
    assert data["redirect_to"] == "misc.record_finding"
    assert "record_finding" in data["error"]


def test_format_message_mentions_latch():
    msg = format_starvation_message(contacts=5, findings=0)
    assert "belief-starvation latch" in msg
    assert "record_finding" in msg


def test_classify_result_as_contact_from_loop_payload():
    ok = classify_result_as_contact(
        "table_table_query",
        '{"success": true, "matched_rows": 12, "returned_rows": 12}',
    )
    assert ok is True
    bad = classify_result_as_contact(
        "table_table_query",
        '{"success": false, "gate": "unknown_columns"}',
    )
    assert bad is False


# -- the recording nudge: the unrecorded reads in context, by call id ----------------------------------

from agent.belief_starvation import (  # noqa: E402
    BLANKET_READS,
    RECORD_NUDGE_NAMED,
    RECORD_NUDGE_READS,
    RecordPace,
    shows_rows,
)


def _read(call_id: int, shown: int = 20, matched: int = 300, **extra) -> dict:
    """A table read whose rows the model saw (the view's trace annotation)."""
    e = _table_hit(call_id, rows=matched)
    e.update(view_rows_shown=shown, view_rows_returned=min(matched, 50),
             result_meta={"matched_rows": matched, "returned_rows": min(matched, 50)},
             evidence_ref="evidence/timelines/corp-ws01-supertimeline.csv", **extra)
    return e


def _finding(call_id: int, cites: tuple = ()) -> dict:
    return {"type": "finding", "call_id": call_id, "description": "jane.doe ran svc_kit.exe on CORP-WS01",
            "linked_call_id": cites[0] if cites else 0, "input_call_ids": list(cites[1:])}


def _note(call_id: int, cites: tuple = ()) -> dict:
    return {"type": "investigation_narration", "kind": "disposition", "call_id": call_id,
            "content": "searched, nothing new " + "x" * 400, "input_call_ids": list(cites)}


def _turns(pace: RecordPace, batches: list[list[dict]], suppress: bool = False) -> list:
    """One check per turn on the entries so far; what it said each turn. A
    fresh pace is first checked before any read, as the loop's first turn."""
    entries, said = [], []
    if pace.after is None:
        pace.check([])
    for batch in batches:
        entries += batch
        said.append(pace.check(entries, suppress=suppress))
    return said


def test_the_list_needs_three_unrecorded_reads_over_two_turns():
    said = _turns(RecordPace(), [[_read(i) for i in range(1, 6)], []])
    assert said == [None, None]                       # five reads, one turn
    said = _turns(RecordPace(), [[_read(1), _read(2)], [_read(3)]])
    assert said[0] is None
    assert said[1].startswith("Before the next reads, record what these reads showed that bears on the case")
    assert RECORD_NUDGE_READS == 3


def test_it_names_each_read_by_call_file_and_rows_oldest_first_and_at_most_eight():
    said = _turns(RecordPace(), [[_read(i) for i in range(1, 6)], [_read(i) for i in range(6, 11)]])
    text = said[1]
    assert "- call 1 (corp-ws01-supertimeline.csv): 20 of 300 rows shown" in text
    named = [ln for ln in text.splitlines() if ln.startswith("- call ")]
    assert len(named) == RECORD_NUDGE_NAMED == 8 and named[0].startswith("- call 1 ") \
        and named[-1].startswith("- call 8 ")
    assert "- and 2 later read(s)" in text
    assert "one misc.record_finding per such thing, citing that read's call id" in text
    assert "Routine or baseline activity is not a finding" in text
    assert "needs no finding and leaves this list on its own; a note does not take a read off it" in text
    assert "disposition" not in text and "record_agent_message" not in text


def test_an_accepted_finding_citing_a_read_takes_it_off_and_a_note_or_a_refusal_does_not():
    pace = RecordPace()
    reads = [_read(i) for i in range(1, 9)]
    said = _turns(pace, [reads[:4], reads[4:]])
    assert said[1] and pace.named == (1, 2, 3, 4, 5, 6, 7, 8)
    # A disposition note naming a read rules on what it names: it does not
    # take the read off. A refused record_finding writes no finding entry.
    entries = reads + [_note(9, cites=(1, 2)),
                       {"type": "tool_call", "call_id": 10, "mcp_tool": "misc_record_finding",
                        "cmd": "<py>:misc_record_finding", "success": False, "input_call_ids": [1]}]
    assert pace.check(entries) is None and pace.named == (1, 2, 3, 4, 5, 6, 7, 8)
    # An accepted finding citing reads 1 and 2: they leave the list, the other six keep it.
    text = pace.check(entries + [_finding(11, cites=(1, 2))])
    assert pace.named == (3, 4, 5, 6, 7, 8)
    assert "- call 3 " in text and "- call 1 " not in text and "- call 2 " not in text


def test_the_list_retires_when_its_reads_are_recorded_or_leave_the_conversation():
    pace = RecordPace()
    reads = [_read(i) for i in range(1, 7)]
    said = _turns(pace, [reads[:3], reads[3:]])
    assert said[1]
    # A finding citing four of them: two unrecorded reads in context, under the count.
    assert pace.check(reads + [_finding(7, cites=(1, 2, 3, 4))]) == ""
    pace = RecordPace()
    said = _turns(pace, [reads[:3], reads[3:], [], [], []])
    # Turn 1's reads leave the conversation after four turns (ATLAS_AGENT_KEEP_TOOL_TURNS).
    assert said[1] and said[2] is None and said[3] is None and said[4] == ""


def test_a_read_the_model_saw_no_row_of_is_never_named():
    parse = {"type": "tool_call", "call_id": 3, "mcp_tool": "ez_evtxecmd", "cmd": "ez_evtxecmd --file x.evtx",
             "success": True, "output": {"success": True, "csv": "analysis/out.csv"}}
    bare = _table_hit(4)                      # no view annotation: the model saw no row of it
    assert is_substantive_contact(parse) and is_substantive_contact(bare)   # the latch counts them
    assert not shows_rows(parse) and not shows_rows(bare) and shows_rows(_read(5))
    said = _turns(RecordPace(), [[parse, bare, _read(5)], [_read(6)]])
    assert said == [None, None]               # two row reads, not four contacts


def test_a_finding_citing_four_named_reads_at_once_is_counted_as_blanket():
    pace = RecordPace()
    reads = [_read(i) for i in range(1, 7)]
    _turns(pace, [reads[:3], reads[3:]])
    pace.check(reads + [_finding(7, cites=(1, 2, 3))])
    assert pace.blanket == 0
    pace.check(reads + [_finding(7, cites=(1, 2, 3)), _finding(8, cites=(3, 4, 5, 6))])
    assert pace.blanket == 1 and BLANKET_READS == 4


def test_the_report_phase_or_the_latch_retires_it():
    pace = RecordPace()
    reads = [_read(i) for i in range(1, 6)]
    said = _turns(pace, [reads[:3], reads[3:]])
    assert said[1]
    assert pace.check(reads, suppress=True) == ""


def test_one_action_is_named_by_the_entry_the_model_saw():
    # A plugin run that wrote two entries for one action: the result the model saw is the later one.
    first, seen = _read(10, action_id=3), _read(11, action_id=3)
    entries = [_read(1), _read(2), first, seen, _read(12), _read(13)]
    pace = RecordPace()
    said = _turns(pace, [entries[:4], entries[4:]])
    assert "- call 11 " in said[1] and "- call 10 " not in said[1]
    pace.check(entries + [_finding(14, cites=(10,))])      # cited by the id the model was never shown
    assert pace.cited == {11}


def test_a_resumed_case_with_prior_claims_gets_the_list_never_the_latch(tmp_path):
    from tests.core.test_audit_fixes import _graph_with_claims
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    _graph_with_claims(case, 1)                      # findings from before the resume
    batches = [[_read(i) for i in range(1, 4)], [_read(4), _read(5)]]
    pace, entries = RecordPace(), []
    pace.check([])
    for batch in batches:
        entries += batch
        assert starvation_latched(entries, case_dir=str(case)) is False
        said = pace.check(entries)
    assert said and said.startswith("Before the next reads, record what these reads showed that bears on the case")


def test_a_resumed_log_names_only_this_conversations_reads():
    # a resumed log loads every earlier entry: reads this conversation never showed
    earlier = [_read(i) for i in range(10, 20)]
    pace = RecordPace()
    assert pace.check(earlier) is None                   # the first check: nothing of this conversation yet
    said = _turns(pace, [[_read(20)], [_read(21)], [_read(22)]])
    assert said[0] is None and said[1] is None           # 2 reads of its own, not 12
    assert said[2] and "- call 20 " in said[2] and "- call 19 " not in said[2]


def test_one_grep_call_is_one_contact_judged_by_its_result():
    """The latch counts model calls, not entries. A strings grep writes two
    executor passes and its result entry, all under one action id: one
    contact, judged by the result the model read (the result entry's
    stdout_excerpt, as the middleware writes it). A grep whose result holds
    no hit is no contact, though its passes succeeded. (This pin counted
    three while the count was by entry; the count is by call now, so one
    grep alone no longer brings the latch within one contact of its
    threshold.)"""
    import json

    def grep(action, first_cid, hits):
        passes = [{"type": "tool_call", "call_id": first_cid + i, "action_id": action,
                   "mcp_tool": "strings_strings_grep",
                   "cmd": f"strings -a {flag}-n 4 evidence/CORP-WS01/disk.raw", "success": True,
                   "stdout_excerpt": "line one\nline two"} for i, flag in enumerate(("", "-el "))]
        result = {"type": "tool_call", "call_id": first_cid + 2, "action_id": action,
                  "cmd": "<py>:strings_strings_grep", "success": True,
                  "stdout_excerpt": json.dumps({
                      "success": True, "file": "evidence/CORP-WS01/disk.raw", "pattern": "jane\\.doe",
                      "match_count": hits, "ascii_match_count": hits, "unicode_match_count": 0,
                      "matches": ["jane.doe@example.com"] * hits,
                      "matches_by_pattern": {"jane\\.doe": hits}, "timeout_seconds": 300})}
        return [*passes, result]

    assert substantive_contact_count(grep(7, 21, 2)) == 1
    assert substantive_contact_count(grep(8, 31, 0)) == 0
    assert substantive_contact_count([*grep(7, 21, 2), *grep(8, 31, 0)]) == 1


def test_a_listing_and_extractions_to_files_are_no_contact():
    """A file listing and the export of files show the model no content; the
    reads of the exported files come next and must not be refused on their
    count."""
    entries = [
        {"type": "tool_call", "call_id": 1, "action_id": 1, "mcp_tool": "tsk_tsk_fls",
         "cmd": "fls -r evidence/usb.dd", "success": True},
        {"type": "tool_call", "call_id": 2, "action_id": 2, "mcp_tool": "tsk_tsk_icat",
         "cmd": "icat evidence/usb.dd 4", "success": True},
        {"type": "tool_call", "call_id": 3, "action_id": 3, "mcp_tool": "tsk_tsk_icat",
         "cmd": "icat evidence/usb.dd 6", "success": True},
    ]
    assert substantive_contact_count(entries) == 0
    assert not starvation_latched(entries)
