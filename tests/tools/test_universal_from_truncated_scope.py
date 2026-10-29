"""A statement about all rows rests on the calls that read the artifact it
is about; an incomplete view of some other artifact does not refuse it, and
the refusal says exactly what the analyst was not shown."""
from __future__ import annotations

from types import SimpleNamespace

from tools._gates import GateContext
from tools._gates import universal_from_truncated as g


def _ctx(description, entries, cited, supporting=""):
    return GateContext(
        description=description, confidence="LIKELY", tier="LIKELY",
        source="test", linked_call_id=0, tested_hypothesis_id="", log=None,
        idx=SimpleNamespace(by_call_id=entries), window=[],
        input_call_ids=cited, supporting_evidence=supporting)


CUT_MFT = {"type": "tool_call", "cmd": "<py>:table_table_query",
           "args": '{"path": "analysis/mft.csv"}', "view_truncated": True,
           "view_omitted_chars": 4200, "stdout_file": "/case/analysis/tool-output/q.stdout"}
FULL_SYNC = {"type": "tool_call", "cmd": "<py>:strings_read_text",
             "evidence_ref": "fs/Users/u/sync_log.log",
             "stdout_excerpt": "RawEvent(CREATE, holiday.jpg)"}


def test_a_cut_view_of_another_artifact_does_not_refuse():
    r = g.check(_ctx("sync_log.log records only two files, holiday.jpg and song.mp3",
                     {1: FULL_SYNC, 2: CUT_MFT}, [1, 2]))
    assert r is None


def test_a_cut_view_of_the_artifact_the_claim_is_about_refuses():
    r = g.check(_ctx("mft.csv lists only desktop.ini in the sync folder",
                     {1: FULL_SYNC, 2: CUT_MFT}, [1, 2]))
    assert r is not None and r["incomplete_call_id"] == 2


def test_without_artifact_names_every_cited_cut_view_counts():
    """Nothing to compare: the conservative reading stands."""
    r = g.check(_ctx("no network logons were observed", {2: CUT_MFT}, [2]))
    assert r is not None and r["incomplete_call_id"] == 2


def test_the_refusal_names_what_was_not_shown():
    r = g.check(_ctx("mft.csv lists only desktop.ini", {2: CUT_MFT}, [2]))
    err = r["error"]
    assert "4200 characters" in err
    assert "the tool itself returned everything" in err
    # A table tool's result is narrowed, never searched through its spilled
    # JSON (the wrong input kind for a text grep).
    assert "q.stdout" not in err and "where=" in err and "pattern=<term>" not in err and "wrong input kind" in err
    assert "cut short" not in err


def test_tool_side_truncation_is_still_its_own_reason():
    entry = {**CUT_MFT, "view_truncated": False, "truncated": True}
    assert g.incomplete_reason(entry) == "its output was truncated"


CUT_SNAPSHOT = {"type": "tool_call", "cmd": "<py>:claim_snapshot",
                "view_truncated": True, "view_omitted_chars": 40350,
                "stdout_file": "/case/analysis/tool-output/snap.stdout"}


def test_a_cut_view_of_the_runs_own_state_is_not_a_refusal_ground():
    """A claim snapshot holds the analyst's own beliefs, not evidence rows;
    however much of it the conversation left out, no unseen row can
    contradict a statement of absence."""
    r = g.check(_ctx("no second principal or alternate controller was identified",
                     {3: CUT_SNAPSHOT}, [3]))
    assert r is None
    r = g.check(_ctx("no second principal or alternate controller was identified",
                     {2: CUT_MFT, 3: CUT_SNAPSHOT}, [3, 2]))
    assert r is not None and r["incomplete_call_id"] == 2


def test_negative_from_truncated_ignores_the_runs_own_state():
    from tools._gates import negative_from_truncated as n
    ctx = GateContext(
        description="no other actor was identified", confidence="UNCONFIRMED",
        tier="UNCONFIRMED", source="test", linked_call_id=3, tested_hypothesis_id="",
        log=None, idx=SimpleNamespace(by_call_id={3: {**CUT_SNAPSHOT, "truncated": True}}),
        window=[], input_call_ids=[3], supporting_evidence="")
    assert n.check(ctx) is None


CUT_LNK = {"type": "tool_call", "cmd": "dotnet LECmd.dll -d mnt/host/fs/Users",
           "args": '{"directory": "mnt/host/fs/Users"}', "view_truncated": True,
           "view_omitted_chars": 9000, "stdout_excerpt": "Target: Plan.docx"}
FULL_EVTX = {"type": "tool_call", "cmd": "<py>:evtx_query",
             "args": '{"path": "mnt/host/fs/Windows/System32/winevt/Logs/Security.evtx", '
                     '"event_id": 1102}',
             "stdout_excerpt": "matched_rows: 0"}
CUT_EVTX = {**FULL_EVTX, "view_truncated": True, "view_omitted_chars": 5000}


def _ctx_analyst(description, entries, lineage, analyst):
    ctx = _ctx(description, entries, lineage)
    ctx.analyst_call_ids = analyst
    return ctx


NEGATIVE_WITHOUT_ARTIFACT = ("LNK files still point to Plan.docx on the share. "
                             "No log-clear events were recorded.")


def test_a_call_atlas_added_to_the_lineage_is_no_basis_for_a_negative():
    """The auto-fill or the lineage repair cites a call that holds what the
    finding names; the analyst did not rest the absence on it and cannot
    remove it."""
    r = g.check(_ctx_analyst(NEGATIVE_WITHOUT_ARTIFACT, {1: FULL_EVTX, 2: CUT_LNK}, [1, 2], [1]))
    assert r is None


def test_without_citations_of_its_own_the_inferred_lineage_is_judged():
    r = g.check(_ctx_analyst(NEGATIVE_WITHOUT_ARTIFACT, {1: FULL_EVTX, 2: CUT_LNK}, [1, 2], []))
    assert r is not None and r["incomplete_call_id"] == 2


def test_the_same_call_cited_by_the_analyst_still_refuses():
    r = g.check(_ctx(NEGATIVE_WITHOUT_ARTIFACT, {1: FULL_EVTX, 2: CUT_LNK}, [1, 2]))
    assert r is not None and r["incomplete_call_id"] == 2


def test_a_negative_sentence_is_judged_on_the_artifacts_it_names():
    desc = "LNK files still point to Plan.docx on the share. Security.evtx holds no 1102 events."
    assert g.check(_ctx(desc, {1: FULL_EVTX, 2: CUT_LNK}, [1, 2])) is None
    r = g.check(_ctx(desc, {1: CUT_EVTX, 2: CUT_LNK}, [1, 2]))
    assert r is not None and r["incomplete_call_id"] == 1


def test_a_negative_with_no_narrower_wording_names_its_words_instead(monkeypatch):
    monkeypatch.setenv("ATLAS_UNIVERSAL_GATE_V2", "0")  # the plain path, kept behind the switch
    desc = "Extraction of the stream from capture.pcap was not successful."
    cut_pcap = {**CUT_MFT, "args": '{"path": "analysis/capture.pcap"}'}
    r = g.check(_ctx(desc, {2: cut_pcap}, [2]))
    assert r is not None and "suggested_rewrite" not in r
    assert "'was not'" in r["error"] and desc[:40] in r["error"]


def test_a_rewrite_that_differs_only_in_punctuation_is_no_rewrite(monkeypatch):
    monkeypatch.setenv("ATLAS_UNIVERSAL_GATE_V2", "0")  # the plain path, kept behind the switch
    desc = "Extraction of the stream from capture.pcap was not successful,  "
    cut_pcap = {**CUT_MFT, "args": '{"path": "analysis/capture.pcap"}'}
    r = g.check(_ctx(desc, {2: cut_pcap}, [2]))
    assert r is not None and "suggested_rewrite" not in r


def test_a_universal_that_can_be_narrowed_keeps_its_suggestion(monkeypatch):
    monkeypatch.setenv("ATLAS_UNIVERSAL_GATE_V2", "0")  # the plain path, kept behind the switch
    r = g.check(_ctx("mft.csv lists all files in the sync folder", {2: CUT_MFT}, [2]))
    assert r["suggested_rewrite"] == "mft.csv lists the observed files in the sync folder"


CUT_SYNC = {**FULL_SYNC, "view_truncated": True, "view_omitted_chars": 3000}
FULL_LNK = {**CUT_LNK, "view_truncated": False, "view_omitted_chars": 0}


def test_known_gap_an_inferred_truncated_basis_of_another_clause_is_not_judged():
    """Tracked trade-off: the analyst cites the call for one clause; a cut
    view that reached the lineage only through Atlas's inference is the other
    clause's real basis, and it is not judged. Judging inferred ids left the
    analyst no way to record a true finding at all."""
    desc = "LNK files name Plan.docx. sync_log.log lists no uploads."
    r = g.check(_ctx_analyst(desc, {1: FULL_LNK, 2: CUT_SYNC}, [1, 2], [1]))
    assert r is None


def test_an_abbreviation_only_widens_the_scope():
    """A sentence split at "e.g." falls back to the whole finding, the old
    and wider scope, never a narrower one."""
    desc = "No events were recorded in the logs, e.g. Security.evtx and the rest."
    r = g.check(_ctx(desc, {1: CUT_EVTX}, [1]))
    assert r is not None and r["incomplete_call_id"] == 1


def test_a_bounded_table_scan_is_not_a_complete_view():
    """A scan stopped at a row bound saw only the head of the file, whether
    the result says so in its flags or only by the row count it stopped at."""
    from core.middleware import _result_meta
    from tools._gates.universal_from_truncated import incomplete_reason
    meta = _result_meta({"success": True, "hit_count": 0, "scan_capped": True,
                         "scanned_rows": 5, "scan_capped_at": 5})
    assert meta == {"hit_count": 0, "scan_capped": True, "scanned_rows": 5}
    assert incomplete_reason({"result_meta": meta}) == \
        "it scanned only the first 5 rows of the file"
    count_only = {"stdout_excerpt": '{"hit_count": 0, "scan_capped_at": 200000}'}
    assert "first 200000 rows" in incomplete_reason(count_only)
    assert incomplete_reason({"result_meta": {"scan_capped": False, "scanned_rows": 9}}) == ""
    assert incomplete_reason({"result_meta": {"hit_count": 50, "max_hits": 50}}) == \
        "it stopped at the 50-hit cap"


def test_a_view_entry_says_how_many_rows_were_shown_and_a_complete_view_withholds_nothing():
    from tools._gates.universal_from_truncated import incomplete_reason, rest_of_result_hint
    shown = {"cmd": "<py>:table_table_grep", "view_rows_returned": 50, "view_rows_shown": 12,
             "view_truncated": True, "view_omitted_rows": 38, "result_meta": {"hit_count": 50, "max_hits": 50}}
    assert incomplete_reason(shown) == "the analyst was shown 12 of the 50 rows the tool returned"
    complete = {"cmd": "<py>:table_table_grep", "view_rows_returned": 29, "view_rows_shown": 29,
                "view_complete": True, "result_meta": {"hit_count": 29, "max_hits": 50}}
    assert incomplete_reason(complete) == ""
    old = {"cmd": "<py>:table_table_grep", "view_truncated": True, "view_omitted_chars": 900}
    assert "900 characters" in incomplete_reason(old)
    # The hint for a table result narrows the call; it never sends a text
    # grep over the spilled JSON.
    hint = rest_of_result_hint(shown, "analysis/tool-output/table_table_grep-7.json", 7)
    assert "pattern=<term>" in hint and "table.table_grep" not in hint.split("wrong input kind")[0].replace(
        "table.table_pivot", "")
    executor = rest_of_result_hint({"cmd": "strings -a evidence/mem.raw"}, "analysis/tool-output/strings-8.txt", 8)
    assert "strings-8.txt" in executor and "strings.strings_grep" in executor
    # Only parameters and result fields the tool has: table_grep has no
    # matched_rows or where=, and time_start= only with the time arguments; the strings
    # and search views their own. Paging and a file of every row are never
    # the way to the rest.
    assert "matched_rows" not in hint and "where=" not in hint
    assert "time_start=" in hint and "offset=" not in hint and "output_csv" not in hint
    import os
    os.environ["ATLAS_TABLE_TIME_ARGS"] = "0"
    try:
        off = rest_of_result_hint(shown, "", 7)
        assert "pattern=<term>" in off and "time_start=" not in off
    finally:
        del os.environ["ATLAS_TABLE_TIME_ARGS"]
    query = rest_of_result_hint({"cmd": "<py>:table_table_query"}, "", 9)
    assert "matched_rows" in query and "where=" in query and "table.table_pivot" in query
    assert "time_start=" in query and "offset=" not in query and "output_csv" not in query
    strings_view = rest_of_result_hint({"cmd": "<py>:strings_strings_grep", "view_rows_shown": 5}, "", 10)
    assert "pattern=<p>" in strings_view and "where=" not in strings_view and "offset=" not in strings_view
    search_view = rest_of_result_hint({"cmd": "<py>:search_search_evidence", "view_rows_shown": 5}, "", 11)
    assert "query=<term>" in search_view and "tool=<name>" in search_view and "where=" not in search_view


# ── ATLAS_UNIVERSAL_GATE_V2: no rewrite, the sentence named, the count first ──

import pytest  # noqa: E402


def test_v2_names_the_sentence_and_asks_for_the_count_without_a_rewrite():
    desc = "mft.csv lists all files in the sync folder. The folder holds desktop.ini."
    r = g.check(_ctx(desc, {2: CUT_MFT}, [2]))
    assert r is not None and "suggested_rewrite" not in r
    err = r["error"]
    assert "The sentence 'mft.csv lists all files in the sync folder.' states something about every row" in err
    assert "call 2 (<py>:table_table_query) is not a complete view" in err
    assert "Count first: narrow the call so every matching row is returned" in err
    assert "Then record what the count shows" in err and "leave call 2 out" in err
    assert "the observed" not in err


def test_v2_names_every_universal_sentence_and_the_absence():
    desc = "mft.csv lists only desktop.ini. No other files were found in mft.csv."
    r = g.check(_ctx(desc, {2: CUT_MFT}, [2]))
    err = r["error"]
    assert err.startswith("The sentences 'mft.csv lists only desktop.ini.' states something about every row; "
                          "'No other files were found in mft.csv.' states an absence")


def test_v2_routes_a_prescription_to_the_recommendations():
    desc = "Reset every account in mft.csv."
    r = g.check(_ctx(desc, {2: CUT_MFT}, [2]))
    err = r["error"]
    assert "is a recommendation, not a statement about the evidence" in err
    assert "claim.add_recommendation(action=..., basis_ids=" in err
    assert "Count first" not in err


def test_v2_a_mixed_finding_gets_both_remedies():
    desc = "mft.csv lists all files in the sync folder. Every file in mft.csv should be quarantined."
    err = g.check(_ctx(desc, {2: CUT_MFT}, [2]))["error"]
    assert "Count first" in err and "claim.add_recommendation" in err


def test_v2_a_complete_view_refuses_nothing():
    full = {**CUT_MFT, "view_truncated": False, "view_omitted_chars": 0, "view_complete": True}
    assert g.check(_ctx("Reset every account in mft.csv.", {2: full}, [2])) is None


@pytest.mark.parametrize("sentence", [
    "Reset every account.",
    "Every domain password should be rotated.",
    "CORP must reset every domain password, not only affected accounts.",
    "Block every address in the indicator list at the perimeter.",
    "The team should isolate all three workstations.",
    "Alle Konten sollten zurückgesetzt werden.",
])
def test_is_prescription_accepts_recommendations(sentence):
    assert g.is_prescription(sentence)


@pytest.mark.parametrize("sentence", [
    "All accounts were compromised and must be reset.",
    # a modal frame launders no fact
    "It should be noted that every workstation beaconed to 203.0.113.9.",
    "Responders must assume all hosts were accessed by the operator.",
    "We recommend treating CORP-WS01 as the only host the attacker reached.",
    "No account shows a logon.",
    "All logons were interactive; no network logons were detected.",
    # (e): a comma and a complementiser end the prescription's clause
    "Reset every account, as every host was compromised.",
    # (e): a modal followed by a state or epistemic verb states, it does not prescribe
    "The logs should show every logon.",
    "Every host should be considered the origin.",
    "Not all hosts were reached.",
])
def test_is_prescription_refuses_statements(sentence):
    assert not g.is_prescription(sentence)


# The analyst's own claim (analysts_words): a reported condition and the
# run's own progress are no statement about rows; an absence about the
# evidence stays judged, also with a reading verb. Invented wording.
CUT_LISTING = {"type": "tool_call", "cmd": "<py>:tsk_tsk_index_find",
               "args": '{"pattern": "README"}', "view_truncated": True, "view_omitted_chars": 5000,
               "stdout_excerpt": "Users/jane.doe/Desktop/README_RESTORE.txt"}
FULL_TEXT = {"type": "tool_call", "cmd": "<py>:strings_read_text",
             "args": '{"file_path": "analysis/extracted/README_RESTORE.txt"}',
             "stdout_excerpt": "your files are copied and locked"}


def test_a_note_finding_with_a_condition_and_a_progress_sentence_is_not_refused():
    desc = ("The memo README_RESTORE.txt on CORP-WS01 says the share was archived and will be purged if no "
            "owner replies, and names a ticket. The archive claim is the memo's own statement; no copy "
            "record has been examined so far.")
    assert g.check(_ctx(desc, {1: CUT_LISTING, 2: FULL_TEXT}, [1, 2])) is None


@pytest.mark.parametrize("sentence", [
    "The mail README_RESTORE.txt was not read by the user.",
    "No README_RESTORE.txt was opened.",
    "No README_RESTORE.txt was recovered.",
    "No README_RESTORE.txt file is on the Desktop.",
])
def test_an_absence_about_the_evidence_with_a_reading_verb_stays_judged(sentence):
    assert g.check(_ctx(sentence, {1: CUT_LISTING}, [1])) is not None


@pytest.mark.parametrize("sentence", [
    # a leading condition with no comma keeps its main clause and the absence in it
    "If the share had been copied out the proxy log would show it and it shows no such upload.",
    # a reading verb as an adjective or a postposed participle, with an evidence predicate
    "No upload was found yet in the examined proxy logs.",
    "No outbound transfer appears in the proxy logs reviewed so far.",
    # an evidence predicate beside a reading verb with its auxiliary: still a claim about the logs
    "No upload was seen in the proxy logs that were reviewed so far.",
])
def test_an_absence_over_examined_evidence_is_no_progress_statement(sentence):
    assert g.is_universal_or_negative(sentence)


def test_an_active_clause_with_a_marker_is_the_evidence_not_the_runs_progress():
    """A marker rescues a passive predicate only ("has not been read yet"); an
    active clause names its own subject, and "yet" makes it no progress
    statement of the analyst."""
    kept = g.analysts_words("The user has not opened the attachment yet.")
    assert "opened" in kept and "user" in kept
    assert "examined" not in g.analysts_words("No copy record has been examined so far.")
