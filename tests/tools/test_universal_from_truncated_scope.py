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


CUT_MFT = {"type": "tool_call", "cmd": "<py>:table_query",
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
    assert "/case/analysis/tool-output/q.stdout" in err
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


def test_a_negative_with_no_narrower_wording_names_its_words_instead():
    desc = "Extraction of the stream from capture.pcap was not successful."
    cut_pcap = {**CUT_MFT, "args": '{"path": "analysis/capture.pcap"}'}
    r = g.check(_ctx(desc, {2: cut_pcap}, [2]))
    assert r is not None and "suggested_rewrite" not in r
    assert "'was not'" in r["error"] and desc[:40] in r["error"]


def test_a_rewrite_that_differs_only_in_punctuation_is_no_rewrite():
    desc = "Extraction of the stream from capture.pcap was not successful,  "
    cut_pcap = {**CUT_MFT, "args": '{"path": "analysis/capture.pcap"}'}
    r = g.check(_ctx(desc, {2: cut_pcap}, [2]))
    assert r is not None and "suggested_rewrite" not in r


def test_a_universal_that_can_be_narrowed_keeps_its_suggestion():
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
