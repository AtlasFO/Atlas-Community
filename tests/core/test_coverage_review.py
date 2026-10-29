"""A recount that moves an image (core.coverage_ledger.rederive_container_coverage)
puts the beliefs that state its coverage under review, and only those: a
coverage word next to a word for the image, or a gap or absence clause
resting on the image, in a belief that points at that image (rests on it,
names its host or its unique file name, or names no host at all)."""
from __future__ import annotations

import json

import pytest

from core import coverage_ledger as cl
from core import evidence_items as ei
from core.claim_graph import add_claim, add_node, get_node, load_graph, save_graph
from core.dependency_index import (
    COVERAGE_REVIEW_NOTE,
    coverage_corrected,
    mark_needs_review,
)

WS1, WS2, WS3 = (f"evidence/hosts/CORP-WS0{i}/disk.dd" for i in (1, 2, 3))
MEM = "evidence/hosts/CORP-WS01/CORP-WS01.mem"
TIMELINE = "evidence/supertimeline.csv"
LINKS = """## Evidence Links

| Label | Kind | Path | Notes |
|-------|------|------|-------|
| CORP-WS01 | disk | evidence/hosts/CORP-WS01 | |
| CORP-WS02 | disk | evidence/hosts/CORP-WS02 | |
| CORP-WS03 | disk | evidence/hosts/CORP-WS03 | |
"""


def _make_case(tmp_path, links=LINKS, images=(WS1, WS2, WS3, MEM), requests=""):
    d = tmp_path / "CASE-A"
    for rel in images:
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_bytes(b"\0" * 4096)
    (d / TIMELINE).write_text("time,host,event\n2031-03-04 10:12:00,CORP-WS01,logon\n",
                              encoding="utf-8")
    (d / ".atlas").mkdir(exist_ok=True)
    (d / ".atlas" / "evidence_inventory.json").write_text(
        json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
    (d / "CASE.md").write_text("**Case ID** CASE-A\n\n" + requests + links, encoding="utf-8")
    cl.build_coverage_ledger(d)
    from core.evidence_links import sync_evidence_links
    sync_evidence_links(d, persist=True)
    return d


@pytest.fixture
def case(tmp_path):
    return _make_case(tmp_path)


def _set(case, rel, unit_status, item_status, **item):
    led = cl.load_ledger(case)
    for u in led["units"].values():
        if u["path"] == rel:
            u["status"] = unit_status
    ei.find(led, rel).update(status=item_status, **item)
    cl.save_ledger(case, led)


def _trace(case, entries):
    (case / "analysis").mkdir(exist_ok=True)
    (case / "analysis" / "CASE-A_trace.json").write_text(
        json.dumps({"case_id": "CASE-A", "entries": entries}), encoding="utf-8")


def _call(cid, tool, ok=True, **args):
    entry = {"type": "tool_call", "call_id": cid, "cmd": f"<py>:{tool}",
             "args": json.dumps(args, sort_keys=True), "success": ok,
             "ts": "2031-03-05T09:00:00Z"}
    if not ok:
        entry.update(failure_class="tool_error", stderr="Invalid magic value")
    return entry


# The two disk images of CORP-WS01 and CORP-WS02 were counted blocked with no
# failed read of them; CORP-WS03's read failed (it stays blocked); a mark,
# a timeline search and a filesystem listing of CORP-WS01 are in the trace.
MARK_WS1 = _call(3, "coverage_mark_blocked", path=WS1, reason="filesystem does not open")
FAILED_WS3 = _call(4, "tsk_tsk_fsstat", ok=False, image=WS3, offset_sectors=63)
TIMELINE_GREP = _call(6, "table_table_grep", path=TIMELINE, pattern="jane.doe")
LISTING_WS1 = _call(8, "tsk_tsk_fls", image=WS1, offset_sectors=63)


def _blocked_without_failed_reads(case):
    for rel in (WS1, WS2, WS3):
        _set(case, rel, "blocked", "blocked", blocked_reason="blocked by the fixture")
    _trace(case, [MARK_WS1, FAILED_WS3, TIMELINE_GREP, LISTING_WS1])


def _belief(case, statement, *, host="", cites=(), gaps=None):
    node = add_claim(case, statement, host=host, gaps=gaps, enforce_validation=False,
                     evidence=[{"artifact": "tool output", "call_id": c} for c in cites])
    nid = node["node_id"]
    if cites:
        g = load_graph(case)
        g["nodes"][nid]["input_call_ids"] = list(cites)
        save_graph(case, g)
    return nid


class TestWhichBeliefs:
    def test_a_recount_selects_the_beliefs_stating_the_coverage_it_corrected(self, case):
        _blocked_without_failed_reads(case)
        cited = _belief(case, "Logon history on CORP-WS01 could not be determined",
                        host="CORP-WS01", cites=[3])
        estate = _belief(case, "UNRESOLVABLE: all disk images were probed/blocked; ownership "
                               "of the staged archive cannot be determined without disk image access")
        on_host = _belief(case, "CORP-WS02 disk image probed/blocked, no event log available",
                          host="CORP-WS02")
        german = _belief(case, "Das Festplattenabbild von CORP-WS02 konnte nicht gelesen werden",
                         host="CORP-WS02")
        in_gaps = _belief(case, "jane.doe logged on to CORP-WS02 at 2031-03-04 10:12:00",
                          host="CORP-WS02", gaps=["the disk image is inaccessible"])
        report_gap = _belief(case, "Evidence gap: the registry hives of CORP-WS01 are missing",
                             host="CORP-WS01", cites=[3])
        moved = cl.rederive_container_coverage(case)
        assert moved == {"unblocked": [WS1, WS2]} or sorted(moved["unblocked"]) == [WS1, WS2]
        hits = cl.coverage_review_hits(case, moved)
        assert hits[cited] == {"recounted": [WS1]}
        assert sorted(hits[estate]["recounted"]) == [WS1, WS2]
        assert hits[on_host] == {"recounted": [WS2]}
        assert hits[german] == {"recounted": [WS2]}
        assert hits[in_gaps] == {"recounted": [WS2]}
        assert hits[report_gap] == {"recounted": [WS1]}

    @pytest.mark.parametrize("statement, host, cites", [
        # what an image showed, on the moved image's host and from a read of it
        ("jane.doe logged on to CORP-WS01 over RDP from 10.0.0.5 at 2031-03-04 10:12:00",
         "CORP-WS01", []),
        ("The Run key on CORP-WS01 starts C:\\Users\\Public\\upd.exe", "CORP-WS01", [8]),
        # a coverage statement about an image that did not move, or of another kind
        ("CORP-WS03 disk image blocked: the filesystem does not open", "CORP-WS03", []),
        ("The memory dump of CORP-WS01 could not be read", "CORP-WS01", []),
        # a gap that is not about the image's coverage
        ("Security.evtx on CORP-WS01 could not be parsed", "CORP-WS01", []),
        # coverage words as everyday words
        ("The attacker probed port 445 on CORP-WS02 from 10.0.0.9", "CORP-WS02", []),
        ("Defender on CORP-WS01 blocked mimikatz.exe at 2031-03-04 10:20:00", "CORP-WS01", []),
        ("jane.doe had no access to the finance share on CORP-WS01", "CORP-WS01", []),
        ("Ransomware on CORP-WS02 rendered the documents unreadable", "CORP-WS02", []),
        ("Die Firewall auf CORP-WS01 blockiert SMB von 10.0.0.9", "CORP-WS01", []),
        ("Das Konto jane.doe auf CORP-WS02 ist gesperrt", "CORP-WS02", []),
        # a file name every host's image shares, on a host whose image did not move
        ("CORP-WS03: disk.dd could not be opened", "", []),
        # a disk as a device or a share, not the evidence
        ("BitLocker on CORP-WS01 blocked access to the disk for the attacker's account",
         "CORP-WS01", []),
        ("CORP-WS01: the ransom note states the disk was encrypted and the files could not "
         "be opened", "CORP-WS01", []),
        ("Access to the disk share from CORP-WS02 was blocked by the firewall at "
         "2031-03-04 10:20:00", "CORP-WS02", []),
        # a container that is no image
        ("The Docker container on CORP-WS01 was blocked from reaching 10.0.0.9",
         "CORP-WS01", []),
        ("The archive container staged.zip on CORP-WS02 could not be opened (password)",
         "CORP-WS02", []),
    ])
    def test_a_belief_that_does_not_state_a_moved_images_coverage_stays(
            self, case, statement, host, cites):
        _blocked_without_failed_reads(case)
        nid = _belief(case, statement, host=host, cites=cites)
        hits = cl.coverage_review_hits(case, cl.rederive_container_coverage(case))
        assert nid not in hits

    def test_hosts_are_named_by_their_whole_label(self, tmp_path):
        dc, branch = "evidence/hosts/CORP-DC01/dc.dd", "evidence/hosts/BRANCH-DC01/branch.dd"
        case = _make_case(tmp_path, images=(dc, branch), links=(
            "## Evidence Links\n\n| Label | Kind | Path | Notes |\n|---|---|---|---|\n"
            "| CORP-DC01 | disk | evidence/hosts/CORP-DC01 | |\n"
            "| BRANCH-DC01 | disk | evidence/hosts/BRANCH-DC01 | |\n"))
        _set(case, dc, "blocked", "blocked", blocked_reason="blocked by the fixture")
        _trace(case, [TIMELINE_GREP])
        other = _belief(case, "BRANCH-DC01 disk image blocked; no event log available")
        own = _belief(case, "CORP-DC01 disk image blocked; no event log available")
        hits = cl.coverage_review_hits(case, cl.rederive_container_coverage(case))
        assert other not in hits and hits[own] == {"recounted": [dc]}

    def test_without_evidence_links_a_host_is_named_by_its_image_path(self, tmp_path):
        case = _make_case(tmp_path, links="")
        for rel in (WS1, WS2, WS3):
            _set(case, rel, "blocked", "blocked", blocked_reason="blocked by the fixture")
        _trace(case, [TIMELINE_GREP])
        field = _belief(case, "CORP-WS02 disk image probed/blocked; no event log available",
                        host="CORP-WS02")
        text_only = _belief(case, "The CORP-WS03 disk image could not be read")
        elsewhere = _belief(case, "ATTACKER-VM01 disk image could not be read", host="ATTACKER-VM01")
        estate = _belief(case, "UNRESOLVABLE: all disk images were probed/blocked")
        hits = cl.coverage_review_hits(case, cl.rederive_container_coverage(case))
        assert hits[field] == {"recounted": [WS2]}
        assert hits[text_only] == {"recounted": [WS3]}
        assert elsewhere not in hits
        assert sorted(hits[estate]["recounted"]) == [WS1, WS2, WS3]

    def test_the_one_image_of_a_case_is_named_by_any_host(self, tmp_path):
        """One disk image, no Evidence Links, a path without the host: a belief
        naming the host it found inside the image is about that image."""
        lone = "evidence/disk.E01"
        case = _make_case(tmp_path, links="", images=(lone,))
        _set(case, lone, "blocked", "blocked", blocked_reason="blocked by the fixture")
        _trace(case, [TIMELINE_GREP])
        nid = _belief(case, "The disk image could not be mounted (Invalid magic value)",
                      host="CORP-WS01")
        assert cl.coverage_review_hits(case, cl.rederive_container_coverage(case)) == {
            nid: {"recounted": [lone]}}

    def test_a_demoted_image_selects_an_absence_resting_on_the_call_credited_for_it(self, case):
        _set(case, MEM, "probed", "examined", calls=["7"],
             examined_by={"call_id": "7", "tool": "vol_symbol_check"})
        _trace(case, [_call(7, "vol_symbol_check", image=MEM), TIMELINE_GREP])
        rests = _belief(case, "No injected code was found in the memory of CORP-WS01",
                        host="CORP-WS01", cites=[7])
        names_host = _belief(case, "No injected code was found on CORP-WS01", host="CORP-WS01")
        moved = cl.rederive_container_coverage(case)
        assert moved == {"demoted": [MEM]}
        hits = cl.coverage_review_hits(case, moved)
        assert hits == {rests: {"recounted": [MEM]}} and names_host not in hits

    def test_nothing_moved_selects_nothing(self, case):
        _belief(case, "UNRESOLVABLE: all disk images were probed/blocked")
        assert cl.coverage_review_hits(case, {}) == {}


class TestTheMark:
    def test_each_belief_carries_its_own_reason_and_a_base_passes_its_on(self, case):
        a = _belief(case, "CORP-WS02 disk image probed/blocked", host="CORP-WS02")
        b = _belief(case, "Logon history on CORP-WS01 could not be determined", host="CORP-WS01")
        conc = add_node(case, kind="conclusion", statement="CORP-WS02 was not examined",
                        parent_ids=[a], edge_type="derived_from")["node_id"]
        moved = {"unblocked": [WS1, WS2]}
        reasons = {a: cl.recount_review_reason([WS2], moved),
                   b: cl.recount_review_reason([WS1], moved)}
        r = mark_needs_review(case, [a, b], reason="coverage corrected by the recount",
                              hits={a: {"recounted": [WS2]}, b: {"recounted": [WS1]}},
                              reasons=reasons)
        g = load_graph(case)
        assert set(r["marked"]) == {a, b, conc}
        assert g["nodes"][a]["invalidation_reason"] == reasons[a]
        assert WS2 in reasons[a] and "re-validate" in reasons[a] and "mark the image blocked" in reasons[a]
        assert "misc.record_finding(supersedes=<this finding>)" in reasons[a]
        assert f"misc.record_finding(supersedes={a})" in cl.recount_review_reason([WS2], moved, a)
        assert g["nodes"][conc]["invalidation_reason"] == reasons[a]
        assert coverage_corrected(g["nodes"][a]) and coverage_corrected(g["nodes"][conc])

    def test_a_belief_questioned_again_gathers_the_new_reason_once(self, case):
        a = _belief(case, "CORP-WS02 disk image probed/blocked", host="CORP-WS02")
        mark_needs_review(case, [a], reason="upstream evidence added/changed/removed")
        mark_needs_review(case, [a], reason="coverage corrected by the recount",
                          hits={a: {"recounted": [WS2]}})
        mark_needs_review(case, [a], reason="coverage corrected by the recount",
                          hits={a: {"recounted": [WS2]}})
        n = get_node(load_graph(case), a)
        assert n["invalidation_reason"] == ("upstream evidence added/changed/removed; "
                                            "coverage corrected by the recount")
        assert n["invalidated_by"] == {"recounted": [WS2]}

    def test_a_recount_stamp_keeps_every_image(self, case):
        a = _belief(case, "UNRESOLVABLE: all disk images were probed/blocked")
        paths = [f"evidence/hosts/CORP-WS{i:02d}/disk.dd" for i in range(1, 26)]
        mark_needs_review(case, [a], reason="coverage corrected", hits={a: {"recounted": paths}})
        assert get_node(load_graph(case), a)["invalidated_by"]["recounted"] == paths


def _answered_task(case, claim_id):
    p = case / ".atlas" / "investigation_tasks.json"
    store = json.loads(p.read_text(encoding="utf-8"))
    for t in store["tasks"]:
        t["status"] = "answered"
        t["related_claim_ids"] = [claim_id]
        for part in t.get("parts") or []:
            part["status"] = "answered"
    p.write_text(json.dumps(store), encoding="utf-8")


def test_plane_a_puts_the_beliefs_a_recount_contradicts_under_review(tmp_path, monkeypatch):
    from core.incremental import plane_a_scan
    from core.investigation_tasks import load_tasks
    monkeypatch.setenv("ATLAS_PLANE_A_AUTO_MOUNT", "off")
    case = _make_case(tmp_path, requests=(
        "## Investigation Requests\n\n- Who owned the staged archive?\n\n"))
    plane_a_scan(case, persist=True)
    _blocked_without_failed_reads(case)
    estate = _belief(case, "UNRESOLVABLE: all disk images were probed/blocked; ownership of "
                           "the staged archive cannot be determined without disk image access")
    cited = _belief(case, "Logon history on CORP-WS01 could not be determined",
                    host="CORP-WS01", cites=[3])
    shown = _belief(case, "jane.doe logged on to CORP-WS01 over RDP from 10.0.0.5 at "
                          "2031-03-04 10:12:00", host="CORP-WS01", cites=[6])
    _answered_task(case, estate)

    res = plane_a_scan(case, persist=True)
    g = load_graph(case)
    for nid, paths in ((estate, {WS1, WS2}), (cited, {WS1})):
        n = g["nodes"][nid]
        assert n["status"] == "needs_review"
        assert n["invalidation_reason"].startswith("coverage corrected: the recount from the trace")
        assert set(n["invalidated_by"]["recounted"]) == paths
    assert g["nodes"][shown]["status"] != "needs_review"
    assert sorted(res["invalidation"]["coverage_marked"]) == sorted([estate, cited])
    tasks = load_tasks(case)["tasks"]
    assert tasks[0]["status"] == "reopened"
    assert not any(str(t.get("text") or "").startswith("[derived]") for t in tasks)
    work = res["work"]
    assert sorted(work["claims_recounted"]) == sorted([estate, cited])
    assert "2 findings to re-validate (2 after the coverage recount)" in work["reasons"]
    brief = (case / ".atlas" / "rerun_brief.md").read_text(encoding="utf-8")
    assert "coverage corrected: the recount from the trace" in brief

    from agent.prompts import rerun_objective
    # The reopened request is the objective; the brief carries the reason.
    assert "coverage corrected" not in rerun_objective(case, work)
    assert "coverage corrected" in rerun_objective(None, work)

    again = plane_a_scan(case, persist=True)
    assert "coverage_rederived" not in again
    assert not (again["invalidation"] or {}).get("coverage_marked")
    assert get_node(load_graph(case), estate)["invalidation_reason"] == \
        g["nodes"][estate]["invalidation_reason"]


class TestTheReport:
    def _findings(self, case):
        a = _belief(case, "CORP-WS02 disk image probed/blocked; no event log available",
                    host="CORP-WS02", gaps=["the disk image is inaccessible"])
        mark_needs_review(case, [a], reason="coverage corrected",
                          hits={a: {"recounted": [WS2]}},
                          reasons={a: cl.recount_review_reason([WS2], {"unblocked": [WS2]})})
        return a

    def test_the_gaps_list_it_as_under_review_not_as_a_standing_gap(self, case):
        from core.report_projection import (
            bind_claims_to_sections,
            deterministic_section_generator,
            load_manifest,
            section_context,
        )
        a = self._findings(case)
        bind_claims_to_sections(case)
        ctx = section_context(case, "gaps")
        node = next(n for n in ctx["claims"] if n["id"] == a)
        assert node["review_reason"].startswith("coverage corrected")
        text = deterministic_section_generator(ctx, load_manifest(case)["sections"]["gaps"])
        assert COVERAGE_REVIEW_NOTE in text
        assert "inaccessible" not in text and "no event log available" not in text

    def test_the_assembled_report_marks_it_and_keeps_its_statement_out_of_the_gaps(self, case):
        from core.claim_graph import lint_report_against_graph
        from core.report_assemble import assemble_client_report
        self._findings(case)
        report = assemble_client_report(case)
        gaps = report.split("Evidence Gaps", 1)[1]
        assert COVERAGE_REVIEW_NOTE in gaps and "inaccessible" not in gaps
        assert "[LIKELY, needs review]" in report and "| LIKELY, needs review |" in report
        assert not any("needs_review_unmentioned" in w
                       for w in lint_report_against_graph(report, case))


def test_a_finding_leaving_review_is_report_work(case):
    """agent.loop's report-phase progress: a finding settled after a review
    Plane A raised (re-validated, superseded or withdrawn) is a member the
    first time; one settled in an earlier run is in the first snapshot."""
    from types import SimpleNamespace

    from agent.loop import Agent
    from core.claim_graph import supersede
    earlier = _belief(case, "CORP-WS03 disk image blocked: the filesystem does not open",
                      host="CORP-WS03")
    g = load_graph(case)
    g["nodes"][earlier]["review_history"] = [{"invalidation_reason": "coverage corrected"}]
    save_graph(case, g)
    a = _belief(case, "CORP-WS02 disk image probed/blocked", host="CORP-WS02")
    b = _belief(case, "CORP-WS01 disk image probed/blocked", host="CORP-WS01")
    mark_needs_review(case, [a, b], reason="coverage corrected")
    agent = SimpleNamespace(case_dir=case)
    first = Agent._report_done(agent)
    assert ("review", earlier) in first and ("review", a) not in first
    assert supersede(case, a, reason="the recount found the image readable; the listing "
                                     "of its filesystem shows the event logs")["success"]
    second = Agent._report_done(agent)
    assert second - first == {("review", a)}
