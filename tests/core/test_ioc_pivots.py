"""IOC pivot ledger — new indicators must re-open the evidence.

The behaviour under test is the general rule, not any case's specifics:
an indicator recorded in a belief creates a search obligation against every
relevant evidence source the case actually has, and stays open until the
trace shows that search happened.
"""
from __future__ import annotations

import json

from core import ioc_pivots as ip


import pytest

pytestmark = pytest.mark.usefixtures("todays_pivots")


def _case(tmp_path, *, sources=(), claims=()):
    (tmp_path / ".atlas").mkdir(parents=True, exist_ok=True)
    for rel in sources:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x", encoding="utf-8")
    nodes = {
        f"C{i:04d}": {"id": f"C{i:04d}", "kind": "claim", "status": "new",
                      "statement": text}
        for i, text in enumerate(claims, start=1)
    }
    (tmp_path / ".atlas" / "claim_graph.json").write_text(
        json.dumps({"schema_version": "1.0", "nodes": nodes, "edges": []}),
        encoding="utf-8")
    # The incident frame the pivots are pinned in is the brief's statement.
    if not (tmp_path / "CASE.md").exists():
        (tmp_path / "CASE.md").write_text("**Case ID:** CASE-A\n**System owner:** victim\n", encoding="utf-8")
    return tmp_path


class TestSourceClassification:
    def test_classes_come_from_the_path(self):
        assert "eventlog" in ip.source_classes("evidence/h1/winevt/Security.evtx")
        assert "network" in ip.source_classes("evidence/fw/firewall-2026.log")
        assert "registry" in ip.source_classes("analysis/h1_NTUSER.DAT")
        assert "filesystem" in ip.source_classes("analysis/h1_$MFT.csv")
        assert ip.source_classes("evidence/notes.txt") == {"generic"}

    def test_disk_images_are_containers_not_targets(self, tmp_path):
        case = _case(tmp_path, sources=("evidence/h1/disk.vmdk",
                                        "evidence/h1/win/Security.evtx"))
        sources = ip.evidence_sources(case)
        assert not any(s.endswith(".vmdk") for s in sources)
        assert any(s.endswith("Security.evtx") for s in sources)


class TestRelevance:
    def test_an_ip_reopens_network_logs(self, tmp_path):
        case = _case(
            tmp_path,
            sources=("evidence/fw/firewall.log", "analysis/h1_NTUSER.DAT"),
            claims=("The attacker beaconed to 203.0.113.44.",))
        ip.refresh_pivots(case)
        opens = {p["ioc"]: p["pending"] for p in ip.open_pivots(case)}
        assert "ip:203.0.113.44" in opens
        assert any("firewall" in t for t in opens["ip:203.0.113.44"])

    def test_an_account_reopens_event_logs_and_hives(self, tmp_path):
        case = _case(
            tmp_path,
            sources=("evidence/h1/winevt/Security.evtx",
                     "analysis/h1_NTUSER.DAT",
                     "evidence/notes.txt"),
            claims=(r"The account CORP\opsadmin created a scheduled task.",))
        ip.refresh_pivots(case)
        opens = {p["ioc"]: p["pending"] for p in ip.open_pivots(case)}
        account = next(k for k in opens if k.startswith("account:"))
        targets = " ".join(opens[account])
        assert "Security.evtx" in targets
        assert "NTUSER.DAT" in targets

    def test_a_host_indicator_reaches_other_hosts_evidence(self, tmp_path):
        """Cross-host correlation: a host named in a belief must be looked
        for in the *other* hosts' material, not only its own."""
        case = _case(
            tmp_path,
            sources=("evidence/corp-dc01/winevt/Security.evtx",
                     "evidence/filesrv01/winevt/Security.evtx"),
            claims=(r"Lateral movement reached \\filesrv01\c$ from the DC.",))
        ip.refresh_pivots(case)
        opens = {p["ioc"]: p["pending"] for p in ip.open_pivots(case)}
        host = next(k for k in opens if k.startswith("host:"))
        assert any("corp-dc01" in t for t in opens[host])

    def test_noise_indicators_are_not_pivoted(self, tmp_path):
        case = _case(
            tmp_path,
            sources=("evidence/fw/firewall.log",),
            claims=("Activity at 2031-02-04T12:00Z mapped to T1059.001 "
                    "from 127.0.0.1.",))
        ip.refresh_pivots(case)
        iocs = {p["ioc"] for p in ip.open_pivots(case)}
        assert not any(i.startswith(("ts:", "technique:")) for i in iocs)
        assert "ip:127.0.0.1" not in iocs


class TestClosingPivots:
    def _one_ip_case(self, tmp_path):
        return _case(
            tmp_path,
            sources=("evidence/fw/firewall.log",),
            claims=("Beacon to 203.0.113.44 seen.",))

    def test_a_search_touching_both_closes_the_pair(self, tmp_path):
        case = self._one_ip_case(tmp_path)
        ip.refresh_pivots(case)
        assert ip.open_pivots(case)
        closed = ip.observe_search(
            case, blob='{"path": "evidence/fw/firewall.log", '
                       '"pattern": "203.0.113.44"}')
        assert closed
        assert not ip.open_pivots(case)

    def test_mentioning_only_the_indicator_does_not_close_it(self, tmp_path):
        case = self._one_ip_case(tmp_path)
        ip.refresh_pivots(case)
        ip.observe_search(case, blob='{"note": "203.0.113.44 is suspicious"}')
        assert ip.open_pivots(case), "no source was actually searched"

    def test_a_source_blocked_in_the_coverage_ledger_stops_being_owed(self, tmp_path):
        """The one verb for an unexaminable source is the coverage ledger's
        blocked, with its reason; the pivot queue takes that verdict over
        on refresh, whether the block came before or after the pivot."""
        from core.coverage_ledger import (
            _add_unit, load_ledger, mark_unit_blocked, save_ledger,
        )
        case = self._one_ip_case(tmp_path)
        ip.refresh_pivots(case)
        pending = ip.open_pivots(case)[0]
        target = pending["pending"][0]
        ledger = load_ledger(case)
        _add_unit(ledger["units"], target, kind="log", reason="test")
        save_ledger(case, ledger)
        blocked = mark_unit_blocked(
            case, target, reason="log truncated to 0 bytes",
            trace_entries=[{"type": "tool_call", "cmd": f"grep x {target}",
                            "mcp_tool": "strings_strings_grep", "success": False}])
        assert blocked["success"], blocked
        ip.refresh_pivots(case)
        assert not ip.open_pivots(case)
        entry = ip.load_pivots(case)["pivots"][pending["ioc"]]
        assert entry["targets"][target] == "blocked"
        assert entry["blocked_reasons"][target] == "log truncated to 0 bytes"
        ip.refresh_pivots(case)
        assert ip.pivot_stats(case)["blocked"] == 1, "a refresh keeps the verdict"

    def test_completed_work_survives_a_refresh(self, tmp_path):
        case = self._one_ip_case(tmp_path)
        ip.refresh_pivots(case)
        ip.observe_search(
            case, blob="grep 203.0.113.44 evidence/fw/firewall.log")
        ip.refresh_pivots(case)
        assert not ip.open_pivots(case), "a refresh must not re-open done work"

    def test_stats_round_trip(self, tmp_path):
        case = self._one_ip_case(tmp_path)
        ip.refresh_pivots(case)
        before = ip.pivot_stats(case)
        assert before["pivots"] == 1 and before["pending"] >= 1
        ip.observe_search(
            case, blob="grep 203.0.113.44 evidence/fw/firewall.log")
        assert ip.pivot_stats(case)["searched"] >= 1


class TestNudge:
    def test_nudge_names_indicator_and_sources(self, tmp_path):
        case = _case(
            tmp_path,
            sources=("evidence/fw/firewall.log",),
            claims=("Beacon to 203.0.113.44 seen.",))
        ip.refresh_pivots(case)
        text = ip.format_pivot_nudge(ip.open_pivots(case))
        assert "203.0.113.44" in text
        assert "firewall.log" in text

    def test_nudge_names_the_verb_that_exists_for_an_unexaminable_source(self, tmp_path):
        """An instruction must name an action the model can take: the
        nudge sends an unexaminable source to coverage.mark_blocked, which
        is a tool, and names no verb the pivot module keeps for itself."""
        case = _case(
            tmp_path,
            sources=("evidence/fw/firewall.log",),
            claims=("Beacon to 203.0.113.44 seen.",))
        ip.refresh_pivots(case)
        text = ip.format_pivot_nudge(ip.open_pivots(case))
        assert "coverage.mark_blocked(path, reason)" in text
        assert not hasattr(ip, "mark_blocked")

    def test_no_open_pivots_means_no_nudge(self):
        assert ip.format_pivot_nudge([]) == ""

    def test_a_clean_miss_is_sent_to_a_disposition_not_a_finding(self, tmp_path):
        case = _case(
            tmp_path,
            sources=("evidence/fw/firewall.log",),
            claims=("Beacon to 203.0.113.44 seen.",))
        ip.refresh_pivots(case)
        text = ip.format_pivot_nudge(ip.open_pivots(case))
        assert "record_agent_message" in text and "disposition=True" in text
        assert "record_finding" in text



class TestOneSearchPerSource:
    """The nudge asks for one search per source with a pattern naming every
    indicator owed there, and that one call credits each of them."""

    PIVOTS = [
        {"ioc": "ip:203.0.113.44", "origin": "C0001",
         "pending": ["evidence/timeline.csv", "evidence/fw/firewall.log"]},
        {"ioc": "domain:update.example.com", "origin": "C0002",
         "pending": ["evidence/timeline.csv"]},
        # as core.entities.extract stores them: lower case, forward slashes
        {"ioc": "path:c:/users/public/upd(1).exe", "origin": "C0003",
         "pending": ["evidence/timeline.csv"]},
        {"ioc": "reg:hklm/software/microsoft/windows/currentversion/run/updater",
         "origin": "C0003", "pending": ["evidence/timeline.csv"]},
    ]

    @staticmethod
    def _searches(text):
        return [line for line in text.splitlines() if " owed): pattern " in line]

    def test_sources_owing_the_most_come_first_with_one_pattern_each(self):
        text = ip.format_pivot_nudge(self.PIVOTS)
        searches = self._searches(text)
        assert searches[0].startswith("- evidence/timeline.csv (4 owed): pattern ")
        assert searches[1] == "- evidence/fw/firewall.log (1 owed): pattern 203.0.113.44"
        assert "203.0.113.44 (from C0001)" in text and text.count("- ip 203.0.113.44") == 1
        assert "terms_with_no_row" in text and "coverage.mark_blocked(path, reason)" in text

    def test_the_capped_result_wording_follows_the_view_switch(self, monkeypatch):
        """With the compact view off the result holds the alternatives block
        and none of the view's keys, so the nudge names that block."""
        monkeypatch.setenv("ATLAS_RESULT_VIEW", "0")
        text = ip.format_pivot_nudge(self.PIVOTS)
        assert "lists the pattern's alternatives" in text
        assert "terms_with_no_row" not in text and "terms_not_settled" not in text

    def test_every_pattern_compiles_and_finds_each_of_its_indicators(self):
        import re
        for line in self._searches(ip.format_pivot_nudge(self.PIVOTS)):
            source, pattern = line[2:].split(" owed): pattern ", 1)
            rx = re.compile(pattern, re.IGNORECASE)
            owed = [p for p in self.PIVOTS if source.split(" (")[0] in p["pending"]]
            for p in owed:
                # the row form a Windows record writes: backslashes, any case
                row = ip.ioc_value(p["ioc"]).replace("/", "\\").upper()
                assert rx.search(row), (p["ioc"], pattern)

    def test_the_printed_pattern_credits_every_indicator_it_names(self, tmp_path):
        (tmp_path / ".atlas").mkdir()
        ip.save_pivots(tmp_path, {"pivots": {
            p["ioc"]: {"origin": p["origin"], "targets": {t: "pending" for t in p["pending"]}}
            for p in self.PIVOTS}})
        line = self._searches(ip.format_pivot_nudge(self.PIVOTS))[0]
        pattern = line.split(" owed): pattern ", 1)[1]
        closed = ip.observe_search(tmp_path, blob="table_grep " + json.dumps(
            {"path": "evidence/timeline.csv", "pattern": pattern}))
        assert sorted(closed) == sorted(f"{p['ioc']} -> evidence/timeline.csv"
                                        for p in self.PIVOTS)
        listed = ip.observe_search(tmp_path, blob="strings_grep " + json.dumps(
            {"file_path": "evidence/fw/firewall.log", "pattern": ["203\\.0\\.113\\.44"]}))
        assert listed == ["ip:203.0.113.44 -> evidence/fw/firewall.log"]
        assert ip.pivot_stats(tmp_path)["pending"] == 0

    def test_a_path_or_key_is_searched_by_its_last_component(self, tmp_path):
        import re
        pivots = [
            {"ioc": "path:c:/users/jane.doe/downloads/kit/tool.exe", "origin": "C0001",
             "pending": ["evidence/timeline.csv"]},
            {"ioc": "file:tool.exe", "origin": "C0001", "pending": ["evidence/timeline.csv"]},
            {"ioc": "reg:hklm/software/microsoft/windows/currentversion/run/updater",
             "origin": "C0002", "pending": ["evidence/timeline.csv"]},
        ]
        line = self._searches(ip.format_pivot_nudge(pivots))[0]
        pattern = line.split(" owed): pattern ", 1)[1]
        assert pattern == "tool.exe|updater" and "/" not in pattern
        rx = re.compile(pattern, re.IGNORECASE)
        assert rx.search("C:\\Users\\jane.doe\\Downloads\\kit\\tool.exe")
        assert rx.search("c:/users/jane.doe/downloads/kit/tool.exe")
        assert rx.search("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run: Updater")
        (tmp_path / ".atlas").mkdir()
        ip.save_pivots(tmp_path, {"pivots": {
            p["ioc"]: {"origin": p["origin"], "targets": {"evidence/timeline.csv": "pending"}}
            for p in pivots}})
        closed = ip.observe_search(tmp_path, blob="table_table_grep " + json.dumps(
            {"path": "evidence/timeline.csv", "pattern": pattern}, ensure_ascii=False))
        assert len(closed) == 3

    def test_every_printed_term_is_a_credited_term(self):
        import re
        for ioc in ("path:c:/users/public/setup (1).exe", "path:c:/tools/kit/", "path:/temp/ab",
                    "reg:hklm/software/microsoft/windows/currentversion/run/updater",
                    "path:C:\\Users\\Public\\upd[2].exe", "ip:203.0.113.44"):
            term = ip.pattern_term(ioc)
            assert re.sub(r"\\(.)", r"\1", term) in ip._search_terms(ioc), (ioc, term)
            row = ip.ioc_value(ioc).replace("/", "\\").upper()
            if ip.ioc_type(ioc) != "path" or len(ip._search_terms(ioc)) > 1:
                assert re.compile(term, re.IGNORECASE).search(row), (ioc, term)

    def test_a_source_that_does_not_fit_is_left_out_whole_and_counted(self):
        many = [{"ioc": f"domain:host{i:03d}." + "a" * 60 + ".example.com", "origin": "C0001",
                 "pending": ["evidence/big.csv"]} for i in range(60)]
        other = [{"ioc": f"domain:other{i:03d}." + "b" * 60 + ".example.com",
                  "origin": "C0001", "pending": ["evidence/other.csv"]} for i in range(59)]
        text = ip.format_pivot_nudge(many + other)
        searches = self._searches(text)
        assert len(searches) == 1 and searches[0].startswith("- evidence/big.csv (60 owed)")
        assert searches[0].count("|") == 59
        assert "(1 more source, 59 more indicator searches: in a later reminder)" in text

    def test_an_analyst_named_indicator_is_listed_once(self):
        from core.case_knowledge import ORIGIN
        text = ip.format_pivot_nudge([{"ioc": "ip:10.0.0.5", "origin": ORIGIN,
                                       "pending": ["evidence/a.csv", "evidence/b.csv"]}])
        assert text.count("- ip 10.0.0.5, named by the analyst in CASE.md") == 1
        assert len(self._searches(text)) == 2
        assert "corroborating hit is a finding" not in text



class TestASearchThatStoppedEarly:
    """A table search stopped at its hit cap saw only the rows before it: the
    indicators its result does not show stay owed, whatever its pattern
    named. Results are rendered as the toolbox renders them."""

    IOCS = ("ip:203.0.113.44", "domain:update.example.com", "account:corp/jdoe")
    SOURCE = "evidence/timeline.csv"

    def _ledger(self, tmp_path, iocs=None):
        (tmp_path / ".atlas").mkdir()
        ip.save_pivots(tmp_path, {"pivots": {
            i: {"origin": "C0001", "targets": {self.SOURCE: "pending"}}
            for i in (iocs or self.IOCS)}})
        return tmp_path

    @staticmethod
    def _rendered(args, rows, *, capped):
        return json.dumps({"success": True, "path": args["path"], "pattern": args["pattern"],
                           "hits": [{"_row": n, "Description": r} for n, r in enumerate(rows)],
                           "hit_count": len(rows), "max_hits": 50,
                           "hit_cap_reached": capped, "scan_capped": False},
                          indent=2, default=str, ensure_ascii=False)

    def _call(self, case, pattern, rows, *, capped=True, truncate=None):
        args = {"path": self.SOURCE, "pattern": pattern}
        result = self._rendered(args, rows, capped=capped)
        if truncate:
            from agent.toolbox import _truncate
            result = _truncate(result, limit=truncate)
        blob = "table_table_grep " + json.dumps(args, default=str, ensure_ascii=False)
        return ip.observe_search(case, blob=blob, result=result)

    def test_only_the_indicators_a_capped_result_shows_are_credited(self, tmp_path):
        case = self._ledger(tmp_path)
        closed = self._call(case, "203.0.113.44|update.example.com|corp/jdoe",
                            ["logon from 203.0.113.44"] * 50)
        assert closed == ["ip:203.0.113.44 -> evidence/timeline.csv"]
        assert {p["ioc"] for p in ip.open_pivots(case)} == {
            "domain:update.example.com", "account:corp/jdoe"}

    def test_a_search_that_ran_to_the_end_credits_every_indicator_it_named(self, tmp_path):
        case = self._ledger(tmp_path)
        assert len(self._call(case, "203.0.113.44|update.example.com|corp/jdoe",
                              ["logon from 203.0.113.44"], capped=False)) == 3
        assert ip.open_pivots(case) == []

    def test_a_single_term_shown_in_the_rows_is_credited(self, tmp_path):
        case = self._ledger(tmp_path, iocs=("domain:update.example.com", "host:CORP-DC01"))
        assert self._call(case, "update.example.com", ["dns update.example.com"] * 50) == [
            "domain:update.example.com -> evidence/timeline.csv"]
        assert self._call(case, "CORP-DC01", ["logon to CORP-DC01"] * 50) == [
            "host:CORP-DC01 -> evidence/timeline.csv"]

    def test_the_parts_of_a_path_in_the_rows_do_not_show_the_path(self, tmp_path):
        path = "path:C:\\Users\\Public\\1.exe"
        case = self._ledger(tmp_path, iocs=(path, "ip:203.0.113.44"))
        closed = self._call(case, "C:\\\\Users\\\\Public\\\\1\\.exe|203\\.0\\.113\\.44",
                            ["C:\\Users\\Public\\setup.exe from 203.0.113.44"] * 50)
        assert closed == ["ip:203.0.113.44 -> evidence/timeline.csv"]

    def test_a_non_ascii_value_is_read_as_written(self, tmp_path):
        case = self._ledger(tmp_path, iocs=("account:corp/müller", "domain:update.example.com"))
        closed = self._call(case, "müller|update\\.example\\.com",
                            ["logon by corp/müller"] * 50)
        assert closed == ["account:corp/müller -> evidence/timeline.csv"]

    def test_a_result_cut_in_its_middle_still_shows_what_it_kept(self, tmp_path):
        case = self._ledger(tmp_path)
        closed = self._call(case, "203.0.113.44|update.example.com|corp/jdoe",
                            ["logon from 203.0.113.44"] * 50, truncate=1200)
        assert closed == ["ip:203.0.113.44 -> evidence/timeline.csv"]

    def test_a_capped_search_credits_every_alternative_its_scan_resolved(self, tmp_path):
        """A table search that stopped at its cap still says which of its
        alternatives occur in the file: an indicator it found nowhere in the
        whole file is searched, one past a row bound is not."""
        case = self._ledger(tmp_path)
        args = {"path": self.SOURCE, "pattern": r"203\.0\.113\.44|update\.example\.com|corp/jdoe"}
        blob = "table_table_grep " + json.dumps(args)

        def result(alternatives):
            return json.dumps({"success": True, **args, "alternatives": alternatives,
                               "hits": [{"_row": n, "Description": "logon from 203.0.113.44"}
                                        for n in range(50)],
                               "hit_count": 50, "hit_cap_reached": True, "scan_capped": False})
        closed = ip.observe_search(case, blob=blob, result=result(
            {"matched": [r"203\.0\.113\.44"], "unresolved": 2}))
        assert closed == ["ip:203.0.113.44 -> evidence/timeline.csv"]
        # A term the block calls matched but whose rows were not shown stays
        # owed (the view says terms_matched_not_returned); a term no row of
        # the whole file holds is settled.
        closed = ip.observe_search(case, blob=blob, result=result(
            {"matched": [r"203\.0\.113\.44", r"update\.example\.com"], "unmatched": ["corp/jdoe"]}))
        assert closed == ["account:corp/jdoe -> evidence/timeline.csv"]
        assert [p["ioc"] for p in ip.open_pivots(case)] == ["domain:update.example.com"]

    def test_the_views_annotation_decides_what_a_search_showed(self, tmp_path, monkeypatch):
        """With the call id on the result and the view's annotation on the
        trace entry, a matched term with no shown row stays owed, a shown
        term is credited, a term with no row is credited as searched, and a
        complete view credits every term it named."""
        from core.execution_log import ExecutionLog
        case = self._ledger(tmp_path)
        (case / "analysis").mkdir()
        log = ExecutionLog()
        log.configure("CASE-A", str(case / "analysis" / "trace.json"))
        monkeypatch.setattr("core.execution_log.log", log)
        args = {"path": self.SOURCE, "pattern": r"203\.0\.113\.44|update\.example\.com|corp/jdoe"}
        blob = "table_table_grep " + json.dumps(args)
        cid = log.record_tool_call("<py>:table_table_grep", True, False, 0, 0, stdout_excerpt="{}")
        log.annotate_tool_call(cid, view_terms_shown=[r"203\.0\.113\.44"], view_complete=False,
                               view_rows_shown=5, view_rows_returned=50)
        view = json.dumps({"_atlas_call_id": cid, "success": True, **args, "hit_cap_reached": True,
                           "terms_with_no_row": ["corp/jdoe"], "terms_matched_not_returned": [r"update\.example\.com"],
                           "rows": ["#1 2031-03-04 10:16:00 | logon from 203.0.113.44"]})
        closed = ip.observe_search(case, blob=blob, result=view)
        assert sorted(closed) == ["account:corp/jdoe -> evidence/timeline.csv",
                                  "ip:203.0.113.44 -> evidence/timeline.csv"]
        assert [p["ioc"] for p in ip.open_pivots(case)] == ["domain:update.example.com"]
        log.annotate_tool_call(cid, view_complete=True)
        assert ip.observe_search(case, blob=blob, result=view) == ["domain:update.example.com -> evidence/timeline.csv"]

    def test_a_term_line_alone_credits_nothing_on_the_text_path(self, tmp_path):
        """A result that stopped early and names every term in its term lines
        (or its echoed pattern) credits only the indicators its rows show."""
        case = self._ledger(tmp_path)
        args = {"path": self.SOURCE, "pattern": r"203\.0\.113\.44|update\.example\.com|corp/jdoe"}
        blob = "table_table_grep " + json.dumps(args)
        result = json.dumps({"success": True, **args, "hit_cap_reached": True,
                             "terms": ["203\\.0\\.113\\.44: 50 rows", "update\\.example\\.com: 3 rows"],
                             "hits": [{"_row": 1, "Description": "logon from 203.0.113.44"}]})
        assert ip.observe_search(case, blob=blob, result=result) == ["ip:203.0.113.44 -> evidence/timeline.csv"]

    def test_a_call_that_cannot_be_read_back_is_credited_as_before(self, tmp_path):
        case = self._ledger(tmp_path)
        closed = ip.observe_search(
            case, blob="grep 203.0.113.44|update.example.com|corp/jdoe evidence/timeline.csv",
            result='{"hit_cap_reached": true}')
        assert len(closed) == 3


class TestDispositionsOpenNoPivots:
    """Documenting a search must not create the pivot it closed: a
    disposition is narration, never a belief, so the indicators it names
    stay out of the ledger while a finding naming them would enter it."""

    def test_a_disposition_recorded_through_the_tool_opens_no_pivot(self, tmp_path):
        from unittest.mock import patch
        from core.claim_graph import load_graph
        from core.execution_log import ExecutionLog
        from tools.misc import record_agent_message
        case = _case(tmp_path, sources=("evidence/fw/firewall.log",))
        (case / "analysis").mkdir()
        log = ExecutionLog()
        log.configure("PIV-001", str(case / "analysis" / "trace.json"))
        with patch("core.execution_log.log", log):
            record_agent_message(
                content="Searched evidence/fw/firewall.log for 203.0.113.44 "
                        "and 198.51.100.7: no match for either.",
                disposition=True)
        ip.refresh_pivots(case)
        assert ip.open_pivots(case) == []
        assert not load_graph(case).get("nodes")


class TestResilience:
    def test_missing_case_is_inert(self, tmp_path):
        missing = tmp_path / "nope"
        assert ip.open_pivots(missing) == []
        assert ip.pivot_stats(missing)["pivots"] == 0

    def test_corrupt_ledger_does_not_raise(self, tmp_path):
        (tmp_path / ".atlas").mkdir(parents=True)
        ip.pivots_path(tmp_path).write_text("{not json", encoding="utf-8")
        assert ip.load_pivots(tmp_path)["pivots"] == {}


class TestAtlasOwnLinkIsNotEvidence:
    """Atlas writes its own dashboard link into the case's trace, so the link
    recurs across calls and ranks as a high-signal indicator — it can top the
    list, ahead of anything the evidence contains. The report
    gate then refuses to report until a finding names it, and none ever can:
    it says nothing about the case, so the run hunts indefinitely."""

    URL = "https://127.0.0.1:8765/_dashboard/dashboard.html?trace=/c/analysis/t.json"

    def _case(self, tmp_path, published=True):
        (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
        if published:
            (tmp_path / "analysis" / "dashboard.url").write_text(
                self.URL + "\n", encoding="utf-8")
        return tmp_path

    def _entries(self, value):
        # Four distinct calls surface it, over the min_calls floor.
        return [{"type": "tool_call", "call_id": i, "success": True,
                 "cmd": "grep x", "stdout_excerpt": f"see {value} for the trace"}
                for i in range(1, 5)]

    def _values(self, tmp_path, entries, published=True):
        from core.ioc_pivots import unrecorded_evidence_indicators
        case = self._case(tmp_path, published)
        return [str(d.get("value")) for d
                in unrecorded_evidence_indicators(entries, case)]

    def test_a_listing_yields_names_not_addresses(self, tmp_path):
        """A directory listing of a Windows image names folders like
        1.0.0.1 (a module version) in every image; a listing is names,
        so no address is demanded from it. The same value in a parser's
        rows still is."""
        listing = [{"type": "tool_call", "call_id": i, "success": True,
                    "cmd": "fls -r -o 2048 analysis/exports/h.raw",
                    "stdout_excerpt": "++++ d/d 1234-144-6:\t1.0.0.1\n"}
                   for i in range(1, 5)]
        assert "1.0.0.1" not in self._values(tmp_path, listing, published=False)
        rows = [{"type": "tool_call", "call_id": i, "success": True,
                 "cmd": "grep x", "stdout_excerpt": "src=1.0.0.1 dst=x"}
                for i in range(1, 5)]
        assert "1.0.0.1" in self._values(tmp_path, rows, published=False)

    def test_the_published_link_is_not_demanded(self, tmp_path):
        assert not any("_dashboard" in v for v
                       in self._values(tmp_path, self._entries(self.URL)))

    def test_it_is_dropped_however_the_trace_spelled_it(self, tmp_path):
        """The extractor reads the link back out of JSON, so it arrives with
        trailing escape and punctuation the published form does not have."""
        for spelling in (self.URL + "\\\\", self.URL + '",', self.URL + ")."):
            assert not any("_dashboard" in v for v
                           in self._values(tmp_path, self._entries(spelling))), spelling

    def test_a_link_atlas_never_published_is_still_evidence(self, tmp_path):
        """Only the address Atlas itself published is dropped. A loopback URL
        is not per se uninteresting — a seized web server configuration may
        genuinely reference one."""
        other = "https://127.0.0.1:9999/admin/login"
        assert any("127.0.0.1:9999" in v for v
                   in self._values(tmp_path, self._entries(other)))

    def test_a_case_that_published_nothing_loses_nothing(self, tmp_path):
        vals = self._values(tmp_path, self._entries(self.URL), published=False)
        assert any("_dashboard" in v for v in vals)


class TestFormatNamespaceUrls:
    """A document format's namespace URL is in every document of the
    format. The evidence scan never demands a ruling on one; a belief that
    names one is the analyst's explicit statement and is read as any
    other, so a dismissal opens no pivot and an assertion does."""

    URL = "http://schemas.microsoft.com/office/2004/12/omml"

    def test_the_evidence_showing_it_repeatedly_demands_nothing(self, tmp_path):
        from core.ioc_pivots import unrecorded_evidence_indicators
        (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
        entries = [{"type": "tool_call", "call_id": i, "success": True,
                    "cmd": "strings x.docx",
                    "stdout_excerpt": f"xmlns:m=\"{self.URL}\" xmlns:w=\"http://203.0.113.9/w\""}
                   for i in range(1, 5)]
        values = [str(d.get("value")) for d in unrecorded_evidence_indicators(entries, tmp_path)]
        assert not any("omml" in v for v in values)
        assert any("203.0.113.9" in v for v in values)

    def test_a_dismissal_opens_no_pivot_and_an_assertion_does(self, tmp_path):
        sources = ("evidence/h1/winevt/Security.evtx", "evidence/docs/plan.docx")
        case = _case(tmp_path, sources=sources, claims=(
            f"Recurring URL {self.URL} is an XML namespace identifier in the Office "
            "documents, not an exfiltration channel.",))
        ip.refresh_pivots(case)
        assert not any("omml" in p["ioc"] for p in ip.open_pivots(case))
        case = _case(tmp_path, sources=sources, claims=(
            f"The implant downloaded its payload from {self.URL}",))
        ip.refresh_pivots(case)
        assert any("omml" in p["ioc"] for p in ip.open_pivots(case))

    def test_namespace_noise_cannot_push_a_real_url_into_the_bulk(self, tmp_path):
        """Nineteen Word namespaces seen in four calls beside one command
        URL seen in three proxy-log calls: without the exclusion the url
        kind passes the demand cap and everything, the command URL
        included, is only mentioned in bulk."""
        from core.ioc_pivots import UNRECORDED_DEMAND_CAP, unrecorded_demand, unrecorded_evidence_indicators
        (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
        namespaces = " ".join(
            f"http://schemas.microsoft.com/office/word/2010/word{i}" for i in range(UNRECORDED_DEMAND_CAP + 7))
        entries = [{"type": "tool_call", "call_id": i, "success": True,
                    "cmd": "strings plan.docx", "stdout_excerpt": namespaces} for i in range(1, 5)]
        entries += [{"type": "tool_call", "call_id": i, "success": True,
                     "cmd": "grep gate evidence/proxy/proxy.log",
                     "stdout_excerpt": "GET http://c2.example/gate.php 200"} for i in range(5, 8)]
        demand, bulk = unrecorded_demand(unrecorded_evidence_indicators(entries, tmp_path))
        assert any("c2.example" in d["value"] for d in demand)
        assert not bulk

    def test_a_spilled_url_does_not_keep_a_json_escape(self, tmp_path):
        from core.ioc_pivots import _spilled_entities
        spill = tmp_path / "spill.json"
        spill.write_bytes(b'{"rows": ["GET https://c2.example/x\\" 200", "GET https://c2.example/x\\" 200"]}')
        ents = _spilled_entities(str(spill))
        assert "url:https://c2.example/x" in ents
        assert not any(e.endswith("\\") for e in ents)


class TestIndicatorsThatFit:
    """No pivot from a text escape or a file name read as an address; a
    parsed table is a target when its class fits, and an unclassified
    derived table only a few times per indicator."""

    def test_an_escape_is_not_an_account_and_a_file_name_not_an_address(self):
        from core.entities import extract
        assert extract("login\\tOperator") == set()
        assert extract("CORP\\tom logged on") == {"account:corp/tom"}
        assert extract("DOMAIN\\nancy") == {"account:domain/nancy"}
        assert extract("Notes@Work.lnk was opened") == {"file:notes@work.lnk"}
        for addr in ("jdoe@example.com", "jdoe@files.zip", "jdoe@docs.md"):
            assert extract(f"mail from {addr} arrived") == {f"email:{addr}"}

    def test_a_term_no_search_could_contain_is_no_pivot(self):
        assert ip._search_terms("path:c:/documents and settings/jdoe/ntuser.dat")
        assert ip._search_terms("path:c:\\temp\\x.exe")
        assert not ip._is_pivotable("file:tab\there.txt")
        assert not ip._is_pivotable("account:corp/\\tAdmin")

    def test_classes_are_whole_name_parts(self):
        assert ip.source_classes("analysis/1/software_registry_ProfileList.csv") == {"generic"}
        assert ip.source_classes("analysis/1/FileList.csv") == {"filesystem"}
        assert ip.source_classes("analysis/plaso_supertimeline.csv") == {"timeline"}
        assert ip.source_classes("analysis/EvtxECmd_Output.csv") == {"eventlog"}

    def test_an_unclassified_table_is_owed_only_when_it_holds_the_indicator(self, tmp_path):
        case = _case(tmp_path, sources=["analysis/1/FileList.csv", "evidence/notes.txt"])
        tables = tmp_path / "analysis" / "1"
        (tables / "hive_KeyA.csv").write_text("path,value\nRun,C:\\Temp\\TOOL.EXE\n", encoding="utf-8")
        (tables / "hive_KeyB.csv").write_bytes("name\ntool.exe started\n".encode("utf-16-le"))
        (tables / "hive_KeyC.csv").write_text("name\nnotepad.exe\n", encoding="utf-8")
        sources = ip.evidence_sources(case)
        targets = ip.relevant_targets("file:tool.exe", sources, root=case)
        assert targets[0] == "analysis/1/FileList.csv"
        assert "evidence/notes.txt" in targets
        assert "analysis/1/hive_KeyA.csv" in targets and "analysis/1/hive_KeyB.csv" in targets
        assert "analysis/1/hive_KeyC.csv" not in targets
        held, absent = ip.generic_fit("file:tool.exe", sources, case)
        assert sorted(held) == ["analysis/1/hive_KeyA.csv", "analysis/1/hive_KeyB.csv"] and absent == 1
        # Without the case root no table is read and none is owed.
        assert not any(t.startswith("analysis/1/hive_") for t in ip.relevant_targets("file:tool.exe", sources))

    def test_an_unchanged_table_is_read_once_per_term(self, tmp_path, monkeypatch):
        case = _case(tmp_path)
        table = tmp_path / "analysis" / "1" / "hive_Key.csv"
        table.parent.mkdir(parents=True)
        table.write_text("name\nevil.exe\n", encoding="utf-8")
        ip._TABLE_TERMS.clear()
        opened = []
        real_open = open

        def _counting_open(path, *a, **kw):
            if str(path) == str(table):
                opened.append(path)
            return real_open(path, *a, **kw)

        monkeypatch.setattr("builtins.open", _counting_open)
        assert ip._table_holds(table, ["evil.exe"]) == {"evil.exe"}
        assert ip._table_holds(table, ["evil.exe"]) == {"evil.exe"}
        assert len(opened) == 1
        table.write_text("name\nother.exe, and a longer row\n", encoding="utf-8")
        assert ip._table_holds(table, ["evil.exe"]) == set()
        assert len(opened) == 2

    def test_a_refresh_keeps_a_source_already_searched(self, tmp_path):
        case = _case(tmp_path, sources=[f"analysis/1/hive_Key{i}.csv" for i in range(5)],
                     claims=["The tool dropper.exe was run from the Temp folder."])
        for i in range(3):
            (tmp_path / "analysis" / "1" / f"hive_Key{i}.csv").write_text(
                f"row{i},dropper.exe\n", encoding="utf-8")
        ledger = ip.refresh_pivots(case)
        pivot = ledger["pivots"]["file:dropper.exe"]
        owed = [t for t in pivot["targets"] if t.startswith("analysis/1/hive_")]
        assert sorted(owed) == [f"analysis/1/hive_Key{i}.csv" for i in range(3)]
        assert pivot["generic_checked_absent"] == 2
        pivot["targets"][owed[0]] = "searched"
        ip.save_pivots(case, ledger)
        # The searched table no longer holds the name: it stays searched.
        (tmp_path / owed[0]).write_text("rewritten\n", encoding="utf-8")
        again = ip.refresh_pivots(case)["pivots"]["file:dropper.exe"]
        assert again["targets"][owed[0]] == "searched"

    def test_every_segment_of_a_split_image_is_a_container(self):
        for seg in ("evidence/img.E01", "evidence/img.E02", "evidence/img.Ex03", "evidence/img.s02"):
            assert "disk" in ip.source_classes(seg), seg
        assert ip.source_classes("evidence/app.log.001") == {"generic"}

    def test_a_bare_dot_com_name_is_no_file(self):
        from core.entities import extract
        assert extract("The user visited example.com daily.") == set()
        assert "file:x.com" in extract("It ran C:\\Windows\\x.com at logon.")


class TestTheReportSaysWhatWasNotSearched:
    """Evidence Gaps names the indicators not searched for in every relevant
    source, the most owed first, capped; a host's report counts its own
    sources only."""

    def _pending(self, monkeypatch, pivots):
        monkeypatch.setattr(ip, "open_pivots", lambda case_dir: pivots)

    def test_nothing_open_means_no_line(self, monkeypatch, tmp_path):
        self._pending(monkeypatch, [])
        assert ip.gap_lines(tmp_path) == []

    def test_the_line_names_the_indicators_and_their_sources(self, monkeypatch, tmp_path):
        pivots = [{"ioc": f"ip:203.0.113.{i}", "origin": "",
                   "pending": [f"analysis/CORP-WS0{j}_security.csv" for j in range(1, 3 if i else 4)]}
                  for i in range(8)]
        self._pending(monkeypatch, pivots)
        line, = ip.gap_lines(tmp_path)
        assert line.startswith("- Not searched for in every relevant source (8 indicator(s)): "
                               "`203.0.113.0` (3 sources), `203.0.113.1` (2 sources)")
        assert line.endswith(" and 2 more")
        de, = ip.gap_lines(tmp_path, "de")
        assert de.startswith("- Nicht in jeder relevanten Quelle gesucht (8 Indikator(en)): "
                             "`203.0.113.0` (3 Quellen)") and de.endswith(" und 2 weitere")

    def test_an_indicator_the_analyst_named_is_marked(self, monkeypatch, tmp_path):
        self._pending(monkeypatch, [{"ioc": "user:jane.doe", "origin": ip._ANALYST_ORIGIN,
                                     "pending": ["analysis/CORP-WS01_security.csv"]}])
        assert "`jane.doe` (1 source, named in the brief)" in ip.gap_lines(tmp_path)[0]
        assert "(1 Quelle, in der Fallbeschreibung genannt)" in ip.gap_lines(tmp_path, "de")[0]

    def test_a_hosts_report_counts_its_own_sources(self, monkeypatch, tmp_path):
        self._pending(monkeypatch, [
            {"ioc": "user:jane.doe", "origin": "", "pending": ["analysis/CORP-WS01_security.csv"]},
            {"ioc": "ip:203.0.113.9", "origin": "", "pending": ["analysis/CORP-WS02_security.csv"]}])
        line, = ip.gap_lines(tmp_path, host="CORP-WS02")
        assert "`203.0.113.9` (1 source)" in line and "jane.doe" not in line
