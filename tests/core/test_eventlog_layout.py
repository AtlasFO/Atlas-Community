"""The Windows event-log requirement is made of the layout the evidence
shows, its demand and its acceptance test come from one table, and nothing
is demanded of media that has shown no layout at all."""
from __future__ import annotations

import json
import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core import eventlog_layout as L
from tools._gates import GateContext
from tools._gates import negative_completeness as nc


def _listing(*names, success=True):
    """A directory listing as the trace records it: the request and what
    the tool printed."""
    return {"type": "tool_call", "cmd": "<py>:misc_list_evidence_dir",
            "success": success,
            "stdout_excerpt": json.dumps({"entries": [{"name": n} for n in names]})}


LEGACY = _listing("AppEvent.Evt", "SecEvent.Evt", "SysEvent.Evt", "SAM", "SYSTEM")
MODERN = _listing("Security.evtx", "System.evtx", "Application.evtx")


class TestLayoutDetection:
    def test_legacy_logs_in_a_listing_establish_the_legacy_layout(self):
        assert [l.name for l in L.layouts_in_evidence([LEGACY])] == ["evt"]

    def test_evtx_logs_establish_the_modern_layout(self):
        assert [l.name for l in L.layouts_in_evidence([MODERN])] == ["evtx"]

    def test_a_failed_call_naming_a_path_is_not_evidence_of_it(self):
        """A refused listing of winevt/Logs says the directory was looked
        for; only what a call that did not fail printed or consumed counts."""
        failed = {"type": "tool_call", "cmd": "fls image 9", "success": False,
                  "stdout_excerpt": "image not found: 'fs/Windows/System32/winevt/Logs'"}
        assert L.layouts_in_evidence([failed]) == ()
        assert [l.name for l in L.layouts_in_evidence([failed, LEGACY])] == ["evt"]

    def test_the_analysts_own_words_are_not_evidence(self):
        note = {"type": "tool_call", "cmd": "<py>:misc_record_agent_message",
                "success": True,
                "stdout_excerpt": "winevt/Logs does not exist here; SecEvent.Evt is the log"}
        assert L.layouts_in_evidence([note]) == ()

    def test_a_parse_that_did_not_fail_consumed_a_real_path(self):
        parse = {"type": "tool_call", "success": True,
                 "cmd": "dotnet EvtxECmd.dll -f fs/Windows/System32/winevt/Logs/Security.evtx"}
        assert [l.name for l in L.layouts_in_evidence([parse])] == ["evtx"]

    def test_the_claims_own_words_decide_when_the_trace_shows_nothing(self):
        assert [l.name for l in L.layouts_in_evidence(
            [], "Security.evtx and the TerminalServices channels are absent")] == ["evtx"]
        assert L.layouts_in_evidence([], "no event logs were recovered") == ()

    def test_two_hosts_two_layouts(self):
        assert [l.name for l in L.layouts_in_evidence([MODERN, LEGACY])] == ["evtx", "evt"]


class TestSearchAndDemandComeFromOneTable:
    @pytest.mark.parametrize("layout", L.LAYOUTS, ids=lambda l: l.name)
    def test_the_demand_names_what_the_acceptance_test_accepts(self, layout):
        """Every path and parser the demand tells the analyst to use is
        recognised as a search when it appears in a command."""
        rx = layout.search_regex()
        assert rx.search(f"icat image 77 > {layout.location}")
        for parser in layout.parsers:
            assert rx.search(f"<py>:{parser.replace('.', '_')}"), parser
        assert layout.location in layout.demand()
        for parser in layout.parsers:
            assert parser in layout.demand()

    def test_a_legacy_export_is_a_search_of_the_legacy_layout_only(self):
        cmds = [{"cmd": "evtexport -m all fs/WINDOWS/system32/config/SecEvent.Evt"}]
        assert L.search_attempted(cmds, [L.EVT])
        assert not L.search_attempted(cmds, [L.EVTX])
        assert L.search_attempted(cmds)

    def test_a_failed_attempt_still_counts_as_a_search(self):
        cmds = [{"cmd": "<py>:tsk_resolve_path", "success": False,
                 "args": '{"fs_path": "Windows/System32/winevt/Logs"}'}]
        assert L.search_attempted(cmds, [L.EVTX])

    def test_the_legacy_security_log_is_searched_by_its_own_event_ids(self):
        rx = L.EVT.security_search_regex()
        assert rx.search("table_query where EventID = 528")
        assert not rx.search("table_query where EventID = 4624")
        assert L.EVTX.security_search_regex().search("where EventID = 4624")


class TestLogonSources:
    def test_legacy_media_needs_its_security_log_and_no_terminalservices(self):
        rows = L.logon_sources([LEGACY])
        assert [r[0] for r in rows] == ["security_evt"]
        assert "SecEvent.Evt" in rows[0][2]
        assert rows[0][1].search("evtexport fs/WINDOWS/system32/config/SecEvent.Evt")

    def test_modern_media_needs_security_and_the_session_channels(self):
        rows = L.logon_sources([MODERN])
        assert [r[0] for r in rows] == ["security_evtx", "sessions_evtx"]
        assert rows[1][1].search("EvtxECmd -f Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx")

    def test_unknown_media_needs_the_security_log_of_either_layout(self):
        rows = L.logon_sources([], "no logons were found")
        assert [r[0] for r in rows] == ["security_log"]
        assert rows[0][1].search("EvtxECmd -f Security.evtx")
        assert rows[0][1].search("evtexport SecEvent.Evt")


def _case(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "analysis").mkdir()
    raw = case / "analysis" / "host.raw"
    raw.write_bytes(b"x" * 64)
    (case / ".atlas" / "evidence_profile.json").write_text(
        json.dumps({"present_classes": ["disk"]}), encoding="utf-8")
    from core.mount_plan import mark_image_opened, register_exported_image
    register_exported_image(case, raw)
    mark_image_opened(case, raw, tool="tsk.mmls")
    return case


def _ctx(case, description, tool_calls, *, tier="UNCONFIRMED", supporting=""):
    log = MagicMock()
    log.case_dir = MagicMock(return_value=str(case))
    return GateContext(
        description=description, confidence=tier.capitalize(), tier=tier,
        source="test", linked_call_id=0, tested_hypothesis_id="", log=log,
        idx=SimpleNamespace(by_call_id={}, by_type={"tool_call": tool_calls}),
        window=[], input_call_ids=[], supporting_evidence=supporting)


class TestTheGateOnLegacyMedia:
    """The refusals a legacy image used to draw were unsatisfiable: they
    demanded winevt/Logs and EvtxECmd of media that has neither."""

    def test_a_logon_negative_after_the_legacy_log_was_read_passes(self, tmp_path):
        calls = [LEGACY, {"type": "tool_call", "success": True,
                          "cmd": "evtexport -m all fs/WINDOWS/system32/config/SecEvent.Evt"}]
        out = nc.check(_ctx(_case(tmp_path),
                            "No logon or session events are recorded for a second "
                            "account; the security log holds no records.", calls))
        assert out is None

    def test_a_logon_negative_without_that_read_demands_the_legacy_log(self, tmp_path):
        out = nc.check(_ctx(_case(tmp_path),
                            "No logon or session events for a second account were found",
                            [LEGACY]))
        assert out is not None and out["gate"] == "negative_completeness"
        assert "SecEvent.Evt" in out["error"]
        assert "TerminalServices" not in out["error"]

    def test_absence_of_the_event_log_demands_the_layout_the_listing_showed(self, tmp_path):
        out = nc.check(_ctx(_case(tmp_path),
                            "The event logs are absent from this host: no Security log "
                            "could be located.", [LEGACY], tier="SUSPECTED"))
        assert out is not None
        assert "eventlog_not_searched" in out["error"]
        assert "SecEvent.Evt" in out["error"] and "evt.evt_export" in out["error"]
        assert "winevt" not in out["error"].split("Search", 1)[1].split("(Windows NT")[0]

    def test_no_layout_shown_means_nothing_is_demanded(self, tmp_path):
        """An opened disk whose listings showed neither layout (or no
        Windows at all) is not asked to search a log it may not have."""
        linux = _listing("var", "etc", "home", "usr")
        out = nc.check(_ctx(_case(tmp_path),
                            "The event logs are absent from this host.",
                            [linux], tier="SUSPECTED"))
        assert out is None


class TestAbsenceIsPredicatedOfTheArtifact:
    """Mentioning a hive and a negation somewhere is not asserting that a
    disk-resident artifact is absent."""

    @pytest.mark.parametrize("text", [
        "The primary domain value in the SECURITY hive is the computer's own "
        "name, so the machine is NOT joined to a domain. The TCP/IP domain "
        "value in the SYSTEM hive is blank.",
        "Recurring registry paths: the typed URLs list one public address; "
        "its purpose is not further established in the evidence.",
        "The registry shows the interface was configured; no second adapter "
        "was in use during the capture.",
    ])
    def test_a_positive_finding_with_a_negation_is_not_an_absence_claim(self, text):
        assert nc._DISK_RESIDENT_RE.search(text)
        assert not nc._ASSERTS_ABSENCE_RE.search(text)

    @pytest.mark.parametrize("text", [
        "no Security.evtx, no System.evtx, no Prefetch directory, no Amcache",
        "The registry hives were not collected from this host.",
        "No $MFT is available for the server.",
        "Prefetch is absent on this machine.",
        "The Security event log does not exist on this volume.",
    ])
    def test_an_absence_predicated_of_the_artifact_still_counts(self, text):
        assert nc._ASSERTS_ABSENCE_RE.search(text)


def test_the_work_order_and_the_ledger_name_both_layouts(tmp_path):
    """The mount plan's work order, written before anything is known about
    the Windows generation, names the Security log of either layout, and the
    ledger's work-order check recognises either."""
    from core.coverage_ledger import _WORK_ORDER_RE
    from core.mount_plan import load_mount_plan, register_exported_image
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    raw = case / "analysis" / "host.raw"
    raw.write_bytes(b"raw")
    register_exported_image(case, raw)
    exp = next(i for i in load_mount_plan(case)["images"] if i.get("origin") == "export_raw")
    order = " ".join(exp["next_work_order"])
    assert "Security.evtx" in order and "SecEvent.Evt" in order
    assert re.search(r"evt\.evt_export", order) and "ez.evtxecmd" in order
    assert _WORK_ORDER_RE.search("SecEvent.Evt") and _WORK_ORDER_RE.search("winevt/Security")
