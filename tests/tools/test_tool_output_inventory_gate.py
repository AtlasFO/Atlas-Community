"""An inventory of a tool's output is not a finding: a statement that opens
on the act of parsing and tallies what came out is refused at record time
and sent to a note; a conclusion that quotes counts on its way to what
they show is not held."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from tools._gates import GateContext
from tools._gates import tool_output_inventory as toi


def _ctx(description, tier="LIKELY"):
    return GateContext(
        description=description, confidence=tier.capitalize(), tier=tier, source="test",
        linked_call_id=0, tested_hypothesis_id="", log=MagicMock(),
        idx=SimpleNamespace(by_call_id={}, by_type={}), window=[], input_call_ids=[])


INVENTORIES = (
    "Amcache.hve (call 20) parsed: 418 file entries, 63 shortcuts, 207 drive "
    "binaries, 9 device containers, 88 device PnPs. Prefetch (call 21): 140 of "
    "141 .pf files parsed (BROWSER.EXE-1A2B3C4D.pf corrupted/unreadable). Both "
    "confirm extensive program execution on the system including the browser.",
    "Security.evtx (call 73) parsed for 2031-03-05 to 2031-03-16: 5,214 total "
    "records, 1,307 in window. 612 logon events (4624), 540 privilege elevation "
    "events (4672), 2 account creation events (4720), 4 network logon events "
    "(4728). Log coverage: 2031-03-06 08:02:11 to 2031-03-15 17:40:05 UTC.",
    "Processed the MFT listing: 41,220 rows, 2,113 deleted entries, 88 ADS records.",
    # a Hayabusa-shaped, a Plaso-shaped and a German inventory
    "Hayabusa processed the winevt tree: 71 high alerts, 402 medium alerts and "
    "1,930 low alerts across 12 channels.",
    "Plaso ingested the image: 4,882,101 events, 27 parsers, 3 warnings.",
    "Amcache.hve geparst: 418 Dateieinträge, 63 Verknüpfungen, 207 Treiber.",
    # a subject that names a user or a tool binary is still an inventory
    "NTUSER.DAT for user jdoe parsed: 4,512 keys and 23 MRU lists.",
    "PECmd.exe processed the Prefetch folder: 140 files, 1 error.",
)

FINDINGS = (
    # counts on the way to a conclusion, opening on the case
    "Attribution: the laptop is owned and used by the single local account "
    "jdoe (SID S-1-5-21-1111111111-2222222222-3333333333-1001). Security.evtx "
    "(call 73) shows 612 interactive logon events (4624) for this account in the "
    "window and none for any other account.",
    "Memory image netscan shows 214 TCPv4 connections to port 443 (call 222), of "
    "which 3 reference cloud addresses: 203.0.113.35 (twice) and 198.51.100.69 (once).",
    "STICK01.dd is a FAT16 filesystem (mkdosfs, 401216 sectors, 4 sectors/cluster) "
    "with no partition table, consistent with a reformatted USB key.",
    "CONFIRMED initial access to DC01 via RDP brute force from 203.0.113.44: 68 "
    "failed logons (4625, LogonType 3) between 04:10 and 04:13 UTC, then one "
    "successful logon (4624) as Administrator at 04:13:22.",
    # a parse that failed is a limitation, not a tally
    "MEDIA#3 (UDF DVD-R) E01 image cannot be parsed by TSK fls - it reports possible "
    "encryption (high entropy 7.81); UDF is not supported by TSK.",
    "NTUSER.DAT for user jdoe is in a dirty state with no transaction logs; "
    "RECmd aborted parsing (0 key/value pairs recovered, call 23), so the "
    "registry-based user activity artifacts from this hive are unavailable.",
    # a parse verb with counts on the way to a conclusion, no colon list
    "Security.evtx parsed for the window shows 68 failed logons (4625) and 1 "
    "successful logon (4624) from 203.0.113.44",
    "Parsed $UsnJrnl shows 1,203 files deleted from C:\\Users\\jdoe\\Documents "
    "between 02:10 and 02:14 and 2 .zip files created in C:\\Windows\\Temp.",
    "Parsing SRUM shows chrome.exe sent 1.2 GB over 14 network connections in 3 "
    "sessions to 198.51.100.10",
    "Parsed the Security log and found that the attacker account 'hacker' was "
    "created at 04:31, and used for 3 RDP logons and 2 network logon events "
    "from 203.0.113.44.",
    # the attacker did the processing
    "The ransomware binary processed 12,000 files on the F: share and 300 files "
    "on C: before the note was dropped.",
    "WinRAR processed 1,204 files from the Projects share into 3 archives; 2 "
    "archive files were then copied to E:\\.",
    # addresses and versions are not counts
    "Amcache parsed: chrome.exe version 98.0.4758.102 connected to 203.0.113.44",
    # the clause's subject did the processing: an act, even as a colon list
    "The attacker processed the share: 12,000 files encrypted and 3 ransom notes dropped.",
)


class TestTheShape:
    def test_a_tally_opening_on_the_parse_is_an_inventory(self):
        for text in INVENTORIES:
            assert len(toi.tally(text)) >= 2, text

    def test_a_conclusion_quoting_counts_is_not(self):
        for text in FINDINGS:
            assert toi.tally(text) == [], text

    def test_an_empty_statement_is_not_held_here(self):
        assert toi.tally("") == [] and toi.tally(None) == []


class TestTheRefusal:
    def test_the_inventory_is_refused_and_told_where_it_goes(self):
        out = toi.check(_ctx(INVENTORIES[0]))
        assert out and out["gate"] == toi.GATE and out["success"] is False
        assert "418 file entries" in out["error"]
        assert "misc.record_agent_message" in out["error"]
        assert out["counts"] == ["418 file entries", "63 shortcuts", "207 drive binaries",
                                 "9 device containers", "88 device PnPs"]
        assert toi.tally(INVENTORIES[1])[:2] == ["5,214 total records", "1,307 in window"]

    def test_a_finding_passes(self):
        for text in FINDINGS:
            assert toi.check(_ctx(text)) is None, text

    def test_it_is_registered_before_the_citation_gates(self):
        from tools._gates import GATES
        names = [n for n, _ in GATES]
        assert names.index("tool_output_inventory") < names.index("lineage_required")


class TestRecordFindingReturnsTheRefusalAlone:
    """An inventory is refused for its shape alone: no evaluation is spent
    on it and no further objection or repair hint rides on the refusal."""

    def test_no_evaluation_and_no_further_objections(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from core.execution_log import ExecutionLog
        from tools import misc
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "1")
        monkeypatch.setattr(misc, "_auto_evaluate",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("evaluated")))
        (tmp_path / "analysis").mkdir()
        log = ExecutionLog()
        log.configure("T", str(tmp_path / "analysis" / "trace.json"), save_session=False)
        log._entries.clear()
        log.record_dair_call("Analyze", "", False, "", "", "stay", "")
        cid = log.record_tool_call("<py>:ez_amcache", True, False, 0, 0,
                                   evidence_ref="mnt/host/fs/Windows/AppCompat/Programs/Amcache.hve",
                                   stdout_excerpt="418 file entries, 63 shortcuts")
        with patch("core.execution_log.log", log):
            r = misc.record_finding(description=INVENTORIES[0], confidence="CONFIRMED",
                                    source="ez.amcache", linked_call_id=cid,
                                    input_call_ids=[cid], supporting_evidence="418 entries",
                                    host="HOST1")
        assert r["success"] is False and r["gate"] == toi.GATE
        assert "also_refused_by" not in r and "repair_hint" not in r and "evaluation" not in r
        assert "ALSO REFUSED" not in r["error"]

    def test_a_finding_inside_a_note_meets_the_same_gate(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from core.execution_log import ExecutionLog
        from tools import misc
        monkeypatch.setenv("ATLAS_FINDING_AUTO_EVALUATE", "0")
        (tmp_path / "analysis").mkdir()
        log = ExecutionLog()
        log.configure("T", str(tmp_path / "analysis" / "trace.json"), save_session=False)
        log._entries.clear()
        log.record_dair_call("Analyze", "", False, "", "", "stay", "")
        cid = log.record_tool_call("<py>:ez_amcache", True, False, 0, 0,
                                   evidence_ref="mnt/host/fs/Windows/AppCompat/Programs/Amcache.hve",
                                   stdout_excerpt="418 file entries, 63 shortcuts")
        with patch("core.execution_log.log", log):
            r = misc.record_agent_message("Parsed the execution artifacts.", input_call_ids=[cid],
                                          findings=[{"description": INVENTORIES[0],
                                                     "confidence": "LIKELY", "linked_call_id": cid,
                                                     "source": "ez.amcache"}])
        assert r["success"]
        inner = r.get("findings") or r.get("finding_results") or []
        assert inner and any((f.get("gate") == toi.GATE) for f in inner if isinstance(f, dict)), r

