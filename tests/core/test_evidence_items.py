"""Every delivered piece of evidence is an item with a status: containers
are items of their own wherever they sit, segments fold into their head,
the rest groups by the top level of evidence/; a probe call naming a path
under an item credits it, a listing, a hash, a recorded finding or an
ancestor directory does not; the report, the rerun and the checks read it,
and the finish floor does not."""
import json

import pytest

from core import coverage_ledger as cl
from core import evidence_items as ei

FILES = [
    "disk.E01", "disk.E02", "traffic.pcap", "tools.zip", "notes.txt", "notes.txt:Zone.Identifier",
    "kape/C/Windows/System32/winevt/Logs/Security.evtx", "kape/C/Windows/System32/winevt/Logs/System.evtx",
    "kape/C/Users/u/NTUSER.DAT", "kape/C/Windows/MEMORY.DMP", "kape/C/memdump.mem",
    "wrap/inner/only.log", "split/image.001", "split/image.002",
    "logs/app.log.001", "logs/app.log.002", "logs/app.log.003",
    "vm/disk.vmdk", "vm/disk-flat.vmdk", ".DS_Store",
]


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True)
    for rel in FILES:
        p = d / "evidence" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x" * 16)
    (d / "evidence" / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 20)
    cl.build_coverage_ledger(d)
    return d


def _items(case):
    return {i["path"]: i for i in cl.load_ledger(case)["items"].values()}


def _probe(case, tool, args, result='{"success": true, "_atlas_call_id": 7}'):
    cl.observe_tool_paths(case, tool_name=tool, cmd_or_args=json.dumps(args), success=True, result_text=result)


class TestGrouping:
    def test_containers_segments_and_the_rest(self, case):
        items = _items(case)
        kinds = {p: i["kind"] for p, i in items.items()}
        assert kinds == {
            "evidence/disk.E01": "image", "evidence/traffic.pcap": "capture", "evidence/tools.zip": "archive",
            "evidence/kape/C/memdump.mem": "memory", "evidence/split/image.001": "image",
            "evidence/vm/disk.vmdk": "image", "evidence/notes.txt": "file", "evidence/kape/C": "tree",
            "evidence/wrap/inner/only.log": "file", "evidence/logs": "tree",
        }
        assert items["evidence/disk.E01"]["segments"] == ["evidence/disk.E02"]
        assert items["evidence/split/image.001"]["segments"] == ["evidence/split/image.002"]
        assert items["evidence/vm/disk.vmdk"]["segments"] == ["evidence/vm/disk-flat.vmdk"]
        assert all(i["status"] == "unseen" for i in items.values())

    def test_a_rebuild_keeps_the_state_of_unchanged_items(self, case):
        _probe(case, "table_table_query", {"path": "evidence/logs/app.log.002"})
        cl.build_coverage_ledger(case)
        assert _items(case)["evidence/logs"]["status"] == "examined"


class TestContact:
    def test_a_file_inside_a_tree_is_counted_against_the_tree(self, case):
        _probe(case, "ez_evtxecmd", {"file_path": "evidence/kape/C/Windows/System32/winevt/Logs/Security.evtx"})
        tree = _items(case)["evidence/kape/C"]
        assert tree["status"] == "examined" and tree["examined_by"] == {"call_id": "7", "tool": "ez_evtxecmd"}
        row = next(r for r in ei.rows(case) if r["path"] == "evidence/kape/C")
        assert (row["named_files"], row["files"], row["named_folders"]) == (1, 4, 0)
        # a container inside the tree takes what lies under it; a crash
        # dump the profile reads as a file stays in the tree
        _probe(case, "vol_vol_pslist", {"memory_path": "evidence/kape/C/memdump.mem"})
        assert _items(case)["evidence/kape/C/memdump.mem"]["status"] == "examined"
        row = next(r for r in ei.rows(case) if r["path"] == "evidence/kape/C")
        assert row["named_files"] == 1

    def test_a_named_folder_is_counted_as_a_folder(self, case):
        _probe(case, "ez_evtxecmd", {"directory": "evidence/kape/C/Windows/System32/winevt/Logs"})
        row = next(r for r in ei.rows(case) if r["path"] == "evidence/kape/C")
        assert (row["named_files"], row["named_folders"]) == (0, 1)

    def test_listings_hashes_findings_and_ancestors_credit_nothing(self, case):
        _probe(case, "misc_list_evidence_dir", {"path": "evidence/traffic.pcap"})
        _probe(case, "hash_hash_file", {"file_path": "evidence/traffic.pcap"})
        _probe(case, "misc_record_finding", {"description": "beaconing in evidence/traffic.pcap"})
        _probe(case, "strings_grep", {"path": "evidence"})
        _probe(case, "yara_scan", {"path": "evidence/kape"})
        assert all(i["status"] == "unseen" for i in _items(case).values())

    def test_a_job_start_reads_the_evidence_it_names(self, case):
        _probe(case, "job_job_start_bulk_extractor", {"image_path": "evidence/split/image.001"})
        assert _items(case)["evidence/split/image.001"]["status"] == "examined"

    def test_a_failed_call_credits_nothing(self, case):
        cl.observe_tool_paths(case, tool_name="net_tshark", cmd_or_args='{"pcap_path": "evidence/traffic.pcap"}',
                              success=False, result_text="ERROR: bad file")
        assert _items(case)["evidence/traffic.pcap"]["status"] == "unseen"

    def test_an_image_is_read_through_its_mount(self, case):
        (case / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
            {"path": str(case / "evidence" / "disk.E01"), "mount_result": {}}]}), encoding="utf-8")
        _probe(case, "tsk_tsk_fls", {"path": str(case / "mnt" / "disk" / "fs" / "Windows")})
        assert _items(case)["evidence/disk.E01"]["status"] == "examined"

    def test_an_archive_is_read_through_the_folder_it_was_extracted_to(self, case):
        out = case / "exports" / "tools"
        out.mkdir(parents=True)
        for n in ("a.exe", "b.dll", "c.txt"):
            (out / n).write_bytes(b"x")
        cl.register_derived_outputs(case, tool_name="archive_zip_extract",
                                    arguments={"archive_path": "evidence/tools.zip", "output_dir": "exports/tools"},
                                    result_text='{"success": true}')
        _probe(case, "misc_pe_info", {"file_path": "exports/tools/a.exe"})
        row = next(r for r in ei.rows(case) if r["path"] == "evidence/tools.zip")
        assert row["status"] == "examined" and (row["named_files"], row["files"]) == (1, 3)


class TestBlocked:
    def test_a_blocked_item_needs_a_failed_attempt_and_no_read(self, case):
        r = cl.mark_unit_blocked(case, "evidence/traffic.pcap", reason="capture header is corrupt", trace_entries=[])
        assert not r["success"] and "no tool call" in r["error"]
        trace = [{"type": "tool_call", "cmd": "<py>:net_tshark evidence/traffic.pcap",
                  "success": False, "failure_class": "tool_error"}]
        r = cl.mark_unit_blocked(case, "evidence/traffic.pcap", reason="capture header is corrupt", trace_entries=trace)
        assert r["success"] and _items(case)["evidence/traffic.pcap"]["status"] == "blocked"
        # the blocking call names the path in the model's own words: no read
        _probe(case, "coverage_mark_blocked", {"path": "evidence/traffic.pcap"})
        assert _items(case)["evidence/traffic.pcap"]["status"] == "blocked"
        _probe(case, "table_table_query", {"path": "evidence/logs/app.log.001"})
        trace = [{"type": "tool_call", "cmd": "<py>:x evidence/logs"}]
        r = cl.mark_unit_blocked(case, "evidence/logs", reason="unreadable encoding throughout", trace_entries=trace)
        assert not r["success"] and "was read" in r["error"]

    def test_a_blocked_unit_blocks_its_item(self, case):
        trace = [{"type": "tool_call", "cmd": "fls evidence/disk.E01", "mcp_tool": "tsk_tsk_fls",
                  "success": False, "failure_class": "tool_error", "stderr": "invalid EWF header checksum"}]
        r = cl.mark_unit_blocked(case, "evidence/disk.E01", reason="EWF header checksum fails", trace_entries=trace)
        assert r["success"] and _items(case)["evidence/disk.E01"]["status"] == "blocked"


class TestReaders:
    def test_report_table_and_gaps_in_both_languages(self, case):
        _probe(case, "net_tshark", {"pcap_path": "evidence/traffic.pcap"})
        findings = [{"finding_id": "F-001", "input_call_ids": [7]}, {"finding_id": "F-002", "input_call_ids": [9]}]
        en = ei.report_lines(case, findings, "en")
        assert en[0].startswith("**Evidence coverage:** 1 of 10 delivered items examined, 0 blocked, 9 not examined")
        row = next(x for x in en if "traffic.pcap" in x)
        assert "| capture | examined | call 7 (net_tshark) | F-001 |" in row
        assert en.index(row) == len(en) - 1                 # not examined first
        assert "`evidence/disk.E01` (+1 segments)" in "\n".join(en)
        gaps = ei.gap_lines(case, "en")
        assert len(gaps) == 9 and not any("traffic.pcap" in g for g in gaps)
        de = ei.report_lines(case, findings, "de")
        assert de[0].startswith("**Auswertung der Beweismittel:** 1 von 10") and "Mitschnitt" in "\n".join(de)
        assert ei.gap_lines(case, "de")[0].startswith("- Nicht ausgewertet:")

    def test_the_rerun_is_pending_while_an_item_is_unread(self, case):
        from core.incremental import summarize_work
        work = summarize_work({"case_dir": str(case)}, open_tasks=[])
        assert work["pending"] and "10 delivered items not yet examined" in work["reasons"]
        led = cl.load_ledger(case)
        for i in led["items"].values():
            i["status"] = "blocked"
        cl.save_ledger(case, led)
        assert summarize_work({"case_dir": str(case)}, open_tasks=[])["pending"] is False

    def test_the_rerun_brief_lists_what_is_unread_and_what_was_read_in_part(self, case):
        from core.rerun_brief import build_rerun_brief
        _probe(case, "table_table_query", {"path": "evidence/logs/app.log.001"})
        text = build_rerun_brief(case, {"case_id": "X"})["text"]
        section = text.split("## Evidence not yet examined", 1)[1].split("\n## ", 1)[0]
        assert "- evidence/traffic.pcap" in section and "- evidence/logs\n" not in section
        assert "- evidence/logs: calls named 1 of 3 files" in section

    def test_a_clear_resets_the_items(self, case):
        _probe(case, "net_tshark", {"pcap_path": "evidence/traffic.pcap"})
        cl.reset_unit_statuses(case)
        item = _items(case)["evidence/traffic.pcap"]
        assert item["status"] == "unseen" and item["touched"] == [] and item["examined_by"] is None

    def test_the_finish_floor_ignores_the_items(self, case):
        led = cl.load_ledger(case)
        before = (cl.ready_for_degraded_exit(case), cl.exit_block_reason(case))
        for i in led["items"].values():
            i["status"] = "examined"
        cl.save_ledger(case, led)
        assert (cl.ready_for_degraded_exit(case), cl.exit_block_reason(case)) == before

    def test_a_handling_stop_withholds_names_but_keeps_the_rows(self, case, monkeypatch):
        from core import handling_stop as hs
        monkeypatch.setattr(hs, "state", lambda _c: {"class": "csam", "frame": "subject"})
        monkeypatch.setattr(hs, "path_is_media", lambda p: str(p).endswith("notes.txt"))
        text = "\n".join(ei.report_lines(case, [], "en"))
        assert "notes.txt" not in text and "withheld under the handling stop" in text
        assert "evidence/notes.txt" not in ei.unseen(case)
