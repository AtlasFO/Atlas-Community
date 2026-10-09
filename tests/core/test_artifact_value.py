"""Artifact value model + absence-contradiction guard.

Fixtures model a listing of event logs whose first entries are empty
channels: a run that reads only the top of such a listing and then reports
the rest as absent must be caught.
"""
from __future__ import annotations

import json
import os

import pytest

from core import artifact_value as av

EMPTY_EVTX = 69632


def _by_name(known, name):
    """The index entry for a basename (volume entries are keyed by path)."""
    return next(v for v in known.values() if v["name"].lower() == name.lower())


def _names(known):
    return {v["name"].lower() for v in known.values()}


@pytest.fixture(autouse=True)
def _scratch_mounts_are_live(monkeypatch):
    """A scratch volume is a plain directory; the mount plan's liveness
    rule reads the mount table, so a test volume under ``mnt/`` counts as
    mounted when it exists."""
    from core import mount_plan
    real = mount_plan._path_is_mounted
    monkeypatch.setattr(mount_plan, "_path_is_mounted",
                        lambda p: (os.path.isdir(p) and "/mnt/" in str(p).replace("\\", "/"))
                        or real(p))


def _case(tmp_path, *, listing=(), files=(), claims=(), trace_cmds=()):
    (tmp_path / ".atlas").mkdir(parents=True, exist_ok=True)
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    if listing:
        lines = ["_host,FileName,FileSize"]
        lines += [f"{h},{n},{s}" for h, n, s in listing]
        (tmp_path / "analysis" / "mft_rows.csv").write_text(
            "\n".join(lines) + "\n", encoding="utf-8")
    for rel, size in files:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x" * size)
    nodes = {
        f"C{i:04d}": {"id": f"C{i:04d}", "kind": "claim", "status": "new",
                      "statement": t}
        for i, t in enumerate(claims, start=1)
    }
    (tmp_path / ".atlas" / "claim_graph.json").write_text(
        json.dumps({"schema_version": "1.0", "nodes": nodes, "edges": []}),
        encoding="utf-8")
    (tmp_path / "analysis" / "CASE_trace.json").write_text(
        json.dumps([{"type": "tool_call", "cmd": c} for c in trace_cmds]),
        encoding="utf-8")
    return tmp_path


class TestValueModel:
    def test_security_log_outranks_a_noise_channel(self):
        sec, _ = av.artifact_score("Security.evtx", 20_971_520)
        bio, _ = av.artifact_score(
            "Microsoft-Windows-Biometrics%4Operational.evtx", 5_000_000)
        assert sec > bio

    def test_an_empty_log_is_worth_almost_nothing(self):
        """The exact trap: a 69,632-byte evtx is a header, not a channel."""
        full, _ = av.artifact_score("Security.evtx", 20_971_520)
        empty, why = av.artifact_score("Setup.evtx", EMPTY_EVTX)
        assert empty < full / 10
        assert "empty" in why

    def test_zero_byte_artifacts_are_empty(self):
        assert av.looks_empty("CORP-DC01_UsnJrnl_J.bin", 0)
        assert not av.looks_empty("Security.evtx", 20_971_520)

    def test_unknown_artifacts_score_zero(self):
        assert av.artifact_score("thumbs.db", 4096)[0] == 0

    def test_ranking_is_by_value_not_listing_order(self):
        entries = [
            {"name": "Setup.evtx", "size": EMPTY_EVTX},          # listed first
            {"name": "Microsoft-Windows-Biometrics%4Operational.evtx",
             "size": EMPTY_EVTX},
            {"name": "Security.evtx", "size": 134_217_728},      # listed last
        ]
        assert av.rank_artifacts(entries)[0]["name"] == "Security.evtx"


class TestKnownArtifacts:
    def test_a_listing_counts_as_knowing(self, tmp_path):
        """A run that wrote the listing cannot claim not to know."""
        case = _case(tmp_path, listing=[("h1", "Security.evtx", "20971520")])
        known = av.known_artifacts(case)
        assert "h1|security.evtx" in known
        assert known["h1|security.evtx"]["size"] == 20_971_520

    def test_the_largest_sighting_wins(self, tmp_path):
        case = _case(tmp_path, listing=[("h1", "Security.evtx", str(EMPTY_EVTX)),
                                        ("h1", "Security.evtx", "134217728")])
        assert av.known_artifacts(case)["h1|security.evtx"]["size"] == 134_217_728

    def test_two_hosts_copies_are_two_artifacts(self, tmp_path):
        case = _case(tmp_path, listing=[("h1", "Security.evtx", "20971520"),
                                        ("h2", "Security.evtx", "134217728")])
        assert sorted(v["host"] for v in av.known_artifacts(case).values()
                      if v["name"] == "Security.evtx") == ["h1", "h2"]


class TestUnexaminedHighValue:
    def test_unread_high_value_artifacts_are_surfaced(self, tmp_path):
        case = _case(
            tmp_path,
            listing=[("h1", "Security.evtx", "20971520"),
                     ("h1", "Setup.evtx", str(EMPTY_EVTX)),
                     ("h1", "notes.txt", "10")],
            trace_cmds=["evtx_dump analysis/Setup.evtx"])
        names = [a["name"] for a in av.unexamined_high_value(case)]
        assert "Security.evtx" in names

    def test_an_artifact_the_run_opened_is_not_owed(self, tmp_path):
        case = _case(
            tmp_path,
            listing=[("h1", "Security.evtx", "20971520")],
            trace_cmds=["evtxecmd -f analysis/Security.evtx"])
        assert not av.unexamined_high_value(case)

    def test_empty_artifacts_are_not_owed(self, tmp_path):
        """Nothing to read is not the same as something unread."""
        case = _case(tmp_path,
                     listing=[("h1", "Setup.evtx", str(EMPTY_EVTX))])
        assert not av.unexamined_high_value(case)


def _mounted_case(tmp_path, *, trace_cmds=()):
    """A case whose one image is mounted: an XP-spelled volume with three
    hives and a profile, recorded in the mount plan the way plane_a does."""
    from core.mount_plan import save_mount_plan
    case = _case(tmp_path, trace_cmds=trace_cmds)
    fs = case / "mnt" / "host" / "fs"
    config = fs / "WINDOWS" / "system32" / "config"
    config.mkdir(parents=True)
    for hive, size in (("SAM", 262_144), ("system", 4_980_736), ("software", 9_437_184)):
        (config / hive).write_bytes(b"regf" + b"\x00" * 64)
        os.truncate(config / hive, size)
    profile = fs / "Documents and Settings" / "Bob"
    profile.mkdir(parents=True)
    (profile / "NTUSER.DAT").write_bytes(b"regf" + b"\x00" * 64)
    os.truncate(profile / "NTUSER.DAT", 1_048_576)
    (case / "evidence").mkdir(exist_ok=True)
    (case / "evidence" / "host.E01").write_bytes(b"EVF" * 16)
    save_mount_plan(case, {"images": [{
        "path": str(case / "evidence" / "host.E01"), "stem": "host",
        "status": "mounted",
        "mount_result": {"success": True, "mount_point": str(fs),
                         "ewf_device": str(case / "mnt" / "host" / "ewf" / "ewf1")}}]})
    return case


class TestVolumeArtifacts:
    def test_a_mounted_volume_makes_its_hives_known_by_path(self, tmp_path):
        """Once an image is mounted the run reads it through the mount and
        the image is one coverage unit; the value table's artifacts on the
        volume must still be known, spelled as the volume spells them."""
        case = _mounted_case(tmp_path)
        known = av.known_artifacts(case)
        assert {"sam", "system", "software", "ntuser.dat"} <= _names(known)
        assert _by_name(known, "sam")["path"] == "mnt/host/fs/WINDOWS/system32/config/SAM"
        assert _by_name(known, "ntuser.dat")["path"].startswith("mnt/host/fs/Documents and Settings/")
        assert _by_name(known, "system")["source"] == "mount:host"

    def test_the_name_alone_in_the_trace_does_not_count_as_reading_a_hive(self, tmp_path):
        """"system" and "software" appear in any trace; a hive on a mounted
        volume is read by its path, or extracted under analysis/ by name."""
        case = _mounted_case(tmp_path, trace_cmds=[
            "strings_grep pattern=system file_path=analysis/notes.txt",
            "tsk_fls mnt/host/fs/WINDOWS/system32",
        ])
        owed = {a["name"].lower() for a in av.unexamined_high_value(case)}
        assert {"sam", "system", "software", "ntuser.dat"} <= owed

    def test_a_hive_read_in_place_or_extracted_is_not_owed(self, tmp_path):
        case = _mounted_case(tmp_path, trace_cmds=[
            "ez_recmd_hive mnt/host/fs/WINDOWS/system32/config/SAM",
            "tsk_icat image 1234 analysis/SYSTEM",
            "ez_recmd_hive -f analysis/SYSTEM --csv analysis/system_out",
        ])
        owed = {a["name"].lower() for a in av.unexamined_high_value(case)}
        assert "sam" not in owed and "system" not in owed
        assert "software" in owed and "ntuser.dat" in owed

    def test_the_nudge_names_where_the_artifact_is(self, tmp_path):
        case = _mounted_case(tmp_path)
        text = av.format_value_nudge(av.unexamined_high_value(case))
        assert "SAM" in text and "at mnt/host/fs/WINDOWS/system32/config/SAM" in text


class TestAbsenceContradiction:
    def test_absence_over_an_indexed_artifact_is_caught(self, tmp_path):
        case = _case(
            tmp_path,
            listing=[("h1", "Security.evtx", "20971520")],
            claims=("Standard Windows forensic artifacts are absent from "
                    "FILESRV01: no Security.evtx, no Prefetch directory.",))
        clashes = av.contradicted_absence_claims(case)
        assert len(clashes) == 1
        assert clashes[0]["artifact"] == "Security.evtx"
        assert clashes[0]["size"] == 20_971_520

    def test_absence_of_something_truly_missing_is_fine(self, tmp_path):
        case = _case(
            tmp_path,
            listing=[("h1", "Setup.evtx", str(EMPTY_EVTX))],
            claims=("No Amcache.hve was recovered from this image.",))
        assert av.contradicted_absence_claims(case) == []

    def test_a_positive_statement_is_not_a_contradiction(self, tmp_path):
        case = _case(
            tmp_path,
            listing=[("h1", "Security.evtx", "20971520")],
            claims=("Security.evtx shows logon events for the tempadmin "
                    "account.",))
        assert av.contradicted_absence_claims(case) == []

    def test_withdrawn_beliefs_are_ignored(self, tmp_path):
        case = _case(tmp_path, listing=[("h1", "Security.evtx", "20971520")])
        graph = json.loads(
            (case / ".atlas" / "claim_graph.json").read_text())
        graph["nodes"] = {"C0001": {"id": "C0001", "kind": "claim",
                                    "status": "withdrawn",
                                    "statement": "no Security.evtx present"}}
        (case / ".atlas" / "claim_graph.json").write_text(json.dumps(graph))
        assert av.contradicted_absence_claims(case) == []

    def test_an_empty_indexed_artifact_does_not_refute_absence(self, tmp_path):
        """Claiming a channel has nothing in it is fair when it is empty."""
        case = _case(
            tmp_path,
            listing=[("h1", "Setup.evtx", str(EMPTY_EVTX))],
            claims=("no Setup.evtx content was recoverable",))
        assert av.contradicted_absence_claims(case) == []


class TestObligations:
    def test_both_duties_block_complete(self, tmp_path):
        from core.investigation_obligations import (
            list_obligations, obligations_met_for_complete,
        )
        case = _case(
            tmp_path,
            listing=[("h1", "Security.evtx", "20971520")],
            claims=("no Security.evtx was recovered from the MFT",))
        ids = {o["id"] for o in list_obligations(case) if not o["met"]}
        assert "absence_claims_supported" in ids
        assert "high_value_artifacts_examined" in ids
        assert not obligations_met_for_complete(case)

    def test_a_clean_case_does_not_trip_them(self, tmp_path):
        from core.investigation_obligations import list_obligations
        case = _case(
            tmp_path,
            listing=[("h1", "Security.evtx", "20971520")],
            claims=("Security.evtx shows 4624 logons for tempadmin.",),
            trace_cmds=["evtxecmd -f analysis/Security.evtx"])
        unmet = {o["id"] for o in list_obligations(case) if not o["met"]}
        assert "absence_claims_supported" not in unmet
        assert "high_value_artifacts_examined" not in unmet


class TestNudge:
    def test_nudge_explains_both_problems(self, tmp_path):
        case = _case(
            tmp_path,
            listing=[("h1", "Security.evtx", "20971520")],
            claims=("no Security.evtx was recovered",))
        text = av.format_value_nudge(
            av.unexamined_high_value(case),
            av.contradicted_absence_claims(case))
        assert "Security.evtx" in text
        assert "20,971,520" in text
        assert "absent" in text.lower()

    def test_nothing_owed_means_no_message(self):
        assert av.format_value_nudge([], []) == ""


class TestResilience:
    def test_empty_case_is_inert(self, tmp_path):
        assert av.known_artifacts(tmp_path) == {}
        assert av.unexamined_high_value(tmp_path) == []
        assert av.contradicted_absence_claims(tmp_path) == []

    def test_malformed_listing_does_not_raise(self, tmp_path):
        (tmp_path / "analysis").mkdir(parents=True)
        (tmp_path / "analysis" / "broken.csv").write_text(
            "not,a,listing\n1,2\n", encoding="utf-8")
        assert av.unexamined_high_value(tmp_path) == []


class TestPayloadIsNotEvidence:
    """A component-store assembly or package carries the name of the channel
    it installs, never its records: an RDP client package is not RDP
    session history and must not be owed as unread evidence."""

    def test_component_store_names_score_nothing(self):
        for name in ("amd64_microsoft-windows-t..localsessionmanager_31bf3856ad364e35_6.1.7601.17514_none_036ad230212a39ce",
                     "amd64_microsoft-windows-t..localsessionmanager_31bf3856ad364e35_6.1.7601.17514_none_036ad230212a39ce.manifest",
                     "Microsoft-Windows-TerminalServices-MiscRedirection-Package~31bf3856ad364e35~amd64~~6.1.7601.17514.mum",
                     "Microsoft-Windows-SmbClient-Package~31bf3856ad364e35~amd64~~6.1.7601.17514.cat"):
            assert av.artifact_score(name) == (0, ""), name

    def test_the_event_logs_of_those_channels_still_score(self):
        assert av.artifact_score("Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx")[0] == 86
        assert av.artifact_score("Microsoft-Windows-SmbClient%4Security.evtx")[0] == 68
        assert av.artifact_score("Microsoft-Windows-Windows Defender%4Operational.evtx")[0] == 70

    def test_a_blocked_unit_is_owed_no_longer(self, tmp_path):
        from core.coverage_ledger import save_ledger
        case = _case(tmp_path, listing=[("h1", "Security.evtx", "20971520"),
                                        ("h1", "System.evtx", "5000000")])
        save_ledger(case, {"units": {"u1": {"path": "evidence/h1/Windows/System32/winevt/Logs/System.evtx",
                                             "status": "blocked", "reason": "parser rejects the file"}}})
        names = [a["name"] for a in av.unexamined_high_value(case)]
        assert "Security.evtx" in names and "System.evtx" not in names


class TestQuestionNamedArtifactsComeFirst:
    """What the case's own questions name outranks the value table: the
    author pointed at it, whatever kind of artifact it is."""

    def _with_question(self, tmp_path, question, listing):
        from core.investigation_tasks import reconcile_case_md
        case = _case(tmp_path, listing=listing)
        (case / "CASE.md").write_text(
            f"## Investigation Requests\n\n- {question}\n", encoding="utf-8")
        reconcile_case_md(case, persist=True)
        return case

    def test_a_named_database_the_value_table_ignores_is_owed_first(self, tmp_path):
        case = self._with_question(
            tmp_path, "By which channel: Google Drive (sync DB, snapshot.db cloud_entry table) or USB",
            [("h1", "Security.evtx", "20971520"), ("h1", "snapshot.db", "204800")])
        owed = av.unexamined_high_value(case)
        assert [a["name"] for a in owed][:2] == ["snapshot.db", "Security.evtx"]
        assert owed[0]["why"] == "named in the case's own questions"
        assert av.question_named_artifacts(case) == {"snapshot.db"}

    def test_a_named_artifact_the_run_read_is_not_owed(self, tmp_path):
        case = self._with_question(
            tmp_path, "Read the sync database snapshot.db",
            [("h1", "snapshot.db", "204800")])
        (case / "analysis" / "CASE_trace.json").write_text(
            '[{"type": "tool_call", "cmd": "sqlite3 analysis/snapshot.db .tables"}]', encoding="utf-8")
        assert not av.unexamined_high_value(case)

    def test_a_question_naming_no_file_changes_nothing(self, tmp_path):
        case = self._with_question(tmp_path, "Who used the machine and when?",
                                   [("h1", "Security.evtx", "20971520")])
        assert av.question_named_artifacts(case) == set()
        assert [a["name"] for a in av.unexamined_high_value(case)] == ["Security.evtx"]


def _win10_case(tmp_path, *, trace_cmds=(), pf_files=0):
    """A mounted Windows 10 volume with the artifact classes the table
    learned: a Recycle Bin record, the device-install log, a Recent folder
    with a shortcut and a Jump List, Chrome's History, an empty burn
    folder, the hives, and as many Prefetch files as asked for."""
    from core.mount_plan import save_mount_plan
    case = _case(tmp_path, trace_cmds=trace_cmds)
    fs = case / "mnt" / "host" / "fs"
    config = fs / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    for hive in ("SAM", "SYSTEM", "SOFTWARE"):
        (config / hive).write_bytes(b"regf" + b"\x00" * 64)
        os.truncate(config / hive, 262_144)
    (config / "systemprofile").mkdir()
    (fs / "Windows" / "inf").mkdir(parents=True)
    (fs / "Windows" / "inf" / "setupapi.dev.log").write_text("x" * 5000, encoding="utf-8")
    bin_dir = fs / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
    bin_dir.mkdir(parents=True)
    (bin_dir / "$IABCDEF.docx").write_bytes(b"\x02" * 544)
    (bin_dir / "$RABCDEF.docx").write_bytes(b"\x00" * 4096)
    recent = fs / "Users" / "bob" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
    (recent / "AutomaticDestinations").mkdir(parents=True)
    (recent / "CustomDestinations").mkdir()
    (recent / "desktop.ini").write_text("[.ShellClassInfo]", encoding="utf-8")
    (recent / "plan.docx.lnk").write_bytes(b"L" * 900)
    (recent / "AutomaticDestinations" / "1b4dd67f29cb1962.automaticDestinations-ms").write_bytes(b"\xd0" * 3000)
    chrome = fs / "Users" / "bob" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    chrome.mkdir(parents=True)
    (chrome / "History").write_bytes(b"SQLite format 3" + b"\x00" * 8000)
    burn = fs / "Users" / "bob" / "AppData" / "Local" / "Microsoft" / "Windows" / "Burn" / "Burn"
    burn.mkdir(parents=True)
    (burn / "desktop.ini").write_text("[.ShellClassInfo]", encoding="utf-8")
    prefetch = fs / "Windows" / "Prefetch"
    prefetch.mkdir()
    for i in range(pf_files):
        (prefetch / f"PROGRAM{i:04d}.EXE-{i:08X}.pf").write_bytes(b"MAM\x04" + b"\x00" * 300)
    (case / "evidence").mkdir(exist_ok=True)
    (case / "evidence" / "host.E01").write_bytes(b"EVF" * 16)
    save_mount_plan(case, {"images": [{
        "path": str(case / "evidence" / "host.E01"), "stem": "host", "status": "mounted",
        "mount_result": {"success": True, "mount_point": str(fs)}}]})
    return case


class TestWiderValueTable:
    def test_the_new_classes_score(self):
        assert av.artifact_score("$IABCDEF.docx")[0] == 76
        assert av.artifact_score("INFO2")[0] == 76
        assert av.artifact_score("setupapi.dev.log")[0] == 75
        assert av.artifact_score("Recent")[0] == 74
        assert av.artifact_score("1b4dd67f29cb1962.automaticDestinations-ms")[0] == 74
        assert av.artifact_score("History")[0] == 72
        assert av.artifact_score("places.sqlite")[0] == 72
        assert av.artifact_score("StickyNotes.snt")[0] == 70
        assert av.artifact_score("Burn")[0] == 70
        assert av.artifact_score("Windows.edb")[0] == 68
        assert av.artifact_score("thumbcache_256.db")[0] == 66
        assert av.artifact_score("Login Data")[0] == 66
        # shortcuts and thumbnails are not scored: a weight is never inert
        assert av.artifact_score("plan.docx.lnk")[0] == 0
        assert av.artifact_score("Thumbs.db")[0] == 0
        assert av.artifact_score("recent_report.docx")[0] == 0

    def test_the_volume_knows_the_classes_by_path(self, tmp_path):
        case = _win10_case(tmp_path)
        known = av.known_artifacts(case)
        rec = _by_name(known, "$iabcdef.docx")
        assert rec["path"] == "mnt/host/fs/$Recycle.Bin/S-1-5-21-1-2-3-1001/$IABCDEF.docx"
        assert rec["roots"] == ["mnt/host/fs/$Recycle.Bin/S-1-5-21-1-2-3-1001", "mnt/host/fs/$Recycle.Bin"]
        assert _by_name(known, "setupapi.dev.log")["path"].endswith("Windows/inf/setupapi.dev.log")
        assert _by_name(known, "recent")["kind"] == "directory" and _by_name(known, "recent")["size"] == 1
        assert _by_name(known, "automaticdestinations")["size"] == 1
        assert _by_name(known, "history")["path"].endswith("Chrome/User Data/Default/History")
        assert _by_name(known, "burn")["kind"] == "directory" and _by_name(known, "burn")["size"] == 0
        # shortcuts are read through their folder; the $R payload is not a record
        names = _names(known)
        assert "plan.docx.lnk" not in names and "$rabcdef.docx" not in names

    def test_an_idle_folder_is_not_owed_and_a_full_one_is(self, tmp_path):
        case = _win10_case(tmp_path)
        owed = {a["name"].lower() for a in av.unexamined_high_value(case)}
        assert "burn" not in owed
        assert {"recent", "automaticdestinations", "history", "$iabcdef.docx",
                "setupapi.dev.log", "sam"} <= owed

    def test_a_folder_parse_credits_the_family(self, tmp_path):
        case = _win10_case(tmp_path, pf_files=3, trace_cmds=[
            "ez_rbcmd -d mnt/host/fs/$Recycle.Bin --csv analysis/rb",
            "ez_pecmd -d mnt/host/fs/Windows/Prefetch --csv analysis/pf",
            "ez_lecmd -d mnt/host/fs/Users/bob/AppData/Roaming/Microsoft/Windows/Recent/",
        ])
        owed = {a["name"].lower() for a in av.unexamined_high_value(case)}
        assert "$iabcdef.docx" not in owed
        assert not any(n.endswith(".pf") for n in owed)
        assert "recent" not in owed
        # a member read on its own credits only itself
        case = _win10_case(tmp_path / "b", pf_files=2, trace_cmds=[
            "tsk_icat image 77 mnt/host/fs/Windows/Prefetch/PROGRAM0000.EXE-00000000.pf"])
        owed = {a["name"] for a in av.unexamined_high_value(case)}
        assert "PROGRAM0000.EXE-00000000.pf" not in owed
        assert "PROGRAM0001.EXE-00000001.pf" in owed

    def test_a_listing_of_the_folder_does_not_credit_a_singleton(self, tmp_path):
        case = _win10_case(tmp_path, trace_cmds=[
            "tsk_fls mnt/host/fs/Windows/System32/config",
            "tsk_fls mnt/host/fs/Windows/System32/config/systemprofile",
            "strings_read_text mnt/host/fs/Windows/System32/config/SAM.LOG1",
        ])
        owed = {a["name"].lower() for a in av.unexamined_high_value(case)}
        assert {"sam", "system", "software"} <= owed

    def test_a_large_family_does_not_crowd_out_the_singletons(self, tmp_path):
        case = _win10_case(tmp_path, pf_files=500)
        known = av.known_artifacts(case)
        assert {"sam", "system", "software", "setupapi.dev.log", "history"} <= _names(known)
        assert sum(1 for n in _names(known) if n.endswith(".pf")) == 100

    def test_the_nudge_counts_a_folder_in_files(self, tmp_path):
        case = _win10_case(tmp_path)
        text = av.format_value_nudge(av.unexamined_high_value(case))
        assert "Recent (1 file)" in text and "bytes" in text

    def test_every_volume_keeps_its_own_hives(self, tmp_path):
        """Two mounted volumes hold two SAM hives; reading one leaves the
        other owed, and an absence claimed about a named host is checked
        against every volume."""
        from core.mount_plan import save_mount_plan
        case = _case(tmp_path, trace_cmds=["ez_recmd_hive mnt/one/fs/Windows/System32/config/SAM"],
                     claims=("No Security.evtx is present on DC01",))
        images = []
        for stem in ("one", "two"):
            config = case / "mnt" / stem / "fs" / "Windows" / "System32" / "config"
            config.mkdir(parents=True)
            (config / "SAM").write_bytes(b"regf" + b"\x00" * 64)
            os.truncate(config / "SAM", 262_144)
            logs = case / "mnt" / stem / "fs" / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            (logs / "Security.evtx").write_bytes(b"ElfFile" + b"\x00" * 64)
            os.truncate(logs / "Security.evtx", 4_194_304)
            (case / "evidence").mkdir(exist_ok=True)
            (case / "evidence" / f"{stem}.E01").write_bytes(b"EVF" * 16)
            images.append({"path": str(case / "evidence" / f"{stem}.E01"), "stem": stem,
                           "status": "mounted",
                           "mount_result": {"success": True, "mount_point": str(case / "mnt" / stem / "fs")}})
        save_mount_plan(case, {"images": images})
        known = av.known_artifacts(case)
        assert sum(1 for v in known.values() if v["name"] == "SAM") == 2
        owed = [a["path"] for a in av.unexamined_high_value(case) if a["name"] == "SAM"]
        assert owed == ["mnt/two/fs/Windows/System32/config/SAM"]
        clashes = av.contradicted_absence_claims(case)
        assert clashes and clashes[0]["artifact"] == "Security.evtx"

    def test_a_volume_answers_only_for_the_host_the_links_tie_it_to(self, tmp_path):
        """Two images, the links naming each image's host: an absence
        claimed for one host is not contradicted by the other host's
        volume; without links and with several volumes, a host-tagged claim
        is not judged against a volume of unknown host."""
        from core.evidence_links import empty_links, save_evidence_links
        from core.mount_plan import save_mount_plan
        case = _case(tmp_path)
        (case / ".atlas" / "claim_graph.json").write_text(json.dumps({
            "schema_version": "1.0", "edges": [], "nodes": {"C0001": {
                "id": "C0001", "kind": "claim", "status": "new", "host": "WS-LAPTOP",
                "statement": "No Amcache.hve is present on WS-LAPTOP"}}}), encoding="utf-8")
        images = []
        for host, folder, image in (("DC01", "DC01", "20240101_0000_CDrive.E01"),
                                    ("WS-LAPTOP", "WS-LAPTOP", "desktop.E01")):
            stem = image.rsplit(".", 1)[0]
            amcache = case / "mnt" / stem / "fs" / "Windows" / "AppCompat" / "Programs"
            if host == "DC01":
                amcache.mkdir(parents=True)
                (amcache / "Amcache.hve").write_bytes(b"regf" + b"\x00" * 64)
                os.truncate(amcache / "Amcache.hve", 4_194_304)
            else:
                (case / "mnt" / stem / "fs" / "Windows").mkdir(parents=True)
            (case / "evidence" / folder).mkdir(parents=True, exist_ok=True)
            (case / "evidence" / folder / image).write_bytes(b"EVF" * 16)
            images.append({"path": str(case / "evidence" / folder / image), "stem": stem,
                           "status": "mounted",
                           "mount_result": {"success": True, "mount_point": str(case / "mnt" / stem / "fs")}})
        save_mount_plan(case, {"images": images})
        # no links: a volume of unknown host judges no host-tagged claim
        assert av.contradicted_absence_claims(case) == []
        links = {**empty_links("X"), "entries": [
            {"label": "DC01", "kind": "disk", "path": "evidence/DC01/20240101_0000_CDrive.E01"},
            {"label": "WS-LAPTOP", "kind": "disk", "path": "evidence/WS-LAPTOP/desktop.E01"}],
            "hosts": ["DC01", "WS-LAPTOP"],
            "paths": ["evidence/DC01/20240101_0000_CDrive.E01", "evidence/WS-LAPTOP/desktop.E01"]}
        save_evidence_links(case, links)
        assert _by_name(av.known_artifacts(case), "amcache.hve")["host"] == "DC01"
        assert av.contradicted_absence_claims(case) == []
        # the same absence claimed for the DC's own host is a clash
        (case / ".atlas" / "claim_graph.json").write_text(json.dumps({
            "schema_version": "1.0", "edges": [], "nodes": {"C0001": {
                "id": "C0001", "kind": "claim", "status": "new", "host": "DC01",
                "statement": "No Amcache.hve is present on DC01"}}}), encoding="utf-8")
        clashes = av.contradicted_absence_claims(case)
        assert clashes and clashes[0]["artifact"] == "Amcache.hve"

    def test_a_listing_row_of_a_volume_file_is_owed_once(self, tmp_path):
        case = _win10_case(tmp_path)
        (case / "analysis" / "mft_rows.csv").write_text(
            "_host,FileName,FileSize\nh1,setupapi.dev.log,9000\n", encoding="utf-8")
        owed = [a for a in av.unexamined_high_value(case, limit=50) if a["name"].lower() == "setupapi.dev.log"]
        assert len(owed) == 1 and owed[0]["path"]

    def test_a_host_label_is_a_whole_token_of_the_image_path_inside_the_case(self, tmp_path):
        from core.evidence_links import empty_links, host_for_image, save_evidence_links
        case = tmp_path / "DC01-intrusion"
        (case / ".atlas").mkdir(parents=True)
        save_evidence_links(case, {**empty_links("X"), "hosts": ["WS1", "WS10", "DC01"]})
        assert host_for_image(str(case / "evidence" / "WS10" / "disk.E01"), case) == "WS10"
        assert host_for_image(str(case / "evidence" / "WS1" / "disk.E01"), case) == "WS1"
        assert host_for_image(str(case / "evidence" / "WS02" / "disk.E01"), case) == ""

    def test_one_unlinked_volume_in_a_two_host_case_judges_no_host_tagged_claim(self, tmp_path):
        from core.mount_plan import save_mount_plan
        case = _case(tmp_path)
        amcache = case / "mnt" / "disk" / "fs" / "Windows" / "AppCompat" / "Programs"
        amcache.mkdir(parents=True)
        (amcache / "Amcache.hve").write_bytes(b"regf" + b"\x00" * 64)
        os.truncate(amcache / "Amcache.hve", 4_194_304)
        (case / "evidence").mkdir(exist_ok=True)
        (case / "evidence" / "disk.E01").write_bytes(b"EVF" * 16)
        save_mount_plan(case, {"images": [{"path": str(case / "evidence" / "disk.E01"), "stem": "disk",
                                           "status": "mounted",
                                           "mount_result": {"success": True, "mount_point": str(case / "mnt" / "disk" / "fs")}}]})
        def graph(*nodes):
            (case / ".atlas" / "claim_graph.json").write_text(json.dumps({
                "schema_version": "1.0", "edges": [],
                "nodes": {f"C{i:04d}": {"id": f"C{i:04d}", "kind": "claim", "status": "new", **n}
                          for i, n in enumerate(nodes, 1)}}), encoding="utf-8")
        graph({"host": "WS02", "statement": "No Amcache.hve is present on WS02"},
              {"host": "WS01", "statement": "WS01 ran the sync client"})
        assert av.contradicted_absence_claims(case) == []
        graph({"host": "WS02", "statement": "No Amcache.hve is present on WS02"})
        assert av.contradicted_absence_claims(case)

    def test_a_question_lifts_every_artifact_of_that_name(self, tmp_path):
        from core.investigation_tasks import load_tasks, save_tasks
        from core.mount_plan import save_mount_plan
        case = _case(tmp_path)
        images = []
        for stem in ("one", "two"):
            edb = case / "mnt" / stem / "fs" / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows"
            edb.mkdir(parents=True)
            (edb / "Windows.edb").write_bytes(b"\xef\xcd\xab\x89" + b"\x00" * 64)
            os.truncate(edb / "Windows.edb", 8_388_608)
            (case / "evidence").mkdir(exist_ok=True)
            (case / "evidence" / f"{stem}.E01").write_bytes(b"EVF" * 16)
            images.append({"path": str(case / "evidence" / f"{stem}.E01"), "stem": stem, "status": "mounted",
                           "mount_result": {"success": True, "mount_point": str(case / "mnt" / stem / "fs")}})
        save_mount_plan(case, {"images": images})
        store = load_tasks(case)
        store["tasks"] = [{"id": "task-0001", "text": "What did the user search for (Windows.edb)?", "status": "open"}]
        save_tasks(case, store)
        # a listing row of the same file is not a third thing to read
        (case / "analysis" / "mft_rows.csv").write_text(
            "_host,FileName,FileSize\nh1,Windows.edb,9000000\n", encoding="utf-8")
        owed = [a for a in av.unexamined_high_value(case, limit=50) if a["name"] == "Windows.edb"]
        assert len(owed) == 2 and all(a["score"] == 100 and a["path"] for a in owed)



class TestWhatCountsAsARead:
    """A listing, a stat or a hash names an artifact without reading it; a
    name counts only as a whole name in a call that read content."""

    def _history_case(self, tmp_path, entries):
        case = _case(tmp_path, listing=[("h1", "History", "204800")])
        (case / "analysis" / "CASE_trace.json").write_text(json.dumps(entries), encoding="utf-8")
        return case

    def _owed(self, case):
        return [a["name"] for a in av.unexamined_high_value(case)]

    def test_a_stat_or_a_listing_naming_the_file_is_no_read(self, tmp_path):
        case = self._history_case(tmp_path, [
            {"type": "tool_call", "mcp_tool": "strings_stat_file", "cmd": "stat /mnt/h1/fs/History"},
            {"type": "tool_call", "mcp_tool": "tsk_tsk_fls", "cmd": "fls -r image History"}])
        assert "History" in self._owed(case)

    def test_a_parser_call_on_the_file_is_a_read(self, tmp_path):
        case = self._history_case(tmp_path, [
            {"type": "tool_call", "mcp_tool": "misc_sqlite_query", "cmd": "sqlite3 /mnt/h1/fs/History .tables"}])
        assert "History" not in self._owed(case)

    def test_the_word_inside_other_text_is_no_read(self, tmp_path):
        case = self._history_case(tmp_path, [
            {"type": "finding", "description": "browser history was reviewed"},
            {"type": "tool_call", "mcp_tool": "misc_sqlite_query", "cmd": "sqlite3 /x/chrome_history_export.db"}])
        assert "History" in self._owed(case)


def _hosts_case(tmp_path, listings, *, trace_cmds=()):
    """A case whose Evidence Links name CORP-WS01 and CORP-WS02 and whose
    analysis/ holds MFT-style listings without a host column."""
    case = _case(tmp_path, trace_cmds=trace_cmds)
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({
        "schema_version": "1.0", "entries": [{"label": "CORP-WS01"}, {"label": "CORP-WS02"}]}),
        encoding="utf-8")
    for name, rows in listings.items():
        lines = ["EntryNumber,ParentPath,FileName,FileSize"]
        lines += [f"{i},{parent},{fname},{size}" for i, (parent, fname, size) in enumerate(rows, start=40)]
        (case / "analysis" / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return case


PROFILES = {
    "ws01_mft.csv": [(".\\Users\\jane.doe", "NTUSER.DAT", 262_144),
                     (".\\Users\\john.roe", "NTUSER.DAT", 524_288)],
    "ws02_mft.csv": [(".\\Users\\jane.doe", "NTUSER.DAT", 786_432)],
}


class TestListingRowsByHostAndPath:
    """A listing row is one artifact per host and path in the image: two
    profiles' or two hosts' NTUSER.DAT are three things to read, not one."""

    def test_each_profile_on_each_host_is_its_own_entry(self, tmp_path):
        case = _hosts_case(tmp_path, PROFILES)
        rows = sorted((v["host"], v["lpath"]) for v in av.known_artifacts(case).values()
                      if v["name"] == "NTUSER.DAT")
        assert rows == [("CORP-WS01", "Users/jane.doe/NTUSER.DAT"), ("CORP-WS01", "Users/john.roe/NTUSER.DAT"),
                        ("CORP-WS02", "Users/jane.doe/NTUSER.DAT")]

    def test_reading_one_profiles_copy_leaves_the_others_owed(self, tmp_path):
        case = _hosts_case(tmp_path, PROFILES, trace_cmds=[
            "ez_recmd_hive -f evidence/ws01/Users/john.roe/NTUSER.DAT --csv analysis/john"])
        owed = sorted((a["host"], a["lpath"]) for a in av.unexamined_high_value(case, limit=50)
                      if a["name"] == "NTUSER.DAT")
        assert owed == [("CORP-WS01", "Users/jane.doe/NTUSER.DAT"), ("CORP-WS02", "Users/jane.doe/NTUSER.DAT")]

    def test_an_extracted_copy_credits_the_rows_of_its_name(self, tmp_path):
        case = _hosts_case(tmp_path, PROFILES, trace_cmds=[
            "tsk_icat image 41 exports/NTUSER.DAT", "ez_recmd_hive -f exports/NTUSER.DAT --csv analysis/out"])
        assert not [a for a in av.unexamined_high_value(case, limit=50) if a["name"] == "NTUSER.DAT"]

    def test_a_folder_row_is_read_by_a_call_under_it(self):
        row = {"name": "Recent", "lpath": "Users/jane.doe/AppData/Roaming/Microsoft/Windows/Recent"}
        assert av._examined_in_trace(
            row, "ez_lecmd -d mnt/ws01/fs/users/jane.doe/appdata/roaming/microsoft/windows/recent/ --csv analysis")
        assert av._examined_in_trace(row, 'ez_lecmd -d "c:\\users\\jane.doe\\appdata\\roaming\\microsoft'
                                          '\\windows\\recent"')
        assert not av._examined_in_trace(row, "ez_lecmd -d mnt/ws01/fs/users/jane.doe/appdata/roaming/microsoft/windows")

    def test_two_listings_of_one_volume_give_one_entry_per_path(self, tmp_path):
        rows = [(".\\Users\\jane.doe", "NTUSER.DAT", 262_144)]
        case = _hosts_case(tmp_path, {"mft.csv": rows, "usn.csv": rows})
        assert [v["lpath"] for v in av.known_artifacts(case).values()
                if v["name"] == "NTUSER.DAT"] == ["Users/jane.doe/NTUSER.DAT"]

    def test_a_listing_without_host_or_folder_folds_by_name(self, tmp_path):
        case = _case(tmp_path)
        (case / "analysis" / "names.csv").write_text(
            "FileName,FileSize\nNTUSER.DAT,262144\nNTUSER.DAT,524288\n", encoding="utf-8")
        known = av.known_artifacts(case)
        assert [k for k, v in known.items() if v["name"] == "NTUSER.DAT"] == ["ntuser.dat"]
        assert known["ntuser.dat"]["size"] == 524_288

    def test_a_volume_with_no_host_shows_a_host_tagged_row(self, tmp_path):
        from core.mount_plan import save_mount_plan
        case = _hosts_case(tmp_path, {"ws01_mft.csv": PROFILES["ws01_mft.csv"]})
        profile = case / "mnt" / "disk" / "fs" / "Users" / "jane.doe"
        profile.mkdir(parents=True)
        (profile / "NTUSER.DAT").write_bytes(b"regf" + b"\x00" * 64)
        os.truncate(profile / "NTUSER.DAT", 262_144)
        (case / "evidence").mkdir(exist_ok=True)
        (case / "evidence" / "disk.E01").write_bytes(b"EVF" * 16)
        save_mount_plan(case, {"images": [{"path": str(case / "evidence" / "disk.E01"), "stem": "disk",
                                           "status": "mounted",
                                           "mount_result": {"success": True,
                                                            "mount_point": str(case / "mnt" / "disk" / "fs")}}]})
        owed = [a for a in av.unexamined_high_value(case, limit=50) if a["name"] == "NTUSER.DAT"]
        assert sorted(a["path"] or a["lpath"] for a in owed) == [
            "Users/john.roe/NTUSER.DAT", "mnt/disk/fs/Users/jane.doe/NTUSER.DAT"]

    def test_the_nudge_names_the_profile_and_the_host(self, tmp_path):
        case = _hosts_case(tmp_path, PROFILES)
        text = av.format_value_nudge(av.unexamined_high_value(case, limit=50))
        assert "at Users/john.roe/NTUSER.DAT [CORP-WS01]" in text
        assert "at Users/jane.doe/NTUSER.DAT [CORP-WS02]" in text
