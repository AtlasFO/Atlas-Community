"""Tests for tools/antiforensics.py."""
import csv
import pytest


@pytest.fixture
def log(tmp_path):
    from core.execution_log import log as _log
    _log.configure("AF-TEST", str(tmp_path / "trace.json"))
    return _log


def _seed_tool_call(log, cmd, stdout):
    log._entries.append({
        "call_id": log._next_id(),
        "type": "tool_call",
        "ts": "2026-05-23T00:00:00+00:00",
        "cmd": cmd,
        "stdout_excerpt": stdout,
        "success": True,
    })
    log._index_version += 1


def test_timestomp_drift_detects_divergence(tmp_path):
    from tools.antiforensics import af_timestomp_drift
    csv_path = tmp_path / "mft.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "ParentPath", "FileName", "EntryNumber",
            "LastModified0x10", "LastModified0x30",
        ])
        w.writeheader()
        # Timestomp: SI is 2020, FN is 2024 → 4-year drift
        w.writerow({
            "ParentPath": "C:\\Windows\\System32",
            "FileName": "evil.exe",
            "EntryNumber": "42",
            "LastModified0x10": "2020-01-01T00:00:00",
            "LastModified0x30": "2024-09-15T14:32:00",
        })
        # Clean row
        w.writerow({
            "ParentPath": "C:\\Users",
            "FileName": "report.docx",
            "EntryNumber": "43",
            "LastModified0x10": "2024-09-15T14:32:00",
            "LastModified0x30": "2024-09-15T14:32:00",
        })
    r = af_timestomp_drift(str(csv_path))
    assert r["success"] is True
    assert r["drift_count"] == 1
    assert r["drift_records"][0]["mft_record"] == 42
    assert r["suggested_finding"]["confidence"] == "LIKELY"


def test_event_log_clear_finds_eid_1102(log):
    from tools.antiforensics import af_event_log_clear
    _seed_tool_call(
        log,
        "dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll -f Security.evtx",
        "Record 1: EventID=1102 User=DOMAIN\\admin Time=2024-09-15T14:00:00 — "
        "Security log cleared\n"
        "Record 2: EventID=4624 User=user Time=2024-09-15T14:01:00 — Logon\n",
    )
    log._flush()
    r = af_event_log_clear()
    assert r["success"] is True
    assert r["clear_events_found"] >= 1
    assert any(e["eid"] == 1102 for e in r["events"])
    assert r["suggested_finding"]["confidence"] == "CONFIRMED"


def test_event_log_clear_no_evtxecmd(log):
    from tools.antiforensics import af_event_log_clear
    r = af_event_log_clear()
    assert r["success"] is False
    assert "ez.evtxecmd" in r["error"]


def test_usn_gaps_is_deprecated():
    # Retired detector: the wired usnparser emits no USN offset, and the
    # sorted-offset-delta heuristic is unsound (USN = byte offset). It must
    # return an explicit deprecation pointing at the sound alternative and
    # never compute a finding — regardless of input.
    from tools.antiforensics import af_usn_gaps
    r = af_usn_gaps("/nonexistent/whatever.csv", gap_threshold=100)
    assert r["success"] is False
    assert r["deprecated"] is True
    assert r["replacement"] == "antiforensics.af_usn_journal_deleted"
    assert "af_usn_journal_deleted" in r["error"]
    assert "suggested_finding" not in r


# ── file-first CSV parsing (Increment 1) ─────────────────────────────────────

def _write_csv(path, fieldnames, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def test_event_log_clear_reads_full_csv_with_account(tmp_path):
    from tools.antiforensics import af_event_log_clear
    csv_path = tmp_path / "evtx.csv"
    _write_csv(csv_path, ["EventId", "Channel", "TimeCreated", "UserName",
                          "MapDescription", "PayloadData1"], [
        # 200 benign rows first — would fall outside a 600-char excerpt
        *[{"EventId": "4624", "Channel": "Security", "TimeCreated": "t",
           "UserName": "user", "MapDescription": "Logon", "PayloadData1": ""}
          for _ in range(200)],
        {"EventId": "1102", "Channel": "Security",
         "TimeCreated": "2024-09-15T14:00:00", "UserName": "DOMAIN\\admin",
         "MapDescription": "The audit log was cleared", "PayloadData1": ""},
    ])
    r = af_event_log_clear(str(csv_path))
    assert r["success"] is True
    assert r["data_source"] == "csv"
    assert r["clear_events_found"] == 1
    assert r["events"][0]["eid"] == 1102
    assert r["events"][0]["account"] == "DOMAIN\\admin"
    assert r["suggested_finding"]["confidence"] == "CONFIRMED"
    assert "DOMAIN\\admin" in r["suggested_finding"]["description"]


def test_event_log_clear_discovers_csv_from_trace_with_lineage(log, tmp_path):
    from tools.antiforensics import af_event_log_clear
    csv_path = tmp_path / "sec_evtx.csv"
    _write_csv(csv_path, ["EventId", "Channel", "UserName"], [
        {"EventId": "104", "Channel": "System", "UserName": "SYSTEM"},
    ])
    _seed_tool_call(
        log,
        f"EvtxECmd.dll -f System.evtx --csv {tmp_path} --csvf sec_evtx.csv",
        "irrelevant truncated excerpt")
    seeded_cid = log._entries[-1]["call_id"]
    log._flush()
    r = af_event_log_clear()  # no explicit path → discover
    assert r["data_source"] == "csv"
    assert r["clear_events_found"] == 1
    assert r["events"][0]["eid"] == 104
    assert r["suggested_finding"]["linked_call_id"] == seeded_cid


def test_event_log_clear_falls_back_to_excerpt(log):
    # No CSV flags in the cmd → legacy excerpt regex, flagged as such.
    from tools.antiforensics import af_event_log_clear
    _seed_tool_call(log, "EvtxECmd.dll -f Security.evtx",
                    "Record 1: EventID=1102 — Security log cleared\n")
    log._flush()
    r = af_event_log_clear()
    assert r["data_source"] == "trace_excerpt"
    assert any(e["eid"] == 1102 for e in r["events"])


def test_prefetch_deletion_reads_csvs_with_lineage(log, tmp_path):
    from tools.antiforensics import af_prefetch_deletion
    pf = tmp_path / "pecmd.csv"
    ac = tmp_path / "appcompat.csv"
    _write_csv(pf, ["ExecutableName", "SourceFilename"], [
        {"ExecutableName": "NOTEPAD.EXE", "SourceFilename": "NOTEPAD.EXE-1.pf"},
    ])
    _write_csv(ac, ["Path"], [
        {"Path": "C:\\Windows\\notepad.exe"},        # has prefetch → not a candidate
        {"Path": "C:\\Temp\\evil.exe"},              # ran, no prefetch → candidate
        {"Path": "C:\\Windows\\svchost.exe"},        # system noise → filtered
    ])
    _seed_tool_call(log, f"AppCompatCacheParser.dll --csv {tmp_path} --csvf appcompat.csv", "x")
    ac_cid = log._entries[-1]["call_id"]
    log._flush()
    r = af_prefetch_deletion(pecmd_csv_path=str(pf), appcompat_csv_path=str(ac))
    assert r["success"] is True
    assert r["data_source"] == "csv"
    paths = [c["path"] for c in r["deletion_candidates"]]
    assert "evil.exe" in paths
    assert "notepad.exe" not in paths     # prefetched
    assert "svchost.exe" not in paths     # noise
    assert r["suggested_finding"]["confidence"] == "SUSPECTED"
    assert r["suggested_finding"]["linked_call_id"] == ac_cid


def test_timestomp_drift_discovers_mft_csv_and_sets_lineage(log, tmp_path):
    from tools.antiforensics import af_timestomp_drift
    mft = tmp_path / "mft.csv"
    _write_csv(mft, ["ParentPath", "FileName", "EntryNumber",
                     "LastModified0x10", "LastModified0x30"], [
        {"ParentPath": "C:\\W", "FileName": "evil.exe", "EntryNumber": "42",
         "LastModified0x10": "2020-01-01T00:00:00",
         "LastModified0x30": "2024-09-15T14:32:00"},
    ])
    _seed_tool_call(log, f"MFTECmd.dll -f $MFT --csv {tmp_path} --csvf mft.csv", "x")
    seeded_cid = log._entries[-1]["call_id"]
    log._flush()
    r = af_timestomp_drift()  # discover
    assert r["drift_count"] == 1
    assert r["suggested_finding"]["linked_call_id"] == seeded_cid


def test_discover_csv_from_trace_parses_flags(log, tmp_path):
    from tools.antiforensics import _discover_csv_from_trace
    (tmp_path / "out.csv").write_text("EventId\n1102\n", encoding="utf-8")
    _seed_tool_call(log, f"EvtxECmd.dll --csv {tmp_path} --csvf out.csv", "x")
    cid = log._entries[-1]["call_id"]
    log._flush()
    found = _discover_csv_from_trace(["evtxecmd"])
    assert found and found[0][0] == str(tmp_path / "out.csv")
    assert found[0][1] == cid


# ── Increment 5 (T2-2): new anti-forensics detectors ─────────────────────────

def test_usn_journal_deleted_flags_missing_usnjrnl(tmp_path):
    from tools.antiforensics import af_usn_journal_deleted
    csv_path = tmp_path / "mft.csv"
    # $Extend siblings present but no $UsnJrnl entry → journal reset.
    _write_csv(csv_path, ["FileName", "ParentPath", "InUse", "FileSize"], [
        {"FileName": "$Quota", "ParentPath": ".\\$Extend", "InUse": "True", "FileSize": "0"},
        {"FileName": "$ObjId", "ParentPath": ".\\$Extend", "InUse": "True", "FileSize": "0"},
        {"FileName": "windows", "ParentPath": ".", "InUse": "True", "FileSize": "0"},
    ])
    r = af_usn_journal_deleted(str(csv_path))
    assert r["success"] is True
    assert r["usnjrnl_present"] is False
    assert r["extend_sibling_count"] == 2
    assert r["suggested_finding"]["confidence"] == "SUSPECTED"
    assert "T1070.004" in r["suggested_finding"]["description"]


def test_usn_journal_present_and_healthy_no_finding(tmp_path):
    from tools.antiforensics import af_usn_journal_deleted
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, ["FileName", "ParentPath", "InUse", "FileSize"], [
        {"FileName": "$Quota", "ParentPath": ".\\$Extend", "InUse": "True", "FileSize": "0"},
        {"FileName": "$UsnJrnl", "ParentPath": ".\\$Extend", "InUse": "True", "FileSize": "0"},
        {"FileName": "$UsnJrnl:$J", "ParentPath": ".\\$Extend", "InUse": "True", "FileSize": "524288"},
    ])
    r = af_usn_journal_deleted(str(csv_path))
    assert r["success"] is True
    assert r["usnjrnl_present"] is True
    assert r["suggested_finding"] is None


def test_ads_enumeration_flags_executable_stream(tmp_path):
    from tools.antiforensics import af_ads_enumeration
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, ["FileName", "ParentPath", "IsAds", "FileSize"], [
        {"FileName": "notes.txt:Zone.Identifier", "ParentPath": "C:\\U\\x", "IsAds": "True", "FileSize": "26"},
        {"FileName": "report.pdf:launch.exe", "ParentPath": "C:\\U\\x", "IsAds": "True", "FileSize": "8192"},
        {"FileName": "image.jpg:secret", "ParentPath": "C:\\a", "IsAds": "True", "FileSize": "40"},
        {"FileName": "normal.txt", "ParentPath": "C:\\a", "IsAds": "False", "FileSize": "10"},
    ])
    r = af_ads_enumeration(str(csv_path))
    assert r["success"] is True
    assert r["total_ads_streams"] == 3          # Zone.Identifier counted but benign
    assert r["suspicious_count"] == 2           # exec + secret, Zone.Identifier filtered
    assert r["executable_ads_count"] == 1
    assert r["suggested_finding"]["confidence"] == "LIKELY"   # exec-like present
    assert "T1564.004" in r["suggested_finding"]["description"]


def test_ads_enumeration_lists_zone_identifier_streams(tmp_path):
    from tools.antiforensics import af_ads_enumeration
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, ["FileName", "ParentPath", "IsAds", "FileSize", "EntryNumber"], [
        {"FileName": "invoice.pdf:Zone.Identifier", "ParentPath": "C:\\U\\Downloads",
         "IsAds": "True", "FileSize": "26", "EntryNumber": "99"},
        {"FileName": "normal.txt", "ParentPath": "C:\\a", "IsAds": "False",
         "FileSize": "10", "EntryNumber": "5"},
    ])
    r = af_ads_enumeration(str(csv_path))
    assert r["success"] is True
    assert r["zone_identifier_streams"] == [
        {"path": "C:\\U\\Downloads\\invoice.pdf:Zone.Identifier", "entry_number": "99"},
    ]
    assert r["suspicious_count"] == 0  # Zone.Identifier is still not "suspicious"


class TestZoneIdentifierRead:
    _CONTENT = (
        "[ZoneTransfer]\r\n"
        "ZoneId=3\r\n"
        "ReferrerUrl=https://mail.corp.cn/click?u=https://evil.example/pay\r\n"
        "HostUrl=https://evil.example/invoice.pdf\r\n"
    )

    def test_parses_host_and_referrer_url(self, tmp_path):
        from tools.antiforensics import af_zone_identifier_read
        stream = tmp_path / "invoice.pdf_Zone.Identifier"
        stream.write_text(self._CONTENT)
        r = af_zone_identifier_read(str(stream))
        assert r["success"] is True
        assert r["zone_id"] == "3"
        assert r["zone_meaning"] == "Internet"
        assert r["host_url"] == "https://evil.example/invoice.pdf"
        assert "evil.example/pay" in r["referrer_url"]

    def test_not_valid_ini(self, tmp_path):
        from tools.antiforensics import af_zone_identifier_read
        stream = tmp_path / "not_zone.txt"
        stream.write_text("just some file content, no sections at all")
        r = af_zone_identifier_read(str(stream))
        assert r["success"] is False

    def test_valid_ini_without_zone_transfer_section(self, tmp_path):
        from tools.antiforensics import af_zone_identifier_read
        stream = tmp_path / "other.ini"
        stream.write_text("[SomeOtherSection]\nkey=value\n")
        r = af_zone_identifier_read(str(stream))
        assert r["success"] is False
        assert "ZoneTransfer" in r["error"]

    def test_missing_file(self, tmp_path):
        from tools.antiforensics import af_zone_identifier_read
        r = af_zone_identifier_read(str(tmp_path / "missing"))
        assert r["success"] is False


def test_linux_history_tampering_symlink_and_rc(tmp_path):
    from tools.antiforensics import af_linux_history_tampering
    root = tmp_path / "mnt"
    (root / "root").mkdir(parents=True)
    # /root/.bash_history symlinked to /dev/null
    (root / "root" / ".bash_history").symlink_to("/dev/null")
    alice = root / "home" / "alice"
    alice.mkdir(parents=True)
    (alice / ".bashrc").write_text("export PATH=$PATH\nexport HISTFILE=/dev/null\n")
    (alice / ".zsh_history").write_text("")   # zeroed
    r = af_linux_history_tampering(str(root))
    assert r["success"] is True
    issues = {i["issue"] for i in r["indicators"]}
    assert {"symlinked", "histfile_tamper", "zeroed"} <= issues
    assert r["suggested_finding"]["confidence"] == "LIKELY"
    assert "T1070.003" in r["suggested_finding"]["description"]


def test_linux_history_tampering_bad_mount():
    from tools.antiforensics import af_linux_history_tampering
    r = af_linux_history_tampering("/nonexistent/xyz")
    assert r["success"] is False


import struct as _struct

_UTMP_FMT = "<hxxi32s4s32s256shhiii16s20s"


def _utmp_record(ut_type, tv_sec, user=b"root"):
    return _struct.pack(_UTMP_FMT, ut_type, 0, b"pts/0", b"", user, b"host",
                        0, 0, 0, tv_sec, 0, b"\x00" * 16, b"\x00" * 20)


def test_linux_log_tampering_zeroing_and_inversion(tmp_path):
    from tools.antiforensics import af_linux_log_tampering
    root = tmp_path / "mnt"
    logdir = root / "var" / "log"
    logdir.mkdir(parents=True)
    data = (
        _utmp_record(7, 1000)
        + _utmp_record(7, 2000)
        + b"\x00" * 384                 # embedded zero record (wipe)
        + _utmp_record(7, 1500)         # non-monotonic (1500 < 2000)
    )
    (logdir / "wtmp").write_bytes(data)
    (logdir / "auth.log").write_text("")   # present but empty → cleared
    r = af_linux_log_tampering(str(root))
    assert r["success"] is True
    wtmp = next(l for l in r["per_log"] if l["log"] == "var/log/wtmp")
    assert wtmp["embedded_zero_records"] == 1
    assert wtmp["timestamp_inversions"] == 1
    assert wtmp["size_mismatch"] is False
    assert any("auth.log" in a for a in r["anomalies"])
    assert r["suggested_finding"]["confidence"] == "SUSPECTED"
    assert "T1070.002" in r["suggested_finding"]["description"]


# ── input-format validation: wrong file passed to a *_csv parameter ──────────

def _recmd_sysmon_csv(path):
    """A minimal but real-shaped RECmd hive dump with a disabled-Sysmon row."""
    _write_csv(path,
               ["HivePath", "HiveType", "KeyPath", "ValueName", "ValueType",
                "ValueData"],
               [{"HivePath": "SYSTEM", "HiveType": "SYSTEM",
                 "KeyPath": "ControlSet001\\Services\\Sysmon",
                 "ValueName": "Start", "ValueType": "RegDword", "ValueData": "4"}])


def test_sysmon_evasion_reads_valid_recmd_csv(tmp_path):
    # Regression guard: a real RECmd hive CSV must still be parsed and flagged.
    from tools.antiforensics import af_sysmon_evasion
    csv_path = tmp_path / "SYSTEM.recmd.csv"
    _recmd_sysmon_csv(csv_path)
    r = af_sysmon_evasion(str(csv_path))
    assert r["success"] is True
    assert any("Start=4" in i["issue"] for i in r["indicators"])
    assert r["suggested_finding"]["confidence"] == "LIKELY"


def test_sysmon_evasion_rejects_regripper_text(tmp_path):
    # The reported bug: RegRipper .txt output (not a CSV) fed to system_hive_csv.
    # It must return a clean, actionable error — never a crash, never a silent
    # zero-indicator false negative.
    from tools.antiforensics import af_sysmon_evasion
    txt = tmp_path / "SYSTEM.regripper.txt"
    txt.write_text(
        "Launching sysmon v.20200925\n"
        "sysmon v.20200925\n\n"
        "ControlSet001\\Services\\Sysmon\n"
        "LastWrite Time 2024-01-15 10:22:33Z\n"
        "  Start           4\n"
        "  Type            0x10\n",
        encoding="utf-8")
    r = af_sysmon_evasion(str(txt))
    assert r["success"] is False
    assert "SYSTEM.regripper.txt" in r["error"]
    # names the schema mismatch and doesn't pretend the file was missing
    assert "expected column" in r["error"]
    assert "not found" not in r["error"]


def test_sysmon_evasion_rejects_utf16_file_with_nul_bytes(tmp_path):
    # A UTF-16 (or otherwise binary) file has NUL bytes that make csv either
    # raise csv.Error (Python <3.11) or silently mis-parse (>=3.11). The NUL
    # guard must reject it cleanly on every version.
    from tools.antiforensics import af_sysmon_evasion
    p = tmp_path / "SYSTEM.regripper.txt"
    p.write_bytes("ControlSet001\\Services\\Sysmon\r\n  Start  4\r\n"
                  .encode("utf-16-le"))
    r = af_sysmon_evasion(str(p))
    assert r["success"] is False
    assert "NUL bytes" in r["error"]


def test_mft_detectors_reject_non_mft_text(tmp_path):
    # The same guard protects the MFT-backed detectors (shared _resolve_csv).
    from tools.antiforensics import af_ads_enumeration, af_timestomp_drift
    txt = tmp_path / "notes.txt"
    txt.write_text("just some notes\nnothing structured here\n", encoding="utf-8")
    for fn in (af_ads_enumeration, af_timestomp_drift):
        r = fn(str(txt))
        assert r["success"] is False
        assert "expected column" in r["error"]


def test_ads_enumeration_filters_kaspersky_checked_stream(tmp_path):
    # Regression for the benign-list typo 'kavicheckedstream...' which could
    # never match; the real stream name must now be filtered out.
    from tools.antiforensics import af_ads_enumeration
    csv_path = tmp_path / "mft.csv"
    _write_csv(csv_path, ["FileName", "ParentPath", "IsAds", "FileSize"], [
        {"FileName": "doc.pdf:KAVICHECKEDSTREAM", "ParentPath": "C:\\a",
         "IsAds": "True", "FileSize": "12"},
        {"FileName": "doc.pdf:launch.exe", "ParentPath": "C:\\a",
         "IsAds": "True", "FileSize": "8192"},
    ])
    r = af_ads_enumeration(str(csv_path))
    assert r["success"] is True
    streams = {s["stream"] for s in r["suspicious_streams"]}
    assert "kavicheckedstream" not in streams   # benign, filtered
    assert "launch.exe" in streams              # still flagged


def test_linux_log_tampering_size_mismatch(tmp_path):
    from tools.antiforensics import af_linux_log_tampering
    root = tmp_path / "mnt"
    logdir = root / "var" / "log"
    logdir.mkdir(parents=True)
    # One valid record plus 10 stray bytes → not a multiple of 384.
    (logdir / "btmp").write_bytes(_utmp_record(6, 500) + b"\x00" * 10)
    r = af_linux_log_tampering(str(root))
    assert r["success"] is True
    btmp = next(l for l in r["per_log"] if l["log"] == "var/log/btmp")
    assert btmp["size_mismatch"] is True
    assert any("multiple of 384" in a for a in r["anomalies"])
