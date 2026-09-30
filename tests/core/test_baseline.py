"""The system baseline: each Windows installation states its own facts
once, as observations read from its hives, before the analyst's first
turn; a dirty hive without logs lowers their confidence; the catalog and
the beliefs check leave them alone."""
import csv
import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from core import baseline as B

ROOT = "CMI-CreateHive{0000}"
FIELDS = ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType",
          "ValueData", "ValueData2", "ValueData3", "Comment", "Recursive", "Deleted", "LastWriteTimestamp", "PluginDetailFile"]


def _filetime_hex(stamp: str) -> str:
    import datetime as _dt
    import struct
    t = _dt.datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_dt.timezone.utc)
    ft = int((t - _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)).total_seconds() * 10_000_000)
    return "-".join(f"{b:02X}" for b in struct.pack("<Q", ft))


def _row(hive, key, name, data, d2="", d3="", deleted="False", vtype="RegSz"):
    return {"HivePath": hive, "HiveType": hive, "Description": "", "Category": "Baseline", "KeyPath": f"{ROOT}\\{key}",
            "ValueName": name, "ValueType": vtype, "ValueData": data, "ValueData2": d2, "ValueData3": d3,
            "Comment": "", "Recursive": "false", "Deleted": deleted, "LastWriteTimestamp": "", "PluginDetailFile": ""}


ROWS = {
    "SYSTEM": [
        _row("SYSTEM", "Select", "Current", "2", vtype="RegDword"),
        _row("SYSTEM", "ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", "STALE-NAME"),
        _row("SYSTEM", "ControlSet002\\Control\\ComputerName\\ComputerName", "ComputerName", "WS-7A2B"),
        _row("SYSTEM", "ControlSet002\\Control\\TimeZoneInformation", "TimeZoneKeyName", "W. Europe Standard Time ard Time", vtype="(plugin)"),
        _row("SYSTEM", "ControlSet002\\Control\\TimeZoneInformation", "Bias", "-60", vtype="(plugin)"),
        _row("SYSTEM", "ControlSet002\\Control\\TimeZoneInformation", "ActiveTimeBias", "-120", vtype="(plugin)"),
        _row("SYSTEM", "ControlSet002\\services\\Tcpip\\Parameters", "NV Hostname", "ws-7a2b"),
        _row("SYSTEM", "ControlSet002\\services\\Tcpip\\Parameters", "Domain", "corp.example.net"),
        _row("SYSTEM", "ControlSet002\\services\\Tcpip\\Parameters\\Interfaces\\{A1}", "DhcpIPAddress", "192.0.2.40"),
        _row("SYSTEM", "ControlSet002\\services\\Tcpip\\Parameters\\Interfaces\\{A1}", "DhcpServer", "192.0.2.1"),
        _row("SYSTEM", "ControlSet002\\services\\Tcpip\\Parameters\\Interfaces\\{A1}", "DhcpDefaultGateway", "192.0.2.1"),
        _row("SYSTEM", "ControlSet002\\services\\Tcpip\\Parameters\\Interfaces\\{A1}", "LeaseObtainedTime", "1900000000", vtype="RegDword"),
        _row("SYSTEM", "ControlSet002\\services\\Tcpip\\Parameters\\Interfaces\\{B2}", "EnableDHCP", "1", vtype="RegDword"),
        _row("SYSTEM", "ControlSet002\\Enum\\USBSTOR\\Disk&Ven_Acme&Prod_Stick&Rev_1.0\\AA11BB22CC33&0", "FriendlyName", "Acme Stick USB Device"),
        _row("SYSTEM", "ControlSet002\\Enum\\USBSTOR\\Disk&Ven_Acme&Prod_Stick&Rev_1.0\\DELETED0000&0", "FriendlyName", "gone", deleted="True"),
        _row("SYSTEM", "ControlSet002\\Control\\Session Manager\\Memory Management\\PrefetchParameters", "EnablePrefetcher", "3", vtype="RegDword"),
        _row("SYSTEM", "ControlSet002\\Control\\FileSystem", "NtfsDisableLastAccessUpdate", "1", vtype="RegDword"),
        _row("SYSTEM", "ControlSet002\\services\\eventlog\\Security", "MaxSize", "20971520", vtype="RegDword"),
        _row("SYSTEM", "ControlSet002\\services\\eventlog\\Security", "Retention", "0", vtype="RegDword"),
        _row("SYSTEM", "ControlSet002\\services\\VSS", "Start", "3", vtype="RegDword"),
        _row("SYSTEM", "ControlSet002\\Control\\Windows", "ShutdownTime", _filetime_hex("2031-02-04 10:41:03"), vtype="RegBinary"),
    ],
    "SOFTWARE": [
        _row("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion", "ProductName", "Windows 7 Ultimate"),
        _row("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild", "7601"),
        _row("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion", "CurrentVersion", "6.1"),
        _row("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion", "CSDVersion", "Service Pack 1"),
        _row("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion", "InstallDate", "1427034866", vtype="RegDword"),
        _row("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion", "RegisteredOwner", "Jane Roe"),
        _row("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1-2-3-1000", "Multiple",
             "KeyName: S-1-5-21-1-2-3-1000", "Timestamp: 2031-01-02 03:04:05", "ProfileImagePath: C:\\Users\\jane", vtype="(plugin)"),
        _row("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Uninstall\\Tool", "Multiple",
             "KeyName: Tool DisplayName: Acme Tool DisplayVersion: 2.1 Publisher: Acme InstallDate: 20310102",
             "Timestamp: 2031-01-02 03:04:05", "", vtype="(plugin)"),
        _row("SOFTWARE", "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{P1}", "ProfileName", "Office"),
    ],
    "SAM": [
        _row("SAM", "SAM\\Domains\\Account\\Users", "V", "Username: jane Id: 1000 ValidUserId: True",
             "Created: 2031-01-02 03:04:05.0000000 Last login: 2031-02-04 10:41:03.0000000 Last password change: ",
             "Account flags: NormalUserAccount", vtype="(plugin)"),
    ],
    "SECURITY": [
        _row("SECURITY", "Policy\\PolPrDmN", "(default)", "08-00-0A-00-08-00-00-00-43-00-4F-00-52-00-50-00", vtype="RegNone"),
        _row("SECURITY", "Policy\\PolPrDmS", "(default)", "01-04-00-00-00-00-00-05-15-00-00-00-01-00-00-00-02-00-00-00-03-00-00-00", vtype="RegNone"),
    ],
}


def _csv_text(rows):
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=FIELDS)
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return out.getvalue()


def _tree(tmp_path, *, previous=False):
    case = tmp_path / "case"
    cfg = case / "evidence" / "host01" / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    for h in B.HIVES:
        (cfg / h).write_bytes(b"regf" + b"\0" * 64)
    if previous:
        old = case / "evidence" / "host01" / "Windows.old" / "Windows" / "System32" / "config"
        old.mkdir(parents=True)
        (old / "SYSTEM").write_bytes(b"regf")
        (old / "SOFTWARE").write_bytes(b"regf")
    (case / ".atlas").mkdir()
    (case / "analysis").mkdir()
    return case


def _stub_recmd(dirty_hives=()):
    calls = []

    def fake(case_dir, hive, out_dir, csv_name, *, nl):
        name = Path(hive).name.upper()
        calls.append((name, nl))
        if name in dirty_hives and not nl:
            return {"success": False, "stdout": "Hive is dirty and the transaction logs do not exist. Use --nl", "stderr": "", "exit_code": 1}
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / csv_name).write_text(_csv_text(ROWS.get(name, [])), encoding="utf-8")
        return {"success": True, "stdout": f"Processing {hive}\nTotal keys 10", "stderr": "", "exit_code": 0}
    return fake, calls


def _log(case):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("CASE", str(case / "analysis" / "trace.json"))
    return l


# ── decoders ─────────────────────────────────────────────────────────────

def test_the_lsa_name_and_the_sid_decode():
    assert B.decode_lsa_name("08-00-0A-00-08-00-00-00-43-00-4F-00-52-00-50-00") == "CORP"
    assert B.decode_lsa_name("12-00-14-00-08-00-00-00-57-00-4F-00-52-00-4B-00-47-00-52-00-4F-00-55-00-50-00") == "WORKGROUP"
    assert B.decode_sid("01-04-00-00-00-00-00-05-15-00-00-00-01-00-00-00-02-00-00-00-03-00-00-00") == "S-1-5-21-1-2-3"
    assert B.decode_sid("") == "" and B.decode_lsa_name("(Binary data)") == ""


# ── installations ────────────────────────────────────────────────────────

def test_installations_are_found_under_a_collected_tree_and_a_previous_one_is_labelled(tmp_path):
    case = _tree(tmp_path, previous=True)
    found = B.find_installations(case)
    stems = {i["stem"]: i for i in found}
    current = next(i for i in found if not i["previous"])
    assert set(current["hives"]) == set(B.HIVES) and current["source"] == "tree"
    assert any(i["previous"] for i in found) and any(s.endswith("-previous") for s in stems)


# ── the profile ──────────────────────────────────────────────────────────

def test_the_profile_reads_the_current_control_set_and_skips_deleted_rows(tmp_path):
    case = _tree(tmp_path)
    fake, calls = _stub_recmd()
    with patch.object(B, "_run_recmd", fake), patch.object(B, "_rip", lambda hive, plugin: ""), \
            patch("core.execution_log.log", _log(case)):
        out = B.run_baseline(case)
    assert out["errors"] == [] and len(out["taken"]) == 1
    prof = B.profiles(case)[0]
    assert prof["control_set"] == "ControlSet002"
    assert prof["identity"]["computer_name"] == "WS-7A2B"          # not the stale set's name
    assert prof["identity"]["domain"] == "CORP" and prof["identity"]["domain_sid"] == "S-1-5-21-1-2-3"
    assert prof["identity"]["dns_suffix"] == "corp.example.net"
    assert prof["os"]["product_name"] == "Windows 7 Ultimate" and prof["os"]["install_date"] == "2015-03-22 14:34:26 UTC"
    assert prof["time"]["zone"] == "W. Europe Standard Time" and prof["time"]["active_time_bias"] == "-120"
    assert [a["name"] for a in prof["accounts"]] == ["jane"] and prof["accounts"][0]["rid"] == 1000
    assert prof["profiles"][0]["path"] == "C:\\Users\\jane"
    assert prof["interfaces"][0]["DhcpIPAddress"] == "192.0.2.40" and prof["interfaces"][0]["LeaseObtainedTime"].endswith("UTC")
    assert [u["serial"] for u in prof["usb"]] == ["AA11BB22CC33"]                    # the deleted row is skipped
    assert prof["software"][0]["name"] == "Acme Tool" and prof["software"][0]["publisher"] == "Acme"
    assert prof["software"][0]["install_date"] == "20310102"
    assert prof["settings"]["event_log_channels"]["Security"]["MaxSize"] == "20971520"
    assert prof["power"]["last_shutdown"] == "2031-02-04 10:41:03 UTC"
    assert prof["confidence"] == "CONFIRMED" and prof["stale_note"] == ""
    assert Path(out["taken"][0]["path"]).with_suffix(".csv").is_file()
    assert sorted(c[0] for c in calls) == sorted(B.HIVES)


def test_a_dirty_hive_without_logs_is_reread_and_lowers_the_confidence(tmp_path):
    case = _tree(tmp_path)
    fake, calls = _stub_recmd(dirty_hives={"SOFTWARE"})
    with patch.object(B, "_run_recmd", fake), patch.object(B, "_rip", lambda hive, plugin: ""), \
            patch("core.execution_log.log", _log(case)):
        out = B.run_baseline(case)
    assert out["errors"] == []
    prof = B.profiles(case)[0]
    assert ("SOFTWARE", True) in calls and prof["hive_state"]["SOFTWARE"]["nl_used"] is True
    assert prof["confidence"] == "LIKELY" and "SOFTWARE" in prof["stale_note"]
    from core.claim_graph import load_graph
    obs = [n for n in load_graph(case)["nodes"].values() if n.get("kind") == "observation"]
    assert obs and all(n["confidence"] == "LIKELY" for n in obs)


def test_observations_cite_the_hive_and_the_call_and_carry_the_labels(tmp_path):
    case = _tree(tmp_path)
    fake, _calls = _stub_recmd()
    log = _log(case)
    with patch.object(B, "_run_recmd", fake), patch.object(B, "_rip", lambda hive, plugin: ""), \
            patch("core.execution_log.log", log):
        B.run_baseline(case)
    from core.claim_graph import load_graph
    nodes = load_graph(case)["nodes"]
    obs = {n["attrs"]["baseline"]: n for n in nodes.values() if n.get("kind") == "observation"}
    assert "os.product" in obs and "identity.domain" in obs and "accounts.local" in obs and "usb.devices" in obs
    reg = obs["os.registered"]
    assert "text typed at setup" in reg["statement"] and reg["evidence"][0]["call_id"] is not None
    assert reg["evidence"][0]["artifact"].endswith("config/SOFTWARE")
    assert any(e.get("type") == "tool_call" and "RECmd" in str(e.get("cmd")) for e in log._entries)
    assert obs["identity.dns_suffix"]["statement"].endswith("(DNS suffix only, not domain membership).")
    assert all(n.get("kind") != "claim" for n in nodes.values())


def test_a_second_run_takes_nothing_new(tmp_path):
    case = _tree(tmp_path)
    fake, calls = _stub_recmd()
    with patch.object(B, "_run_recmd", fake), patch.object(B, "_rip", lambda hive, plugin: ""), \
            patch("core.execution_log.log", _log(case)):
        first = B.run_baseline(case)
        second = B.run_baseline(case)
    assert first["taken"] and second["taken"] == [] and second["skipped"][0]["why"] == "already profiled"
    assert len(calls) == len(B.HIVES)


def test_the_prompt_the_report_and_the_status_line_read_the_profile(tmp_path):
    case = _tree(tmp_path)
    fake, _calls = _stub_recmd()
    with patch.object(B, "_run_recmd", fake), patch.object(B, "_rip", lambda hive, plugin: ""), \
            patch("core.execution_log.log", _log(case)):
        B.run_baseline(case)
    block = B.prompt_block(case)
    assert block.startswith("# SYSTEM BASELINE") and "WS-7A2B" in block and "Time basis" in block
    assert "observations O" in block
    lines = B.report_lines(case, "en")
    assert lines[0].startswith("**System identification**") and any("domain CORP (SID S-1-5-21-1-2-3)" in l for l in lines)
    assert any("Time basis" in l for l in lines)
    assert "Systemidentifikation" in B.report_lines(case, "de")[0]
    assert B.status_line(case, stem=B.profiles(case)[0]["installation"]).startswith("baseline: analysis/baseline/")
    assert B.status_line(case, stem="nothing-here").startswith("baseline: not taken")
    assert "UTC+02:00 when last written" in block and "(SID S-1-5-21-1-2-3)" in block
    assert ("install of this build" in block) == ("installed " in block)
    assert any("UTC+02:00" in l for l in lines)


def test_the_status_line_matches_the_stem_whole_and_names_a_previous_installation_apart(tmp_path):
    case = _tree(tmp_path, previous=True)
    fake, _calls = _stub_recmd()
    with patch.object(B, "_run_recmd", fake), patch.object(B, "_rip", lambda hive, plugin: ""), \
            patch("core.execution_log.log", _log(case)):
        B.run_baseline(case)
    names = sorted(p["installation"] for p in B.profiles(case))
    current = next(n for n in names if not n.endswith("-previous"))
    previous = next(n for n in names if n.startswith(current) and n.endswith("-previous"))
    line = B.status_line(case, stem=current)
    assert line.startswith(f"baseline: analysis/baseline/{current}.json")
    assert f"previous installation: analysis/baseline/{previous}.json" in line
    assert B.status_line(case, stem=current[:-1]).startswith("baseline: not taken")
    assert any("(vorherige Installation)" in l for l in B.report_lines(case, "de"))
    assert any("(previous installation)" in l for l in B.report_lines(case, "en"))


def test_a_stale_profile_carries_a_german_note_in_the_german_report(tmp_path):
    case = _tree(tmp_path)
    fake, _calls = _stub_recmd(dirty_hives=("SYSTEM",))
    with patch.object(B, "_run_recmd", fake), patch.object(B, "_rip", lambda hive, plugin: ""), \
            patch("core.execution_log.log", _log(case)):
        B.run_baseline(case)
    assert any("waren dirty" in l for l in B.report_lines(case, "de"))
    assert any("may be stale" in l for l in B.report_lines(case, "en"))


def test_the_utc_offset_reads_the_windows_bias():
    assert B._utc_offset(240) == "UTC-04:00" and B._utc_offset("-60") == "UTC+01:00"
    assert B._utc_offset(0) == "UTC+00:00" and B._utc_offset("") == "" and B._utc_offset(None) == ""


def test_observations_stay_out_of_the_catalog_and_do_not_count_as_beliefs(tmp_path):
    case = _tree(tmp_path)
    fake, _calls = _stub_recmd()
    with patch.object(B, "_run_recmd", fake), patch.object(B, "_rip", lambda hive, plugin: ""), \
            patch("core.execution_log.log", _log(case)):
        B.run_baseline(case)
    from core.ioc_catalog import build_catalog
    cat = build_catalog(case)
    assert cat["iocs"] == [] and cat["review"] == [] and cat["affected_assets"] == []
    from core.claim_graph import graph_snapshot_for_report
    assert graph_snapshot_for_report(case)["has_graph"] is False


def test_a_missing_batch_or_tool_never_raises(tmp_path):
    case = _tree(tmp_path)
    with patch.object(B, "BATCH", Path("/nonexistent/atlas_baseline.reb")):
        out = B.run_baseline(case)
    assert out["taken"] == [] and out["errors"]
    fake = lambda *a, **k: {"success": False, "stdout": "", "stderr": "dotnet: not found", "exit_code": 127}
    with patch.object(B, "_run_recmd", fake), patch("core.execution_log.log", _log(case)):
        out = B.run_baseline(case)
    assert out["taken"] == [] and out["skipped"] and "unreadable" in out["skipped"][0]["why"]
    assert B.profiles(case) == [] and B.status_line(case, stem="x").startswith("baseline: not taken")


def test_the_lsa_name_decodes_the_64_bit_header_and_never_returns_bytes():
    sixty_four = "12-00-14-00-00-00-00-00-10-00-00-00-00-00-00-00-57-00-4F-00-52-00-4B-00-47-00-52-00-4F-00-55-00-50-00"
    assert B.decode_lsa_name(sixty_four) == "WORKGROUP"
    assert B.decode_lsa_name("08-00-0A-00-08-00-00-00-43-00-4F-00-52-00-50-00") == "CORP"
    assert B.decode_lsa_name("12-00-14-00-00-00-00-00-FF-00-00-00-00-00-00-00-57-00") == ""     # offset past the data
    assert B.decode_lsa_name("12-00-14-00-04-00-00-00-57-00-4F-00") == ""                         # offset inside the header


def test_the_xp_audit_policy_is_decoded_from_the_raw_value_and_later_versions_use_the_plugin():
    import struct
    raw = "-".join(f"{b:02X}" for b in struct.pack("<10I", 1, 3, 3, 0, 1, 2, 3, 3, 0, 3))
    rows = [_row("SECURITY", "Policy\\PolAdtEv", "(default)", raw, vtype="RegNone")]

    def no_plugin(hive, plugin):
        raise AssertionError("the plugin must not run on NT 5.x")

    with patch.object(B, "_rip", no_plugin):
        lines = B._audit_policy("", rows, "5.1")
    assert lines[0] == "Auditing enabled"
    assert "Logon: success and failure" in lines and "Object Access: none" in lines and "Privilege Use: success" in lines
    assert B._audit_policy("", rows, "6.0") == ["audit policy not decoded for this version (6.0)"]
    assert B._audit_policy("", [], "5.2") == ["audit policy not decoded (PolAdtEv absent or short)"]
    with patch.object(B, "_rip", lambda hive, plugin: "Logon/Logoff:Logon    S/F\nnoise\n"):
        assert B._audit_policy("x", rows, "6.1") == ["Logon/Logoff:Logon    S/F"]


def test_a_generated_usb_instance_id_is_kept_whole_and_labelled():
    assert B._usb_entry("ROOT\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_Acme&Prod_Stick&Rev_1.0\\AA11BB22CC33&0") == \
        ("Disk&Ven_Acme&Prod_Stick&Rev_1.0", "AA11BB22CC33", "")
    assert B._usb_entry("ROOT\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_Acme&Prod_Stick&Rev_1.0\\7&2a8b5f7c&0") == \
        ("Disk&Ven_Acme&Prod_Stick&Rev_1.0", "7&2a8b5f7c&0", "generated by Windows, the device reports no serial")
    assert B._usb_entry("ROOT\\ControlSet001\\Enum\\USB\\VID_1234") is None


def test_an_unsigned_dword_bias_reads_as_negative():
    assert B._utc_offset(4294967176) == "UTC+02:00" and B._utc_offset(-330) == "UTC+05:30"


def test_a_zone_states_its_standard_and_daylight_offsets():
    assert B._zone_offsets({"bias": "300", "daylight_bias": "-60"}) == \
        "standard UTC-05:00, daylight saving UTC-04:00; "
    assert B._zone_offsets({"bias": "300", "daylight_bias": "4294967236"}) == \
        "standard UTC-05:00, daylight saving UTC-04:00; "
    assert B._zone_offsets({"bias": "-330", "daylight_bias": "0"}) == "standard UTC+05:30; "
    assert B._zone_offsets({"bias": "", "daylight_bias": "-60"}) == ""
    assert B._zone_offsets({"bias": "-60", "daylight_bias": "-60"}, de=True) == \
        "Normalzeit UTC+01:00, Sommerzeit UTC+02:00; "


def test_a_standard_bias_moves_the_standard_offset_only():
    assert B._zone_offsets({"bias": "300", "standard_bias": "-30", "daylight_bias": "-60"}) == \
        "standard UTC-04:30, daylight saving UTC-04:00; "
