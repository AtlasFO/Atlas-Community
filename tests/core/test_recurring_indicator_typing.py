"""The recurring-indicator scan and its report gate (core.ioc_pivots,
tools.reasoning.reason_pre_report_check): the blocker asks for a ruling (a
finding for what bears on the case, a disposition for the rest), the
report's Limitations list what only a disposition ruled out, and the scan
reads no value that is not an indicator: a command line, the head of an
OID or a version string, the case's own image digests, a URL cut short
beside its whole. Each rule has the demand it must still make. Invented
fixtures only (CORP-WS01, 203.0.113.x, example.com, dates in 2031)."""
from __future__ import annotations

import hashlib
import json
from unittest.mock import patch

from core.entities import extract
from core.indicators import _found
from core.ioc_pivots import ruled_out_without_finding, unrecorded_evidence_indicators


def _tc(cid, text, cmd=""):
    return {"type": "tool_call", "call_id": cid, "success": True, "cmd": cmd, "stdout_excerpt": text}


def _vals(entries, case_dir=None):
    return {d["value"] for d in unrecorded_evidence_indicators(entries, case_dir, min_calls=3)}


# the blocker asks for a ruling, and a disposition is one.

def _check(tmp_path, texts, extra=()):
    from core.execution_log import ExecutionLog
    from tools.reasoning import reason_pre_report_check
    inst = ExecutionLog()
    inst.configure("GATE", str(tmp_path / "trace.json"))
    inst.record_dair_call("Triage", "", False, "", "", "stay", "")
    for name in ("reason_plan", "reason_hypothesize", "reason_synthesize"):
        inst.record_reason_call(name, True, "ok", {})
    for t in texts:
        inst.record_tool_call("tshark -r capture", True, False, 0, 0, stdout_excerpt=t)
    for content in extra:
        inst.record_agent_message(content, [], kind="disposition")
    with patch("core.execution_log.log", inst), patch.object(inst, "case_dir", return_value=str(tmp_path)), \
            patch("core.coverage_ledger.ready_for_degraded_exit", return_value=True):
        return [i for i in reason_pre_report_check()["blocking_issues"] if "Indicators recur" in i]


def test_the_blocker_names_the_disposition_route_and_one_disposition_clears_it(tmp_path):
    texts = ["beacon to update.example.com from 203.0.113.9"] * 3
    (issue,) = _check(tmp_path, texts)
    assert "Rule the rest out in one disposition" in issue and "rules them benign" not in issue
    assert "Record a finding for each that bears on the case" in issue
    (tmp_path / "b").mkdir()
    assert not _check(tmp_path / "b", texts, extra=[
        "203.0.113.9 and update.example.com are the vendor's update service: no indicator"])


def test_the_limitations_list_what_only_a_disposition_ruled_out():
    seen = [_tc(i, "logon from 203.0.113.9 and 203.0.113.44") for i in (1, 2, 3)]
    ruled = {"type": "investigation_narration", "kind": "disposition", "call_id": 9,
             "content": "203.0.113.9 is the site's own VPN gateway: no indicator"}
    finding = {"type": "finding", "call_id": 10, "description": "The intruder logged on from 203.0.113.44."}
    out = ruled_out_without_finding(seen + [ruled, finding])
    assert out == [{"value": "203.0.113.9", "kind": "ip", "calls": 3, "disposition": 9,
                    "reason": "203.0.113.9 is the site's own VPN gateway: no indicator"}]


def test_the_report_states_the_line(tmp_path, monkeypatch):
    from core.investigation_exit import open_limit_lines
    entries = [_tc(i, "logon from 203.0.113.9") for i in (1, 2, 3)] + [
        {"type": "investigation_narration", "kind": "disposition", "call_id": 9,
         "content": "203.0.113.9 is the site's own VPN gateway"}]
    monkeypatch.setattr("core.execution_log.trace_entries", lambda case_dir: entries)
    lines = [x for x in open_limit_lines(tmp_path) if x.startswith("Recurring values ruled out")]
    assert lines == ["Recurring values ruled out without a finding (1): 203.0.113.9 (ip) - disposition call 9: "
                     "203.0.113.9 is the site's own VPN gateway"]


# the head of an OID or a version string is no address; ip.port is.

def test_an_oid_or_a_version_string_is_no_address_and_an_address_with_its_port_is():
    for oid in ("1.3.6.1.4.1.311.2.1.15", "1.3.14.3.2.26", "{*.8086.3595.0.0.0.0}"):
        assert not [e for e in extract(oid) if e.startswith("ip:")], oid
    row = "IP 203.0.113.7.443 > 10.0.0.9.1055: Flags [P.]"
    assert {"ip:203.0.113.7", "ip:10.0.0.9"} <= extract(row)       # the shared pair with the row sighting:
    assert _found("ip", "203.0.113.7", row)                         # core.indicators._found reads it alike
    assert "203.0.113.7" in _vals([_tc(i, row) for i in (1, 2, 3)])


def test_a_network_identifier_is_no_indicator_but_its_hosts_are():
    rows = [_tc(i, "RuntimeVersion 15.0.0.0 then 15.0.0.7") for i in (1, 2, 3)]
    assert _vals(rows) == {"15.0.0.7"}


# the case's own image digests are no indicator; a plain evidence file's are.

def test_an_images_acquisition_digest_is_not_demanded_a_sample_files_digest_is(tmp_path):
    image = hashlib.md5(b"r2c image").hexdigest()
    sample = hashlib.sha256(b"r2c sample").hexdigest()
    (tmp_path / ".atlas").mkdir()
    (tmp_path / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
        {"path": "evidence/corp-ws01.E01", "hash_preflight": {"success": True, "acquisition_hashes": {"md5": image}}}]}))
    (tmp_path / ".atlas" / "evidence_catalog.json").write_text(json.dumps({"units": {
        "u1": {"path": "evidence/payload.exe", "content_sha256": sample, "fingerprint_mode": "full"}}}))
    memory = hashlib.sha256(b"r2c memory").hexdigest()
    (tmp_path / ".atlas" / "coverage_ledger.json").write_text(json.dumps({"units": {
        "m1": {"id": "m1", "path": "evidence/corp-ws01.mem", "kind": "container"}}}))
    catalog = json.loads((tmp_path / ".atlas" / "evidence_catalog.json").read_text())
    catalog["units"]["m1"] = {"path": "evidence/corp-ws01.mem", "content_sha256": memory, "fingerprint_mode": "full"}
    (tmp_path / ".atlas" / "evidence_catalog.json").write_text(json.dumps(catalog))
    rows = [_tc(i, f"MD5: {image}\nSHA256 of the sample: {sample}\nSHA256 of the memory image: {memory}")
            for i in (1, 2, 3)]
    vals = _vals(rows, tmp_path)
    assert image not in vals and memory not in vals and sample in vals


# the command line is the run's own words.

def test_a_value_only_in_the_command_line_is_not_demanded():
    cmd = "rip.pl -r evidence/corp-ws01/NTUSER.DAT -p userassist --bn /opt/tools/baseline.reb"
    assert "baseline.reb" not in _vals([_tc(i, "UserAssist rows", cmd) for i in (1, 2, 3)])
    assert "baseline.reb" in _vals([_tc(i, "loaded /opt/tools/baseline.reb") for i in (1, 2, 3)])


# a URL cut short beside its whole in the same output.

def test_a_cut_url_beside_its_whole_is_dropped_and_apart_both_stay():
    same = [_tc(i, "https://www.ex https://www.example.com/a https://intranet/") for i in (1, 2, 3)]
    assert _vals(same) == {"https://www.example.com/a", "https://intranet/"}
    apart = [_tc(i, "https://www.ex") for i in (1, 2, 3)] + [_tc(i, "https://www.example.com/a") for i in (4, 5, 6)]
    assert {"https://www.ex", "https://www.example.com/a"} <= _vals(apart)


# a URL named without its query or its trailing slash is named.

def test_a_url_named_without_its_query_or_slash_is_ruled_on_a_deeper_path_is_not():
    rows = [_tc(i, "visited https://shop.example.com/p?id=1 and https://news.example.com/") for i in (1, 2, 3)]
    named = {"type": "finding", "call_id": 9,
             "description": "The user visited https://shop.example.com/p and https://news.example.com."}
    assert _vals(rows + [named]) == set()
    deeper = {"type": "finding", "call_id": 9, "description": "The user read https://news.example.com/x."}
    assert "https://news.example.com/" in _vals(rows + [deeper])


def test_a_large_spill_swept_by_bytes_reads_no_oid_head_and_keeps_an_address(tmp_path):
    from core.indicators import SPILL_READ_CHARS
    rows = []
    for i in (1, 2, 3):
        spill = tmp_path / f"strings{i}.txt"
        spill.write_text("1.3.6.1.4.1.311.2.1.15\n1.3.14.3.2.26\nconnect 203.0.113.9\n" + "x" * (SPILL_READ_CHARS + 10))
        rows.append(dict(_tc(i, "strings output, see the retained file"), stdout_file=str(spill)))
    vals = _vals(rows)
    assert "203.0.113.9" in vals and not {"1.3.6.1", "1.3.14.3", "4.1.311.2"} & vals


# The review's cut: only a value of a kind with an investigative handle blocks.

def test_a_file_name_or_a_private_address_is_mentioned_never_demanded():
    from core.ioc_pivots import describe_unrecorded_bulk, unrecorded_demand
    rows = [_tc(i, "svchost.exe and payload.dll ran; vpn 10.0.0.7; beacon to 203.0.113.9") for i in (1, 2, 3)]
    demand, bulk = unrecorded_demand(unrecorded_evidence_indicators(rows, None, min_calls=3))
    assert {d["value"] for d in demand} == {"203.0.113.9"}
    line = describe_unrecorded_bulk(bulk)
    assert all(v in line for v in ("svchost.exe (file)", "payload.dll (file)", "10.0.0.7 (ip)"))


def test_the_audit_lists_only_demandable_kinds_with_the_clause_that_names_each():
    rows = [_tc(i, "svchost.exe beacon to 203.0.113.77") for i in (1, 2, 3)]
    reason = "svchost.exe is the Windows service host. 203.0.113.77 is the scanner the site runs; " + "x" * 200
    ruled = {"type": "investigation_narration", "kind": "disposition", "call_id": 9, "content": reason}
    out = ruled_out_without_finding(rows + [ruled])
    assert [d["value"] for d in out] == ["203.0.113.77"]
    assert out[0]["reason"].startswith("203.0.113.77 is the scanner the site runs;") and len(out[0]["reason"]) <= 160


def test_one_scan_serves_a_trace_version_and_a_new_call_reads_again():
    from core.ioc_pivots import _seen_by_calls
    rows = [_tc(i, "beacon to 203.0.113.9") for i in (1, 2, 3)]
    first = _seen_by_calls(rows)
    assert _seen_by_calls(list(rows)) is first
    assert _seen_by_calls(rows + [_tc(4, "beacon to 203.0.113.10")]) is not first


def test_private_addresses_never_hide_an_outside_one():
    from core.ioc_pivots import unrecorded_demand
    private = " ".join(f"10.0.0.{n}" for n in range(1, 16))
    rows = [_tc(i, f"hosts {private}; beacon to 203.0.113.9") for i in (1, 2, 3)]
    demand, bulk = unrecorded_demand(unrecorded_evidence_indicators(rows, None, min_calls=3))
    assert [d["value"] for d in demand] == ["203.0.113.9"] and len(bulk) == 15
    only_low = [_tc(i, "hosts 10.0.0.1 10.0.0.2") for i in (1, 2, 3)]
    assert unrecorded_demand(unrecorded_evidence_indicators(only_low, None, min_calls=3))[0] == []


def test_a_changed_mount_plan_is_read_again_for_an_unchanged_trace(tmp_path):
    import os
    from core.ioc_pivots import _seen_by_calls
    (tmp_path / ".atlas").mkdir()
    plan = tmp_path / ".atlas" / "mount_plan.json"
    plan.write_text(json.dumps({"images": []}))
    rows = [_tc(i, "beacon to 203.0.113.9") for i in (1, 2, 3)]
    first = _seen_by_calls(rows, tmp_path)
    assert _seen_by_calls(rows, tmp_path) is first
    stamp = plan.stat().st_mtime_ns + 1_000_000_000
    os.utime(plan, ns=(stamp, stamp))
    assert _seen_by_calls(rows, tmp_path) is not first
