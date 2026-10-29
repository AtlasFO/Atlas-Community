"""Typed indicators: rows the analyst states are checked against the cited
outputs, sided, given a use, and turned into the deliverable; prose rows
stay under review; the owner's own assets never become block items."""
from tests._edition import DEVTOOLS_SHIPPED, NO_DEVTOOLS
import csv
import io
import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest

from core import indicators as I
from core.ioc_catalog import build_catalog, render_csv, render_markdown, write_indicator_files


@pytest.fixture(autouse=True)
def _catalogue_before_sightings(monkeypatch):
    """This module pins the indicator lists built from recorded beliefs
    alone (ATLAS_IOC_SIGHTED_CATALOG=0); the sighted lists are pinned in
    tests/core/test_sighted_catalog.py."""
    monkeypatch.setenv("ATLAS_IOC_SIGHTED_CATALOG", "0")



# ── shapes ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("row, value", [
    ({"type": "ip", "value": "192.0.2.10:443", "side": "attacker"}, "192.0.2.10"),
    ({"type": "ipv4", "value": "192.0.2.10", "side": "adversary"}, "192.0.2.10"),
    ({"type": "mac", "value": "AA-BB-CC-DD-EE-FF", "side": "victim"}, "aa:bb:cc:dd:ee:ff"),
    ({"type": "sha256", "value": "A" * 64, "side": "attacker"}, "a" * 64),
    ({"type": "url", "value": "hxxp://bad[.]example[.]net/x", "side": "attacker"}, "http://bad.example.net/x"),
    ({"type": "domain", "value": "Relay.Example.NET.", "side": "attacker"}, "relay.example.net"),
    ({"type": "serial", "value": "7a210098760543212345", "side": "subject"}, "7A210098760543212345"),
    ({"type": "key_id", "value": "AKIAEXAMPLEKEY000001", "side": "subject"}, "AKIAEXAMPLEKEY000001"),
])
def test_rows_are_canonical(row, value):
    out, why = I.normalize_row(row)
    assert why == "" and out["value"] == value


@pytest.mark.parametrize("row", [
    {"type": "ip", "value": "999.1.1.1", "side": "attacker"},
    {"type": "hash", "value": "abc", "side": "attacker"},
    {"type": "email", "value": "x@y.ost", "side": "subject"},
    {"type": "email", "value": "x@y.exe", "side": "subject"},
    {"type": "url", "value": "relay.example.net", "side": "attacker"},
    {"type": "path", "value": "svc.exe", "side": "attacker"},
    {"type": "ip", "value": "192.0.2.10", "side": "enemy"},
    {"type": "thing", "value": "x", "side": "attacker"},
    "192.0.2.10",
])
def test_rows_that_cannot_be_indicators_are_dropped_with_a_reason(row):
    out, why = I.normalize_row(row)
    assert out is None and why


# ── presence, normalised per type ────────────────────────────────────────

@pytest.mark.parametrize("kind, value, text, found", [
    ("path", "C:\\Windows\\System32\\svc.exe", "mnt/host/fs/Windows/System32/svc.exe  12 KB", True),
    ("path", "mnt/host/fs/Windows/System32/svc.exe", "C:\\WINDOWS\\system32\\svc.exe", True),
    ("path", "C:\\Users\\a\\x.exe", "C:\\Users\\b\\x.exe", False),
    ("registry", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\svc", "ROOT\\ControlSet001\\Services\\svc | ImagePath", True),
    ("registry", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\upd", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\upd", True),
    ("ip", "192.0.2.10", "dst 192.0.2.10:443 syn", True),
    ("ip", "192.0.2.1", "dst 192.0.2.10:443", False),
    ("mac", "aa:bb:cc:dd:ee:ff", "MAC AA-BB-CC-DD-EE-FF seen", True),
    ("url", "http://bad.example.net/x", "GET hxxp://bad[.]example[.]net/x 200", True),
    ("hash", "d" * 32, "MD5: " + "D" * 32, True),
    ("account", "CORP\\j.doe", "user j.doe logged on", True),
    ("account", "j.doe", "user j.doer logged on", False),
    ("domain", "relay.example.net", "resolve relay.example.net. 192.0.2.10", True),
    ("domain", "example.net", "relay.example.net", False),
    ("pattern", "*.locked", "notes.txt.locked", True),
])
def test_presence_is_judged_after_the_types_normalisation(kind, value, text, found):
    assert I._found(kind, value, text) is found


# ── use labels ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("frame, side, kind, value, use", [
    ("incident", "attacker", "ip", "198.51.100.7", ["block"]),
    ("incident", "attacker", "ip", "10.9.9.9", ["hunt", "scope"]),
    ("incident", "attacker", "ip", "100.64.1.1", ["hunt", "scope"]),
    ("incident", "attacker", "domain", "relay.example.net", ["block"]),
    ("incident", "attacker", "domain", "abcdefghijklmnop.onion", ["hunt"]),
    ("incident", "attacker", "hash", "a" * 32, ["hunt"]),
    ("incident", "attacker", "serial", "AB12345678", ["hunt"]),
    ("incident", "attacker", "account", "svc-upd", ["contain", "hunt"]),
    ("incident", "attacker", "cloud_resource", "bucket-x", ["request"]),
    ("incident", "victim", "credential_id", "AKIAEXAMPLEKEY000001", ["scope"]),
    ("incident", "victim", "host", "FS01", ["scope"]),
    ("incident", "subject", "account", "j.doe", ["identify", "contain"]),
    ("incident", "subject", "serial", "AB12345678", ["identify"]),
    ("incident", "third_party", "email", "a@b.example.org", ["request"]),
    ("incident", "third_party", "cloud_resource", "bucket-y", ["request"]),
    ("incident", "third_party", "path", "C:\\x\\y", ["review"]),
    ("incident", "subject", "email", "j@mail.example.org", ["identify", "request"]),
    ("incident", "subject", "credential_id", "AKIAEXAMPLEKEY000001", ["identify", "request"]),
    ("subject", "subject", "account", "j.doe", ["identify"]),
    ("subject", "subject", "email", "j@mail.example.org", ["identify", "request"]),
    ("incident", "attacker", "ip", "0.0.0.0", ["review"]),
    ("incident", "attacker", "ip", "224.0.0.251", ["review"]),
    ("subject", "victim", "account", "target.person", ["identify"]),
    ("subject", "attacker", "ip", "198.51.100.7", ["identify"]),
    ("subject", "third_party", "domain", "relay.example.net", ["identify"]),
    ("subject", "third_party", "path", "C:\\x\\y", ["review"]),
    ("subject", "any", "cloud_resource", "bucket-x", ["request"]),
    ("subject", "subject", "hash", "a" * 32, ["hunt"]),
])
def test_the_use_table_covers_every_combination(frame, side, kind, value, use):
    assert I.use_for(frame, side, kind, value) == use


# ── validation against the cited outputs ─────────────────────────────────

def _log(tmp_path, *outputs):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    l.configure("CASE", str(tmp_path / "analysis" / "trace.json"))
    ids = [l.record_tool_call(f"tool {i}", True, False, 0, 0, stdout_excerpt=text)
           for i, text in enumerate(outputs)]
    return l, ids


def test_values_the_cited_outputs_do_not_show_are_dropped_and_named(tmp_path):
    l, ids = _log(tmp_path, "svc.exe created C:\\Users\\Public\\svc.exe at 2031-02-04 10:41:03 UTC by 198.51.100.7")
    with patch("core.execution_log.log", l):
        out = I.validate([
            {"type": "path", "value": "C:\\Users\\Public\\svc.exe", "side": "attacker",
             "first_seen": "2031-02-04T10:41:03Z"},
            {"type": "ip", "value": "198.51.100.7", "side": "attacker"},
            {"type": "ip", "value": "198.51.100.8", "side": "attacker"},
            {"type": "hash", "value": "e" * 40, "side": "attacker", "last_seen": "2031-02-05 09:00"},
        ], call_ids=ids, case_dir=None)
    kept = {r["value"]: r for r in out["kept"]}
    assert set(kept) == {"C:\\Users\\Public\\svc.exe", "198.51.100.7"}
    assert kept["C:\\Users\\Public\\svc.exe"]["first_seen"].startswith("2031-02-04 10:41:03")
    dropped = {d["value"]: d["reason"] for d in out["dropped"]}
    assert "198.51.100.8" in dropped and dropped["198.51.100.8"] == I.DROP_REASON_NO_SIGHTING
    assert ("e" * 40) in dropped
    assert kept["198.51.100.7"]["sightings"][0]["cited"] is True
    assert kept["198.51.100.7"]["seen_basis"] == "sightings"


def test_a_lookup_echo_is_no_sign_the_value_was_present(tmp_path):
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    l.configure("CASE", str(tmp_path / "analysis" / "trace.json"))
    lookup = l.record_tool_call("<py>:enrich_vt_lookup_ip", True, False, 0, 0,
                                stdout_excerpt='{"ip": "198.51.100.7", "malicious": 9}')
    seen = l.record_tool_call("<py>:table_table_query", True, False, 0, 0,
                              stdout_excerpt="4624 logon from 198.51.100.7")
    row = {"type": "ip", "value": "198.51.100.7", "side": "attacker"}
    with patch("core.execution_log.log", l):
        # The lookup shows nothing; the run-wide sighting on the table call
        # keeps the row, marked as not cited by this finding.
        only_lookup = I.validate([row], call_ids=[lookup], case_dir=None)["kept"]
        assert [s["call"] for s in only_lookup[0]["sightings"]] == [seen]
        assert only_lookup[0]["sightings"][0]["cited"] is False
        both = I.validate([row], call_ids=[lookup, seen], case_dir=None)["kept"]
        assert both[0]["sightings"][0]["cited"] is True


def test_a_row_without_a_cited_call_is_dropped(tmp_path):
    """With no evidence call in the log at all, the row is dropped with the
    context reason; a value shown only by an uncited call is kept (see the
    lookup-echo test above)."""
    l, _ids = _log(tmp_path)
    with patch("core.execution_log.log", l):
        out = I.validate([{"type": "ip", "value": "198.51.100.7", "side": "attacker"}], call_ids=[], case_dir=None)
    assert out["kept"] == [] and out["dropped"][0]["reason"] == I.DROP_REASON_NO_SIGHTING
    assert out["dropped"][0]["refusal"] == "presence"


def _case(tmp_path, brief="", nodes=()):
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True, exist_ok=True)
    # The incident frame these rules are pinned in is the brief's
    # statement: a brief naming no owner is the neutral frame.
    (d / "CASE.md").write_text(brief or "# Case: X\n\n**Case ID:** X\n**System owner:** victim\n", encoding="utf-8")
    graph = {"nodes": {}, "edges": []}
    for i, n in enumerate(nodes, start=1):
        graph["nodes"][f"C{i:04d}"] = {"id": f"C{i:04d}", "kind": "claim", "status": "new",
                                       "confidence": "LIKELY", "input_call_ids": [i], **n}
    (d / ".atlas" / "claim_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    return d


def test_an_own_asset_stated_as_the_attackers_is_re_sided(tmp_path):
    d = _case(tmp_path, nodes=[{"host": "FS01", "statement": "FS01 (192.0.2.10) served the share."}])
    l, ids = _log(tmp_path, "logon from 192.0.2.10 and from 198.51.100.7")
    with patch("core.execution_log.log", l):
        out = I.validate([{"type": "ip", "value": "192.0.2.10", "side": "attacker"},
                          {"type": "ip", "value": "198.51.100.7", "side": "attacker"}],
                         call_ids=ids, case_dir=d, frame="incident")
    rows = {r["value"]: r for r in out["kept"]}
    assert rows["192.0.2.10"]["side"] == "victim" and rows["192.0.2.10"]["compromised"] is True
    assert rows["198.51.100.7"]["side"] == "attacker"
    assert [r["value"] for r in out["resided"]] == ["192.0.2.10"]


def test_a_subject_row_keeps_its_side_even_as_an_own_asset(tmp_path):
    d = _case(tmp_path, nodes=[{"host": "PC", "statement": "PC (192.0.2.20) is the laptop."}])
    l, ids = _log(tmp_path, "profile of j.doe on PC 192.0.2.20")
    with patch("core.execution_log.log", l):
        out = I.validate([{"type": "host", "value": "PC", "side": "subject"}],
                         call_ids=ids, case_dir=d, frame="incident")
    assert out["kept"][0]["side"] == "subject" and out["resided"] == []


# ── the catalog built from typed rows ────────────────────────────────────

def _typed_case(tmp_path, brief=""):
    return _case(tmp_path, brief=brief, nodes=[
        {"host": "FS01", "statement": "The service svc-upd on FS01 (192.0.2.10) called 198.51.100.7 "
                                      "over 443 and dropped C:\\Users\\Public\\svc.exe; 10.9.9.9 relayed.",
         "indicators": [
             {"type": "ip", "value": "198.51.100.7", "side": "attacker", "first_seen": "2031-02-04 10:41:03 UTC"},
             {"type": "ip", "value": "10.9.9.9", "side": "attacker"},
             {"type": "path", "value": "C:\\Users\\Public\\svc.exe", "side": "attacker"},
             {"type": "account", "value": "svc-upd", "side": "attacker"},
             {"type": "ip", "value": "192.0.2.10", "side": "victim", "compromised": True},
         ]},
        {"host": "FS01", "statement": "A second address 203.0.113.9 appears in the proxy log beside "
                                      "198.51.100.7, the attacker's relay."},
    ])


def test_typed_rows_are_the_actionable_list_and_prose_stays_under_review(tmp_path):
    cat = build_catalog(_typed_case(tmp_path))
    assert cat["frame"] == "incident"
    rows = {r["value"]: r for r in cat["iocs"]}
    assert rows["198.51.100.7"]["use"] == ["block"] and rows["198.51.100.7"]["source"] == "typed"
    assert rows["10.9.9.9"]["use"] == ["hunt", "scope"]
    assert rows["svc-upd"]["use"] == ["contain", "hunt"] and rows["svc-upd"]["role"] == "attacker_account"
    assert rows["C:\\Users\\Public\\svc.exe"]["role"] == "attacker_tool"
    assert rows["198.51.100.7"]["first_seen"] == "2031-02-04 10:41:03 UTC"
    assert cat["iocs"][0]["value"] == "198.51.100.7"          # block items lead
    affected = {r["value"]: r for r in cat["affected_assets"]}
    assert affected["192.0.2.10"]["use"] == ["scope"] and affected["192.0.2.10"]["compromised"] is True
    review = {r["value"]: r for r in cat["review"]}
    assert "203.0.113.9" in review and review["203.0.113.9"]["use"] == ["review"]
    assert "198.51.100.7" not in review                       # deduplicated against the typed row
    assert cat["by_use"]["block"] == 1 and cat["total"] == 4


def test_the_subject_frame_lists_identifiers_and_provider_requests(tmp_path):
    brief = ("# Case: X\n\n**Case ID:** X\n**Engagement:** examination\n**System owner:** suspect\n")
    d = _case(tmp_path, brief=brief, nodes=[
        {"host": "LAPTOP", "statement": "The laptop's user j.doe stored a key in keys.csv.",
         "indicators": [{"type": "account", "value": "j.doe", "side": "subject"},
                        {"type": "credential_id", "value": "AKIAEXAMPLEKEY000001", "side": "subject"},
                        {"type": "email", "value": "target@mail.example.org", "side": "victim"}]},
    ])
    cat = build_catalog(d)
    assert cat["frame"] == "subject"
    rows = {r["value"]: r for r in cat["iocs"]}
    assert rows["j.doe"]["use"] == ["identify"]
    assert rows["AKIAEXAMPLEKEY000001"]["use"] == ["identify", "request"]
    assert rows["target@mail.example.org"]["use"] == ["identify", "request"] and rows["target@mail.example.org"]["side"] == "victim"
    text = render_markdown(cat, case_id="X")
    assert "Frame: examination" in text and "## Request from the provider" in text


def test_the_markdown_opens_with_the_frame_and_the_ownership_warning(tmp_path):
    cat = build_catalog(_typed_case(tmp_path))
    text = render_markdown(cat, case_id="X")
    head = text.splitlines()[:6]
    assert any(l.startswith("Frame: incident") for l in head)
    assert any(l.startswith("Own-asset basis:") and "P0 baseline pending" in l for l in head)
    assert "Verify ownership before deploying a block item." in head
    assert "## Block at the perimeter" in text and "## Affected assets" in text and "## Review before use" in text
    assert "| 198.51.100.7 | ip | attacker | LIKELY | 2031-02-04 10:41:03 UTC |" in text


def test_the_csv_leads_with_the_use_column(tmp_path):
    d = _typed_case(tmp_path)
    rows = list(csv.DictReader(io.StringIO(render_csv(build_catalog(d), d))))
    assert list(rows[0].keys())[0] == "use"
    by_value = {r["value"]: r for r in rows}
    assert by_value["198.51.100.7"]["use"] == "block" and by_value["198.51.100.7"]["source"] == "typed"
    assert by_value["10.9.9.9"]["use"] == "hunt scope"
    assert by_value["203.0.113.9"]["use"] == "review" and by_value["203.0.113.9"]["source"] == "prose"
    assert by_value["192.0.2.10"]["use"] == "scope" and by_value["192.0.2.10"]["claim_ids"] == "C0001"


def test_both_files_are_written_beside_the_reports(tmp_path):
    d = _typed_case(tmp_path)
    out = write_indicator_files(d)
    assert Path(out["markdown"]).name.endswith("_iocs.md") and Path(out["csv"]).is_file()
    assert out["total"] == 4 and out["by_use"]["block"] == 1


# ── the pre-report warning ───────────────────────────────────────────────

def test_a_substantiated_exfiltration_finding_without_rows_is_named(tmp_path):
    d = _case(tmp_path, nodes=[
        {"host": "FS01", "statement": "Data was exfiltrated to 198.51.100.7 over HTTPS"},
        {"host": "FS01", "statement": "Data was staged in an archive",
         "indicators": [{"type": "path", "value": "C:\\x\\a.7z", "side": "attacker"}]},
    ])
    entries = [{"claim_id": "C0001", "confidence": "LIKELY", "description": "Data was exfiltrated to 198.51.100.7 over HTTPS",
                "gate_metadata": {"validated_techniques": ["T1048"]}},
               {"claim_id": "C0002", "confidence": "LIKELY", "description": "Data was staged in an archive",
                "gate_metadata": {"validated_techniques": ["T1560"]}}]
    text = I.report_warning(d, entries)
    assert "C0001" in text and "exfiltration" in text and "C0002" not in text
    assert "claim.add_indicators" in text
    assert I.report_warning(d, entries[1:]) == ""


# ── the repair tool ──────────────────────────────────────────────────────

def test_add_indicators_checks_against_the_claims_cited_calls(tmp_path):
    from tools.claim_tools import add_indicators
    d = _case(tmp_path, nodes=[{"host": "FS01", "statement": "svc.exe called 198.51.100.7",
                                "source_finding_call_id": 7, "input_call_ids": [1]}])
    with patch("core.indicators._evidence_entries",
               lambda ids: [(1, {"type": "tool_call", "cmd": "table_grep", "stdout_excerpt": "conn 198.51.100.7:443 svc.exe"})]
               if 1 in ids else []):
        out = add_indicators("C0001", [{"type": "ip", "value": "198.51.100.7", "side": "attacker"},
                                       {"type": "ip", "value": "198.51.100.9", "side": "attacker"}],
                             case_dir=str(d))
    assert out["success"] and [r["value"] for r in out["kept"]] == ["198.51.100.7"]
    assert out["dropped"][0]["value"] == "198.51.100.9"
    node = json.loads((d / ".atlas" / "claim_graph.json").read_text())["nodes"]["C0001"]
    assert node["indicators"][0]["value"] == "198.51.100.7"
    cat = build_catalog(d)
    assert cat["iocs"][0]["value"] == "198.51.100.7" and cat["iocs"][0]["source"] == "typed"


def test_only_what_a_tool_printed_counts_as_presence(tmp_path):
    """A value that appears only in a command line, or only in the
    analyst's own reasoning output, was shown by no evidence."""
    l, ids = _log(tmp_path)
    from core.execution_log import ExecutionLog
    grep_id = l.record_tool_call("bash -c 'grep -rn 198.51.100.4 /mnt/case/logs'", True, False, 0, 0, stdout_excerpt="")
    reason_id = l.record_reason_call("reason_hypothesize", True, "H3: the relay is 198.51.100.9", {})
    with patch("core.execution_log.log", l), patch("core.indicators._in_index", lambda *a, **k: False):
        out = I.validate([{"type": "ip", "value": "198.51.100.4", "side": "attacker"},
                          {"type": "ip", "value": "198.51.100.9", "side": "attacker"}],
                         call_ids=[grep_id, reason_id], case_dir=None)
    assert out["kept"] == [] and len(out["dropped"]) == 2


@pytest.mark.parametrize("kind, value, text, found", [
    ("path", "C:\\Users\\admin\\Desktop\\note.txt", "C:\\Users\\other\\Desktop\\note.txt", False),
    ("path", "C:\\Users\\bob\\AppData\\Roaming\\x\\update.exe", "C:\\ProgramData\\x\\update.exe", False),
    ("path", "mnt/img1/fs/Windows/System32/svc.exe", "C:\\Windows\\System32\\svc.exe", True),
    ("registry", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
     "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\Updater", False),
    ("ip", "198.51.100.7", "Connection from 198.51.100.7.", True),
    ("hash", "d" * 32, "sha256 " + "d" * 64, False),
    ("service", "svc", "svchost.exe running", False),
    ("service", "svc", "service svc started", True),
    ("ip", "2001:db8::1", "dst 2001:0db8:0000:0000:0000:0000:0000:0001 port 443", True),
])
def test_presence_needs_the_whole_value_at_a_boundary(kind, value, text, found):
    assert I._found(kind, value, text) is found


# ── plumbing cases ───────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["java-update.net", "go-daddy.com", "rb-bank.de", "cloud-log.com",
                                  "secure-zip.com", "go.com", "ts.net", "rb.gy", "node.js.org"])
def test_a_host_under_a_delegated_name_is_a_domain_whatever_its_labels_look_like(name):
    from core.ioc_catalog import _dotted_kind
    assert _dotted_kind(name) == "domain"
    out, why = I.normalize_row({"type": "domain", "value": name, "side": "attacker"})
    assert out and why == ""


def test_a_url_keeps_an_address_host_or_a_file_looking_host(tmp_path):
    from core.ioc_catalog import _candidates
    cands = _candidates("The payload came from http://203.0.113.7/stage2.ps1 and "
                        "https://release-archive.zip/setup; the intranet http://intranet.corp.local/login was reached.", set())
    urls = {v for c, v in cands if c == "domain"}
    assert "http://203.0.113.7/stage2.ps1" in urls and "https://release-archive.zip/setup" in urls


def test_an_intranet_url_is_an_own_asset_not_infrastructure(tmp_path):
    d = _case(tmp_path, nodes=[{"host": "FS01", "statement":
                                "The operator opened http://intranet.corp.local/login from FS01 and the attacker "
                                "fetched http://203.0.113.7/stage2.ps1."}])
    cat = build_catalog(d)
    affected = {r["value"] for r in cat["affected_assets"]}
    review = {r["value"]: r for r in cat["review"]}
    assert any("intranet.corp.local" in v for v in affected)
    assert "http://203.0.113.7/stage2.ps1" in review and review["http://203.0.113.7/stage2.ps1"]["role"] == "attacker_infra"


def test_prose_forms_of_a_typed_value_do_not_become_review_rows(tmp_path):
    d = _case(tmp_path, nodes=[{"host": "WS01", "statement":
                                "The attacker ran C:\\Users\\bob\\Downloads\\dropper.exe, which called 203.0.113.9:443.",
                                "indicators": [{"type": "path", "value": "C:\\Users\\bob\\Downloads\\dropper.exe", "side": "attacker"},
                                               {"type": "ip", "value": "203.0.113.9", "side": "attacker"}]}])
    cat = build_catalog(d)
    review = {r["value"].lower() for r in cat["review"]}
    assert not ({"dropper.exe", "bob", "203.0.113.9", "203.0.113.9:443"} & review)


def test_subject_frame_prose_rows_carry_no_attacker_wording(tmp_path):
    brief = "# Case: X\n\n**Case ID:** X\n**Engagement:** examination\n**System owner:** suspect\n"
    d = _case(tmp_path, brief=brief, nodes=[{"host": "LAPTOP", "statement":
                                             "The profile j.doe synced files to storage.example.net and mailed "
                                             "contact@example.org; the attacker word never applies here."}])
    cat = build_catalog(d)
    roles = {r["value"]: (r["role"], r["explanation"]) for r in cat["review"]}
    assert roles["storage.example.net"] == ("third_party", "named in the finding")
    assert roles["contact@example.org"] == ("third_party", "named in the finding")
    text = render_markdown(cat, case_id="X")
    assert "attacker-controlled" not in text and "attacker activity" not in text


def test_typed_third_party_rows_get_their_own_group_and_subject_sides_are_listed_apart(tmp_path):
    from core.ioc_catalog import _USE_TITLES
    d = _case(tmp_path, nodes=[{"host": "WS01", "statement": "A broker was contacted.",
                                "indicators": [{"type": "email", "value": "broker@example.net", "side": "third_party"},
                                               {"type": "serial", "value": "AB12345678", "side": "third_party"},
                                               {"type": "ip", "value": "203.0.113.9", "side": "attacker"}]}])
    text = render_markdown(build_catalog(d), case_id="X")
    # a provider holds the broker's mailbox: a request item; the device serial stays a third-party identifier
    assert "broker@example.net" in text.split(f"## {_USE_TITLES['request']}")[1].split("## ")[0]
    assert "## Third-party identifiers" in text and "AB12345678" in text.split("## Third-party identifiers")[1]
    brief = "# Case: X\n\n**Case ID:** X\n**Engagement:** examination\n**System owner:** suspect\n"
    d2 = _case(tmp_path / "s", brief=brief, nodes=[{"host": "LAPTOP", "statement": "The subject mailed the plan.",
                                                    "indicators": [{"type": "account", "value": "subj01", "side": "subject"},
                                                                   {"type": "email", "value": "target@example.com", "side": "victim"}]}])
    text2 = render_markdown(build_catalog(d2), case_id="Y")
    subject_part = text2.split("## Identifiers of the person under investigation")[1].split("## ")[0]
    victim_part = text2.split("## Victims and named targets")[1].split("## ")[0]
    assert "subj01" in subject_part and "target@example.com" not in subject_part
    assert "target@example.com" in victim_part


def test_a_formula_looking_value_is_quoted_in_the_csv(tmp_path):
    d = _case(tmp_path, nodes=[{"host": "WS01", "statement": "A crafted pattern was found.",
                                "indicators": [{"type": "pattern", "value": "=HYPERLINK(\"http://x\")", "side": "attacker"}]}])
    text = render_csv(build_catalog(d), d)
    assert "'=HYPERLINK" in text


def test_a_missing_tld_list_is_loud(monkeypatch, capsys):
    import core.ioc_catalog as C
    monkeypatch.setattr(C, "_tlds", lambda: frozenset())
    assert C.tld_list_missing() is True
    monkeypatch.setattr(C, "_tlds", lambda: frozenset({"net"}))
    cat = {"frame": "incident", "iocs": [], "review": [], "affected_assets": [], "tld_list_missing": True,
           "beliefs_considered": 1, "own_asset_basis": ""}
    assert "top-level domain list is missing" in render_markdown(cat, case_id="X")


def test_the_shipped_tld_list_loads():
    from core.ioc_catalog import _tlds
    _tlds.cache_clear()
    entries = _tlds()
    assert len(entries) > 1000 and "onion" in entries and "example" not in entries


def test_typed_rows_travel_to_the_replacing_belief(tmp_path):
    from core import claim_graph as cg
    d = _case(tmp_path)
    old = cg.add_claim(d, statement="The relay was 203.0.113.9", confidence="LIKELY", host="WS01")["node_id"]
    cg.set_claim_indicators(d, old, [{"type": "ip", "value": "203.0.113.9", "side": "attacker"}])
    new = cg.add_claim(d, statement="The relay was 203.0.113.9 on port 8443", confidence="LIKELY", host="WS01")["node_id"]
    assert cg.supersede(d, old, new, reason="sharper statement")["success"]
    node = cg.get_node(cg.load_graph(d), new)
    assert node["indicators"][0]["value"] == "203.0.113.9" and node["indicators"][0]["carried_from"] == old
    assert build_catalog(d)["iocs"][0]["value"] == "203.0.113.9"


def test_a_later_side_never_silently_replaces_the_first(tmp_path):
    from core import claim_graph as cg
    d = _case(tmp_path)
    cid = cg.add_claim(d, statement="The relay was 203.0.113.9", confidence="LIKELY", host="WS01")["node_id"]
    cg.set_claim_indicators(d, cid, [{"type": "ip", "value": "203.0.113.9", "side": "attacker"}])
    cg.set_claim_indicators(d, cid, [{"type": "ip", "value": "203.0.113.9", "side": "victim"}])
    row = cg.get_node(cg.load_graph(d), cid)["indicators"][0]
    assert row["side"] == "attacker" and "victim" in row["note"]


def test_a_search_tools_echo_of_its_request_shows_nothing(tmp_path):
    l, ids = _log(tmp_path, '{"query": "198.51.100.4", "results": [], "result_count": 0}',
                  '{"query": "198.51.100.5", "results": [{"snippet": "2031-03-04 10:16:00 dst 198.51.100.5:443"}], '
                  '"result_count": 1}')
    with patch("core.execution_log.log", l), patch("core.indicators._in_index", lambda *a, **k: False):
        out = I.validate([{"type": "ip", "value": "198.51.100.4", "side": "attacker"},
                          {"type": "ip", "value": "198.51.100.5", "side": "attacker"}],
                         call_ids=ids, case_dir=None)
    assert [r["value"] for r in out["kept"]] == ["198.51.100.5"]
    assert out["dropped"][0]["value"] == "198.51.100.4"


@pytest.mark.parametrize("value", ["setup-download.zip", "release-kubernetes.zip", "999.md", "portal.corp.local"])
def test_a_typed_domain_under_a_delegated_or_special_use_name_keeps_its_type(value):
    out, why = I.normalize_row({"type": "domain", "value": value, "side": "attacker"})
    assert out and why == ""
    out, why = I.normalize_row({"type": "email", "value": "x@" + value, "side": "attacker"})
    assert out and why == ""


# ── the frame and the subject's identifiers ──────────────────────────────

def _brief_case(root, text):
    case = root / "CASE"
    case.mkdir(parents=True)
    (case / ".atlas").mkdir()
    (case / "CASE.md").write_text(text, encoding="utf-8")
    return case


def test_the_frame_follows_the_owner_row_and_then_the_subject_row(tmp_path):
    meta = "## Case Metadata\n\n| Field | Value |\n|---|---|\n| **Engagement** | examination |\n"
    subject = "| **Subject** | \"Jane Roe\" — an insider |\n"
    assert I.frame_for(_brief_case(tmp_path / "a", meta + "| **System owner** | victim organisation |\n" + subject)) == "incident"
    assert I.frame_for(_brief_case(tmp_path / "b", meta + subject)) == "subject"
    assert I.frame_for(_brief_case(tmp_path / "c", meta + "| **System owner** | suspect |\n")) == "subject"
    # No owner named and no Subject row: neutral (by design), whatever
    # the Engagement row or the brief's words say.
    assert I.frame_for(_brief_case(tmp_path / "d", meta)) == "neutral"
    assert I.frame_for(_brief_case(tmp_path / "e", "# Case\n\nThe lure read:\n\nSubject: Payment advice\n")) == "neutral"


def test_the_subjects_stated_identifiers_are_sided_as_the_subject(tmp_path):
    brief = ("## Case Metadata\n\n| Field | Value |\n|---|---|\n| **System owner** | victim organisation |\n"
             "| **Subject** | \"Jane Roe\" — an insider |\n| **Subject username** | `jroe` |\n")
    d = _case(tmp_path, brief=brief, nodes=[{"host": "PC01", "statement": "PC01 holds the profile."}])
    l, ids = _log(tmp_path, "profile of jroe on PC01; upload to 198.51.100.7 by CORP\\jroe; file plans.docx")
    with patch("core.execution_log.log", l):
        out = I.validate([{"type": "account", "value": "CORP\\jroe", "side": "attacker"},
                          {"type": "ip", "value": "198.51.100.7", "side": "attacker"},
                          {"type": "file", "value": "plans.docx", "side": "victim"}],
                         call_ids=ids, case_dir=d, frame="incident")
    rows = {r["value"]: r for r in out["kept"]}
    assert rows["CORP\\jroe"]["side"] == "subject" and "subject" in rows["CORP\\jroe"]["note"]
    assert rows["198.51.100.7"]["side"] == "attacker" and rows["plans.docx"]["side"] == "victim"
    assert [r["value"] for r in out["resided"]] == ["CORP\\jroe"]


# ── typed rows refused at record time stay visible ───────────────────────

_SHA = "ab" * 32                     # an invented 64-hex digest
_SLIP = _SHA + "c"                   # the same, one character too long


def _shown(text):
    return lambda ids: [(1, {"type": "tool_call", "cmd": "hash_file", "stdout_excerpt": text})] if 1 in ids else []


def test_a_near_length_hash_is_named_by_its_length():
    row, why = I.normalize_row({"type": "sha256", "value": _SLIP, "side": "attacker"})
    assert row is None and why.startswith("65 hex characters")


def test_a_hash_slip_is_suggested_from_the_cited_output():
    with patch("core.indicators._evidence_entries", _shown(f"sha256 {_SHA.upper()}  C:\\Temp\\m.exe")):
        out = I.validate([{"type": "sha256", "value": _SLIP, "side": "attacker"},
                          {"type": "hash", "value": _SHA[:-1] + "0", "side": "attacker"}],
                         call_ids=[1], case_dir=None)
    shape, presence = out["dropped"]
    assert shape["type"] == "hash" and shape["suggested"] == _SHA and "the cited output shows" in shape["reason"]
    assert presence["suggested"] == _SHA                # a wrong digit fails presence, not shape


def test_two_close_digests_suggest_neither():
    other = _SHA[:-1] + "0"            # also within two edits of the slip
    with patch("core.indicators._evidence_entries", _shown(f"{_SHA} a.exe\n{other} b.exe")):
        out = I.validate([{"type": "hash", "value": _SLIP, "side": "attacker"}], call_ids=[1], case_dir=None)
    assert "suggested" not in out["dropped"][0]


def _refused_case(tmp_path):
    from tools.claim_tools import add_indicators
    d = _case(tmp_path, nodes=[{"host": "CORP-WS01", "statement": "m.exe dumped credentials on CORP-WS01",
                                "source_finding_call_id": 7, "input_call_ids": [1]}])
    with patch("core.indicators._evidence_entries", _shown(f"{_SHA}  C:\\Temp\\m.exe")):
        out = add_indicators("C0001", [{"type": "hash", "value": _SLIP, "side": "attacker"}], case_dir=str(d))
    return d, out


def test_a_refused_row_is_kept_on_the_claim_and_listed_as_not_exported(tmp_path):
    d, out = _refused_case(tmp_path)
    assert out["success"] and out["kept"] == [] and out["dropped"][0]["value"] == _SLIP
    node = json.loads((d / ".atlas" / "claim_graph.json").read_text())["nodes"]["C0001"]
    assert node["indicators_dropped"][0]["value"] == _SLIP
    cat = build_catalog(d)
    assert cat["iocs"] == [] and cat["not_exported_total"] == 1
    row = cat["not_exported"][0]
    assert row["claim_ids"] == ["C0001"] and row["hosts"] == ["CORP-WS01"]
    text = render_markdown(cat, case_id="X")
    assert "## Not exported" in text and _SLIP in text
    assert _SLIP not in render_csv(cat, d)


def test_the_suggested_value_clears_the_refused_row(tmp_path):
    from tools.claim_tools import add_indicators
    d, _out = _refused_case(tmp_path)
    with patch("core.indicators._evidence_entries", _shown(f"{_SHA}  C:\\Temp\\m.exe")):
        add_indicators("C0001", [{"type": "hash", "value": _SHA, "side": "attacker"}], case_dir=str(d))
    node = json.loads((d / ".atlas" / "claim_graph.json").read_text())["nodes"]["C0001"]
    assert "indicators_dropped" not in node
    assert build_catalog(d)["not_exported"] == []


def test_the_advisory_names_the_refused_row_until_its_finding_is_superseded(tmp_path):
    from core.claim_graph import supersede
    d, _out = _refused_case(tmp_path)
    text = I.dropped_warning(d)
    assert "C0001" in text and "Malformed" in text and "claim.add_indicators" in text
    assert "nothing here blocks the report" in text
    supersede(d, "C0001", reason="withdrawn by the analyst")
    assert I.dropped_warning(d) == ""


def test_a_successor_inherits_only_the_rows_it_does_not_resolve(tmp_path):
    from core.claim_graph import load_graph, save_graph, supersede
    d, _out = _refused_case(tmp_path)
    g = load_graph(d)
    g["nodes"]["C0002"] = {"id": "C0002", "kind": "claim", "status": "new", "confidence": "LIKELY",
                           "host": "CORP-WS01", "statement": "m.exe dumped credentials on CORP-WS01"}
    save_graph(d, g)
    supersede(d, "C0001", "C0002", reason="re-recorded")
    assert load_graph(d)["nodes"]["C0002"]["indicators_dropped"][0]["carried_from"] == "C0001"
    g = load_graph(d)
    g["nodes"]["C0003"] = {"id": "C0003", "kind": "claim", "status": "new", "confidence": "LIKELY",
                           "host": "CORP-WS01", "statement": "m.exe dumped credentials on CORP-WS01",
                           "indicators": [{"type": "hash", "value": _SHA, "side": "attacker"}]}
    save_graph(d, g)
    supersede(d, "C0002", "C0003", reason="re-recorded with the digest")
    assert "indicators_dropped" not in load_graph(d)["nodes"]["C0003"]


def test_the_record_path_can_hand_its_refused_rows_to_the_claim(tmp_path):
    """The interface the finding recorder passes its refused rows through."""
    from core.claim_graph import load_graph, upsert_claim_from_finding
    d = _case(tmp_path)
    res = upsert_claim_from_finding(d, statement="m.exe ran on CORP-WS01", confidence="LIKELY",
                                    host="CORP-WS01", finding_call_id=11,
                                    indicators_dropped=[{"type": "hash", "value": _SLIP, "reason": "65 hex characters"}])
    assert load_graph(d)["nodes"][res["claim_id"]]["indicators_dropped"][0]["value"] == _SLIP


def test_a_value_its_calls_do_not_show_is_sent_to_a_re_record(tmp_path):
    from tools.claim_tools import add_indicators
    d = _case(tmp_path, nodes=[{"host": "CORP-WS01", "statement": "svc.exe beaconed out",
                                "source_finding_call_id": 41, "input_call_ids": [1]}])
    with patch("core.indicators._evidence_entries", _shown("conn 198.51.100.7:443 svc.exe")):
        add_indicators("C0001", [{"type": "ip", "value": "198.51.100.9", "side": "attacker"}], case_dir=str(d))
    text = I.dropped_warning(d)
    assert "Not shown by the finding's cited calls" in text and "finding call 41" in text
    assert "supersedes=" in text and "Malformed" not in text


def test_a_refused_row_re_typed_under_another_type_is_resolved(tmp_path):
    from tools.claim_tools import add_indicators
    d = _case(tmp_path, nodes=[{"host": "CORP-WS01", "statement": "m.exe ran",
                                "source_finding_call_id": 7, "input_call_ids": [1]}])
    with patch("core.indicators._evidence_entries", _shown("C:\\Temp\\m.exe started")):
        out = add_indicators("C0001", [{"type": "path", "value": "m.exe", "side": "attacker"}], case_dir=str(d))
        assert out["dropped"][0]["refusal"] == "shape"
        add_indicators("C0001", [{"type": "file", "value": "m.exe", "side": "attacker"}], case_dir=str(d))
    node = json.loads((d / ".atlas" / "claim_graph.json").read_text())["nodes"]["C0001"]
    assert "indicators_dropped" not in node


def test_a_value_another_finding_typed_is_not_listed_as_refused(tmp_path):
    d = _case(tmp_path, nodes=[
        {"host": "CORP-WS01", "statement": "svc.exe beaconed out",
         "indicators_dropped": [{"type": "ip", "value": "198.51.100.7", "reason": "not in the output",
                                 "refusal": "presence"}]},
        {"host": "CORP-WS01", "statement": "the firewall logged 198.51.100.7",
         "indicators": [{"type": "ip", "value": "198.51.100.7", "side": "attacker"}]},
    ])
    assert build_catalog(d)["not_exported"] == []


def test_only_claims_and_conclusions_contribute_refused_rows(tmp_path):
    d = _case(tmp_path, nodes=[{"host": "CORP-WS01", "statement": "isolate CORP-WS01", "kind": "recommendation",
                                "indicators_dropped": [{"type": "hash", "value": _SLIP, "reason": "x"}]}])
    assert build_catalog(d)["not_exported"] == []


def test_a_refused_value_with_a_newline_and_a_pipe_is_one_table_row():
    with patch("core.indicators._evidence_entries", _shown("nothing relevant")):
        out = I.validate([{"type": "ip", "value": "198.51.100.9 |\nx", "side": "attacker"}],
                         call_ids=[1], case_dir=None)
    drop = out["dropped"][0]
    assert "\n" not in drop["value"]
    text = render_markdown({"not_exported": [dict(drop, category=drop["type"], claim_ids=["C0001"])]}, case_id="X")
    rows = [l for l in text.splitlines() if l.startswith("| ") and "C0001" in l]
    assert len(rows) == 1 and "\\|" in rows[0]


# ── the one echo-free output reader ─────────────────────────────────────

def _entry(excerpt, *, args=None, cmd="<py>:table_table_grep", ref=""):
    e = {"type": "tool_call", "cmd": cmd, "stdout_excerpt": excerpt, "success": True}
    if args is not None:
        e["args"] = json.dumps(args) if isinstance(args, dict) else args
    if ref:
        e["evidence_ref"] = ref
    return e


def test_request_echo_is_removed_by_argument_key_and_by_value():
    """A field under one of the call's own argument keys, or whose value the
    call was given, is the request again; a row holding the same text stays."""
    e = _entry(json.dumps({"success": True, "filter": "jane.doe", "where": "jane.doe",
                           "image": "evidence/ws01.E01", "hits": [{"user": "jane.doe", "msg": "logon"}]}),
               args={"filter": "jane.doe", "image": "evidence/ws01.E01"})
    assert I.printed_rows(e) == ['{"user": "jane.doe", "msg": "logon"}']
    # A flat record loses the request the same way; its other fields stay.
    flat = _entry(json.dumps({"success": True, "filter": "jane.doe", "pattern": "jane", "note": "nothing else"}),
                  args={"filter": "jane.doe"})
    assert I.printed_rows(flat) == ['{"success": true, "note": "nothing else"}']


def test_a_not_found_record_shows_nothing_it_was_asked_for():
    """A record that names the request only to say it was not found does not
    print the requested value, parsed or cut short."""
    e = _entry(json.dumps({"username": "jane.doe", "exists": False}), args={"username": "jane.doe"})
    assert "jane.doe" not in I.printed_text(e)
    by_value = _entry(json.dumps({"account": "jane.doe", "exists": False}), args={"user": "jane.doe"})
    assert "jane.doe" not in I.printed_text(by_value)
    cut = _entry('{"account": "jane.doe", "exists": false, "sha256": "' + "a" * 64,
                 args={"user": "jane.doe"})
    assert "jane.doe" not in I.printed_text(cut)
    assert "a" * 64 in I.printed_text(cut)


def test_the_shared_key_list_is_the_fallback_without_args():
    """A baseline entry carries no args: the shared echo keys still go."""
    e = _entry(json.dumps({"pattern": "203.0.113.7", "terms": ["203.0.113.7"], "hits": [{"dst": "203.0.113.7:443"}]}))
    assert I.printed_rows(e) == ['{"dst": "203.0.113.7:443"}']
    assert I.printed_text(_entry(json.dumps({"pattern": "203.0.113.7", "note": "no row"}))) == '{"note": "no row"}'


def test_a_cut_argument_string_still_strips_the_echo():
    """An argument string the trace cut at 400 characters parses as nothing;
    its keys and values are still read as key-value pairs."""
    args = '{"path": "analysis/x.csv", "needle_text": "203.0.113.7", "pattern": "203\\\\.0\\\\.113\\\\.7|' + "a" * 400
    e = _entry(json.dumps({"needle_text": "203.0.113.7", "path": "analysis/x.csv",
                           "rows": [["2031-03-04 10:16:00", "203.0.113.7"]]}), args=args)
    assert I.printed_rows(e) == ['["2031-03-04 10:16:00", "203.0.113.7"]']
    assert "analysis/x.csv" in I.request_strings(e) and "203.0.113.7" in I.request_strings(e)


def test_a_shell_commands_literals_and_paths_are_request_strings():
    e = _entry("", cmd="grep -rn 'jane.doe' /mnt/CASE-A/fs/Users --include \"*.log\"")
    req = I.request_strings(e)
    assert "jane.doe" in req and "/mnt/case-a/fs/users" in req and "*.log" in req
    assert I.request_strings(_entry("", args={"path": "analysis/x.csv", "pattern": "a|b"}, ref="evidence/ws01.E01")) \
        == {"analysis/x.csv", "a|b", "evidence/ws01.e01"}
    assert I.request_strings(_entry("", args="{'path': 'analysis/x.csv'}")) == {"analysis/x.csv"}


def test_echoes_banners_and_coincidences_show_nothing():
    # The alternatives of a search say which parts of the analyst's pattern
    # matched a row, not what the row holds.
    printed = I.printed_text(_entry(json.dumps({
        "success": True, "pattern": "bob|alice", "alternatives": {"matched": ["bob", "alice"], "unmatched": []},
        "hits": [{"user": "jacobson", "msg": "alicexyz"}]})))
    assert "jacobson" in printed and "alicexyz" in printed
    assert not re.search(r"\balice\b", printed) and "bob" not in printed
    # A field whose value the call was given is the request again.
    disk = "evidence/CORP-WS01.E01"
    printed = I.printed_text(_entry(json.dumps({"success": True, "image": disk, "offset": 63,
                                                "files": [{"name": "setup.log"}]}), args={"image_path": disk}))
    assert "corp-ws01" not in printed and "setup.log" in printed
    cut = '{"success": true, "image": "' + disk + '", "command": "fls -o 63", "files": [{"name": "setu'
    printed = I.printed_text(_entry(cut, args={"image_path": disk}))
    assert "corp-ws01" not in printed and "fls" not in printed and "setu" in printed
    # A command-line tool's banner restates its own words; its zero-row line
    # and the zero-row shapes of a JSON result show nothing.
    cmd = "EvtxECmd -f System.evtx --csv out --inc 4624,4625"
    printed = I.printed_text(_entry("Command line: -f System.evtx --inc 4624,4625\nrow: EventID 4625 user svc-backup",
                                    cmd=cmd))
    assert "4624" not in printed and "4625" in printed
    assert I.printed_text(_entry("Command line: --inc 4624\nProcessed 1 file; 0 records matched",
                                 cmd="EvtxECmd --inc 4624")).strip() == "processed 1 file;"
    assert I.printed_rows(_entry(json.dumps({"success": True, "matched_rows": 0, "path": "x.csv"}))) == []
    assert I.printed_rows(_entry(json.dumps({"success": True, "rows": [], "path": "x.csv"}))) == []
    assert I.printed_rows(_entry('{"success": true, "hit_count": 0, "hits": [], "path": "x.csv", "note": "cut')) == []
    assert I._request_tokens({"cmd": "fls -o 63 x.raw"}, frozenset({"a b"})) == {"fls", "-o", "63", "x.raw", "a b", "a", "b"}


def test_labelled_data_lines_survive_but_the_tools_banner_does_not():
    # Sysmon's CommandLine, a shortcut's Arguments and a subscription's Query
    # are data under a banner-like label; only the line made of the call's
    # own words is the banner.
    text = ("Command line: -f System.evtx --inc 4624\nCommandLine: powershell -enc QQ==\n"
            "Arguments: -nop beacon.example.org\nQuery: SELECT * FROM __InstanceModificationEvent")
    printed = I.printed_text(_entry(text, cmd="EvtxECmd -f System.evtx --inc 4624"))
    assert "4624" not in printed
    assert "powershell -enc qq==" in printed and "beacon.example.org" in printed
    assert "__instancemodificationevent" in printed
    # Without the call's words no labelled line is a banner.
    assert "4624" in I.printed_text(_entry(text, cmd=""))


def test_a_zero_count_line_drops_only_itself():
    printed = I.printed_text(_entry("System.evtx: 0 records matched\nSecurity.evtx: 12 records matched\njane.doe 203.0.113.7",
                                    cmd=""))
    assert "0 records matched" not in printed and "system.evtx" not in printed
    assert "12 records matched" in printed and "jane.doe 203.0.113.7" in printed
    assert I.printed_text(_entry("Processed 1 file; 0 records matched\n\n", cmd="")).strip() == "processed 1 file;"
    assert I.printed_rows(_entry("0 records matched\n", cmd="")) == []
    # Only the zero-count clause of a line goes.
    one_line = I.printed_text(_entry("Security.evtx: 12 records matched; System.evtx: 0 records matched", cmd=""))
    assert "security.evtx: 12 records matched" in one_line and "system.evtx" not in one_line


def test_rows_under_another_key_keep_the_result():
    # A result with rows under one key and an empty list or a zero count
    # under another holds rows; the parsed and the cut form agree.
    assert "jane.doe" in I.printed_text(_entry(json.dumps({"success": True, "hits": [{"user": "jane.doe"}], "lines": []})))
    assert "setup.log" in I.printed_text(_entry(json.dumps({"files": [{"name": "setup.log"}], "errors": [], "total": 0})))
    assert "setu" in I.printed_text(_entry('{"total": 0, "errors": [], "files": [{"name": "setu'))
    assert I.printed_rows(_entry(json.dumps({"hit_count": 0, "hits": []}))) == []
    assert I.printed_rows(_entry('{"hit_count": 0, "hits": [], "note": "cu')) == []
    assert I._no_rows({"columns": ["date"], "rows": []}) and not I._no_rows({"rows": [[1, 2]]})
    assert "ghost.exe ran" in I.printed_text(_entry(json.dumps({"lines": ["ghost.exe ran"], "files": [], "count": 0})))
    assert "ghost" in I.printed_text(_entry('{"count": 0, "files": [], "lines": ["ghost'))
    # A value with any word of its own is data; the program's name may open a banner.
    assert "select *" in I.printed_text(_entry("Query: SELECT *\nrow", cmd="sqlite3 *"))
    assert "select * from x" in I.printed_text(_entry("Query: SELECT * FROM x", cmd="sqlite3 * from x"))
    assert I.printed_rows(_entry("Command line: EvtxECmd.exe -f x.evtx", cmd="/opt/ez/evtxecmd -f x.evtx")) == []


def test_a_cut_search_result_loses_its_echo():
    cut = '{"success": true, "pattern": "ghost\\\\.exe|[a-z]{2}", "alternatives": {"matched": [], ' \
          '"unmatched": ["ghost\\\\.exe"]}, "hits": [{"pattern": "row value", "desc": "dropp'
    printed = I.printed_text(_entry(cut))
    assert "ghost" not in printed
    assert "row value" in printed  # a data column of the same name stays
    assert I._first_container('{"a": "x[1]", "b": [1]}') == 19


def test_the_reader_takes_the_spill_or_the_excerpt_never_both(tmp_path):
    spill = tmp_path / "out.json"
    spill.write_text(json.dumps({"pattern": "x", "hits": [{"a": "from the spill"}]}))
    e = _entry(json.dumps({"pattern": "x", "hits": [{"a": "from the excerpt"}]}))
    assert I.printed_rows(e) == ['{"a": "from the excerpt"}']
    e["stdout_file"] = str(spill)
    assert I.printed_rows(e) == ['{"a": "from the spill"}']
    assert I.printed_rows(e, text='{"pattern": "x", "hits": [{"a": "a window"}]}') == ['{"a": "a window"}']
    e["stdout_file"] = str(tmp_path / "gone.json")
    assert I.printed_rows(e) == ['{"a": "from the excerpt"}']


def test_echo_free_off_restores_the_earlier_reader(monkeypatch):
    e = _entry(json.dumps({"pattern": "203.0.113.7", "note": "nothing", "hits": [{"dst": "203.0.113.7"}]}))
    monkeypatch.setenv("ATLAS_IOC_ECHO_FREE", "0")
    legacy = I.printed_rows(e)
    assert len(legacy) == 1 and "nothing" in legacy[0] and "pattern" not in legacy[0]
    monkeypatch.setenv("ATLAS_IOC_ECHO_FREE", "1")
    assert I.printed_rows(e) == ['{"dst": "203.0.113.7"}']


@pytest.mark.skipif(not DEVTOOLS_SHIPPED, reason=NO_DEVTOOLS)
def test_one_reader_is_shared():
    import devtools.validation.run_audit as ra
    assert ra.printed_rows is I.printed_rows and ra.request_strings is I.request_strings


# ── sightings ────────────────────────────────────────────────────────────

def _case_log(tmp_path, monkeypatch):
    """A case directory with a configured log and an index of its own."""
    from core import provenance
    from core.execution_log import ExecutionLog
    case = tmp_path / "CASE-A"
    for sub in ("analysis", "evidence", "exports", ".atlas"):
        (case / sub).mkdir(parents=True, exist_ok=True)
    l = ExecutionLog()
    l.configure("CASE-A", str(case / "analysis" / "trace.json"))
    monkeypatch.setattr("core.execution_log.log", l)
    monkeypatch.setattr("core.evidence_index.db_path", lambda: str(case / "analysis" / "evidence_index.db"))
    provenance.reset_cache()
    return case, l


def _table(case, rel, text="x"):
    """A parsed table that predates the run's first call (intake's parser
    wrote it): derived without a ledger record."""
    import os
    import time
    p = case / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    past = time.time() - 3600
    os.utime(p, (past, past))
    return p


def _call(l, cmd, excerpt, *, args=None, ref="", spill=None, success=True):
    cid = l.record_tool_call(cmd, success, False, 0, 0, stdout_excerpt=excerpt, evidence_ref=ref,
                             stdout_file=str(spill) if spill else "")
    if args is not None:
        l.annotate_tool_call(cid, args=json.dumps(args, sort_keys=True))
    return cid


def test_spill_echo_is_not_a_sighting(tmp_path, monkeypatch):
    case, l = _case_log(tmp_path, monkeypatch)
    spill = case / "analysis" / "tool-output" / "grep.json"
    spill.parent.mkdir(parents=True)
    spill.write_text(json.dumps({"pattern": "corp-svc01|jane.doe", "alternatives": {"matched": ["corp-svc01"],
                                 "unmatched": ["jane.doe"]}, "hits": [{"host": "CORP-SVC01", "msg": "boot"}]}))
    _table(case, "analysis/t.csv")
    cid = _call(l, "<py>:table_table_grep", "", args={"pattern": "corp-svc01|jane.doe", "path": "analysis/t.csv"},
                spill=spill)
    rows = [{"type": "account", "value": "jane.doe", "side": "attacker"}]
    assert I.validate(rows, call_ids=[cid], case_dir=str(case))["kept"] == []
    spill.write_text(json.dumps({"pattern": "corp-svc01|jane.doe", "hits": [
        {"host": "CORP-SVC01", "user": "jane.doe", "ts": "2031-03-04 10:16:00"}]}))
    kept = I.validate(rows, call_ids=[cid], case_dir=str(case))["kept"]
    assert kept and kept[0]["sightings"][0]["rows"] == 1 and kept[0]["first_seen"] == "2031-03-04 10:16:00"


def test_a_program_printing_its_argument_is_not_a_sighting(tmp_path, monkeypatch):
    case, l = _case_log(tmp_path, monkeypatch)
    (case / "evidence" / "ws01.log").write_text("x")
    cid = _call(l, "python3 -c 'print(\"203.0.113.7\")' evidence/ws01.log", "203.0.113.7\n")
    rows = [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}]
    assert I.validate(rows, call_ids=[cid], case_dir=str(case))["kept"] == []
    dated = _call(l, "python3 -c 'print(open(\"evidence/ws01.log\").read())' 203.0.113.7",
                  "2031-03-04 10:16:00 CORP-WS01 connect 203.0.113.7:443\n")
    kept = I.validate(rows, call_ids=[dated], case_dir=str(case))["kept"]
    assert kept and kept[0]["sightings"][0]["call"] == dated


def test_a_read_of_a_run_written_file_is_not_a_sighting(tmp_path, monkeypatch):
    from core.provenance import record_outputs
    case, l = _case_log(tmp_path, monkeypatch)
    before = {}
    writer = _call(l, "python3 analysis/notes.py", "wrote analysis/notes.txt")
    (case / "analysis" / "notes.txt").write_text("the relay was 203.0.113.7 at 2031-03-04 10:16:00")
    (case / "CASE.md").write_text("Brief: 203.0.113.7 is the suspected relay")
    from core.provenance import output_snapshot
    record_outputs(case, l.index().by_call_id[writer], before, output_snapshot(case))
    read = _call(l, "cat analysis/notes.txt", "the relay was 203.0.113.7 at 2031-03-04 10:16:00")
    brief = _call(l, "cat CASE.md", "Brief: 203.0.113.7 is the suspected relay")
    rows = [{"type": "ip", "value": "203.0.113.7", "side": "attacker"}]
    out = I.validate(rows, call_ids=[read, brief], case_dir=str(case))
    assert out["kept"] == [] and out["dropped"][0]["reason"] == I.DROP_REASON_NO_SIGHTING


def test_a_parser_output_under_analysis_is_derived_and_lineage_stops_at_a_program(tmp_path, monkeypatch):
    from core.provenance import call_provenance, output_snapshot, record_outputs
    case, l = _case_log(tmp_path, monkeypatch)
    (case / "evidence" / "ws01.E01").write_text("img")
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01.E01", "kind": "image"}], "hosts": ["CORP-WS01"]}))
    before = output_snapshot(case)
    parser = _call(l, "EvtxECmd -f evidence/ws01.E01 --csv analysis/ws01", "done", ref="evidence/ws01.E01")
    (case / "analysis" / "ws01").mkdir()
    (case / "analysis" / "ws01" / "sec.csv").write_text("TimeCreated,Computer,EventId,User\n"
                                                        "2031-03-04 10:16:00,CORP-WS01,4624,jane.doe\n")
    record_outputs(case, l.index().by_call_id[parser], before, output_snapshot(case))
    grep = _call(l, "<py>:table_table_grep", json.dumps({"pattern": "jane.doe", "path": "analysis/ws01/sec.csv",
                                                         "columns": ["TimeCreated", "Computer", "EventId", "User"],
                                                         "rows": [["2031-03-04 10:16:00", "CORP-WS01", "4624", "jane.doe"]]}),
                args={"pattern": "jane.doe", "path": "analysis/ws01/sec.csv"})
    prov = call_provenance(l.index().by_call_id[grep], case)
    assert prov["class"] == "derived" and prov["hosts"] == {"CORP-WS01"}
    kept = I.validate([{"type": "account", "value": "jane.doe", "side": "attacker"}],
                      call_ids=[grep], case_dir=str(case))["kept"]
    s = kept[0]["sightings"][0]
    assert s["located"] is True and s["host"] == "CORP-WS01" and s["first"] == "2031-03-04 10:16:00"
    # The same table written by a program is the run's own material.
    before = output_snapshot(case)
    prog = _call(l, "python3 make_table.py", "wrote analysis/own.csv")
    (case / "analysis" / "own.csv").write_text("TimeCreated,User\n2031-03-04 10:16:00,jane.doe\n")
    record_outputs(case, l.index().by_call_id[prog], before, output_snapshot(case))
    own_read = _call(l, "<py>:table_table_grep", json.dumps({"pattern": "jane.doe", "path": "analysis/own.csv",
                                                             "rows": [["2031-03-04 10:16:00", "jane.doe"]]}),
                     args={"pattern": "jane.doe", "path": "analysis/own.csv"})
    assert call_provenance(l.index().by_call_id[own_read], case)["class"] == "own"
    assert I.validate([{"type": "account", "value": "jane.doe", "side": "attacker"}],
                      call_ids=[own_read], case_dir=str(case))["kept"][0]["sightings"][0]["call"] == grep


def test_value_shown_only_by_an_uncited_call_is_kept_and_an_unplaced_sighting_is_unlocated(tmp_path, monkeypatch):
    case, l = _case_log(tmp_path, monkeypatch)
    uncited = _call(l, "<py>:table_table_query", json.dumps({"rows": [{"src": "203.0.113.7", "n": 3}]}),
                    args={"table_id": "t7", "sql": "select src, count(*) n from t group by src"})
    cited = _call(l, "<py>:reason_hypothesize", "the relay is 203.0.113.7")
    out = I.validate([{"type": "ip", "value": "203.0.113.7", "side": "attacker"}],
                     call_ids=[cited], case_dir=str(case), host="CORP-WS01")
    s = out["kept"][0]["sightings"]
    assert [x["call"] for x in s] == [uncited] and s[0]["cited"] is False
    assert s[0]["located"] is False and s[0]["host"] == ""
    assert out["kept"][0]["seen_basis"] == "none"


def test_sighting_time_and_host_come_from_the_row(tmp_path, monkeypatch):
    case, l = _case_log(tmp_path, monkeypatch)
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CORP-WS01", "path": "evidence/ws01", "kind": "folder"},
        {"label": "CORP-WS05", "path": "evidence/ws05", "kind": "folder"}], "hosts": ["CORP-WS01", "CORP-WS05"]}))
    _table(case, "analysis/timeline.csv")
    _table(case, "analysis/ws01/sec.csv")
    plaso = _call(l, "<py>:table_table_grep", json.dumps({
        "pattern": "203.0.113.7", "path": "analysis/timeline.csv",
        "columns": ["date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host", "short"],
        "rows": [["03/04/2031", "10:16:00", "UTC", "M...", "LOG", "Syslog", "x", "jane.doe", "corp-ws05", "connect 203.0.113.7"],
                 ["03/05/2031", "09:00:00", "UTC", "M...", "LOG", "Syslog", "x", "jane.doe", "corp-ws05", "connect 203.0.113.7"]]}),
        args={"pattern": "203.0.113.7", "path": "analysis/timeline.csv"})
    evtx = _call(l, "<py>:table_table_grep", json.dumps({
        "pattern": "203.0.113.7", "path": "analysis/ws01/sec.csv",
        "hits": [{"TimeCreated": "2031-03-06T08:00:00.1234567", "Computer": "ws01.corp.example", "EventId": 4624,
                  "RemoteHost": "203.0.113.7"}]}),
        args={"pattern": "203.0.113.7", "path": "analysis/ws01/sec.csv"})
    kept = I.validate([{"type": "ip", "value": "203.0.113.7", "side": "attacker", "first_seen": "2020-01-01 00:00"}],
                      call_ids=[plaso, evtx], case_dir=str(case))["kept"]
    by = {s["call"]: s for s in kept[0]["sightings"]}
    assert by[plaso]["host"] == "CORP-WS05" and by[plaso]["first"] == "2031-03-04 10:16:00" \
        and by[plaso]["last"] == "2031-03-05 09:00:00" and by[plaso]["rows"] == 2
    assert by[evtx]["host"] == "CORP-WS01" and by[evtx]["first"] == "2031-03-06 08:00:00"
    assert kept[0]["first_seen"] == "2031-03-04 10:16:00" and kept[0]["last_seen"] == "2031-03-06 08:00:00"
    assert kept[0]["seen_basis"] == "sightings"


def test_stated_time_kept_only_without_a_dated_sighting(tmp_path, monkeypatch):
    case, l = _case_log(tmp_path, monkeypatch)
    (case / "evidence" / "mem.raw").write_text("x")
    cid = _call(l, "strings evidence/mem.raw", "svc.exe 203.0.113.7 2031-02-04 10:41:00\nother line")
    # A moment to the minute dates its row: the cited call alone gives the sighting time.
    minute = _call(l, "strings evidence/mem.raw", "svc.exe 203.0.113.7 at 2031-02-04 10:41 connect\nsecond line")
    rows = [{"type": "ip", "value": "203.0.113.7", "side": "attacker", "first_seen": "2031-02-04 10:41:00"}]
    only = [e for e in l._entries if e.get("call_id") != cid]
    saved, l._entries[:] = list(l._entries), only
    kept = I.validate(rows, call_ids=[minute], case_dir=str(case))["kept"]
    assert kept[0]["seen_basis"] == "sightings" and kept[0]["first_seen"] == "2031-02-04 10:41:00"
    l._entries[:] = [e for e in saved if e.get("call_id") != minute]
    # The stamp shown in a form no row time reads: date and clock joined by a
    # slash, which the stated-stamp check accepts and the parser does not.
    undated = _call(l, "strings evidence/mem.raw", "svc.exe 203.0.113.7 at 2031-02-04/10:41 connect\nsecond line")
    rows = [{"type": "ip", "value": "203.0.113.7", "side": "attacker", "first_seen": "2031-02-04 10:41:00"}]
    kept = I.validate(rows, call_ids=[undated], case_dir=str(case))["kept"]
    assert kept[0]["seen_basis"] == "sightings"  # the uncited dated call dates the row too
    assert kept[0]["first_seen"] == "2031-02-04 10:41:00"
    l._entries[:] = [e for e in l._entries if e.get("call_id") != cid]
    kept = I.validate(rows, call_ids=[undated], case_dir=str(case))["kept"]
    assert kept[0]["seen_basis"] == "stated" and kept[0]["first_seen"] == "2031-02-04 10:41:00"
    kept = I.validate([{"type": "ip", "value": "203.0.113.7", "side": "attacker", "first_seen": "2031-09-09 09:09"}],
                      call_ids=[undated], case_dir=str(case))["kept"]
    assert "first_seen" not in kept[0] and kept[0]["seen_basis"] == "none"


def test_sightings_are_bounded_and_cited_come_first(tmp_path, monkeypatch):
    case, l = _case_log(tmp_path, monkeypatch)
    ids = [_call(l, f"strings evidence/f{i}.bin", f"row {i} 203.0.113.7 2031-03-0{i % 9 + 1} 10:00:00") for i in range(12)]
    found = I.sightings("ip", "203.0.113.7", [ids[5]], case_dir=str(case), limit=4)
    assert len(found) == 4 and found[0]["call"] == ids[5] and found[0]["cited"] is True
    assert all(s["cited"] is False for s in found[1:])


def test_echo_free_requires_sightings(monkeypatch):
    monkeypatch.setenv("ATLAS_IOC_SIGHTINGS", "0")
    monkeypatch.setenv("ATLAS_IOC_ECHO_FREE", "1")
    assert I._sightings_on() is True
    monkeypatch.setenv("ATLAS_IOC_ECHO_FREE", "0")
    assert I._sightings_on() is False
    monkeypatch.setenv("ATLAS_IOC_SIGHTINGS", "1")
    assert I._sightings_on() is True


def test_sightings_off_restores_the_cited_only_check(tmp_path, monkeypatch):
    case, l = _case_log(tmp_path, monkeypatch)
    seen = _call(l, "<py>:table_table_query", "4624 logon from 198.51.100.7")
    monkeypatch.setenv("ATLAS_IOC_SIGHTINGS", "0")
    monkeypatch.setenv("ATLAS_IOC_ECHO_FREE", "0")
    row = {"type": "ip", "value": "198.51.100.7", "side": "attacker"}
    out = I.validate([row], call_ids=[], case_dir=str(case))
    assert out["kept"] == [] and "no evidence call" in out["dropped"][0]["reason"]
    kept = I.validate([row], call_ids=[seen], case_dir=str(case))["kept"]
    assert kept and "sightings" not in kept[0]


def test_an_index_hit_takes_its_source_calls_provenance(tmp_path, monkeypatch):
    from core import evidence_index as ei
    case, l = _case_log(tmp_path, monkeypatch)
    filler = "filler line about nothing in particular\n" * 20
    prog = _call(l, "python3 -c 'print(\"203.0.113.7 is the relay\")'", "203.0.113.7 is the relay")
    ei.index_output(call_id=prog, tool="python3", text="203.0.113.7 is the relay\n" + filler)
    assert I.sightings("ip", "203.0.113.7", [], case_dir=str(case)) == []
    (case / "evidence" / "c.pcap").write_text("x")
    seen = _call(l, "tshark -r evidence/c.pcap", "")
    ei.index_output(call_id=seen, tool="tshark", text="2031-03-04 10:16:00 10.0.0.5 -> 203.0.113.7:443 SYN\n" + filler)
    found = I.sightings("ip", "203.0.113.7", [], case_dir=str(case))
    assert [s["call"] for s in found] == [seen] and found[0]["located"] is True


def test_refresh_backfills_legacy_rows(tmp_path, monkeypatch):
    from core.claim_graph import add_claim, load_graph
    case, l = _case_log(tmp_path, monkeypatch)
    seen = _call(l, "<py>:table_table_query", json.dumps({"rows": [{"ts": "2031-03-04 10:16:00", "dst": "203.0.113.7"}]}),
                 args={"table_id": "t7", "sql": "select ts, dst from t"})
    r = add_claim(str(case), "The workstation reached 203.0.113.7 over port 443 on 2031-03-04.", host="CORP-WS01",
                  confidence="LIKELY", evidence=[{"call_id": seen}], enforce_validation=False)
    cid = r["node_id"]
    graph = load_graph(str(case))
    graph["nodes"][cid]["input_call_ids"] = [seen]
    graph["nodes"][cid]["indicators"] = [{"type": "ip", "value": "203.0.113.7", "side": "attacker"},
                                         {"type": "ip", "value": "203.0.113.9", "side": "attacker"}]
    from core.claim_graph import save_graph
    save_graph(str(case), graph)
    assert I.refresh_sightings(str(case), per_turn=1) == 1
    rows = {r["value"]: r for r in load_graph(str(case))["nodes"][cid]["indicators"]}
    assert rows["203.0.113.7"]["seen_basis"] == "sightings" and rows["203.0.113.7"]["sightings"][0]["call"] == seen
    assert "sightings" not in rows["203.0.113.9"]
    assert I.refresh_sightings(str(case), per_turn=None) == 1
    rows = {r["value"]: r for r in load_graph(str(case))["nodes"][cid]["indicators"]}
    assert rows["203.0.113.9"]["sightings"] == [] and rows["203.0.113.9"]["seen_basis"] == "none"
    assert I.refresh_sightings(str(case)) == 0


def test_seen_text_names_call_host_span_and_citation():
    row = {"sightings": [
        {"call": 412, "host": "CORP-WS05", "cited": True, "located": True,
         "first": "2031-03-01 08:12:00", "last": "2031-03-09 17:40:00", "rows": 37},
        {"call": 518, "host": "CORP-WS01", "cited": False, "located": True, "first": "", "last": "", "rows": 1},
        {"call": 77, "host": "", "cited": False, "located": False, "first": "", "last": "", "rows": 2}]}
    assert I.seen_text(row) == ("call 412 on CORP-WS05, 2031-03-01 08:12 to 2031-03-09 17:40 (37 rows); "
                                "call 518 on CORP-WS01 (1 row) (not cited by this finding); "
                                "call 77 (2 rows) (not cited by this finding) (location unresolved)")


def test_an_attacker_row_on_an_own_address_is_re_sided_refused_or_kept_and_stays_listed(tmp_path, monkeypatch):
    """Lateral movement: the analyst types the address of an own host,
    named by the short name it calls itself, as attacker-side. A refused row
    carries the own side; a kept row is an affected asset with scope, listed
    and never dropped."""
    from core.ioc_catalog import build_catalog
    case, l = _case_log(tmp_path, monkeypatch)
    (case / "CASE.md").write_text("**Case ID:** CASE-A\n**System owner:** victim\n", encoding="utf-8")
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CASE-WS01", "path": "evidence/ws01.E01", "kind": "disk"}], "hosts": ["CASE-WS01"]}))
    statement = "WS01 (203.0.113.5) opened an SMB session to the file server."
    (case / ".atlas" / "claim_graph.json").write_text(json.dumps({"nodes": {"C0001": {
        "id": "C0001", "kind": "claim", "status": "new", "confidence": "LIKELY", "statement": statement}}}))
    row = {"type": "ip", "value": "203.0.113.5", "side": "attacker"}
    refused = I.validate([dict(row)], call_ids=[], case_dir=str(case))["dropped"]
    assert refused[0]["refusal"] == "presence" and refused[0]["side"] == "victim"
    _table(case, "analysis/smb.csv")
    cid = _call(l, "<py>:table_table_grep", "2031-03-04 10:16:00,203.0.113.5,445",
                args={"path": "analysis/smb.csv", "pattern": "445"})
    kept = I.validate([dict(row)], call_ids=[cid], case_dir=str(case))["kept"]
    assert kept[0]["side"] == "victim" and kept[0]["compromised"] is True
    graph = json.loads((case / ".atlas" / "claim_graph.json").read_text())
    graph["nodes"]["C0001"]["indicators"] = kept
    (case / ".atlas" / "claim_graph.json").write_text(json.dumps(graph))
    cat = build_catalog(case)
    listed = [i for i in cat["affected_assets"] if i["value"] == "203.0.113.5"]
    assert listed and "scope" in listed[0]["use"]


# ── a result's own fields beside its row lists ───────────────────────────

_OWN_SHA = "5f" * 32
_PROSE_SHA = "a0" * 32


def _hash_result(note="same content as analysis/carved/jpg/00000101.jpg: one file under several paths"):
    return json.dumps({"success": True, "file": "analysis/export/report.pdf", "size_bytes": 4096,
                       "md5": "0f" * 16, "sha256": _OWN_SHA, "cache_hit": False,
                       "identical_to": [{"path": "analysis/carved/jpg/00000101.jpg", "source": "analysis"}],
                       "note": note})


def test_a_hash_result_keeps_its_own_fields_as_a_row_after_its_related_records():
    e = _entry(_hash_result(), args={"file": "analysis/export/report.pdf"}, cmd="<py>:hash_hash_file")
    rows = I.printed_rows(e)
    assert rows[0] == '{"path": "analysis/carved/jpg/00000101.jpg", "source": "analysis"}'
    assert len(rows) == 2 and _OWN_SHA in rows[1] and "4096" in rows[1]
    # the request (the file asked for), the flag and the tool's prose are no field of it
    assert "report.pdf" not in rows[1] and "cache_hit" not in rows[1] and "several paths" not in rows[1]


def test_a_result_sets_header_is_no_row_and_a_records_own_fields_are_pinned():
    """A listing under a row key is a result set: its path, host, flags,
    counts and notes are its header, no row. A record beside the records
    it lists keeps its scalar fields as a row after them: a path and a host
    it reports do, its counts, flags, the request and its prose do not."""
    listing = _entry(json.dumps({"success": True, "glob": "*", "folder": "analysis/export", "host": "CORP-WS01",
                                 "truncated": False, "elapsed_ms": 12, "count": 2,
                                 "note": "Open one of these names with the matching parser, do not guess MFT.csv",
                                 "entries": [{"name": "a.txt"}, {"name": "b.txt"}]}),
                     args={"glob": "*"}, cmd="<py>:misc_list_evidence_dir")
    assert I.printed_rows(listing) == ['{"name": "a.txt"}', '{"name": "b.txt"}']
    record = _entry(json.dumps({"success": True, "glob": "*", "folder": "analysis/export", "host": "CORP-WS01",
                                "truncated": False, "elapsed_ms": 12, "count": 2,
                                "note": "Open one of these names with the matching parser, do not guess MFT.csv",
                                "related": [{"name": "a.txt"}, {"name": "b.txt"}]}),
                    args={"glob": "*"}, cmd="<py>:misc_example_record")
    rows = I.printed_rows(record)
    assert rows[:2] == ['{"name": "a.txt"}', '{"name": "b.txt"}']
    assert json.loads(rows[2]) == {"folder": "analysis/export", "host": "corp-ws01", "elapsed_ms": 12}
    assert not any("mft.csv" in r for r in rows)


def test_a_hash_in_a_hash_result_is_a_sighting_and_one_only_in_its_prose_is_not(tmp_path, monkeypatch):
    case, l = _case_log(tmp_path, monkeypatch)
    _table(case, "analysis/export/report.pdf")
    cid = _call(l, "<py>:hash_hash_file", _hash_result(note=f"identical to a file whose sha256 is {_PROSE_SHA}"),
                args={"file": "analysis/export/report.pdf"})
    kept = I.validate([{"type": "hash", "value": _OWN_SHA, "side": "subject"}], call_ids=[cid], case_dir=str(case))["kept"]
    assert kept and kept[0]["sightings"][0]["call"] == cid
    out = I.validate([{"type": "hash", "value": _PROSE_SHA, "side": "subject"}], call_ids=[cid], case_dir=str(case))
    assert out["kept"] == [] and out["dropped"][0]["refusal"] == "presence"


def test_a_hash_written_with_its_algorithm_is_that_hash_when_the_name_fits_its_length():
    for raw in (f"sha256:{_OWN_SHA}", f"SHA-256: {_OWN_SHA.upper()}", f"sha256={_OWN_SHA}"):
        assert I.normalize_row({"type": "hash", "value": raw, "side": "subject"})[0]["value"] == _OWN_SHA, raw
    assert I.normalize_row({"type": "hash", "value": "md5:" + "0f" * 16, "side": "subject"})[0]["value"] == "0f" * 16
    assert I.normalize_row({"type": "hash", "value": "sha1:" + "ab" * 20, "side": "subject"})[0]["value"] == "ab" * 20
    # a name that does not fit the digest's length is no hash of that name
    row, why = I.normalize_row({"type": "hash", "value": "md5:" + _OWN_SHA, "side": "subject"})
    assert row is None and "not an MD5, SHA-1 or SHA-256 hash" in why


def test_a_records_count_shaped_fields_are_no_field_of_its_row():
    """Counts by the lexical shape of their key (finding_count, shown,
    num_hits, total_engines) are tallies of the result, not record fields."""
    e = _entry(json.dumps({"success": True, "case": "CASE-A", "finding_count": 5, "shown": 2, "num_hits": 3,
                           "total_engines": 70, "findings": [{"id": "F1"}, {"id": "F2"}]}),
               args={}, cmd="<py>:misc_example_findings")
    rows = I.printed_rows(e)
    assert rows[:2] == ['{"id": "f1"}', '{"id": "f2"}'] and json.loads(rows[2]) == {"case": "case-a"}


# ── a field the call was given, in a record that says more ──────────────

_R8_SHA = "7e" * 32


def test_a_result_keeps_the_subject_it_was_asked_about():
    """A hash record keeps the file hashed and an archive record the
    password it opened with: the rest of the record is a result."""
    hashed = _entry(json.dumps({"success": True, "file": "analysis/export/report.pdf", "size_bytes": 4096,
                                "sha256": _R8_SHA}), args={"file_path": "analysis/export/report.pdf"},
                    cmd="<py>:hash_hash_file")
    assert "analysis/export/report.pdf" in I.printed_text(hashed)
    opened = _entry(json.dumps({"success": True, "output_dir": "analysis/out", "member_count": 1,
                                "uncompressed_bytes": 48512, "password_used": "tide2031"}),
                    args={"path": "analysis/a.zip", "output_dir": "analysis/out", "password": ["sand", "tide2031"]},
                    cmd="<py>:archive_zip_extract")
    assert "tide2031" in I.printed_text(opened)


def test_a_record_that_only_restates_the_request_loses_it():
    """Flags, counts, times, a list of names, a failure or a message that
    restates the request say nothing more: the asked-for value goes."""
    cases = [
        ({"account": "jane.doe", "exists": False}, {"user": "jane.doe"}, "jane.doe"),
        ({"account": "jane.doe", "found": False, "elapsed_ms": 12, "attempts": 3}, {"user": "jane.doe"}, "jane.doe"),
        ({"account": "jane.doe", "found": False, "near": ["jane.do", "jane.d0e"]}, {"user": "jane.doe"}, "jane.doe"),
        ({"account": "jane.doe", "success": False, "sha256": _R8_SHA}, {"user": "jane.doe"}, "jane.doe"),
        ({"target": "C:/cases/x/report.pdf", "error": "File not found: C:/cases/x/report.pdf"},
         {"file_path": "C:/cases/x/report.pdf"}, "c:/cases/x/report.pdf"),
        ({"password_used": "tide2031", "member_count": 1}, {"password": ["sand", "tide2031"]}, "tide2031"),
    ]
    for record, args, value in cases:
        text = I.printed_text(_entry(json.dumps(record), args=args))
        echoed = [k for k, v in record.items() if isinstance(v, str) and v.casefold() == value]
        assert echoed and not any(f'"{k.casefold()}"' in text for k in echoed), record


def test_a_window_of_a_flat_view_entry_is_read_as_it_stands(tmp_path):
    """windowed: the piece the caller holds is read, not the whole flat
    output the view split; without it the flat rows stand."""
    spill = tmp_path / "flat.json"
    spill.write_text(json.dumps([{"name": "a.exe"}, {"name": "b.exe"}, {"name": "c.exe"}]))
    e = _entry("", cmd="<py>:vol_pslist")
    e.update(stdout_file=str(spill), rows_split="flat")
    window = '[{"name": "a.exe"}]'
    assert "c.exe" in I.rows_text(e, text=window)
    assert I.rows_text(e, text=window, windowed=True) == '{"name": "a.exe"}'



def test_with_no_owner_named_an_attacker_row_on_a_listed_asset_takes_no_side(tmp_path, monkeypatch):
    """The neutral frame: the asset the brief lists is nobody's side here,
    so a stated attacker on it is undetermined, with the reason."""
    case, l = _case_log(tmp_path, monkeypatch)
    (case / ".atlas" / "evidence_links.json").write_text(json.dumps({"entries": [
        {"label": "CASE-WS01", "path": "evidence/ws01.E01", "kind": "disk"}], "hosts": ["CASE-WS01"]}))
    _table(case, "analysis/smb.csv")
    cid = _call(l, "<py>:table_table_grep", "2031-03-04 10:16:00,203.0.113.5,445",
                args={"path": "analysis/smb.csv", "pattern": "445"})
    row = {"type": "ip", "value": "203.0.113.5", "side": "attacker"}
    (case / ".atlas" / "claim_graph.json").write_text(json.dumps({"nodes": {"C0001": {
        "id": "C0001", "kind": "claim", "status": "new", "confidence": "LIKELY",
        "statement": "WS01 (203.0.113.5) opened an SMB session to the file server."}}}))
    assert I.frame_for(case) == "neutral"
    kept = I.validate([dict(row)], call_ids=[cid], case_dir=str(case), frame="neutral")["kept"]
    assert kept[0]["side"] == "undetermined" and not kept[0].get("compromised")
    assert "no owner is named" in kept[0]["note"]
