"""Typed indicators: rows the analyst states are checked against the cited
outputs, sided, given a use, and turned into the deliverable; prose rows
stay under review; the owner's own assets never become block items."""
import csv
import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from core import indicators as I
from core.ioc_catalog import build_catalog, render_csv, render_markdown, write_indicator_files


# ── shapes ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("row, value", [
    ({"type": "ip", "value": "192.0.2.10:443", "side": "attacker"}, "192.0.2.10"),
    ({"type": "ipv4", "value": "192.0.2.10", "side": "adversary"}, "192.0.2.10"),
    ({"type": "mac", "value": "AA-BB-CC-DD-EE-FF", "side": "victim"}, "aa:bb:cc:dd:ee:ff"),
    ({"type": "sha256", "value": "A" * 64, "side": "attacker"}, "a" * 64),
    ({"type": "url", "value": "hxxp://bad[.]example[.]net/x", "side": "attacker"}, "http://bad.example.net/x"),
    ({"type": "domain", "value": "Relay.Example.NET.", "side": "attacker"}, "relay.example.net"),
    ({"type": "serial", "value": "4c530012450531101593", "side": "subject"}, "4C530012450531101593"),
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
    assert "198.51.100.8" in dropped and "500,000" in dropped["198.51.100.8"] and "8,000,000" in dropped["198.51.100.8"]
    assert ("e" * 40) in dropped


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
        assert I.validate([row], call_ids=[lookup], case_dir=None)["kept"] == []
        assert I.validate([row], call_ids=[lookup, seen], case_dir=None)["kept"]


def test_a_row_without_a_cited_call_is_dropped(tmp_path):
    out = I.validate([{"type": "ip", "value": "198.51.100.7", "side": "attacker"}], call_ids=[], case_dir=None)
    assert out["kept"] == [] and "no evidence call" in out["dropped"][0]["reason"]


def _case(tmp_path, brief="", nodes=()):
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True, exist_ok=True)
    (d / "CASE.md").write_text(brief or "# Case: X\n\n**Case ID:** X\n", encoding="utf-8")
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
        {"host": "LAPTOP", "statement": "The laptop's user j.doe stored a key in rootkey.csv.",
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
                  '{"query": "198.51.100.5", "results": [{"snippet": "dst 198.51.100.5:443"}], "result_count": 1}')
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
    assert I.frame_for(_brief_case(tmp_path / "d", meta)) == "incident"
    assert I.frame_for(_brief_case(tmp_path / "e", "# Case\n\nThe lure read:\n\nSubject: Payment advice\n")) == "incident"


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
