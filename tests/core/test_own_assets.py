"""The own-asset set is built from sources that state identity, never from
a relation: appositions bind, prose across a clause or a comma does not,
and a value the clause assigns to the other side never joins."""
import json

import pytest

from core import own_assets as oa

HOSTS = ["HOST-A", "HOST-B"]

_BINDS = [
    ("HOST-A (192.0.2.10) and HOST-B (192.0.2.11) were in scope.",
     [("HOST-A", "192.0.2.10"), ("HOST-B", "192.0.2.11")]),
    ("192.0.2.11 (HOST-B) opened sessions to 198.51.100.7.", [("HOST-B", "192.0.2.11")]),
    ("HOST-A at 192.0.2.10 is the file server.", [("HOST-A", "192.0.2.10")]),
    ("The IP of HOST-A is 192.0.2.10.", [("HOST-A", "192.0.2.10")]),
    ("HOST-A hat die Adresse 192.0.2.10.", [("HOST-A", "192.0.2.10")]),
    ("HOST-A (IP 192.0.2.10) holds the share.", [("HOST-A", "192.0.2.10")]),
    ("HOST-A's IP address is 192.0.2.10.", [("HOST-A", "192.0.2.10")]),
    # a clause end between the two halves binds nothing
    ("The relay is 198.51.100.7. HOST-B (192.0.2.11) talks to it.", [("HOST-B", "192.0.2.11")]),
    ("Source 198.51.100.7; HOST-A was reached first.", []),
    # an enumeration is not an apposition
    ("In scope: HOST-A, HOST-B, 198.51.100.7, updater.exe.", []),
    ("HOST-A, 192.0.2.10", []),
    # a provenance parenthetical names where a value was seen, not whose it is
    ("Sessions from external IP 198.51.100.7 (HOST-A event 4625) were logged.", []),
    ("Logons from remote address 198.51.100.7 (HOST-A).", []),
    ("Source IP 198.51.100.7 (HOST-A event 4625) failed 300 times.", []),
    # a time is not an address
    ("HOST-A at 10:42 contacted 198.51.100.7.", []),
]


@pytest.mark.parametrize("statement, want", _BINDS)
def test_only_closed_appositions_bind(statement, want):
    assert oa.bind_appositions(statement, HOSTS) == sorted(want), statement


def _case(tmp_path, brief="", nodes=(), links=None):
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True)
    (d / "CASE.md").write_text(brief or "# Case: X\n\n**Case ID:** X\n", encoding="utf-8")
    graph = {"nodes": {}, "edges": []}
    for i, n in enumerate(nodes, start=1):
        graph["nodes"][f"C{i:04d}"] = {"id": f"C{i:04d}", "kind": "claim", "status": "new",
                                       "confidence": "LIKELY", **n}
    (d / ".atlas" / "claim_graph.json").write_text(json.dumps(graph), encoding="utf-8")
    if links is not None:
        (d / ".atlas" / "evidence_links.json").write_text(json.dumps(links), encoding="utf-8")
    return d


def test_claim_hosts_and_their_appositions_join_the_set(tmp_path):
    d = _case(tmp_path, nodes=[
        {"host": "HOST-A", "statement": "HOST-A (192.0.2.10) served the share."},
        {"host": "HOST-B", "statement": "HOST-B (192.0.2.11) opened sessions to 198.51.100.7, "
                                        "the remote address."},
    ])
    a = oa.own_assets(d)
    assert a["hosts"] == ["HOST-A", "HOST-B"]
    assert oa.lookup(a, "192.0.2.10")["host"] == "HOST-A"
    assert oa.lookup(a, "192.0.2.11")["host"] == "HOST-B"
    assert oa.lookup(a, "198.51.100.7") is None
    assert "claim_apposition" in oa.lookup(a, "192.0.2.10", "ip")["sources"]


def test_a_directory_name_is_an_own_domain_and_matches_as_host_or_domain(tmp_path):
    d = _case(tmp_path, nodes=[{"host": "HOST-A", "statement":
                                "HOST-A joined the domain CORP.LOCAL as CORP.LOCAL\\svc-backup."}])
    a = oa.own_assets(d)
    assert oa.lookup(a, "corp.local")["type"] == "domain"
    assert oa.lookup(a, "CORP.LOCAL", "domain")
    assert oa.lookup(a, "corp.local", "host")


def test_brief_tables_are_read_under_estate_sections_only(tmp_path):
    brief = (
        "# Case: X\n\n**Case ID:** X\n\n"
        "## Target Systems (from the request)\n\n"
        "| | Type | OS | Identifier |\n|---|---|---|---|\n"
        "| **PC** | workstation | Windows 7 | IP `192.0.2.20` |\n"
        "| **RM#1** | USB stick | exFAT | Serial `4C530012450531101593` |\n"
        "| **RM#2** | USB stick | FAT32 | imaged with tool 3.3.0.5 |\n\n"
        "## What you already know\n\n"
        "| Side | Address |\n|---|---|\n| other | IP 198.51.100.7 |\n"
    )
    a = oa.own_assets(_case(tmp_path, brief=brief))
    assert oa.lookup(a, "192.0.2.20")["host"] == "PC"
    assert oa.lookup(a, "4c530012450531101593", "serial")["host"] == "RM#1"
    assert oa.lookup(a, "3.3.0.5") is None
    assert oa.lookup(a, "198.51.100.7") is None
    assert "other" not in a["hosts"]


def test_a_header_column_binds_bare_addresses(tmp_path):
    brief = ("# Case: X\n\n## Hosts\n\n| Host | IP address | Role |\n|---|---|---|\n"
             "| SRV-1 | 192.0.2.30 | mail |\n")
    a = oa.own_assets(_case(tmp_path, brief=brief))
    assert oa.lookup(a, "192.0.2.30")["host"] == "SRV-1"


def test_evidence_links_give_hosts_aliases_and_principals(tmp_path):
    links = {"entries": [
        {"label": "FS01", "kind": "disk", "path": "evidence/fs01.E01"},
        {"label": "fileserver01", "kind": "alias", "alias_of": "FS01"},
        {"label": "j.doe", "kind": "principal"},
        {"label": "GP/MDE", "kind": "tabular", "path": "evidence/"},
    ]}
    a = oa.own_assets(_case(tmp_path, links=links))
    assert set(a["hosts"]) == {"FS01", "fileserver01"}
    assert oa.lookup(a, "CORP\\j.doe", "account")["type"] == "account"
    assert oa.lookup(a, "GP/MDE") is None


def test_a_baseline_profile_is_read_when_present(tmp_path):
    d = _case(tmp_path)
    folder = d / "analysis" / "baseline"
    folder.mkdir(parents=True)
    (folder / "vol1.json").write_text(json.dumps({
        "identity": {"computer_name": "WS-7", "domain": "corp.local"},
        "interfaces": [{"ip": "192.0.2.40"}], "accounts": [{"name": "alice"}],
        "usb": [{"serial": "AA11BB22CC33"}]}), encoding="utf-8")
    a = oa.own_assets(d)
    assert oa.lookup(a, "192.0.2.40")["host"] == "WS-7"
    assert oa.lookup(a, "alice", "account") and oa.lookup(a, "aa11bb22cc33", "serial")
    assert oa.lookup(a, "CORP.LOCAL")["sources"] == ["baseline"]


def test_a_missing_case_yields_an_empty_set(tmp_path):
    a = oa.own_assets(tmp_path / "nowhere")
    assert a == {"values": {}, "hosts": []}


def test_a_baseline_profile_yields_its_registry_named_addresses(tmp_path):
    d = _case(tmp_path)
    folder = d / "analysis" / "baseline"
    folder.mkdir(parents=True)
    (folder / "ws01.json").write_text(json.dumps({
        "installation": "ws01", "identity": {"computer_name": "WS01"},
        "interfaces": [{"guid": "{1}", "IPAddress": ["192.0.2.10"], "DhcpIPAddress": "0.0.0.0"},
                       {"guid": "{2}", "DhcpIPAddress": "198.51.100.7"}]}), encoding="utf-8")
    a = oa.own_assets(d)
    assert oa.lookup(a, "192.0.2.10", "ip")["host"] == "WS01"
    assert oa.lookup(a, "198.51.100.7", "ip") and not oa.lookup(a, "0.0.0.0", "ip")
