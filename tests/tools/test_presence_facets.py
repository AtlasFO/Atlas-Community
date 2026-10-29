"""What a cited row shows, facet by facet (tools/_gates/citation_support):
a time bound to the statement's name when it names no entity, a block
record's time on the line after its name, the host label only where the
case holds more than one host, a registry key that is no account, the
not_shown line naming only what no row holds, an address with its port,
and mail dates written with a month name. Each facet has the binding it
must still refuse. Invented fixtures: CORP-WS01, CORP\\jane.doe,
203.0.113.x, example.com, dates in 2031."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.entities import extract
from core.indicators import _found
from tools._gates import citation_support as cs

HOST = ["CORP-WS01"]


def _call(cid, lines, path="evidence/ws01/out.txt"):
    return {"type": "tool_call", "call_id": cid, "cmd": f"cat {path}", "success": True,
            "stdout_excerpt": "\n".join(lines)}


def _unshown(statement, calls, hosts=HOST):
    return cs.shown_values(statement, calls, hosts=hosts)["unshown"]


# a statement without an entity binds its time to a row with its name.

def test_a_time_beside_the_statements_name_is_shown():
    call = _call(1, ["adapter WL999-A key written 2031-03-04 10:31:44Z"])
    assert _unshown("Adapter WL999-A key was written at 2031-03-04 10:31", [call]) == []


def test_a_time_in_the_row_of_another_record_is_not_shown():
    call = _call(2, ["adapter WL777-B key written 2031-03-04 10:31:44Z",
                     "adapter WL999-A key written 2031-03-04 11:02:10Z"])
    assert _unshown("Adapter WL999-A key was written at 2031-03-04 10:31", [call]) == ["ts:2031-03-04 10:31"]


def test_a_statement_with_no_name_shows_a_time_its_cited_rows_hold():
    call = _call(3, ["system key written 2031-03-04 10:31:44Z"])
    assert _unshown("The system key was last written at 2031-03-04 10:31", [call]) == []
    assert _unshown("The system key was last written at 2031-03-04 12:00", [call]) == ["ts:2031-03-04 12:00"]


# a block record's time stands on the line after its name.

def test_the_time_on_the_line_after_the_name_is_shown():
    call = _call(4, ["UserAssist entry: dropper.exe", "  LastWrite 2031-03-04 09:12:44Z"])
    assert _unshown("dropper.exe ran at 2031-03-04 09:12", [call]) == []


def test_the_next_records_time_and_the_previous_line_are_never_borrowed():
    call = _call(5, ["entry: alpha.exe", "  2031-03-04 09:00:00Z", "entry: beta.exe", "  2031-03-04 10:00:00Z"])
    assert _unshown("alpha.exe ran at 2031-03-04 10:00", [call]) == ["ts:2031-03-04 10:00"]
    assert _unshown("beta.exe ran at 2031-03-04 09:00", [call]) == ["ts:2031-03-04 09:00"]


def test_a_row_with_its_own_time_borrows_none():
    call = _call(6, ["entry: alpha.exe 2031-03-04 08:00:00Z", "  2031-03-04 09:00:00Z"])
    assert _unshown("alpha.exe ran at 2031-03-04 09:00", [call]) == ["ts:2031-03-04 09:00"]


def test_the_row_test_borrows_the_next_line_the_same_way():
    stmt = "dropper.exe ran at 2031-03-04 09:12"
    block = _call(7, ["UserAssist entry: dropper.exe", "  LastWrite 2031-03-04 09:12:44Z"])
    other = _call(8, ["entry: dropper.exe", "entry: other.exe 2031-03-04 09:12:44Z"])
    assert cs.call_shows(cs.claim_terms(stmt, HOST), block) is not None
    assert cs.call_shows(cs.claim_terms(stmt, HOST), other) is not None   # known limit: the next line's time
    alone = _call(9, ["entry: dropper.exe 2031-03-04 08:00:00Z", "  2031-03-04 09:12:44Z"])
    assert cs.call_shows(cs.claim_terms(stmt, HOST), alone) is None


# the fallback's host label binds only where the case holds several hosts.

def _ledger(tmp_path, containers):
    case = tmp_path / "CASE-A"
    (case / ".atlas").mkdir(parents=True)
    units = {f"u{i}": {"id": f"u{i}", "path": f"evidence/img{i}.E01", "kind": "container"} for i in range(containers)}
    units["d0"] = {"id": "d0", "path": "evidence/notes.txt", "kind": "derived"}
    (case / ".atlas" / "coverage_ledger.json").write_text(json.dumps({"case": "CASE-A", "units": units}))
    return str(case)


@pytest.mark.parametrize("containers,cites", [(1, True), (2, False), (0, False)])
def test_without_links_the_ledger_says_whether_the_case_holds_one_host(tmp_path, monkeypatch, containers, cites):
    case = _ledger(tmp_path, containers)
    monkeypatch.setattr(cs, "_active_case_dir", lambda: case)
    stmt = "The task Updater-Sync ran on CORP-WS01 at 2031-03-04 09:12"
    terms = cs.claim_terms(stmt, [], host="CORP-WS01")
    row = "2031-03-04 09:12:03 Task Scheduler started Updater-Sync"
    assert (cs.row_shows(terms, row) is not None) is cites


def test_with_two_linked_hosts_the_label_is_still_required():
    stmt = "The task Updater-Sync ran on CORP-WS01 at 2031-03-04 09:12"
    row = "2031-03-04 09:12:03 Task Scheduler started Updater-Sync"
    assert cs.row_shows(cs.claim_terms(stmt, ["CORP-WS01"]), row) is not None
    assert cs.row_shows(cs.claim_terms(stmt, ["CORP-WS01", "CORP-WS02"]), row) is None


# a registry key is no account.

def test_a_key_inside_a_registry_path_and_a_root_key_are_no_account():
    assert not [e for e in extract("Found key ControlSet001\\Control\\Windows and value ShutdownTime")
                if e.startswith("account:")]
    assert not [e for e in extract("HKLM\\Software and HKEY_LOCAL_MACHINE\\System") if e.startswith("account:")]
    assert "account:corp/jane.doe" in extract("logon by CORP\\jane.doe from 203.0.113.9")


# the not_shown line names what no row of the trace holds.

def test_the_line_names_only_the_value_no_row_holds():
    calls = [_call(10, ["2031-03-04 09:12:44 connect 203.0.113.9:443"])]
    unseen, every = cs.unseen_terms("Beacon to 203.0.113.9 at 2031-03-04 11:00", calls, hosts=HOST)
    assert unseen == ["2031-03-04 11:00"] and every == ["203.0.113.9", "2031-03-04 11:00"]


def test_values_each_shown_apart_are_named_together():
    from tools.misc import _not_shown_line
    calls = [_call(11, ["connect 203.0.113.9:443"]), _call(12, ["2031-03-04 11:00:02 logon jane.doe"])]
    log = SimpleNamespace(_entries=calls, case_dir=lambda: None)
    line = _not_shown_line(log, "Beacon to 203.0.113.9 at 2031-03-04 11:00")
    assert line.startswith("no row in the trace shows 203.0.113.9, 2031-03-04 11:00 together")
    gone = _not_shown_line(log, "Beacon to 203.0.113.77 at 2031-03-04 11:00")
    assert gone.startswith("no call in the trace shows 203.0.113.77;")


# an address with its port, as tcpdump prints it.

def test_an_address_with_its_port_is_the_address_and_a_longer_run_is_not():
    assert _found("ip", "203.0.113.5", "IP 203.0.113.5.80 > 203.0.113.9.1055: Flags [P.]")
    assert not _found("ip", "1.3.6.1", "oid 1.3.6.1.4.1.311.2.1.15")
    assert not _found("ip", "203.0.113.5", "203.0.113.55 replied")
    assert not _found("ip", "203.0.113.5", "version 203.0.113.5.80.12")


# mail dates written with a month name.

def test_mail_dates_are_read_as_their_minute():
    times = cs._row_times("from jane.doe@example.com tue mar  4 09:12:44 2031")
    assert "2031-03-04 09:12" in times
    assert cs._row_times("Date: Tue, 04 Mar 2031 09:12:44 -0400") == {"2031-03-04 09:12", "2031-03-04 13:12"}
    assert "2031-03-04 09:13" not in cs._row_times("Date: Tue, 04 Mar 2031 09:12:44 +0000")
    assert cs._row_times("issued 04 Mar 2031, no clock") == set()
