"""The undetermined side, values in recorded steps need a
sighting (sharing the refused-steps record with the marked-value
check), and the PRIOR KNOWLEDGE sentence. Invented fixtures only
(CORP-WS01, jane.doe, 203.0.113.x, example.com)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from core import indicators as I
from core.claim_graph import add_node, add_recommendation, load_graph, merge_indicator_rows


def test_undetermined_is_a_side_with_no_use(monkeypatch):
    row, why = I.normalize_row({"type": "domain", "value": "update-check.example.com", "side": "unknown"})
    assert why == "" and row["side"] == "undetermined"
    assert I.use_for("incident", "undetermined", "domain", "update-check.example.com") == ["review"]
    assert I.use_for("subject", "undetermined", "email", "x@example.com") == ["review"]
    monkeypatch.setenv("ATLAS_IOC_ROLES", "0")
    assert I.normalize_row({"type": "domain", "value": "a.example.com", "side": "undetermined"})[0] is None


def test_a_stated_side_replaces_undetermined_and_otherwise_the_first_stands():
    node = {"indicators": [{"type": "ip", "value": "203.0.113.9", "side": "undetermined"}]}
    merge_indicator_rows(node, [{"type": "ip", "value": "203.0.113.9", "side": "attacker"}])
    assert node["indicators"][0]["side"] == "attacker" and node["indicators"][0]["note"] == "side stated later"
    merge_indicator_rows(node, [{"type": "ip", "value": "203.0.113.9", "side": "victim"}])
    assert node["indicators"][0]["side"] == "attacker"


def test_the_catalogue_role_and_its_printed_label():
    from core import ioc_catalog as C
    assert C._typed_role("undetermined", "domain", "a.example.com", False) == C.UNDETERMINED
    assert C._role_cell({"role": C.UNDETERMINED}) == "undetermined"
    assert C._role_cell({"role": C.ATTACKER_INFRA}) == "attacker infrastructure"
    assert C._role_cell({"role": C.ATTACKER_FILE}) == "attacker tool or file"
    assert C._role_cell({"role": C.AFFECTED_ASSET}) == "victim asset"
    assert C._role_cell({"role": C.THIRD_PARTY}) == "third-party service"


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "case"
    (d / ".atlas").mkdir(parents=True)
    c = add_node(d, kind="claim", statement="CORP-WS01 beaconed to update-check.example.com", confidence="LIKELY",
                 host="CORP-WS01")
    return d, c["node_id"]


def _sighted(seen: set[str]):
    def fake(kind, value, cited, **kw):
        return [{"call_id": 4, "located": True}] if value.lower() in seen else []
    return fake


def _step(d, cid, action="Block update-check.example.com and 203.0.113.50 at the perimeter",
          indicators=("update-check.example.com", "203.0.113.50"), phase="contain"):
    return add_recommendation(d, action=action, phase=phase, basis_ids=[cid], indicators=list(indicators))


def test_a_value_no_output_shows_is_refused_once_then_removed(case):
    d, cid = case
    with patch("core.indicators.sightings", _sighted({"update-check.example.com"})):
        first = _step(d, cid)
        assert first["success"] is False and first["gate"] == "recommendation_value_unsighted"
        assert "names 203.0.113.50, which no tool output of this case shows" in first["error"]
        second = _step(d, cid)
    assert second["success"] is True and second["removed_values"] == ["203.0.113.50"]
    node = load_graph(d)["nodes"][second["node_id"]]
    assert "203.0.113.50" not in node["statement"] and node["indicators"] == ["update-check.example.com"]
    assert "Named 1 value(s) no tool output shows; removed: 203.0.113.50." in node["reasoning"]


def test_investigate_steps_private_addresses_and_sighted_values_pass(case):
    d, cid = case
    with patch("core.indicators.sightings", _sighted({"update-check.example.com", "203.0.113.50"})):
        assert _step(d, cid)["success"] is True
    with patch("core.indicators.sightings", _sighted(set())):
        assert _step(d, cid, phase="investigate", action="Search the proxy logs for 203.0.113.77",
                     indicators=("203.0.113.77",))["success"] is True
        assert _step(d, cid, action="Isolate 10.0.0.15 from the network", indicators=("10.0.0.15",),
                     phase="contain")["success"] is True


def test_a_step_with_nothing_left_is_refused(case):
    d, cid = case
    with patch("core.indicators.sightings", _sighted(set())):
        _step(d, cid, action="203.0.113.60", indicators=("203.0.113.60",))
        again = _step(d, cid, action="203.0.113.60", indicators=("203.0.113.60",))
    assert again["success"] is False and "names nothing" in again["error"]


def test_the_switch_off_records_as_before(case, monkeypatch):
    d, cid = case
    monkeypatch.setenv("ATLAS_REC_VALUE_SIGHTING", "0")
    with patch("core.indicators.sightings", _sighted(set())):
        assert _step(d, cid)["success"] is True


def test_the_prior_knowledge_contract_says_named_is_not_seen(monkeypatch):
    import core.case_knowledge as ck
    assert ck.PRIOR_INDICATOR_SENTENCE in ck.contract_text()
    monkeypatch.setenv("ATLAS_IOC_PRIOR_CONTEXT", "0")
    assert ck.contract_text() == ck.CONTRACT


def test_an_internal_name_is_no_external_value_and_a_public_domain_is(case):
    d, cid = case
    with patch("core.indicators.sightings", _sighted(set())):
        ok = _step(d, cid, action="Isolate corp-ws01.example.local from the network",
                   indicators=("corp-ws01.example.local",))
        assert ok["success"] is True
        bad = _step(d, cid, action="Block files.example.com at the proxy", indicators=("files.example.com",))
        assert bad["success"] is False and "files.example.com" in bad["error"]


def test_alternating_values_end_on_the_third_call(case):
    d, cid = case
    a_step = dict(action="Block 203.0.113.61 at the perimeter", indicators=("203.0.113.61",))
    with patch("core.indicators.sightings", _sighted(set())):
        a = _step(d, cid, **a_step)
        b = _step(d, cid, action="Block 203.0.113.62 at the perimeter", indicators=("203.0.113.62",))
        third = _step(d, cid, **a_step)
    assert a["success"] is False and b["success"] is False
    assert third["success"] is True and third["removed_values"] == ["203.0.113.61"]


def test_a_url_or_mail_address_on_an_internal_name_is_no_external_value(case):
    d, cid = case
    with patch("core.indicators.sightings", _sighted(set())):
        ok = _step(d, cid, action="Block http://intranet.example.local/x and admin@corp.example.internal",
                   indicators=("http://intranet.example.local/x", "admin@corp.example.internal"))
        assert ok["success"] is True
        bad = _step(d, cid, action="Block http://files.example.com/a.bin at the proxy",
                    indicators=("http://files.example.com/a.bin",))
        assert bad["success"] is False


def test_a_process_name_is_no_account(case, monkeypatch):
    row, why = I.normalize_row({"type": "account", "value": "tool.exe", "side": "victim"})
    assert row is None and "names a file" in why
    assert I.normalize_row({"type": "account", "value": "jane.doe", "side": "victim"})[0]
    assert I.normalize_row({"type": "account", "value": "CORP\\jdoe", "side": "victim"})[0]
    # A row recorded before the shape held is not named by a credential step.
    from core.recommendations import objects_for
    claim = {"indicators": [{"type": "account", "value": "tool.exe", "side": "victim"},
                            {"type": "account", "value": "jane.doe", "side": "victim"}]}
    assert objects_for("credentials", claim, frame="incident") == ["jane.doe"]
    monkeypatch.setenv("ATLAS_ACCOUNT_SHAPE", "0")
    assert I.normalize_row({"type": "account", "value": "tool.exe", "side": "victim"})[0]


def test_the_privileged_step_names_only_accounts_stated_privileged(monkeypatch):
    from core.recommendations import objects_for
    claim = {"statement": "jane.doe used the domain admin account svc-ops to reach CORP-DC01; "
                          "john.roe opened the lure.",
             "indicators": [{"type": "account", "value": v, "side": "victim"}
                            for v in ("svc-ops", "john.roe", "adm-jdoe")]}
    # An account's own name is no statement of its rights: adm-jdoe is
    # named privileged only by a current belief that says so.
    assert objects_for("privileged", claim, frame="incident") == ["svc-ops"]
    assert objects_for("credentials", claim, frame="incident") == ["svc-ops", "john.roe", "adm-jdoe"]
    graph = {"nodes": {
        "C0002": {"kind": "claim", "status": "new",
                  "statement": "adm-jdoe holds administrative rights on CORP-DC01."},
        "C0003": {"kind": "claim", "status": "superseded",
                  "statement": "john.roe is a privileged account."},
    }}
    assert objects_for("privileged", claim, frame="incident", graph=graph) == ["svc-ops", "adm-jdoe"]
    monkeypatch.setenv("ATLAS_PRIVILEGED_OBJECTS", "0")
    assert objects_for("privileged", claim, frame="incident") == ["svc-ops", "john.roe", "adm-jdoe"]


def test_only_program_and_script_names_are_refused_as_accounts(monkeypatch):
    for value in ("jane.zip", "li.so", "jo.py", "jane.doe"):
        assert I.normalize_row({"type": "account", "value": value, "side": "victim"})[0], value
    for value in ("tool.exe", "CORP\\run.ps1", "agent.so"):
        row, why = I.normalize_row({"type": "account", "value": value, "side": "victim"})
        assert row is None and "names a file" in why, value


def test_an_address_is_an_account_whatever_its_last_label():
    # A UPN, a mail address, a Kerberos principal: the label after the last
    # dot belongs to a host (com, pl, sh, so, py), never to a file name.
    for value in ("jane.doe@corp.example.com", "JANE.DOE@CORP.EXAMPLE.COM", "anna.przyklad@corp.example.pl",
                  "ops@build.example.sh", "svc@mail.example.so", "dev@lab.example.py",
                  "HTTP/web01.corp.example.com@CORP.EXAMPLE.COM", "jane.doe@corp.example.xn--p1ai"):
        assert I.normalize_row({"type": "account", "value": value, "side": "victim"})[0], value
    # A file stays a file: no address shape, or a top label that is not letters.
    for value in ("invoice.pdf.com", "C:\\Users\\Public\\invoice.pdf.com", "tool.exe", "a@b.example.ps1"):
        row, why = I.normalize_row({"type": "account", "value": value, "side": "victim"})
        assert row is None and "names a file" in why, value
    from core.recommendations import objects_for
    claim = {"indicators": [{"type": "account", "value": "jane.doe@corp.example.com", "side": "victim"},
                            {"type": "account", "value": "tool.exe", "side": "victim"}]}
    assert objects_for("credentials", claim, frame="incident") == ["jane.doe@corp.example.com"]


def test_a_qualified_account_may_hold_spaces(monkeypatch):
    for value in ("NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\NETWORK SERVICE", "CORP\\Jane Doe"):
        assert I.normalize_row({"type": "account", "value": value, "side": "victim"})[0], value
    for value in ("jane doe", "CORP \\jdoe", "CORP\\jane logged on at nine"):
        assert I.normalize_row({"type": "account", "value": value, "side": "victim"})[0] is None, value
    monkeypatch.setenv("ATLAS_ACCOUNT_SHAPE", "0")
    assert I.normalize_row({"type": "account", "value": "NT AUTHORITY\\SYSTEM", "side": "victim"})[0] is None
