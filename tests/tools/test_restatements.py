"""One statement recorded twice: a direct claim that says nothing a standing
belief does not already say is answered with that belief's id; a statement
is never related to its own negation; and the pre-report advisory names
standing pairs where one claim restates or refines another."""
from pathlib import Path

import pytest

from core.claim_graph import add_claim, load_graph, save_graph, supersede
from tools.misc import _near_duplicate, _relation, standing_duplicate_pairs

EXECUTED = "The file evil.exe was executed on the host WS-EXAMPLE from the Temp folder."
NOT_EXECUTED = "The file evil.exe was not executed on the host WS-EXAMPLE from the Temp folder."


def _tool():
    from tools.claim_tools import add_claim as tool
    return getattr(tool, "fn", tool)


@pytest.fixture
def case(tmp_path) -> Path:
    c = tmp_path / "C"
    (c / ".atlas").mkdir(parents=True)
    return c


def test_a_statement_is_not_related_to_its_negation():
    assert _relation(NOT_EXECUTED, EXECUTED) is None
    assert _relation(EXECUTED, EXECUTED)[0] == "restates"


def test_a_negator_inside_a_value_does_not_count():
    old = "The chat client identity is nick=zed, ident=zz, email=none@example.org on the server."
    new = "The chat client identity is nick=zed, ident=zz on the server."
    assert _relation(new, old) is not None


def test_the_finding_path_records_a_negation_instead_of_folding_it():
    class Log:
        _entries = [{"type": "finding", "call_id": 5, "host": "", "description": EXECUTED}]

    assert _near_duplicate(EXECUTED, "", Log()) is not None
    assert _near_duplicate(NOT_EXECUTED, "", Log()) is None


def test_an_exact_restatement_is_answered_with_the_standing_id(case):
    cid = add_claim(case, "The user admin logged on to the host WS-EXAMPLE interactively.",
                    host="WS-EXAMPLE", enforce_validation=False)["node_id"]
    before = load_graph(case)["nodes"].keys() - set()
    r = _tool()("The user admin logged on to WS-EXAMPLE interactively.", host="WS-EXAMPLE",
                case_dir=str(case))
    assert r["success"] is True and r["node_id"] == cid and r["restates"] == cid
    assert load_graph(case)["nodes"].keys() == before


def test_a_restated_conclusion_is_answered_with_its_id(case):
    from core.claim_graph import add_node
    nid = add_node(case, kind="conclusion", statement="The main user of WS-EXAMPLE is the account jdoe.",
                   confidence="LIKELY", host="WS-EXAMPLE")["node_id"]
    r = _tool()("The main user of WS-EXAMPLE is jdoe.", host="WS-EXAMPLE", case_dir=str(case))
    assert r["node_id"] == nid and r["restates"] == nid


@pytest.mark.parametrize("statement,host", [
    ("The user jsmith logged on to the host WS-EXAMPLE interactively.", "WS-EXAMPLE"),   # another name
    ("The user admin never logged on to the host WS-EXAMPLE interactively.", "WS-EXAMPLE"),  # negation
    ("The user admin logged on to the host WS-EXAMPLE interactively.", "WS-OTHER"),       # another host
    ("The user admin logged on to the host WS-EXAMPLE interactively 14 times.", "WS-EXAMPLE"),  # a number
])
def test_a_claim_that_says_something_else_is_recorded(case, statement, host):
    cid = add_claim(case, "The user admin logged on to the host WS-EXAMPLE interactively.",
                    host="WS-EXAMPLE", enforce_validation=False)["node_id"]
    r = _tool()(statement, host=host, case_dir=str(case))
    assert r["success"] is True and r["node_id"] != cid and "restates" not in r


def _nodes(case, *rows):
    ids = [add_claim(case, s, confidence=c, host="WS-EXAMPLE", enforce_validation=False)["node_id"]
           for s, c in rows]
    return ids, load_graph(case)["nodes"]


def test_standing_restatements_and_refinements_are_named(case):
    (a, b, c), nodes = _nodes(
        case,
        ("Web-mail copies are stored as plain-text files in the user's profile folder.", "LIKELY"),
        ("Web-mail copies are kept as plain-text files in the user's profile folder, one per site.", "LIKELY"),
        ("Web-mail copies are stored as plain-text files in the user's profile folder "
         "C:\\Users\\jdoe\\Cookies, 42 files.", "LIKELY"))
    pairs = {(p["older"], p["newer"]): p["relation"] for p in standing_duplicate_pairs(nodes)}
    assert pairs[(a, b)] == "restates" and pairs[(a, c)] == "refines"


def test_a_template_with_another_value_is_another_fact(case):
    _ids, nodes = _nodes(
        case,
        ("Account alpha was created by the operator account at 09:12 UTC (event 4720, H1).", "LIKELY"),
        ("Account beta was created by the operator account at 09:14 UTC (event 4720, H2).", "LIKELY"))
    assert standing_duplicate_pairs(nodes) == []


def test_a_weaker_refinement_or_a_linked_or_retired_pair_is_not_named(case):
    (a, b), nodes = _nodes(
        case,
        ("Web-mail copies are stored as plain-text files in the user's profile folder.", "CONFIRMED"),
        ("Web-mail copies are stored as plain-text files in the user's profile folder, "
         "including jdoe_webmail.txt.", "SUSPECTED"))
    assert standing_duplicate_pairs(nodes) == []            # lower tier than the older
    graph = load_graph(case)
    graph["nodes"][b]["confidence"] = "CONFIRMED"
    graph["nodes"][b]["refines"] = a
    save_graph(case, graph)
    assert standing_duplicate_pairs(load_graph(case)["nodes"]) == []   # linked on purpose
    graph["nodes"][b].pop("refines")
    save_graph(case, graph)
    assert standing_duplicate_pairs(load_graph(case)["nodes"]) != []
    supersede(case, a, b, reason="the newer replaces it")
    assert standing_duplicate_pairs(load_graph(case)["nodes"]) == []   # the older is retired


def test_a_statement_and_its_negation_are_named_as_a_contradiction():
    from tools.misc import standing_contradictions

    def node(i, st, t, **kw):
        return {"id": i, "kind": "claim", "status": "new", "statement": st, "host": "CORP-WS01",
                "created_at": t, "confidence": "LIKELY", **kw}

    yes = node("C1", "evil.exe was executed from the Temp folder of jane.doe", "1")
    no = node("C2", "evil.exe was not executed from the Temp folder of jane.doe", "2")
    assert standing_contradictions({"C1": yes, "C2": no}) == [
        {"older": "C1", "newer": "C2", "words": ["evil.exe", "executed"]}]
    # The negation of another clause opposes nothing.
    other = node("C3", "evil.exe was executed from the Temp folder of jane.doe. No persistence was found.", "3")
    assert standing_contradictions({"C1": yes, "C3": other}) == []
    # A superseded side, or a pair a recorded conflict names, is not listed.
    assert standing_contradictions({"C1": dict(yes, status="superseded"), "C2": no}) == []
    conflict = {"id": "C4", "kind": "conflict", "status": "new", "statement": "x",
                "conflicting_claim_ids": ["C1", "C2"]}
    assert standing_contradictions({"C1": yes, "C2": no, "C4": conflict}) == []


def test_a_refinement_that_only_adds_a_site_adds_information():
    from tools.misc import _adds_information
    assert _adds_information("The browser of jane.doe opened evil.xyz after the logon",
                             "The browser of jane.doe opened a site after the logon")
