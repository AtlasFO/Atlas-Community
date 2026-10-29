"""A submit's arguments are read as its schema declares them (a list
sent as a JSON string, nested fields too), and a submit that cannot be read
is answered, never dropped. Invented fixtures only."""
from __future__ import annotations

import json
from types import SimpleNamespace

from agent.frontier import SubmitApplier
from agent.item_executor import ItemSpec, read_submit, run_item
from agent.llm import ChatResponse
from core.frontier_prompts import submit_schema
from core.tool_arg_coerce import coerce_tool_arguments, coerce_value
from tests.agent.test_frontier_submit import _FINDING, _LABELS, _Agent, _item, _run, env  # noqa: F401
from tests.agent.test_item_executor import _Box, _call, _Client, _agent


def _plan_spec():
    return ItemSpec(kind="plan", system="s", user="u", core_tools=["table.table_grep"], submit=submit_schema("plan"))


def test_nested_coercion_changes_types_only_and_never_a_key():
    item = {"type": "object", "properties": {"basis": {"type": "array", "items": {"type": "object"}},
                                             "statement": {"type": "string"}}, "required": ["statement"]}
    prop = {"type": "array", "items": item}
    rows = [{"statment": "a guessed key", "_note": "an annotation", "basis": json.dumps([{"call_id": 3}])}]
    out = coerce_value(rows, prop)
    assert out[0]["basis"] == [{"call_id": 3}]                        # the type, coerced
    assert set(out[0]) == {"statment", "_note", "basis"}             # no key renamed, added or dropped


def test_a_json_looking_quote_in_a_string_field_stays_a_string():
    sch = submit_schema("plan")["function"]["parameters"]
    quote = '{"EventId": 4624, "UserName": "jane.doe"}'
    f = [{**_FINDING, "basis": [{"call_id": 11, "quote": quote}], "statement": "[a statement in brackets]"}]
    out, _n = coerce_tool_arguments({"findings": json.dumps(f)}, sch)
    assert out["findings"][0]["basis"][0]["quote"] == quote
    assert out["findings"][0]["statement"] == "[a statement in brackets]"


def test_the_live_mcp_object_array_parameters_come_out_unchanged():
    """The mechanical extract of the live tool declarations: no live MCP
    parameter is an array of objects with properties; the four list[dict]
    parameters have no item properties, so nested coercion leaves them as
    given, a JSON-string item field included."""
    from agent.toolbox import Toolbox
    tb = Toolbox()
    for tool, param in (("misc_record_finding", "indicators"), ("misc_record_agent_message", "findings"),
                        ("misc_batch_run", "tool_calls"), ("claim_add_indicators", "indicators")):
        sch = tb.tools[tool].schema
        given = [{"type": "ip", "value": "203.0.113.7", "extra": json.dumps(["a", "b"])}]
        out, _n = coerce_tool_arguments({param: given}, sch)
        assert out[param] == given, tool


def test_a_findings_list_sent_as_a_json_string_is_recorded(env):
    case, log, m = env
    agent = _Agent([{"success": True, "claim_id": "C0090"}])
    ap = SubmitApplier(agent, case, m, _item(log), "join_hit")
    nested = {**_FINDING, "basis": json.dumps(_FINDING["basis"]), "bears_on": json.dumps(["task-0001/p1"])}
    args, unread, _named = read_submit(_plan_spec(), {"findings": "\n" + json.dumps([nested]),
                                              "labels": json.dumps(_LABELS)})
    assert unread == "" and isinstance(args["findings"][0]["basis"], list)
    assert ap(args, _run(), False) is None and ap.out["findings"] == 1


def test_an_unreadable_submit_is_answered_and_nothing_of_it_applied():
    args, unread, _named = read_submit(_plan_spec(), {"findings": '[{"statement": "cut'})
    assert args == {} and unread.startswith("not read: findings must be an array; it came as str")
    args, unread, _named = read_submit(_plan_spec(), {"_malformed_arguments": "{\"findings\": [ ... cut",
                                              "_longest_argument": "findings (20311 characters)"})
    assert args == {} and "not valid JSON" in unread and "findings (20311 characters) took most of them" in unread


def test_an_unread_forced_submit_gets_the_repair_round_and_the_repair_is_read_too(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "1,1")
    seen = []
    script = [ChatResponse(content="", tool_calls=[_call(1, "table.table_grep", {"path": "a.csv", "pattern": "x"})]),
              ChatResponse(content="", tool_calls=[_call(2, "submit_plan", {"findings": '[{"cut'})]),
              ChatResponse(content="", tool_calls=[_call(3, "submit_plan", {"findings": json.dumps([_FINDING])})])]
    client = _Client(script)
    run = run_item(_agent(client, _Box()), _plan_spec(), on_submit=lambda a, r, f: seen.append((a, f)) or None,
                   progress=lambda r: 0)
    assert len(seen) == 1 and isinstance(seen[0][0]["findings"], list) and seen[0][1] is True
    assert run.end == "forced" and client.asks[2]["tool_choice"] == "required"
    # still unread after both one-round budgets: the item ends, on_submit never saw a string
    seen.clear()
    script = script[:2] + [ChatResponse(content="", tool_calls=[_call(i, "submit_plan", {"findings": '[{"cut'})])
                           for i in (3, 4)]
    run = run_item(_agent(_Client(script), _Box()), _plan_spec(),
                   on_submit=lambda a, r, f: seen.append(a) or None, progress=lambda r: 0)
    assert seen == [] and run.submit is None and run.submits == 3


def test_brief_and_coverage_never_get_an_unread_string(monkeypatch):
    from core.coverage_path import COVERAGE_SUBMIT
    from core.frontier_prompts import BRIEF_SUBMIT
    for submit, field in ((BRIEF_SUBMIT, "entities"), (COVERAGE_SUBMIT, None)):
        props = submit["function"]["parameters"].get("properties") or {}
        key = field or next(k for k, p in props.items() if "array" in str(p.get("type")))
        spec = ItemSpec(kind="t", system="s", user="u", core_tools=[], submit=submit)
        monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "1,1")
        script = [ChatResponse(content="", tool_calls=[_call(i, submit["function"]["name"], {key: '[{"cut'})])
                  for i in range(3)]                     # unread, unread when forced, unread in the repair round
        run = run_item(_agent(_Client(script), _Box()), spec)
        # every submit was answered (three rounds given), none was read
        assert run.submit is None and run.submits == 3


def test_pending_repairs_keep_their_places_across_an_unread_submit(env, monkeypatch):
    """Through run_item with the applier: refused once, then an unread submit
    (never passed on), then the repair: recorded, nothing refused twice."""
    case, log, m = env
    refusal = {"success": False, "gate": "evidence_strength", "error": "cite the row"}
    ap = SubmitApplier(_Agent([refusal, {"success": True, "claim_id": "C0091"}]), case, m, _item(log), "join_hit")
    ap.named = {11, 12}                                               # the calls the item names (its basis)
    seen = []

    def on_submit(args, run, final):
        seen.append(args)
        return ap(args, run, final)
    script = [ChatResponse(content="", tool_calls=[_call(1, "submit_plan", {"findings": [_FINDING], "labels": _LABELS})]),
              ChatResponse(content="", tool_calls=[_call(2, "submit_plan", {"findings": '[{"cut'})]),
              ChatResponse(content="", tool_calls=[_call(3, "submit_plan", {"findings": [_FINDING]})])]
    agent = _agent(_Client(script), _Box())
    monkeypatch.setattr(agent, "_call_once", lambda *a, **k: {"kind": "ran", "result": "{}"})
    run = run_item(agent, _plan_spec(), on_submit=on_submit, progress=lambda r: len(seen))
    ap.finish()
    assert len(seen) == 2 and ap.out["findings"] == 1 and run.submits == 3
    assert not [i for i in log.work_items() if i["origin"] == "followup"]


def test_a_plain_string_where_a_nested_list_of_strings_is_declared_is_a_list_of_it(env):
    case, log, m = env
    args, unread, _named = read_submit(_plan_spec(), {"findings": [{**_FINDING, "bears_on": "task-0001/p1"}]})
    assert unread == "" and args["findings"][0]["bears_on"] == ["task-0001/p1"]
    out, _n = coerce_tool_arguments({"tags": "one"}, {"type": "object", "properties": {
        "tags": {"type": "array", "items": {"type": "string"}}}})
    assert out["tags"] == "one"                                       # the top level keeps its own rules


# -- a wrapped submit, a complete value with more after it, two repair budgets -------------------

def test_a_submit_wrapped_in_one_string_is_unwrapped_and_logged_generically():
    logged = []
    inner = {"findings": [_FINDING], "labels": _LABELS}
    args, unread, _named = read_submit(_plan_spec(), {"payload_text": json.dumps(inner)}, log=logged.append)
    assert unread == "" and args["findings"][0]["statement"] == _FINDING["statement"]
    assert logged and logged[0]["key"] == "payload_text" and logged[0]["chars"] > 0
    args, unread, _named = read_submit(_plan_spec(), {"_wrapped": "not json at all"})
    assert args == {} and unread.startswith("not read: none of submit_plan's fields were given (got: _wrapped)")
    args, unread, _named = read_submit(_plan_spec(), {"_wrapped": json.dumps({"other": 1})})
    assert args == {} and "none of submit_plan's fields" in unread


def test_double_encoded_tool_arguments_are_unwrapped_or_told_as_malformed():
    from agent.llm import _parse_tool_calls

    def parse(raw):
        return _parse_tool_calls([{"id": "c1", "function": {"name": "t", "arguments": raw}}])[0].arguments
    assert parse("null") == {} and parse("[]") == {} and parse('""') == {}       # no arguments: a valid call
    assert parse(json.dumps(json.dumps({"path": "a.csv"}))) == {"path": "a.csv"}
    plain, items = parse(json.dumps("plain text")), parse("[1, 2]")
    assert plain["_not_object"] == "str" and items["_not_object"] == "list"
    assert parse('{"path": "a.csv"}') == {"path": "a.csv"}
    _args, unread, _named = read_submit(_plan_spec(), items)
    assert unread.startswith("not read: the arguments of submit_plan must be a JSON object; got list")


def test_a_complete_array_with_the_rest_of_the_submit_inside_it_is_diagnosed_not_applied():
    s = "\n" + json.dumps([_FINDING, _FINDING]) + ': false, "labels": [{"ref": {"kind": "host"}}], "events": []'
    args, unread, _named = read_submit(_plan_spec(), {"findings": s})
    assert args == {} and "it holds a complete list of 2 item(s) followed by" in unread
    assert "(labels, events written inside findings)" in unread and "send each field as its own argument" in unread


def test_unread_then_refused_then_repaired_uses_both_budgets(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "1,1")
    replies = iter(["finding 1 refused (gate): fix it", None])
    seen = []

    def on_submit(a, r, final):
        seen.append(final)
        return next(replies)
    script = [ChatResponse(content="", tool_calls=[_call(1, "table.table_grep", {"path": "a.csv", "pattern": "x"})]),
              ChatResponse(content="", tool_calls=[_call(2, "submit_plan", {"findings": '[{"cut'})]),
              ChatResponse(content="", tool_calls=[_call(3, "submit_plan", {"findings": [_FINDING]})]),
              ChatResponse(content="", tool_calls=[_call(4, "submit_plan", {"findings": [_FINDING]})])]
    client = _Client(script)
    run = run_item(_agent(client, _Box()), _plan_spec(), on_submit=on_submit, progress=lambda r: 0)
    assert seen == [True, True] and run.end == "forced" and run.submits == 3 and run.digest
    assert all(a["tool_choice"] == "required" for a in client.asks[1:])


def test_a_third_unread_forced_submit_ends_the_item(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "1,1")
    script = [ChatResponse(content="", tool_calls=[_call(1, "table.table_grep", {"path": "a.csv", "pattern": "x"})])] + [
        ChatResponse(content="", tool_calls=[_call(i, "submit_plan", {"findings": '[{"cut'})]) for i in (2, 3, 4)]
    client = _Client(script)
    run = run_item(_agent(client, _Box()), _plan_spec(), on_submit=lambda a, r, f: None, progress=lambda r: 0)
    assert run.submits == 3 and run.submit is None and len(client.asks) == 4


def test_unread_unforced_submits_count_as_empty_rounds_and_reach_the_forced_round(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    script = [ChatResponse(content="", tool_calls=[_call(i, "submit_plan", {"findings": '[{"cut'})]) for i in range(5)]
    client = _Client(script)
    run_item(_agent(client, _Box()), _plan_spec(), on_submit=lambda a, r, f: None, progress=lambda r: 0)
    assert [a["tool_choice"] for a in client.asks][:3] == [None, None, "required"]


def test_a_tool_call_whose_arguments_are_no_object_is_told_so():
    from agent.llm import _parse_tool_calls
    from agent.toolbox import Toolbox
    args = _parse_tool_calls([{"id": "c1", "function": {"name": "t", "arguments": "[1, 2]"}}])[0].arguments
    text, _loaded = Toolbox().call("misc_record_agent_message", args)
    assert "must be a JSON object; got list" in text and "not valid JSON" not in text
