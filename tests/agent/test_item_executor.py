"""The item executor (one short fresh conversation per item,
its own tool list, a submit tool, behavioural guards) and the evidence
triage as its first item type."""
from __future__ import annotations

import json

from agent.item_executor import ItemSpec, run_item
from agent.llm import ChatResponse, ToolCall
from agent.loop import Agent
from tests.agent.test_call_once import _CountingBox

SUBMIT = {"type": "function", "function": {"name": "submit_x", "description": "end",
                                            "parameters": {"type": "object", "properties": {}}}}


class _Box(_CountingBox):
    def schemas_for(self, names):
        return [{"type": "function", "function": {"name": n, "description": "", "parameters": {}}} for n in names]


class _Client:
    model, base_url = "fake", "http://fake"
    total_input_tokens = total_output_tokens = 0

    def __init__(self, script):
        self.script, self.asks = list(script), []

    def chat(self, messages, tools=None, role=None, tool_choice=None, **kw):
        self.asks.append({"tools": [t["function"]["name"] for t in tools or []], "tool_choice": tool_choice,
                          "messages": len(messages)})
        return self.script.pop(0)


def _call(i, name, args=None):
    return ToolCall(id=f"t{i}", name=name, arguments=args or {})


def _agent(client, box):
    a = Agent(client, box, case_dir=None, quiet=True)
    a._run_setup("sys", "user")
    return a


def _spec():
    return ItemSpec(kind="test", system="sys", user="item", core_tools=["table.table_grep"], submit=SUBMIT)


def test_an_item_reads_then_submits_on_its_own_list():
    box = _Box()
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "table.table_grep", {"path": "a.csv",
                                                                                         "pattern": "x"}),
                                                            _call(2, "misc.other_tool")]),
                      ChatResponse(content="", tool_calls=[_call(3, "submit_x", {"done": True})])])
    run = run_item(_agent(client, box), _spec())
    assert run.submit == {"done": True} and run.end == "submitted" and run.rounds == 2
    assert run.refused_off_list == 1 and [c[0] for c in box.calls] == ["table.table_grep"]
    assert box.calls[0][2] is True                                   # budget free
    assert client.asks[0]["tools"] == ["table.table_grep", "submit_x"] and client.asks[0]["tool_choice"] is None


def test_two_rounds_with_nothing_new_force_the_submit(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    box = _Box()
    same = {"path": "a.csv", "pattern": "x"}
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "table.table_grep", same)]),
                      ChatResponse(content="", tool_calls=[_call(2, "table.table_grep", same)]),
                      ChatResponse(content="", tool_calls=[_call(3, "table.table_grep", same)]),
                      ChatResponse(content="", tool_calls=[_call(4, "submit_x", {})])])
    run = run_item(_agent(client, box), _spec())
    assert run.end == "forced" and len(box.calls) == 1
    assert client.asks[-1] == {"tools": ["submit_x"], "tool_choice": "required", "messages": client.asks[-1]["messages"]}


def test_the_context_budget_forces_the_submit(monkeypatch):
    import agent.item_executor as X
    monkeypatch.setattr(X, "_budget", lambda: 10)
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "submit_x", {"a": 1})])])
    run = run_item(_agent(client, _Box()), _spec())
    assert run.end == "context_fit" and client.asks[0]["tool_choice"] == "required"


def test_the_triage_runs_as_an_item_and_its_submit_is_recorded(tmp_path, monkeypatch):
    import core.execution_log as elog
    from core import evidence_triage as TR
    from tests.core.test_evidence_leave import _case
    case = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis", "exports"):
        (case / d).mkdir(parents=True)
    elog.log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    led = _case(case, monkeypatch)
    ws01 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws01.raw"))
    labels = [c["label"] for c in led["classes"].values() if c["item"] == ws01["id"]]
    replies = {}
    for iid in led["items"]:
        replies[iid] = ChatResponse(content="", tool_calls=[_call(9, "submit_triage", {
            "decisions": [{"decision": "read_now", "classes": labels[:1]}]})])

    class _PerItem(_Client):
        def chat(self, messages, tools=None, role=None, tool_choice=None, **kw):
            iid = messages[1]["content"].split("\n", 1)[0].removeprefix("ITEM ID ")
            self.asks.append(iid)
            return replies[iid]
    client = _PerItem([])
    agent = Agent(client, _Box(), case_dir=case, quiet=True)
    agent._run_setup("sys", "user")
    done = TR.triage_pending(elog.log, case, agent=agent)
    assert len(done) == len(led["items"]) and all(d["end"] == "submitted" for d in done)
    from core.coverage_ledger import load_ledger
    after = load_ledger(case)
    assert any(c["state"] == "relevant" for c in after["classes"].values() if c["item"] == ws01["id"])
    assert "submit_triage" in json.dumps(TR.TRIAGE_SUBMIT) and "evtx" not in TR.TRIAGE_ITEM_SYS.lower()



def test_a_triage_item_whose_forced_round_brings_no_submit_takes_the_models_retry(tmp_path, monkeypatch):
    # The forced round calls a tool it was not offered; the retry's submit
    # decides the classes, not the fallback for an item without a submit.
    import core.execution_log as elog
    from core import evidence_triage as TR
    from tests.core.test_evidence_leave import _case
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "1,1")
    case = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis", "exports"):
        (case / d).mkdir(parents=True)
    elog.log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    led = _case(case, monkeypatch)
    ws01 = next(i for i in led["items"].values() if i["path"].endswith("corp-ws01.raw"))
    labels = [c["label"] for c in led["classes"].values() if c["item"] == ws01["id"]]
    scripts = {iid: [ChatResponse(content="thinking", tool_calls=[]),
                     ChatResponse(content="", tool_calls=[_call(8, "table.table_grep", {"path": "a.csv"})]),
                     ChatResponse(content="", tool_calls=[_call(9, "submit_triage", {
                         "decisions": [{"decision": "read_now", "classes": labels[:1]}]})])]
               for iid in led["items"]}

    class _PerItem(_Client):
        def chat(self, messages, tools=None, role=None, tool_choice=None, **kw):
            iid = messages[1]["content"].split("\n", 1)[0].removeprefix("ITEM ID ")
            self.asks.append((iid, tool_choice))
            return scripts[iid].pop(0)
    client = _PerItem([])
    box = _Box()
    agent = Agent(client, box, case_dir=case, quiet=True)
    agent._run_setup("sys", "user")
    done = TR.triage_pending(elog.log, case, agent=agent)
    assert len(done) == len(led["items"]) and all(d["end"] == "forced" for d in done)
    assert not box.calls and all(not v for v in scripts.values())
    from core.coverage_ledger import load_ledger
    after = load_ledger(case)
    assert any(c["state"] == "relevant" for c in after["classes"].values() if c["item"] == ws01["id"])


def _no_submit_script(retry):
    same = {"path": "a.csv", "pattern": "x"}
    return [ChatResponse(content="", tool_calls=[_call(1, "table.table_grep", same)]),
            ChatResponse(content="", tool_calls=[_call(2, "table.table_grep", same)]),
            ChatResponse(content="", tool_calls=[_call(3, "table.table_grep", same)]),
            ChatResponse(content="", tool_calls=[_call(4, "table.table_grep", {"path": "b.csv", "pattern": "y"}),
                                                 _call(5, "table.table_pivot", {"path": "b.csv"})]),
            retry]


class _Seen(_Client):
    def chat(self, messages, **kw):
        self.last_messages = list(messages)
        return super().chat(messages, **kw)


def test_a_forced_round_without_a_submit_gets_one_retry_then_ends(monkeypatch):
    # The forced round's reads are answered, never run: the retry is forced
    # too, and a second round without a submit ends the item as "stuck".
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    box = _Box()
    client = _Seen(_no_submit_script(ChatResponse(content="", tool_calls=[_call(6, "table.table_grep",
                                                                                 {"path": "c.csv", "pattern": "z"})])))
    agent = _agent(client, box)
    run = run_item(agent, _spec())
    assert run.end == "stuck" and run.submit is None and len(client.asks) == 5 and run.rounds == 5
    assert [a["tool_choice"] for a in client.asks[3:]] == ["required", "required"]
    assert client.asks[4]["tools"] == ["submit_x"]
    assert len(box.calls) == 1 and run.ran_calls == run.calls == []     # only round 1 ran; nothing from 4-5
    replies = [m for m in client.last_messages if m.get("role") == "tool"]
    assert [m["tool_call_id"] for m in replies] == ["t4", "t5"]
    assert all(m["content"].startswith("not run: only submit_x is offered in this round") for m in replies)


def test_a_retry_that_submits_ends_as_a_forced_submit(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    box = _Box()
    client = _Client(_no_submit_script(ChatResponse(content="", tool_calls=[_call(6, "submit_x", {"n": 1})])))
    seen = []
    run = run_item(_agent(client, box), _spec(), on_submit=lambda a, r, f: seen.append((a, f)))
    assert run.end == "forced" and run.submit == {"n": 1} and seen == [({"n": 1}, True)]
    assert len(box.calls) == 1


def test_a_failing_item_falls_back_to_the_stateless_call_and_logs_once(tmp_path, monkeypatch):
    import core.execution_log as elog
    from core import evidence_triage as TR
    from tests.core.test_evidence_leave import _case
    case = tmp_path / "case"
    for d in ("evidence/disk", ".atlas", "analysis", "exports"):
        (case / d).mkdir(parents=True)
    elog.log.configure("CASE-A", str(case / "analysis" / "CASE-A_trace.json"), save_session=False)
    led = _case(case, monkeypatch)
    monkeypatch.setattr("agent.item_executor.run_item", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    asked = []
    monkeypatch.setattr(TR, "triage_call", lambda s, u, ask=None: asked.append(u) or "{}")
    agent = Agent(_Client([]), _Box(), case_dir=case, quiet=True)
    events = []
    monkeypatch.setattr(agent, "_log", events.append)
    done = TR.triage_pending(elog.log, case, agent=agent)
    assert len(asked) == len(led["items"]) and all(d["end"] == "stateless" for d in done)
    assert [e["event"] for e in events].count("triage_item_failed") == 1


def test_item_use_readers_swaps_readers_in_after_the_core():
    box = _Box()
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "item_use_readers",
                                                                 {"names": ["fmt.read_a", "nope"]})]),
                      ChatResponse(content="", tool_calls=[_call(2, "fmt.read_a", {"path": "x.bin"})]),
                      ChatResponse(content="", tool_calls=[_call(3, "submit_x", {})])])
    spec = _spec()
    spec.menu = ["fmt.read_a", "fmt.read_b"]
    run = run_item(_agent(client, box), spec)
    assert client.asks[0]["tools"] == ["table.table_grep", "item_use_readers", "submit_x"]
    assert client.asks[1]["tools"] == ["table.table_grep", "fmt.read_a", "item_use_readers", "submit_x"]
    assert run.readers == ["fmt.read_a"] and [c[0] for c in box.calls] == ["fmt.read_a"] and run.end == "submitted"


def test_a_submit_answered_with_a_repair_goes_back_into_the_item():
    box = _Box()
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "submit_x", {"n": 1}), _call(2, "x.y")]),
                      ChatResponse(content="", tool_calls=[_call(3, "submit_x", {"n": 2})])])
    seen = []

    def on_submit(args, run, final):
        seen.append((args["n"], final))
        return "finding 1 refused: no basis; resubmit finding 1 only" if args["n"] == 1 else None
    run = run_item(_agent(client, box), _spec(), on_submit=on_submit)
    assert seen == [(1, False), (2, False)] and run.submit == {"n": 2} and run.submits == 2
    assert run.end == "submitted" and box.calls == []                # the call beside the submit never ran


def test_refused_submits_without_progress_end_with_a_final_forced_submit(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    box = _Box()
    same = ChatResponse(content="", tool_calls=[_call(1, "submit_x", {"n": 1})])
    client = _Client([same] + [ChatResponse(content="", tool_calls=[_call(i, "submit_x", {"n": 1})])
                               for i in (2, 3, 4)])
    finals = []

    def on_submit(args, run, final):
        finals.append(final)
        return "refused again"
    run = run_item(_agent(client, box), _spec(), on_submit=on_submit)
    # refused submits make no progress: two of them, then the forced one, whose
    # refusal gets one repair round (forced too); the repair's submit is final
    assert finals == [False, False, True, True] and run.end == "forced" and len(client.asks) == 4
    assert client.asks[2]["tool_choice"] == "required" and client.asks[2]["tools"] == ["submit_x"]
    assert client.asks[3]["tool_choice"] == "required" and client.asks[3]["tools"] == ["submit_x"]


def test_the_request_is_rebuilt_from_a_digest_the_note_and_the_last_round(monkeypatch):
    box = _Box()
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "table.table_grep", {"path": "a.csv",
                                                                                         "pattern": "x"})]),
                      ChatResponse(content="", tool_calls=[_call(2, "item_note", {"add": [
                          {"fact": "jane.doe ran svc_kit.exe", "call_id": 1, "quote": "rows"},
                          {"fact": "made up", "call_id": 1, "quote": "not there"}]}),
                          _call(3, "table.table_grep", {"path": "b.csv", "pattern": "y"})]),
                      ChatResponse(content="", tool_calls=[_call(4, "submit_x", {})])])
    sent = []
    real = client.chat

    def chat(messages, **kw):
        sent.append([m.get("content") or "" for m in messages])
        return real(messages, **kw)
    client.chat = chat
    run = run_item(_agent(client, box), _spec(), verify_note=lambda cid, q, r: "1#R1" if q == "rows" else None)
    assert run.end == "submitted" and [n["fact"] for n in run.notes] == ["jane.doe ran svc_kit.exe"]
    third = sent[2]
    assert any(str(t).startswith("EARLIER CALLS OF THIS ITEM") for t in third)
    assert any(str(t).startswith("YOUR NOTE") and "jane.doe ran svc_kit.exe" in t for t in third)
    assert client.asks[1]["tools"][-2:] == ["item_note", "submit_x"]


def test_the_patience_counts_rounds_without_progress(monkeypatch):
    from agent.item_executor import ITEM_PATIENCE, patience
    assert patience() == ITEM_PATIENCE == (6, 3)
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "4,2")
    assert patience() == (4, 2)
    box = _Box()
    steps = iter([0, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    client = _Client([ChatResponse(content="", tool_calls=[_call(i, "table.table_grep",
                                                                 {"path": f"{i}.csv", "pattern": "x"})])
                      for i in range(1, 4)] + [ChatResponse(content="", tool_calls=[_call(9, "submit_x", {})])])
    run = run_item(_agent(client, box), _spec(), progress=lambda run: next(steps))
    # the fourth request is the forced one (its read-only reply gets the one retry)
    assert run.progressed and [x["tool_choice"] for x in client.asks].index("required") == 3


def test_a_state_flipped_back_and_forth_progresses_once(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    flips = iter(["A", "B"] * 20)
    client = _Client([ChatResponse(content="", tool_calls=[_call(i, "table.table_grep",
                                                                 {"path": f"{i}.csv", "pattern": "x"})])
                      for i in range(1, 9)] + [ChatResponse(content="", tool_calls=[_call(99, "submit_x", {})])])
    run = run_item(_agent(client, _Box()), _spec(), progress=lambda run: next(flips))
    # the fourth request is the forced one (its read-only reply gets the one retry)
    assert run.progressed and [x["tool_choice"] for x in client.asks].index("required") == 3


def test_a_cut_output_re_read_is_neutral_only_once(monkeypatch):
    import agent.item_executor as X
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "3,3")
    monkeypatch.setattr(X, "digest", lambda calls, budget: ("EARLIER CALLS", {5}))
    agent = _agent(_Client([ChatResponse(content="", tool_calls=[_call(i, "table.table_grep",
                                                                       {"path": "a.csv", "pattern": "x"})])
                            for i in range(1, 9)] + [ChatResponse(content="", tool_calls=[_call(99, "submit_x", {})])]),
                   _Box())
    replies = iter([{"kind": "ran", "result": '{"rows": [1], "_atlas_call_id": 5}'}]
                   + [{"kind": "replayed", "result": '{"rows": [1], "_atlas_call_id": 5}'}] * 10)
    monkeypatch.setattr(agent, "_call_once", lambda *a, **k: next(replies))
    run = run_item(agent, _spec(), progress=lambda run: 0)
    # round 1 reads (no progress), round 2 re-reads a call the digest does not
    # hold yet (empty), round 3 re-reads the cut output (neutral, once), round
    # 4 re-reads it again (empty): the third empty round forces the submit
    asks = agent.client.asks
    assert not run.progressed and [x["tool_choice"] for x in asks].index("required") == 4


def test_only_calls_the_item_ran_are_its_own(monkeypatch):
    agent = _agent(_Client([ChatResponse(content="", tool_calls=[_call(i, "table.table_grep",
                                                                       {"path": f"{i}.csv", "pattern": "x"})])
                            for i in (1, 2)] + [ChatResponse(content="", tool_calls=[_call(9, "submit_x", {})])]),
                   _Box())
    replies = iter([{"kind": "ran", "result": '{"rows": [1], "_atlas_call_id": 5}'},
                    {"kind": "replayed", "result": '{"rows": [1], "_atlas_call_id": 3}'}])
    monkeypatch.setattr(agent, "_call_once", lambda *a, **k: next(replies))
    run = run_item(agent, _spec())
    assert run.calls == [5, 3] and run.ran_calls == [5]



# -- a forced submit's refusal gets one repair round ------------------------------------------

def _forced_script(n_repair=1):
    return [ChatResponse(content="", tool_calls=[_call(i, "table.table_grep", {"path": "a.csv", "pattern": "x"})])
            for i in (1, 2)] + [ChatResponse(content="", tool_calls=[_call(10 + i, "submit_x", {"n": i})])
                                   for i in range(n_repair + 1)]


def test_a_forced_submits_refusal_is_sent_back_once_and_the_repair_is_final(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    client = _Client(_forced_script())
    replies = iter(["finding 1 refused (gate): fix it. Resubmit only the refused finding(s)", None])
    seen = []

    def on_submit(args, run, final):
        seen.append((args["n"], final))
        return next(replies)
    run = run_item(_agent(client, _Box()), _spec(), on_submit=on_submit, progress=lambda r: 0)
    assert seen == [(0, True), (1, True)] and run.end == "forced" and run.rounds == 4
    assert client.asks[-1]["tools"] == ["submit_x"] and client.asks[-1]["tool_choice"] == "required"


def test_a_repair_round_without_a_submit_or_with_a_failing_call_keeps_the_forced_end(monkeypatch):
    # A repair round without a submit takes the read budget for one retry;
    # a retry without a submit ends the item, its end still the forced one.
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    script = _forced_script(0) + [ChatResponse(content="no", tool_calls=[]), ChatResponse(content="no", tool_calls=[])]
    client = _Client(script)
    run = run_item(_agent(client, _Box()), _spec(), on_submit=lambda a, r, f: "refused",
                   progress=lambda r: 0)
    assert run.end == "forced" and run.rounds == 5 and run.digest and client.asks[-1]["tool_choice"] == "required"

    class _Failing(_Client):
        def chat(self, messages, **kw):
            if len(self.asks) == 3:          # two reads, the forced submit, then the repair round
                self.asks.append({})
                raise RuntimeError("provider error on the repair round")
            return super().chat(messages, **kw)
    run = run_item(_agent(_Failing(_forced_script(0)), _Box()), _spec(), on_submit=lambda a, r, f: "refused",
                   progress=lambda r: 0)
    assert run.end == "forced" and run.rounds == 3


def test_a_context_fit_end_repairs_only_when_the_repair_request_fits(monkeypatch):
    import agent.item_executor as X
    sizes = iter([10 ** 9, 0])                     # the forced request does not fit, the repair does
    monkeypatch.setattr(X, "_chars", lambda messages: next(sizes))
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "submit_x", {"n": 1})]),
                      ChatResponse(content="", tool_calls=[_call(2, "submit_x", {"n": 2})])])
    run = run_item(_agent(client, _Box()), _spec(), on_submit=lambda a, r, f: "refused" if a["n"] == 1 else None)
    assert run.end == "context_fit" and len(client.asks) == 2 and client.asks[1]["tool_choice"] == "required"
    sizes = iter([10 ** 9, 10 ** 9])                 # neither fits: the forced submit stays final
    monkeypatch.setattr(X, "_chars", lambda messages: next(sizes))
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "submit_x", {"n": 1})])])
    run = run_item(_agent(client, _Box()), _spec(), on_submit=lambda a, r, f: "refused")
    assert run.end == "context_fit" and len(client.asks) == 1


# -- the tools an item answers itself read their arguments as their schema declares them --------

_LIST_SUBMIT = {"type": "function", "function": {"name": "submit_x", "description": "end", "parameters": {
    "type": "object", "properties": {"findings": {"type": "array", "items": {"type": "object", "properties": {
        "statement": {"type": "string"}, "basis": {"type": "array"}}}}}}}}
_NOTE = {"fact": "jane.doe ran svc_kit.exe", "call_id": 1, "quote": "rows"}


def _replies(client):
    """The tool replies of the round before each ask, one list per ask."""
    out = []
    real = client.chat

    def chat(messages, **kw):
        out.append(" | ".join(str(m.get("content")) for m in messages if m.get("role") == "tool"))
        return real(messages, **kw)
    client.chat = chat
    return out


def test_a_note_keeps_its_object_entries_and_names_each_other_one_by_its_place():
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "table.table_grep", {"path": "a.csv"})]),
                      ChatResponse(content="", tool_calls=[_call(2, "item_note", {"add": [
                          _NOTE, "jane.doe ran a second tool", json.dumps({**_NOTE, "fact": "svc_kit.exe from CORP-WS01"})]})]),
                      ChatResponse(content="", tool_calls=[_call(3, "submit_x", {})])])
    replies = _replies(client)
    run = run_item(_agent(client, _Box()), _spec(), verify_note=lambda cid, q, r: "1#R1" if q == "rows" else None)
    assert [n["fact"] for n in run.notes] == ["jane.doe ran svc_kit.exe"]          # one row noted once
    reply = replies[-1]
    assert reply.startswith("noted 2") and "add item 2 came as str ('jane.doe ran a second tool')" in reply
    assert "send it as an object with fact, call_id, quote" in reply and run.end == "submitted"


def test_a_readers_list_sent_as_a_json_string_swaps_the_readers_in():
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "item_use_readers",
                                                                 {"names": json.dumps(["fmt.read_a"])})]),
                      ChatResponse(content="", tool_calls=[_call(2, "submit_x", {})])])
    spec = _spec()
    spec.menu = ["fmt.read_a", "fmt.read_b"]
    run = run_item(_agent(client, _Box()), spec)
    assert run.readers == ["fmt.read_a"] and "fmt.read_a" in client.asks[1]["tools"]


def test_a_forced_submit_records_every_object_and_names_the_string_without_a_read_round(monkeypatch):
    import agent.item_executor as X
    monkeypatch.setattr(X, "_budget", lambda: 10)                                  # forced at once
    findings = [{"statement": f"svc_kit.exe ran on CORP-WS01 at 2031-03-10 14:{i:02d}:00", "basis": []}
                for i in range(9)]
    findings.insert(3, "svc_kit.exe also ran on CORP-WS02")
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "submit_x", {"findings": findings})])])
    got = []
    spec = ItemSpec(kind="test", system="sys", user="item", core_tools=["table.table_grep"], submit=_LIST_SUBMIT)
    run = run_item(_agent(client, _Box()), spec, on_submit=lambda a, r, f: got.append(len(a["findings"])))
    assert got == [9] and run.end == "context_fit" and len(client.asks) == 1
    assert run.unread_entries == ["findings item 4 came as str ('svc_kit.exe also ran on CORP-WS02'): send it as an "
                                  "object with statement, basis"]


def test_a_submit_with_no_object_at_all_is_not_read_and_a_repaired_one_names_its_strings():
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "submit_x", {"findings": ["a", "b"]})]),
                      ChatResponse(content="", tool_calls=[_call(2, "submit_x", {"findings": [
                          {"statement": "svc_kit.exe ran", "basis": []}, "c"]})]),
                      ChatResponse(content="", tool_calls=[_call(3, "submit_x", {"findings": [
                          {"statement": "svc_kit.exe ran", "basis": []}]})])])
    replies, seen = _replies(client), []

    def on_submit(a, r, f):
        seen.append(len(a["findings"]))
        return "refused: repair it" if len(seen) == 1 else None
    spec = ItemSpec(kind="test", system="sys", user="item", core_tools=["table.table_grep"], submit=_LIST_SUBMIT)
    run = run_item(_agent(client, _Box()), spec, on_submit=on_submit)
    assert seen == [1, 1] and run.end == "submitted"
    assert "not read: findings item 1 came as str ('a')" in replies[1] and "none of it is an object" in replies[1]
    assert "refused: repair it Also not read: findings item 2 came as str ('c')" in replies[2]


def test_mistyped_notes_are_empty_rounds_that_reach_the_forced_round_never_an_error(monkeypatch):
    monkeypatch.setenv("ATLAS_ITEM_PATIENCE", "2,2")
    note = [_call(1, "item_note", {"add": ["jane.doe ran svc_kit.exe"]})]
    client = _Client([ChatResponse(content="", tool_calls=note) for _ in range(3)]
                     + [ChatResponse(content="", tool_calls=[_call(9, "submit_x", {})])])
    run = run_item(_agent(client, _Box()), _spec(), verify_note=lambda cid, q, r: "1#R1")
    assert run.end == "forced" and client.asks[-1]["tool_choice"] == "required"


_SHAPES = {"A": lambda v: json.dumps(v), "B": lambda v: ["jane.doe ran svc_kit.exe", "CORP-WS01"],
           "C": lambda v: v[0] if v and isinstance(v[0], dict) else {"x": 1}}


import pytest  # noqa: E402


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("tool", ["item_note", "item_use_readers", "submit_x"])
def test_no_argument_shape_of_a_local_tool_raises_or_ends_the_item_in_error(tool, shape):
    value = {"item_note": [_NOTE], "item_use_readers": ["fmt.read_a"],
             "submit_x": [{"statement": "svc_kit.exe ran", "basis": []}]}[tool]
    key = {"item_note": "add", "item_use_readers": "names", "submit_x": "findings"}[tool]
    first = [_call(1, tool, {key: _SHAPES[shape](value)})]
    client = _Client([ChatResponse(content="", tool_calls=first)] * 2
                     + [ChatResponse(content="", tool_calls=[_call(9, "submit_x", {})])] * 2)
    spec = ItemSpec(kind="test", system="sys", user="item", core_tools=["table.table_grep"], submit=_LIST_SUBMIT,
                    menu=["fmt.read_a"])
    run = run_item(_agent(client, _Box()), spec, verify_note=lambda cid, q, r: "1#R1")
    assert run.end in ("submitted", "forced", "stuck", "context_fit")


def test_a_stamped_python_result_is_the_items_call_and_a_replay_of_it_is_a_reread(monkeypatch):
    """Every dict result carries its call id first; the item registers the call by it. A replay or pointer
    answer is another call's read: registered as seen, never as this item's own read."""
    read = json.dumps({"_atlas_call_id": 478, "success": True, "path": "analysis/f.bat", "call_id": 12,
                       "lines": ["@echo off"]}, indent=2)
    replies = iter([{"result": read, "kind": "ran", "ran_clean": True},
                    {"result": "[replayed from turn 1: identical call]\n" + read, "kind": "replayed"}])
    client = _Client([ChatResponse(content="", tool_calls=[_call(1, "strings.read_text", {"file_path": "f.bat"})]),
                      ChatResponse(content="", tool_calls=[_call(2, "strings.read_text", {"file_path": "f.bat"})]),
                      ChatResponse(content="", tool_calls=[_call(3, "submit_x", {})])])
    agent = _agent(client, _Box())
    monkeypatch.setattr(agent, "_call_once", lambda *a, **k: next(replies))
    spec = ItemSpec(kind="test", system="sys", user="item", core_tools=["strings.read_text"], submit=SUBMIT)
    run = run_item(agent, spec)
    assert run.calls == [478, 478] and run.ran_calls == [478]           # the content's call_id 12 never registers
    assert run.seen[478].startswith("[replayed")

def test_a_declined_request_ends_the_item_without_another_round():
    client = _Client([ChatResponse(content="", finish_reason="refusal", refusal={"category": "cyber"}),
                      ChatResponse(content="", tool_calls=[_call(1, "submit_x", {})])])
    run = run_item(_agent(client, _Box()), _spec())
    assert run.end == "declined" and run.rounds == 1 and len(client.asks) == 1
