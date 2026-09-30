"""Agent.run_chat_turn — the single-turn tool-calling loop shared by the CLI
REPL (chat) and the dashboard chat worker. Driven with stub client/toolbox so
no LLM Hub or MCP server is needed. UI(quiet=True) degrades to plain mode, so
this runs with or without rich installed."""
from agent.loop import Agent
from agent.tui import UI


class _ToolCall:
    def __init__(self, id, name, arguments):
        self.id = id
        self.name = name
        self.arguments = arguments


class _Resp:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


class _Client:
    """Yields a fixed script of responses, one per chat() call."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def chat(self, messages, tools=None):
        self.calls += 1
        return self._responses.pop(0)


class _Toolbox:
    def __init__(self):
        self.called = []

    def openai_tools(self):
        return []

    def call(self, name, args):
        self.called.append((name, args))
        return (f"result of {name}", False)


def _agent(client, toolbox):
    a = Agent(client=client, toolbox=toolbox, case_dir=None, ui=UI(quiet=True))
    a.messages = [{"role": "system", "content": "sys"}]
    return a


def test_direct_text_answer():
    client = _Client([_Resp(content="hello there")])
    a = _agent(client, _Toolbox())
    events = []
    out = a.run_chat_turn("hi", on_event=events.append)
    assert out == "hello there"
    assert [m["role"] for m in a.messages] == ["system", "user", "assistant"]
    assert [e["type"] for e in events] == ["assistant"]
    assert events[-1]["text"] == "hello there"


def test_tool_then_answer():
    tb = _Toolbox()
    client = _Client([
        _Resp(tool_calls=[_ToolCall("c1", "hash_hash_file", {"path": "x"})]),
        _Resp(content="the hash is abc"),
    ])
    a = _agent(client, tb)
    events = []
    out = a.run_chat_turn("hash the file", on_event=events.append)
    assert out == "the hash is abc"
    # system, user, assistant(tool_calls), tool, assistant(text)
    assert [m["role"] for m in a.messages] == \
        ["system", "user", "assistant", "tool", "assistant"]
    assert tb.called == [("hash_hash_file", {"path": "x"})]
    assert [e["type"] for e in events] == ["tool_call", "assistant"]
    assert events[0]["name"] == "hash_hash_file"


def test_atlas_finish_is_not_surfaced_as_a_tool():
    tb = _Toolbox()
    client = _Client([
        _Resp(tool_calls=[_ToolCall("f1", "atlas_finish", {})]),
        _Resp(content="done"),
    ])
    a = _agent(client, tb)
    events = []
    out = a.run_chat_turn("wrap up", on_event=events.append)
    assert out == "done"
    assert tb.called == []  # atlas_finish never hits the toolbox
    assert [e["type"] for e in events] == ["assistant"]


def test_works_without_on_event_callback():
    client = _Client([_Resp(content="ok")])
    a = _agent(client, _Toolbox())
    assert a.run_chat_turn("hi") == "ok"


def test_user_message_recorded_before_the_model_call():
    client = _Client([_Resp(content="ok")])
    a = _agent(client, _Toolbox())
    a.run_chat_turn("remember this")
    assert a.messages[1] == {"role": "user", "content": "remember this"}


def test_tool_round_cap_emits_error_instead_of_silent_empty(monkeypatch):
    import agent.loop as loop_mod
    monkeypatch.setattr(loop_mod, "CHAT_MAX_TOOL_ROUNDS", 2)
    tb = _Toolbox()
    client = _Client([
        _Resp(tool_calls=[_ToolCall("c1", "hash_hash_file", {"path": "a"})]),
        _Resp(tool_calls=[_ToolCall("c2", "hash_hash_file", {"path": "b"})]),
        # Would be round 3 — must not be consumed once the cap is hit.
        _Resp(content="should not reach"),
    ])
    a = _agent(client, tb)
    events = []
    out = a.run_chat_turn("keep going", on_event=events.append)
    assert "Stopped after 2 tool rounds" in out
    assert client._responses  # third response unused
    assert any(e.get("type") == "error" for e in events)
    assert not any(e.get("type") == "assistant" for e in events)


def test_unlimited_tool_rounds_when_cap_is_zero(monkeypatch):
    import agent.loop as loop_mod
    monkeypatch.setattr(loop_mod, "CHAT_MAX_TOOL_ROUNDS", 0)
    # More than the old hard-coded 40 would have allowed — use 5 for speed.
    responses = [
        _Resp(tool_calls=[_ToolCall(f"c{i}", "hash_hash_file", {"path": str(i)})])
        for i in range(5)
    ]
    responses.append(_Resp(content="finally done"))
    client = _Client(responses)
    a = _agent(client, _Toolbox())
    events = []
    out = a.run_chat_turn("dig", on_event=events.append)
    assert out == "finally done"
    assert events[-1] == {"type": "assistant", "text": "finally done"}


def test_recovers_pseudo_xml_tool_call_in_content():
    """Model wrote <tool_call>name(...)</tool_call> in content — recover."""
    tb = _Toolbox()
    client = _Client([
        _Resp(content=(
            "Checking the file."
            "<tool_call>hash_hash_file({\"path\": \"x\"})</arg_value></tool_call>"
        )),
        _Resp(content="the hash is abc"),
    ])
    a = _agent(client, tb)
    events = []
    out = a.run_chat_turn("hash it", on_event=events.append)
    assert out == "the hash is abc"
    assert tb.called == [("hash_hash_file", {"path": "x"})]
    assert any(e.get("type") == "tool_call"
               and e.get("name") == "hash_hash_file" for e in events)


def test_recovers_atlas_load_namespaces_list_form():
    tb = _Toolbox()
    tb.load = lambda ns: list(ns)  # type: ignore[attr-defined]
    # Agent._handle_meta routes atlas_load_namespaces through load_with_budget
    # (the tool-schema budget), so the double has to answer that shape, not
    # just load(). Mirrors Toolbox.load_with_budget's return contract.
    tb.load_with_budget = lambda ns: {  # type: ignore[attr-defined]
        "loaded": list(ns),
        "newly_loaded": list(ns),
        "refused": [],
        "unknown": [],
        "schema_count": 0,
        "max": 128,
    }
    tb.namespace_summary = lambda: "ok"  # type: ignore[attr-defined]
    client = _Client([
        _Resp(content=(
            "<tool_call>atlas_load_namespaces([\"strings\", \"table\"])"
            "</arg_value></tool_call>"
        )),
        _Resp(content="ready"),
    ])
    a = _agent(client, tb)
    events = []
    out = a.run_chat_turn("load ns", on_event=events.append)
    assert out == "ready"
    assert any(e.get("name") == "atlas_load_namespaces" for e in events
               if e.get("type") == "tool_call")


class _EndlessPseudoClient:
    """Always answers with a *recoverable* pseudo tool call and never with a
    plain answer — the shape that used to loop forever when
    ATLAS_CHAT_MAX_TOOL_ROUNDS is 0 (the default)."""

    def __init__(self):
        self.calls = 0

    def chat(self, messages, tools=None):
        self.calls += 1
        return _Resp(content="<tool_call>hash_hash_file(path=x)</tool_call>")


def test_endless_recoverable_pseudo_calls_terminate():
    from agent import loop as loop_mod

    client = _EndlessPseudoClient()
    a = _agent(client, _Toolbox())
    a.run_chat_turn("go")  # must return rather than spin
    # Bounded by the recovery ceiling plus the (≤2) nudge rounds that follow
    # it, not by the unlimited round budget.
    assert client.calls <= loop_mod._CHAT_MAX_PSEUDO_RECOVERIES + 4


def test_nudges_when_pseudo_tool_unparseable():
    client = _Client([
        _Resp(content="<tool_call>???broken???"),
        _Resp(content="ok after nudge"),
    ])
    a = _agent(client, _Toolbox())
    events = []
    out = a.run_chat_turn("go", on_event=events.append)
    assert out == "ok after nudge"
    # user nudge injected between the broken assistant and the retry
    roles = [m["role"] for m in a.messages]
    assert roles.count("user") >= 2


# ── a chat is not a run: it leaves none of a run's state in the case ──────

def _case_agent(client, toolbox, case_dir, command):
    a = Agent(client=client, toolbox=toolbox, case_dir=case_dir,
              ui=UI(quiet=True), command=command)
    a.messages = [{"role": "system", "content": "sys"}]
    return a


def test_chat_tool_round_writes_no_run_status(tmp_path):
    client = _Client([
        _Resp(tool_calls=[_ToolCall("c1", "hash_hash_file", {"path": "x"})]),
        _Resp(content="the hash is abc"),
    ])
    a = _case_agent(client, _Toolbox(), tmp_path, "chat")
    assert a.run_chat_turn("hash it") == "the hash is abc"
    assert not (tmp_path / ".atlas" / "run_status.json").exists()
    names = [p.name for p in (tmp_path / "analysis").iterdir()]
    assert names and all(n.startswith("chat_transcript_") for n in names)


def test_run_tool_round_writes_run_status(tmp_path):
    # The guard is on the command, not on tool calls in general.
    import json
    import os
    a = _case_agent(_Client([]), _Toolbox(), tmp_path, "run")
    a._run_tool(_ToolCall("c1", "hash_hash_file", {"path": "x"}))
    status = json.loads((tmp_path / ".atlas" / "run_status.json").read_text())
    assert status["stopped_reason"] == "running"
    assert status["pid"] == os.getpid()
    assert a.transcript_path.name.startswith("agent_transcript_")


# ── an empty reply is asked again, never shown as the answer ──────────────

def test_empty_reply_is_nudged_then_answered():
    client = _Client([
        _Resp(tool_calls=[_ToolCall("c1", "hash_hash_file", {"path": "x"})]),
        _Resp(content=""),          # no text, no call: the answer went nowhere
        _Resp(content="the hash is abc"),
    ])
    a = _agent(client, _Toolbox())
    events = []
    out = a.run_chat_turn("hash it", on_event=events.append)
    assert out == "the hash is abc"
    assert [e["type"] for e in events] == ["tool_call", "assistant"]
    assert events[-1]["text"] == "the hash is abc"
    nudges = [m for m in a.messages
              if m["role"] == "user" and m["content"].startswith("[empty reply]")]
    assert len(nudges) == 1


def test_repeated_empty_replies_end_in_a_visible_error():
    from agent import loop as loop_mod
    n = loop_mod.EMPTY_REPLY_NUDGES_MAX
    client = _Client([_Resp(content="") for _ in range(n + 1)]
                     + [_Resp(content="never asked")])
    a = _agent(client, _Toolbox())
    events = []
    out = a.run_chat_turn("go", on_event=events.append)
    assert client.calls == n + 1
    assert [e["type"] for e in events] == ["error"]
    assert "empty" in events[0]["message"] and "empty" in out
