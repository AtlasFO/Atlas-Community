"""Text-form tool calls in XML dialects are recovered, and a CONFIRMED
claim refused twice without an evaluation in between is downgraded."""
from agent.loop import Agent
from tools import misc


def _agent():
    return object.__new__(Agent)


def test_arg_key_arg_value_dialect_is_recovered():
    text = ("Let me hash the file.<tool_call>hash_hash_file<arg_key>file_path</arg_key>"
            "<arg_value>exports/x.bin</arg_value></tool_call>")
    calls = _agent()._recover_tool_calls_from_content(text)
    assert [(c.name, c.arguments) for c in calls] == [("hash_hash_file", {"file_path": "exports/x.bin"})]


def test_function_parameter_dialect_with_typed_values():
    text = ("<tool_call><function=strings_strings_grep><parameter=path>evidence/a.log</parameter>"
            "<parameter=max_results>50</parameter><parameter=patterns>[\"a\", \"b\"]</parameter>"
            "</function></tool_call>")
    calls = _agent()._recover_tool_calls_from_content(text)
    assert len(calls) == 1
    assert calls[0].name == "strings_strings_grep"
    assert calls[0].arguments == {"path": "evidence/a.log", "max_results": 50, "patterns": ["a", "b"]}


def test_prose_form_still_recovered_and_blocks_do_not_double_count():
    text = ("<tool_call>misc_list_evidence_dir<arg_key>path</arg_key><arg_value>evidence</arg_value>"
            "</tool_call> then <tool_call>atlas_load_namespaces([\"net\"])</tool_call>")
    calls = _agent()._recover_tool_calls_from_content(text)
    assert [c.name for c in calls] == ["misc_list_evidence_dir", "atlas_load_namespaces"]
    assert calls[1].arguments == {"namespaces": ["net"]}


def test_json_object_dialect_is_recovered():
    text = ('I will list the partitions.\n'
            '{\n  "tool": "tsk_mmls",\n  "arguments": {\n    "image": "evidence/a.dd"\n  }\n}')
    calls = _agent()._recover_tool_calls_from_content(text)
    assert [(c.name, c.arguments) for c in calls] == [("tsk_mmls", {"image": "evidence/a.dd"})]


def test_json_wire_shape_with_nested_function_is_recovered():
    text = '{"function": {"name": "hash_hash_file", "arguments": {"file_path": "exports/x.bin"}}}'
    calls = _agent()._recover_tool_calls_from_content(text)
    assert [(c.name, c.arguments) for c in calls] == [
        ("hash_hash_file", {"file_path": "exports/x.bin"})]


def test_json_arguments_serialised_twice_are_decoded():
    text = '{"tool": "strings_stat_file", "arguments": "{\\"path\\": \\"evidence/a.log\\"}"}'
    calls = _agent()._recover_tool_calls_from_content(text)
    assert [(c.name, c.arguments) for c in calls] == [
        ("strings_stat_file", {"path": "evidence/a.log"})]


def test_json_call_without_arguments_recovers_with_no_arguments():
    calls = _agent()._recover_tool_calls_from_content('{"tool": "coverage_coverage_report"}')
    assert [(c.name, c.arguments) for c in calls] == [("coverage_coverage_report", {})]


def test_a_bare_argument_object_names_no_tool_and_is_not_recovered():
    # The arguments alone, with nothing saying which tool they belong to.
    # Guessing from the last refused call would invent a call the model
    # never named.
    assert _agent()._recover_tool_calls_from_content('{"image": "evidence/a.dd"}') == []


def test_quoted_json_in_prose_is_not_mistaken_for_a_call():
    # A "name" key carries no tool intent: evidence a model quotes back is
    # full of them, and recovering those would fabricate calls.
    text = 'The registry value decoded to {"name": "svchost", "path": "C:\\\\Windows"}.'
    assert _agent()._recover_tool_calls_from_content(text) == []


def test_json_call_surrounded_by_prose_leaves_the_prose_behind():
    text = 'First {"tool": "misc_inventory_evidence", "arguments": {}} then I will assess.'
    calls = _agent()._recover_tool_calls_from_content(text)
    assert [(c.name, c.arguments) for c in calls] == [("misc_inventory_evidence", {})]


class _AliasToolbox:
    """Knows one tool under its listed name and its dotted playbook alias."""

    def resolve(self, name):
        return {"ns_tool": "ns_tool", "ns.tool": "ns_tool"}.get(name)


def test_recovered_call_is_stored_under_the_listed_name():
    """A call written under the playbook's dotted alias must enter the
    history under the name the tool list carries: a gateway drops a later
    function call to a name that is not in the list, and the loop then sees
    an empty turn."""
    agent = _agent()
    agent.toolbox = _AliasToolbox()
    calls = agent._recover_tool_calls_from_content('<tool_call>ns.tool(x="1")</tool_call>')
    assert [(c.name, c.arguments) for c in calls] == [("ns_tool", {"x": "1"})]


def test_recovered_call_prefers_the_listed_name_over_the_mcp_name():
    """The MCP name doubles its namespace; the list carries the single
    form, so that is what the history must show."""

    class _ListingToolbox:
        def resolve(self, name):
            return "ns_ns_tool" if name in ("ns_ns_tool", "ns.tool", "ns_tool") else None

        def listed_name(self, name):
            return "ns_tool" if self.resolve(name) else None

    agent = _agent()
    agent.toolbox = _ListingToolbox()
    calls = agent._recover_tool_calls_from_content("<tool_call>ns_ns_tool()</tool_call>")
    assert [c.name for c in calls] == ["ns_tool"]


def test_a_colon_separated_name_is_recovered():
    """A model that read "misc (…): start_execution_log" in the namespace
    summary writes ``misc:start_execution_log``; that is a call too."""
    calls = _agent()._recover_tool_calls_from_content(
        '<tool_call>ns:tool(case_id="X")<tool_call>ns:other()')
    assert [(c.name, c.arguments) for c in calls] == [("ns:tool", {"case_id": "X"}),
                                                       ("ns:other", {})]


def test_a_name_the_toolbox_does_not_know_is_kept():
    agent = _agent()
    agent.toolbox = _AliasToolbox()
    calls = agent._recover_tool_calls_from_content("<tool_call>other_tool()</tool_call>")
    assert [c.name for c in calls] == ["other_tool"]


class _Log:
    def __init__(self):
        self._entries = []


def _refusal():
    return {"gate": "evidence_strength", "detail_gate": "confirmed_requires_supported_evaluate",
            "error": "CONFIRMED tier requires a preceding reason.evaluate_finding call"}


def test_second_unevaluated_confirmed_attempt_downgrades(monkeypatch):
    log = _Log()
    assert misc._repeat_without_evaluation(_refusal(), "FTP creds used", "h1", log) is False
    log._entries.append({"type": "tool_call", "cmd": "strings"})
    assert misc._repeat_without_evaluation(_refusal(), "FTP creds  used", "H1", log) is True


def test_an_evaluation_in_between_resets_the_refusal(monkeypatch):
    log = _Log()
    assert misc._repeat_without_evaluation(_refusal(), "x", "", log) is False
    log._entries.append({"type": "reason_call", "tool": "reason_evaluate_finding"})
    assert misc._repeat_without_evaluation(_refusal(), "x", "", log) is False
    assert misc._repeat_without_evaluation(_refusal(), "x", "", log) is True


def test_other_failures_are_not_touched(monkeypatch):
    other = {"gate": "lineage_required", "error": "no lineage"}
    assert misc._repeat_without_evaluation(other, "x", "", _Log()) is False
    assert misc._repeat_without_evaluation(other, "x", "", _Log()) is False


def test_a_challenged_or_uncertain_review_is_never_downgraded_on_a_repeat(monkeypatch):
    for verdict in ("CHALLENGED", "UNCERTAIN"):
        log = _Log()
        refused = dict(_refusal(), evaluate_verdict=verdict,
                       error=f"CONFIRMED tier refused: the reason.evaluate_finding returned VERDICT: {verdict}")
        # A repeated review answered from the call memo adds no reason call.
        assert misc._repeat_without_evaluation(refused, "FTP creds used", "h1", log) is False
        assert misc._repeat_without_evaluation(refused, "FTP creds used", "h1", log) is False
