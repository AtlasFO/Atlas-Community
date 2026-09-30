"""Tests for DAIR's server-side work-order enforcement.

These guarantee an active phase never leaves with an empty priority_tools and
that the Triage max-pass cap is enforced regardless of what the model returns.
"""
import pytest

# # dair backends are openai-compat/llmhub; no anthropic stub is
# needed here — and stubbing it would shadow the real module for sibling tests.
from tools import dair  # noqa: E402


@pytest.fixture
def clean_trace():
    """Snapshot and restore the shared execution-log entries around a test."""
    from core.execution_log import log
    saved = list(log._entries)
    log._entries.clear()
    yield log
    log._entries.clear()
    log._entries.extend(saved)


class TestDefaultWorkOrder:
    def test_pcap(self):
        assert dair._default_work_order("a suspicious.pcap")[0].startswith("net.")

    def test_pe(self):
        assert "misc.pe_scanner" in dair._default_work_order("PE32 EXE payload")

    def test_unknown_falls_back(self):
        assert dair._default_work_order("mystery") == dair._FALLBACK_WORK_ORDER

    def test_script_payload_uses_deob(self):
        order = dair._default_work_order("extracted a .hta with obfuscated JavaScript")
        assert "deob.decode_chain" in order

    def test_email_uses_parse_email_first(self):
        order = dair._default_work_order("a phishing .eml attachment")
        assert order[0] == "misc.parse_email"


class TestFindingsNudge:
    def test_lagging_true_when_no_findings(self, clean_trace):
        clean_trace._entries.extend(
            [{"type": "tool_call"} for _ in range(15)])
        assert dair._findings_lagging() is True

    def test_not_lagging_below_threshold(self, clean_trace):
        # Threshold is 4 tool calls (belief-starvation early nudge).
        clean_trace._entries.extend([{"type": "tool_call"} for _ in range(3)])
        assert dair._findings_lagging() is False

    def test_not_lagging_when_findings_keep_pace(self, clean_trace):
        clean_trace._entries.extend([{"type": "tool_call"} for _ in range(15)])
        clean_trace._entries.extend([{"type": "finding"} for _ in range(5)])
        assert dair._findings_lagging() is False


class TestEnforceWorkOrder:
    def test_report_phase_exempt(self):
        a = {"current_phase": "Report"}
        tools, note = dair._enforce_work_order(a, {"priority_tools": []}, "", "")
        assert tools == [] and note == ""

    def test_empty_triage_gets_default(self, clean_trace):
        a = {"current_phase": "Triage", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": []}, "a .pcap file", "phishing")
        assert note == "default_fallback"
        assert tools and tools[0].startswith("net.")

    def test_empty_prefers_reason_merge(self, clean_trace):
        clean_trace._entries.append({
            "type": "reason_call", "tool": "reason_plan",
            "directives": {"priority_tools": ["net.http_session_inventory",
                                              "hash.hash_file"]}})
        a = {"current_phase": "Collect", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(a, {"priority_tools": []}, "s", "c")
        assert note == "reason_merge"
        assert tools == ["net.http_session_inventory", "hash.hash_file"]

    def test_non_empty_model_output_untouched(self, clean_trace):
        a = {"current_phase": "Triage", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["strings.stat_file"]}, "s", "c")
        assert tools == ["strings.stat_file"] and note == ""

    def test_triage_max_pass_cap_forces_collect(self, clean_trace):
        clean_trace._entries.extend([
            {"type": "dair_call", "current_phase": "Triage", "stack_action": "stay"},
            {"type": "dair_call", "current_phase": "Triage", "stack_action": "stay"},
        ])
        a = {"current_phase": "Triage", "stack_action": "stay",
             "transition_recommended": False}
        tools, note = dair._enforce_work_order(a, {"priority_tools": []},
                                               "pcap", "ctx")
        assert note == "triage_cap"
        assert a["transition_recommended"] is True
        assert a["next_phase"] == "Collect"
        assert a["stack_action"] == "push"

    def test_cap_not_triggered_when_stays_broken(self, clean_trace):
        clean_trace._entries.extend([
            {"type": "dair_call", "current_phase": "Triage", "stack_action": "stay"},
            {"type": "dair_call", "current_phase": "Collect", "stack_action": "push"},
        ])
        a = {"current_phase": "Triage", "stack_action": "stay",
             "transition_recommended": False}
        tools, note = dair._enforce_work_order(a, {"priority_tools": ["x.y"]},
                                               "s", "c")
        assert a["transition_recommended"] is False

    def test_oscillation_cap_forces_analyze(self, clean_trace):
        # 3 Triage→Collect round-trips + 3 findings: the 4th Collect
        # recommendation must be overridden to Analyze, or a run oscillates
        # through round-trips without Analyze ever being recommended.
        clean_trace._entries.extend(
            [{"type": "dair_call", "current_phase": "Triage",
              "next_phase": "Collect", "stack_action": "push"}] * 3
            + [{"type": "finding", "confidence": "LIKELY",
                "description": f"f{i}"} for i in range(3)])
        a = {"current_phase": "Triage", "stack_action": "push",
             "next_phase": "Collect", "transition_recommended": True}
        tools, note = dair._enforce_work_order(a, {"priority_tools": ["x.y"]},
                                               "s", "c")
        assert note == "oscillation_cap"
        assert a["next_phase"] == "Analyze"
        assert a["stack_action"] == "push"
        assert a["transition_recommended"] is True

    def test_oscillation_cap_needs_findings(self, clean_trace):
        # Round-trips without findings = genuinely still collecting; the
        # oscillation cap must not force Analyze on an empty record.
        clean_trace._entries.extend(
            [{"type": "dair_call", "current_phase": "Triage",
              "next_phase": "Collect", "stack_action": "push"}] * 4)
        a = {"current_phase": "Triage", "stack_action": "push",
             "next_phase": "Collect", "transition_recommended": True}
        tools, note = dair._enforce_work_order(a, {"priority_tools": ["x.y"]},
                                               "s", "c")
        assert note != "oscillation_cap"
        assert a["next_phase"] == "Collect"


def _barren_cycle(phase, tools):
    """One prior dair_assess cycle: same phase/stay with the given work order,
    followed by successful tool calls that recorded nothing."""
    return [
        {"type": "dair_call", "current_phase": phase, "stack_action": "stay",
         "directives": {"priority_tools": list(tools)}},
        {"type": "tool_call", "tool": tools[0], "success": True},
        {"type": "tool_call", "tool": tools[-1], "success": True},
    ]


class TestEmptyLoopValve:
    """The success-but-empty stall: identical work order re-issued while its
    tools SUCCEED and no finding lands (a strings.* rabbit-hole is the
    typical shape). The evidence-exhaustion valve never fires there because
    nothing fails."""

    ORDER = ["strings.strings_extract", "hash.hash_file"]

    def test_fallback_is_not_a_strings_dump(self):
        # Re-prescribing strings_extract as the escape hatch would re-create
        # the loop; the last-resort order must be an inventory sweep.
        assert "strings.strings_extract" not in dair._FALLBACK_WORK_ORDER

    def test_third_barren_cycle_forces_advance(self, clean_trace):
        clean_trace._entries.extend(
            _barren_cycle("Collect", self.ORDER) * 2)
        a = {"current_phase": "Collect", "stack_action": "stay",
             "transition_recommended": False}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": list(self.ORDER)}, "s", "c")
        assert note == "empty_loop"
        assert a["transition_recommended"] is True
        assert a["next_phase"] == "Analyze"
        assert a["stack_action"] == "push"

    def test_finding_resets_the_valve(self, clean_trace):
        entries = _barren_cycle("Collect", self.ORDER) * 2
        entries.insert(3, {"type": "finding", "confidence": "LIKELY",
                           "description": "progress"})
        clean_trace._entries.extend(entries)
        a = {"current_phase": "Collect", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": list(self.ORDER)}, "s", "c")
        assert note != "empty_loop"

    def test_changed_work_order_resets_the_valve(self, clean_trace):
        clean_trace._entries.extend(
            _barren_cycle("Collect", self.ORDER)
            + _barren_cycle("Collect", ["net.tcpdump_read"]))
        a = {"current_phase": "Collect", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": list(self.ORDER)}, "s", "c")
        assert note != "empty_loop"

    def test_fires_on_the_effective_fallback_order(self, clean_trace):
        # The observed failure mode exactly: the model keeps emitting an
        # empty list and the deterministic fallback re-prescribes the same
        # sweep every cycle. The valve must compare against the effective
        # work order, not the (empty) model output.
        fallback = list(dair._FALLBACK_WORK_ORDER)
        clean_trace._entries.extend(_barren_cycle("Collect", fallback) * 2)
        a = {"current_phase": "Collect", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": []}, "mystery", "mystery")
        assert note == "empty_loop"
        assert a["next_phase"] == "Analyze"
        assert tools == fallback  # the fill still supplies a work order

    def test_not_in_triage(self, clean_trace):
        # Triage has its own max-pass cap; the empty-loop valve is scoped to
        # the later phases where that cap can't help.
        clean_trace._entries.extend(_barren_cycle("Triage", self.ORDER) * 2)
        a = {"current_phase": "Triage", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": list(self.ORDER)}, "s", "c")
        assert note != "empty_loop"


def _stalled_cycle(phase, progress_changed):
    """One prior dair_call entry recording a progress verdict, as
    core.progress_signature would have stored it."""
    return {
        "type": "dair_call", "current_phase": phase, "stack_action": "stay",
        "progress": {"changed": progress_changed},
    }


class TestProductiveStallValve:
    """The general fix: successful, VARIED tool calls that keep succeeding
    while the knowledge state itself stops changing. (3b)/(3c) don't catch
    this — nothing fails, and the work order isn't identical each time."""

    def test_third_stalled_cycle_forces_advance(self, clean_trace):
        clean_trace._entries.extend([
            _stalled_cycle("Collect", False),
            _stalled_cycle("Collect", False),
        ])
        a = {"current_phase": "Collect", "stack_action": "stay",
             "transition_recommended": False}
        # Different tools each call (unlike the empty-loop scenario) — no
        # work-order repetition, so (3c) must not be what fires here.
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.query_a"]}, "s", "c")
        assert note == "productive_stall"
        assert a["transition_recommended"] is True
        assert a["next_phase"] == "Analyze"
        assert a["stack_action"] == "push"

    def test_progress_resets_the_valve(self, clean_trace):
        clean_trace._entries.extend([
            _stalled_cycle("Collect", False),
            _stalled_cycle("Collect", True),  # progress landed since
        ])
        a = {"current_phase": "Collect", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.query_b"]}, "s", "c")
        assert note != "productive_stall"

    def test_not_in_triage(self, clean_trace):
        # Triage has its own dedicated caps (oscillation/max-pass); the
        # productive-stall valve is scoped to the later phases.
        clean_trace._entries.extend([
            _stalled_cycle("Triage", False),
            _stalled_cycle("Triage", False),
        ])
        a = {"current_phase": "Triage", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.query_a"]}, "s", "c")
        assert note != "productive_stall"

    def test_report_phase_exempt_from_progress_gating(self, clean_trace):
        clean_trace._entries.extend([
            _stalled_cycle("Report", False),
            _stalled_cycle("Report", False),
        ])
        a = {"current_phase": "Report"}
        tools, note = dair._enforce_work_order(a, {"priority_tools": []}, "s", "c")
        assert tools == [] and note == ""
        # Progress is still computed/attached for Report cycles (telemetry),
        # just never used to gate the (exempt) work order.
        assert "progress" in a

    def test_assessment_carries_explainable_progress(self, clean_trace):
        a = {"current_phase": "Collect", "stack_action": "stay"}
        dair._enforce_work_order(a, {"priority_tools": ["table.query_a"]}, "s", "c")
        assert "progress" in a
        assert "changed" in a["progress"]
        assert "reasons" in a["progress"]
        # Internal snapshot travels for record_dair_call but isn't meant for
        # the LLM-facing assessment surface long-term; dair_assess() (not
        # _enforce_work_order) is responsible for stripping it before return.
        assert "_progress_snapshot" in a

    def test_new_finding_prevents_stall_from_triggering(self, clean_trace):
        # Two prior "stalled" cycles, but a finding landed since the last one
        # — the fresh progress_signature.snapshot() computed inside THIS call
        # must reflect that and report changed=True, keeping the valve off
        # even though the trailing dair_call history still shows changed=False.
        clean_trace._entries.extend([
            _stalled_cycle("Collect", False),
            _stalled_cycle("Collect", False),
            {"type": "finding", "call_id": 99, "confidence": "LIKELY",
             "description": "new lead", "linked_call_id": 5},
        ])
        a = {"current_phase": "Collect", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.query_a"]}, "s", "c")
        assert note != "productive_stall"
        assert a["progress"]["changed"] is True


class TestCollectCapWaitsForABarrenPass:
    """The Collect pass count alone does not end collection: a pass that
    still records progress keeps the phase, the first barren pass past the
    count ends it."""

    def _three_productive_stays(self, clean_trace):
        clean_trace._entries.extend([
            _stalled_cycle("Collect", True),
            _stalled_cycle("Collect", True),
            _stalled_cycle("Collect", True),
        ])

    def test_a_productive_fourth_pass_keeps_collecting(self, clean_trace):
        self._three_productive_stays(clean_trace)
        clean_trace._entries.append(
            {"type": "finding", "call_id": 7, "confidence": "LIKELY",
             "description": "new lead from this pass", "linked_call_id": 5})
        a = {"current_phase": "Collect", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.query_a"]}, "s", "c")
        assert note != "collect_cap"
        assert a.get("transition_recommended") is not True
        assert a["progress"]["changed"] is True

    def test_a_barren_fourth_pass_is_capped(self, clean_trace):
        self._three_productive_stays(clean_trace)
        a = {"current_phase": "Collect", "stack_action": "stay"}
        tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.query_a"]}, "s", "c")
        assert note == "collect_cap"
        assert a["transition_recommended"] is True
        assert a["next_phase"] == "Analyze"


class TestValveArbitration:
    """Advance valves are evaluated independently and arbitrated by specificity.
    A more specific diagnosis must win when multiple valves apply — never rely
    on elif ordering (the evidence_exhausted / productive_stall failure class).
    """

    def test_select_valve_prefers_lower_specificity(self):
        from tools.dair import _ValveCandidate, _select_valve
        a = _ValveCandidate("productive_stall", "Analyze", "general")
        b = _ValveCandidate("evidence_exhausted", "Analyze", "specific")
        c = _ValveCandidate("empty_loop", "Analyze", "pattern")
        assert _select_valve([a, b, c]).note == "evidence_exhausted"
        assert _select_valve([a, c]).note == "empty_loop"
        assert _select_valve([a]).note == "productive_stall"
        assert _select_valve([]) is None

    def test_evidence_exhausted_outranks_productive_stall_when_both_apply(
            self, clean_trace):
        """Modern traces carry progress on every dair_call. Missing-evidence
        failures + stalled progress must yield evidence_exhausted (specific),
        not productive_stall (general) — the shadowing bug class."""
        clean_trace._entries.extend([
            _stalled_cycle("Collect", False),
            _stalled_cycle("Collect", False),
            _stalled_cycle("Collect", False),
        ])
        for i in range(3):
            clean_trace._entries.append({
                "call_id": 5000 + i, "type": "tool_call",
                "cmd": "net.tcpdump_read", "mcp_tool": "net.tcpdump_read",
                "success": False,
                "stderr": "No such file or directory: capture.pcap",
                "failure_class": "tool_error",
            })
        a = {"current_phase": "Collect", "stack_action": "stay",
             "transition_recommended": False, "next_phase": ""}
        _tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["net.tcpdump_read"]}, "missing pcap", "ctx")
        assert note == "evidence_exhausted", (
            f"expected evidence_exhausted to outrank productive_stall, got {note!r}")
        assert a["next_phase"] == "Analyze"
        assert a["stack_action"] == "push"

    def test_evidence_exhausted_outranks_empty_loop_when_both_apply(
            self, clean_trace):
        wo = ["net.tcpdump_read"]
        for _ in range(3):
            clean_trace._entries.append({
                "type": "dair_call", "current_phase": "Collect",
                "stack_action": "stay",
                "directives": {"priority_tools": list(wo)},
                "progress": {"changed": False},
            })
        for i in range(3):
            clean_trace._entries.append({
                "call_id": 6000 + i, "type": "tool_call",
                "cmd": "net.tcpdump_read", "success": False,
                "stderr": "No such file or directory: /evidence/c2.pcap",
            })
        a = {"current_phase": "Collect", "stack_action": "stay",
             "transition_recommended": False, "next_phase": ""}
        _tools, note = dair._enforce_work_order(
            a, {"priority_tools": list(wo)}, "missing", "ctx")
        assert note == "evidence_exhausted"

    def test_productive_stall_still_wins_without_missing_evidence(
            self, clean_trace):
        """Varied successful tools, no missing-file failures
        — productive_stall remains the correct diagnosis."""
        clean_trace._entries.extend([
            _stalled_cycle("Collect", False),
            _stalled_cycle("Collect", False),
        ])
        a = {"current_phase": "Collect", "stack_action": "stay",
             "transition_recommended": False}
        _tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.query_a"]}, "s", "c")
        assert note == "productive_stall"

    def test_analyze_productive_stall_is_soft_hint_only(self, clean_trace):
        """B0/X5: Analyze stall must not hard-force Scan (phase thrash)."""
        clean_trace._entries.extend([
            _stalled_cycle("Analyze", False),
            _stalled_cycle("Analyze", False),
        ])
        a = {"current_phase": "Analyze", "stack_action": "stay",
             "transition_recommended": False, "next_phase": ""}
        _tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["table.query_a"]}, "s", "c")
        assert note == "productive_stall_hint"
        assert a.get("stack_action") == "stay"
        assert a.get("transition_recommended") is not True
        assert a.get("next_phase") in ("", None)

    def test_analyze_evidence_exhausted_is_soft_hint(self, clean_trace):
        """X11: Analyze missing-file storms must not hard-push Scan."""
        clean_trace._entries.extend([
            _stalled_cycle("Analyze", False),
            _stalled_cycle("Analyze", False),
            _stalled_cycle("Analyze", False),
        ])
        for i in range(3):
            clean_trace._entries.append({
                "call_id": 7000 + i, "type": "tool_call",
                "cmd": "ez.evtxecmd", "mcp_tool": "ez.evtxecmd",
                "success": False,
                "stderr": "No such file or directory: Security.evtx",
                "failure_class": "tool_error",
            })
        a = {"current_phase": "Analyze", "stack_action": "stay",
             "transition_recommended": False, "next_phase": ""}
        _tools, note = dair._enforce_work_order(
            a, {"priority_tools": ["ez.evtxecmd"]}, "missing evtx", "ctx")
        assert note == "evidence_exhausted_hint"
        assert a.get("stack_action") == "stay"
        assert a.get("next_phase") in ("", None)
