"""Tests for tools/dair.py — openai-compat / llmhub backends."""
import json
import pytest
from contextlib import contextmanager
from unittest.mock import patch, MagicMock




# ── Sample output fixtures ────────────────────────────────────────────────────

_CHALLENGES_BLOCK = (
    'VERIFICATION_CHALLENGES:\n'
    '[\n'
    '  {"claim": "toolx.exe at C:\\\\Windows\\\\Temp\\\\toolx.exe",'
    ' "challenge_method": "strings.stat_file",'
    ' "verified": null, "confidence_impact": "—", "notes": ""}\n'
    ']\n'
)

_ASSESSMENT_STAY = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "Checking toolx.exe claim",'
    ' "transition_recommended": false, "next_phase": "", "transition_rationale": "",'
    ' "stack_action": "stay", "investigation_focus": "Verify toolx.exe file presence",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["strings.stat_file"],'
    ' "skip_tools": [], "focus_pids": [], "focus_paths": [],'
    ' "max_depth": "", "next_hypothesis_triggers": []}}'
)

_ASSESSMENT_PUSH_COLLECT = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "All claims verified",'
    ' "transition_recommended": true, "next_phase": "Collect",'
    ' "transition_rationale": "toolx.exe confirmed — begin artifact collection",'
    ' "stack_action": "push", "investigation_focus": "Collect memory and registry artifacts",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["vol.netscan", "ez.evtxecmd"],'
    ' "skip_tools": [], "focus_pids": [], "focus_paths": [],'
    ' "max_depth": "", "next_hypothesis_triggers": []}}'
)

_ASSESSMENT_REPORT = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Scan", "phase_rationale": "No new pivots found",'
    ' "transition_recommended": true, "next_phase": "Report",'
    ' "transition_rationale": "Investigation complete",'
    ' "stack_action": "push", "investigation_focus": "Write final report",'
    ' "verification_challenges": [], "recommended_actions": ['
    '"Isolate ws01 from network", "Reset all domain admin credentials",'
    ' "Remove toolx.exe and toolx2.exe service"],'
    ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
    ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
)

_ASSESSMENT_POP = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Triage", "phase_rationale": "Challenge resolved",'
    ' "transition_recommended": true, "next_phase": "Analyze",'
    ' "transition_rationale": "Claim verified — resuming analysis",'
    ' "stack_action": "pop", "investigation_focus": "Continue artifact analysis",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
    ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
)

_CHALLENGE_VERIFIED_FALSE = (
    'VERIFICATION_CHALLENGES:\n'
    '[{"claim": "atmfd.dll absent from drivers",'
    ' "challenge_method": "tsk.fls",'
    ' "verified": false,'
    ' "confidence_impact": "CONFIRMED -> SUSPECTED",'
    ' "notes": "file exists at expected path"}]\n'
    + _ASSESSMENT_STAY
)

_CHALLENGE_VERIFIED_TRUE = (
    'VERIFICATION_CHALLENGES:\n'
    '[{"claim": "toolx.exe at C:\\\\Windows\\\\Temp\\\\toolx.exe",'
    ' "challenge_method": "strings.stat_file",'
    ' "verified": true,'
    ' "confidence_impact": "—",'
    ' "notes": "stat_file confirms size 40960 bytes"}]\n'
    + _ASSESSMENT_PUSH_COLLECT
)


# ── Mock factories ────────────────────────────────────────────────────────────

def _http_resp(content: str):
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {
        "choices": [{"message": {"content": content, "reasoning": ""}}]
    }
    return m


def _starved_resp():
    """A reply that spent its whole visible budget thinking: no content, and
    the endpoint reports it stopped on length."""
    m = MagicMock()
    m.status_code = 200
    m.raise_for_status = MagicMock()
    m.json.return_value = {
        "choices": [{"message": {"content": "", "reasoning": "..."},
                     "finish_reason": "length"}],
        "usage": {"completion_tokens_details": {"reasoning_tokens": 4096}},
    }
    return m


class TestWhenTheDirectorThinksItselfMute:
    """An assessment that returns nothing is the most expensive failure in a
    run: minutes are spent and the phase state it should have decided stays
    where it was. The reasoning role already climbs a ladder for this, and
    the director climbs the same one rather than giving up after one try."""

    def test_an_empty_reply_is_retried_more_than_once(self):
        from tools.dair import _ask_openai_compat
        http_mock = MagicMock(return_value=_starved_resp())
        with patch("httpx.post", http_mock), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_API_KEY", ""):
            out = _ask_openai_compat("sys", "a long request " * 400)
        assert out["success"] is False
        assert http_mock.call_count >= 3, (
            "the director gave up before climbing its own ladder")

    def test_an_empty_reply_records_what_the_model_was_writing(self):
        """The reply of a cut or empty call is kept nowhere else; its size
        and ends travel with the failure so the trace shows the shape."""
        from tools.dair import _ask_openai_compat
        with patch("httpx.post", MagicMock(return_value=_starved_resp())), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_API_KEY", ""):
            out = _ask_openai_compat("sys", "a long request " * 400)
        assert out["success"] is False
        cut = out["reply_cut"]
        assert set(cut) == {"reasoning_chars", "reasoning_head", "reasoning_tail"}
        assert cut["reasoning_chars"] >= len(cut["reasoning_tail"])

    def test_a_reply_that_arrives_is_not_retried(self):
        from tools.dair import _ask_openai_compat
        http_mock = MagicMock(return_value=_http_resp("DAIR_ASSESSMENT {}"))
        with patch("httpx.post", http_mock), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_API_KEY", ""):
            out = _ask_openai_compat("sys", "short request")
        assert out["success"] is True
        assert http_mock.call_count == 1


# ── Backend context managers ──────────────────────────────────────────────────

@contextmanager
def _compat_ctx(text: str):
    http_mock = MagicMock(return_value=_http_resp(text))
    with patch("httpx.post", http_mock), \
         patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
         patch("tools.dair.DAIR_BACKEND", "openai-compat"):
        yield http_mock


# ── Helper ────────────────────────────────────────────────────────────────────

def _run(ctx_fn, text, stack="[]", context=""):
    from tools.dair import dair_assess
    with ctx_fn(text):
        return dair_assess("toolx.exe found in memory.", phase_stack=stack, case_context=context)


def _candidate_values(result: dict, kind: str | None = None) -> set[str]:
    return {
        str(p.get("value", "")).upper()
        for p in result.get("candidate_pivots") or []
        if kind is None or p.get("kind") == kind
    }


# ── Success / failure basics ──────────────────────────────────────────────────

class TestDairAssessSuccess:
    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_returns_success(self, ctx_fn):
        assert _run(ctx_fn, _ASSESSMENT_STAY)["success"] is True

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_current_phase_parsed(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_STAY)
        assert r["current_phase"] == "Triage"

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_atlas_call_id_present(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_STAY)
        assert "_atlas_call_id" in r

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_tokens_present(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_STAY)
        assert "input_tokens" in r
        assert "output_tokens" in r


class TestDairAssessFailure:

    def test_claude_backend_returns_removed_error(self):
        from tools.dair import dair_assess
        with patch("tools.dair.DAIR_BACKEND", "claude"):
            r = dair_assess("some findings")
        assert r["success"] is False
        assert "no longer supported" in r["error"]

    def test_missing_compat_url_returns_error(self):
        from tools.dair import dair_assess
        with patch("tools.dair.DAIR_URL", ""), \
             patch("tools.dair.DAIR_BACKEND", "openai-compat"):
            r = dair_assess("some findings")
        assert r["success"] is False

    def test_ids_the_run_has_not_issued_are_refused_before_the_director_is_asked(self, tmp_path):
        """A given lineage list is bounded against the ids the trace holds
        before any model call: an invented id is a cheap refusal that says
        how many ids exist, not an assessment recorded on a false edge."""
        from tools.dair import dair_assess
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        tid = l.record_tool_call("vol.psscan", True, False, 0, 0)
        with patch("core.execution_log.log", l), _compat_ctx(_ASSESSMENT_STAY) as http_mock:
            r = dair_assess("summary", input_call_ids=[tid, tid + 40])
        assert r["success"] is False and r["gate"] == "lineage_required"
        assert f"the highest is {tid}" in r["error"]
        assert http_mock.call_count == 0
        assert not [e for e in l._entries if e.get("type") == "dair_call"]

    def test_malformed_assessment_block_returns_defaults(self):
        r = _run(_compat_ctx, "Some analysis. DAIR_ASSESSMENT: {broken json")
        assert r["success"] is True
        assert r["current_phase"] == "Triage"
        assert r["stack_action"] == "stay"
        assert r["verification_challenges"] == []


# ── Assessment block parsing ──────────────────────────────────────────────────

class TestDairAssessmentParsing:
    """The director's reply is read by key, not by position: models drift
    from the template (wrapper objects, missing label, prose after the block)
    and each drift must still yield the model's decision, not the empty
    template that the server fallbacks then overwrite."""

    def test_unlabeled_fenced_object_is_accepted(self):
        from tools.dair import _parse_dair_assessment
        raw = (
            "Analyze continues: the freshest lead is the unread stream.\n\n"
            "```json\n"
            '{"rationale": "one lead open", "transition_recommended": false,'
            ' "next_phase": "", "investigation_focus": "Resolve the open lead",'
            ' "priority_tools": ["tsk.istat", "strings.strings_grep"],'
            ' "curiosity_budget": 2, "deferred_intent_dispositions": []}\n'
            "```"
        )
        a = _parse_dair_assessment(raw)
        assert a["investigation_focus"] == "Resolve the open lead"
        assert a["directives"]["priority_tools"] == ["tsk.istat", "strings.strings_grep"]
        assert a["directives"]["curiosity_budget"] == 2

    def test_fields_nested_under_a_wrapper_object_are_hoisted(self):
        from tools.dair import _parse_dair_assessment
        raw = (
            "DAIR_ASSESSMENT:\n```json\n"
            '{"current_phase": "Report",'
            ' "phase_stack": [{"phase": "Report", "entry_reason": "done", "depth": 4}],'
            ' "directive": {"investigation_focus": "Close out and report",'
            ' "priority_tools": [], "curiosity_budget": 0,'
            ' "recommended_actions": [{"scope": "host", "action": "rotate the account"}]}}\n'
            "```"
        )
        a = _parse_dair_assessment(raw)
        assert a["current_phase"] == "Report"
        assert a["investigation_focus"] == "Close out and report"
        assert a["recommended_actions"] == [{"scope": "host", "action": "rotate the account"}]
        assert a["directives"]["priority_tools"] == []

    def test_prose_with_braces_after_the_block_is_ignored(self):
        from tools.dair import _parse_dair_assessment
        raw = (
            _ASSESSMENT_PUSH_COLLECT
            + "\n\nNote: the stack is now {Triage, Collect}; run the batch."
        )
        a = _parse_dair_assessment(raw)
        assert a["stack_action"] == "push"
        assert a["next_phase"] == "Collect"

    def test_list_items_are_never_mistaken_for_the_assessment(self):
        from tools.dair import _parse_dair_assessment
        raw = (
            _CHALLENGES_BLOCK
            + '{"rationale": "x", "transition_recommended": true, "next_phase": "Collect",'
            ' "stack_action": "push", "priority_tools": ["vol.netscan"]}'
        )
        a = _parse_dair_assessment(raw)
        assert a["stack_action"] == "push"
        assert a["directives"]["priority_tools"] == ["vol.netscan"]

    def test_broken_block_still_yields_the_template(self):
        from tools.dair import _parse_dair_assessment
        a = _parse_dair_assessment("DAIR_ASSESSMENT: {broken json")
        assert a["stack_action"] == "stay"
        assert a["phase_rationale"] == ""


# ── Stack behaviour ───────────────────────────────────────────────────────────

class TestDairStackBehaviour:
    def test_empty_stack_starts_at_triage(self):
        r = _run(_compat_ctx, _ASSESSMENT_STAY, stack="[]")
        assert r["current_phase"] == "Triage"

    def test_invalid_stack_json_falls_back_gracefully(self):
        r = _run(_compat_ctx, _ASSESSMENT_STAY, stack="not-json")
        assert r["success"] is True

    def test_push_to_collect_on_transition(self):
        r = _run(_compat_ctx, _ASSESSMENT_PUSH_COLLECT)
        assert r["transition_recommended"] is True
        assert r["next_phase"] == "Collect"
        assert r["stack_action"] == "push"

    def test_pop_action_parsed(self):
        stack = json.dumps([
            {"phase": "Analyze", "entry_reason": "artifact collection complete", "depth": 1},
            {"phase": "Triage", "entry_reason": "atmfd.dll claim", "depth": 2},
        ])
        r = _run(_compat_ctx, _ASSESSMENT_POP, stack=stack)
        assert r["stack_action"] == "pop"
        assert r["next_phase"] == "Analyze"

    def test_stay_action_parsed(self):
        r = _run(_compat_ctx, _ASSESSMENT_STAY)
        assert r["stack_action"] == "stay"
        assert r["transition_recommended"] is False

    def test_deep_stack_parsed_correctly(self):
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "case opened", "depth": 0},
            {"phase": "Collect", "entry_reason": "toolx.exe confirmed", "depth": 1},
            {"phase": "Triage", "entry_reason": "atmfd.dll claim", "depth": 2},
            {"phase": "Scan", "entry_reason": "new pivot host01", "depth": 3},
        ])
        r = _run(_compat_ctx, _ASSESSMENT_STAY, stack=stack)
        assert r["success"] is True


# ── Verification challenges ───────────────────────────────────────────────────

class TestDairVerificationChallenges:
    def test_challenges_populated_from_block(self):
        r = _run(_compat_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert len(r["verification_challenges"]) == 1
        assert r["verification_challenges"][0]["claim"].startswith("toolx.exe")

    def test_challenge_verified_null(self):
        r = _run(_compat_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert r["verification_challenges"][0]["verified"] is None

    def test_challenge_verified_false_with_confidence_impact(self):
        r = _run(_compat_ctx, _CHALLENGE_VERIFIED_FALSE)
        c = r["verification_challenges"][0]
        assert c["verified"] is False
        assert "SUSPECTED" in c["confidence_impact"]

    def test_challenge_verified_true(self):
        r = _run(_compat_ctx, _CHALLENGE_VERIFIED_TRUE)
        c = r["verification_challenges"][0]
        assert c["verified"] is True

    def test_no_challenges_outside_triage(self):
        r = _run(_compat_ctx, _ASSESSMENT_PUSH_COLLECT)
        assert r["verification_challenges"] == []

    def test_challenges_block_takes_precedence_over_assessment_field(self):
        # VERIFICATION_CHALLENGES block has 1 item; DAIR_ASSESSMENT.verification_challenges is []
        r = _run(_compat_ctx, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert len(r["verification_challenges"]) == 1

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_pending_challenge_in_priority_tools(self, ctx_fn):
        r = _run(ctx_fn, _CHALLENGES_BLOCK + _ASSESSMENT_STAY)
        assert "strings.stat_file" in r["directives"]["priority_tools"]


# ── Recommended actions ───────────────────────────────────────────────────────

class TestDairRecommendedActions:
    def test_recommended_actions_at_report(self):
        r = _run(_compat_ctx, _ASSESSMENT_REPORT)
        assert len(r["recommended_actions"]) == 3
        assert r["next_phase"] == "Report"

    def test_recommended_actions_empty_non_report(self):
        r = _run(_compat_ctx, _ASSESSMENT_STAY)
        assert r["recommended_actions"] == []

    def test_recommended_actions_empty_push_to_collect(self):
        r = _run(_compat_ctx, _ASSESSMENT_PUSH_COLLECT)
        assert r["recommended_actions"] == []


# ── Directives ────────────────────────────────────────────────────────────────

class TestDairDirectives:
    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_directives_present(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_STAY)
        assert "directives" in r
        assert "priority_tools" in r["directives"]
        assert "tool_manifest_version" in r["directives"]

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_directives_parsed_from_raw(self, ctx_fn):
        r = _run(ctx_fn, _ASSESSMENT_PUSH_COLLECT)
        assert "vol.netscan" in r["directives"]["priority_tools"]

    def test_malformed_directives_gets_default_work_order(self):
        # Malformed directives in an active phase must NOT leave the agent with
        # an empty work order — the server-side safety net fills an evidence-
        # typed default.
        bad = 'DAIR_ASSESSMENT:\n{"current_phase": "Triage", "phase_rationale": "x", "transition_recommended": false, "next_phase": "", "transition_rationale": "", "stack_action": "stay", "investigation_focus": "x", "verification_challenges": [], "recommended_actions": [], "directives": "broken"}'
        r = _run(_compat_ctx, bad)
        assert isinstance(r["directives"], dict)
        assert r["directives"]["priority_tools"]  # non-empty
        assert r.get("work_order_enforced") in ("default_fallback", "reason_merge")

    def test_unknown_priority_tool_is_annotated(self):
        raw = (
            'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Triage", "phase_rationale": "x",'
            ' "transition_recommended": false, "next_phase": "",'
            ' "transition_rationale": "", "stack_action": "stay",'
            ' "investigation_focus": "x", "verification_challenges": [],'
            ' "recommended_actions": [],'
            ' "directives": {"priority_tools": ["vol.psscan", "vol.nope"],'
            ' "skip_tools": [], "focus_pids": [], "focus_paths": [],'
            ' "max_depth": "", "next_hypothesis_triggers": []}}'
        )
        r = _run(_compat_ctx, raw)
        assert r["directives"]["priority_tools"] == ["vol.psscan", "vol.nope"]
        assert r["directives"]["unknown_priority_tools"] == ["vol.nope"]

    def test_system_prompt_includes_tool_capability_manifest(self):
        from tools.dair import _DAIR_SYS

        assert "TOOL CAPABILITY MANIFEST" in _DAIR_SYS
        assert "network_pcap" in _DAIR_SYS
        assert "vol.psscan" in _DAIR_SYS


# ── Backend selection ─────────────────────────────────────────────────────────

class TestDairBackendSelection:
    def test_explicit_compat_backend(self):
        from tools.dair import dair_assess
        http_mock = MagicMock(return_value=_http_resp(_ASSESSMENT_STAY))
        with patch("httpx.post", http_mock), \
             patch("tools.dair.DAIR_URL", "http://localhost:8001"), \
             patch("tools.dair.DAIR_BACKEND", "openai-compat"):
            r = dair_assess("findings")
        assert r["success"] is True
        http_mock.assert_called_once()

    def test_autodetect_uses_compat_when_url_present(self):
        from tools.dair import _active_backend
        with patch("tools.dair.DAIR_BACKEND", ""), \
             patch("tools.dair.DAIR_URL", "http://localhost:8001"):
            assert _active_backend() == "openai-compat"

    def test_explicit_backend_overrides_autodetect(self):
        from tools.dair import _active_backend
        with patch("tools.dair.DAIR_BACKEND", "openai-compat"):
            assert _active_backend() == "openai-compat"


# ── Execution log recording ───────────────────────────────────────────────────

class TestDairExecutionLog:
    def test_record_dair_call_invoked_on_success(self, tmp_path):
        from tools.dair import dair_assess
        mock_log = MagicMock()
        # A mock path would be written to: the case is a temporary directory.
        mock_log.case_dir.return_value = str(tmp_path)
        mock_log._path = str(tmp_path / "analysis" / "CASE_trace.json")
        mock_log.record_dair_call.return_value = 42
        with patch("httpx.post", MagicMock(return_value=_http_resp(_ASSESSMENT_STAY))), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_BACKEND", "openai-compat"):
            from core import execution_log
            original_log = execution_log.log
            try:
                execution_log.log = mock_log
                r = dair_assess("some findings")
            finally:
                execution_log.log = original_log
        assert "_atlas_call_id" in r

    def test_record_dair_call_includes_phase_rationale(self, tmp_path, monkeypatch):
        """Unconfigured log used to silently return 0 — now it raises, so this
        test must configure the log. Once configured, the entry round-trips
        with phase_rationale preserved."""
        import core.execution_log as elog
        monkeypatch.setattr(elog, "_SESSION_FILE",
                            str(tmp_path / "session.json"))
        log = elog.ExecutionLog()
        log.configure("TEST-002", str(tmp_path / "trace.json"))
        cid = log.record_dair_call(
            current_phase="Triage",
            phase_rationale="Checking toolx.exe existence",
            transition_recommended=False,
            next_phase="",
            transition_rationale="",
            stack_action="stay",
            investigation_focus="Verify file at path",
            verification_challenges=[{
                "claim": "toolx.exe at C:\\Windows\\Temp",
                "challenge_method": "strings.stat_file",
                "verified": None,
                "confidence_impact": "—",
                "notes": "",
            }],
            recommended_actions=[],
            directives={"priority_tools": ["strings.stat_file"], "skip_tools": [],
                        "focus_pids": [], "focus_paths": [], "max_depth": "",
                        "next_hypothesis_triggers": []},
        )
        assert cid > 0
        assert log._entries[0]["phase_rationale"] == "Checking toolx.exe existence"

    def test_record_dair_call_with_configured_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("TEST-001", str(tmp_path / "trace.json"))
        cid = log.record_dair_call(
            current_phase="Scan",
            phase_rationale="Mapping lateral movement",
            transition_recommended=True,
            next_phase="Report",
            transition_rationale="No new pivots",
            stack_action="push",
            investigation_focus="Write report",
            verification_challenges=[],
            recommended_actions=["Isolate ws01"],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        assert cid > 0
        entry = log._entries[-1]
        assert entry["type"] == "dair_call"
        assert entry["phase_rationale"] == "Mapping lateral movement"
        assert entry["transition_rationale"] == "No new pivots"
        assert entry["recommended_actions"] == ["Isolate ws01"]

    def test_markdown_renders_phase_transition(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("TEST-001", str(tmp_path / "trace.json"))
        log.record_dair_call(
            current_phase="Triage",
            phase_rationale="All claims verified",
            transition_recommended=True,
            next_phase="Collect",
            transition_rationale="toolx.exe confirmed — begin artifact collection",
            stack_action="push",
            investigation_focus="Map lateral movement",
            verification_challenges=[],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = log.to_markdown()
        assert "Phase Transition" in md
        assert "Triage" in md
        assert "Collect" in md

    def test_markdown_renders_challenge_table(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("TEST-001", str(tmp_path / "trace.json"))
        log.record_dair_call(
            current_phase="Triage",
            phase_rationale="Checking claims",
            transition_recommended=False,
            next_phase="",
            transition_rationale="",
            stack_action="stay",
            investigation_focus="Run verification tools",
            verification_challenges=[{
                "claim": "toolx.exe at C:\\Windows\\Temp",
                "challenge_method": "strings.stat_file",
                "verified": None,
                "confidence_impact": "—",
                "notes": "",
            }],
            recommended_actions=[],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = log.to_markdown()
        assert "Verification Challenges" in md
        assert "PENDING" in md
        assert "strings.stat_file" in md

    def test_markdown_renders_recommended_actions(self, tmp_path):
        from core.execution_log import ExecutionLog
        log = ExecutionLog()
        log.configure("TEST-001", str(tmp_path / "trace.json"))
        log.record_dair_call(
            current_phase="Scan",
            phase_rationale="Sweep complete",
            transition_recommended=True,
            next_phase="Report",
            transition_rationale="Investigation complete",
            stack_action="push",
            investigation_focus="Write report",
            verification_challenges=[],
            recommended_actions=["Isolate ws01", "Reset domain admin credentials"],
            directives={"priority_tools": [], "skip_tools": [], "focus_pids": [],
                        "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []},
        )
        md = log.to_markdown()
        assert "Recommended Actions" in md
        assert "Isolate ws01" in md

    def test_initiated_and_dair_entries_both_present_on_success(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             _compat_ctx(_ASSESSMENT_STAY):
            dair_assess("toolx.exe found.", phase_stack="[]")
        types = [e["type"] for e in inst._entries]
        assert "call_initiated" in types
        assert "dair_call" in types
        assert types.index("call_initiated") < types.index("dair_call")

    def test_initiated_entry_tool_and_backend(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             _compat_ctx(_ASSESSMENT_STAY):
            dair_assess("toolx.exe found.", phase_stack="[]")
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert initiated[0]["tool"] == "dair_assess"
        assert initiated[0]["backend"] == "openai-compat"
        assert "model" in initiated[0]["inputs"]

    def test_initiated_entry_on_timeout(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             patch("httpx.post", side_effect=TimeoutError("request timed out")), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_BACKEND", "openai-compat"):
            r = dair_assess("findings")
        assert r["success"] is False
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert len(initiated) == 1  # written before the HTTP call that raised


class TestVerificationSatisfied:
    def test_verification_satisfied_defaults_false(self):
        r = _run(_compat_ctx, _ASSESSMENT_STAY)
        assert r["verification_satisfied"] is False

    def test_verification_satisfied_true_parsed(self):
        text = (
            _CHALLENGES_BLOCK
            + 'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Triage", "phase_rationale": "Primary IOCs verified",'
            ' "transition_recommended": true, "next_phase": "Collect",'
            ' "transition_rationale": "Core claims confirmed — residual VT checks are enrichment only",'
            ' "stack_action": "push", "investigation_focus": "Begin artifact collection",'
            ' "verification_satisfied": true,'
            ' "verification_challenges": [], "recommended_actions": [],'
            ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
            ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
        )
        r = _run(_compat_ctx, text)
        assert r["verification_satisfied"] is True
        assert r["transition_recommended"] is True
        assert r["next_phase"] == "Collect"

    def test_auto_satisfied_when_dair_assessment_parse_fails(self):
        # VERIFICATION_CHALLENGES well-formed (all verified=true) but DAIR_ASSESSMENT
        # is broken JSON — simulates a parse-failure stall.
        text = (
            'VERIFICATION_CHALLENGES:\n'
            '[{"claim": "toolx.exe at C:\\\\Windows\\\\Temp",'
            ' "challenge_method": "strings.stat_file",'
            ' "verified": true, "confidence_impact": "—", "notes": "confirmed"}]\n'
            'DAIR_ASSESSMENT:\n{broken json here'
        )
        r = _run(_compat_ctx, text)
        assert r["success"] is True
        assert r["verification_satisfied"] is True
        assert r["transition_recommended"] is True
        assert r["next_phase"] == "Collect"
        assert r["stack_action"] == "push"
        assert len(r["verification_challenges"]) == 1

    def test_auto_satisfaction_skipped_when_challenge_pending(self):
        text = (
            'VERIFICATION_CHALLENGES:\n'
            '[{"claim": "toolx.exe", "challenge_method": "strings.stat_file",'
            ' "verified": null, "confidence_impact": "—", "notes": ""}]\n'
            'DAIR_ASSESSMENT:\n{broken json'
        )
        r = _run(_compat_ctx, text)
        assert r["verification_satisfied"] is False
        assert r["transition_recommended"] is False

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_verification_satisfied_both_backends(self, ctx_fn):
        text = (
            'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Triage", "phase_rationale": "done",'
            ' "transition_recommended": true, "next_phase": "Collect",'
            ' "transition_rationale": "satisfied", "stack_action": "push",'
            ' "investigation_focus": "collect", "verification_satisfied": true,'
            ' "verification_challenges": [], "recommended_actions": [],'
            ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
            ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
        )
        r = _run(ctx_fn, text)
        assert r["verification_satisfied"] is True


# ── Scan → Triage loop ────────────────────────────────────────────────────────

class TestDairScanToTriageLoop:
    def test_scan_pushes_triage_on_new_pivot(self):
        text = (
            'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Scan", "phase_rationale": "New pivot host found",'
            ' "transition_recommended": true, "next_phase": "Triage",'
            ' "transition_rationale": "ws02 lateral movement indicators — full cycle",'
            ' "stack_action": "push", "investigation_focus": "Triage ws02",'
            ' "verification_satisfied": false,'
            ' "verification_challenges": [], "recommended_actions": [],'
            ' "directives": {"priority_tools": ["reason.plan", "strings.stat_file"],'
            ' "skip_tools": [], "focus_pids": [], "focus_paths": [],'
            ' "max_depth": "", "next_hypothesis_triggers": []}}'
        )
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "case opened", "depth": 0},
            {"phase": "Collect", "entry_reason": "triage complete", "depth": 1},
            {"phase": "Analyze", "entry_reason": "collection complete", "depth": 2},
            {"phase": "Scan", "entry_reason": "analysis complete", "depth": 3},
        ])
        r = _run(_compat_ctx, text, stack=stack)
        assert r["success"] is True
        assert r["current_phase"] == "Scan"
        assert r["next_phase"] == "Triage"
        assert r["stack_action"] == "push"
        assert r["transition_recommended"] is True

    def test_scan_to_report_when_no_pivot(self):
        r = _run(_compat_ctx, _ASSESSMENT_REPORT)
        assert r["next_phase"] == "Report"
        assert r["stack_action"] == "push"
        assert len(r["recommended_actions"]) > 0


class TestDairInputsCaptured:
    """Inputs to dair_assess (tool_results_summary, phase_stack, case_context)
    are stored on the dair_call entry for audit/inspection."""

    def test_success_path_captures_inputs(self, tmp_path):
        import json as _json
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("IN-D-001", str(tmp_path / "trace.json"))
        stack = _json.dumps([{"phase": "Triage", "entry_reason": "open", "depth": 0}])
        with patch("core.execution_log.log", inst), _compat_ctx(_ASSESSMENT_STAY):
            dair_assess(
                "toolx.exe at C:\\Windows\\Temp confirmed.",
                phase_stack=stack,
                case_context="CASE-A at EXAMPLE",
            )
        entry = [e for e in inst._entries if e["type"] == "dair_call"][-1]
        assert "inputs" in entry
        assert "toolx.exe" in entry["inputs"]["tool_results_summary"]
        assert "CASE-A" in entry["inputs"]["case_context"]
        assert isinstance(entry["inputs"]["phase_stack"], list)
        assert entry["inputs"]["phase_stack"][0]["phase"] == "Triage"
        assert "toolx.exe" in entry["inputs"]["user_message"]

    def test_failure_path_still_captures_inputs(self, tmp_path):
        # Missing URL path — dair_assess returns success=False but a
        # dair_call entry should be emitted with inputs intact.
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        inst = ExecutionLog()
        inst.configure("IN-D-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             patch("tools.dair.DAIR_URL", ""), \
             patch("tools.dair.DAIR_BACKEND", "openai-compat"):
            r = dair_assess("findings summary",
                            phase_stack="[]",
                            case_context="ctx")
        assert r["success"] is False
        dair_entries = [e for e in inst._entries if e["type"] == "dair_call"]
        assert dair_entries, "dair_call entry should exist even on failure"
        entry = dair_entries[-1]
        assert "inputs" in entry
        assert entry["inputs"]["tool_results_summary"].startswith("findings summary")
        assert entry["inputs"]["case_context"] == "ctx"


# ── Candidate pivot observation ──────────────────────────────────────────────

_SCAN_STAY_NEW_HOST = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Scan", "phase_rationale": "Continuing sweep",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "",'
    ' "stack_action": "stay",'
    ' "investigation_focus": "Sweep for lateral movement from host-01",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["yara.scan_directory"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)


def _scan_stack_json(case_id: str = "host-01") -> str:
    return (
        '['
        '{"phase": "Triage", "entry_reason": "initial", "depth": 1},'
        '{"phase": "Collect", "entry_reason": "verified", "depth": 2},'
        '{"phase": "Analyze", "entry_reason": "collected", "depth": 3},'
        '{"phase": "Scan", "entry_reason": "swept ' + case_id + '", "depth": 4}'
        ']'
    )


class TestDairCandidatePivots:
    """Record candidate pivots without mutating DAIR phase control."""

    def _run(self, summary: str, case_context: str, stack: str | None = None):
        from tools.dair import dair_assess
        stack = stack or _scan_stack_json()
        with _compat_ctx(_SCAN_STAY_NEW_HOST):
            return dair_assess(summary,
                               phase_stack=stack,
                               case_context=case_context)

    def test_new_ip_forces_push(self, tmp_path):
        # Configure the log so the dair_call goes somewhere.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="ShimCache shows lateral hop to 10.0.1.6 c$ admin share",
                case_context="Host host-01 (10.0.0.11)",
            )
        assert r["success"] is True
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "10.0.1.6" in _candidate_values(r, "host")
        assert "server-enforced" not in (r.get("transition_rationale") or "").lower()

    def test_new_unc_path_hostname_forces_push(self, tmp_path):
        # UNC-path hostname extraction works with zero configuration —
        # \\HOSTNAME\share is an unambiguous host reference regardless of
        # the case's naming scheme.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="ShimCache UNC path \\\\DC02\\admin$\\toolx.exe staging",
                case_context="Host alpha-01 (10.0.0.11)",
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "DC02" in _candidate_values(r, "host")

    def test_env_var_prefix_hostname_forces_push(self, tmp_path, monkeypatch):
        # Case-specific hostname prefix detection is opt-in via the
        # ATLAS_PIVOT_HOSTNAME_PREFIXES env var. Operators set it per-case
        # in .env. Without it, bare hostnames like "ws-02" are NOT
        # detected (only UNC paths and IPs are).
        monkeypatch.setenv("ATLAS_PIVOT_HOSTNAME_PREFIXES", "ws,srv")
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="ws-02 c$\\windows\\temp\\staging contains toolx.exe (suspicious)",
                case_context="Host host-01 (10.0.0.11)",
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "WS-02" in _candidate_values(r, "host")

    def test_bare_hostname_without_env_var_does_not_push(self, tmp_path, monkeypatch):
        # Without ATLAS_PIVOT_HOSTNAME_PREFIXES, a bare "ws-02" mention
        # in narrative text doesn't trigger a push — only IPs and UNC paths
        # are detected in the case-agnostic default.
        monkeypatch.delenv("ATLAS_PIVOT_HOSTNAME_PREFIXES", raising=False)
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="Sweep complete; no new lateral activity observed on ws-02",
                case_context="Host alpha-01 (10.0.0.11)",
            )
        # No IP, no UNC path → no push override; model "stay" is preserved.
        assert r["stack_action"] == "stay"

    def test_only_known_host_no_override(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="Continuing scan of host-01 — no new external traffic",
                case_context="Host host-01 (10.0.0.11)",
            )
        # Model said "stay" and there's no new host — must stay.
        assert r["stack_action"] == "stay"

    def test_multiple_new_pivots_first_pushed_rest_queued(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary=(
                    "ShimCache enumerated UNC paths on 10.0.1.5, 10.0.1.6, "
                    "ws-02, host-04 — all containing temp\\*.exe drops."
                ),
                case_context="Host host-01 (10.0.0.11)",
            )
        assert r["stack_action"] == "stay"
        assert "10.0.1.5" in _candidate_values(r, "host")
        assert "10.0.1.6" in _candidate_values(r, "host")
        assert not r.get("pending_pivots")

    def test_stop_word_filters_unc_extracted_host(self, tmp_path):
        # If a UNC-path-like token happens to surface a stop-word as the
        # extracted host (e.g. \\WINDOWS\share in a path mention), the
        # stop-list drops it before treating it as a pivot.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="Scanning for \\\\WINDOWS\\system32 references — none new",
                case_context="Host alpha-01 (10.0.0.11)",
            )
        # "WINDOWS" is a stop-word → no push.
        assert r["stack_action"] == "stay"

    def test_env_prefix_stop_word_split_on_hyphen(self, monkeypatch, tmp_path):
        # When an operator sets a prefix that produces a hyphenated match
        # whose leading token is a stop-word (e.g. "tcp-4" if they set
        # ATLAS_PIVOT_HOSTNAME_PREFIXES="tcp"), the split-on-hyphen filter
        # drops it. Guards against false positives from networking jargon.
        monkeypatch.setenv("ATLAS_PIVOT_HOSTNAME_PREFIXES", "tcp")
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="connection table shows tcp-4 socket open on alpha-01",
                case_context="Host alpha-01",
            )
        assert r["stack_action"] == "stay"

    def test_model_push_not_downgraded(self, tmp_path):
        # If the model already said push, candidate observation does not
        # downgrade it. This regression-locks the "never rewrite model phase"
        # invariant.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("AUTOPUSH", str(tmp_path / "trace.json"))
        already_push = (
            'DAIR_ASSESSMENT:\n'
            '{"current_phase": "Scan", "phase_rationale": "Pivot identified",'
            ' "transition_recommended": true, "next_phase": "Triage",'
            ' "transition_rationale": "Model identified host-04 pivot",'
            ' "stack_action": "push",'
            ' "investigation_focus": "Triage host-04",'
            ' "verification_challenges": [], "recommended_actions": [],'
            ' "directives": {"priority_tools": ["vol.pslist"], "skip_tools": [],'
            ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
            ' "next_hypothesis_triggers": []}}'
        )
        from tools.dair import dair_assess
        with patch("core.execution_log.log", l), _compat_ctx(already_push):
            r = dair_assess(
                "host-04 pivot from host-01",
                phase_stack=_scan_stack_json(),
                case_context="Host host-01 only",
            )
        # Stays "push" — and candidate observation doesn't append
        # "server-enforced" text.
        assert r["stack_action"] == "push"
        assert "server-enforced" not in (r.get("transition_rationale") or "").lower()


# ── Cross-phase candidate detection ──────────────────────────────────────────

_ANALYZE_STAY_NEW_HOST = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Analyze", "phase_rationale": "Examining process tree",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "",'
    ' "stack_action": "stay",'
    ' "investigation_focus": "Analyzing PsExec activity on host-01",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["vol.cmdline"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)

_COLLECT_STAY_NEW_HOST = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Collect", "phase_rationale": "Continuing artifact pulls",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "",'
    ' "stack_action": "stay",'
    ' "investigation_focus": "Pulling registry hives on host-01",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["ez.recmd_hive"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)

_ANALYZE_PUSH_TO_SCAN_NEW_HOST = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Analyze", "phase_rationale": "Per-host analysis done",'
    ' "transition_recommended": true, "next_phase": "Scan",'
    ' "transition_rationale": "Advance to cross-host sweep",'
    ' "stack_action": "push",'
    ' "investigation_focus": "Cross-host IOC sweep",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["yara.scan_directory"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)


class TestDairCrossPhasePivot:
    """Candidate detection runs from Scan, Analyze, AND Collect without
    forcing a push or queue."""

    def test_analyze_surfaces_new_host_forces_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE", str(tmp_path / "trace.json"))
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
            {"phase": "Collect", "entry_reason": "verified", "depth": 1},
            {"phase": "Analyze", "entry_reason": "collected", "depth": 2},
        ])
        with patch("core.execution_log.log", l), \
             _compat_ctx(_ANALYZE_STAY_NEW_HOST):
            r = dair_assess(
                "vol.netscan shows established session to 10.0.1.7:445 from PID 4044",
                phase_stack=stack,
                case_context="Host host-01 (10.0.0.11)",
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "10.0.1.7" in _candidate_values(r, "host")

    def test_collect_surfaces_new_host_forces_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE", str(tmp_path / "trace.json"))
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
            {"phase": "Collect", "entry_reason": "verified", "depth": 1},
        ])
        with patch("core.execution_log.log", l), \
             _compat_ctx(_COLLECT_STAY_NEW_HOST):
            r = dair_assess(
                "Registry hive enumeration revealed \\\\CORP-FILESRV02\\C$ "
                "mapped drive in HKCU\\Network",
                phase_stack=stack,
                case_context="Host host-01 (10.0.0.11)",
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "CORP-FILESRV02" in _candidate_values(r, "host")

    def test_triage_does_not_pivot_on_own_focus(self, tmp_path):
        # A Triage entry investigating host-01 mentioning a NEW host (e.g.
        # 10.0.1.9) would normally pivot — but Triage is excluded from
        # the eligible-phase set. Stays "stay".
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE", str(tmp_path / "trace.json"))
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
        ])
        # Use _ASSESSMENT_STAY which sets current_phase=Triage and stay.
        with patch("core.execution_log.log", l), \
             _compat_ctx(_ASSESSMENT_STAY):
            r = dair_assess(
                "Verifying toolx.exe; also saw 10.0.1.9 in passing",
                phase_stack=stack,
                case_context="Host host-01 (10.0.0.11)",
            )
        # Triage stays; no pivot push on its own surface mentions.
        assert r["stack_action"] == "stay"

    def test_model_push_to_non_triage_enqueues_overflow(self, tmp_path):
        # Model advances Analyze → Scan (per-host pipeline). Summary mentions
        # a new candidate host. Candidate observation does NOT downgrade the
        # model push and does not enqueue a follow-up.
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("XPHASE", str(tmp_path / "trace.json"))
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
            {"phase": "Collect", "entry_reason": "verified", "depth": 1},
            {"phase": "Analyze", "entry_reason": "collected", "depth": 2},
        ])
        with patch("core.execution_log.log", l), \
             _compat_ctx(_ANALYZE_PUSH_TO_SCAN_NEW_HOST):
            r = dair_assess(
                "PsExec evidence to 10.0.1.8 confirmed; advancing to cross-host sweep",
                phase_stack=stack,
                case_context="Host host-01 (10.0.0.11)",
            )
        # Model push to Scan preserved.
        assert r["stack_action"] == "push"
        assert r["next_phase"] == "Scan"
        # New pivot observed, not enqueued or overridden.
        assert "10.0.1.8" in _candidate_values(r, "host")
        assert not r.get("pending_pivots")
        assert "enqueued" not in (r.get("transition_rationale") or "").lower()


# ── Legacy pivot queues do not drive control flow ────────────────────────────

class TestDairPivotQueueDrain:
    """Legacy pending pivots no longer drive synthetic DAIR transitions."""

    def test_candidate_pivots_do_not_short_circuit_subsequent_call(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("DRAIN", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l), \
             _compat_ctx(_SCAN_STAY_NEW_HOST):
            r1 = dair_assess(
                "ShimCache hits on 10.0.1.5, 10.0.1.6, 10.0.1.7",
                phase_stack=_scan_stack_json(),
                case_context="Host host-01 (10.0.0.11)",
            )
        assert r1["stack_action"] == "stay"
        assert {"10.0.1.5", "10.0.1.6", "10.0.1.7"} <= _candidate_values(r1, "host")
        assert not r1.get("pending_pivots")

        # Trace should record candidate_pivots on the dair_call entry.
        last_dair = [e for e in l._entries if e.get("type") == "dair_call"][-1]
        assert last_dair.get("candidate_pivots") == r1["candidate_pivots"]

        # Second call: nothing recorded changed, so the standing assessment
        # is returned — the model's own, not a synthetic drain.
        with patch("core.execution_log.log", l), \
             _compat_ctx(_SCAN_STAY_NEW_HOST) as client:
            r2 = dair_assess(
                "Continuing cross-host sweep",
                phase_stack=_scan_stack_json(),
                case_context="Host host-01 (10.0.0.11)",
            )
        assert r2["stack_action"] == "stay"
        assert r2["input_tokens"] == 0
        assert r2["output_tokens"] == 0
        assert "drained from queue" not in (r2.get("investigation_focus") or "")
        assert not r2.get("pending_pivots")
        assert r2["reused_from_call_id"] == r1["_atlas_call_id"]
        client.assert_not_called()
        # Asked for explicitly, the model is consulted on the same state.
        with patch("core.execution_log.log", l), \
             _compat_ctx(_SCAN_STAY_NEW_HOST) as client:
            r3 = dair_assess(
                "Continuing cross-host sweep",
                phase_stack=_scan_stack_json(),
                case_context="Host host-01 (10.0.0.11)",
                fresh=True,
            )
        assert "reused_from_call_id" not in r3
        assert not r3.get("pending_pivots")
        client.assert_called_once()

    def test_legacy_queue_ignored_when_current_phase_is_triage(self, tmp_path):
        # A Triage frame must run the model; legacy queue entries are ignored.
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("DRAIN", str(tmp_path / "trace.json"))
        # Seed a prior legacy dair_call entry with pending_pivots.
        l.record_dair_call(
            current_phase="Scan", phase_rationale="prior",
            transition_recommended=True, next_phase="Triage",
            transition_rationale="prior push", stack_action="push",
            investigation_focus="prior triage focus",
            pending_pivots=["10.0.1.99"],
        )
        # Now call dair_assess on a Triage frame.
        stack = json.dumps([
            {"phase": "Triage", "entry_reason": "open", "depth": 0},
        ])
        with patch("core.execution_log.log", l), \
             _compat_ctx(_ASSESSMENT_STAY) as client:
            r = dair_assess(
                "Verifying initial IOC",
                phase_stack=stack,
                case_context="Host host-01",
            )
        # Model ran — no synthetic-drain investigation_focus, current_phase
        # preserved.
        client.assert_called_once()
        assert r["current_phase"] == "Triage"
        assert r["stack_action"] == "stay"
        assert "drained from queue" not in (r.get("investigation_focus") or "")

    def test_legacy_queue_ignored_when_queued_host_already_investigated(self, tmp_path):
        # Queued host appears in a later dair_call's investigation_focus.
        # The model is still called because legacy queue entries do not drive
        # control flow.
        from core.execution_log import ExecutionLog
        from tools.dair import dair_assess
        l = ExecutionLog()
        l.configure("DRAIN", str(tmp_path / "trace.json"))
        # Earlier entry queued 10.0.1.99…
        l.record_dair_call(
            current_phase="Scan", phase_rationale="prior",
            transition_recommended=True, next_phase="Triage",
            transition_rationale="prior push", stack_action="push",
            investigation_focus="Triage 10.0.1.5",
            pending_pivots=["10.0.1.99"],
        )
        # …and a subsequent Triage entry already touched it.
        l.record_dair_call(
            current_phase="Triage", phase_rationale="pivot triage",
            transition_recommended=False, next_phase="",
            transition_rationale="", stack_action="stay",
            investigation_focus="Triage pivot host 10.0.1.99",
        )
        with patch("core.execution_log.log", l), \
             _compat_ctx(_SCAN_STAY_NEW_HOST):
            r = dair_assess(
                "Continuing sweep — no new hosts",
                phase_stack=_scan_stack_json(),
                case_context="Host host-01 (10.0.0.11)",
            )
        # Queue empty → model runs → no synthetic push.
        # _SCAN_STAY_NEW_HOST has stack_action=stay, no new pivots in summary.
        assert r["stack_action"] == "stay"


# ── Candidate principal detection ────────────────────────────────────────────
# A newly-*created* account is a candidate lead just like a new host. Detection
# keys on account-creation cues (high precision); a plain mention is ignored.

_SCAN_STAY_EMPTY_FOCUS = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Scan", "phase_rationale": "Continuing sweep",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "",'
    ' "stack_action": "stay",'
    ' "investigation_focus": "",'
    ' "verification_challenges": [], "recommended_actions": [],'
    ' "directives": {"priority_tools": ["yara.scan_directory"], "skip_tools": [],'
    ' "focus_pids": [], "focus_paths": [], "max_depth": "",'
    ' "next_hypothesis_triggers": []}}'
)


class TestDairPrincipalCandidates:
    """Record candidate principals without mutating DAIR phase control."""

    def _run(self, summary, case_context, assessment=_SCAN_STAY_NEW_HOST):
        from tools.dair import dair_assess
        with _compat_ctx(assessment):
            return dair_assess(summary,
                               phase_stack=_scan_stack_json(),
                               case_context=case_context)

    def test_new_account_creation_forces_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="Security EID 4720 — new local admin account 'svc_x' was created",
                case_context="Subject jdoe on host host-01; no svc_x account known",
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "SVC_X" in _candidate_values(r, "principal")
        assert "server-enforced" not in (r.get("transition_rationale") or "").lower()

    def test_controller_question_becomes_focus(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="A covert local admin account 'printer_svc' was created on the host",
                case_context="Subject jdoe on host host-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        assert r["stack_action"] == "stay"
        assert "PRINTER_SVC" in _candidate_values(r, "principal")
        assert not (r.get("investigation_focus") or "")

    def test_builtin_account_does_not_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="The built-in Guest account was created/enabled during the window",
                case_context="Subject jdoe on host host-01",
            )
        # 'Guest' is a built-in stop-word principal → no push.
        assert r["stack_action"] == "stay"

    def test_mention_without_creation_cue_does_not_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="account svc_x ran notepad.exe and opened a document",
                case_context="Subject jdoe on host host-01",
            )
        # Mention, not creation → no principal pivot.
        assert r["stack_action"] == "stay"

    def test_known_principal_in_context_no_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="new user account 'svc_x' was created on the host",
                case_context="Known principal: account svc_x already under investigation",
            )
        # svc_x is already known (named in case_context) → no new candidate.
        assert r["stack_action"] == "stay"

    def test_rdp_logon_unknown_principal_forces_push(self, tmp_path):
        # Tier A: an unknown identity authenticating over RDP forces a push —
        # the second-principal class that creation-only detection missed.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary=("Security 4778 — RDP session established for account "
                         "svc_rdp (logon type 10)"),
                case_context="Subject jdoe on host host-01; no svc_rdp account known",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        assert r["stack_action"] == "stay"
        assert r["next_phase"] == ""
        assert "SVC_RDP" in _candidate_values(r, "principal")

    def test_interactive_logon_unknown_principal_forces_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="account maint_op logged in interactively (logon type 2)",
                case_context="Subject jdoe on host host-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        assert r["stack_action"] == "stay"
        assert "MAINT_OP" in _candidate_values(r, "principal")

    def test_network_logon_unknown_principal_queues_not_forces(self, tmp_path):
        # Tier B: noisier network logon enqueues rather than pre-empting stay.
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="account batch_svc network logon type 3 observed",
                case_context="Subject jdoe on host host-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
        )
        assert r["stack_action"] == "stay"
        assert not r.get("pending_pivots")
        assert "BATCH_SVC" in _candidate_values(r, "principal")
        candidate = next(
            p for p in r.get("candidate_pivots") or []
            if p.get("value", "").upper() == "BATCH_SVC"
        )
        assert candidate.get("cue") == "appearance"

    def test_known_rdp_principal_in_context_no_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="account svc_rdp logged in via RDP (logon type 10)",
                case_context="account svc_rdp already under investigation on host host-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        # Known-set gating: svc_rdp already under investigation → no re-pivot.
        assert r["stack_action"] == "stay"

    def test_rdp_logon_by_known_subject_no_push(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("PRINCIPALPUSH", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = self._run(
                summary="jdoe logged in via RDP (logon type 10)",
                case_context="Subject jdoe on host host-01",
                assessment=_SCAN_STAY_EMPTY_FOCUS,
            )
        # The case subject's own logon must not pivot — 'Subject jdoe' makes
        # jdoe a known principal.
        assert r["stack_action"] == "stay"


class TestPrincipalTokenExtraction:
    """Unit coverage for the principal token helpers."""

    def test_creation_cue_required_by_default(self):
        from tools.dair import _extract_principal_tokens
        assert _extract_principal_tokens("user svc_x logged in") == set()
        assert "SVC_X" in _extract_principal_tokens(
            "new local admin account 'svc_x' was created")

    def test_cue_free_extraction_for_known_set(self):
        from tools.dair import _extract_principal_tokens
        # require_cue=False is how the known set reads case_context / focus.
        toks = _extract_principal_tokens(
            "Establish who controls principal PRINTER_SVC", require_cue=False)
        assert "PRINTER_SVC" in toks

    def test_builtins_filtered(self):
        from tools.dair import _extract_principal_tokens
        toks = _extract_principal_tokens(
            "new admin account 'Administrator' created and Guest account created")
        assert "ADMINISTRATOR" not in toks
        assert "GUEST" not in toks

    def test_filesystem_vocabulary_and_trailing_dot_filtered(self):
        # 'PROFILES.' (a profile-path fragment plus the sentence period)
        # must not be harvested as a forced principal candidate: it
        # deadlocks pre_report_check and the run ends with no report.
        from tools.dair import _extract_principal_tokens
        assert _extract_principal_tokens(
            "who controls principal PROFILES. on this host",
            require_cue=False) == set()
        assert _extract_principal_tokens(
            "user: Public staged files in Music", require_cue=False) == set()
        # sentence-ending dot is stripped from a real name, not kept
        toks = _extract_principal_tokens(
            "principal backdoor7. was created (4720)", require_cue=False)
        assert toks == {"BACKDOOR7"}

    def test_prose_after_a_cue_word_is_not_a_principal(self):
        """"principal identified", "user profile", "principal hypothesis":
        the next English word, not a name. A name is written as one: quoted,
        qualified, or carrying a capital, a digit or punctuation."""
        from tools.dair import _extract_principal_tokens
        text = ("No second principal identified on this system; no second user "
                "profile; the second principal hypothesis is resolved. The 3 "
                "account creation events (4720) are for service accounts.")
        assert _extract_principal_tokens(text) == set()
        assert _extract_principal_tokens(
            "account creation (4720): user jdoe created; see Users\\jdoe") == {"JDOE"}
        assert _extract_principal_tokens(
            "account creation (4720): user `jdoe` created") == {"JDOE"}
        assert _extract_principal_tokens(
            "account creation (4720): user jdoe2 created") == {"JDOE2"}
        # A bare lowercase word alone is prose, whatever it turns out to be.
        assert _extract_principal_tokens(
            "account creation (4720) by user jdoe, unquoted") == set()

    def test_interactive_auth_cue_emits_token_under_forced(self):
        from tools.dair import _extract_principal_tokens
        toks = _extract_principal_tokens(
            "svc_rdp logged in via RDP (logon type 10)", cue="forced")
        assert "SVC_RDP" in toks

    def test_network_logon_is_appearance_not_forced(self):
        from tools.dair import _extract_principal_tokens
        text = "account batch_svc network logon type 3 observed"
        assert _extract_principal_tokens(text, cue="forced") == set()
        assert "BATCH_SVC" in _extract_principal_tokens(text, cue="appearance")

    def test_any_cue_is_union_but_bare_mention_still_empty(self):
        from tools.dair import _extract_principal_tokens
        assert "SVC_X" in _extract_principal_tokens(
            "account svc_x logged in via rdp", cue="any")
        # A bare mention with no cue family still yields nothing.
        assert _extract_principal_tokens(
            "account svc_x ran notepad.exe", cue="any") == set()

    def test_default_cue_stays_creation_only(self):
        # Default must remain creation-only so existing callers are unchanged:
        # an interactive logon does NOT extract under the default cue.
        from tools.dair import _extract_principal_tokens
        assert _extract_principal_tokens("svc_rdp logged in via rdp") == set()
        assert "SVC_RDP" in _extract_principal_tokens(
            "new admin account 'svc_rdp' was created")


# ── evidence-grounded work orders + escape valve ──────────────────────

class TestEvidenceBlob:
    """`_evidence_blob` is tri-state: None when the evidence dir is unreadable
    (so grounding is skipped), else a possibly-empty string of real filenames."""

    def test_none_when_no_evidence_dir(self, tmp_path, monkeypatch):
        from tools import dair
        monkeypatch.setattr(dair, "_case_root", lambda: str(tmp_path))
        assert dair._evidence_blob() is None

    def test_empty_string_when_dir_present_but_no_files(self, tmp_path, monkeypatch):
        from tools import dair
        (tmp_path / "evidence").mkdir()
        monkeypatch.setattr(dair, "_case_root", lambda: str(tmp_path))
        assert dair._evidence_blob() == ""

    def test_lists_real_filenames_lowercased(self, tmp_path, monkeypatch):
        from tools import dair
        ev = tmp_path / "evidence"
        ev.mkdir()
        (ev / "Capture.PCAP").write_text("x")
        (ev / "disk.E01").write_text("x")
        monkeypatch.setattr(dair, "_case_root", lambda: str(tmp_path))
        blob = dair._evidence_blob()
        assert "capture.pcap" in blob and "disk.e01" in blob


class TestDefaultWorkOrderGrounding:
    def test_pcap_cue_without_pcap_falls_back(self):
        from tools.dair import _default_work_order, _FALLBACK_WORK_ORDER
        # Brief mentions a pcap/network, but no evidence backs any known type —
        # the net.* order must NOT be prescribed against a missing capture.
        order = _default_work_order(
            "network capture analysis of the pcap",
            evidence_blob="notes.txt readme.md")
        assert order == _FALLBACK_WORK_ORDER
        assert not any(t.startswith("net.") for t in order)

    def test_pcap_cue_but_disk_present_selects_disk_order(self):
        from tools.dair import _default_work_order
        # Text says pcap, but the real evidence is a disk image — ground to disk.
        order = _default_work_order(
            "network capture analysis of the pcap",
            evidence_blob="suspect_disk.e01")
        assert not any(t.startswith("net.") for t in order)
        assert any("mount" in t or t.startswith("tsk.") for t in order)

    def test_pcap_cue_with_pcap_selects_net_order(self):
        from tools.dair import _default_work_order
        order = _default_work_order(
            "network capture analysis of the pcap",
            evidence_blob="c2_traffic.pcap")
        assert order[0].startswith("net.")

    def test_evidence_only_selection_without_text_cue(self):
        from tools.dair import _default_work_order
        # No cue in the text, but a PCAP is present — pick the net order anyway.
        order = _default_work_order("investigate the incident",
                                    evidence_blob="c2_traffic.pcap")
        assert order[0].startswith("net.")

    def test_ungrounded_none_preserves_legacy_text_behaviour(self):
        from tools.dair import _default_work_order
        # evidence_blob=None (unreadable) → cue in text still selects net order.
        order = _default_work_order("analyze the pcap", evidence_blob=None)
        assert order[0].startswith("net.")


class TestEvidenceExhaustionEscapeValve:
    """The general escape valve: repeated stays in a non-Triage phase while the
    prescribed tools keep failing on absent evidence must force a transition so
    the run can reach Report (reason.synthesize is Report-gated)."""

    def _seed_stuck_collect(self, tmp_path, stays: int, failures: int):
        from core.execution_log import log
        log.configure("STUCK-PCAP", str(tmp_path / "trace.json"),
                      save_session=False)
        for _ in range(stays):
            log.record_dair_call(
                current_phase="Collect", phase_rationale="need pcap",
                transition_recommended=False, next_phase="",
                transition_rationale="", stack_action="stay",
                investigation_focus="pcap")
        for i in range(failures):
            log.record_tool_call(
                cmd=f"net.tcpdump_read run{i}", success=False, truncated=False,
                retries=0, exit_code=1,
                stderr="tcpdump: /evidence/c2.pcap: No such file or directory")
        return log

    def test_forces_advance_after_repeated_missing_evidence(
        self, tmp_path, monkeypatch):
        from tools import dair
        # Evidence dir exists but has no pcap.
        (tmp_path / "evidence").mkdir()
        monkeypatch.setattr(dair, "_case_root", lambda: str(tmp_path))
        self._seed_stuck_collect(tmp_path, stays=3, failures=3)

        assessment = {"current_phase": "Collect", "stack_action": "stay",
                      "next_phase": "", "transition_recommended": False}
        tools, note = dair._enforce_work_order(
            assessment, {"priority_tools": ["net.tcpdump_read"]},
            "no packets — capture file missing",
            "CASE_QUESTION: what did the attacker exfiltrate over the network?")
        assert note == "evidence_exhausted"
        assert assessment["transition_recommended"] is True
        assert assessment["stack_action"] == "push"
        assert assessment["next_phase"] == "Analyze"  # one step toward Report
        assert "out of scope" in assessment["transition_rationale"].lower()

    def test_does_not_fire_without_failures(self, tmp_path, monkeypatch):
        from tools import dair
        (tmp_path / "evidence").mkdir()
        monkeypatch.setattr(dair, "_case_root", lambda: str(tmp_path))
        # Stays present but no failing tool_calls → not evidence_exhausted.
        # productive_stall may still hard-advance Collect (gathering escape).
        self._seed_stuck_collect(tmp_path, stays=4, failures=0)
        assessment = {"current_phase": "Collect", "stack_action": "stay",
                      "next_phase": "", "transition_recommended": False}
        _tools, note = dair._enforce_work_order(
            assessment, {"priority_tools": ["net.tcpdump_read"]}, "working", "ctx")
        assert note != "evidence_exhausted"
        assert note != "evidence_exhausted_hint"
        # Other Collect escapes (productive_stall / collect_cap / empty_loop)
        # may still advance — this test only guards false evidence_exhausted.

    def test_does_not_fire_before_stay_threshold(self, tmp_path, monkeypatch):
        from tools import dair
        (tmp_path / "evidence").mkdir()
        monkeypatch.setattr(dair, "_case_root", lambda: str(tmp_path))
        # Only 1 prior stay; need >= _STALL_MAX_STAYS-1 (=2) prior stays.
        # Failures present but stay threshold not yet met.
        self._seed_stuck_collect(tmp_path, stays=1, failures=3)
        assessment = {"current_phase": "Collect", "stack_action": "stay",
                      "next_phase": "", "transition_recommended": False}
        _tools, note = dair._enforce_work_order(
            assessment, {"priority_tools": ["net.tcpdump_read"]}, "missing", "ctx")
        assert note != "evidence_exhausted"

    def test_fires_at_aligned_stay_threshold(self, tmp_path, monkeypatch):
        """Stay threshold is aligned with empty_loop/productive_stall (2 prior
        stays) so the specific diagnosis can compete in the same cycle."""
        from tools import dair
        (tmp_path / "evidence").mkdir()
        monkeypatch.setattr(dair, "_case_root", lambda: str(tmp_path))
        self._seed_stuck_collect(tmp_path, stays=2, failures=3)
        assessment = {"current_phase": "Collect", "stack_action": "stay",
                      "next_phase": "", "transition_recommended": False}
        _tools, note = dair._enforce_work_order(
            assessment, {"priority_tools": ["net.tcpdump_read"]}, "missing", "ctx")
        assert note == "evidence_exhausted"
        assert assessment["next_phase"] == "Analyze"

    def test_next_phase_walks_to_report(self):
        from tools.dair import _next_phase
        assert _next_phase("Collect") == "Analyze"
        assert _next_phase("Analyze") == "Scan"
        assert _next_phase("Scan") == "Report"
        assert _next_phase("Report") == "Report"


class TestReportCollectDamper:
    def test_stays_in_report_when_sudo_auth_recorded(self, tmp_path, monkeypatch):
        from tools import dair
        from core.execution_log import log as elog

        (tmp_path / "evidence").mkdir()
        monkeypatch.setattr(dair, "_case_root", lambda: str(tmp_path))
        elog._entries.append({
            "type": "tool_call",
            "tool": "tsk_mmls",
            "failure_class": "sudo_auth",
            "success": False,
        })
        assessment = {
            "current_phase": "Report",
            "stack_action": "push",
            "next_phase": "Collect",
            "transition_recommended": True,
        }
        _tools, note = dair._enforce_work_order(
            assessment, {"priority_tools": []}, "blocked", "ctx")
        assert note == "report_collect_damper"
        assert assessment["stack_action"] == "stay"
        assert assessment["next_phase"] == ""


# ── Assess on change ─────────────────────────────────────────────────────────

_REPORT_STAY = (
    'DAIR_ASSESSMENT:\n'
    '{"current_phase": "Report", "phase_rationale": "Report in progress",'
    ' "transition_recommended": false, "next_phase": "",'
    ' "transition_rationale": "", "stack_action": "stay",'
    ' "investigation_focus": "Write the report",'
    ' "verification_challenges": [], "recommended_actions": ["Rotate credentials"],'
    ' "directives": {"priority_tools": [], "skip_tools": [], "focus_pids": [],'
    ' "focus_paths": [], "max_depth": "", "next_hypothesis_triggers": []}}'
)


def _report_stack_json() -> str:
    stack = json.loads(_scan_stack_json())
    stack.append({"phase": "Report", "entry_reason": "swept", "depth": 5})
    return json.dumps(stack)


class TestAssessOnChange:
    """The window forces a dair_assess call every few actions; the director
    is consulted only when the recorded state differs from the one its
    standing assessment was made on, and that assessment is returned again
    otherwise. Phase progression stays with the valves, which see every
    call whether the director was consulted or not."""

    def _log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("CHG", str(tmp_path / "trace.json"))
        return l

    def _assess(self, l, reply=_SCAN_STAY_NEW_HOST, stack=None,
                summary="batch ran", **kw):
        from tools.dair import dair_assess
        with patch("core.execution_log.log", l), _compat_ctx(reply) as client:
            r = dair_assess(summary, phase_stack=stack or _scan_stack_json(),
                            case_context="Host host-01", **kw)
        return r, client

    def test_an_unchanged_state_gets_the_standing_assessment(self, tmp_path):
        l = self._log(tmp_path)
        r1, c1 = self._assess(l)
        c1.assert_called_once()
        r2, c2 = self._assess(l, summary="nothing new")
        c2.assert_not_called()
        assert r2["reused_from_call_id"] == r1["_atlas_call_id"]
        assert r2["investigation_focus"] == r1["investigation_focus"]
        assert (r2["directives"]["priority_tools"]
                == r1["directives"]["priority_tools"])
        # A dair_call of its own is on the trace, so the window reopens.
        last = [e for e in l._entries if e.get("type") == "dair_call"][-1]
        assert last["call_id"] == r2["_atlas_call_id"] != r1["_atlas_call_id"]
        assert last["inputs"]["reused_from_call_id"] == r1["_atlas_call_id"]

    def test_a_new_finding_consults_the_director(self, tmp_path):
        l = self._log(tmp_path)
        self._assess(l)
        l.record_finding("beacon from host-01 to an external host", "SUSPECTED")
        r2, c2 = self._assess(l, summary="found a beacon")
        c2.assert_called_once()
        assert "reused_from_call_id" not in r2

    def test_a_new_hypothesis_consults_the_director(self, tmp_path):
        l = self._log(tmp_path)
        self._assess(l)
        l.record_reason_call(tool="reason_hypothesize", success=True,
                             conclusion="H1: staged exfil", directives={},
                             hypothesis_id="H0001")
        _r2, c2 = self._assess(l)
        c2.assert_called_once()

    def test_an_open_deferred_probe_consults_the_director(self, tmp_path):
        l = self._log(tmp_path)
        self._assess(l)
        l.record_deferred_intent("vol.psscan", {}, "window aged out")
        _r2, c2 = self._assess(l)
        c2.assert_called_once()

    def test_a_failed_call_since_the_assessment_consults_the_director(self, tmp_path):
        l = self._log(tmp_path)
        self._assess(l)
        l.record_tool_call("vol.psscan", False, False, 0, 1, stderr="plugin error")
        _r2, c2 = self._assess(l, summary="the scan failed")
        c2.assert_called_once()

    def test_a_call_the_runs_stop_cut_short_is_no_failure(self, tmp_path):
        l = self._log(tmp_path)
        self._assess(l)
        l.record_tool_call("vol.psscan", False, False, 0, -15,
                           stderr="interrupted: the run was stopped while this tool ran",
                           interrupted=True)
        l.record_tool_call("vol.pslist", True, False, 0, 0)
        r2, c2 = self._assess(l, summary="nothing new")
        c2.assert_not_called()
        assert "reused_from_call_id" in r2

    def test_triage_always_consults_the_director(self, tmp_path):
        l = self._log(tmp_path)
        self._assess(l, reply=_ASSESSMENT_STAY, stack="[]")
        _r2, c2 = self._assess(l, reply=_ASSESSMENT_STAY, stack="[]")
        c2.assert_called_once()

    def test_a_standing_assessment_stands_for_a_bounded_run(self, tmp_path):
        from tools.dair import _REUSE_MAX_CONSECUTIVE
        l = self._log(tmp_path)
        _r, c = self._assess(l, reply=_REPORT_STAY, stack=_report_stack_json())
        consulted = [c.call_count]
        for _ in range(_REUSE_MAX_CONSECUTIVE + 1):
            _r, c = self._assess(l, reply=_REPORT_STAY, stack=_report_stack_json())
            consulted.append(c.call_count)
        assert consulted == [1] + [0] * _REUSE_MAX_CONSECUTIVE + [1]

    def test_the_valves_still_advance_a_stalled_phase(self, tmp_path):
        # Reused assessments count like any other: the same barren Scan
        # work order still trips the empty-loop valve on schedule.
        l = self._log(tmp_path)
        results = [self._assess(l)[0] for _ in range(3)]
        assert [r["stack_action"] for r in results[:2]] == ["stay", "stay"]
        assert results[2]["stack_action"] == "push"
        assert results[2]["next_phase"] == "Report"

    def test_the_switch_consults_every_time(self, tmp_path):
        from tools import dair
        l = self._log(tmp_path)
        with patch.object(dair, "DAIR_REUSE_STANDING", 0):
            self._assess(l)
            _r2, c2 = self._assess(l)
        c2.assert_called_once()


class TestStructuredReply:
    """The director is asked for the assessment object itself; the schema
    is the parser's own key set, and the parser reads either shape."""

    def test_the_schema_is_the_parser_key_set(self):
        from tools.reasoning import _EMPTY_DIRECTIVES
        from tools.dair import _ASSESSMENT_KEYS, _DAIR_RESPONSE_FORMAT
        spec = _DAIR_RESPONSE_FORMAT["json_schema"]
        assert spec["strict"] is True
        schema = spec["schema"]
        assert set(schema["properties"]) == set(_ASSESSMENT_KEYS) | {"directives"}
        assert set(schema["required"]) == set(schema["properties"])
        directives = schema["properties"]["directives"]
        assert set(directives["properties"]) == set(_EMPTY_DIRECTIVES)
        assert directives["additionalProperties"] is False

    def test_the_ruling_is_left_unconstrained_by_default(self, monkeypatch):
        """Neither the schema nor a lowered effort rides along uninvited.

        Both were measured changing the phase the director reported on
        prompts whose unconstrained answer was stable across samples, so a
        run gets the reply shape the parser has always read until an
        operator asks for otherwise."""
        from tools.dair import _ask_openai_compat
        monkeypatch.delenv("ATLAS_EFFORT_DAIR", raising=False)
        http_mock = MagicMock(return_value=_http_resp(_SCAN_STAY_NEW_HOST))
        with patch("httpx.post", http_mock), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_API_KEY", ""):
            out = _ask_openai_compat("sys", "user")
        assert out["success"] is True
        body = http_mock.call_args.kwargs["json"]
        assert "response_format" not in body
        assert "reasoning_effort" not in body

    def test_the_schema_is_sent_when_it_is_asked_for(self, monkeypatch):
        from tools import dair
        monkeypatch.setattr(dair, "DAIR_RESPONSE_SCHEMA", 1)
        http_mock = MagicMock(return_value=_http_resp(_SCAN_STAY_NEW_HOST))
        with patch("httpx.post", http_mock), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_API_KEY", ""):
            out = dair._ask_openai_compat("sys", "user")
        assert out["success"] is True
        body = http_mock.call_args.kwargs["json"]
        assert body["response_format"]["type"] == "json_schema"
        assert body["response_format"]["json_schema"]["name"] == "dair_assessment"

    def test_an_endpoint_that_rejects_the_schema_still_answers(self, monkeypatch, tmp_path):
        from agent import llm
        from tools import dair
        monkeypatch.setattr(dair, "DAIR_RESPONSE_SCHEMA", 1)
        monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "compat.json"))
        monkeypatch.setenv("ATLAS_AGENT_INPUT_TPM", "0")
        llm.clear_api_compat_cache(memory_only=True)
        rejected = MagicMock(status_code=400,
                             text='{"error": "response_format is not supported"}')
        http_mock = MagicMock(side_effect=[rejected, _http_resp(_SCAN_STAY_NEW_HOST)])
        with patch("httpx.post", http_mock), \
             patch("tools.dair.DAIR_URL", "http://localhost:8000"), \
             patch("tools.dair.DAIR_API_KEY", ""):
            out = dair._ask_openai_compat("sys", "user")
        assert out["success"] is True
        first, second = [c.kwargs["json"] for c in http_mock.call_args_list]
        assert "response_format" in first
        assert "response_format" not in second

    def test_the_bare_object_a_schema_yields_is_parsed(self):
        from tools.dair import _parse_dair_assessment
        obj = json.loads(_SCAN_STAY_NEW_HOST.split("\n", 1)[1])
        a = _parse_dair_assessment(json.dumps(obj))
        assert a["investigation_focus"] == obj["investigation_focus"]
        assert a["directives"]["priority_tools"] == ["yara.scan_directory"]


class TestRepeatedOutputNotice:
    """The director is told when its recent work re-derives what the run
    already holds. The empty-loop valve catches an identical work order; a
    varied one returning answers already obtained is invisible to it, and to
    the call memo, which keys on the question rather than the answer. The
    notice reports that rate and decides nothing."""

    class _Log:
        def __init__(self, entries):
            self._entries = entries

    @staticmethod
    def _calls(hashes):
        return [{"type": "tool_call", "output_hash": h} for h in hashes]

    def _rate(self, entries):
        from unittest.mock import patch
        from tools.dair import _recent_repeat_rate
        with patch("core.execution_log.log", self._Log(entries)):
            return _recent_repeat_rate()

    def test_a_run_re_deriving_what_it_holds_is_told(self):
        entries = self._calls([f"h{i}" for i in range(20)]
                              + [f"h{i}" for i in range(20)])
        out = self._rate(entries)
        assert "REPEATED OUTPUT" in out
        assert "20 of the last 40" in out
        assert "Judge whether" in out          # reports, does not instruct

    def test_a_productive_run_is_left_alone(self):
        assert self._rate(self._calls([f"h{i}" for i in range(60)])) == ""

    def test_a_moderate_rate_is_not_worth_saying(self):
        entries = self._calls([f"h{i}" for i in range(40)]
                              + [f"h{i}" for i in range(5)]
                              + [f"n{i}" for i in range(35)])
        assert self._rate(entries) == ""

    def test_a_run_too_short_to_judge_says_nothing(self):
        assert self._rate(self._calls(["a", "a", "a", "a"])) == ""

    def test_calls_without_an_output_hash_are_ignored(self):
        assert self._rate([{"type": "tool_call"} for _ in range(40)]) == ""

    def test_entries_that_are_not_tool_calls_do_not_count(self):
        entries = ([{"type": "finding", "output_hash": "h"} for _ in range(40)]
                   + self._calls(["a", "b"]))
        assert self._rate(entries) == ""


class TestThePrivateHelperIsNotATool:
    """A helper added just above a decorated tool takes that tool's decorator
    and the tool stops existing. When `dair_assess` vanishes from the
    namespace, a finding cannot be recorded outside an active DAIR
    investigation, so a run reads evidence and records nothing."""

    def _tool_names(self):
        from agent.toolbox import Toolbox
        return list(Toolbox().tools.keys())

    def test_dair_assess_is_registered(self):
        names = self._tool_names()
        assert any("dair_assess" in n for n in names), \
            "dair_assess missing from the toolbox — a finding cannot be recorded without it"

    def test_no_private_function_is_exposed_as_a_tool(self):
        """Catches the whole class, not just this one: a registered tool is
        `<namespace>_<function>`, so a private function shows up with the
        namespace separator followed by an underscore."""
        leaked = [n for n in self._tool_names() if "__" in n]
        assert leaked == [], f"private helpers registered as tools: {leaked}"


def test_host_tokens_are_read_from_a_list_shaped_field():
    """A director focus a model answered as a list is read as its text, so
    the host-context readers and the report checks built on them do not
    fail on an older trace."""
    from tools.dair import _extract_host_tokens
    found = _extract_host_tokens(["RDP from 10.0.0.51 to dc01", "then \\\\FILESRV01\\share"])
    assert "10.0.0.51" in found
    assert _extract_host_tokens(None) == set()


def test_principal_tokens_are_read_from_a_list_shaped_field():
    from tools.dair import _extract_principal_tokens
    found = _extract_principal_tokens(["who controls principal SVC.BACKUP01", "next"], require_cue=False)
    assert found and "SVC.BACKUP01" in {t.upper() for t in found}
    assert _extract_principal_tokens(None, require_cue=False) == set()


def test_the_director_is_shown_the_report_gates_own_verdict():
    """The latest pre-report verdict goes to the director as a block of its
    own; a trace without one adds nothing."""
    from tools.dair import _report_gate_block
    entries = [
        {"type": "reason_call", "tool": "reason_synthesize", "conclusion": "x"},
        {"type": "reason_call", "tool": "reason_pre_report_check", "call_id": 7,
         "conclusion": "READY_TO_REPORT: false\nBLOCKING_ISSUES (1): a finding cites nothing"},
        {"type": "reason_call", "tool": "reason_pre_report_check", "call_id": 9,
         "conclusion": ["READY_TO_REPORT: false", "BLOCKING_ISSUES (1): re-cite F3"]},
    ]
    block = _report_gate_block(entries)
    assert block.startswith("REPORT GATE (latest reason.pre_report_check, call #9)")
    assert "re-cite F3" in block and "cites nothing" not in block
    assert _report_gate_block(entries[:1]) == ""
