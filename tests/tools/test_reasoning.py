"""Tests for tools/reasoning.py — openai-compat / llmhub backends."""
import pytest
from contextlib import contextmanager
from unittest.mock import patch, MagicMock


_DIRECTIVES_JSON = (
    'DIRECTIVES:\n'
    '{"priority_tools": ["vol.psscan", "vol.cmdline"], '
    '"skip_tools": [], "focus_pids": [5024], '
    '"focus_paths": ["C:\\\\ProgramData\\\\staging\\\\"], '
    '"max_depth": "targeted", "next_hypothesis_triggers": []}'
)


# ── Mock factories ────────────────────────────────────────────────────────────


def _http_resp(content: str):
    """Return a mock httpx response with an OpenAI-compatible chat completion."""
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.json.return_value = {
        "choices": [{"message": {"content": content, "reasoning": ""}}]
    }
    return m


# ── Backend context managers ──────────────────────────────────────────────────


@contextmanager
def _compat_ctx(text: str):
    """Context manager that routes calls through the openai-compat backend."""
    http_mock = MagicMock(return_value=_http_resp(text))
    with patch("httpx.post", http_mock), \
         patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
         patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
        yield http_mock


# ── Shared behavioural tests (both backends) ──────────────────────────────────

class TestReasonPlan:
    def _run(self, ctx_fn, text="Investigation plan.\n" + _DIRECTIVES_JSON):
        from tools.reasoning import reason_plan
        with ctx_fn(text):
            return reason_plan("Suspected keylogger on wkstn-01", "memory.img, c-drive.E01")

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_returns_success(self, ctx_fn):
        assert self._run(ctx_fn)["success"] is True

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_directives_parsed(self, ctx_fn):
        r = self._run(ctx_fn)
        assert r["directives"].get("priority_tools") == ["vol.psscan", "vol.cmdline"]

    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_conclusion_strips_directives(self, ctx_fn):
        r = self._run(ctx_fn)
        assert "DIRECTIVES" not in r["conclusion"]
        assert "Investigation plan." in r["conclusion"]


    def test_evidence_capped_at_300_lines_compat(self):
        from tools.reasoning import reason_plan
        big = "\n".join(f"line{i}" for i in range(400))
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_plan("case", big)
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "line399" not in user_msg
        assert "omitted for brevity" in user_msg

    def test_short_evidence_not_trimmed(self):
        from tools.reasoning import reason_plan
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_plan("case", "line1\nline2\nline3")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "line1" in user_msg
        assert "omitted for brevity" not in user_msg

    def test_server_error_has_directives_key_compat(self):
        from tools.reasoning import reason_plan
        with patch("httpx.post", side_effect=Exception("refused")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_plan("case", "evidence")
        assert "directives" in r



class TestReasonHypothesize:
    @pytest.mark.parametrize("ctx_fn", [_compat_ctx])
    def test_returns_success(self, ctx_fn):
        from tools.reasoning import reason_hypothesize
        with ctx_fn("Hypothesis A.\n" + _DIRECTIVES_JSON):
            r = reason_hypothesize("cmd.exe from orphaned PPID 2748 in Session 0")
        assert r["success"] is True

    def test_conclusion_strips_directives(self):
        from tools.reasoning import reason_hypothesize
        content = "Hypothesis: malicious.\nDIRECTIVES:\n{\"priority_tools\": [\"vol.psscan\"]}"
        with patch("httpx.post", return_value=_http_resp(content)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("cmd.exe from orphaned PPID")
        assert "DIRECTIVES" not in r["conclusion"]
        assert "Hypothesis: malicious." in r["conclusion"]

    def test_conclusion_returned_in_full(self):
        from tools.reasoning import reason_hypothesize
        long_text = "A" * 2000
        with patch("httpx.post", return_value=_http_resp(long_text)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert len(r["conclusion"]) == 2000

    def test_context_included_in_request(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize("observation", context="Windows 10, CASE-A")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "CASE-A" in user_msg

    def test_server_unreachable_returns_error(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", side_effect=Exception("connection refused")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "connection refused" in r["error"]

    def test_server_unreachable_has_directives_key(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", side_effect=Exception("refused")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert "directives" in r


class TestReasonEvaluateFinding:
    def test_supported_verdict(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", return_value=_http_resp("VERDICT: SUPPORTED.\n" + _DIRECTIVES_JSON)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_evaluate_finding("Keylogger installed", "Amcache entry, 40/70 VT detections")
        assert r["success"] is True
        assert "SUPPORTED" in r["conclusion"]

    def test_challenged_verdict(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", return_value=_http_resp("VERDICT: CHALLENGED.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_evaluate_finding("gpupdate.exe run by attacker", "Process in memory")
        assert "CHALLENGED" in r["conclusion"]

    def test_decorated_challenged_verdict_still_emits_self_correction(self, tmp_path):
        """Markdown-decorated verdicts ("**VERDICT: CHALLENGED**") must parse —
        an unparseable evaluation makes the CONFIRMED gate refuse
        well-evidenced findings over formatting alone."""
        from core.execution_log import ExecutionLog
        import core.execution_log as elog_mod
        from tools.reasoning import reason_evaluate_finding
        fresh = ExecutionLog()
        fresh.configure("DECORATED-VERDICT", str(tmp_path / "trace.json"))
        with patch.object(elog_mod, "log", fresh), \
             patch("httpx.post", return_value=_http_resp("**Verdict:** *CHALLENGED* — weak evidence.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_evaluate_finding("finding", "evidence")
        scs = [e for e in fresh._entries if e.get("type") == "self_correction"]
        assert scs and scs[-1]["trigger"] == "evaluate_challenged"

    def test_case_context_included(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_evaluate_finding("finding", "evidence", case_context="LAB-7 dataset")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "LAB-7" in user_msg

    def test_directives_present(self):
        from tools.reasoning import reason_evaluate_finding
        with patch("httpx.post", return_value=_http_resp(_DIRECTIVES_JSON)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_evaluate_finding("finding", "evidence")
        assert "directives" in r

    def test_challenged_auto_emits_self_correction(self, tmp_path):
        """When the model returns VERDICT: CHALLENGED, a self_correction trace
        entry must be auto-emitted with trigger='evaluate_challenged' and a
        linked_call_id pointing at the eval call itself. This ensures every
        CHALLENGED moment lands in the trace even when the agent abandons
        the claim instead of attempting record_finding."""
        from core.execution_log import ExecutionLog
        import core.execution_log as elog_mod
        from tools.reasoning import reason_evaluate_finding

        # Bind a fresh log so we can inspect emitted entries deterministically
        inst = ExecutionLog()
        inst.configure("CHALLENGE-AUTO", str(tmp_path / "trace.json"))
        with patch.object(elog_mod, "log", inst), \
             patch("httpx.post", return_value=_http_resp("VERDICT: CHALLENGED. Process record stub.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            result = reason_evaluate_finding(
                "Suspicious binary X is the C2 implant",
                "vol.psscan PID=5024",
            )
        sc_entries = [e for e in inst._entries if e.get("type") == "self_correction"]
        assert len(sc_entries) == 1, f"expected exactly 1 self_correction, got {len(sc_entries)}"
        sc = sc_entries[0]
        assert sc["trigger"] == "evaluate_challenged"
        # The correction must carry the split protocol, not blanket-downgrade
        # advice — post-friction blanket downgrades are an under-tiering
        # mechanism (0 CONFIRMED on directly-captured evidence).
        assert "Split the claim" in sc["new_belief"]
        assert "downgrade the tier" not in sc["new_belief"]
        # linked_call_id should point at the reason_call eval entry (not the
        # call_initiated stub that precedes it)
        eval_entries = [
            e for e in inst._entries
            if e.get("type") == "reason_call" and e.get("tool") == "reason_evaluate_finding"
        ]
        assert len(eval_entries) == 1
        assert sc["linked_call_id"] == eval_entries[0]["call_id"]
        # prior_belief should carry the finding text
        assert "Suspicious binary X" in sc["prior_belief"]

    def test_supported_does_not_emit_self_correction(self, tmp_path):
        """SUPPORTED verdict should leave the trace clean — no self_correction."""
        from core.execution_log import ExecutionLog
        import core.execution_log as elog_mod
        from tools.reasoning import reason_evaluate_finding

        inst = ExecutionLog()
        inst.configure("SUPPORTED-NOEMIT", str(tmp_path / "trace.json"))
        with patch.object(elog_mod, "log", inst), \
             patch("httpx.post", return_value=_http_resp("VERDICT: SUPPORTED. Solid evidence.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_evaluate_finding("legit finding", "good evidence")
        sc_entries = [e for e in inst._entries if e.get("type") == "self_correction"]
        assert sc_entries == []


def _seed_report_phase(tmp_path):
    """Helper: configure execution log + seed a Report-phase dair_call."""
    from core.execution_log import ExecutionLog
    l = ExecutionLog()
    l.configure("TEST", str(tmp_path / "trace.json"))
    l.record_dair_call(
        current_phase="Report",
        phase_rationale="Investigation complete",
        transition_recommended=False,
        next_phase="",
        transition_rationale="",
        stack_action="stay",
        investigation_focus="Synthesize findings",
    )
    return l


class TestReasonSynthesize:
    def test_returns_success(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("Gap: initial access unknown.")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("1. Keylogger\n2. BITS exfil")
        assert r["success"] is True

    def test_investigation_summary_included(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_synthesize("finding 1\nfinding 2", investigation_summary="ran psscan, netscan")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "psscan" in user_msg

    def test_openai_compat_posts_to_completions_endpoint(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_synthesize("findings")
        call_url = m.call_args[0][0]
        assert "v1/chat/completions" in call_url

    def test_directives_present(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp(_DIRECTIVES_JSON)), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("findings")
        assert "directives" in r


class TestSynthesizeGate:
    def test_ids_the_run_has_not_issued_are_refused_before_the_model_is_asked(self, tmp_path):
        """The dispatcher every reason tool consults bounds a given lineage
        list against the ids the trace holds first: an invented id costs a
        refusal that says how many ids exist, never a model call."""
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        top = max(l.index().by_call_id)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("findings", input_call_ids=[top, top + 300])
        assert r["success"] is False and r["gate"] == "lineage_required"
        assert f"the highest is {top}" in r["error"] and r["conclusion"] == ""
        assert m.call_count == 0
        assert not [e for e in l._entries if e.get("type") == "reason_call"]

    def test_synthesize_refused_without_dair_call(self, tmp_path):
        from tools.reasoning import reason_synthesize
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            r = reason_synthesize("findings")
        assert r["success"] is False
        assert "No dair_assess call" in r["error"]

    def test_synthesize_refused_outside_report_phase(self, tmp_path):
        from tools.reasoning import reason_synthesize
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call(
            current_phase="Triage",
            phase_rationale="",
            transition_recommended=False,
            next_phase="",
            transition_rationale="",
            stack_action="stay",
            investigation_focus="",
        )
        with patch("core.execution_log.log", l):
            r = reason_synthesize("findings")
        assert r["success"] is False
        assert "Analyze" in r["error"]
        assert "Triage" in r["error"]

    def test_synthesize_succeeds_in_report_phase(self, tmp_path):
        from tools.reasoning import reason_synthesize
        l = _seed_report_phase(tmp_path)
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("findings")
        assert r["success"] is True

    def test_synthesize_uses_most_recent_dair_call(self, tmp_path):
        """Older dair_call in non-Report doesn't block if most recent is Report."""
        from tools.reasoning import reason_synthesize
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"))
        l.record_dair_call("Triage", "", False, "", "", "stay", "")
        l.record_dair_call("Collect", "", False, "", "", "stay", "")
        l.record_dair_call("Report", "", False, "", "", "stay", "")
        with patch("core.execution_log.log", l), \
             patch("httpx.post", return_value=_http_resp("ok")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_synthesize("findings")
        assert r["success"] is True


class TestBackendConfig:
    def test_claude_backend_returns_removed_error(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.REASON_BACKEND", "claude"):
            r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "no longer supported" in r["error"]
        assert "directives" in r

    def test_missing_reason_url_returns_error(self):
        from tools.reasoning import reason_hypothesize
        with patch("tools.reasoning.REASON_URL", ""), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert r["success"] is False
        assert "REASON_URL" in r["error"]

    def test_auto_detect_compat_when_url_set(self):
        from tools.reasoning import _active_backend
        with patch("tools.reasoning.REASON_BACKEND", ""), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"):
            assert _active_backend() == "openai-compat"

    def test_explicit_backend_overrides_autodetect(self):
        from tools.reasoning import _active_backend
        with patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            assert _active_backend() == "openai-compat"


class TestParseDirectives:
    def test_parses_valid_json_block(self):
        from tools.reasoning import _parse_directives
        text = 'analysis\nDIRECTIVES:\n{"priority_tools": ["vol.psscan"], "skip_tools": []}'
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.psscan"]

    def test_returns_keyed_defaults_on_no_marker(self):
        from tools.reasoning import _parse_directives
        result = _parse_directives("no directives here")
        assert "priority_tools" in result
        assert "skip_tools" in result
        assert result["priority_tools"] == []

    def test_returns_keyed_defaults_on_bad_json(self):
        from tools.reasoning import _parse_directives
        result = _parse_directives("DIRECTIVES:\n{bad json!!!}")
        assert "priority_tools" in result
        assert result["priority_tools"] == []

    def test_returns_keyed_defaults_on_empty_input(self):
        from tools.reasoning import _parse_directives
        result = _parse_directives("")
        assert "priority_tools" in result
        assert result["priority_tools"] == []

    def test_partial_directives_merged_with_defaults(self):
        from tools.reasoning import _parse_directives
        result = _parse_directives('DIRECTIVES:\n{"priority_tools": ["vol.psscan"]}')
        assert result["priority_tools"] == ["vol.psscan"]
        assert "skip_tools" in result
        assert "focus_pids" in result

    def test_case_insensitive_marker(self):
        from tools.reasoning import _parse_directives
        text = 'directives:\n{"focus_pids": [1234]}'
        d = _parse_directives(text)
        assert d["focus_pids"] == [1234]

    def test_accepts_bare_json_without_fences(self):
        from tools.reasoning import _parse_directives
        text = 'DIRECTIVES:\n{"priority_tools": ["ez.amcache"], "skip_tools": ["plaso.*"]}'
        d = _parse_directives(text)
        assert "plaso.*" in d["skip_tools"]

    def test_handles_markdown_bold_marker(self):
        from tools.reasoning import _parse_directives
        text = '**DIRECTIVES:**\n{"priority_tools": ["vol.netscan"], "skip_tools": []}'
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.netscan"]

    def test_handles_json_code_fence(self):
        from tools.reasoning import _parse_directives
        text = 'DIRECTIVES:\n```json\n{"priority_tools": ["vol.malfind"], "focus_pids": [5024]}\n```'
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.malfind"]
        assert d["focus_pids"] == [5024]

    def test_strips_line_comments(self):
        from tools.reasoning import _parse_directives
        text = 'DIRECTIVES:\n{"priority_tools": ["vol.psscan"], "focus_pids": [1234] // check pid\n}'
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.psscan"]

    def test_bold_marker_with_code_fence(self):
        from tools.reasoning import _parse_directives
        text = (
            '**DIRECTIVES:**\n```json\n'
            '{"priority_tools": ["vol.cmdline"], "skip_tools": [], '
            '"focus_pids": [5024], "focus_paths": ["C:\\\\staging\\\\"], '
            '"max_depth": "targeted", "next_hypothesis_triggers": []}\n```'
        )
        d = _parse_directives(text)
        assert d["priority_tools"] == ["vol.cmdline"]
        assert d["max_depth"] == "targeted"


class TestReasonHypothesizeEvidence:
    """Tests for the new `evidence` parameter on reason_hypothesize."""

    def test_evidence_included_in_prompt(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize(
                "periodic connection from WS01 to SRV01 every 2 minutes",
                evidence="1. EID 4624 × 10 at 120-second intervals\n2. toolx.exe MD5 40/70 VT",
            )
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "SUPPORTING EVIDENCE" in user_msg
        assert "EID 4624" in user_msg

    def test_observation_always_first(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize("orphaned PPID", evidence="psscan output", context="CASE-A")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        obs_pos = user_msg.index("OBSERVATION")
        ev_pos = user_msg.index("SUPPORTING EVIDENCE")
        ctx_pos = user_msg.index("CASE CONTEXT")
        assert obs_pos < ev_pos < ctx_pos

    def test_backward_compat_no_evidence(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize("observation", context="Windows 10")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "OBSERVATION" in user_msg
        assert "CASE CONTEXT" in user_msg
        assert "SUPPORTING EVIDENCE" not in user_msg

    def test_no_evidence_no_section(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")) as m, \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_hypothesize("observation only")
        user_msg = m.call_args[1]["json"]["messages"][1]["content"]
        assert "SUPPORTING EVIDENCE" not in user_msg
        assert "CASE CONTEXT" not in user_msg


class TestTokenExtraction:
    """Tests for token usage extraction in both backends."""


    def test_compat_backend_returns_tokens(self):
        from tools.reasoning import reason_hypothesize
        m = MagicMock()
        m.raise_for_status = MagicMock()
        m.json.return_value = {
            "choices": [{"message": {"content": "ok", "reasoning": ""}}],
            "usage": {"prompt_tokens": 400, "completion_tokens": 75},
        }
        with patch("httpx.post", return_value=m), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert r["input_tokens"] == 400
        assert r["output_tokens"] == 75

    def test_compat_backend_missing_usage_defaults_zero(self):
        from tools.reasoning import reason_hypothesize
        with patch("httpx.post", return_value=_http_resp("ok")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_hypothesize("observation")
        assert r["input_tokens"] == 0
        assert r["output_tokens"] == 0



class TestReasonPreReportCheck:
    """Tests for reason_pre_report_check."""

    @pytest.fixture
    def configured_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-PRE", str(tmp_path / "trace.json"))
        # The coverage floor is a real gate now: pre_report_check blocks on
        # the same verdict atlas_finish classifies on. These tests exercise
        # the other checks, so give them a case whose floor is met — the
        # inventory has run and there is nothing to cover.
        import json
        (tmp_path / ".atlas").mkdir(exist_ok=True)
        (tmp_path / ".atlas" / "evidence_inventory.json").write_text(
            json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
        return l

    def test_empty_trace_not_ready(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("empty" in issue.lower() for issue in r["blocking_issues"])

    def test_missing_plan_is_blocking(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("reason.plan" in issue for issue in r["blocking_issues"])

    def test_missing_synthesize_is_blocking(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("reason.synthesize" in issue for issue in r["blocking_issues"])

    def test_confirmed_findings_without_evaluate_is_warning(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_finding("toolx.exe", "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True  # warning only, not blocking
        assert len(r["warnings"]) > 0

    def test_missing_coverage_report_is_warning(self, configured_log):
        # ATT&CK coverage is useful but must not block the report deliverable.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding("toolx.exe", "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert any("coverage_report" in w for w in r["warnings"])
        assert not any("coverage_report" in i for i in r["blocking_issues"])

    def test_coverage_report_executed_clears_the_gate(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding("toolx.exe", "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("coverage_report" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def _record_two_cited_likely(self, configured_log):
        c1 = configured_log.record_tool_call("net.ngrep_search", True, False, 0, 0)
        configured_log.record_finding("Harassing POST from 192.168.15.4", "LIKELY",
                                      "net.ngrep_search", linked_call_id=c1)
        configured_log.record_finding("Gmail session jcoachj via cookies", "LIKELY",
                                      "net.ngrep_search", linked_call_id=c1)

    def test_under_tiering_unevaluated_is_blocking(self, configured_log):
        # 0 CONFIRMED, ≥2 evidence-backed LIKELY, <2 evaluate calls. A
        # warning alone is easy to ignore, so unevaluated under-tiering is a
        # hard gate.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        self._record_two_cited_likely(configured_log)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("evaluate" in i.lower() and "LIKELY" in i
                   for i in r["blocking_issues"])

    def test_under_tiering_after_evaluation_is_warning_only(self, configured_log):
        # The agent evaluated ≥2 findings and stands by LIKELY — a judgment
        # call, so the gate must not force promotion (overclaiming risk).
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "PARTIAL", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "PARTIAL", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        self._record_two_cited_likely(configured_log)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert any("CONFIRMED promotion" in w for w in r["warnings"])

    def _record_happy_path_calls(self, configured_log):
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})

    def test_single_unmapped_attack_finding_warns_within_tolerance(
            self, configured_log):
        # Per-finding contract (post single-digit-coverage plateau): a small
        # remainder of unmapped attack findings (<= TTP_UNMAPPED_BLOCK) warns
        # instead of blocking, so one honest straggler can't deadlock Report.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_finding(
            "toolx.exe is a backdoor beaconing to 198.51.100.2 (CVE-2031-0001)",
            "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert any("MITRE technique" in w for w in r["warnings"])

    def test_unmapped_attack_findings_above_tolerance_warn(
            self, configured_log):
        # ATT&CK labelling is advisory — unmapped attack findings warn but
        # never block Report (timeline/analysis outrank T-ID stamps).
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_finding(
            "toolx2.exe ransomware encrypted the fileserver (T1486)",
            "CONFIRMED", "ez.mftecmd")
        for desc in (
                "toolx.exe is a backdoor beaconing to 198.51.100.2",
                "Dropper wrote payload.dll under ProgramData",
                "Ransomware encrypted share files matching .locked extension"):
            configured_log.record_finding(desc, "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        # Ignore unrelated attribution blockers if any; MITRE must not block.
        assert not any("MITRE technique" in i for i in r["blocking_issues"])
        warned = [w for w in r["warnings"] if "MITRE technique" in w]
        assert warned
        assert "call_ids" in warned[0] and "#" in warned[0]
        # Happy-path + malware-only findings should be report-ready.
        assert r["ready_to_report"] is True

    def test_attack_finding_carrying_technique_clears_the_gate(self, configured_log):
        # New contract: it's not enough that mitre_map *ran* — an attack
        # finding must actually carry a MITRE technique (T-ID in the
        # description here) for the gate to clear.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_tool_call("<py>:correlate_correlate_mitre_map",
                                        True, False, 0, 0)
        configured_log.record_finding(
            "toolx.exe is a backdoor beaconing to 198.51.100.2 (T1071.001)",
            "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("MITRE technique" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def test_mitre_map_running_does_not_clear_unmapped_findings(
            self, configured_log):
        # mitre_map merely *running* is not mapping.
        # An unmapped attack finding still surfaces (as a warning within
        # tolerance) even though mitre_map executed.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_tool_call("<py>:correlate_correlate_mitre_map",
                                        True, False, 0, 0)
        configured_log.record_finding(
            "toolx.exe is a backdoor beaconing to 198.51.100.2",
            "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert any("MITRE technique" in w for w in r["warnings"])

    def test_non_attack_case_skips_mitre_gate(self, configured_log):
        # Harassment/network cases without malware findings must not be
        # forced through MITRE mapping.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_finding(
            "Harassing emails sent from the suspect's Gmail account",
            "CONFIRMED", "net.ngrep_search")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("mitre_map" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def _record_schardt_shaped_findings(self, configured_log, techniques=None):
        # Hacking-tool / sniffing / cracking findings (shaped after the public
        # Hacking Case) with zero malware/CVE vocabulary. A malware-only
        # vocabulary misses all of them and the report goes out with no
        # mapped TTPs.
        gm = {"validated_techniques": techniques} if techniques else None
        configured_log.record_finding(
            "Hacking tools Cain, 123WASP and Look@LAN installed under "
            "Program Files by user Mr. Evil",
            "CONFIRMED", "ez.recmd_hive", gate_metadata=gm)
        configured_log.record_finding(
            "Ethereal interception file recovered — network packet sniffing "
            "of the corporate WLAN",
            "CONFIRMED", "tsk.icat", gate_metadata=gm)
        configured_log.record_finding(
            "Password cracking activity: recovered hash lists staged for "
            "brute-force",
            "CONFIRMED", "strings.strings_grep", gate_metadata=gm)

    def test_schardt_hacking_tool_findings_trigger_attack_warning(self, configured_log):
        # Hacking-tool vocabulary must still surface unmapped attack findings,
        # but as warnings — never block Report for missing T-IDs.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_tool_call("<py>:correlate_correlate_mitre_map",
                                        True, False, 0, 0)
        self._record_schardt_shaped_findings(configured_log)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert any("MITRE technique" in w for w in r["warnings"])
        assert not any("MITRE technique" in i for i in r["blocking_issues"])

    def test_schardt_findings_with_structured_techniques_pass(self, configured_log):
        # The structured mitre_techniques= channel (validated_techniques on
        # the entry) clears both the attack gate and the backstop.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_tool_call("<py>:correlate_correlate_mitre_map",
                                        True, False, 0, 0)
        self._record_schardt_shaped_findings(configured_log,
                                             techniques=["T1040", "T1588.002"])
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("MITRE technique" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def _record_three_neutral_confirmed(self, configured_log):
        # Deliberately no attack-shaped vocabulary — exercises the structural
        # backstop, not the attack-vocabulary gate.
        configured_log.record_finding(
            "Harassing email sent from the suspect's Gmail account",
            "CONFIRMED", "net.ngrep_search")
        configured_log.record_finding(
            "Suspect's laptop was connected to the office network at 14:02",
            "CONFIRMED", "ez.evtxecmd")
        configured_log.record_finding(
            "Document 'letter.docx' authored under the suspect's profile",
            "CONFIRMED", "ez.mftecmd")

    def test_structural_backstop_warns_confirmed_run_without_techniques(
            self, configured_log):
        # >=3 CONFIRMED with no technique → warning only (never blocks Report).
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        self._record_three_neutral_confirmed(configured_log)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert any("MITRE technique" in w for w in r["warnings"])
        assert not any("MITRE technique" in i for i in r["blocking_issues"])

    def test_structural_backstop_optout_via_synthesize(self, configured_log):
        # Genuinely TTP-less cases (harassment, attribution) opt out by
        # stating so in reason.synthesize.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "SUMMARY: harassment confirmed via webmail and printer artifacts. "
            "TTPs: not applicable — harassment case, no attack tooling.", {})
        self._record_three_neutral_confirmed(configured_log)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("MITRE technique" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def test_ttp_optout_honored_from_synthesize_inputs(self, configured_log):
        # Agent puts opt-out in findings payload; model may omit it from
        # conclusion — still pass the structural / mapping gates.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "SUMMARY: hardware attachment confirmed. Analysis complete.",
            {},
        )
        for e in reversed(configured_log._entries):
            if e.get("tool") == "reason_synthesize":
                e["inputs"] = {
                    "user_message": (
                        "FINDINGS:\nC1 CONFIRMED: USB adapter attached.\n"
                        "TTPs: not applicable — workstation config, not ATT&CK."
                    )
                }
                break
        self._record_three_neutral_confirmed(configured_log)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("MITRE technique" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def test_structural_backstop_below_threshold_passes(self, configured_log):
        # 1-2 CONFIRMED findings on a non-attack case must not be forced
        # through MITRE mapping (harassment single-finding pattern).
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_finding(
            "Harassing email sent from the suspect's Gmail account",
            "CONFIRMED", "net.ngrep_search")
        configured_log.record_finding(
            "Suspect's laptop was connected to the office network at 14:02",
            "CONFIRMED", "ez.evtxecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("MITRE technique" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def test_structural_backstop_cleared_by_one_technique(self, configured_log):
        # One finding carrying a T-ID in its description satisfies the
        # backstop for the whole run.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        self._record_three_neutral_confirmed(configured_log)
        configured_log.record_finding(
            "Suspect accessed coworker's mailbox without authorization "
            "(T1078 Valid Accounts)",
            "CONFIRMED", "ez.evtxecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("MITRE technique" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def test_gap_statement_does_not_count_as_optout(self, configured_log):
        # "no TTPs mapped yet" is a gap admission, not an opt-out — still warn,
        # but do not block Report.
        from tools.reasoning import reason_pre_report_check
        self._record_happy_path_calls(configured_log)
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "SUMMARY: strong findings. GAPS: no TTPs mapped yet.", {})
        self._record_three_neutral_confirmed(configured_log)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert any("MITRE technique" in w for w in r["warnings"])
        assert not any("MITRE technique" in i for i in r["blocking_issues"])

    def test_all_checks_pass(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding("toolx.exe", "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert r["blocking_issues"] == []

    # ── BLOCKER detection (negation-aware fallback) ───────────────────────────

    def _full_passing_trace(self, log, synth_conclusion, finding_desc="toolx.exe persistence"):
        log.record_tool_call("vol.psscan", True, False, 0, 0)
        log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        log.record_reason_call("reason_plan", True, "plan", {})
        log.record_reason_call("reason_hypothesize", True, "hyp", {})
        log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        log.record_reason_call("reason_synthesize", True, synth_conclusion, {})
        log.record_finding(finding_desc, "CONFIRMED", "ez.mftecmd")

    def test_negated_blocker_prose_passes(self, configured_log):
        # The old bare-word \bBLOCKER\b fallback wrongly blocked clean syntheses
        # that merely said there were none.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log,
            "All artifact categories exhausted; no blocker conditions found.")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("BLOCKER" in i for i in r["blocking_issues"])

    def test_canonical_blockers_none_passes(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(configured_log, "Synthesis complete.\nBLOCKERS: None")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True

    def test_real_blocker_header_blocks(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log, "Findings incomplete.\nBLOCKERS: identity unresolved")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("BLOCKER" in i for i in r["blocking_issues"])

    def test_unnegated_blocker_prose_blocks(self, configured_log):
        # Non-canonical prose flagging a real blocker still blocks (fallback).
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log, "One blocker remains: registry hive was never parsed.")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("BLOCKER" in i for i in r["blocking_issues"])

    # ── report-gate deadlock relief ───────────────────────────────────────────
    # A genuine dead-end (evidence no tool can parse, an artifact destroyed)
    # must not loop pre_report_check until the turn budget is spent with no
    # report. Two bounded
    # valves: (a) the agent acknowledges a blocker as unresolvable WITH a
    # justification; (b) the system forces budget wrap-up and unresolved
    # content-quality blockers downgrade to documented limitations.

    # A legacy .evt dead-end: extraction succeeded, no tool parses legacy .evt.
    _EVT_DEADEND = (
        "The Windows XP .evt event logs were extracted but no available tool "
        "can parse the legacy binary .evt format (EvtxECmd and hayabusa handle "
        "only .evtx; evtx_dump refused). Extraction was attempted twice."
    )

    def test_acknowledged_unresolvable_blocker_in_header_clears_gate(
            self, configured_log):
        # (a) A BLOCKERS line the agent annotates as genuinely unresolvable with
        # a justification becomes a documented limitation, not a deadlock.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log,
            "SUMMARY: strong findings.\nBLOCKERS: " + self._EVT_DEADEND)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("BLOCKER" in i for i in r["blocking_issues"])
        assert r["documented_limitations"]
        assert any("unresolvable" in w.lower() for w in r["warnings"])

    def test_dedicated_unresolvable_section_clears_a_real_blocker(
            self, configured_log):
        # (a) A dedicated UNRESOLVABLE: section justifies a blocker that the
        # BLOCKERS line itself does not spell out as unresolvable.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log,
            "BLOCKERS: The .evt event logs remain unexamined.\n"
            "UNRESOLVABLE: The .evt logs cannot be parsed by any available "
            "tool; the legacy binary format predates EvtxECmd and hayabusa "
            "support and extraction was attempted twice.")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert r["documented_limitations"]

    def test_inline_ack_records_the_sentence_not_the_whole_blob(
            self, configured_log):
        # The prose-fallback ack carries the acknowledging SENTENCE into the
        # report, not the entire synthesis text (which may be raw model
        # analysis, such as a synthesis that opens "Let me analyze...").
        from tools.reasoning import reason_pre_report_check
        blob = (
            "One blocker remains after the sweep. "
            "Event logs were extracted but no available tool can parse the "
            "legacy .evt format, documented as a limitation. "
            "Then more trailing analysis about findings F4 through F12 follows."
        )
        self._full_passing_trace(configured_log, blob)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert r["documented_limitations"]
        dl = r["documented_limitations"][0]
        assert "no available tool can parse" in dl
        assert "trailing analysis" not in dl
        assert "One blocker remains" not in dl

    def test_bare_unresolvable_without_justification_still_blocks(
            self, configured_log):
        # The hatch requires a substantive justification — a bare "unresolvable"
        # must not rubber-stamp the gate away.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(configured_log, "BLOCKERS: identity unresolvable")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("BLOCKER" in i for i in r["blocking_issues"])

    def test_blocker_hint_names_the_escape_hatch(self, configured_log):
        # The refusal must teach the agent the legitimate escape; with no
        # hatch to reach for, the agent loops instead.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log, "BLOCKERS: registry hive parsing incomplete")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert any("UNRESOLVABLE" in i for i in r["blocking_issues"])

    def test_budget_wrapup_downgrades_unresolved_content_blocker(
            self, configured_log):
        # (b) At the gate level: a real BLOCKERS the agent could not
        # resolve, and the loop forced budget wrap-up. The deliverable
        # must not be lost — the content blocker downgrades to a limitation.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log,
            "BLOCKERS: registry hive parsing incomplete for two SAM accounts")
        # Same trace blocks without the system marker.
        with patch("core.execution_log.log", configured_log):
            blocked = reason_pre_report_check()
        assert blocked["ready_to_report"] is False
        # The loop forces wrap-up near the budget: stamp the system marker.
        configured_log.record_budget_wrapup("turn_budget", 130)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert r["blocking_issues"] == []
        assert r["documented_limitations"]
        assert any("budget wrap-up" in w.lower() for w in r["warnings"])

    def test_stall_wrapup_without_escape_does_not_relax_blockers(
            self, configured_log):
        # A stall/quiet wrap-up with an OPEN coverage ledger stamps
        # allow_synthesize_escape=False. The report gate must honour that
        # flag exactly like the synthesize gate — otherwise any budget_wrapup
        # marker downgrades every content blocker, and a quiet stall still
        # ships a hollow report.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log,
            "BLOCKERS: registry hive parsing incomplete for two SAM accounts")
        configured_log.record_budget_wrapup(
            "progress_stall", 40, allow_synthesize_escape=False)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("BLOCKER" in i for i in r["blocking_issues"])

        # Once the ledger permits (force-report stamps the escape flag),
        # the same trace downgrades as designed.
        configured_log.record_budget_wrapup(
            "progress_stall", 55, allow_synthesize_escape=True)
        with patch("core.execution_log.log", configured_log):
            r2 = reason_pre_report_check()
        assert r2["ready_to_report"] is True
        assert r2["documented_limitations"]

    def test_budget_wrapup_does_not_relax_structural_prereqs(
            self, configured_log):
        # (b) is scoped to content-quality blockers. A missing reason.synthesize
        # is a structural prerequisite and must still block even under wrap-up —
        # a report with no synthesize has no lineage spine.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_finding("toolx.exe persistence", "CONFIRMED", "ez.mftecmd")
        configured_log.record_budget_wrapup("wall_clock", 5)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("reason.synthesize" in i for i in r["blocking_issues"])

    def test_agent_narration_cannot_forge_budget_wrapup(self, configured_log):
        # Only the loop's typed budget_wrapup entry counts. An agent-authored
        # narration containing the wrap-up string must NOT relax the gate,
        # otherwise the agent could bypass it on demand.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log,
            "BLOCKERS: registry hive parsing incomplete for two SAM accounts")
        configured_log.record_agent_message(
            "[budget wrap-up] Only 3 turns remain — writing the report now.")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("BLOCKER" in i for i in r["blocking_issues"])

    def test_instructional_blocker_echo_does_not_block(self, configured_log):
        # A synthesis that re-emits the rubric ("separating BLOCKERS from
        # ADVISORIES") must not deadlock Report.
        from tools.reasoning import reason_pre_report_check
        self._full_passing_trace(
            configured_log,
            "Output a structured punch list, separating BLOCKERS from "
            "ADVISORIES. End with a single canonical line: BLOCKERS: ...")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("BLOCKER" in i for i in r["blocking_issues"])

    def test_unsupported_mitre_stamps_do_not_anti_spam_block(self, configured_log):
        # Unsupported validated_techniques must not count as "carried" — else
        # an immutable bad stamp permanently trips the all-unsupported gate.
        from tools.reasoning import reason_pre_report_check, finding_carries_technique
        self._record_happy_path_calls(configured_log)
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "SUMMARY: hardware attachment. TTPs: not applicable — workstation "
            "config change, not ATT&CK-mappable.", {})
        f = {
            "description": (
                "USB network adapter attached with a wireless profile; config files "
                "modified on the workstation"
            ),
            "confidence": "CONFIRMED",
            "validated_techniques": [
                {"technique_id": "T1098", "relevance": "unsupported"},
                {"technique_id": "T1106", "relevance": "unsupported"},
            ],
        }
        assert finding_carries_technique(f) is False
        configured_log.record_finding(
            f["description"], "CONFIRMED", "strings.strings_grep",
            gate_metadata={"validated_techniques": f["validated_techniques"]})
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("unsupported by their finding" in i
                       for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    def test_superseded_finding_excluded_from_mitre_gates(
            self, configured_log, tmp_path):
        from tools.reasoning import reason_pre_report_check
        from core.claim_graph import empty_graph, save_graph
        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        import json
        (case / ".atlas" / "evidence_inventory.json").write_text(
            json.dumps({"complete": True, "summary": {}}), encoding="utf-8")
        g = empty_graph()
        g["nodes"]["C0001"] = {
            "id": "C0001", "kind": "claim", "status": "superseded",
            "statement": (
                "USB network adapter attached to "
                "host WS01 via USB with a wireless profile"
            ),
            "superseded_by": "C0008",
        }
        g["nodes"]["C0008"] = {
            "id": "C0008", "kind": "claim", "status": "new",
            "statement": (
                "USB composite device enumerated on WS01; "
                "config modified 2031-02-04"
            ),
        }
        save_graph(str(case), g)
        self._record_happy_path_calls(configured_log)
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "SUMMARY: hardware. TTPs: not applicable — config change.", {})
        configured_log.record_finding(
            "USB network adapter attached to "
            "host WS01 via USB with a wireless profile",
            "CONFIRMED", "strings.strings_grep",
            gate_metadata={"validated_techniques": [
                {"technique_id": "T1098", "relevance": "unsupported"},
                {"technique_id": "T1106", "relevance": "unsupported"},
            ]})
        configured_log.record_finding(
            "USB composite device enumerated on WS01; "
            "config modified 2031-02-04",
            "LIKELY", "strings.strings_grep")
        with patch("core.execution_log.log", configured_log), \
             patch.object(configured_log, "case_dir", return_value=str(case)):
            r = reason_pre_report_check()
        assert any("superseded" in w for w in r["warnings"])
        assert not any("unsupported by their finding" in i
                       for i in r["blocking_issues"])
        assert r["ready_to_report"] is True

    # ── Case-question gate (extraction + bounded threshold) ────────────────────

    _POLLUTED_CQ = (
        "CASE_QUESTION: What hacking tools did Greg Schardt install and use? "
        "Plan: verify evidence hash, mount the E01 image, parse SAM SOFTWARE "
        "SYSTEM registry hives via RECmd, enumerate UserAssist Prefetch "
        "AppCompatCache execution artifacts, run DAIR triage collect analyze "
        "scan report phases against all 31 NIST questions"
    )

    def test_polluted_case_question_satisfied_by_finding(self, configured_log):
        # CASE_QUESTION jammed onto one line with plan text used to inflate the
        # token threshold so no finding could satisfy it. Now extraction stops
        # at '?' and the threshold is capped.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_agent_message(self._POLLUTED_CQ)
        configured_log.record_reason_call("reason_synthesize", True, "done\nBLOCKERS: None", {})
        # T-ID attached: "hacking tools" is attack-shaped vocabulary for the
        # MITRE gate, and this test targets the case-question gate, not the
        # MITRE one.
        configured_log.record_finding(
            "Greg Schardt installed and used hacking tools (Cain & Abel, Ethereal, "
            "Network Stumbler) under the Mr. Evil account (T1588.002)",
            "CONFIRMED", "ez.pecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert not any("Case question" in i for i in r["blocking_issues"]), r["blocking_issues"]
        assert r["ready_to_report"] is True

    def test_case_question_unanswered_still_blocks(self, configured_log):
        # The gate must still fire when no finding addresses the question.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_agent_message(self._POLLUTED_CQ)
        configured_log.record_reason_call("reason_synthesize", True, "done\nBLOCKERS: None", {})
        configured_log.record_finding("Disk image acquired and hashed", "CONFIRMED", "ewf.info")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert any("Case question" in i for i in r["blocking_issues"])
        assert r["ready_to_report"] is False

    _MULTI_CQ = (
        "CASE_QUESTION: Investigate the following open requests:\n"
        "- task-0001: What happened on HOST-A during the breach?\n"
        "- task-0002: Was there lateral movement to HOST-B?\n\n"
        "Evidence: disk image and EVTX exports."
    )

    def test_multi_task_case_question_gates_each_request(self, configured_log):
        # Only the first request is answered — second must still block.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_agent_message(self._MULTI_CQ)
        configured_log.record_reason_call("reason_synthesize", True, "done\nBLOCKERS: None", {})
        configured_log.record_finding(
            "HOST-A breach activity included malicious logons and staging (T1078)",
            "CONFIRMED", "ez.evtxecmd")
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        cq_issues = [i for i in r["blocking_issues"] if "Case question" in i]
        assert any("HOST-B" in i or "lateral" in i.lower() for i in cq_issues), cq_issues
        assert not any("HOST-A during the breach" in i for i in cq_issues), cq_issues
        assert r["ready_to_report"] is False

    def test_multi_task_case_question_all_addressed(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_agent_message(self._MULTI_CQ)
        configured_log.record_reason_call("reason_synthesize", True, "done\nBLOCKERS: None", {})
        configured_log.record_finding(
            "HOST-A breach activity included malicious logons and staging (T1078)",
            "CONFIRMED", "ez.evtxecmd")
        configured_log.record_finding(
            "lateral movement to HOST-B via RDP from HOST-A (T1021.001)",
            "CONFIRMED", "ez.evtxecmd")
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert not any("Case question" in i for i in r["blocking_issues"]), r["blocking_issues"]

    def test_token_totals_reported(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_reason_call("reason_plan", True, "plan", {}, input_tokens=300, output_tokens=100)
        configured_log.record_reason_call("reason_synthesize", True, "ok", {}, input_tokens=500, output_tokens=200)
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["total_input_tokens"] == 800
        assert r["total_output_tokens"] == 300

    def test_persists_ready_to_report_in_trace(self, configured_log):
        # The pre_report_check_required gate (on export_execution_log) reads
        # READY_TO_REPORT from the trace
        # entry — pre_report_check must write it.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding("toolx.exe", "CONFIRMED", "ez.mftecmd")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        # Trace entry should exist with the parseable marker.
        pre = [e for e in configured_log._entries
               if e.get("type") == "reason_call"
               and e.get("tool") == "reason_pre_report_check"]
        assert len(pre) == 1
        assert "READY_TO_REPORT: true" in pre[0]["conclusion"]

    def test_persists_ready_false_when_blocked(self, configured_log):
        # Empty trace → blocking issue (start_execution_log not called).
        from tools.reasoning import reason_pre_report_check
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        pre = [e for e in configured_log._entries
               if e.get("type") == "reason_call"
               and e.get("tool") == "reason_pre_report_check"]
        assert len(pre) == 1
        assert "READY_TO_REPORT: false" in pre[0]["conclusion"]

    def test_multi_host_findings_without_correlate_warns(self, configured_log):
        # When findings span ≥2 hosts but no correlate.process_to_file /
        # correlate.network_to_process call was logged, a warning fires
        # (non-blocking).
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_tool_call(
            "<py>:correlate_correlate_mitre_map", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Beacon on 10.0.0.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        configured_log.record_finding(
            "Beacon on 10.0.1.7 PID 1820 (T1021)",
            "CONFIRMED", "vol.netscan")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True  # warning-level
        assert any("correlate" in w for w in r["warnings"])
        assert any("cross-host" in w.lower() for w in r["warnings"])

    def test_multi_host_with_correlate_no_warning(self, configured_log):
        # Same multi-host setup, but a correlate.network_to_process tool_call
        # is present → no cross-host correlation warning.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_tool_call(
            "<py>:correlate_correlate_mitre_map", True, False, 0, 0)
        configured_log.record_tool_call(
            "<py>:correlate_network_to_process", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Beacon on 10.0.0.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        configured_log.record_finding(
            "Beacon on 10.0.1.7 PID 1820 (T1021)",
            "CONFIRMED", "vol.netscan")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("cross-host" in w.lower() for w in r["warnings"])

    def test_single_host_does_not_trigger_correlation_warning(self, configured_log):
        # Single-host case — no correlate.* needed; warning must not fire.
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_tool_call(
            "<py>:correlate_correlate_mitre_map", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Beacon on 10.0.0.11 PID 4044 (T1055)",
            "CONFIRMED", "vol.netscan")
        with patch("core.execution_log.log", configured_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True
        assert not any("cross-host" in w.lower() for w in r["warnings"])

    def test_synthesize_blockers_are_blocking(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "SUMMARY: draft\nBLOCKERS: run roster sweep before attribution\nWARNINGS: none",
            {},
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("reason.synthesize" in issue for issue in r["blocking_issues"])

    def test_synthesize_inline_blocker_labels_are_blocking(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call("vol.psscan", True, False, 0, 0)
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call(
            "reason_synthesize", True,
            "LOGICAL GAPS:\n1. TEMP.ZIP CONTENT GAP (BLOCKER): temp.zip contents were not characterized.\n",
            {},
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("rewording findings" in issue for issue in r["blocking_issues"])

    def test_case_question_ignores_background_after_evidence_marker(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_agent_message(
            "CASE_QUESTION: Did Daniel Roe copy classified ExampleCorp data and what was done with it? "
            "Evidence: segmented E01, email and chat exports."
        )
        configured_log.record_tool_call("ez.evtxecmd 4624", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Daniel Roe copied classified ExampleCorp data and archived it for exfiltration.",
            "LIKELY",
            "ez.mftecmd",
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert not any("Case question" in issue for issue in r["blocking_issues"])

    def test_pcap_human_attribution_requires_identity_closure(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call(
            "tcpdump -r /cases/nitroba/evidence/nitroba.pcap -A",
            True, False, 0, 0,
        )
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Johnny Coach was responsible for the anonymous email from 192.168.15.4",
            "CONFIRMED",
            "net.ngrep_search",
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("structured PCAP identity inventory" in issue for issue in r["blocking_issues"])
        assert any("roster/knowns sweep" in issue for issue in r["blocking_issues"])

    def test_pcap_human_attribution_with_identity_closure_passes(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call(
            "<py>:pcap_identity_timeline roster=CHEM109", True, False, 0, 0
        )
        configured_log.record_tool_call(
            "<py>:knowns_pattern_generate person_username CHEM109", True, False, 0, 0
        )
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Johnny Coach was responsible for the anonymous email from 192.168.15.4",
            "CONFIRMED",
            "net.pcap_identity_timeline",
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True

    def test_pcap_identity_finding_source_counts_as_closure(self, configured_log):
        from tools.reasoning import reason_pre_report_check
        configured_log.record_tool_call(
            "sudo tcpdump -r /cases/nitroba/evidence/nitroba.pcap -nn -A tcp port 80",
            True, False, 0, 0,
        )
        configured_log.record_tool_call(
            "<py>:knowns_pattern_generate person_username CHEM109", True, False, 0, 0
        )
        configured_log.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        configured_log.record_reason_call("reason_plan", True, "plan", {})
        configured_log.record_reason_call("reason_hypothesize", True, "hyp", {})
        configured_log.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        configured_log.record_reason_call("reason_synthesize", True, "ok", {})
        configured_log.record_finding(
            "Structured PCAP identity inventory dispositions every account and the sender is LIKELY Johnny Coach.",
            "LIKELY",
            "net.http_session_inventory",
        )
        with patch("core.execution_log.log", configured_log), \
             patch("tools.reasoning.reason_audit_findings",
                   return_value={"summary": {"candidate_count": 0}, "candidates": []}):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is True


class TestCallInitiatedLogging:
    """Tests for pre-flight call_initiated trace entries in reason.* tools."""

    def test_initiated_and_reason_entries_both_present_on_success(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        text = "Plan.\n" + _DIRECTIVES_JSON
        with patch("core.execution_log.log", inst), _compat_ctx(text):
            reason_plan("keylogger on wkstn-01", "memory.img")
        types = [e["type"] for e in inst._entries]
        assert "call_initiated" in types
        assert "reason_call" in types
        assert types.index("call_initiated") < types.index("reason_call")

    def test_initiated_entry_tool_matches_reason_tool(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Hypothesis.\n" + _DIRECTIVES_JSON):
            reason_hypothesize("svchost.exe with no parent")
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert initiated[0]["tool"] == "reason_hypothesize"
        assert initiated[0]["backend"] == "openai-compat"

    def test_initiated_entry_on_timeout(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             patch("httpx.post", side_effect=TimeoutError("request timed out")), \
             patch("tools.reasoning.REASON_URL", "http://localhost:8000"), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            r = reason_plan("case", "evidence")
        assert r["success"] is False
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert len(initiated) == 1

    def test_initiated_entry_compat_backend(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("TEST-PRE", str(tmp_path / "trace.json"))
        text = "Plan.\n" + _DIRECTIVES_JSON
        with patch("core.execution_log.log", inst), _compat_ctx(text):
            reason_plan("case", "evidence")
        initiated = [e for e in inst._entries if e["type"] == "call_initiated"]
        assert initiated[0]["backend"] == "openai-compat"


_CITE_ALL = (
    'Citation analysis complete.\n'
    'CITE_CHECK:\n'
    '{"verdict": "ALL_CITED", "cited_claims": ["toolx.exe at C:\\\\Windows\\\\Temp"],'
    ' "uncited_claims": [], "rationale": "all claims backed by tool output"}'
)
_CITE_UNCITED = (
    'Two uncited claims.\n'
    'CITE_CHECK:\n'
    '{"verdict": "UNCITED_CLAIMS_PRESENT",'
    ' "cited_claims": ["PID 5024"],'
    ' "uncited_claims": ["parent PID 2748 was orphaned", "process ran from Session 0"],'
    ' "rationale": "two claims without tool citation"}'
)
_CITE_INSUFFICIENT = (
    'CITE_CHECK:\n'
    '{"verdict": "INSUFFICIENT_EVIDENCE", "cited_claims": [], "uncited_claims": [],'
    ' "rationale": "supporting_evidence empty"}'
)


class TestReasonCiteCheck:
    """reason.cite_check verifies claims are backed by citations."""

    def test_all_cited_verdict(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CITE_ALL):
            r = reason_cite_check("toolx.exe at C:\\Windows\\Temp confirmed",
                                  "stat_file: C:\\Windows\\Temp\\toolx.exe size 40960")
        assert r["success"] is True
        assert r["verdict"] == "ALL_CITED"
        assert "toolx.exe at C:\\Windows\\Temp" in r["cited_claims"]
        assert r["uncited_claims"] == []

    def test_uncited_claims_present(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CITE_UNCITED):
            r = reason_cite_check(
                "PID 5024 spawned from orphaned PPID 2748 in Session 0",
                "vol.psscan: PID=5024 PPID=2748",
            )
        assert r["verdict"] == "UNCITED_CLAIMS_PRESENT"
        assert len(r["uncited_claims"]) == 2

    def test_insufficient_evidence_verdict(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CITE_INSUFFICIENT):
            r = reason_cite_check("anything", "")
        assert r["verdict"] == "INSUFFICIENT_EVIDENCE"

    def test_malformed_cite_check_block_returns_defaults(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("no cite_check block here"):
            r = reason_cite_check("finding", "evidence")
        assert r["verdict"] == "INSUFFICIENT_EVIDENCE"
        assert r["cited_claims"] == []
        assert r["uncited_claims"] == []

    def test_cite_check_logged_as_reason_call(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_cite_check
        inst = ExecutionLog()
        inst.configure("CC-005", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CITE_ALL):
            reason_cite_check("finding", "evidence")
        reason_entries = [e for e in inst._entries if e["type"] == "reason_call"]
        assert any(e.get("tool") == "reason_cite_check" for e in reason_entries)


_CONF_CONFIRMED = (
    'CONFIDENCE_SCORE:\n'
    '{"tier": "CONFIRMED", "score": 0.92, '
    '"rationale": "Multiple independent artifacts agree.", '
    '"downgrade_reasons": []}'
)
_CONF_DOWNGRADE = (
    'CONFIDENCE_SCORE:\n'
    '{"tier": "SUSPECTED", "score": 0.40, '
    '"rationale": "YARA hit alone is never above SUSPECTED.", '
    '"downgrade_reasons": ["YARA-only evidence", "no corroborating artifact"]}'
)


class TestReasonConfidenceScore:
    """G-Quality: reason.confidence_score returns evidence-grounded tier."""

    def test_confirmed_score_parsed(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_confidence_score
        inst = ExecutionLog()
        inst.configure("CS-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CONF_CONFIRMED):
            r = reason_confidence_score(
                "toolx.exe is the implant",
                "vol.psscan PID=5024 + tsk.fls match + VT 40/70 + ez.evtxecmd 7045",
                intended_tier="CONFIRMED",
            )
        assert r["success"] is True
        assert r["tier"] == "CONFIRMED"
        assert r["score"] >= 0.85
        assert r["downgrade_reasons"] == []

    def test_downgrade_with_reasons(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_confidence_score
        inst = ExecutionLog()
        inst.configure("CS-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx(_CONF_DOWNGRADE):
            r = reason_confidence_score(
                "helper.dll is Cobalt Strike beacon",
                "YARA rule match only",
                intended_tier="CONFIRMED",
            )
        assert r["tier"] == "SUSPECTED"
        assert len(r["downgrade_reasons"]) > 0
        assert r["score"] < 0.60

    def test_unparseable_returns_unconfirmed_default(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_confidence_score
        inst = ExecutionLog()
        inst.configure("CS-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("no score block here"):
            r = reason_confidence_score("any finding", "any evidence")
        assert r["tier"] == "UNCONFIRMED"
        assert r["score"] == 0.0

    def test_score_clamped_to_unit_range(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_confidence_score
        inst = ExecutionLog()
        inst.configure("CS-004", str(tmp_path / "trace.json"))
        weird = (
            'CONFIDENCE_SCORE:\n{"tier":"CONFIRMED","score":99.0,'
            '"rationale":"x","downgrade_reasons":[]}'
        )
        with patch("core.execution_log.log", inst), _compat_ctx(weird):
            r = reason_confidence_score("a", "b")
        assert 0.0 <= r["score"] <= 1.0


class TestHypothesisIdLineage:
    """Hypothesis lineage: reason_hypothesize generates a hypothesis_id and logs it on reason_call."""

    def test_hypothesize_returns_hypothesis_id(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("HY-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Hypothesis A.\n" + _DIRECTIVES_JSON):
            r = reason_hypothesize("orphan PID 5024")
        assert r["success"] is True
        assert r.get("hypothesis_id", "").startswith("H")

    def test_reason_call_entry_includes_hypothesis_id(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("HY-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("ok\n" + _DIRECTIVES_JSON):
            reason_hypothesize("anomaly")
        reason_entries = [e for e in inst._entries if e["type"] == "reason_call"]
        assert reason_entries[-1].get("hypothesis_id", "").startswith("H")

    def test_hypothesis_id_sequence_increments(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("HY-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("ok\n" + _DIRECTIVES_JSON):
            r1 = reason_hypothesize("obs 1")
            r2 = reason_hypothesize("obs 2")
        assert r1["hypothesis_id"] == "H0001"
        assert r2["hypothesis_id"] == "H0002"

    def test_plan_does_not_get_hypothesis_id(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("HY-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Plan.\n" + _DIRECTIVES_JSON):
            r = reason_plan("case", "evidence")
        assert "hypothesis_id" not in r
        reason_entries = [e for e in inst._entries if e["type"] == "reason_call"]
        assert "hypothesis_id" not in reason_entries[-1]


class TestReasonInputsCaptured:
    """Inputs sent to reason.* models are stored on the reason_call entry."""

    def test_plan_records_user_message(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("IN-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Plan.\n" + _DIRECTIVES_JSON):
            reason_plan("test case description", "pre-enum data")
        entry = [e for e in inst._entries if e.get("tool") == "reason_plan"][-1]
        assert "inputs" in entry
        assert "test case description" in entry["inputs"]["user_message"]
        assert "pre-enum data" in entry["inputs"]["user_message"]
        assert entry["inputs"]["system_prompt_kind"] == "reason_plan"

    def test_hypothesize_records_inputs(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_hypothesize
        inst = ExecutionLog()
        inst.configure("IN-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Hypo.\n" + _DIRECTIVES_JSON):
            reason_hypothesize("orphan PID 5024", evidence="vol.psscan output")
        entry = [e for e in inst._entries if e.get("tool") == "reason_hypothesize"][-1]
        assert "inputs" in entry
        assert "orphan PID 5024" in entry["inputs"]["user_message"]
        assert "vol.psscan output" in entry["inputs"]["user_message"]

    def test_evaluate_finding_records_inputs(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_evaluate_finding
        inst = ExecutionLog()
        inst.configure("IN-003", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), _compat_ctx("Eval.\n" + _DIRECTIVES_JSON):
            reason_evaluate_finding("malicious .exe", "stat output", case_context="CASE-A")
        entry = [e for e in inst._entries if e.get("tool") == "reason_evaluate_finding"][-1]
        assert "inputs" in entry
        assert "malicious .exe" in entry["inputs"]["user_message"]
        assert "CASE-A" in entry["inputs"]["user_message"]

    def test_error_path_still_records_inputs(self, tmp_path):
        # When the reasoning backend is misconfigured, the resulting failed
        # reason_call entry must still capture what was sent.
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_plan
        inst = ExecutionLog()
        inst.configure("IN-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst), \
             patch("tools.reasoning.REASON_URL", ""), \
             patch("tools.reasoning.REASON_BACKEND", "openai-compat"):
            reason_plan("case desc", "evidence")
        entry = [e for e in inst._entries if e.get("tool") == "reason_plan"][-1]
        assert "inputs" in entry
        assert "case desc" in entry["inputs"]["user_message"]


_AUDIT_TWO_CANDIDATES = (
    'I see two unrecorded factual claims.\n'
    'AUDIT_FINDINGS:\n'
    '[\n'
    '  {"narration_call_id": 10, "narration_excerpt": "toolx2.exe is CS beacon",\n'
    '   "suggested_finding": {"description": "toolx2.exe (PID 7000) is a CS beacon implant",\n'
    '                          "suggested_confidence": "CONFIRMED",\n'
    '                          "suggested_source": "vol.netscan"},\n'
    '   "suggested_linked_call_id": 5,\n'
    '   "rationale": "Specific PID + C2 IP/port claim with no finding entry."},\n'
    '  {"narration_call_id": 11, "narration_excerpt": "Rar.exe archiving",\n'
    '   "suggested_finding": {"description": "Rar.exe archived data Feb 4",\n'
    '                          "suggested_confidence": "CONFIRMED",\n'
    '                          "suggested_source": "vol.cmdline"},\n'
    '   "suggested_linked_call_id": 6,\n'
    '   "rationale": "Specific timestamped exfil staging action."}\n'
    ']'
)
_AUDIT_EMPTY = "All claims accounted for.\nAUDIT_FINDINGS:\n[]"


class TestReasonAuditFindings:
    """reason.audit_findings — model-based scan for unrecorded findings."""

    def test_empty_trace_returns_no_candidates(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", inst):
            r = reason_audit_findings()
        assert r["candidates"] == []
        assert r["summary"]["total_narrations"] == 0
        assert r["summary"]["candidate_count"] == 0

    def test_candidates_parsed_from_model(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-002", str(tmp_path / "trace.json"))
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_agent_message("toolx2.exe (PID 7000) is CS beacon")
        inst.record_agent_message("Rar.exe ran Feb 4 archiving data")
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_TWO_CANDIDATES):
            r = reason_audit_findings()
        assert r["summary"]["candidate_count"] == 2
        assert r["candidates"][0]["suggested_finding"]["description"].startswith("toolx2")
        assert r["candidates"][1]["narration_call_id"] == 11

    def test_no_candidates_when_findings_already_recorded(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-003", str(tmp_path / "trace.json"))
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_agent_message("toolx2.exe is CS beacon")
        inst.record_finding("toolx2.exe is CS beacon (PID 7000)", "CONFIRMED",
                            "vol.netscan", linked_call_id=2)
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_EMPTY):
            r = reason_audit_findings()
        assert r["summary"]["candidate_count"] == 0

    def test_logged_as_reason_call(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-004", str(tmp_path / "trace.json"))
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_agent_message("some narration")
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_EMPTY):
            reason_audit_findings()
        # _ask emits both a call_initiated and a reason_call for the same tool
        # name — count only the reason_call.
        rcs = [
            e for e in inst._entries
            if e.get("type") == "reason_call"
            and e.get("tool") == "reason_audit_findings"
        ]
        assert len(rcs) == 1

    def test_narration_window_truncates(self, tmp_path):
        """If 100 narrations exist, narration_window=5 sends only the last 5."""
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-005", str(tmp_path / "trace.json"),
                       save_session=False)
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        for i in range(50):
            inst.record_agent_message(f"narration {i}")
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_EMPTY):
            r = reason_audit_findings(narration_window=5)
        assert r["summary"]["total_narrations"] == 5

    def test_delta_skips_llm_when_no_new_narrations(self, tmp_path):
        """Second audit with no new narrations must not call the model."""
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_audit_findings
        inst = ExecutionLog()
        inst.configure("AF-006", str(tmp_path / "trace.json"),
                       save_session=False)
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_agent_message("toolx2.exe is CS beacon")
        ask = MagicMock(return_value={
            "success": True, "conclusion": _AUDIT_EMPTY, "tokens": {},
        })
        with patch("core.execution_log.log", inst), \
             patch("tools.reasoning._ask", ask):
            first = reason_audit_findings()
            second = reason_audit_findings()
        assert first["summary"]["total_narrations"] == 1
        assert ask.call_count == 1
        assert second["summary"].get("skipped_reason") == "no_new_narrations"
        assert second["candidates"] == []
        assert second.get("gate") == "audit_delta_empty"


class TestPreReportCheckSurfacesAuditWarnings:
    """reason.pre_report_check folds audit_findings results into warnings."""

    def test_warning_added_when_candidates(self, tmp_path):
        from core.execution_log import ExecutionLog
        from tools.reasoning import reason_pre_report_check
        inst = ExecutionLog()
        inst.configure("PRC-A1", str(tmp_path / "trace.json"))
        # Minimal trace that passes the major blocking checks:
        inst.record_dair_call("Triage", "", False, "", "", "stay", "")
        inst.record_reason_call("reason_plan", True, "ok", {})
        inst.record_reason_call("reason_hypothesize", True, "ok", {})
        inst.record_reason_call("reason_synthesize", True, "ok", {})
        # A narration that the audit will flag
        inst.record_agent_message("toolx2.exe is CS beacon")
        with patch("core.execution_log.log", inst), _compat_ctx(_AUDIT_TWO_CANDIDATES):
            r = reason_pre_report_check()
        # Audit count surfaces in warnings; we don't care about other warnings
        assert any("aren't recorded as structured" in w for w in r["warnings"])
        assert r["audit_summary"]["candidate_count"] == 2


class TestPreReportStructuralIntegrity:
    """Structural-integrity checks: covert-account controller (blocking),
    multi-channel exfil (warning), and named-recipient roster x-ref (warning)."""

    @pytest.fixture
    def base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-STRUCT", str(tmp_path / "trace.json"))
        # Satisfy the non-structural blockers up front.
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        l.record_reason_call("reason_hypothesize", True, "hyp", {})
        return l

    def test_covert_account_without_controller_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "Covert local admin account 'svc_x' was created (RID 1500)",
            "CONFIRMED", "ez.recmd")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("svc_x" in i.lower() and "controls it" in i.lower()
                   for i in r["blocking_issues"])

    def test_prose_after_a_cue_word_is_not_an_account_to_disposition(self, base_log):
        """A finding that closes the second-principal question in plain
        English names no account: "principal identified", "user profile" and
        "principal hypothesis" are the next words, not accounts whose
        controller the report must establish."""
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "No second principal identified on this system; no second user "
            "profile; the distinct principal hypothesis is resolved. The 3 "
            "account creation events (4720) are for service accounts.",
            "LIKELY", "ez.evtxecmd")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("controls it" in i.lower() for i in r["blocking_issues"])

    def test_controller_established_by_session_clears_block(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "Covert local admin account 'svc_x' was created (RID 1500)",
            "CONFIRMED", "ez.recmd")
        base_log.record_finding(
            "Account svc_x logged in via RDP logon type 10 from 10.0.0.5",
            "CONFIRMED", "ez.evtxecmd")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("svc_x" in i.lower() for i in r["blocking_issues"])

    def test_controller_parked_unknown_clears_block(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "New user account 'svc_x' was created on the host",
            "LIKELY", "ez.recmd")
        base_log.record_finding(
            "Controller of account svc_x is unknown — requires authentication logs",
            "UNCONFIRMED", "analysis")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("svc_x" in i.lower() for i in r["blocking_issues"])

    def test_multiple_exfil_channels_warns(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "Classified data exfiltrated to cloud via Dropbox", "CONFIRMED", "mft")
        base_log.record_finding(
            "Classified data exfiltrated over FTP to the staging host", "CONFIRMED", "ftp")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("channel" in w.lower() for w in r["warnings"])

    def test_named_recipient_without_xref_warns(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "Stolen research was exfiltrated via email to buyer@evil.example",
            "CONFIRMED", "ost")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("roster" in w.lower() for w in r["warnings"])

    def test_recipient_with_roster_xref_no_warn(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "Stolen research was exfiltrated via email to buyer@evil.example",
            "CONFIRMED", "ost")
        base_log.record_reason_call(
            "reason_evaluate_finding", True,
            "buyer@evil.example cross-referenced against the suspect roster — match", {})
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("roster" in w.lower() for w in r["warnings"])


class TestPreReportHypothesisLedger:
    """FIX 2 — every raised hypothesis must be resolved (cited by a finding's
    tested_hypothesis_id) or parked before Report. A distinct/second-principal
    hypothesis left open BLOCKS ('suspected a second actor then dropped it');
    generic unresolved hypotheses WARN."""

    @pytest.fixture
    def base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-HYP", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        return l

    def test_open_generic_hypothesis_warns_not_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_reason_call(
            "reason_hypothesize", True, "orphaned cmd.exe under session 0", {},
            hypothesis_id="H0001",
            inputs={"user_message": "OBSERVATION: orphaned cmd.exe under session 0"})
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("H0001" in w and "never resolved" in w.lower()
                   for w in r["warnings"])
        assert not any("H0001" in i for i in r["blocking_issues"])

    def test_resolved_generic_hypothesis_no_warn(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_reason_call(
            "reason_hypothesize", True, "orphaned cmd.exe", {},
            hypothesis_id="H0001",
            inputs={"user_message": "OBSERVATION: orphaned cmd.exe under session 0"})
        base_log.record_finding(
            "Orphaned cmd.exe (PID 4012) is a benign scheduler artifact",
            "LIKELY", "vol", tested_hypothesis_id="H0001")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("H0001" in w for w in r["warnings"])
        assert not any("H0001" in i for i in r["blocking_issues"])

    def test_distinct_principal_hypothesis_open_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_reason_call(
            "reason_hypothesize", True, "second operator?", {},
            hypothesis_id="H0002",
            inputs={"user_message":
                    "OBSERVATION: who controls account svc_rdp and how did "
                    "they authenticate?"})
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("H0002" in i and "distinct/second principal" in i.lower()
                   for i in r["blocking_issues"])

    def test_distinct_principal_resolved_by_finding_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_reason_call(
            "reason_hypothesize", True, "second operator?", {},
            hypothesis_id="H0002",
            inputs={"user_message": "OBSERVATION: who controls account svc_rdp?"})
        base_log.record_finding(
            "Account svc_rdp is controlled by an external actor — Security 4624 "
            "logon type 10 from 10.0.0.5", "CONFIRMED", "ez.evtxecmd",
            tested_hypothesis_id="H0002")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("H0002" in i for i in r["blocking_issues"])

    def test_distinct_principal_detected_via_rdp_in_observation(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_reason_call(
            "reason_hypothesize", True, "rdp inbound", {},
            hypothesis_id="H0003",
            inputs={"user_message":
                    "OBSERVATION: an inbound RDP session (logon type 10) "
                    "preceded the data copy"})
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("H0003" in i for i in r["blocking_issues"])


class TestPreReportAttributionClosure:
    """FIX 3b — a human/account verdict needs a logon/RDP inventory somewhere in
    the trace, and every surfaced controller-question principal must be
    dispositioned, before Report."""

    @pytest.fixture
    def base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-CLOSURE", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        l.record_reason_call("reason_hypothesize", True, "hyp", {})
        return l

    def test_verdict_without_logon_enum_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Dana exfiltrated the classified data", "CONFIRMED", "mft")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_verdict_with_evtxecmd_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Dana exfiltrated the classified data", "CONFIRMED", "mft")
        base_log.record_tool_call(
            "dotnet /opt/EZ/EvtxECmd/EvtxECmd.dll -f Security.evtx --inc 4624,4625",
            True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_verdict_with_pyform_eventlog_scan_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Mallory copied the classified research", "CONFIRMED", "mft")
        base_log.record_tool_call("<py>:ez_ez_evtxecmd", True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_verdict_with_linux_last_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding("Dana exfiltrated the classified data", "CONFIRMED", "mft")
        base_log.record_tool_call("last -f /var/log/wtmp", True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_process_attribution_verdict_not_blocked(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "toolx2.exe exfiltrated data to C2 192.0.2.10", "CONFIRMED", "vol")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        # Process/malware attribution (no human/account) → not gated on logon enum.
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])

    def test_surfaced_principal_undispositioned_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_dair_call(
            current_phase="Triage", phase_rationale="pivot",
            transition_recommended=False, next_phase="",
            transition_rationale="", stack_action="stay",
            investigation_focus=("Establish who controls principal SVC_RDP — "
                                 "authentication/source unestablished"))
        base_log.record_finding("Dana exfiltrated data", "CONFIRMED", "mft")
        base_log.record_tool_call("<py>:ez_ez_evtxecmd", True, False, 0, 0)
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("SVC_RDP" in i and "disposition" in i.lower()
                   for i in r["blocking_issues"])

    def test_surfaced_principal_attributed_with_session_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_dair_call(
            current_phase="Triage", phase_rationale="pivot",
            transition_recommended=False, next_phase="",
            transition_rationale="", stack_action="stay",
            investigation_focus="Establish who controls principal SVC_RDP")
        base_log.record_tool_call("<py>:ez_ez_evtxecmd", True, False, 0, 0)
        base_log.record_finding(
            "Account svc_rdp logged in via RDP type 10 from 10.0.0.5 — operated "
            "by an external actor", "CONFIRMED", "ez.evtxecmd")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("SVC_RDP" in i and "disposition" in i.lower()
                       for i in r["blocking_issues"])

    def test_surfaced_principal_parked_unknown_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_dair_call(
            current_phase="Triage", phase_rationale="pivot",
            transition_recommended=False, next_phase="",
            transition_rationale="", stack_action="stay",
            investigation_focus="who controls principal SVC_RDP")
        base_log.record_finding(
            "Controller of account svc_rdp is unknown — requires authentication logs",
            "UNCONFIRMED", "analysis")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("SVC_RDP" in i and "disposition" in i.lower()
                       for i in r["blocking_issues"])

    def test_forced_candidate_pivot_principal_undispositioned_blocks(self, base_log):
        """A forced pivot principal blocks — but only when GROUNDED in tool
        output (phantom-principal guard)."""
        from tools.reasoning import reason_pre_report_check
        base_log.record_dair_call(
            current_phase="Analyze", phase_rationale="assess auth artifacts",
            transition_recommended=False, next_phase="",
            transition_rationale="", stack_action="stay",
            investigation_focus="Review authentication anomalies",
            candidate_pivots=[{
                "kind": "principal",
                "value": "SVC_RDP",
                "phase": "Triage",
                "cue": "forced",
            }])
        base_log.record_finding("Dana exfiltrated data", "CONFIRMED", "mft")
        base_log.record_tool_call(
            "<py>:ez_ez_evtxecmd", True, False, 0, 0,
            stdout_excerpt="4624 TargetUserName=SVC_RDP LogonType=10")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("SVC_RDP" in i and "forced principal candidate" in i
                   for i in r["blocking_issues"])

    def test_phantom_pivot_principal_never_blocks(self, base_log):
        """DAIR is LLM-authored: a forced pivot value that appears in NO tool
        output ('PROCESSES') must not create a disposition blocker."""
        from tools.reasoning import reason_pre_report_check
        base_log.record_dair_call(
            current_phase="Analyze", phase_rationale="assess",
            transition_recommended=False, next_phase="",
            transition_rationale="", stack_action="stay",
            investigation_focus="Review authentication anomalies",
            candidate_pivots=[
                {"kind": "principal", "value": "PROCESSES",
                 "phase": "Triage", "cue": "forced"},
                {"kind": "principal", "value": "GHOST_USER99",
                 "phase": "Triage", "cue": "forced"},
            ])
        base_log.record_finding("Dana exfiltrated data", "CONFIRMED", "mft")
        base_log.record_tool_call(
            "<py>:ez_ez_evtxecmd", True, False, 0, 0,
            stdout_excerpt="4624 TargetUserName=dana LogonType=2")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("PROCESSES" in i for i in r["blocking_issues"])
        assert not any("GHOST_USER99" in i for i in r["blocking_issues"])

    def test_no_verdict_no_block(self, base_log):
        from tools.reasoning import reason_pre_report_check
        base_log.record_finding(
            "A suspicious archive was observed in the staging folder", "SUSPECTED", "mft")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("session-enumeration" in i.lower() for i in r["blocking_issues"])


class TestHypothesizeSplit:
    """Part 1 — reason_hypothesize splits ranked H1…Hn into per-hypothesis records."""

    def test_five_hypotheses_parsed(self):
        from tools.reasoning import _parse_sub_hypotheses
        concl = (
            "ANALYSIS\n\n"
            "H1 — Second principal staged exfil tooling (Likelihood: MEDIUM-HIGH)\n"
            "Rationale: account name 'tempadmin' mimics a system artifact.\n\n"
            "H2 — Mallory created tempadmin as a deniable persona (Likelihood: HIGH)\n"
            "Rationale: PC User is already admin.\n\n"
            "H3 — Guest account is the actual vector (Likelihood: LOW-MEDIUM)\n"
            "Rationale: Guest is NOT disabled.\n\n"
            "H4 — benign printer service account (Likelihood: LOW)\n\n"
            "H5 — malware-created account (Likelihood: LOW)\n"
        )
        subs = _parse_sub_hypotheses(concl, "H0001")
        assert [s["sub_id"] for s in subs] == [f"H0001.{i}" for i in range(1, 6)]
        by = {s["label"]: s for s in subs}
        assert by["H1"]["likelihood_tier"] == "HIGH"    # MEDIUM-HIGH → HIGH
        assert by["H2"]["likelihood_tier"] == "HIGH"
        assert by["H3"]["likelihood_tier"] == "MEDIUM"   # LOW-MEDIUM → MEDIUM
        assert by["H4"]["likelihood_tier"] == "LOW"
        assert "TEMPADMIN" in by["H1"]["entities"]
        assert "GUEST" in by["H3"]["entities"]

    def test_unstructured_conclusion_returns_empty(self):
        from tools.reasoning import _parse_sub_hypotheses
        assert _parse_sub_hypotheses("A single prose hypothesis, no headers.", "H0002") == []
        assert _parse_sub_hypotheses("", "H0003") == []


class TestPreReportHypothesisExhaustion:
    """Part 3 — every MEDIUM+ contested principal must reach a verdict (controller
    established with a session/identity binding, or refuted). Parking ≠ terminal."""

    @pytest.fixture
    def base_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-EXHAUST", str(tmp_path / "trace.json"))
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        return l

    def _seed_hyp(self, log, subs):
        cid = log.record_reason_call("reason_hypothesize", True, "ranked", {},
                                     hypothesis_id="H0001")
        log.update_reason_call(cid, sub_hypotheses=subs)

    def test_unresolved_contested_principal_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [
            {"sub_id": "H0001.1", "label": "H1", "title": "second principal",
             "likelihood_tier": "HIGH", "entities": ["TEMPADMIN"]},
        ])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("TEMPADMIN" in i and "never driven to a verdict" in i
                   for i in r["blocking_issues"])

    def test_parked_only_still_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [
            {"sub_id": "H0001.1", "label": "H1", "title": "second principal",
             "likelihood_tier": "HIGH", "entities": ["TEMPADMIN"]},
        ])
        base_log.record_finding(
            "Controller of tempadmin is PARKED AS UNKNOWN — no session artifact",
            "UNCONFIRMED", "analysis")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert any("TEMPADMIN" in i for i in r["blocking_issues"])

    def test_controller_established_with_session_clears_pair(self, base_log):
        # H1 and H2 share entity tempadmin — a session binding resolves both.
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [
            {"sub_id": "H0001.1", "label": "H1", "title": "second principal",
             "likelihood_tier": "HIGH", "entities": ["TEMPADMIN"]},
            {"sub_id": "H0001.2", "label": "H2", "title": "Mallory persona",
             "likelihood_tier": "HIGH", "entities": ["TEMPADMIN"]},
        ])
        base_log.record_finding(
            "Account tempadmin is operated by an external actor — Security 4624 "
            "logon type 10 from 10.0.0.5", "CONFIRMED", "ez.evtxecmd")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("TEMPADMIN" in i for i in r["blocking_issues"])

    def test_refutation_clears(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [
            {"sub_id": "H0001.3", "label": "H3", "title": "Guest vector",
             "likelihood_tier": "MEDIUM", "entities": ["GUEST"]},
        ])
        base_log.record_finding(
            "Guest-vector hypothesis REFUTED — Guest profile empty beyond the logon",
            "UNCONFIRMED", "analysis")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("GUEST" in i for i in r["blocking_issues"])

    def test_low_only_entity_warns_not_blocks(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [
            {"sub_id": "H0001.5", "label": "H5", "title": "malware account",
             "likelihood_tier": "LOW", "entities": ["SVCBOT"]},
        ])
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert not any("SVCBOT" in i for i in r["blocking_issues"])
        assert any("SVCBOT" in w for w in r["warnings"])

    def test_unresolved_principal_regression(self, base_log):
        from tools.reasoning import reason_pre_report_check
        self._seed_hyp(base_log, [
            {"sub_id": "H0001.1", "label": "H1", "title": "second principal",
             "likelihood_tier": "HIGH", "entities": ["TEMPADMIN"]},
            {"sub_id": "H0001.2", "label": "H2", "title": "Mallory persona",
             "likelihood_tier": "HIGH", "entities": ["TEMPADMIN"]},
            {"sub_id": "H0001.3", "label": "H3", "title": "Guest vector",
             "likelihood_tier": "MEDIUM", "entities": ["GUEST"]},
        ])
        base_log.record_finding(
            "Covert account tempadmin was used to run toolx.exe", "LIKELY", "ez.recmd")
        base_log.record_finding(
            "Controller of tempadmin PARKED AS UNKNOWN — no session artifact",
            "UNCONFIRMED", "analysis")
        with patch("core.execution_log.log", base_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        blk = " ".join(r["blocking_issues"])
        assert "TEMPADMIN" in blk and "GUEST" in blk


class TestOverclaimCapabilityVsAct:
    """A CONFIRMED finding with capability-only vocabulary ('installed and
    configured') and an exfiltration-class technique must draw a warning."""

    @pytest.fixture
    def gated_log(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST-OVERCLAIM", str(tmp_path / "trace.json"))
        l.record_tool_call("vol.psscan", True, False, 0, 0)
        l.record_tool_call("coverage.coverage_report", True, False, 0, 0)
        l.record_reason_call("reason_plan", True, "plan", {})
        l.record_reason_call("reason_hypothesize", True, "hyp", {})
        l.record_reason_call("reason_evaluate_finding", True, "SUPPORTED", {})
        l.record_reason_call("reason_synthesize", True, "ok", {})
        return l

    _GDRIVE_DESC = (
        "Google Drive was installed and configured on the PC with personal "
        "email account person@example.com")
    _GDRIVE_TECH = {"validated_techniques": [
        {"technique_id": "T1567.002",
         "name": "Exfiltration to Cloud Storage",
         "tactic": "Exfiltration"}]}

    def test_capability_confirmed_unevaluated_exfil_blocks(self, gated_log):
        # An installation-only finding tiered CONFIRMED with an
        # exfiltration technique and NO evaluate_finding that reviewed it (the
        # fixture's SUPPORTED eval echoes no description — it is the most-recent
        # fallback the record gate rode). Nothing evidence-aware ever vetted the
        # overclaim, so the report-boundary backstop must BLOCK.
        from tools.reasoning import reason_pre_report_check
        gated_log.record_finding(self._GDRIVE_DESC, "CONFIRMED", "ez.recmd",
                                 gate_metadata=self._GDRIVE_TECH)
        with patch("core.execution_log.log", gated_log):
            r = reason_pre_report_check()
        assert r["ready_to_report"] is False
        assert any("capability" in i.lower() for i in r["blocking_issues"])

    def test_capability_confirmed_with_matched_supported_eval_warns(self, gated_log):
        # Same overclaim shape, but a SUPPORTED reason.evaluate_finding whose
        # user_message echoes THIS finding's description exists — an
        # evidence-aware reviewer signed off, so we defer to it: warning, not
        # a block.
        from tools.reasoning import reason_pre_report_check
        from tools._gates._match import normalize_desc
        gated_log.record_reason_call(
            "reason_evaluate_finding", True,
            "VERDICT: SUPPORTED — sync-log entries cited.", {},
            inputs={"user_message": f"FINDING:\n{normalize_desc(self._GDRIVE_DESC)} "
                                    "and more context"})
        gated_log.record_finding(self._GDRIVE_DESC, "CONFIRMED", "ez.recmd",
                                 gate_metadata=self._GDRIVE_TECH)
        with patch("core.execution_log.log", gated_log):
            r = reason_pre_report_check()
        assert any("capability" in w.lower() for w in r["warnings"])
        assert not any("capability" in i.lower() for i in r["blocking_issues"])

    def test_act_evidence_in_description_passes(self, gated_log):
        from tools.reasoning import reason_pre_report_check
        gated_log.record_finding(
            "Google Drive client uploaded 5 project files per sync log entries "
            "on 2015-03-23",
            "CONFIRMED", "strings.grep",
            gate_metadata={"validated_techniques": [
                {"technique_id": "T1567.002",
                 "name": "Exfiltration to Cloud Storage",
                 "tactic": "Exfiltration"}]})
        with patch("core.execution_log.log", gated_log):
            r = reason_pre_report_check()
        assert not any("capability" in w.lower() for w in r["warnings"])

    def test_capability_without_exfil_technique_passes(self, gated_log):
        from tools.reasoning import reason_pre_report_check
        gated_log.record_finding(
            "Eraser 6.2 was installed and configured on the PC",
            "CONFIRMED", "ez.amcacheparser",
            gate_metadata={"validated_techniques": [
                {"technique_id": "T1070.004", "name": "File Deletion",
                 "tactic": "Defense Evasion"}]})
        with patch("core.execution_log.log", gated_log):
            r = reason_pre_report_check()
        assert not any("capability" in w.lower() for w in r["warnings"])

    def test_evaluate_prompt_contains_capability_vs_act(self):
        from tools.reasoning import _EVALUATE_SYS
        assert "CAPABILITY VS ACT" in _EVALUATE_SYS


# ── Deterministic-first cite_check ───────────────────────────────────────────

class TestDeterministicFirstCiteCheck:
    """String matching runs before the model and settles what it can: values
    the cited call shows need no model, a value the evidence lacks is
    uncited whatever a model would say, and only the ambiguous remainder
    (prose claims, values the trace does not corroborate) is sent."""

    _FINDING = "Beacon from 10.0.1.5 to 198.51.100.7 over 443"
    _EVIDENCE = "vol.netscan: 10.0.1.5:49213 -> 198.51.100.7:443 ESTABLISHED"

    def _log(self, tmp_path, stdout: str):
        from core.execution_log import ExecutionLog
        inst = ExecutionLog()
        inst.configure("CC-D", str(tmp_path / "trace.json"))
        inst._entries.append({"type": "tool_call", "call_id": 7,
                              "cmd": "vol netscan", "stdout_excerpt": stdout})
        return inst

    def _check(self, inst, finding, evidence, call_ids, reply=None):
        from tools.reasoning import reason_cite_check
        with patch("core.execution_log.log", inst), \
             _compat_ctx(reply or _CITE_UNCITED) as client:
            r = reason_cite_check(finding, evidence, input_call_ids=call_ids)
        return r, client

    def _logged(self, inst) -> dict:
        return [e for e in inst._entries
                if e.get("type") == "reason_call"
                and e.get("tool") == "reason_cite_check"][-1]

    def test_values_the_cited_call_shows_need_no_model(self, tmp_path):
        inst = self._log(tmp_path, self._EVIDENCE)
        r, client = self._check(inst, self._FINDING, self._EVIDENCE, [7])
        client.assert_not_called()
        assert r["success"] is True
        assert r["verdict"] == "ALL_CITED"
        assert set(r["cited_claims"]) == {"10.0.1.5", "198.51.100.7"}
        assert r["deterministic"] is True
        logged = self._logged(inst)
        assert "ALL_CITED" in logged["conclusion"]
        assert self._FINDING.lower() in logged["inputs"]["user_message"].lower()

    def test_a_value_the_evidence_lacks_is_flagged_without_the_model(self, tmp_path):
        inst = self._log(tmp_path, self._EVIDENCE)
        r, client = self._check(inst, self._FINDING,
                                "vol.netscan: 10.0.1.5:49213 ESTABLISHED", [7])
        client.assert_not_called()
        assert r["verdict"] == "UNCITED_CLAIMS_PRESENT"
        assert r["uncited_claims"] == ["198.51.100.7"]
        assert "198.51.100.7" in r["rationale"]
        # The gate reads the recorded conclusion: the flag must be there.
        assert "UNCITED_CLAIMS_PRESENT" in self._logged(inst)["conclusion"]

    def test_empty_evidence_is_insufficient_without_the_model(self, tmp_path):
        inst = self._log(tmp_path, self._EVIDENCE)
        r, client = self._check(inst, self._FINDING, "", [7])
        client.assert_not_called()
        assert r["verdict"] == "INSUFFICIENT_EVIDENCE"

    def test_values_the_cited_call_did_not_show_go_to_the_model(self, tmp_path):
        inst = self._log(tmp_path, "vol.netscan: nothing of note")
        r, client = self._check(inst, self._FINDING, self._EVIDENCE, [7],
                                reply=_CITE_ALL)
        client.assert_called_once()
        assert r["verdict"] == "ALL_CITED"
        assert "deterministic" not in r

    def test_prose_claims_go_to_the_model(self, tmp_path):
        inst = self._log(tmp_path, self._EVIDENCE)
        _r, client = self._check(inst, "The operator staged data before exfiltration",
                                 self._EVIDENCE, [7])
        client.assert_called_once()

    def test_without_cited_calls_the_model_decides(self, tmp_path):
        inst = self._log(tmp_path, self._EVIDENCE)
        _r, client = self._check(inst, self._FINDING, self._EVIDENCE, None)
        client.assert_called_once()
