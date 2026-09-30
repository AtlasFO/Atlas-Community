"""Events are the addon extension point: core dispatches them, a disabled
addon is reported rather than skipped, and a failing hook never reaches the
run. An optional addon may be absent; it is never silently absent."""
import sys
import textwrap

import pytest

from core import plugins
from core.addons import EVENTS, REPORT_FINALIZED, Addon, hook

_ADDON_SRC = textwrap.dedent('''
    from core.addons import AFTER_TOOL_CALL, REPORT_FINALIZED, Addon, hook

    class ProbeAddon(Addon):
        name = "probe_addon"

        @hook(REPORT_FINALIZED)
        def finalize(self, case_dir: str, report_path: str) -> dict:
            if report_path == "boom":
                raise RuntimeError("addon exploded")
            return {"success": True, "seen": [case_dir, report_path]}

        @hook(AFTER_TOOL_CALL)
        def capture(self, tool_name, args, result) -> None:
            pass
''')


@pytest.fixture
def probe_addon(tmp_path, monkeypatch):
    """An addon package on sys.path, discovered like one under plugins/."""
    pkg = tmp_path / "probe_addon"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(_ADDON_SRC, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(plugins, "discover_plugin_modules",
                        lambda: ["probe_addon"])
    monkeypatch.delenv("ATLAS_PLUGINS", raising=False)
    monkeypatch.delenv("ATLAS_PLUGINS_DISABLED", raising=False)
    yield "probe_addon"
    sys.modules.pop("probe_addon", None)


class TestEventVocabulary:
    def test_unknown_event_is_refused_at_decoration(self):
        with pytest.raises(ValueError, match="unknown addon event"):
            hook("no_such_event")

    def test_dispatching_an_unknown_event_is_refused(self):
        with pytest.raises(ValueError, match="unknown addon event"):
            plugins.dispatch_event("no_such_event")

    def test_report_finalized_is_in_the_vocabulary(self):
        assert REPORT_FINALIZED in EVENTS


class TestDispatch:
    def test_enabled_addon_runs_and_returns_its_result(self, probe_addon):
        out = plugins.dispatch_event(
            REPORT_FINALIZED, case_dir="/c", report_path="/c/r.md")
        assert [o["status"] for o in out] == ["ok"]
        assert out[0]["result"]["seen"] == ["/c", "/c/r.md"]

    def test_disabled_addon_is_reported_not_skipped(self, probe_addon,
                                                    monkeypatch):
        monkeypatch.setenv("ATLAS_PLUGINS_DISABLED", "probe_addon")
        out = plugins.dispatch_event(
            REPORT_FINALIZED, case_dir="/c", report_path="/c/r.md")
        assert out == [{"addon": "probe_addon", "event": REPORT_FINALIZED,
                        "status": "disabled"}]

    def test_globally_disabled_addon_is_reported_too(self, probe_addon,
                                                     monkeypatch):
        monkeypatch.setenv("ATLAS_PLUGINS", "0")
        out = plugins.dispatch_event(
            REPORT_FINALIZED, case_dir="/c", report_path="/c/r.md")
        assert [o["status"] for o in out] == ["disabled"]

    def test_a_raising_hook_is_reported_and_never_propagates(self, probe_addon):
        out = plugins.dispatch_event(
            REPORT_FINALIZED, case_dir="/c", report_path="boom")
        assert out[0]["status"] == "failed"
        assert "addon exploded" in out[0]["error"]

    def test_addons_for_event_says_who_would_produce_it(self, probe_addon,
                                                        monkeypatch):
        assert plugins.addons_for_event(REPORT_FINALIZED) == [
            {"addon": "probe_addon", "enabled": True}]
        monkeypatch.setenv("ATLAS_PLUGINS_DISABLED", "probe_addon")
        assert plugins.addons_for_event(REPORT_FINALIZED) == [
            {"addon": "probe_addon", "enabled": False}]

    def test_an_event_no_addon_hooks_dispatches_to_nothing(self, probe_addon,
                                                           monkeypatch):
        monkeypatch.setattr(plugins, "discover_plugin_modules", lambda: [])
        assert plugins.dispatch_event(REPORT_FINALIZED, case_dir="/c",
                                      report_path="/c/r.md") == []


class TestIsEnabled:
    def test_both_switches_are_honoured(self, monkeypatch):
        monkeypatch.delenv("ATLAS_PLUGINS", raising=False)
        monkeypatch.delenv("ATLAS_PLUGINS_DISABLED", raising=False)
        assert plugins.is_enabled("anything")
        monkeypatch.setenv("ATLAS_PLUGINS_DISABLED", "one,anything,two")
        assert not plugins.is_enabled("anything")
        monkeypatch.delenv("ATLAS_PLUGINS_DISABLED")
        monkeypatch.setenv("ATLAS_PLUGINS", "0")
        assert not plugins.is_enabled("anything")


class TestRegistrationKeepsEventsApart:
    def test_only_after_tool_call_hooks_reach_the_middleware(self):
        """A report hook must not be called with (tool_name, args, result)."""
        class ReportOnly(Addon):
            name = "report_only"

            @hook(REPORT_FINALIZED)
            def finalize(self, case_dir: str, report_path: str) -> dict:
                return {}

        class Fake:
            def __init__(self):
                self.middlewares = []

            def add_middleware(self, mw):
                self.middlewares.append(mw)

        mcp = Fake()
        ReportOnly().register(mcp)
        assert mcp.middlewares == []


class TestBothReportWritersDispatch:
    """The report a run owes is the same report whichever writer produced
    it — the exit-time writer used to deliver less than the tool path."""

    def test_exit_time_report_dispatches_report_finalized(self, tmp_path,
                                                          monkeypatch):
        from agent.cli import _ensure_report_on_exit
        from core import plugins as plug
        from tests.core.test_audit_fixes import _graph_with_claims

        case = tmp_path / "case"
        (case / ".atlas").mkdir(parents=True)
        (case / "evidence").mkdir()
        (case / "CASE.md").write_text(
            "# Case: T\n\n**Case ID:** T\n\n## Investigation Requests\n"
            "- What happened?\n", encoding="utf-8")
        _graph_with_claims(case, 2)

        seen = {}

        def fake_dispatch(event, **payload):
            seen["event"] = event
            seen["payload"] = payload
            return [{"addon": "probe", "event": event, "status": "ok",
                     "result": {"path": "x.tsv"}}]

        monkeypatch.setattr(plug, "dispatch_event", fake_dispatch)

        import core.report_projection as rp
        rp._PROVIDER_DOWN_UNTIL[0] = 0.0
        orig = rp.default_llm_section_generator
        rp.default_llm_section_generator = lambda ctx, sec: (
            _ for _ in ()).throw(RuntimeError("no provider"))

        class FakeAgent:
            stats = {"stopped_reason": "quiet"}

            def _report_written(self):
                return False

        try:
            _ensure_report_on_exit(case, FakeAgent())
        finally:
            rp.default_llm_section_generator = orig
            rp._PROVIDER_DOWN_UNTIL[0] = 0.0

        assert seen["event"] == REPORT_FINALIZED
        assert seen["payload"]["case_dir"] == str(case)
        assert seen["payload"]["report_path"].endswith(
            "reports/T_investigation_report.md")

