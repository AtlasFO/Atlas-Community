"""The usage ledger: what the transport records, under which context, and
how the dashboard reads it back by period and price."""
from __future__ import annotations

from datetime import date

import pytest

from core import usage_ledger as ledger


def _row(**kw):
    base = dict(role="agent", provider="hub", model="m1", input_tokens=1000,
                output_tokens=100, cached_tokens=0, reasoning_tokens=0,
                usage_reported=True, status="ok")
    base.update(kw)
    return ledger.record(**base)


class TestContext:
    def test_nothing_is_recorded_without_a_case(self):
        assert _row() is False
        assert ledger.daily_rows("2000-01-01") == []

    def test_configure_exports_to_the_environment_for_children(self, monkeypatch):
        import json
        import os
        ledger.configure(case_id="C1", run_id="R1", command="run", started_by="ana")
        assert json.loads(os.environ["ATLAS_USAGE_CONTEXT"])["case_id"] == "C1"
        ledger.configure(command="brain_learn")
        ctx = ledger.current()
        assert ctx["case_id"] == "C1" and ctx["command"] == "brain_learn"

    def test_a_block_context_does_not_leak(self):
        ledger.configure(case_id="C1", run_id="R1", command="run")
        with ledger.context(case_id="C2", command="autofill"):
            assert ledger.current()["case_id"] == "C2"
            assert _row() is True
        assert ledger.current()["case_id"] == "C1"
        cases = {r["case_id"] for r in ledger.daily_rows("2000-01-01")}
        assert cases == {"C2"}

    def test_a_relative_path_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv("ATLAS_USAGE_DB", "relative/usage.db")
        assert ledger.db_path().is_absolute()
        assert not str(ledger.db_path()).endswith("relative/usage.db")

    def test_a_write_failure_never_raises(self, monkeypatch, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_text("x")
        monkeypatch.setenv("ATLAS_USAGE_DB", str(blocker / "usage.db"))
        ledger.configure(case_id="C1", run_id="R1", command="run")
        assert _row() is False


class TestRowsAndPeriods:
    def test_every_rung_and_status_is_one_row(self):
        ledger.configure(case_id="C1", run_id="R1", command="run", started_by="ana")
        _row()
        _row(status="starved")
        _row(status="cut", usage_reported=False, input_tokens=0, output_tokens=0)
        rows = ledger.daily_rows("2000-01-01")
        assert len(rows) == 1
        assert rows[0]["calls"] == 3 and rows[0]["unreported"] == 1
        assert rows[0]["input"] == 2000 and rows[0]["started_by"] == "ana"

    def test_period_keys_follow_iso_weeks_and_utc_months(self):
        assert ledger.period_key("2027-01-01", "week") == "2026-W53"
        assert ledger.period_key("2032-09-27", "week") == "2032-W40"
        assert ledger.period_key("2032-09-27", "month") == "2032-09"

    def test_the_window_starts_on_the_first_of_the_month_or_its_monday(self):
        today = date(2032, 9, 27)
        assert ledger.window_start("month", 3, today) == date(2032, 7, 1)
        assert ledger.window_start("week", 3, today) == date(2032, 6, 28)
        assert ledger.window_start("month", 12, date(2026, 3, 15)) == date(2025, 4, 1)

    def test_cost_prices_cached_input_at_its_own_rate(self):
        prices = {"hub|m1": {"input": 2.0, "cached": 0.5, "output": 8.0}}
        row = {"provider": "hub", "model": "m1", "input": 1_000_000,
               "cached": 400_000, "output": 100_000}
        assert ledger.row_cost(row, prices) == pytest.approx(600_000 * 2.0 / 1e6 + 400_000 * 0.5 / 1e6 + 100_000 * 8.0 / 1e6)
        prices["hub|m1"]["cached"] = None
        assert ledger.row_cost(row, prices) == pytest.approx(2.0 + 0.8)
        assert ledger.row_cost({"provider": "hub", "model": "other", "input": 1, "cached": 0, "output": 1}, prices) is None

    def test_aggregate_groups_runs_into_periods_and_counts_unpriced(self):
        ledger.configure(case_id="C1", run_id="R1", command="run", started_by="ana")
        _row()
        _row(model="m2")
        ledger.configure(case_id="C2", run_id="R2", command="chat", started_by="bo")
        _row()
        agg = ledger.aggregate(ledger.daily_rows("2000-01-01"), "month",
                               {"hub|m1": {"input": 1.0, "cached": None, "output": 1.0}})
        assert len(agg["periods"]) == 1
        runs = agg["periods"][0]["runs"]
        assert {r["run_id"] for r in runs} == {"R1", "R2"}
        assert agg["total"]["runs"] == 2 and agg["total"]["calls"] == 3
        assert agg["total"]["unpriced"] == 1 and agg["unpriced_models"] == ["hub|m2"]
        assert agg["total"]["cost"] == pytest.approx(2 * (1000 + 100) / 1e6)
        assert [c["case_id"] for c in agg["cases"]] and sum(c["runs"] for c in agg["cases"]) == 2

    def test_a_locked_ledger_refuses_a_clear(self, monkeypatch):
        import sqlite3
        ledger.configure(case_id="C1", run_id="R1", command="run")
        _row()
        blocker = sqlite3.connect(str(ledger.db_path()), timeout=0)
        blocker.execute("BEGIN EXCLUSIVE")
        monkeypatch.setattr(ledger, "_TIMEOUT", 0.1)
        try:
            with pytest.raises(sqlite3.OperationalError):
                ledger.clear(None)
        finally:
            blocker.rollback()
            blocker.close()
        assert ledger.clear(None) == 1

    def test_a_removed_ledger_is_recreated_under_a_live_process(self):
        ledger.configure(case_id="C1", run_id="R1", command="run")
        _row()
        ledger.db_path().unlink()
        assert _row() is True
        assert len(ledger.daily_rows("2000-01-01")) == 1

    def test_clear_all_and_before_a_date(self):
        ledger.configure(case_id="C1", run_id="R1", command="run")
        _row()
        assert ledger.clear("2000-01-01") == 0
        assert ledger.clear("2999-01-01") == 1
        _row()
        assert ledger.clear(None) == 1
        assert ledger.models_seen() == []


class TestTransport:
    def test_the_client_records_one_row_per_request(self, monkeypatch):
        from agent import llm
        ledger.configure(case_id="C1", run_id="R1", command="run", started_by="ana")
        client = llm.LLMHubClient(base_url="http://127.0.0.1:9/v1", api_key="k", model="m1")
        reply = llm.ChatResponse(content="ok", input_tokens=50, output_tokens=5,
                                 usage_reported=True)
        monkeypatch.setattr(client, "_send", lambda url, payload, api, prov, model, profile: (reply, profile))
        resp = client.chat([{"role": "user", "content": "hi"}], role="report")
        assert resp.content == "ok"
        rows = ledger.daily_rows("2000-01-01")
        assert len(rows) == 1 and rows[0]["calls"] == 1
        assert rows[0]["model"] == "m1" and rows[0]["input"] == 50
        assert rows[0]["provider"] == "127.0.0.1:9"

    def test_a_client_built_from_an_endpoint_records_the_provider_it_names(self, monkeypatch):
        from agent import llm
        ledger.configure(case_id="C1", run_id="R1", command="run")
        client = llm.LLMHubClient(base_url="http://127.0.0.1:9/v1", api_key="k",
                                  model="m1", usage_provider="gw")
        reply = llm.ChatResponse(content="ok", input_tokens=5, output_tokens=1,
                                 usage_reported=True)
        shaped_for = []

        def send(url, payload, api, prov, model, profile):
            shaped_for.append(prov)
            return reply, profile
        monkeypatch.setattr(client, "_send", send)
        client.chat([{"role": "user", "content": "hi"}], role="dair")
        assert ledger.daily_rows("2000-01-01")[0]["provider"] == "gw"
        # the label is the ledger's only: the request is shaped as before
        assert shaped_for == [""]


class TestRoleLabels:
    """Reasoning and the director resolve their provider into an endpoint;
    the ledger still records the provider's name for their calls."""

    @staticmethod
    def _reply():
        class _Resp:
            status_code = 200
            text = ""

            def raise_for_status(self):
                return None

            def json(self):
                return {"choices": [{"finish_reason": "stop",
                                     "message": {"content": '{"phase": "Triage"}'}}],
                        "usage": {"prompt_tokens": 12, "completion_tokens": 3}}
        return _Resp()

    def test_a_reasoning_call_is_recorded_under_its_provider(self, monkeypatch):
        from unittest.mock import patch
        from tools import reasoning as R
        for name, value in (("REASON_URL", "http://example.test/v1"), ("REASON_API_KEY", "k"),
                            ("REASON_MODEL", "m-reason"), ("REASON_BACKEND", "openai-compat"),
                            ("REASON_PROVIDER", "gw")):
            monkeypatch.setattr(R, name, value)
        ledger.configure(case_id="C1", run_id="R1", command="run")
        with patch("httpx.post", return_value=self._reply()):
            R._ask_openai_compat("system", "question", "reason_hypothesize")
        assert {r["provider"] for r in ledger.daily_rows("2000-01-01")} == {"gw"}

    def test_a_director_call_is_recorded_under_its_provider(self, monkeypatch):
        from unittest.mock import patch
        from tools import dair as D
        for name, value in (("DAIR_URL", "http://example.test/v1"), ("DAIR_API_KEY", "k"),
                            ("DAIR_MODEL", "m-dair"), ("DAIR_BACKEND", "openai-compat"),
                            ("DAIR_PROVIDER", "gw")):
            monkeypatch.setattr(D, name, value)
        ledger.configure(case_id="C1", run_id="R1", command="run")
        with patch("httpx.post", return_value=self._reply()):
            D._ask_openai_compat("system", "assess")
        assert {r["provider"] for r in ledger.daily_rows("2000-01-01")} == {"gw"}

    def test_the_named_provider_survives_the_backend_rewrite(self):
        import os
        import subprocess
        import sys
        from pathlib import Path
        code = ("from tools import reasoning as R, dair as D; "
                "print(R.REASON_BACKEND, R.REASON_PROVIDER, D.DAIR_BACKEND, D.DAIR_PROVIDER)")
        env = {**os.environ, "REASON_BACKEND": "llmhub", "DAIR_BACKEND": "llmhub"}
        out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                             text=True, timeout=180, cwd=Path(__file__).resolve().parents[2])
        assert out.stdout.strip().splitlines()[-1].split() == [
            "openai-compat", "llmhub", "openai-compat", "llmhub"], out.stderr[-2000:]
