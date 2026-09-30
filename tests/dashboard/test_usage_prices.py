"""The price list on Settings, Token spend: which models it offers, that a
row goes only when the admin deletes it or (opted in) when its model leaves
the LLM settings, and that host-labelled ledger rows join their provider."""
from __future__ import annotations

import pytest

from core import usage_import
from core import usage_ledger as ledger
from dashboard import auth, usage_prices as up


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "DEFAULT_DB_PATH", tmp_path / "auth.db")
    auth.init_db()


@pytest.fixture
def llm(monkeypatch):
    """What the LLM settings name, as provider|model keys; None = unreadable."""
    state = {"keys": set(), "providers": []}
    monkeypatch.setattr(up, "configured_keys",
                        lambda: None if state["keys"] is None else set(state["keys"]))
    monkeypatch.setattr(usage_import, "configured", lambda: list(state["providers"]))
    return state


def _listed():
    return {m["key"]: m for m in up.sync()["models"]}


def _record(provider, model):
    ledger.configure(case_id="C1", run_id="R1", command="run")
    ledger.record(role="agent", provider=provider, model=model,
                  input_tokens=10, output_tokens=1)
    ledger.reset()


class TestOffered:
    def test_a_model_in_the_llm_settings_is_listed_on_its_own(self, llm):
        llm["keys"] = {"gw|m1"}
        rows = _listed()
        assert rows["gw|m1"]["configured"] is True and rows["gw|m1"]["used"] is False

    def test_a_model_the_ledger_recorded_is_listed(self, llm):
        _record("gw", "m9")
        assert _listed()["gw|m9"]["used"] is True

    def test_an_unreadable_llm_settings_changes_nothing(self, llm):
        llm["keys"] = {"gw|m1"}
        up.save({"autoremove": True})
        _listed()
        llm["keys"] = None
        assert "gw|m1" in _listed()


class TestDeleteAndAutoremove:
    def test_a_deleted_row_stays_deleted(self, llm):
        llm["keys"] = {"gw|m1"}
        _record("gw", "m9")
        _listed()
        up.delete("gw|m1")
        up.delete("gw|m9")
        assert _listed() == {}

    def test_a_deleted_model_returns_when_added_to_the_llm_settings_again(self, llm):
        llm["keys"] = {"gw|m1"}
        _listed()
        up.delete("gw|m1")
        llm["keys"] = set()
        assert _listed() == {}
        llm["keys"] = {"gw|m1"}
        assert "gw|m1" in _listed()

    def test_without_autoremove_a_removed_model_keeps_its_row_and_price(self, llm):
        llm["keys"] = {"gw|m1"}
        _listed()
        up.save({"prices": {"gw|m1": {"input": 1, "output": 2}}})
        llm["keys"] = set()
        rows = _listed()
        assert rows["gw|m1"]["configured"] is False
        assert up.sync()["prices"]["gw|m1"]["input"] == 1

    def test_with_autoremove_a_removed_model_goes_with_its_price(self, llm):
        llm["keys"] = {"gw|m1", "gw|m2"}
        _listed()
        up.save({"autoremove": True, "prices": {"gw|m1": {"input": 1, "output": 2}}})
        llm["keys"] = {"gw|m2"}
        payload = up.sync()
        assert [m["key"] for m in payload["models"]] == ["gw|m2"]
        assert payload["prices"] == {} and payload["autoremove"] is True

    def test_autoremove_leaves_a_ledger_only_row(self, llm):
        _record("gw", "m9")
        up.save({"autoremove": True})
        assert "gw|m9" in _listed()

    def test_deleting_an_unlisted_key_is_refused(self, llm):
        with pytest.raises(up.PriceError):
            up.delete("gw|nothing")


class TestRelabel:
    def test_host_rows_join_the_provider_that_owns_the_host(self, llm):
        llm["providers"] = [("gw", "https://gw.example/v2", "m1")]
        _record("gw.example", "m1")
        _record("gw", "m1")
        up.save({"prices": {"gw.example|m1": {"input": 1.5, "cached": 0.2, "output": 3.5},
                            "gw|m1": {"input": 0, "cached": 0, "output": 0}}})
        payload = up.sync()
        assert [m["key"] for m in payload["models"]] == ["gw|m1"]
        # a zero price does not win over a real one for the same model
        assert payload["prices"]["gw|m1"] == {"input": 1.5, "cached": 0.2, "output": 3.5}
        assert {r["provider"] for r in ledger.daily_rows("2000-01-01")} == {"gw"}

    def test_a_real_price_on_the_provider_row_stays(self, llm):
        llm["providers"] = [("gw", "https://gw.example/v2", "m1")]
        _record("gw.example", "m1")
        up.save({"prices": {"gw.example|m1": {"input": 1, "output": 1},
                            "gw|m1": {"input": 2, "output": 2}}})
        assert up.sync()["prices"]["gw|m1"]["input"] == 2

    def test_a_host_two_providers_share_is_left_alone(self, llm):
        llm["providers"] = [("a", "https://gw.example/v2", "m1"),
                            ("b", "https://gw.example/v2", "m2")]
        _record("gw.example", "m3")
        assert "gw.example|m3" in _listed()


class TestSave:
    def test_prices_are_checked(self, llm):
        for bad in ({"gw|m1": {"input": -1, "output": 1}},
                    {"gw|m1": {"input": "x", "output": 1}},
                    {"gw|m1": {"output": 1}}, {"no-bar": {"input": 1, "output": 1}}, []):
            with pytest.raises(up.PriceError):
                up.save({"prices": bad})

    def test_currency_and_autoremove_save_on_their_own(self, llm):
        up.save({"prices": {"gw|m1": {"input": 1, "output": 1}}})
        up.save({"currency": "USD"})
        up.save({"autoremove": True})
        payload = up.sync()
        assert payload["currency"] == "USD" and payload["autoremove"] is True
        assert payload["prices"]["gw|m1"]["cached"] is None
