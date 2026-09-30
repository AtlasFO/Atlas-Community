"""The reasoning-level vocabulary, and that it agrees with the request path.

The registry in core.effort names each role's environment variable, and
core.llmhub derives that name independently when it resolves a role. Two
derivations of one name is how a setting comes to be written where nothing
reads it, so the first test here holds them together.
"""
import os

import pytest

from core import effort, llmhub


def _clear_effort_env(monkeypatch):
    for var in [k for k in list(os.environ) if k.startswith("ATLAS_EFFORT_")]:
        monkeypatch.delenv(var, raising=False)


class TestRoleRegistry:
    def test_every_role_resolves_through_the_variable_it_advertises(
            self, monkeypatch):
        """Setting a role's advertised variable must change what that role
        sends. This is the drift guard: core.llmhub builds the variable name
        from the role, core.effort states it, and nothing else checks them."""
        for entry in effort.ROLES:
            _clear_effort_env(monkeypatch)
            monkeypatch.setenv(entry.var, "medium")
            assert llmhub.reasoning_effort_for(entry.key) == "medium", entry.key

    def test_the_defaults_match_the_request_path(self, monkeypatch):
        _clear_effort_env(monkeypatch)
        for entry in effort.ROLES:
            expected = effort.normalise(
                llmhub.default_effort_for(entry.key)) or "default"
            assert effort.default_for(entry.key) == expected

    def test_role_keys_are_unique_and_look_up(self):
        keys = [r.key for r in effort.ROLES]
        assert len(keys) == len(set(keys))
        for key in keys:
            assert effort.role(key) is not None
        assert effort.role("not-a-role") is None

    def test_every_role_carries_text_for_the_page_that_sets_it(self):
        """The setting is explained where it is changed, so a role with no
        description would ship a select box nobody can interpret."""
        for entry in effort.ROLES:
            assert entry.label.strip()
            assert len(entry.blurb.strip()) > 40

    def test_the_analyst_is_the_role_a_run_refuses_to_start_without(self):
        assert not any(hasattr(r, "required") for r in effort.ROLES)


class TestNormalise:
    @pytest.mark.parametrize("given", ["low", "LOW", " High ", "medium"])
    def test_accepts_a_level_in_any_casing(self, given):
        assert effort.normalise(given) == given.strip().lower()

    @pytest.mark.parametrize("given", ["", None, "default", "DEFAULT"])
    def test_empty_and_default_are_one_answer(self, given):
        assert effort.normalise(given) == "default"

    @pytest.mark.parametrize("given", ["none", "highest", "1", "off"])
    def test_anything_else_is_refused(self, given):
        """'none' included: it is a value the request path may pin for an
        endpoint that needs it, never a level a user picks for a role."""
        assert effort.normalise(given) == ""


class TestUpdates:
    def test_maps_roles_to_their_variables(self):
        assert effort.updates({"agent": "high", "dair": "low"}) == {
            "ATLAS_EFFORT_AGENT": "high",
            "ATLAS_EFFORT_DAIR": "low",
        }

    def test_a_default_is_written_rather_than_removed(self):
        """The endpoint's own level chosen on purpose is an answer, and the
        analyst refuses to start without one — so it has to be on the file."""
        assert effort.updates({"agent": "default"}) == {
            "ATLAS_EFFORT_AGENT": "default"}

    def test_an_unknown_role_is_refused(self):
        with pytest.raises(ValueError, match="not a model role"):
            effort.updates({"nonesuch": "low"})

    def test_an_unknown_level_is_refused(self):
        with pytest.raises(ValueError, match="not a reasoning level"):
            effort.updates({"agent": "maximum"})

    def test_nothing_is_written_when_one_entry_is_bad(self):
        """Validation precedes the write, so a rejected value cannot leave
        half a form on the file and a run unable to start."""
        with pytest.raises(ValueError):
            effort.updates({"agent": "high", "dair": "maximum"})


class TestSettings:
    def test_reports_configured_effective_and_default(self):
        rows = {r["role"]: r for r in effort.settings(
            {"ATLAS_EFFORT_AGENT": "high"})}
        assert rows["agent"]["value"] == "high"
        assert rows["agent"]["effective"] == "high"
        # A lookup role left alone reports the level it actually runs at.
        assert rows["reason_cite_check"]["value"] == ""
        assert rows["reason_cite_check"]["effective"] == "low"
        assert rows["reason_cite_check"]["default"] == "low"

    def test_a_value_no_longer_understood_is_surfaced_not_hidden(self):
        """A hand-edited file can hold anything. Showing it beats rendering a
        select that silently claims a level the file does not contain."""
        rows = {r["role"]: r for r in effort.settings(
            {"ATLAS_EFFORT_AGENT": "maximum"})}
        assert rows["agent"]["invalid"] == "maximum"
        assert rows["agent"]["value"] == ""

    def test_every_registered_role_is_offered(self):
        rows = effort.settings({})
        assert [r["role"] for r in rows] == [e.key for e in effort.ROLES]
