"""One alias rule for every place that checks a model id against a
provider's list (core.model_context.listed_model, over match_model_entry):
`atlas provider use`, the dashboard save and the context probe. An alias
named by a dated snapshot or a variant is stored as typed; a match by case
alone stores the list's spelling. Invented model ids only."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.model_context import listed_model

LIST = [{"id": "vendor-small-4-5-20310101"}, {"id": "vendor-small-4-5-20301001"}, {"id": "acme/model-b:free"},
        {"id": "Model-C"}]


@pytest.mark.parametrize("typed,stored", [
    ("vendor-small-4-5", "vendor-small-4-5"),            # dated snapshots: the alias as typed
    ("acme/model-b", "acme/model-b"),                    # a variant: as typed
    ("model-c", "Model-C"),                              # case alone: the list's spelling
    ("Model-C", "Model-C"),
    ("vendor-small-4-5-20310101", "vendor-small-4-5-20310101"),
    ("vendor-large-9", None),
])
def test_the_rule(typed, stored):
    assert listed_model(LIST, typed) == stored


@pytest.fixture
def gw(monkeypatch):
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_API_KEY", "k-1")

    class Resp:
        status_code = 200
        text = ""
    monkeypatch.setattr("core.llmhub.get_models", lambda *a, **k: (Resp(), LIST))


def _use(model):
    from agent import cli
    cli.cmd_provider_use(SimpleNamespace(name="gw", role="analyst", model=model, no_probe=False, dry_run=True,
                                         env=False))


def test_provider_use_takes_an_alias_and_stores_the_lists_case(gw, capsys):
    _use("vendor-small-4-5")
    assert "ATLAS_PROVIDER_GW_MODEL=vendor-small-4-5\n" in capsys.readouterr().out
    _use("model-c")
    assert "ATLAS_PROVIDER_GW_MODEL=Model-C\n" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="not in 'gw'"):
        _use("vendor-large-9")
