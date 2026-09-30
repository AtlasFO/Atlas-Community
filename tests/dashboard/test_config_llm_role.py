"""dashboard/config_llm.assign_role: the Settings page's Roles in a run table
changes one role's provider without re-saving a provider."""
import pytest

from dashboard import config_llm


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """An isolated .env with two providers, and config_llm pointed at it."""
    (tmp_path / ".env").write_text("", encoding="utf-8")
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
    for name in ("gwalpha", "gwbravo"):
        result = config_llm.save_provider({
            "preset_id": "custom", "name": name,
            "base_url": f"https://{name}.example/v1", "model": f"{name}/model",
            "roles": [], "skip_probe": True,
        })
        _keep(monkeypatch, result["updates"])
    return tmp_path


def _keep(monkeypatch, updates):
    # The config functions also set os.environ for immediate effect, as the
    # dashboard needs; registering each key with monkeypatch keeps it for
    # the test and restores the old value after it.
    for key, value in updates.items():
        monkeypatch.setenv(key, value)


def test_a_role_moves_and_the_other_roles_stay(repo, monkeypatch):
    for role, name in (("analyst", "gwalpha"), ("reason", "gwalpha"), ("dair", "gwbravo")):
        _keep(monkeypatch, config_llm.assign_role(role, name)["updates"])
    result = config_llm.assign_role("reason", "gwbravo")
    _keep(monkeypatch, result["updates"])
    env = (repo / ".env").read_text()
    assert "REASON_BACKEND=gwbravo" in env
    assert "ATLAS_AGENT_PROVIDER=gwalpha" in env
    assert "DAIR_BACKEND=gwbravo" in env
    assert set(result["updates"]) == {"REASON_BACKEND"}


def test_a_role_can_be_turned_off_but_the_analyst_cannot(repo, monkeypatch):
    _keep(monkeypatch, config_llm.assign_role("reviewer", "gwalpha")["updates"])
    result = config_llm.assign_role("reviewer", "")
    _keep(monkeypatch, result["updates"])
    assert "ATLAS_REVIEW_PROVIDER=\n" in (repo / ".env").read_text()
    with pytest.raises(config_llm.ConfigError, match="analyst"):
        config_llm.assign_role("analyst", "")


def test_assigning_a_role_clears_its_model_override(repo, monkeypatch):
    """The override is read before the provider's model; left in place the
    table would show an assignment the run does not follow. It is read from
    the file, where it may have been added after the dashboard started."""
    env = repo / ".env"
    env.write_text(env.read_text() + "DAIR_MODEL=stale/model\nREASON_MODEL=kept/model\n",
                   encoding="utf-8")
    monkeypatch.delenv("DAIR_MODEL", raising=False)
    result = config_llm.assign_role("dair", "gwbravo")
    _keep(monkeypatch, result["updates"])
    assert result["updates"]["DAIR_MODEL"] == ""
    text = env.read_text()
    assert "DAIR_MODEL=\n" in text
    assert "REASON_MODEL=kept/model" in text   # another role's override stays


@pytest.mark.parametrize("role, name, match", [
    ("director", "gwalpha", "no such role"),
    ("reason", "nosuchgw", "no such provider"),
])
def test_an_unknown_role_or_provider_is_refused(repo, role, name, match):
    with pytest.raises(config_llm.ConfigError, match=match):
        config_llm.assign_role(role, name)


def test_the_route_saves_a_role_and_explains_a_refusal(repo, monkeypatch):
    import json

    from dashboard import auth
    from dashboard.app import _post_config_llm_role
    assert auth.effective_min_role("config/llm/role") == "admin"
    ok = _post_config_llm_role(None, None, {"role": "reason", "provider": "gwbravo"})
    assert ok.status_code == 200
    _keep(monkeypatch, json.loads(ok.body)["updates"])
    assert "REASON_BACKEND=gwbravo" in (repo / ".env").read_text()
    refused = _post_config_llm_role(None, None, {"role": "director", "provider": "gwbravo"})
    assert refused.status_code == 400 and b"no such role" in refused.body
    assert _post_config_llm_role(None, None, None).status_code == 400


def test_every_gated_post_route_names_its_minimum_role():
    """The route table is the whole answer to who may call what; a route
    missing from it is admin only by the fail-closed default, which a
    reader of the table cannot see."""
    from dashboard import auth
    from dashboard.app import POST_GATED
    assert not set(POST_GATED) - set(auth.ROUTE_MIN_ROLE)
