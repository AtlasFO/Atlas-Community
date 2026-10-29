"""Provider profiles: the shipped files, the user layer, validation, binding
and the security rules of the loader. Invented names and hosts only."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core import provider_profiles as pp

SHIPPED = pp.SHIPPED_DIR
OLD_PRESETS = Path(__file__).resolve().parents[1] / "fixtures" / "llm_requests" / "_presets.json"


def _user(tmp_path: Path, name: str, text: str) -> Path:
    folder = Path(pp.user_dir())
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")
    return folder / name


def _catalog():
    return pp.load(reload=True)


# ── the shipped files ────────────────────────────────────────────────────

def test_every_shipped_profile_validates_and_is_named_by_its_id():
    catalog = _catalog()
    assert catalog.errors == {}
    assert sorted(catalog.profiles) == sorted(p.stem for p in SHIPPED.glob("*.toml"))
    assert len({p.order for p in catalog.profiles.values()}) == len(catalog.profiles)


def test_the_presets_keep_every_field_they_had_as_code():
    """The 14 presets of the menu, moved to files: label, notes and request
    shape equal what the code held, field by field."""
    from core import llm_setup
    now = {p.id: p for p in llm_setup.presets()}
    # The OpenAI-compatible Anthropic preset lives on as anthropic-compat; it
    # sends no thinking budget any more (Claude models from Opus 4.7 on
    # refuse one), which its notes say.
    # The custom profile's note speaks to the user (the Auth fields or a
    # profile file), not of a code class.
    moved, changed = {"anthropic": "anthropic-compat"}, {("anthropic", "thinking_control"), ("anthropic", "notes"),
                                                         ("custom", "notes")}
    for old in json.loads(OLD_PRESETS.read_text(encoding="utf-8")):
        preset = now[moved.get(old["id"], old["id"])]
        for key, value in old.items():
            if key in ("id", "default_choice") or (old["id"], key) in changed:   # default_choice dropped: no preset is pre-selected
                continue
            got = getattr(preset, key)
            assert (list(got) if isinstance(got, tuple) else got) == value, (old["id"], key)
    old_ids = [o["id"] for o in json.loads(OLD_PRESETS.read_text(encoding="utf-8"))]
    assert [p.id for p in llm_setup.presets() if p.id in old_ids] == old_ids    # same relative order


def test_the_base_set_is_shipped_with_no_prices():
    catalog = _catalog()
    for pid in ("groq", "together", "fireworks", "cerebras", "azure-openai", "lmstudio", "vllm", "llamacpp"):
        assert pid in catalog.profiles
    text = "\n".join(p.read_text(encoding="utf-8") for p in SHIPPED.glob("*.toml"))
    assert "price" not in text and "cost" not in text


def test_the_keys_of_schema_1_never_change():
    """A shipped file never renames a key within schema 1, so a git pull
    cannot break a user's override file."""
    schema = json.loads((SHIPPED / "schema.json").read_text(encoding="utf-8"))

    def table(node):
        ref = node.get("$ref", "")
        return schema["$defs"][ref.rsplit("/", 1)[-1]] if ref else node
    tables = {k: sorted(table(v).get("properties", {})) for k, v in schema["properties"].items()
              if "properties" in table(v)}
    assert sorted(schema["properties"]) == sorted([
        "schema", "id", "order", "label", "description", "notes", "evidence", "dialect", "implicit",
        "needs_api_key", "disabled", "connection", "auth", "env", "headers", "request", "reasoning", "models"])
    assert tables == {"connection": ["base_url", "default_model", "models_paging"], "auth": ["header", "prefix"],
                      "env": ["api", "api_key", "base_url", "model", "thinking"],
                      "request": ["max_tools", "rate_limit_counts_cache_reads", "temperature",
                                  "tool_choice_rejected"],
                      "reasoning": ["control", "echo_fields", "levels"]}
    rule = schema["properties"]["models"]["additionalProperties"]
    assert sorted(rule["properties"]) == ["reasoning", "request"]


def test_only_env_names_a_variable_and_its_names_are_shaped_by_role():
    schema = json.loads((SHIPPED / "schema.json").read_text(encoding="utf-8"))
    patterns = {k: v.get("pattern") or v["items"]["pattern"]
                for k, v in schema["properties"]["env"]["properties"].items()}
    assert patterns == {"base_url": "^[A-Z][A-Z0-9_]*_BASE_URL$", "model": "^[A-Z][A-Z0-9_]*_MODEL$",
                        "api_key": "^[A-Z][A-Z0-9_]*_(API_)?KEY$", "thinking": "^[A-Z][A-Z0-9_]*_THINKING$",
                        "api": "^[A-Z][A-Z0-9_]*_API$"}
    def patterns_in(node):
        if isinstance(node, dict):
            yield from ([node["pattern"]] if isinstance(node.get("pattern"), str) else [])
            for value in node.values():
                yield from patterns_in(value)
    others = list(patterns_in({k: v for k, v in schema["properties"].items() if k != "env"}))
    assert others and not [p for p in others if p.startswith("^[A-Z]")]   # no other key holds a variable name


# ── the user layer ───────────────────────────────────────────────────────

def test_a_user_file_changes_only_what_it_names(tmp_path):
    _user(tmp_path, "openrouter.toml", 'schema = 1\nid = "openrouter"\n[connection]\nbase_url = "https://gw.example.com/v1"\n')
    profile = _catalog().profiles["openrouter"]
    assert profile.base_url == "https://gw.example.com/v1"
    assert profile.control == "reasoning_object" and profile.label == "OpenRouter"
    assert profile.source == "merged"


def test_a_user_file_can_add_and_disable_profiles(tmp_path):
    _user(tmp_path, "acme.toml", 'schema = 1\nid = "acme"\nlabel = "Acme"\n[connection]\n'
                                 'base_url = "https://llm.example.com/v1"\n[auth]\nheader = "X-Acme-Key"\n')
    _user(tmp_path, "groq.toml", 'schema = 1\nid = "groq"\ndisabled = true\n')
    _catalog()
    assert pp.get("acme").source == "user" and pp.get("acme").auth_header == "X-Acme-Key"
    assert "groq" not in [p.id for p in pp.menu()]
    with pytest.raises(pp.ProfileError, match="disabled"):
        pp.get("groq")


def test_a_broken_user_file_makes_its_profile_unusable_never_the_shipped_one(tmp_path):
    _user(tmp_path, "openrouter.toml", 'schema = 1\nid = "openrouter"\n[conection]\nbase_url = "x"\n')
    catalog = _catalog()
    assert "openrouter" not in catalog.profiles
    message = catalog.errors["openrouter"]
    assert "provider_profiles.local" in message or str(pp.user_dir()) in message
    assert "'conection' (did you mean 'connection'?)" in message
    with pytest.raises(pp.ProfileError):
        pp.get("openrouter")
    assert "deepseek" in catalog.profiles        # every other profile still loads


@pytest.mark.parametrize("text, reason", [
    ('schema = 1\nid = "openrouter"\nlabel = \n', "not readable as TOML"),
    ('schema = 2\nid = "openrouter"\n', "schema"),
    ('schema = 1\nid = "other"\n', "is not the file name"),
    ('schema = 1\nid = "openrouter"\norder = "first"\n', "order"),
    ('schema = 1\nid = "openrouter"\ndialect = "gemini-native"\n', "is not one Atlas speaks"),
    ('schema = 1\nid = "openrouter"\n[reasoning]\ncontrol = "output_config"\n', "is not how the chat dialect"),
    ('schema = 1\nid = "openrouter"\n[models."m-*".reasoning]\ncontrol = "output_config"\n', 'models."m-*"'),
])
def test_each_rule_names_the_file_the_key_and_the_reason(tmp_path, text, reason):
    _user(tmp_path, "openrouter.toml", text)
    message = _catalog().errors["openrouter"]
    assert "openrouter.toml" in message and reason in message



def test_a_tool_budget_is_declared_per_profile_and_per_model(tmp_path):
    """max_tools: how many tool schemas one request may carry. Anthropic
    declares it; a user file may lower it for one model; a profile that says
    nothing leaves Atlas's common cap."""
    catalog = _catalog()
    assert catalog.profiles["anthropic"].for_model("claude-sonnet-5-5").max_tools == 1000
    assert catalog.profiles["openrouter"].for_model("z-ai/glm-5.2").max_tools is None
    _user(tmp_path, "anthropic.toml", 'schema = 1\nid = "anthropic"\n'
                                      '[models."claude-haiku-5-5*".request]\nmax_tools = 128\n')
    anthropic = _catalog().profiles["anthropic"]
    assert anthropic.for_model("claude-haiku-5-5").max_tools == 128
    assert anthropic.for_model("claude-sonnet-5-5").max_tools == 1000
    # The declared budget is not a request shape: seeded into the learned
    # shape (whose max_tools is the learned ceiling) it would reach a chat.
    assert all("max_tools" not in anthropic.request_shape(m) for m in ("claude-sonnet-5-5", "claude-haiku-5-5"))


@pytest.mark.parametrize("value", ["0", "-5", '"all"', "12.5"])
def test_a_tool_budget_is_a_positive_whole_number(tmp_path, value):
    _user(tmp_path, "openrouter.toml", f'schema = 1\nid = "openrouter"\n[request]\nmax_tools = {value}\n')
    assert "openrouter.toml" in _catalog().errors["openrouter"]

# ── security ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    '[env]\napi_key = ["CLOUD_SECRET_KEY"]\n',
    'implicit = true\n',
])
def test_env_and_implicit_are_refused_in_a_user_file(tmp_path, text):
    _user(tmp_path, "openrouter.toml", 'schema = 1\nid = "openrouter"\n' + text)
    assert "shipped profiles only" in _catalog().errors["openrouter"]


@pytest.mark.parametrize("header", ["Authorization", "authorization", "X-Api-Key", "Api-Key", "Cookie",
                                    "Host", "Content-Type", "Proxy-Authorization", "X-Acme-Key",
                                    "Transfer-Encoding", "Connection", "TE", "Upgrade"])
def test_headers_never_carry_a_credential(tmp_path, header):
    _user(tmp_path, "acme.toml", f'schema = 1\nid = "acme"\nlabel = "Acme"\n[auth]\nheader = "X-Acme-Key"\n'
                                 f'[headers]\n{header} = "v"\n')
    assert "the key goes through [auth]" in _catalog().errors["acme"]


def test_a_user_fallback_file_is_ignored_and_fallback_providers_keep_working(tmp_path, monkeypatch):
    """Every provider no profile claims binds to the fallback: a user file
    there is not read (reported, never an error), so none of them breaks."""
    from core import providers
    _user(tmp_path, "custom.toml", 'schema = 1\nid = "custom"\nnotes = "x"\n')
    catalog = _catalog()
    assert "custom" not in catalog.errors and catalog.profiles["custom"].source == "shipped"
    assert any("cannot be changed by a user file" in why for why in catalog.ignored.values())
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "https://gw.example.com/v1")
    assert providers.resolve("gw").profile == "custom"


def test_a_broken_implicit_profile_names_its_file_and_reason(tmp_path, monkeypatch):
    from core import providers
    _user(tmp_path, "llmhub.toml", 'schema = 1\nid = "llmhub"\nlable = "x"\n')
    _catalog()
    monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
    with pytest.raises(providers.UnknownProvider, match=r"llmhub\.toml.*'lable' \(did you mean 'label'\?\)"):
        providers.resolve("llmhub")


@pytest.mark.parametrize("url, ok", [
    ("https://llm.example.com/v1", True), ("http://localhost:8000/v1", True), ("http://127.0.0.1:9/v1", True),
    ("http://10.0.0.5:8000/v1", True), ("http://llm.example.com/v1", False), ("ftp://llm.example.com", False),
    ("http://169.254.169.254/v1", False),
])
def test_a_base_url_is_https_unless_the_host_is_local(tmp_path, url, ok):
    _user(tmp_path, "acme.toml", f'schema = 1\nid = "acme"\nlabel = "Acme"\n[connection]\nbase_url = "{url}"\n')
    assert ("acme" in _catalog().profiles) is ok


def test_profiles_are_read_from_the_install_never_from_a_case_folder(tmp_path, monkeypatch):
    case = tmp_path / "case"
    (case / "provider_profiles.local").mkdir(parents=True)
    (case / "provider_profiles.local" / "openrouter.toml").write_text(
        'schema = 1\nid = "openrouter"\n[connection]\nbase_url = "https://evil.example.com/v1"\n', encoding="utf-8")
    monkeypatch.chdir(case)
    assert _catalog().profiles["openrouter"].base_url == "https://openrouter.ai/api/v1"


def test_a_header_value_holds_no_line_break(tmp_path):
    _user(tmp_path, "acme.toml", 'schema = 1\nid = "acme"\nlabel = "Acme"\n[headers]\n'
                                 'X-Trace = "a\\r\\nX-Other: b"\n')
    assert "no line break" in _catalog().errors["acme"]


def test_header_values_are_sent_as_written(tmp_path):
    """No interpolation: a value that looks like a placeholder is a literal."""
    _user(tmp_path, "acme.toml", 'schema = 1\nid = "acme"\nlabel = "Acme"\n[headers]\n'
                                 'X-Trace = "${API_KEY} {api_key} $HOME"\n')
    _catalog()
    assert pp.get("acme").headers == {"X-Trace": "${API_KEY} {api_key} $HOME"}


# ── binding ──────────────────────────────────────────────────────────────

def test_an_instance_binds_by_preset_then_by_name_then_to_the_fallback(monkeypatch):
    _catalog()
    monkeypatch.setenv("ATLAS_PROVIDER_GW_PRESET", "OpenRouter")
    profile, rule = pp.bind("gw")
    assert (profile.id, rule) == ("openrouter", "preset")
    profile, rule = pp.bind("DeepSeek")
    assert (profile.id, rule) == ("deepseek", "name")
    assert pp.bind("my-gateway")[0].id == "custom"


def test_a_preset_that_names_no_profile_makes_the_instance_unusable(monkeypatch):
    _catalog()
    monkeypatch.setenv("ATLAS_PROVIDER_GW_PRESET", "openruoter")
    with pytest.raises(pp.ProfileError, match="names no provider profile"):
        pp.bind("gw")


def test_model_rules_apply_most_specific_last_and_add_to_the_level_map(tmp_path):
    _user(tmp_path, "acme.toml", 'schema = 1\nid = "acme"\nlabel = "Acme"\n'
                                 '[reasoning]\nlevels = { low = "low", high = "high", max = "max" }\n'
                                 '[models."m-*".reasoning]\nlevels = { max = "high" }\n'
                                 '[models."m-1*".request]\ntemperature = false\n'
                                 '[models."m-1*".reasoning]\nlevels = { max = "low" }\n')
    p = _catalog().profiles["acme"]
    assert p.for_model("x").levels == {"low": "low", "high": "high", "max": "max"}
    assert p.for_model("m-2").levels == {"low": "low", "high": "high", "max": "high"}
    assert p.for_model("m-12").levels == {"low": "low", "high": "high", "max": "low"}
    assert (p.for_model("m-12").send_temperature, p.for_model("m-2").send_temperature) == (False, True)
    assert p.level_map("m-2") == {"max": "high"}


def test_a_non_chat_profile_binds_by_name_only_at_its_own_host(tmp_path):
    _user(tmp_path, "acme.toml", 'schema = 1\nid = "acme"\nlabel = "Acme"\ndialect = "responses"\n'
                                 '[connection]\nbase_url = "https://llm.example.com/v1"\n')
    _catalog()
    assert pp.bind("acme", "https://llm.example.com/v1")[0].id == "acme"
    profile, rule = pp.bind("acme", "https://gw.example.com/v1")
    assert profile.id == "custom" and "non-chat" in rule


def test_a_broken_profile_never_stops_an_instance_of_another(tmp_path, monkeypatch):
    for text in ('schema = 1\nid = "openrouter"\nlabel = \n', 'schema = 1\nid = "openrouter"\nbogus = 1\n',
                 'schema = 1\nid = "other"\n'):
        _user(tmp_path, "openrouter.toml", text)
        _catalog()
        assert pp.bind("deepseek")[0].id == "deepseek"
        with pytest.raises(pp.ProfileError):
            pp.bind("openrouter")


# ── run pinning ──────────────────────────────────────────────────────────

def test_a_child_process_is_told_when_the_profiles_changed_after_the_run_started(tmp_path):
    _catalog()
    pp.pin_for_children()
    assert pp.child_drift() == ""
    _user(tmp_path, "groq.toml", 'schema = 1\nid = "groq"\nnotes = "edited"\n')
    _catalog()
    assert "changed since the run started" in pp.child_drift()


# ── the profile's auth and headers reach every request path ─────────────

def _listing(monkeypatch):
    from unittest.mock import MagicMock
    seen = {}

    def fake_get(url, headers=None, timeout=None):
        seen.update(url=url, headers=dict(headers or {}))
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": [{"id": "deployment-a"}]}
        return resp

    monkeypatch.setattr("httpx.get", fake_get)
    return seen


def test_a_probe_before_a_save_speaks_with_the_chosen_profile(monkeypatch):
    """The wizard and the settings form test a provider not saved yet: the
    profile they show decides the auth header (Azure: the key bare in api-key)."""
    from core import llm_setup
    from dashboard import config_llm
    seen = _listing(monkeypatch)
    base = "https://res-a.openai.azure.com/openai/v1"
    assert llm_setup.probe(base, "k-test", profile_id="azure-openai").ok
    assert seen["headers"].get("api-key") == "k-test" and "Authorization" not in seen["headers"]
    config_llm.probe(base, "k-test", preset_id="azure-openai")
    assert seen["headers"].get("api-key") == "k-test"
    llm_setup.probe(base, "k-test")
    assert seen["headers"].get("Authorization") == "Bearer k-test"


def test_a_saved_provider_binds_its_profile_auth_and_its_own_variables_win(monkeypatch):
    from core import providers
    monkeypatch.setenv("ATLAS_PROVIDERS", "az")
    monkeypatch.setenv("ATLAS_PROVIDER_AZ_BASE_URL", "https://res-a.openai.azure.com/openai/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_AZ_API_KEY", "k-test")
    monkeypatch.setenv("ATLAS_PROVIDER_AZ_PRESET", "azure-openai")
    provider = providers.resolve("az")
    assert (provider.profile, provider.auth_header, provider.auth_prefix) == ("azure-openai", "api-key", "")
    assert provider.headers() == {"Content-Type": "application/json", "api-key": "k-test"}
    monkeypatch.setenv("ATLAS_PROVIDER_AZ_AUTH_HEADER", "Authorization")
    assert providers.resolve("az").headers()["Authorization"] == "Bearer k-test"


def test_an_unusable_profile_stops_its_provider_with_the_reason(monkeypatch, tmp_path):
    from core import providers
    _user(tmp_path, "openrouter.toml", 'schema = 1\nid = "openrouter"\nbogus = 1\n')
    _catalog()
    monkeypatch.setenv("ATLAS_PROVIDERS", "openrouter")
    monkeypatch.setenv("ATLAS_PROVIDER_OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    with pytest.raises(providers.UnknownProvider, match="bogus"):
        providers.resolve("openrouter")


def test_doctor_names_the_profile_of_a_providers_host_but_never_binds_by_host(monkeypatch, capsys):
    from agent import cli
    from core import providers
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "https://api.anthropic.com/v1")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_MODEL", "m")
    provider = providers.resolve("gw")
    assert provider.profile == "custom" and "anthropic-version" not in provider.headers()
    line = cli._doctor_binding("gw", provider, pp, providers)
    assert "profile=custom (fallback; shipped: provider_profiles/custom.toml)" in line
    assert "url from ATLAS_PROVIDER_GW_BASE_URL" in line and "ATLAS_PROVIDER_GW_PRESET=anthropic" in line


def test_a_providers_url_says_where_it_comes_from(tmp_path, monkeypatch):
    """The hub's URL comes from its variable or from its profile file; a user
    file over the shipped one shows as merged."""
    from core import providers
    monkeypatch.delenv("LLMHUB_BASE_URL", raising=False)
    _catalog()
    assert providers.url_source("llmhub") == "from profile llmhub (shipped: provider_profiles/llmhub.toml)"
    _user(tmp_path, "llmhub.toml", 'schema = 1\nid = "llmhub"\n[connection]\nbase_url = "https://hub.example.com/v2"\n')
    _catalog()
    assert providers.resolve("llmhub").base_url == "https://hub.example.com/v2"
    assert "merged: provider_profiles/llmhub.toml, " in providers.url_source("llmhub")
    monkeypatch.setenv("LLMHUB_BASE_URL", "https://hub2.example.com/v2")
    assert providers.url_source("llmhub") == "from LLMHUB_BASE_URL"
    monkeypatch.setenv("ATLAS_PROVIDERS", "gw")
    monkeypatch.setenv("ATLAS_PROVIDER_GW_BASE_URL", "https://gw.example.com/v1")
    assert providers.url_source("gw") == "from ATLAS_PROVIDER_GW_BASE_URL"


def test_a_profile_says_whether_the_rate_limit_counts_cache_reads(tmp_path):
    """Default: everything counts. A rule can say otherwise for some models."""
    from agent import llm
    _user(tmp_path, "acme.toml", 'schema = 1\nid = "acme"\nlabel = "Acme"\n'
                                 '[models."m-cached*".request]\nrate_limit_counts_cache_reads = false\n')
    catalog = _catalog()
    assert catalog.profiles["acme"].for_model("m-1").rate_limit_counts_cache_reads is True
    assert catalog.profiles["acme"].for_model("m-cached-2").rate_limit_counts_cache_reads is False
    assert llm.resolve_api_compat("", "m-1", "acme").pace_cache_reads is True
    assert llm.resolve_api_compat("", "m-cached-2", "acme").pace_cache_reads is False
    assert llm.resolve_api_compat("", "claude-x", "anthropic").pace_cache_reads is False
    assert llm.resolve_api_compat("", "claude-x", "anthropic-compat").pace_cache_reads is True
