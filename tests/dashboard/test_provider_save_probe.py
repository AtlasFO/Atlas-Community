"""A provider save checks the endpoint with the provider's own profile and
key (the bound one on an edit, the stored key when the field is left blank,
none for a keyless profile) and makes no model call: a model the listing
does not show saves only after Test connection got an answer for the same
base URL, model and profile. A local recording stub; invented names only."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core import provider_profiles
from dashboard import config_llm

ACME = """schema = 1
id = "acme"
label = "Acme gateway"
dialect = "chat"

[connection]
base_url = "https://llm.example.com/v1"

[auth]
header = "X-Acme-Key"
prefix = ""
"""
OPEN = """schema = 1
id = "openbox"
label = "Open box"
dialect = "chat"
needs_api_key = false

[connection]
base_url = "http://127.0.0.1:9/v1"
"""


@pytest.fixture
def stub():
    seen: list[tuple[str, str, dict]] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            seen.append(("GET", self.path, dict(self.headers)))
            self._send(200, {"data": [{"id": "model-a"}]})

        def do_POST(self):
            seen.append(("POST", self.path, dict(self.headers)))
            self._send(200, {"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1", seen
    srv.shutdown()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("", encoding="utf-8")
    prof = tmp_path / "profiles"
    prof.mkdir()
    (prof / "acme.toml").write_text(ACME, encoding="utf-8")
    (prof / "openbox.toml").write_text(OPEN, encoding="utf-8")
    monkeypatch.setenv("ATLAS_PROVIDER_PROFILES_DIR", str(prof))
    provider_profiles.load(reload=True)
    monkeypatch.setattr(config_llm, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("ATLAS_PROVIDERS", raising=False)
    yield tmp_path
    provider_profiles.load(reload=True)


def _saved(monkeypatch, url, name="gw2", preset="acme", key="k-stored"):
    monkeypatch.setenv("ATLAS_PROVIDERS", name)
    stem = name.upper()
    monkeypatch.setenv(f"ATLAS_PROVIDER_{stem}_BASE_URL", url)
    monkeypatch.setenv(f"ATLAS_PROVIDER_{stem}_MODEL", "model-a")
    monkeypatch.setenv(f"ATLAS_PROVIDER_{stem}_PRESET", preset)
    if key:
        monkeypatch.setenv(f"ATLAS_PROVIDER_{stem}_API_KEY", key)


def test_an_edit_save_checks_with_the_bound_profile_and_the_stored_key(repo, stub, monkeypatch):
    url, seen = stub
    _saved(monkeypatch, url)
    config_llm.save_provider({"name": "gw2", "base_url": url, "model": "model-a", "preset_id": "", "api_key": ""})
    gets = [h for m, _p, h in seen if m == "GET"]
    assert gets and gets[0].get("X-Acme-Key") == "k-stored" and "Authorization" not in gets[0]
    assert not [1 for m, _p, _h in seen if m == "POST"]          # no model call on save


def test_a_model_the_listing_does_not_show_needs_a_test_of_these_values(repo, stub, monkeypatch):
    url, seen = stub
    _saved(monkeypatch, url)
    data = {"name": "gw2", "base_url": url, "model": "model-z", "preset_id": "acme", "api_key": ""}
    with pytest.raises(config_llm.ConfigError, match="press Test connection"):
        config_llm.save_provider(data)
    with pytest.raises(config_llm.ConfigError):
        config_llm.save_provider({**data, "tested": {"base_url": url, "model": "model-a", "profile": "acme"}})
    config_llm.save_provider({**data, "tested": {"base_url": url + "/", "model": "model-z", "profile": "acme"}})
    assert "ATLAS_PROVIDER_GW2_MODEL=model-z" in (repo / ".env").read_text()
    assert not [1 for m, _p, _h in seen if m == "POST"]


def test_a_keyless_profile_is_checked_on_save_without_a_key(repo, stub, monkeypatch):
    url, seen = stub
    config_llm.save_provider({"name": "box", "base_url": url, "model": "model-a", "preset_id": "openbox",
                              "api_key": ""})
    assert [1 for m, _p, _h in seen if m == "GET"]


def test_a_typed_key_is_checked_without_a_pastes_edge_whitespace(repo, stub, monkeypatch):
    url, seen = stub
    config_llm.probe(url, "  k-typed \t", name="gw4", preset_id="acme")
    gets = [h for m, _p, h in seen if m == "GET"]
    assert gets and gets[0].get("X-Acme-Key") == "k-typed"


def test_a_keyed_profile_with_no_key_anywhere_is_saved_unchecked(repo, stub, monkeypatch):
    url, seen = stub
    config_llm.save_provider({"name": "gw3", "base_url": url, "model": "model-a", "preset_id": "acme",
                              "api_key": ""})
    assert seen == []


def test_a_model_matched_by_case_alone_is_saved_as_the_list_spells_it(repo, stub, monkeypatch):
    url, _seen = stub
    _saved(monkeypatch, url)
    config_llm.save_provider({"name": "gw2", "base_url": url, "model": "MODEL-A", "preset_id": "acme",
                              "api_key": ""})
    assert "ATLAS_PROVIDER_GW2_MODEL=model-a\n" in (repo / ".env").read_text()
