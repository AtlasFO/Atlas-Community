"""Tests for GNOME keyring secret loading — must not prompt when .env has keys."""
from __future__ import annotations

import os

import core.secrets as secrets


def test_skips_keyring_when_llmhub_already_set(monkeypatch):
    monkeypatch.setenv("LLMHUB_API_KEY", "from-env")
    monkeypatch.delenv("ATLAS_USE_KEYRING", raising=False)
    monkeypatch.delenv("ATLAS_NO_KEYRING", raising=False)

    called = []

    def _fake_lookup(key: str):
        called.append(key)
        return "should-not-run"

    monkeypatch.setattr(secrets, "_lookup", _fake_lookup)
    monkeypatch.setattr(secrets.shutil, "which", lambda _: "/usr/bin/secret-tool")

    assert secrets.keyring_lookups_enabled() is False
    assert secrets.load_into_environ() == []
    assert called == []


def test_opt_in_use_keyring_even_when_env_set(monkeypatch):
    monkeypatch.setenv("LLMHUB_API_KEY", "from-env")
    monkeypatch.setenv("ATLAS_USE_KEYRING", "1")
    monkeypatch.delenv("ATLAS_NO_KEYRING", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    monkeypatch.setattr(
        secrets, "_lookup",
        lambda key: "vt-from-vault" if key == "VIRUSTOTAL_API_KEY" else None,
    )
    monkeypatch.setattr(secrets.shutil, "which", lambda _: "/usr/bin/secret-tool")

    filled = secrets.load_into_environ()
    assert "VIRUSTOTAL_API_KEY" in filled
    assert secrets.os.environ["VIRUSTOTAL_API_KEY"] == "vt-from-vault"


def test_no_keyring_force_off(monkeypatch):
    monkeypatch.delenv("LLMHUB_API_KEY", raising=False)
    monkeypatch.delenv("TSYSTEMS_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("REASON_API_KEY", raising=False)
    monkeypatch.setenv("ATLAS_NO_KEYRING", "1")
    monkeypatch.delenv("ATLAS_USE_KEYRING", raising=False)

    called = []
    monkeypatch.setattr(secrets, "_lookup", lambda k: called.append(k) or "x")
    monkeypatch.setattr(secrets.shutil, "which", lambda _: "/usr/bin/secret-tool")

    assert secrets.load_into_environ() == []
    assert called == []


def test_looks_up_when_no_primary_key(monkeypatch):
    for k in secrets._PRIMARY_LLM_KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("ATLAS_USE_KEYRING", raising=False)
    monkeypatch.delenv("ATLAS_NO_KEYRING", raising=False)

    monkeypatch.setattr(
        secrets, "_lookup",
        lambda key: "hub-from-vault" if key == "LLMHUB_API_KEY" else None,
    )
    monkeypatch.setattr(secrets.shutil, "which", lambda _: "/usr/bin/secret-tool")

    filled = secrets.load_into_environ()
    assert filled == ["LLMHUB_API_KEY"]
    assert secrets.os.environ["LLMHUB_API_KEY"] == "hub-from-vault"


class TestKeyringStorageIsReadableAfterwards:
    """Storing a secret in the vault must also make the loader willing to read
    it. core.secrets skips keyring probes once a primary LLM key is present,
    which is every working install — so without the recorded opt-in an OSINT
    key saved to the keyring was written and then never loaded again."""

    def test_successful_keyring_write_records_the_opt_in(self, tmp_path, monkeypatch):
        from core import envfile, secrets

        env_path = tmp_path / ".env"
        env_path.write_text("ANTHROPIC_API_KEY=sk-present\n", encoding="utf-8")
        repo = tmp_path / "repo"
        (repo / "bin").mkdir(parents=True)
        stub = repo / "bin" / "atlas-secret"
        stub.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-present")
        monkeypatch.delenv("ATLAS_USE_KEYRING", raising=False)
        monkeypatch.delenv("ATLAS_NO_KEYRING", raising=False)
        # An LLM key in the environment: keyring probes are off by default.
        assert secrets.keyring_lookups_enabled() is False

        out = envfile.save_secret_value(repo, env_path, "OTX_API_KEY",
                                        "vault-value", "keyring")

        assert out["stored"] == "keyring"
        assert "OTX_API_KEY" not in env_path.read_text()   # secret stays out of .env
        assert os.environ["ATLAS_USE_KEYRING"] == "1"
        assert "ATLAS_USE_KEYRING=1" in env_path.read_text()
        # ...and the loader will now actually consult the vault.
        assert secrets.keyring_lookups_enabled() is True
