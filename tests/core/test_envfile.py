"""Tests for core/envfile.py — the in-place .env editor. No network, no keyring.

This file edits the one place that also holds API keys, so every property here is
a failure that would either lose a credential or produce a config that silently
reads differently than it looks.
"""
import os

import pytest

from core import envfile

SAMPLE = """# Atlas MCP server
VIRUSTOTAL_API_KEY=vt-secret

# hub block
LLMHUB_BASE_URL=https://llm-server.llmhub.t-systems.net/v2
LLMHUB_MODEL=GLM-5.2
REASON_BACKEND=llmhub
DAIR_BACKEND=llmhub

ATLAS_PROVIDERS=gw-a,gw-b
# ATLAS_PROVIDER_GW_B_BASE_URL=https://gw.example/llm/b/v1
ATLAS_PROVIDER_GW_B_BASE_URL=https://gw-internal.example/llm/b/v1
ATLAS_PROVIDER_GW_B_MODEL=
# ATLAS_AGENT_PROVIDER=something-old
REASON_BACKEND=llmhub
"""


@pytest.fixture
def env_file(tmp_path):
    path = tmp_path / ".env"
    path.write_text(SAMPLE, encoding="utf-8")
    return path


class TestEnvIntEnvFloat:
    """python-dotenv loads an unquoted 'KEY=600     # comment' value with the
    comment still attached, and int() on it raises ValueError in every
    module that parses it at import time (core.paths among them).
    env_int()/env_float() must degrade to the default instead of raising."""

    def test_reported_bug_scenario(self, monkeypatch):
        monkeypatch.setenv(
            "ATLAS_DEFAULT_TIMEOUT",
            "600     # most tools (regripper, yara, strings, etc.)")
        assert envfile.env_int("ATLAS_DEFAULT_TIMEOUT", 300) == 600

    def test_normal_value(self, monkeypatch):
        monkeypatch.setenv("X", "42")
        assert envfile.env_int("X", 0) == 42
        monkeypatch.setenv("Y", "3.5")
        assert envfile.env_float("Y", 0.0) == 3.5

    def test_missing_var_falls_back_to_default(self, monkeypatch):
        monkeypatch.delenv("MISSING_VAR", raising=False)
        assert envfile.env_int("MISSING_VAR", 7) == 7
        assert envfile.env_float("MISSING_VAR", 7.0) == 7.0

    def test_empty_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("EMPTY_VAR", "")
        assert envfile.env_int("EMPTY_VAR", 9) == 9

    def test_malformed_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("BAD_VAR", "not-a-number")
        assert envfile.env_int("BAD_VAR", 5) == 5
        assert envfile.env_float("BAD_VAR", 5.0) == 5.0

    def test_comment_whitespace_variants(self, monkeypatch):
        monkeypatch.setenv("A", "12#comment")
        assert envfile.env_int("A", 0) == 12
        monkeypatch.setenv("B", "  12  #  comment  ")
        assert envfile.env_int("B", 0) == 12


class TestReadValues:
    def test_ignores_commented_assignments(self, env_file):
        assert "ATLAS_AGENT_PROVIDER" not in envfile.read_values(env_file)

    def test_last_assignment_wins_like_dotenv(self, env_file):
        assert envfile.read_values(env_file)["REASON_BACKEND"] == "llmhub"

    def test_empty_value_is_present_but_empty(self, env_file):
        values = envfile.read_values(env_file)
        assert values["ATLAS_PROVIDER_GW_B_MODEL"] == ""


class TestSetValues:
    def test_replaces_in_place_leaving_one_live_line(self, env_file):
        envfile.set_values(env_file, {"REASON_BACKEND": "gw-b"})
        lines = env_file.read_text(encoding="utf-8").splitlines()
        # SAMPLE assigns REASON_BACKEND twice. Appending a third would leave a
        # stale line above that reads as if it were live.
        assert [l for l in lines if l.startswith("REASON_BACKEND=")] == \
            ["REASON_BACKEND=gw-b"]

    def test_replaces_a_commented_assignment_rather_than_appending(self, env_file):
        envfile.set_values(env_file, {"ATLAS_AGENT_PROVIDER": "gw-b"})
        lines = env_file.read_text(encoding="utf-8").splitlines()
        matching = [l for l in lines if "ATLAS_AGENT_PROVIDER" in l]
        assert matching == ["ATLAS_AGENT_PROVIDER=gw-b"]

    def test_appends_unknown_key(self, env_file):
        envfile.set_values(env_file, {"ATLAS_REVIEW_PROVIDER": "gw-b"})
        assert "ATLAS_REVIEW_PROVIDER=gw-b" in \
            env_file.read_text(encoding="utf-8").splitlines()

    def test_fills_an_empty_value(self, env_file):
        envfile.set_values(env_file,
                           {"ATLAS_PROVIDER_GW_B_MODEL": "b-model-x"})
        assert envfile.read_values(env_file)[
            "ATLAS_PROVIDER_GW_B_MODEL"] == "b-model-x"

    def test_leaves_everything_else_byte_identical(self, env_file):
        before = env_file.read_text(encoding="utf-8").splitlines()
        envfile.set_values(env_file, {"REASON_BACKEND": "gw-b"})
        after = env_file.read_text(encoding="utf-8").splitlines()
        untouched = [l for l in before if not l.startswith("REASON_BACKEND=")]
        assert [l for l in after if not l.startswith("REASON_BACKEND=")] == untouched

    def test_does_not_touch_credentials(self, env_file):
        envfile.set_values(env_file, {"REASON_BACKEND": "gw-b"})
        assert "VIRUSTOTAL_API_KEY=vt-secret" in \
            env_file.read_text(encoding="utf-8").splitlines()

    def test_keeps_comments_and_blank_lines(self, env_file):
        envfile.set_values(env_file, {"DAIR_BACKEND": "gw-b"})
        lines = env_file.read_text(encoding="utf-8").splitlines()
        assert lines[0] == "# Atlas MCP server"
        assert "# hub block" in lines
        assert "" in lines
        # The commented URL is documentation and must survive.
        assert any(l.startswith("# ATLAS_PROVIDER_GW_B_BASE_URL=")
                   for l in lines)

    def test_preserves_the_inode(self, env_file):
        """A worktree symlinks its .env at the primary checkout. Replacing the
        file would break the link and give the checkouts different config."""
        before = os.stat(env_file).st_ino
        envfile.set_values(env_file, {"REASON_BACKEND": "gw-b"})
        assert os.stat(env_file).st_ino == before

    def test_idempotent(self, env_file):
        envfile.set_values(env_file, {"REASON_BACKEND": "gw-b"})
        first = env_file.read_text(encoding="utf-8")
        envfile.set_values(env_file, {"REASON_BACKEND": "gw-b"})
        assert env_file.read_text(encoding="utf-8") == first

    def test_round_trip_back_to_the_default(self, env_file):
        envfile.set_values(env_file, {"REASON_BACKEND": "gw-b",
                                      "ATLAS_AGENT_PROVIDER": "gw-b"})
        envfile.set_values(env_file, {"REASON_BACKEND": "llmhub",
                                      "ATLAS_AGENT_PROVIDER": "llmhub"})
        values = envfile.read_values(env_file)
        assert values["REASON_BACKEND"] == "llmhub"
        assert values["ATLAS_AGENT_PROVIDER"] == "llmhub"
        lines = env_file.read_text(encoding="utf-8").splitlines()
        assert len([l for l in lines if l.startswith("REASON_BACKEND=")]) == 1

    def test_file_without_trailing_newline_does_not_glue_lines(self, tmp_path):
        path = tmp_path / "b.env"
        path.write_text("A=1\nB=2", encoding="utf-8")
        envfile.set_values(path, {"C": "3"})
        assert path.read_text(encoding="utf-8").splitlines() == ["A=1", "B=2", "C=3"]

    def test_empty_update_is_a_noop(self, env_file):
        before = env_file.read_text(encoding="utf-8")
        envfile.set_values(env_file, {})
        assert env_file.read_text(encoding="utf-8") == before


class TestResolve:
    def test_returns_the_env_beside_the_repo_root(self, tmp_path):
        (tmp_path / ".env").write_text("A=1", encoding="utf-8")
        assert envfile.resolve(tmp_path) == (tmp_path / ".env").resolve()

    def test_follows_a_symlink_to_the_real_file(self, tmp_path):
        real_dir = tmp_path / "primary"
        real_dir.mkdir()
        real = real_dir / ".env"
        real.write_text("A=1", encoding="utf-8")
        worktree = tmp_path / "worktree"
        worktree.mkdir()
        try:
            (worktree / ".env").symlink_to(real)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation not permitted on this host")
        assert envfile.resolve(worktree) == real.resolve()
