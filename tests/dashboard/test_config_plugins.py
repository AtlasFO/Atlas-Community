"""Tests for dashboard/config_plugins.py — the Config Page's Plugins tab
backend: enable/disable (writes ATLAS_PLUGINS_DISABLED to .env) and upload
(delegates to core.plugins.install_from_zip, already covered in depth by
tests/core/test_plugins_install.py — here we only check the base64/error
wrapping and the ATLAS_PLUGINS_DISABLED bookkeeping)."""
from __future__ import annotations

import base64
import io
import sys
import zipfile

import pytest

from dashboard import config_plugins
from core import plugins as core_plugins


def _zip_b64(files: dict[str, str]) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return base64.b64encode(buf.getvalue()).decode("ascii")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / "plugins" / "sample_addon").mkdir(parents=True)
    # A real __init__.py, not a namespace package: the actual repo's
    # plugins/ (also __init__.py-based) sits later on sys.path for the
    # duration of the test session, and a regular package match always
    # wins over an earlier namespace-package portion — without this,
    # `import plugins` would silently resolve to the real repo's package
    # despite tmp_path being first in sys.path.
    (tmp_path / "plugins" / "__init__.py").write_text("")
    # __init__.py must re-export register (docs/addons.md checklist step
    # 1) — discover_plugin_modules() only counts a submodule that exposes
    # a callable `register` attribute; an empty __init__.py imports fine
    # but is silently skipped, same as a real misconfigured addon would be.
    (tmp_path / "plugins" / "sample_addon" / "__init__.py").write_text(
        "from plugins.sample_addon.plugin import register\n")
    (tmp_path / "plugins" / "sample_addon" / "plugin.py").write_text(
        "def register(mcp): pass\n")
    (tmp_path / ".env").write_text("ATLAS_PROVIDERS=\n")
    monkeypatch.setattr(core_plugins, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(config_plugins, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("ATLAS_PLUGINS_DISABLED", raising=False)
    monkeypatch.delenv("ATLAS_PLUGINS", raising=False)
    # discover_plugin_modules() imports the top-level `plugins` package and
    # relies on Python's module cache — once anything in this test process
    # has imported the real repo's plugins/, sys.modules["plugins"] stays
    # pinned to it regardless of _REPO_ROOT, and its own "insert into
    # sys.path if not already present" check is a no-op once the real repo
    # root is already on sys.path. Evict the cache and put tmp_path first
    # in sys.path so a fresh import resolves against the fixture instead.
    #
    # Deliberately NOT monkeypatch.delitem() here: across this file's ~9
    # tests, each one's delitem only remembers the *immediately prior*
    # sys.modules['plugins'] value — once test 1 replaces it with a fake
    # module, test 2's delitem snapshots that fake as "the value to
    # restore", cascading a stale fake module into every test that runs
    # after this whole file (confirmed: it broke an unrelated test in
    # tests/core/test_runtime_capabilities.py). Save/restore the ORIGINAL
    # real module explicitly instead, so restoration is correct regardless
    # of how many tests in this file run or in what order.
    saved_modules = {n: sys.modules[n] for n in sys.modules
                     if n == "plugins" or n.startswith("plugins.")}
    for name in saved_modules:
        del sys.modules[name]
    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        yield tmp_path
    finally:
        for name in [n for n in sys.modules
                     if n == "plugins" or n.startswith("plugins.")]:
            del sys.modules[name]
        sys.modules.update(saved_modules)


class TestStatus:
    def test_lists_discovered_addon(self, repo):
        names = [a["name"] for a in config_plugins.status()["addons"]]
        assert "sample_addon" in names

    def test_globally_enabled_by_default(self, repo):
        assert config_plugins.status()["plugins_globally_enabled"] is True


class TestEnableDisable:
    def test_disable_then_enable_round_trips(self, repo, monkeypatch):
        result = config_plugins.disable("sample_addon")
        assert result == {"success": True, "name": "sample_addon", "disabled": True}
        addon = next(a for a in config_plugins.status()["addons"]
                     if a["name"] == "sample_addon")
        assert addon["enabled"] is False
        assert "ATLAS_PLUGINS_DISABLED=sample_addon" in (repo / ".env").read_text()

        result = config_plugins.enable("sample_addon")
        assert result == {"success": True, "name": "sample_addon", "disabled": False}
        addon = next(a for a in config_plugins.status()["addons"]
                     if a["name"] == "sample_addon")
        assert addon["enabled"] is True

    def test_disable_unknown_addon_refused(self, repo):
        with pytest.raises(config_plugins.ConfigError, match="no such plugin"):
            config_plugins.disable("never_existed")

    def test_disable_twice_is_idempotent(self, repo):
        config_plugins.disable("sample_addon")
        result = config_plugins.disable("sample_addon")
        assert result["disabled"] is True
        assert (repo / ".env").read_text().count("sample_addon") == 1


class TestUpload:
    def test_uploads_and_extracts(self, repo):
        z = _zip_b64({
            "__init__.py": "from plugins.uploaded_addon.plugin import register\n",
            "plugin.py": "def register(mcp): pass\n",
        })
        result = config_plugins.upload("uploaded_addon", z)
        assert result["success"] is True
        assert (repo / "plugins" / "uploaded_addon" / "plugin.py").is_file()
        names = [a["name"] for a in result["addons"]]
        assert "uploaded_addon" in names

    def test_invalid_base64_rejected(self, repo):
        with pytest.raises(config_plugins.ConfigError, match="base64"):
            config_plugins.upload("bad_b64", "not-valid-base64!!!")

    def test_empty_upload_rejected(self, repo):
        with pytest.raises(config_plugins.ConfigError, match="empty"):
            config_plugins.upload("empty_one", "")

    def test_collision_surfaces_as_config_error(self, repo):
        z = _zip_b64({"__init__.py": "", "plugin.py": "x"})
        with pytest.raises(config_plugins.ConfigError, match="already exists"):
            config_plugins.upload("sample_addon", z)
