"""Tests for core/plugins.py's install_from_zip() — the upload path behind
the dashboard's new Plugins config page. Covers the security-sensitive
parts (zip-slip, symlink members, name validation) since discovery/list/
register already have no test coverage to build on and this is genuinely
new, admin-only-but-still-should-not-footgun logic."""
from __future__ import annotations

import io
import zipfile

import pytest

from core import plugins


@pytest.fixture
def repo(tmp_path, monkeypatch):
    (tmp_path / "plugins").mkdir()
    monkeypatch.setattr(plugins, "_REPO_ROOT", tmp_path)
    return tmp_path


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


class TestInstallFromZip:
    def test_extracts_a_well_formed_addon(self, repo):
        z = _zip_bytes({
            "__init__.py": "from plugins.my_addon.plugin import register\n",
            "plugin.py": "def register(mcp): pass\n",
            "addon.yaml": "name: my_addon\nversion: \"0.1.0\"\n",
        })
        result = plugins.install_from_zip("my_addon", z)
        assert result["name"] == "my_addon"
        assert result["has_register"] is True
        assert result["has_manifest"] is True
        assert (repo / "plugins" / "my_addon" / "plugin.py").is_file()

    def test_bad_name_rejected(self, repo):
        z = _zip_bytes({"__init__.py": "", "plugin.py": "x"})
        with pytest.raises(plugins.PluginError, match="package name"):
            plugins.install_from_zip("Not-Valid!", z)
        assert not (repo / "plugins" / "Not-Valid!").exists()

    def test_refuses_to_clobber_existing_addon(self, repo):
        (repo / "plugins" / "existing").mkdir()
        z = _zip_bytes({"__init__.py": "", "plugin.py": "x"})
        with pytest.raises(plugins.PluginError, match="already exists"):
            plugins.install_from_zip("existing", z)

    def test_bad_zip_rejected(self, repo):
        with pytest.raises(plugins.PluginError, match="not a valid zip"):
            plugins.install_from_zip("broken", b"not a zip file")
        assert not (repo / "plugins" / "broken").exists()

    def test_missing_init_py_rejected(self, repo):
        z = _zip_bytes({"plugin.py": "def register(mcp): pass\n"})
        with pytest.raises(plugins.PluginError, match="__init__.py"):
            plugins.install_from_zip("no_init", z)
        assert not (repo / "plugins" / "no_init").exists()

    def test_zip_slip_parent_traversal_rejected(self, repo):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("__init__.py", "")
            zf.writestr("../../evil.py", "pwned = True\n")
        with pytest.raises(plugins.PluginError, match="escapes"):
            plugins.install_from_zip("slippy", buf.getvalue())
        assert not (repo / "evil.py").exists()
        assert not (repo / "plugins" / "slippy").exists()

    def test_zip_slip_absolute_path_rejected(self, repo, tmp_path):
        target = tmp_path / "outside.py"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("__init__.py", "")
            zf.writestr(str(target), "pwned = True\n")
        with pytest.raises(plugins.PluginError, match="escapes"):
            plugins.install_from_zip("slippy2", buf.getvalue())
        assert not target.exists()

    def test_symlink_member_rejected(self, repo):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("__init__.py", "")
            info = zipfile.ZipInfo("link")
            info.external_attr = (0o120777 << 16)  # S_IFLNK
            zf.writestr(info, "/etc/passwd")
        with pytest.raises(plugins.PluginError, match="symlink"):
            plugins.install_from_zip("linky", buf.getvalue())
        assert not (repo / "plugins" / "linky").exists()

    def test_partial_extraction_cleaned_up_on_failure(self, repo, monkeypatch):
        z = _zip_bytes({"__init__.py": "", "plugin.py": "x", "addon.yaml": "name: x\n"})

        def boom(*a, **k):
            raise OSError("disk full")
        monkeypatch.setattr(zipfile.ZipFile, "extractall", boom)
        with pytest.raises(OSError):
            plugins.install_from_zip("cleanup_case", z)
        assert not (repo / "plugins" / "cleanup_case").exists()


if __name__ == "__main__":
    # Note: one runnable self-check without pytest, per repo convention.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        from pathlib import Path
        p = Path(d)
        (p / "plugins").mkdir()
        plugins._REPO_ROOT = p
        z = _zip_bytes({"__init__.py": "", "plugin.py": "def register(mcp): pass\n"})
        r = plugins.install_from_zip("demo_addon", z)
        assert r["name"] == "demo_addon"
        assert (p / "plugins" / "demo_addon" / "plugin.py").is_file()
        try:
            plugins.install_from_zip("demo_addon", z)
            raise SystemExit("expected PluginError on re-install")
        except plugins.PluginError:
            pass
        print("core/plugins.py install_from_zip self-check OK")
