"""Addon (plugin) management for the dashboard Config Page — thin wrapper
over core/plugins.py, same shape as config_share.py and config_osint.py.

Enable/disable is a `.env` write (ATLAS_PLUGINS_DISABLED, comma-separated
addon names), through core.envfile.set_values() — the single write path
every other config page already uses, so the keyring-vs-.env decision and
lock ownership can't drift between pages. It does NOT take effect until the
MCP server process next starts: core.plugins.register_plugins() runs once
at server startup (see server.py), a separate process from this dashboard
HTTP server. status()/enable()/disable() surface that explicitly rather
than implying a live toggle.

Upload extracts into plugins/<name>/ via core.plugins.install_from_zip()
and is deliberately strict (see that function's docstring) — an addon is
trusted Python code with no sandboxing (docs/addons.md), so admin-only
access plus zip-slip/symlink rejection is the whole security boundary,
not a sandbox.
"""
from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from core import envfile, plugins

_REPO_ROOT = Path(__file__).resolve().parents[1]


class ConfigError(Exception):
    """Raised for validation/precondition failures — safe to show the admin."""


def _env_path():
    path = envfile.resolve(_REPO_ROOT)
    if not path.is_file():
        raise ConfigError(
            f"no .env at {path} — create it first (cp .env.example .env)")
    return path


def _disabled_names() -> list[str]:
    raw = os.environ.get("ATLAS_PLUGINS_DISABLED") or ""
    return [n.strip() for n in raw.split(",") if n.strip()]


def status() -> dict:
    return {
        "addons": plugins.list_addons(),
        "plugins_globally_enabled":
            (os.environ.get("ATLAS_PLUGINS") or "1").strip().lower()
            not in ("0", "false", "no", "off"),
    }


def _set_disabled(name: str, *, disabled: bool) -> dict:
    name = (name or "").strip()
    if not name:
        raise ConfigError("a plugin name is required")
    known = {a["name"] for a in plugins.list_addons()}
    if name not in known:
        raise ConfigError(f"no such plugin: {name!r}")
    current = _disabled_names()
    if disabled:
        if name in current:
            return {"success": True, "name": name, "disabled": True}
        current.append(name)
    else:
        if name not in current:
            return {"success": True, "name": name, "disabled": False}
        current = [n for n in current if n != name]
    value = ",".join(current)
    env_path = _env_path()
    with envfile.lock():
        envfile.set_values(env_path, {"ATLAS_PLUGINS_DISABLED": value})
        os.environ["ATLAS_PLUGINS_DISABLED"] = value
    return {"success": True, "name": name, "disabled": disabled}


def disable(name: str) -> dict:
    return _set_disabled(name, disabled=True)


def enable(name: str) -> dict:
    return _set_disabled(name, disabled=False)


def upload(name: str, zip_b64: str) -> dict:
    """zip_b64: standard base64 (RFC 4648) of the addon's zip archive —
    the dashboard has no multipart parser today (see serve.py's
    _read_body()), so uploads travel as base64 inside the same JSON-body
    convention every other config POST already uses."""
    try:
        raw = base64.b64decode(zip_b64 or "", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError(f"invalid base64 upload: {exc}") from exc
    if not raw:
        raise ConfigError("empty upload")
    try:
        result = plugins.install_from_zip(name, raw)
    except plugins.PluginError as exc:
        raise ConfigError(str(exc)) from exc
    return {"success": True, **result, **status()}
