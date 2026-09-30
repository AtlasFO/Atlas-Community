"""SMB network share config for the dashboard Config Page — thin wrapper
over core/smb_share.py, same shape as config_osint.py and mail.py.

The dashboard process is deliberately never sudo-capable in general (see
core/smb_share.py's own docstring) — every call here goes through that
module, which in turn only ever invokes bin/atlas-smb-share via `sudo -n`
under the fixed, literal ATLAS_SMB_SHARE sudoers grant. This module never
runs apt/samba/systemctl itself; if samba isn't installed, enable() just
raises ConfigError pointing at install.sh / the CLI instead of trying to
install it from an HTTP request.
"""
from __future__ import annotations

from typing import Any

from core import smb_share


class ConfigError(Exception):
    """Raised for validation/precondition failures — safe to show the admin."""


def status() -> dict:
    return smb_share.status()


def enable() -> dict:
    try:
        return smb_share.enable()
    except smb_share.ShareError as exc:
        raise ConfigError(str(exc)) from exc


def disable() -> dict:
    try:
        return smb_share.disable()
    except smb_share.ShareError as exc:
        raise ConfigError(str(exc)) from exc


def save_password(data: dict[str, Any]) -> dict:
    """data: {password}. Unlike other secrets in this codebase, a blank
    password is never "leave unchanged" — Samba has no existing value to
    fall back to from this module's point of view, so blank is just
    rejected outright."""
    password = str(data.get("password") or "")
    if not password:
        raise ConfigError("password is required")
    try:
        smb_share.set_password(password)
    except smb_share.ShareError as exc:
        raise ConfigError(str(exc)) from exc
    return {"success": True, **status()}
