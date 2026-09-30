"""Python entry point for the Atlas SMB network share feature — see
the SMB network share design note for the full
design and rationale.

Single-user/single-host only: the share always authenticates as *this*
process's own user, against *this* host's ATLAS_CASES_ROOT (default
~/cases). Every privileged step (writing /etc/samba/atlas-share.conf,
smbpasswd, systemctl) goes through bin/atlas-smb-share via `sudo -n` — this
module never touches any of that itself, because dashboard/*.py runs
unprivileged and share/atlas-sudoers.in only grants exactly four fixed,
literal invocations of that wrapper (see its own header), not general sudo
access. enable()/set_password() therefore take no username/cases-root
arguments: the sudoers grant is templated to those exact values at install
time (bin/atlas-sudoers), so calling with anything else would just fail the
`sudo -n` exact-match rather than do anything useful.
"""
from __future__ import annotations

import getpass
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WRAPPER = _REPO_ROOT / "bin" / "atlas-smb-share"

_EMPTY_STATUS = {
    "installed": False, "enabled": False, "service_active": False,
    "share_name": "", "share_path": "", "share_user": "", "password_set": False,
}


class ShareError(Exception):
    """Raised for validation/precondition failures — safe to show the admin."""


def _sudo_prefix() -> list[str]:
    return [] if os.geteuid() == 0 else ["sudo", "-n"]


def _current_username() -> str:
    # The account this process runs as, from the password database; the
    # login environment only when the uid has no entry there. A container
    # or a service started without a login environment still has a name.
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        pass
    try:
        return getpass.getuser()
    except (OSError, KeyError) as exc:
        raise ShareError("could not determine the current username") from exc


def _cases_root() -> str:
    return os.environ.get("ATLAS_CASES_ROOT") or os.path.expanduser("~/cases")


def _package_installed() -> bool:
    return shutil.which("smbpasswd") is not None


def _run(args: list[str], *, input_text: Optional[str] = None,
         timeout: float = 20.0) -> subprocess.CompletedProcess:
    if not _WRAPPER.is_file():
        raise ShareError(f"missing {_WRAPPER} — reinstall Atlas or check your checkout")
    cmd = [*_sudo_prefix(), str(_WRAPPER), *args]
    try:
        return subprocess.run(cmd, input=input_text, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ShareError(f"timed out running: atlas-smb-share {' '.join(args)}") from exc
    except OSError as exc:
        raise ShareError(f"failed to run {_WRAPPER}: {exc}") from exc


def status() -> dict:
    """Never raises for "not installed"/"not permitted yet" — returns
    installed: False with an error string instead, so callers can show a
    friendly message rather than a stack trace."""
    if not _package_installed():
        return {**_EMPTY_STATUS, "error": None}
    try:
        proc = _run(["status"])
    except ShareError as exc:
        return {**_EMPTY_STATUS, "error": str(exc)}
    if proc.returncode != 0:
        return {**_EMPTY_STATUS,
                "error": (proc.stderr or proc.stdout or "status check failed").strip()}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {**_EMPTY_STATUS, "error": "unexpected status output from atlas-smb-share"}
    data.setdefault("error", None)
    return data


def is_installed() -> bool:
    return bool(status().get("installed"))


def enable() -> dict:
    """Enables the share for this host's current user and ATLAS_CASES_ROOT.
    Raises ShareError with a message safe to show the admin on failure."""
    if not _package_installed():
        raise ShareError(
            "samba is not installed — run install.sh with the network-share "
            "option, or `sudo apt-get install samba` and try again")
    cases_root = _cases_root()
    if not Path(cases_root).is_dir():
        raise ShareError(f"cases root does not exist: {cases_root}")
    proc = _run(["enable", cases_root, _current_username()])
    if proc.returncode != 0:
        raise ShareError((proc.stderr or proc.stdout or "enable failed").strip())
    return status()


def disable() -> dict:
    proc = _run(["disable"])
    if proc.returncode != 0:
        raise ShareError((proc.stderr or proc.stdout or "disable failed").strip())
    return status()


def set_password(password: str) -> dict:
    if not password:
        raise ShareError("password is required")
    proc = _run(["set-password", _current_username()],
               input_text=f"{password}\n{password}\n")
    if proc.returncode != 0:
        raise ShareError((proc.stderr or proc.stdout or "set-password failed").strip())
    return {"success": True}
