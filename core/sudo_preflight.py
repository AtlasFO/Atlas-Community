"""Passwordless-sudo preflight for investigation runs.

Atlas uses ``sudo -n`` for mount/loop/carve/network tools. Without a
least-privilege grant (``share/atlas-sudoers.in`` → ``/etc/sudoers.d/atlas-$USER``),
those calls fail as ``sudo_auth`` and thrash the investigation. Fail closed
at CLI start so the operator installs sudoers before a multi-hour run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO_ROOT / "bin" / "atlas-sudoers"
_TEMPLATE = _REPO_ROOT / "share" / "atlas-sudoers.in"


def whitelisted_binaries(template: Optional[Path] = None) -> list[str]:
    """Absolute binary paths from the Cmnd_Alias in share/atlas-sudoers.in.

    Read out of the template instead of duplicated here: a second list is a
    second thing to drift, and the installed grant is what actually decides.
    """
    path = Path(template) if template else _TEMPLATE
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[str] = []
    in_alias = False
    for line in text.splitlines():
        body = line.split("#", 1)[0]
        if "Cmnd_Alias" in body:
            in_alias = True
            body = body.split("=", 1)[-1]
        elif not in_alias:
            continue
        for token in body.rstrip().rstrip("\\").split(","):
            # Keep only the command word; an entry may carry an argument pattern.
            token = token.strip().split(" ", 1)[0].lstrip("!")
            if token.startswith("/"):
                out.append(token)
        if not line.rstrip().endswith("\\"):
            in_alias = False
    return out


def audit_sudoers_binaries(template: Optional[Path] = None,
                           stat_fn=None) -> list[str]:
    """Flag whitelisted binaries a non-root user could replace.

    sudo matches the absolute path, so an earlier PATH entry cannot hijack the
    grant — but a group- or world-writable binary, or a writable directory
    holding one, hands a root shell to whoever can write there. Eight entries
    sit under /usr/local/bin, which is group-writable in some installations, so
    this is worth asserting rather than assuming.

    Advisory by construction: it returns findings and never raises. A missing
    binary is not a finding (it simply is not installed here), an OS error is
    skipped, and a non-POSIX host returns nothing rather than a false alarm — a
    broken check must not brick a run.
    """
    st_fn = stat_fn or os.stat
    if os.name != "posix" and stat_fn is None:
        return []
    findings: list[str] = []
    for binary in dict.fromkeys(whitelisted_binaries(template)):
        for target, what in ((binary, "binary"),
                             (os.path.dirname(binary) or "/", "directory")):
            try:
                st = st_fn(target)
            except OSError:
                continue
            if st.st_uid != 0:
                findings.append(
                    f"{what} not owned by root: {target} (uid {st.st_uid})")
            if st.st_mode & 0o022:
                findings.append(
                    f"{what} writable by group or other: {target} "
                    f"(mode {oct(st.st_mode & 0o7777)})")
    return findings


def _skip_requested(explicit: bool = False) -> bool:
    if explicit:
        return True
    return (os.environ.get("ATLAS_SKIP_SUDO_CHECK") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _run_sudo_n(argv: list[str], *, timeout: float = 5.0) -> tuple[bool, str]:
    """Return (ok, stderr/stdout snippet) for ``sudo -n <argv>``."""
    cmd = ["sudo", "-n", *argv]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return False, "sudo binary not found on PATH"
    except subprocess.TimeoutExpired:
        return False, f"timed out: {' '.join(cmd)}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    if proc.returncode == 0:
        return True, ""
    err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
    return False, err[:300]


def _resolve_probe_bin(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for cand in (f"/usr/sbin/{name}", f"/sbin/{name}", f"/usr/bin/{name}"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def check_passwordless_sudo() -> tuple[bool, list[str]]:
    """Probe passwordless sudo for Atlas-critical binaries.

    Returns ``(ok, detail_lines)``. Checks ``sudo -n true`` (executor
    preflight) and ``sudo -n losetup -h`` when losetup is installed (mount
    path). File-backed TSK does not need sudo; this gate covers the rest.
    """
    details: list[str] = []
    ok_true, err_true = _run_sudo_n(["true"])
    if not ok_true:
        details.append(f"sudo -n true → FAIL ({err_true})")
        return False, details
    details.append("sudo -n true → OK")

    losetup = _resolve_probe_bin("losetup")
    if losetup:
        # -h / --help exits 0 without touching devices
        ok_loop, err_loop = _run_sudo_n([losetup, "-h"])
        if not ok_loop:
            # Some builds use --help only
            ok_loop, err_loop = _run_sudo_n([losetup, "--help"])
        if not ok_loop:
            details.append(f"sudo -n {losetup} -h → FAIL ({err_loop})")
            details.append(
                "sudo works for `true` but not for Atlas mount tools — "
                "install the least-privilege sudoers grant."
            )
            return False, details
        details.append(f"sudo -n {losetup} -h → OK")
    else:
        details.append("losetup not on PATH — skipped mount-tool probe")

    # Advisory only, and deliberately after the pass/fail decision: a writable
    # whitelisted binary is a real hole, but refusing to start over it would
    # turn a hardening check into an outage on a machine whose /usr/local/bin
    # permissions Atlas does not control.
    for finding in audit_sudoers_binaries():
        details.append(f"WARN sudoers grant: {finding}")

    return True, details


def sudoers_script_hint() -> str:
    script = _SCRIPT if _SCRIPT.is_file() else Path("bin/atlas-sudoers")
    return (
        f"atlas: passwordless sudo is required for mount/loop/carve/network "
        f"tools (sudo -n).\n"
        f"\n"
        f"  Fix (one interactive password, then passwordless for Atlas tools):\n"
        f"    {script}\n"
        f"\n"
        f"  Then re-run your investigation. This installs "
        f"/etc/sudoers.d/atlas-$USER from share/atlas-sudoers.in "
        f"(least privilege — not NOPASSWD: ALL).\n"
        f"\n"
        f"  Escape hatch (tests/CI only): ATLAS_SKIP_SUDO_CHECK=1 or "
        f"--skip-sudo-check\n"
    )


def require_passwordless_sudo(*, skip: bool = False) -> None:
    """Exit the process if passwordless sudo is unavailable."""
    if _skip_requested(skip):
        return
    ok, details = check_passwordless_sudo()
    if ok:
        return
    sys.stderr.write(sudoers_script_hint())
    if details:
        sys.stderr.write("\nProbe detail:\n")
        for line in details:
            sys.stderr.write(f"  - {line}\n")
    sys.exit(2)
