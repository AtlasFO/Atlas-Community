"""Remote-SIFT execution: run forensic tools on an external SANS SIFT VM.

The CLI, agent loop, and LLM orchestration stay LOCAL; only the forensic tool
subprocesses execute on the VM. This is achieved by routing the single executor
choke point (`core.executor.run`) over SSH when remote mode is enabled, using
the same host config + SSH options as the read-only live runner (`core.ssh`).

Two evidence modes (operator's choice, `ATLAS_REMOTE_MODE`):

  * ``resident`` (default) — evidence already lives on the VM; the case brief
    references VM-side paths. Nothing is copied. The thinnest possible driver.
  * ``copy`` — evidence lives on the client. The CLI rsyncs the local case dir
    up to a per-case workspace on the VM before the run, remaps local paths in
    each tool's argv to their workspace equivalents, and rsyncs the produced
    analysis/exports/reports back down afterwards.

Disabled by default: `remote_config()` returns None unless `ATLAS_REMOTE_SIFT`
names a host, so `core.executor.run` behaves exactly as before out of the box.

Configuration (environment):
  ATLAS_REMOTE_SIFT        host key in live_hosts.json (enables remote mode)
  ATLAS_REMOTE_MODE        "resident" (default) | "copy"
  ATLAS_REMOTE_WORKSPACE   remote base dir for copy mode (default ~/atlas-workspace)
  ATLAS_REMOTE_LOCAL_ROOT  local path prefix mapped to the workspace
                          (default: current working directory)
"""
from __future__ import annotations

import os
import shlex
import subprocess
import time
from typing import Any, Optional

from core.executor import _apply_line_cap, _parse_stderr, _spill_target_dir
from core.paths import (OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES, DEFAULT_TIMEOUT,
                        spill_file_path)
from core.ssh import _SSH_OPTS, _resolve_host, SSHConfigError

_VALID_MODES = ("resident", "copy")


def _spill_full_stdout(full_stdout: str, cmd0: str) -> Optional[str]:
    """Write the untruncated remote stdout to a spill file. Best-effort —
    returns the path or None; never raises."""
    try:
        spill_dir = _spill_target_dir()
        if spill_dir is None:
            return None
        path = spill_file_path(spill_dir, cmd0)
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(full_stdout)
        return path
    except Exception:
        return None


def remote_config() -> Optional[dict]:
    """Resolve the active remote-SIFT config, or None when remote mode is off.

    Read from the environment at call time so tests and the CLI can toggle it.
    """
    host = os.environ.get("ATLAS_REMOTE_SIFT")
    if not host:
        return None
    mode = (os.environ.get("ATLAS_REMOTE_MODE") or "resident").strip().lower()
    if mode not in _VALID_MODES:
        mode = "resident"
    workspace = (os.environ.get("ATLAS_REMOTE_WORKSPACE")
                 or "~/atlas-workspace").rstrip("/")
    local_root = os.path.abspath(
        os.environ.get("ATLAS_REMOTE_LOCAL_ROOT") or os.getcwd())
    return {
        "host": host,
        "mode": mode,
        "workspace": workspace,
        "local_root": local_root.rstrip("/"),
    }


def is_enabled() -> bool:
    return remote_config() is not None


# ── path remapping (copy mode) ───────────────────────────────────────────────

def _remap_path(token: str, cfg: dict) -> str:
    """Rewrite a local case-dir path to its workspace equivalent on the VM.

    Only rewrites in ``copy`` mode, and only tokens under ``local_root`` — every
    other token (tool names, flags, VM-side paths) is passed through untouched.
    """
    if cfg["mode"] != "copy":
        return token
    root = cfg["local_root"]
    abs = os.path.abspath(os.path.expanduser(token)) if token.startswith(
        ("/", "~", ".")) else token
    if abs == root:
        return cfg["workspace"]
    if abs.startswith(root + os.sep):
        return cfg["workspace"] + "/" + abs[len(root) + 1:]
    return token


def remap_argv(argv: list[str], cfg: dict) -> list[str]:
    """Remap every local path token in a tool argv for copy-mode execution."""
    return [_remap_path(a, cfg) for a in argv]


def remote_cwd(cwd: Optional[str], cfg: dict) -> str:
    """The working directory to cd into on the VM before running the tool.

    In copy mode the local cwd is remapped into the workspace; in resident mode
    the local cwd has no meaning on the VM, so fall back to the workspace root.
    """
    if cfg["mode"] == "copy":
        base = cwd or cfg["local_root"]
        return _remap_path(base, cfg)
    return cwd or cfg["workspace"]


# ── remote execution ─────────────────────────────────────────────────────────

def _ssh_prefix(resolved: dict) -> list[str]:
    return ["ssh"] + _SSH_OPTS + [
        "-i", resolved["identity"],
        "-p", str(resolved["port"]),
        f"{resolved['user']}@{resolved['host']}",
        "--",
    ]


def build_remote_argv(cmd: list[str], cfg: dict, resolved: dict,
                      cwd: Optional[str]) -> tuple[list[str], str]:
    """Build the local ssh argv that runs `cmd` on the VM, plus the pretty
    remote command string (no identity path) for the trace.

    The remote side is a single ``sh -lc 'cd <dir> && exec <argv>'`` so relative
    output paths resolve inside the workspace and login PATH finds the SIFT
    tools. Every operand is shell-quoted, so hostile filenames stay literal.
    """
    rargv = remap_argv(cmd, cfg)
    rcwd = remote_cwd(cwd, cfg)
    inner = (f"cd {shlex.quote(rcwd)} && exec "
             + " ".join(shlex.quote(a) for a in rargv))
    ssh_argv = _ssh_prefix(resolved) + ["sh", "-lc", inner]
    pretty = f"[remote:{cfg['host']}] (cd {rcwd}) " + " ".join(rargv)
    return ssh_argv, pretty


def run_remote(
    cmd: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Optional[str] = None,
    line_cap: Optional[int] = MAX_TOOL_OUTPUT_LINES,
    stdout_file: Optional[str] = None,
) -> dict[str, Any]:
    """Execute a forensic tool `cmd` (argv list) on the configured SIFT VM.

    Mirrors ``core.executor.run``'s result schema so the trace pipeline treats a
    remote call identically to a local one. Never raises — errors are captured.
    Does NOT write a trace entry: the caller (executor.run) owns _log_tool so a
    call is logged exactly once whether it ran locally or remotely.

    stdout_file: when set, the tool's stdout (streamed back over SSH) is written
    to this LOCAL path instead of captured in memory — for stdout-IS-artifact
    tools (icat, mactime, strings, …), so their output lands on the client.
    """
    cfg = remote_config()
    result: dict[str, Any] = {
        "success": False, "stdout": "", "stderr": "", "exit_code": -1,
        "elapsed_seconds": 0.0, "truncated": False, "cmd": " ".join(cmd),
        "retries": 0, "progress_lines": [], "source": "remote_sift",
    }
    if cfg is None:
        result["stderr"] = "run_remote called but remote mode is disabled"
        return result
    result["host"] = cfg["host"]
    result["remote_mode"] = cfg["mode"]

    try:
        resolved = _resolve_host(cfg["host"])
    except SSHConfigError as e:
        result["stderr"] = str(e)
        return result

    ssh_argv, pretty = build_remote_argv(cmd, cfg, resolved, cwd)
    result["cmd"] = pretty
    if stdout_file:
        result["output_path"] = stdout_file

    start = time.perf_counter()
    try:
        if stdout_file:
            parent = os.path.dirname(os.path.abspath(stdout_file))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(stdout_file, "wb") as fh:
                proc = subprocess.run(ssh_argv, stdout=fh,
                                      stderr=subprocess.PIPE, timeout=timeout)
            result["exit_code"] = proc.returncode
            result["success"] = proc.returncode == 0
            result["stdout"] = f"Output written to {stdout_file}"
            result["stderr"], result["progress_lines"] = _parse_stderr(
                proc.stderr.decode("utf-8", errors="replace"))
        else:
            proc = subprocess.run(ssh_argv, capture_output=True, timeout=timeout)
            result["exit_code"] = proc.returncode
            result["success"] = proc.returncode == 0
            full_stdout = proc.stdout.decode("utf-8", errors="replace")
            stdout = full_stdout
            if len(stdout) > OUTPUT_CAP:
                stdout = stdout[:OUTPUT_CAP]
                result["truncated"] = True
            if line_cap is not None:
                stdout, trimmed = _apply_line_cap(stdout, line_cap)
                if trimmed:
                    result["truncated"] = True
            if result["truncated"]:
                spill = _spill_full_stdout(full_stdout, cmd[0] if cmd else "tool")
                if spill:
                    result["stdout_file"] = spill
            result["stdout"] = stdout
            result["stderr"], result["progress_lines"] = _parse_stderr(
                proc.stderr.decode("utf-8", errors="replace"))
    except subprocess.TimeoutExpired:
        result["stderr"] = f"Remote command timed out after {timeout}s"
        result["timed_out"] = True
    except Exception as e:  # noqa: BLE001 — mirror executor: never raise
        result["stderr"] = f"Remote executor error: {e}"

    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
    return result


# ── rsync bracketing (copy mode) ─────────────────────────────────────────────

def _rsync_base(resolved: dict) -> list[str]:
    ssh_cmd = ("ssh " + " ".join(_SSH_OPTS)
               + f" -i {shlex.quote(resolved['identity'])}"
               + f" -p {resolved['port']}")
    return ["rsync", "-az", "-e", ssh_cmd]


def _remote_spec(resolved: dict, path: str) -> str:
    return f"{resolved['user']}@{resolved['host']}:{path}"


def sync_evidence_up(cfg: dict, timeout: int = 3600) -> dict:
    """Copy-mode only: rsync the local case's evidence/ (and brief) up to the
    VM workspace before the run. No-op in resident mode. Never raises."""
    if cfg["mode"] != "copy":
        return {"success": True, "skipped": "resident mode"}
    try:
        resolved = _resolve_host(cfg["host"])
    except SSHConfigError as e:
        return {"success": False, "error": str(e)}
    ev = os.path.join(cfg["local_root"], "evidence")
    if not os.path.isdir(ev):
        return {"success": True, "skipped": "no local evidence/ dir"}
    dest = _remote_spec(resolved, cfg["workspace"] + "/")
    # Ensure the workspace exists remotely, then push evidence (+ brief).
    mkdir = _ssh_prefix(resolved) + ["mkdir", "-p", cfg["workspace"]]
    argv = _rsync_base(resolved) + ["--relative",
                                    os.path.join(".", "evidence") + "/", dest]
    try:
        subprocess.run(mkdir, capture_output=True, timeout=60)
        proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                              cwd=cfg["local_root"])
        ok = proc.returncode == 0
        return {"success": ok,
                "stderr": proc.stderr.decode("utf-8", "replace")[:2000],
                "dest": dest}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}


def sync_outputs_back(cfg: dict, timeout: int = 3600) -> dict:
    """Copy-mode only: rsync analysis/exports/reports from the VM workspace back
    down to the local case dir after the run. No-op in resident mode."""
    if cfg["mode"] != "copy":
        return {"success": True, "skipped": "resident mode"}
    try:
        resolved = _resolve_host(cfg["host"])
    except SSHConfigError as e:
        return {"success": False, "error": str(e)}
    results = {}
    ok_all = True
    for sub in ("analysis", "exports", "reports"):
        src = _remote_spec(resolved, cfg["workspace"] + f"/{sub}/")
        dst = os.path.join(cfg["local_root"], sub) + "/"
        os.makedirs(dst, exist_ok=True)
        argv = _rsync_base(resolved) + [src, dst]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout)
            results[sub] = proc.returncode
            ok_all = ok_all and proc.returncode == 0
        except Exception as e:  # noqa: BLE001
            results[sub] = str(e)
            ok_all = False
    return {"success": ok_all, "subdirs": results}
