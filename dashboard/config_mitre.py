"""Refreshing the MITRE ATT&CK tables from the Settings page.

The tables Atlas reads live under ~/cases/.common/ (tools/mitre/__init__.py).
They are built by ``tools.mitre.build_mitre_cache`` from MITRE's STIX
release — a 54 MB download, tens of seconds — so a refresh runs as a
subprocess in the background and this module keeps its state in a small
file the page polls: idle, running, success or error, with the release
version and the builder's own last lines.

The button updates *this machine's* tables. The copy bundled with Atlas
under share/.common/ is rebuilt with the same command from a checkout and
committed; a web button must not write into the repository.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = Path(os.environ.get(
    "ATLAS_MITRE_REFRESH_STATE",
    os.path.expanduser("~/.cache/atlas/mitre_refresh.json")))
TABLES = ("techniques", "groups", "software", "mitigations")
_LOG_TAIL = 12

_lock = threading.Lock()
_proc: subprocess.Popen | None = None


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def runtime_dir() -> Path:
    """Where the loaders read from — one directory for all four tables."""
    from tools.mitre import DEFAULT_TECHNIQUES_PATH
    return Path(DEFAULT_TECHNIQUES_PATH).expanduser().parent


def bundled_dir() -> Path:
    return _REPO_ROOT / "share" / ".common"


def _table_meta(directory: Path) -> dict[str, Any]:
    """Version, build time and row counts of the tables in `directory`."""
    out: dict[str, Any] = {"dir": str(directory), "version": "", "built_at": "",
                           "present": False}
    for name in TABLES:
        path = directory / f"mitre_{name}.json"
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            out[name] = None
            continue
        out["present"] = True
        meta = doc.get("_meta") or {}
        out["version"] = out["version"] or str(meta.get("version") or "")
        out["built_at"] = out["built_at"] or str(meta.get("built_at") or "")
        out[name] = len(doc.get(name) or {})
    return out


def _load_state() -> dict[str, Any]:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {"state": "idle", "message": "", "log": []}


def _save_state(state: dict[str, Any]) -> None:
    """Atomic: the page polls this file while the watcher writes it, and a
    half-written file would read as idle mid-refresh."""
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.replace(tmp, STATE_PATH)
    except OSError:
        pass


def status() -> dict[str, Any]:
    """What the Settings card shows; also repairs a refresh that died with
    the dashboard, which would otherwise read as running forever."""
    from tools.mitre.build_mitre_cache import MITRE_CTI_URL
    state = _load_state()
    with _lock:
        alive = _proc is not None and _proc.poll() is None
    if state.get("state") == "running" and not alive:
        state.update({"state": "error", "finished_at": _utcnow(),
                      "message": "the refresh was interrupted (dashboard restarted?) — start it again"})
        _save_state(state)
    return {
        "installed": _table_meta(runtime_dir()),
        "bundled": _table_meta(bundled_dir()),
        "source": MITRE_CTI_URL,
        "refresh": state,
    }


def _watch(proc: subprocess.Popen, state: dict[str, Any]) -> None:
    """Follow the builder's stderr into the state file, then close it out."""
    global _proc
    log: list[str] = []
    version = ""
    try:
        for raw in proc.stderr or []:
            line = raw.rstrip()
            if not line:
                continue
            log.append(line[:200])
            del log[:-_LOG_TAIL]
            if "ATT&CK release:" in line:
                version = line.rsplit(":", 1)[-1].strip()
            state.update({"log": list(log), "version": version})
            _save_state(state)
        rc = proc.wait()
    except Exception as exc:  # noqa: BLE001 — the watcher must end in a state
        rc = -1
        log.append(f"watcher failed: {exc!r}")
    meta = _table_meta(runtime_dir())
    if rc == 0:
        counts = ", ".join(f"{meta.get(n) or 0} {n}" for n in TABLES)
        state.update({"state": "success", "finished_at": _utcnow(),
                      "version": version or meta.get("version") or "",
                      "message": f"ATT&CK {version or meta.get('version') or '?'} — {counts}",
                      "log": list(log)})
    else:
        state.update({"state": "error", "finished_at": _utcnow(),
                      "message": (log[-1] if log else f"builder exited with {rc}"),
                      "log": list(log)})
    _save_state(state)
    with _lock:
        _proc = None


def start_refresh() -> dict[str, Any]:
    """Run the builder in the background; refuse a second one meanwhile."""
    global _proc
    with _lock:
        if _proc is not None and _proc.poll() is None:
            return {"success": False, "error": "a refresh is already running"}
        target = runtime_dir()
        target.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(_REPO_ROOT) + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        state = {"state": "running", "started_at": _utcnow(), "finished_at": "",
                 "message": "downloading MITRE's STIX release and rebuilding the tables",
                 "version": "", "log": []}
        _save_state(state)
        try:
            _proc = subprocess.Popen(
                [sys.executable, "-m", "tools.mitre.build_mitre_cache",
                 "--output-dir", str(target)],
                cwd=str(_REPO_ROOT), env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, text=True, bufsize=1)
        except OSError as exc:
            state.update({"state": "error", "finished_at": _utcnow(),
                          "message": f"could not start the builder: {exc}"})
            _save_state(state)
            return {"success": False, "error": state["message"]}
        threading.Thread(target=_watch, args=(_proc, state), daemon=True).start()
    return {"success": True, "refresh": state}
