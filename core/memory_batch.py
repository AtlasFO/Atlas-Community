"""The per-image memory batch (memory-speed design 3.2): one background job
that reads every memory image of the case in two passes and keeps each
plugin's answer in the result store (core.vol_cache), so the analysis
never waits on a cold image.

- Pass 1, image by image in the evidence's order: a sequential read that
  brings the image into the page cache, then windows.info (which saves the
  image's layer config) and the walk of every memory structure
  (evidence_disposition.MEMORY_STRUCTURES, walks first). A walk that fails
  moves its structure to its scan, in the same pass.
- Pass 2, with ATLAS_MEMORY_BATCH_SCANS (on by default): the paced read
  again, then at once the scan of every structure on the warm image. Never
  a cold scan in the background: measured on a disk without an idle I/O
  class, a paced read and a scan of a warm image under nice leave a
  foreground read as fast as alone, a cold scan does not. A structure whose
  walk costs more on a warm image than its scan (WARM_SCAN_FIRST) is left
  to its scan in pass 2.

Its own lane: one batch for the case (the job's argv is the case's one
manifest, which the job registry deduplicates), at the lowest CPU
priority, the warm read pausing per chunk while a foreground tool call
runs (core.executor marks them in .atlas/busy, one mark per call named by
its process id; a mark of a process that is gone is ignored, and the
marks are cleared at a fresh start). Known blind spot: work a tool does in
the server process itself (a table count over a large export) starts no
subprocess and sets no mark, so the lanes do not pause for it. A plugin the analysis asks
for that is still queued moves its image to the front and answers with the
job instead of a second cold read. Never awaited: at the run's end a batch
still running is stopped and what it did not run is disclosed.
``ATLAS_MEMORY_BATCH`` (on by default) switches it; off, the survey's
one-plugin info job runs alone.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

BATCH_DIR = "memory_batch"
BUSY_DIR = "busy"
# A busy mark older than this is a call that died without removing it (the
# process-id check catches a dead process at once; this catches a reused id).
BUSY_STALE_SECONDS = 4 * 3600
# Measured mechanism fact (memory-speed design 5.2), not a choice of what to
# look for: on a warm image this walk takes longer and writes about ten
# times the output of its structure's scan, so with pass 2 on the structure
# is read by its scan alone.
WARM_SCAN_FIRST = frozenset({"handles"})
# Plugins Volatility files under its registry namespace (wiring of the
# plugin names the wrappers in tools/volatility.py pass).
_REGISTRY_PLUGINS = frozenset({"hivelist", "hivescan", "printkey", "userassist", "amcache", "scheduled_tasks"})


def batch_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_MEMORY_BATCH", True)


def scans_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_MEMORY_BATCH_SCANS", True)


def plugin_string(short: str) -> str:
    """The plugin name the wrappers pass for a structure plugin, so the
    batch's stored answers are the ones a wrapper call looks up."""
    return f"windows.registry.{short}" if short in _REGISTRY_PLUGINS else f"windows.{short}"


def plan() -> tuple[list[str], list[str]]:
    """(walks, scans) of the memory structures: one walk per structure (its
    first, walks first) and its first scan."""
    from core.evidence_disposition import MEMORY_STRUCTURES, first_walk, memory_cost, walk_first
    walks, scans = [], []
    for plugins in MEMORY_STRUCTURES.values():
        w = first_walk(plugins)
        s = next((p for p in walk_first(plugins) if memory_cost(p) == "scan"), "")
        if s and w in WARM_SCAN_FIRST and scans_on():
            w = ""
        if w:
            walks.append(plugin_string(w))
        if s:
            scans.append(plugin_string(s))
    return list(dict.fromkeys(walks)), list(dict.fromkeys(scans))


def fallback_scan(walk: str) -> str:
    """The scan of the structure whose walk this is ("" when none)."""
    from core.evidence_disposition import MEMORY_STRUCTURES, memory_cost
    short = walk.rsplit(".", 1)[-1]
    for plugins in MEMORY_STRUCTURES.values():
        if short in plugins:
            return next((plugin_string(p) for p in plugins if memory_cost(p) == "scan"), "")
    return ""


def batch_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / ".atlas" / BATCH_DIR


def busy_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / ".atlas" / BUSY_DIR


# ── the foreground marks (written by core.executor around a tool call) ──

_SEQ = [0]


def mark_busy(case_dir: Optional[str], lane: str = "") -> Optional[Path]:
    """Mark a running call; a background lane's own call carries the
    lane's name, and no lane pauses for it."""
    if not case_dir:
        return None
    try:
        d = busy_dir(case_dir)
        d.mkdir(parents=True, exist_ok=True)
        _SEQ[0] += 1
        p = d / (f"{os.getpid()}-{_SEQ[0]}" + (f"-{lane}" if lane else ""))
        p.touch()
        return p
    except OSError:
        return None


def unmark_busy(mark: Optional[Path]) -> None:
    if mark is not None:
        try:
            mark.unlink()
        except OSError:
            pass


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True                              # exists, owned by someone else
    return True


def _live_mark(p: Path, now: float) -> bool:
    """A fresh mark of a live process's foreground call (a lane's mark,
    named pid-seq-lane, is never one)."""
    parts = p.name.split("-")
    if len(parts) > 2:
        return False
    try:
        if now - p.stat().st_mtime >= BUSY_STALE_SECONDS:
            return False
    except OSError:
        return False
    return not parts[0].isdigit() or _alive(int(parts[0]))


def foreground_busy(case_dir: str | os.PathLike) -> bool:
    """Whether a foreground tool call is running now: a fresh busy mark of
    a process that is still alive (a killed run's marks never pause the
    batch)."""
    now = time.time()
    try:
        return any(_live_mark(p, now) for p in busy_dir(case_dir).iterdir())
    except OSError:
        return False


# ── the job ──────────────────────────────────────────────────────────────

def manifest_path(case_dir: str | os.PathLike) -> Path:
    return batch_dir(case_dir) / "manifest.json"


# ── the batch's owners (the run processes that started or adopted it) ─────
#
# The batch is a detached job: it outlives the process that started it, by
# design of the job supervisor. A run killed before its _run_end (the OOM
# killer, kill -9) would leave it reading for no one. Every process that
# calls ensure() is recorded as an owner (pid and kernel start time); the
# batch stops when every recorded owner is gone. No clock: a slow run is
# alive, a dead one is gone.

STOP_OWNER_GONE = "the run that started the batch is gone"


def owners_path(case_dir: str | os.PathLike) -> Path:
    return batch_dir(case_dir) / "owners.json"


def _proc_state(pid: int) -> tuple[str, str] | None:
    """(kernel start time, state letter) of ``pid`` from /proc, or None when
    no such process exists; ("", "") when /proc cannot be read."""
    try:
        with open(f"/proc/{int(pid)}/stat", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return ("", "")
    fields = data.rsplit(")", 1)[-1].split()
    return (fields[19] if len(fields) > 19 else "", fields[0] if fields else "")


def owner_alive(owner: dict[str, Any]) -> bool:
    """A recorded owner is alive when a process with its pid exists, is no
    zombie, and has its recorded start time (a reused pid is another
    process). /proc unreadable: alive (never stop on a doubt)."""
    try:
        pid = int(owner.get("pid"))
    except (TypeError, ValueError):
        return False
    st = _proc_state(pid)
    if st is None:
        return False
    start, state = st
    if not start and not state:
        return _alive(pid)
    if state == "Z":
        return False
    return not owner.get("start") or start == str(owner.get("start"))


def add_owner(case_dir: str | os.PathLike, pid: int | None = None) -> None:
    """Record this process (or ``pid``) as an owner of the batch; owners
    already gone are dropped. Locked and written atomically: beside threads
    and other processes call ensure too."""
    import fcntl
    pid = int(pid or os.getpid())
    p = owners_path(case_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            owners = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            owners = []
        owners = [o for o in owners if isinstance(o, dict) and owner_alive(o) and int(o.get("pid") or 0) != pid]
        st = _proc_state(pid)
        owners.append({"pid": pid, "start": (st or ("", ""))[0]})
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(owners), encoding="utf-8")
        os.replace(tmp, p)


def owners_gone(case_dir: str | os.PathLike) -> list[dict[str, Any]] | None:
    """The recorded owners when every one is gone, else None. No owner file
    (a batch started before owners were recorded) or an unreadable one:
    None, the batch keeps running."""
    try:
        owners = json.loads(owners_path(case_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    owners = [o for o in owners if isinstance(o, dict)] if isinstance(owners, list) else []
    if not owners or any(owner_alive(o) for o in owners):
        return None
    return owners


def status(case_dir: str | os.PathLike) -> dict[str, Any]:
    try:
        return json.loads((batch_dir(case_dir) / "status.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ensure(case_dir: str | os.PathLike, images: list[str]) -> dict[str, Any]:
    """Start the case's batch over ``images`` (absolute paths) once; a
    second call returns the job already started. {"job_id", ...} or an
    error."""
    from tools import jobs as J
    from tools import volatility as VV
    from core import VOL_TIMEOUT
    walks, scans = plan()
    d = batch_dir(case_dir)
    d.mkdir(parents=True, exist_ok=True)
    # The wrappers' own binary and symbols, so the batch's answers are the
    # ones a wrapper call looks up.
    man = {"case": str(Path(case_dir).resolve()), "images": list(images), "vol": VV.VOL,
           "symbols": VV.vol3_symbols(),
           "walks": walks, "scans": scans, "pass2": scans_on(),
           "timeouts": {i: VV._memory_budget(i, VOL_TIMEOUT) for i in images},
           "status": str(d / "status.json"), "front": str(d / "front.json"), "busy_dir": str(busy_dir(case_dir))}
    mp = manifest_path(case_dir)
    if not mp.is_file() or json.loads(mp.read_text(encoding="utf-8")).get("images") != man["images"]:
        mp.write_text(json.dumps(man, indent=1), encoding="utf-8")
    try:
        add_owner(case_dir)                       # this run owns the batch it starts or adopts
    except OSError:
        # Owners that cannot be recorded must not stop a live run's batch on
        # a stale list: no owner file means the batch keeps running.
        try:
            owners_path(case_dir).unlink()
        except OSError:
            pass
    r = J._start_job("memory_batch", {"manifest": str(mp)})
    if r.get("job_id"):
        st = status(case_dir)
        st.setdefault("job_id", r["job_id"])
        if st.get("job_id") != r["job_id"]:
            st["job_id"] = r["job_id"]
        _save_status(case_dir, st)
    return r


def _save_status(case_dir: str | os.PathLike, st: dict[str, Any]) -> None:
    p = batch_dir(case_dir) / "status.json"
    try:
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(st, indent=1), encoding="utf-8")
        os.replace(tmp, p)
    except OSError:
        pass


def _running(case_dir: str | os.PathLike) -> str:
    """The batch's job id while it runs, else ""."""
    job = str(status(case_dir).get("job_id") or "")
    if not job:
        return ""
    try:
        from tools import jobs as J
        job_dir, meta, err = J._load_job(job)
        return job if not err and job_dir is not None and J._job_state(job_dir, meta or {}) == "running" else ""
    except Exception:  # noqa: BLE001
        return ""


def queued(case_dir: str | os.PathLike, image: str, plugin: str) -> str:
    """The batch's job id when it will still run ``plugin`` on ``image``;
    the image is then moved to the front of the batch. "" otherwise."""
    job = _running(case_dir) or _restart_orphaned(case_dir)
    if not job:
        return ""
    try:
        man = json.loads(manifest_path(case_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    target = os.path.realpath(image)
    img = next((i for i in man.get("images") or [] if os.path.realpath(i) == target), "")
    planned = list(man.get("walks") or []) + ["windows.info"] + (list(man.get("scans") or [])
                                                                  if man.get("pass2") else [])
    if not img or plugin not in planned:
        return ""
    done = ((status(case_dir).get("images") or {}).get(img) or {}).get("plugins") or {}
    if done.get(plugin) in ("done", "failed"):
        return ""
    try:
        fp = Path(man["front"])
        front = json.loads(fp.read_text(encoding="utf-8")) if fp.is_file() else []
        if img not in front:
            fp.write_text(json.dumps([img] + list(front)), encoding="utf-8")
    except (OSError, ValueError, KeyError):
        pass
    return job


_RESTARTED: set[str] = set()


def _restart_orphaned(case_dir: str | os.PathLike) -> str:
    """A batch that stopped because its owners were gone (a run killed
    before its end) is started again, once per process, by the first
    memory call made on the case: the run that resumes it, or a dashboard
    chat worker answering a question (then owned by that worker until it
    ends). Its stored answers are reused (the runner skips them), so only
    the plugin in flight is lost. The job id, or ""."""
    st = status(case_dir)
    key = str(Path(case_dir).resolve())
    if st.get("stop_reason") != STOP_OWNER_GONE or st.get("state") == "done" or key in _RESTARTED:
        return ""
    _RESTARTED.add(key)
    try:
        man = json.loads(manifest_path(case_dir).read_text(encoding="utf-8"))
        r = ensure(case_dir, list(man.get("images") or []))
    except Exception:  # noqa: BLE001
        return ""
    return str(r.get("job_id") or "") if r.get("job_id") and _running(case_dir) else ""


def pass1_running(case_dir: str | os.PathLike) -> bool:
    """Whether the batch is running and some image's first pass (warm
    read, info, walks) is not done: the coverage lane starts after it, so
    two heavy readers never share the case disk from the start."""
    if not _running(case_dir):
        return False
    try:
        man = json.loads(manifest_path(case_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    images = status(case_dir).get("images") or {}
    return any(((images.get(i) or {}).get("pass1")) != "done" for i in man.get("images") or [])


def stop(case_dir: str | os.PathLike) -> dict[str, Any]:
    """At the run's end: a batch still running is stopped, never awaited,
    and what it did not run is recorded for the disclosure."""
    job = _running(case_dir)
    if not job:
        return {}
    try:
        from tools import jobs as J
        J.job_cancel(job)
    except Exception:  # noqa: BLE001
        pass
    st = status(case_dir)
    st["stopped"] = True
    st["not_run"] = not_run(case_dir)
    _save_status(case_dir, st)
    return st


def not_run(case_dir: str | os.PathLike) -> dict[str, list[str]]:
    """Per image, the planned plugins the batch has not run."""
    try:
        man = json.loads(manifest_path(case_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    planned = ["windows.info"] + list(man.get("walks") or []) + (list(man.get("scans") or [])
                                                                  if man.get("pass2") else [])
    images = (status(case_dir).get("images") or {})
    out = {}
    for img in man.get("images") or []:
        done = ((images.get(img) or {}).get("plugins") or {})
        left = [p for p in planned if done.get(p) not in ("done", "failed")]
        if left:
            out[img] = left
    return out


def stop_lines(case_dir: str | os.PathLike) -> list[str]:
    """The disclosure of a batch stopped at the run's end."""
    st = status(case_dir)
    if not st.get("stopped") or not st.get("not_run"):
        return []
    parts = [f"{Path(img).name}: {', '.join(p.split('.', 1)[-1] for p in left)}"
             for img, left in sorted((st.get("not_run") or {}).items())]
    when = (f"stopped ({st['stop_reason']})" if st.get("stop_reason") else "stopped at the run's end")
    return [f"The memory batch was {when} before it ran: " + "; ".join(parts)]


def runner_cmd(manifest: str, output_dir: str = "") -> list[str]:
    """The batch job's argv (tools/memory_batch_runner.py over the case's
    one manifest, so the job registry runs one batch per case)."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [sys.executable, os.path.join(repo, "tools", "memory_batch_runner.py"), manifest]
