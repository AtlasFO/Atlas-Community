"""The memory batch's worker (core.memory_batch): run by the background job
supervisor over the case's manifest. Image by image: a sequential read
into the page cache, then the planned plugins, each answer kept in the
result store (core.vol_cache) under the key a wrapper call looks up. Runs
at the lowest CPU priority (an idle I/O class does not hold on a disk
without a scheduler that honours it, so the read is paced instead): the
read pauses per chunk while a foreground tool call runs. Writes its progress to the manifest's status
file and takes images asked for first from its front file.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

CHUNK = 16 << 20                 # the sequential read's chunk
PAUSE = 0.5                      # the wait between checks while the foreground is busy
POLL = 2.0                       # how often a running plugin's owners are checked
KILL_GRACE = 10                  # seconds between TERM and KILL to a plugin's process group


class OwnerGone(Exception):
    """Every process that owns the batch is gone (core.memory_batch.owners_gone)."""


class Cancelled(BaseException):
    """The job was cancelled (SIGTERM or SIGINT to the runner): the plugin in
    flight runs in its own process group, so the runner stops it itself."""


def _on_signal(signum, _frame):
    raise Cancelled(signum)


def _check_owners(case: str) -> None:
    from core.memory_batch import owners_gone
    if owners_gone(case) is not None:
        raise OwnerGone()


def _lower_priority() -> None:
    try:
        os.nice(19)
    except OSError:
        pass


def _load(path: str, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _save(path: str, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, path)


def warm(image: str, case: str, paced: bool = True, check=None) -> float:
    """Read the image once in large chunks; MB/s of the read. Pauses while a
    foreground tool call runs (a guard per chunk). The read covers the
    whole image, so it also takes the image's full content hash, kept as
    the image's identity in the result store (core.vol_cache) while the
    file keeps the size and mtime it had before the read."""
    import hashlib
    from core.memory_batch import foreground_busy
    from core import vol_cache as V
    start, total = time.monotonic(), 0
    digest = hashlib.sha256()
    try:
        fd = os.open(image, os.O_RDONLY)
        before = os.fstat(fd)
    except OSError:
        return 0.0
    try:
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_SEQUENTIAL)
        except (AttributeError, OSError):
            pass
        while True:
            if check is not None:
                check()                          # the batch's owners, per chunk
            while paced and foreground_busy(case):
                time.sleep(PAUSE)
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
    except OSError:
        total = -1
    finally:
        os.close(fd)
    try:
        after = os.stat(image)
        if (total == before.st_size == after.st_size and after.st_mtime_ns == before.st_mtime_ns):
            V.record_full_hash(case, image, digest.hexdigest(), after.st_size, after.st_mtime_ns)
    except OSError:
        pass
    secs = max(time.monotonic() - start, 1e-6)
    return round(max(total, 0) / secs / (1 << 20), 1)


def run_plugin(man: dict, image: str, plugin: str) -> str:
    """Run one plugin unless its answer is stored; "done" or "failed"."""
    from core import vol_cache as V
    case = man["case"]
    key = V.key_for(case, image, plugin, None, vol_bin=man["vol"], symbol_dir=man["symbols"])
    if key and V.lookup(case, key) is not None:
        return "done"
    flags = []
    use = V.config_for_use(case, image)
    if use:
        flags = ["-c", use]
    else:
        p = V.config_path(case, image)
        if p is not None:
            p.parent.mkdir(parents=True, exist_ok=True)
            flags = ["--save-config", str(p)]
    cmd = [man["vol"], "-s", man["symbols"], *flags, "-f", image, "-r", "json", plugin]
    timeout = int((man.get("timeouts") or {}).get(image) or 3600)
    try:
        code, stdout, stderr = _run_watched(cmd, timeout, case)
    except subprocess.TimeoutExpired:
        return "failed"
    except OSError:
        return "failed"
    result = {"success": code == 0, "stdout": stdout, "stderr": stderr[-2000:],
              "exit_code": code, "truncated": False, "timed_out": False, "cmd": " ".join(cmd)}
    if not result["success"] and use:
        V.forget_config(case, image)
        return run_plugin(man, image, plugin)
    if V.store(case, key, result, {"cmd": result["cmd"], "call_id": None, "trace": "memory batch",
                                   "volatility": V.vol_version(man["vol"]),
                                   "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}):
        return "done"
    return "done" if V.complete(result) else "failed"


def _stop_group(proc: subprocess.Popen, grace: float = KILL_GRACE) -> None:
    """TERM, then KILL after a grace, to the plugin's own process group
    (started in a session of its own, so no other process is in it)."""
    import signal
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 5)):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _run_watched(cmd: list[str], timeout: int, case: str) -> tuple[int, str, str]:
    """Run one plugin in a process group of its own, checking the batch's
    owners every POLL seconds: gone, the plugin's group is stopped and
    OwnerGone raised. The plugin's own timeout stays a per-call guard."""
    import tempfile
    with tempfile.TemporaryFile("w+") as out, tempfile.TemporaryFile("w+") as err:
        proc = subprocess.Popen(cmd, stdout=out, stderr=err, text=True, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    code = proc.wait(timeout=POLL)
                    break
                except subprocess.TimeoutExpired:
                    pass
                try:
                    _check_owners(case)
                except OwnerGone:
                    _stop_group(proc)
                    raise
                if time.monotonic() >= deadline:
                    _stop_group(proc)
                    raise subprocess.TimeoutExpired(cmd, timeout)
        except Cancelled:
            # A cancel: the supervisor's own kill follows its grace, so the
            # plugin is stopped within a shorter one.
            _stop_group(proc, grace=2)
            raise
        out.seek(0)
        err.seek(0)
        return code, out.read(), err.read()


def run_image(man: dict, status: dict, image: str, plugins: list[str], which: int) -> None:
    from core.memory_batch import fallback_scan
    st = status.setdefault("images", {}).setdefault(image, {"plugins": {}})
    st[f"pass{which}"] = "running"
    _save(man["status"], status)
    st[f"warm{which}_mb_s"] = warm(image, man["case"], check=lambda: _check_owners(man["case"]))
    queue = list(plugins)
    while queue:
        plugin = queue.pop(0)
        if st["plugins"].get(plugin) == "done":
            continue
        _check_owners(man["case"])
        st["plugins"][plugin] = "running"
        _save(man["status"], status)
        state = run_plugin(man, image, plugin)
        st["plugins"][plugin] = state
        if state == "failed" and which == 1 and man.get("pass2"):
            # Only with background scans on; off, the walk's failure is
            # recorded and its scan stays on request.
            scan = fallback_scan(plugin)
            if scan and scan not in queue and st["plugins"].get(scan) != "done":
                queue.append(scan)                  # a failed walk moves its structure to its scan
        _save(man["status"], status)
    st[f"pass{which}"] = "done"
    _save(man["status"], status)


def _next(remaining: list[str], front_path: str) -> str:
    front = _load(front_path, [])
    for img in front if isinstance(front, list) else []:
        if img in remaining:
            remaining.remove(img)
            return img
    return remaining.pop(0)


def main(manifest: str) -> int:
    import signal
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _on_signal)
        except ValueError:          # not the main thread (a test calling main): nothing to install
            pass
    try:
        return _main(manifest)
    except Cancelled:
        # memory_batch.stop records the stop and what was not run; the runner
        # writes nothing more, so it never overwrites that record.
        return 143


def _main(manifest: str) -> int:
    _lower_priority()
    man = _load(manifest, {})
    status = _load(man["status"], {})
    status["state"] = "running"
    for k in ("stopped", "stop_reason", "not_run", "owners"):   # an earlier stop no longer holds
        status.pop(k, None)
    _save(man["status"], status)
    passes = [(1, ["windows.info"] + list(man.get("walks") or []))]
    if man.get("pass2"):
        passes.append((2, list(man.get("scans") or [])))
    try:
        for which, plugins in passes:
            remaining = list(man.get("images") or [])
            while remaining:
                run_image(man, status, _next(remaining, man["front"]), plugins, which)
    except OwnerGone:
        return _stopped_owner_gone(man, status)
    status["state"] = "done"
    _save(man["status"], status)
    print(json.dumps({"images": len(man.get("images") or []), "status": man["status"]}))
    return 0


def _stopped_owner_gone(man: dict, status: dict) -> int:
    """Record the stop as core.memory_batch.stop does (stopped, not_run),
    with its reason and the owners that were gone; exit non-zero, so the job
    registry never takes it for a finished batch."""
    from core import memory_batch as MB
    for st in (status.get("images") or {}).values():
        for p, state in list((st.get("plugins") or {}).items()):
            if state == "running":
                st["plugins"][p] = "stopped"
    status["state"] = "stopped"
    _save(man["status"], status)
    status["stopped"] = True
    status["stop_reason"] = MB.STOP_OWNER_GONE
    status["owners"] = MB.owners_gone(man["case"]) or []
    status["not_run"] = MB.not_run(man["case"])
    _save(man["status"], status)
    # A stop of Atlas's, not a failure of the images: the job's record says so.
    from tools.jobs_runner import record_atlas_stop
    record_atlas_stop(MB.STOP_OWNER_GONE)
    print(json.dumps({"stopped": MB.STOP_OWNER_GONE}))
    return 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
