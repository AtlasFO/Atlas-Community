"""Volatility 3 plugin wrappers — Windows, Linux, and cross-platform.

This file runs Volatility and parses its results. To the extent the
Volatility Software License 1.0 treats it as an Addition, it is offered
under that licence in addition to Atlas's own (see THIRD-PARTY.md):
https://www.volatilityfoundation.org/license/vsl-v1.0
"""
import os
import glob
import json
from typing import Optional, Any
from fastmcp import FastMCP, Context
from core import run, run_with_progress, output_safe, vol3_bin, vol3_symbols, DEFAULT_TIMEOUT, VOL_TIMEOUT
from core.paths import MIN_THROUGHPUT_MB_S, scale_timeout

mcp = FastMCP("volatility")
VOL = vol3_bin()

# A memory plugin walks the whole image: a scanner touches every page and a
# lister still maps the kernel across it. The budget therefore scales with
# the image, at a quarter of the sequential-read assumption other tools use
# (a Python page scanner is that much slower than a raw read); the
# configured base stays the floor, so small images are unaffected.
_SCAN_THROUGHPUT_MB_S = max(1, MIN_THROUGHPUT_MB_S // 4)


def _memory_budget(image: str, base: int) -> int:
    return scale_timeout(base, image, min_throughput_mb_s=_SCAN_THROUGHPUT_MB_S)




def _store_key(image: str, plugin: str, extra: list[str] | None, output_dir: str | None) -> tuple[str, str]:
    """(case, key) of a plugin call in the result store (core.vol_cache);
    ("", "") when there is no case, the store is off or the call writes
    files."""
    try:
        from core import vol_cache as V
        from core.paths import active_case_dir
        case = active_case_dir()
        if not case or not V.store_on() or V.writes_files(plugin, extra, output_dir):
            return "", ""
        return case, V.key_for(case, image, plugin, extra, vol_bin=VOL, symbol_dir=vol3_symbols())
    except Exception:  # noqa: BLE001 - no store, a plain call
        return "", ""


def _from_store(case: str, key: str, cmd: list[str]) -> dict | None:
    """A stored answer as a full call of this run: recorded in the trace
    with its own saved output, its cached_from naming the stored call."""
    from core import vol_cache as V
    hit = V.lookup(case, key) if key else None
    if hit is None:
        return None
    import shutil
    from core.executor import _log_tool, _spill_target_dir, capped_output, spill_file_path
    from core.execution_log import log
    result = {**(hit.get("result") or {}), "cmd": " ".join(cmd), "success": True, "truncated": False,
              "retries": 0, "stderr": "", "exit_code": 0, "elapsed_seconds": 0.0, "timed_out": False}
    try:
        # The same cut a run gives (the model's context), the full output in
        # the answer's own saved copy for this run, so citations and row
        # references resolve it like a call that ran.
        result["stdout"], result["truncated"] = capped_output(hit["output"])
        spill = _spill_target_dir()
        if spill is not None:
            path = spill_file_path(spill, "vol")
            shutil.copyfile(hit["output"], path)
            result["stdout_file"] = path
    except Exception:  # noqa: BLE001 - an unreadable stored output is a miss
        return None
    _log_tool(result)
    meta = dict(hit.get("meta") or {})
    log.annotate_tool_call(result["_atlas_call_id"], cached_from=meta)
    result["cached_from"] = meta
    result["note"] = "answered from the result store, not re-run (the same image, symbols and Volatility)"
    return result


def _job_stamp(job_id: str) -> dict:
    """A deferred answer stands for the batch job's start record: whether the
    image was read is the job's outcome (core.coverage_ledger), never this
    call's success. {"_atlas_call_id": <the start's call id>} or {}."""
    try:
        from tools.jobs import _load_job
        _dir, meta, err = _load_job(str(job_id or ""))
        cid = (meta or {}).get("start_call_id") if not err else None
        return {"_atlas_call_id": int(cid)} if cid else {}
    except Exception:  # noqa: BLE001 - the result entry still names the job
        return {}


def _in_batch(case: str, image: str, plugin: str) -> dict | None:
    """A plugin the case's memory batch will still run on this image: the
    image moves to the front of the batch and the call answers with the
    job, instead of a second cold read of the image (core.memory_batch)."""
    if not case:
        return None
    try:
        from core.memory_batch import queued
        job = queued(case, image, plugin)
    except Exception:  # noqa: BLE001
        return None
    if not job:
        return None
    return {**_job_stamp(job), "success": True, "deferred": True, "job_id": job, "plugin": plugin, "image": image,
            "hint": (f"{plugin} on this image runs in the memory batch, background job {job}, now moved to the "
                     "front; its answer is kept: once the batch has run it, the same call in a later round or "
                     "item returns it at once. Work on other leads meanwhile.")}


def _keep(case: str, key: str, result: dict) -> None:
    if not key:
        return
    from datetime import datetime, timezone
    from core import vol_cache as V
    try:
        from core.execution_log import log
        trace = str(getattr(log, "_case_id", "") or "")
    except Exception:  # noqa: BLE001
        trace = ""
    V.store(case, key, result, {"cmd": result.get("cmd"), "call_id": result.get("_atlas_call_id"),
                                "trace": trace, "volatility": V.vol_version(VOL),
                                "time": datetime.now(timezone.utc).isoformat(timespec="seconds")})


# Calls answered "deferred" in this process: a repeat waits for the batch.
_DEFERRED: set[tuple[str, str]] = set()
_WAIT_POLL = 2.0


def _wait_batch(case: str, image: str, plugin: str, budget: int) -> bool:
    """Wait for the batch to finish ``plugin`` on ``image``, at most the
    plugin's own per-call budget (waiting costs what running it would).
    True when the batch ran it (or stopped), False when it is still due."""
    import time
    from core import memory_batch as MB
    target = os.path.realpath(image)
    deadline = time.monotonic() + max(1, budget)
    while time.monotonic() < deadline:
        images = MB.status(case).get("images") or {}
        mine = next((v for k, v in images.items() if os.path.realpath(k) == target), {}) or {}
        if (mine.get("plugins") or {}).get(plugin) in ("done", "failed") or not MB._running(case):
            return True
        time.sleep(_WAIT_POLL)
    return False


def _from_batch(case: str, key: str, cmd: list[str], image: str, plugin: str, timeout: int) -> dict | None:
    """The batch's part of a call: the deferred answer the first time; on a
    repeat the stored answer when the batch has run it, waited for once per
    image and plugin in this process (up to the plugin's per-call budget);
    after that one wait a repeat answers at once. None when the call is to
    run here."""
    waiting = _in_batch(case, image, plugin)
    if waiting is None:
        return None
    seen = (os.path.realpath(image), plugin)
    if seen not in _DEFERRED:
        _DEFERRED.add(seen)
        return waiting
    import time
    budget = _memory_budget(image, timeout)
    if seen in _WAITED:
        # Waited for once already: no second foreground wait. The answer,
        # when the batch has run it meanwhile, is still returned.
        stored = _from_store(case, key, cmd)
        return stored if stored is not None else _still_queued(case, image, plugin, waiting, None, budget)
    _WAITED.add(seen)
    started = time.monotonic()
    if not _wait_batch(case, image, plugin, budget):
        return _still_queued(case, image, plugin, waiting, int(time.monotonic() - started), budget)
    return _from_store(case, key, cmd)


# Plugins this process has waited for once (image, plugin): a repeat after
# that wait answers without waiting again.
_WAITED: set[tuple[str, str]] = set()
# How many ready plugins a still-queued answer names (the rest counted).
_READY_NAMED = 6


def _position(man: dict, images: dict, target: str, plugin: str) -> str:
    """Where the plugin stands in the batch, said only when it is known: the
    plugins that run before it on this image, and for a second-pass scan the
    first pass of every image left before it (the runner runs pass 2 after
    pass 1 of every image)."""
    def states_of(img: str) -> dict:
        return next((v for k, v in images.items() if os.path.realpath(k) == os.path.realpath(img)), {}).get(
            "plugins") or {}
    pass1 = ["windows.info"] + list(man.get("walks") or [])
    pass2 = list(man.get("scans") or []) if man.get("pass2") else []
    mine = states_of(target)
    if plugin in pass1:
        left = [p for p in pass1 if mine.get(p) not in ("done", "failed")]
        if plugin in left:
            return f"{left.index(plugin)} plugin(s) of this image run before it"
    elif plugin in pass2:
        first = sum(1 for img in man.get("images") or [] for p in pass1
                    if states_of(img).get(p) not in ("done", "failed"))
        left = [p for p in pass2 if mine.get(p) not in ("done", "failed")]
        if plugin in left:
            return (f"it is a second-pass plugin: the first pass of every image runs first ({first} plugin(s) of it "
                    f"left), then {left.index(plugin)} second-pass plugin(s) of this image")
    return "its place in the batch is not known"


def _still_queued(case: str, image: str, plugin: str, waiting: dict, waited: int | None, budget: int) -> dict:
    """A repeat that finds the plugin still not run: new facts instead of
    the first answer's promise. Its place in the batch when that is known,
    the plugins of this image whose answers are ready (those calls answer at
    once), and the moves. The queued plugins are counted, never named: each
    call moves the image to the front, and a list of names invites calling
    them in turn. No time estimate: the batch records none."""
    from core import memory_batch as MB
    try:
        man = json.loads(MB.manifest_path(case).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        man = {}
    target = os.path.realpath(image)
    images = MB.status(case).get("images") or {}
    states = next((v for k, v in images.items() if os.path.realpath(k) == target), {}).get("plugins") or {}
    order = ["windows.info"] + list(man.get("walks") or []) + (list(man.get("scans") or []) if man.get("pass2") else [])
    ready = [p.split(".", 1)[-1] for p in order if states.get(p) == "done"]
    named = ", ".join(ready[:_READY_NAMED]) + (f" and {len(ready) - _READY_NAMED} more" if len(ready) > _READY_NAMED
                                               else "")
    waited_text = (f"still not run after waiting {waited} s" if waited is not None
                   else f"still not run; this call was waited for once already (up to {budget} s)")
    hint = (f"{waited_text}; {_position(man, images, target, plugin)}. It is not waited for again: read the "
            "item's other evidence or submit; the answer is kept, and once the batch has run it, the same call in a "
            "later round or item returns it at once."
            + (f" Ready now on this image: {named}." if ready else ""))
    out = {**_job_stamp(waiting.get("job_id")), "success": True, "deferred": True, "still_queued": True,
           "job_id": waiting.get("job_id"), "plugin": plugin, "ready": ready[:_READY_NAMED], "hint": hint}
    if waited is not None:                       # a reply that did not wait states no wait
        out["waited_seconds"] = waited
    return out


def _warm_for_scan(case: str, image: str, plugin: str) -> bool:
    """A scan run on request reads the image sequentially first: a pool
    scan is I/O bound on a cold image (measured 14 to 21 times slower), and
    one read at disk speed makes it warm. Not paced: this read is the
    foreground call, and it marks itself busy like any foreground call, so
    the background lanes pause while it reads."""
    from core.evidence_disposition import memory_cost
    if memory_cost(plugin) != "scan" or not case:
        return False
    from core.executor import _lane
    from core.memory_batch import mark_busy, unmark_busy
    mark = mark_busy(case, lane=_lane())
    try:
        from tools.memory_batch_runner import warm
        warm(image, case, paced=False)
        return True
    except Exception:  # noqa: BLE001 - a cold scan still runs
        return False
    finally:
        unmark_busy(mark)


def _vol(image: str, plugin: str, extra: list[str] | None = None,
         output_dir: str | None = None, timeout: int = VOL_TIMEOUT) -> dict:
    # -o OUTPUT_DIR is a global Volatility flag — must come before the plugin name.
    # Plugin-specific args (--pid, --dump, etc.) go in extra, after the plugin.
    out_flags = ["-o", output_dir] if output_dir else []
    cmd = [VOL, "-s", vol3_symbols()] + out_flags + ["-f", image, "-r", "json", plugin] + (extra or [])
    case, key = _store_key(image, plugin, extra, output_dir)
    stored = _from_store(case, key, cmd)
    if stored is not None:
        return stored
    if not extra and not output_dir:
        batch = _from_batch(case, key, cmd, image, plugin, timeout)
        if batch is not None:
            return batch
    if _warm_for_scan(case, image, plugin):
        case, key = _store_key(image, plugin, extra, output_dir)    # the read took the image's full hash
    result = _run_with_config(case, image, cmd, timeout)
    _keep(case, key, result)
    return result


def _config_flags(case: str, image: str) -> tuple[list[str], bool]:
    """(global flags, using a saved config): -c with the image's saved
    layer config, else --save-config to keep the one this call finds."""
    if not case:
        return [], False
    try:
        from core import vol_cache as V
        use = V.config_for_use(case, image)
        if use:
            return ["-c", use], True
        p = V.config_path(case, image)
        if p is not None:
            p.parent.mkdir(parents=True, exist_ok=True)
            return ["--save-config", str(p)], False
    except Exception:  # noqa: BLE001 - no config, a plain call
        pass
    return [], False


def _run_with_config(case: str, image: str, cmd: list[str], timeout: int) -> dict:
    """Run a plugin with the image's layer config (core.vol_cache): a call
    that fails with it is run once more without it, and the config is found
    and saved again."""
    flags, using = _config_flags(case, image)
    at = cmd.index("-f")                       # global flags go before the plugin
    result = run(cmd[:at] + flags + cmd[at:], timeout=_memory_budget(image, timeout))
    if using and not result.get("success") and not result.get("timed_out"):
        from core import vol_cache as V
        V.forget_config(case, image)
        flags, _u = _config_flags(case, image)
        result = run(cmd[:at] + flags + cmd[at:], timeout=_memory_budget(image, timeout))
    return result


def _info_cmd(image_path: str, output_dir: str = "") -> list[str]:
    """One info-class pass over a memory image (OS build, system time): the
    evidence survey's header, run as a background job (output_dir unused:
    the job keeps its own output)."""
    return [VOL, "-s", vol3_symbols(), "-f", image_path, "-r", "json", "windows.info"]


def _pid_extra(pid: Optional[int] = None) -> list[str]:
    """Build a `--pid N` flag pair, or [] if pid is None/0."""
    return ["--pid", str(pid)] if pid else []


def _offset_extra(offset: Optional[str] = None) -> list[str]:
    """Build a `--offset OFFSET` flag pair, or [] if offset is None/empty."""
    return ["--offset", offset] if offset else []


async def _vol_progress(image: str, plugin: str, ctx: Any,
                        output_dir: str | None = None, timeout: int = VOL_TIMEOUT) -> dict:
    """Async variant of _vol() with FastMCP Context progress reporting."""
    out_flags = ["-o", output_dir] if output_dir else []
    cmd = [VOL, "-s", vol3_symbols()] + out_flags + ["-f", image, "-r", "json", plugin]
    case, key = _store_key(image, plugin, None, output_dir)
    stored = _from_store(case, key, cmd)
    if stored is not None:
        return stored
    if not output_dir:
        batch = _from_batch(case, key, cmd, image, plugin, timeout)
        if batch is not None:
            return batch
    if _warm_for_scan(case, image, plugin):
        case, key = _store_key(image, plugin, None, output_dir)     # the read took the image's full hash
    flags, using = _config_flags(case, image)
    at = cmd.index("-f")
    result = await run_with_progress(cmd[:at] + flags + cmd[at:], ctx, timeout=_memory_budget(image, timeout))
    if using and not result.get("success") and not result.get("timed_out"):
        from core import vol_cache as V
        V.forget_config(case, image)
        flags, _u = _config_flags(case, image)
        result = await run_with_progress(cmd[:at] + flags + cmd[at:], ctx, timeout=_memory_budget(image, timeout))
    _keep(case, key, result)
    return result


# ── Image info ──────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_info(image: str) -> dict:
    """Display OS version, architecture, and kernel build from a memory image."""
    return _vol(image, "windows.info")


@mcp.tool()
@output_safe
def vol_symbol_check(memory_image: str) -> dict:
    """
    Pre-flight check: verify the memory image exists and Volatility 3 symbol
    files are cached. Returns the resolved absolute path in the 'image' field
    so downstream plugins can use it directly without re-expanding ~.

    If symbols_ready is False, call vol_info once (requires internet) to
    trigger the download for this kernel build, then retry memory plugins.
    """
    expanded = os.path.expanduser(memory_image)
    if not os.path.exists(expanded):
        return {
            "success": False,
            "image": memory_image,
            "symbols_ready": False,
            "cached_symbol_count": 0,
            "cached_guids": [],
            "note": f"Image not found: {expanded} — check the path and try again.",
        }

    symbols_dir = vol3_symbols()
    cached = glob.glob(os.path.join(symbols_dir, "windows", "ntkrnlmp.pdb", "*.json.xz"))
    cached += glob.glob(os.path.join(symbols_dir, "windows", "ntoskrnl.pdb", "*.json.xz"))

    return {
        "success": True,
        "image": expanded,
        "symbols_ready": len(cached) > 0,
        "cached_symbol_count": len(cached),
        "cached_guids": [os.path.basename(p) for p in cached],
        "note": (
            "Symbol cache is populated — proceed with memory plugins."
            if cached else
            "Symbol cache is empty — call vol_info once to download symbols (requires internet)."
        ),
    }


# ── Process enumeration ─────────────────────────────────────────────────────

@mcp.tool()
async def vol_pslist(image: str, ctx: Context, pid: Optional[int] = None) -> dict:
    """List processes via EPROCESS linked list walk. Fast; misses hidden processes."""
    if pid:
        return _vol(image, "windows.pslist", _pid_extra(pid))
    return await _vol_progress(image, "windows.pslist", ctx, timeout=VOL_TIMEOUT)


@mcp.tool()
async def vol_psscan(image: str, ctx: Context) -> dict:
    """Scan for EPROCESS pool tags — finds hidden and exited processes. Preferred over pslist."""
    return await _vol_progress(image, "windows.psscan", ctx, timeout=VOL_TIMEOUT)


@mcp.tool()
@output_safe
def vol_pstree(image: str, pid: Optional[int] = None) -> dict:
    """Display process hierarchy with parent-child relationships."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.pstree", extra)


@mcp.tool()
@output_safe
def vol_psxview(image: str) -> dict:
    """Cross-reference process lists (pslist, psscan, sessions, etc.) to find hidden processes."""
    return _vol(image, "windows.psxview")


# ── Process details ──────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_cmdline(image: str, pid: Optional[int] = None) -> dict:
    """Extract command-line arguments for all or a specific process."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.cmdline", extra)


@mcp.tool()
@output_safe
def vol_envars(image: str, pid: Optional[int] = None) -> dict:
    """Extract environment variables per process (reveals working dir, injected vars)."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.envars", extra)


@mcp.tool()
@output_safe
def vol_getsids(image: str, pid: Optional[int] = None) -> dict:
    """Extract security identifiers (SIDs) associated with processes."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.getsids", extra)


@mcp.tool()
@output_safe
def vol_privileges(image: str, pid: Optional[int] = None) -> dict:
    """List token privileges per process (look for SeDebugPrivilege, SeTcbPrivilege)."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.privileges", extra)


@mcp.tool()
@output_safe
def vol_dlllist(image: str, pid: Optional[int] = None) -> dict:
    """List loaded DLLs per process. Check for spoofed or injected DLLs."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.dlllist", extra)


@mcp.tool()
@output_safe
def vol_handles(image: str, pid: Optional[int] = None) -> dict:
    """
    List open handles per process (files, registry keys, mutexes, events, threads).

    Volatility 3's `windows.handles` plugin only accepts --pid and --offset —
    there is no built-in handle-type filter. To filter the result by type
    (File, Key, Mutant, Thread, Process, Section, Event, …), grep the rendered
    output column "Type" via `strings.strings_grep` on the JSON output or pipe
    the result through a downstream filter.
    """
    extra = []
    extra += _pid_extra(pid)
    return _vol(image, "windows.handles", extra)


@mcp.tool()
@output_safe
def vol_ldrmodules(image: str, pid: Optional[int] = None) -> dict:
    """Cross-reference loaded modules across PEB/VAD/LDR lists. Discrepancies = injection indicator."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.ldrmodules", extra)


@mcp.tool()
@output_safe
def vol_sessions(image: str) -> dict:
    """List active user sessions."""
    return _vol(image, "windows.sessions")


# ── Network ──────────────────────────────────────────────────────────────────

@mcp.tool()
async def vol_netstat(image: str, ctx: Context) -> dict:
    """Walk TCP/IP structures — active connections at capture time."""
    return await _vol_progress(image, "windows.netstat", ctx, timeout=VOL_TIMEOUT)


@mcp.tool()
async def vol_netscan(image: str, ctx: Context) -> dict:
    """Pool-tag scan for network connections — finds historical/closed connections too."""
    return await _vol_progress(image, "windows.netscan", ctx, timeout=VOL_TIMEOUT)


# ── Services ─────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_svcscan(image: str) -> dict:
    """Enumerate services via pool scan — finds hidden and deleted services still in memory."""
    return _vol(image, "windows.svcscan")


@mcp.tool()
@output_safe
def vol_svclist(image: str) -> dict:
    """List services via SCM (Service Control Manager) structures."""
    return _vol(image, "windows.svclist")


@mcp.tool()
@output_safe
def vol_svcdiff(image: str) -> dict:
    """Diff services found via SCM vs pool scan to detect hidden services."""
    return _vol(image, "windows.svcdiff")


# ── Registry ──────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_registry_hivelist(image: str) -> dict:
    """List all loaded registry hives and their virtual addresses."""
    return _vol(image, "windows.registry.hivelist")


@mcp.tool()
@output_safe
def vol_registry_hivescan(image: str) -> dict:
    """Pool-tag scan for registry hives — finds unloaded/hidden hives."""
    return _vol(image, "windows.registry.hivescan")


@mcp.tool()
@output_safe
def vol_registry_printkey(image: str, key: str, hive_offset: Optional[str] = None) -> dict:
    """
    Print a registry key and its values from memory.
    key: e.g. 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    """
    extra = ["--key", key]
    if hive_offset:
        extra += ["--offset", hive_offset]
    return _vol(image, "windows.registry.printkey", extra)


@mcp.tool()
@output_safe
def vol_userassist(image: str) -> dict:
    """Extract UserAssist registry entries — GUI execution evidence (programs run via Explorer)."""
    return _vol(image, "windows.registry.userassist")


@mcp.tool()
@output_safe
def vol_registry_amcache(image: str) -> dict:
    """Extract Amcache entries from memory (program execution evidence)."""
    return _vol(image, "windows.registry.amcache")


@mcp.tool()
@output_safe
def vol_scheduled_tasks(image: str) -> dict:
    """Extract scheduled tasks from registry in memory."""
    return _vol(image, "windows.registry.scheduled_tasks")


# ── Injection & anomalous memory ─────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_malfind(image: str, pid: Optional[int] = None, dump: bool = False, output_dir: Optional[str] = None) -> dict:
    """
    Find RWX memory regions with PE headers or shellcode — primary injection scanner.
    Set dump=True with output_dir to extract suspicious regions to disk.
    """
    extra = []
    extra += _pid_extra(pid)
    if dump and output_dir:
        extra += ["--dump"]
    return _vol(image, "windows.malfind", extra, output_dir=output_dir if dump else None)


@mcp.tool()
@output_safe
def vol_vadinfo(image: str, pid: Optional[int] = None) -> dict:
    """Inspect Virtual Address Descriptor tree for a process — all memory regions."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.vadinfo", extra)


@mcp.tool()
@output_safe
def vol_vadwalk(image: str, pid: Optional[int] = None) -> dict:
    """Walk the VAD tree structure for a process."""
    extra = _pid_extra(pid)
    return _vol(image, "windows.vadwalk", extra)


@mcp.tool()
@output_safe
def vol_hollowprocesses(image: str) -> dict:
    """Detect process hollowing by comparing VAD entries against PEB module list."""
    return _vol(image, "windows.hollowprocesses")


@mcp.tool()
@output_safe
def vol_pebmasquerade(image: str) -> dict:
    """Detect PEB masquerading — process pretending to be a different executable."""
    return _vol(image, "windows.malware.pebmasquerade")


@mcp.tool()
@output_safe
def vol_suspicious_threads(image: str) -> dict:
    """Find threads with suspicious start addresses (e.g. starting in non-image memory)."""
    return _vol(image, "windows.suspicious_threads")


@mcp.tool()
@output_safe
def vol_vadyarascan(image: str, yara_rules: str, pid: Optional[int] = None) -> dict:
    """
    YARA scan of process VAD regions directly from memory.
    yara_rules: path to a .yar file or inline rule string.
    """
    extra = ["--yara-rules", yara_rules]
    extra += _pid_extra(pid)
    return _vol(image, "windows.vadyarascan", extra, timeout=VOL_TIMEOUT)


@mcp.tool()
@output_safe
def vol_cmdscanner(image: str) -> dict:
    """Scan for COMMAND_HISTORY and CONSOLE_INFORMATION structures — console input history."""
    return _vol(image, "windows.cmdscan")


@mcp.tool()
@output_safe
def vol_consoles(image: str) -> dict:
    """Extract console I/O buffers — what was typed and displayed in cmd.exe windows."""
    return _vol(image, "windows.consoles")


# ── Kernel modules & drivers ──────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_modules(image: str) -> dict:
    """List loaded kernel modules via linked list walk."""
    return _vol(image, "windows.modules")


@mcp.tool()
@output_safe
def vol_modscan(image: str) -> dict:
    """Pool-tag scan for kernel modules — finds hidden/unlinked drivers."""
    return _vol(image, "windows.modscan")


@mcp.tool()
@output_safe
def vol_driverscan(image: str) -> dict:
    """Scan for DRIVER_OBJECT structures in pool memory."""
    return _vol(image, "windows.driverscan")


@mcp.tool()
@output_safe
def vol_driverirp(image: str) -> dict:
    """List IRP handlers for all drivers — used to find hooked dispatch routines."""
    return _vol(image, "windows.driverirp")


@mcp.tool()
@output_safe
def vol_devicetree(image: str) -> dict:
    """Display driver/device object tree — shows device stacking for rootkit detection."""
    return _vol(image, "windows.devicetree")


@mcp.tool()
@output_safe
def vol_callbacks(image: str) -> dict:
    """List kernel notification callbacks (PsSetCreateProcessNotifyRoutine, etc.)."""
    return _vol(image, "windows.callbacks")


@mcp.tool()
@output_safe
def vol_ssdt(image: str) -> dict:
    """Display the System Service Descriptor Table — detect SSDT hooks."""
    return _vol(image, "windows.ssdt")


@mcp.tool()
@output_safe
def vol_unhooked_system_calls(image: str) -> dict:
    """Compare SSDT entries to expected values to find unhooked system calls."""
    return _vol(image, "windows.unhooked_system_calls")


# ── File system artifacts ────────────────────────────────────────────────────

@mcp.tool()
async def vol_filescan(image: str, ctx: Context) -> dict:
    """Scan for FILE_OBJECT structures — lists all files cached in memory."""
    return await _vol_progress(image, "windows.filescan", ctx, timeout=VOL_TIMEOUT)


@mcp.tool()
@output_safe
def vol_dumpfiles(
    image: str,
    virt_addr: Optional[str] = None,
    pid: Optional[int] = None,
    output_dir: Optional[str] = None,
) -> dict:
    """
    Dump files from memory by virtual address (from filescan output) or PID.
    Requires output_dir.
    """
    if not output_dir:
        return {"success": False, "stderr": "output_dir is required for dumpfiles"}
    extra = []
    if virt_addr:
        extra += ["--virtaddr", virt_addr]
    extra += _pid_extra(pid)
    return _vol(image, "windows.dumpfiles", extra, output_dir=output_dir)


@mcp.tool()
@output_safe
def vol_mftscan(image: str) -> dict:
    """Scan for MFT entries in memory — finds files not in the live filesystem."""
    return _vol(image, "windows.mftscan", timeout=VOL_TIMEOUT)


@mcp.tool()
@output_safe
def vol_memmap(image: str, pid: int, dump: bool = False, output_dir: Optional[str] = None) -> dict:
    """
    Show or dump memory map for a process.
    Set dump=True with output_dir to write process memory to disk.
    """
    extra = _pid_extra(pid)
    if dump and output_dir:
        extra += ["--dump"]
    return _vol(image, "windows.memmap", extra, output_dir=output_dir if dump else None)


# ── Execution artifacts ───────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_amcache(image: str) -> dict:
    """Extract Amcache.hve entries from a running system — program execution evidence."""
    return _vol(image, "windows.amcache")


@mcp.tool()
@output_safe
def vol_shimcachemem(image: str) -> dict:
    """Extract AppCompatCache (ShimCache) from memory — execution evidence with timestamps."""
    return _vol(image, "windows.shimcachemem")


# ── Credentials ────────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_hashdump(image: str) -> dict:
    """Dump NTLM password hashes from SAM and SYSTEM hives in memory."""
    return _vol(image, "windows.hashdump")


@mcp.tool()
@output_safe
def vol_cachedump(image: str) -> dict:
    """Extract cached domain credentials (DCC2 hashes) from memory."""
    return _vol(image, "windows.cachedump")


@mcp.tool()
@output_safe
def vol_lsadump(image: str) -> dict:
    """Dump LSA secrets from memory (service account passwords, auto-logon creds)."""
    return _vol(image, "windows.lsadump")


# ── Misc Windows ──────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_mutantscan(image: str) -> dict:
    """Scan for mutex objects — malware often uses mutexes to prevent reinfection."""
    return _vol(image, "windows.mutantscan")


@mcp.tool()
@output_safe
def vol_symlinkscan(image: str) -> dict:
    """Scan for symbolic link objects in kernel pool memory."""
    return _vol(image, "windows.symlinkscan")


@mcp.tool()
@output_safe
def vol_thrdscan(image: str) -> dict:
    """Scan for ETHREAD objects — thread-level investigation."""
    return _vol(image, "windows.thrdscan")


@mcp.tool()
@output_safe
def vol_timeliner(image: str, output_dir: Optional[str] = None) -> dict:
    """
    Generate a unified timeline of all memory artifacts.
    Produces a bodyfile suitable for mactime.
    """
    return _vol(image, "timeliner", output_dir=output_dir, timeout=VOL_TIMEOUT)


@mcp.tool()
@output_safe
def vol_yarascan(image: str, yara_rules: str, pid: Optional[int] = None) -> dict:
    """YARA scan across all process memory regions."""
    extra = ["--yara-rules", yara_rules]
    extra += _pid_extra(pid)
    return _vol(image, "windows.yarascan", extra, timeout=VOL_TIMEOUT)


# ── Linux plugins ─────────────────────────────────────────────────────────────

@mcp.tool()
@output_safe
def vol_linux_pslist(image: str) -> dict:
    """List Linux processes."""
    return _vol(image, "linux.pslist")


@mcp.tool()
@output_safe
def vol_linux_psscan(image: str) -> dict:
    """Scan for Linux TASK_STRUCT objects."""
    return _vol(image, "linux.psscan")


@mcp.tool()
@output_safe
def vol_linux_pstree(image: str) -> dict:
    """Linux process hierarchy."""
    return _vol(image, "linux.pstree")


@mcp.tool()
@output_safe
def vol_linux_netstat(image: str) -> dict:
    """Linux network connections from memory."""
    return _vol(image, "linux.ip")


@mcp.tool()
@output_safe
def vol_linux_lsof(image: str, pid: Optional[int] = None) -> dict:
    """List open files per Linux process."""
    extra = _pid_extra(pid)
    return _vol(image, "linux.lsof", extra)


@mcp.tool()
@output_safe
def vol_linux_malfind(image: str) -> dict:
    """Find suspicious memory regions in Linux processes."""
    return _vol(image, "linux.malfind")


@mcp.tool()
@output_safe
def vol_linux_lsmod(image: str) -> dict:
    """List loaded Linux kernel modules."""
    return _vol(image, "linux.lsmod")


@mcp.tool()
@output_safe
def vol_linux_check_modules(image: str) -> dict:
    """Detect hidden kernel modules on Linux — compares sysfs vs module list."""
    return _vol(image, "linux.check_modules")
