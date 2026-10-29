"""Background jobs for long-running forensic tools (plaso, carvers).

A full log2timeline pass or bulk_extractor scan can hold a synchronous MCP
call open for hours, serializing the whole investigation. These tools launch
the SAME commands (identical argv, built by the sync tools' own command
builders — no arbitrary execution surface) as detached jobs supervised by
`tools/jobs_runner.py`, then let the agent keep working:

    job.job_start_bulk_extractor(...)  →  {"job_id": ...}
    job.job_status(job_id)             →  running / finished, log tail
    job.job_collect(job_id)            →  capped output + exit code (traced)

Job state lives entirely on disk under <analysis>/jobs/<job_id>/ (meta.json,
pid, stdout.log, exit_code), so jobs survive MCP server restarts and
job_list/job_status never depend on in-memory state.

Notes:
- Not supported in remote-SIFT mode — run the synchronous tools instead.
- needs_sudo jobs (carvers) assume the same NOPASSWD sudo as executor.run.
- Trace entries are written at start and collect.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Optional

from fastmcp import FastMCP

from core import output_safe, VOL_TIMEOUT, PLASO_TIMEOUT, scale_timeout
from core.executor import _apply_line_cap
from core.paths import (OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES, MIN_THROUGHPUT_MB_S, assert_output_safe,
                        unique_output_stem)
from tools import carving as _carving
from tools import plaso as _plaso
from tools import hayabusa as _hayabusa
from tools import volatility as _volatility
from core import memory_batch as _memory_batch

mcp = FastMCP("jobs")

_JOB_SEQ = itertools.count()

# Repo root so `python -m tools.jobs_runner` resolves regardless of case cwd.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _image_extract_cmd(manifest: str, output_dir: str = "") -> list:
    """The batch image extract's argv: the stdlib worker over the manifest
    job_start_image_extract wrote (output_dir is the folder the disk guard
    watches)."""
    return [sys.executable, os.path.join(_REPO_ROOT, "tools", "image_extract_runner.py"), manifest]


def _manifest_seconds(params: dict) -> int:
    """The batch extract's budget hint, scaled with the bytes its manifest
    copies."""
    try:
        with open(params["manifest"], encoding="utf-8") as f:
            return int(json.load(f).get("seconds") or VOL_TIMEOUT)
    except (OSError, ValueError, KeyError, TypeError):
        return VOL_TIMEOUT


# Closed registry: kind → (command builder, needs_sudo, base timeout for the
# informational budget hint, or a function of the job's parameters that
# gives it). Builders are the exact functions the sync tools use, so a
# background job runs an identical argv.
_JOB_BUILDERS: dict[str, tuple[Callable[..., list], bool, int | Callable[[dict], int]]] = {
    "plaso_timeline":         (_plaso._timeline_cmd, False, PLASO_TIMEOUT),
    "plaso_targeted":         (_plaso._targeted_cmd, False, VOL_TIMEOUT * 12),
    "bulk_extractor":         (_carving._bulk_extractor_cmd, True, VOL_TIMEOUT * 12),
    "bulk_extractor_unalloc": (_carving._bulk_extractor_unalloc_cmd, True, VOL_TIMEOUT * 6),
    "foremost":               (_carving._foremost_cmd, True, VOL_TIMEOUT * 12),
    "scalpel":                (_carving._scalpel_cmd, True, VOL_TIMEOUT * 12),
    "hayabusa_triage":        (_hayabusa._cmd, False, VOL_TIMEOUT * 6),
    "image_extract":          (_image_extract_cmd, False, _manifest_seconds),
    "memory_info":            (_volatility._info_cmd, False, VOL_TIMEOUT),
    "memory_batch":           (_memory_batch.runner_cmd, False, VOL_TIMEOUT * 12),
}


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by root (sudo child)


def _jobs_root() -> Optional[Path]:
    """<analysis dir>/jobs when the execution log is configured, else
    ./analysis/jobs when cwd looks like a case directory, else None."""
    try:
        from core.execution_log import log
        trace_dir = log.trace_dir()
    except Exception:
        trace_dir = None
    if trace_dir:
        base = Path(trace_dir) / "jobs"
    elif os.path.isdir("analysis"):
        base = Path(os.getcwd()) / "analysis" / "jobs"
    else:
        return None
    assert_output_safe(str(base))
    return base


def _load_job(job_id: str) -> tuple[Optional[Path], Optional[dict], Optional[dict]]:
    """Returns (job_dir, meta, error_dict). Exactly one of meta/error is set."""
    root = _jobs_root()
    if root is None:
        return None, None, {"success": False,
                            "error": "No case context — start the execution log "
                                     "first (misc.start_execution_log)."}
    # job_id is used as a directory name — reject any path separators.
    if not job_id or "/" in job_id or job_id in (".", ".."):
        return None, None, {"success": False, "error": f"Invalid job_id: {job_id!r}"}
    job_dir = root / job_id
    meta_path = job_dir / "meta.json"
    if not meta_path.is_file():
        return None, None, {"success": False,
                            "error": f"Unknown job_id: {job_id} (no {meta_path})"}
    try:
        with open(meta_path) as f:
            return job_dir, json.load(f), None
    except (OSError, json.JSONDecodeError) as e:
        return None, None, {"success": False,
                            "error": f"Unreadable job metadata for {job_id}: {e}"}


def _find_duplicate_job(root: Path, argv: list) -> Optional[tuple]:
    """(meta, state) of an existing job with the identical argv that is
    running or finished cleanly, else None."""
    for meta_path in sorted(root.glob("*/meta.json")):
        try:
            with open(meta_path) as f:
                m = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if m.get("argv") != argv:
            continue
        state = _job_state(meta_path.parent, m)
        if state in ("running", "finished"):
            return m, state
    return None


def _mnt_reads(root: Path, argv: list, params: dict) -> dict:
    """{"mnt_paths", "raw_views"} a job reads (core.raw_views.views_named)."""
    texts = [str(a) for a in argv]
    manifest = str(params.get("manifest") or "")
    if manifest:
        try:
            texts.append(Path(manifest).read_text(encoding="utf-8"))
        except OSError:
            pass
    try:
        from core.execution_log import log as _elog
        case = _elog.case_dir() or str(root.parent.parent)
        from core.raw_views import views_named
        return views_named(case, texts)
    except Exception:  # noqa: BLE001 - nothing recorded, nothing spared
        return {}


def _start_job(kind: str, params: dict) -> dict:
    from core import remote as _remote
    if _remote.is_enabled():
        return {
            "success": False,
            "remote_mode": True,
            "error": "Background jobs are not supported in remote-SIFT mode — "
                     "run the synchronous tool instead.",
        }

    builder, needs_sudo, base_timeout = _JOB_BUILDERS[kind]
    argv = builder(**params)

    # Solution-material gate: jobs_runner Popens the stored argv OUTSIDE
    # core.executor, so the executor's scan never sees it — enforce here,
    # before the argv is persisted to meta.json.
    from core.paths import (SOLUTION_BLOCK_MESSAGE,
                            contains_solution_reference, is_solution_path)
    blocked = next((a for a in argv if is_solution_path(a)
                    or contains_solution_reference(a)), None)
    if blocked:
        return {"success": False,
                "error": f"Blocked argument '{blocked[:200]}': "
                         f"{SOLUTION_BLOCK_MESSAGE}"}
    # A job that runs as root cannot read a FUSE mount of this user (a raw
    # view): refused here, as the executor refuses the synchronous tool.
    if needs_sudo:
        from core.raw_views import sudo_refusal
        refusal = sudo_refusal(argv)
        if refusal:
            return refusal

    root = _jobs_root()
    if root is None:
        return {"success": False,
                "error": "No case context — start the execution log first "
                         "(misc.start_execution_log)."}

    # Dedup: an identical argv that is already running or already succeeded
    # is re-issued surprisingly often (re-planned foundation batches). Point
    # the agent at the existing job instead of burning hours re-running it.
    # Failed/aborted jobs never dedup — a retry is legitimate there.
    dup = _find_duplicate_job(root, argv)
    if dup:
        dmeta, dstate = dup
        # The call starts nothing new but stands for the job it names: its
        # record is that job's start, so it counts by that job's outcome
        # (core.coverage_ledger.resolved_entry), never as a read of its own.
        from core.execution_log import log
        dup_call_id = log.record_tool_call(
            cmd=f"[background job {dmeta['job_id']}] {dmeta.get('cmd', '')}",
            success=True, truncated=False, retries=0, exit_code=0, elapsed_seconds=0.0,
            stdout_excerpt=f"[background job {dstate}, started earlier: {dmeta['job_id']}]")
        return {
            "_atlas_call_id": dup_call_id,
            "success": True, "deduplicated": True,
            "job_id": dmeta["job_id"], "kind": kind,
            "cmd": dmeta.get("cmd"), "state": dstate,
            "batch_id": dmeta.get("batch_id", ""),
            "stdout_log": str(root / dmeta["job_id"] / "stdout.log"),
            "hint": ("An identical job is already running — "
                     "job.job_wait(job_id) for it."
                     if dstate == "running" else
                     "An identical job already finished — "
                     "job.job_collect(job_id) returns its result. Use a "
                     "different output_dir to force a re-run."),
        }

    # Disk-space fail-safe: never launch a hours-long carve/timeline onto a
    # volume that is already low — it would fill the disk and take down the run.
    # The jobs_runner watchdog then aborts the job if space runs out mid-carve.
    from core import diskguard as _diskguard
    _disk = _diskguard.check(params.get("output_dir")
                             or params.get("storage_file") or str(root))
    if not _disk["ok"]:
        return {"success": False, "disk_low": True,
                "error": _diskguard.message(_disk, f"{kind} background job")}

    job_id = (f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}"
              f"_{kind}_{os.getpid()}_{next(_JOB_SEQ)}")
    job_dir = root / job_id
    job_dir.mkdir(parents=True, exist_ok=False)

    # Informational only — detached jobs have no hard timeout; job_status
    # compares elapsed time against this to flag over-budget jobs.
    input_path = (params.get("evidence_path") or params.get("image_path")
                  or params.get("unallocated_raw"))
    timeout_hint = (base_timeout(params) if callable(base_timeout)
                    else scale_timeout(base_timeout, input_path))

    # Jobs started under the same DAIR work-order batch share a batch_id so
    # job_wait_all(batch_id=...) can block on the whole foundation batch.
    try:
        from core.execution_log import log as _elog
        batch_id = (f"dair-{_elog._last_dair_cid}"
                    if _elog._last_dair_cid else "")
    except Exception:
        batch_id = ""

    meta = {
        "job_id": job_id,
        "kind": kind,
        "cmd": " ".join(argv),
        "argv": argv,
        "needs_sudo": needs_sudo,
        "params": params,
        "batch_id": batch_id,
        "cwd": os.getcwd(),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "started_ts": time.time(),
        "timeout_hint_seconds": timeout_hint,
        # What it reads under the case's mnt/ (its command and its manifest):
        # the run-end teardown spares those mounts while the job runs, and a
        # raw view whose daemon changes under it fails the job.
        **_mnt_reads(root, argv, params),
    }
    with open(job_dir / "meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    proc = subprocess.Popen(
        [sys.executable, "-m", "tools.jobs_runner", str(job_dir)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        cwd=_REPO_ROOT,
    )

    # Trace the start. Consistent with _log_tool's audit-integrity stance:
    # nothing has run yet, so a trace failure fails the start (after
    # terminating the supervisor we just spawned).
    try:
        from core.execution_log import log
        start_call_id = log.record_tool_call(
            cmd=f"[background job {job_id}] {meta['cmd']}",
            success=True,
            truncated=False,
            retries=0,
            exit_code=0,
            elapsed_seconds=0.0,
            stdout_excerpt=f"[background job started: {job_id}]",
        )
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            pass
        raise

    # Its start time, so a cancel hours later can tell the supervisor from
    # a process that was given the same pid after it exited. Merged into the
    # file: a quick job's runner may already have recorded its outcome.
    from tools.jobs_runner import merge_meta
    ident = _proc_identity(proc.pid)
    started = {"supervisor_pid": proc.pid, "supervisor_start": ident[0] if ident else "",
               "start_call_id": start_call_id}
    meta.update(started)
    merge_meta(str(job_dir), started, base=meta)

    return {
        # The record this result stands for: the job's start, which reads
        # nothing until the job's outcome says so.
        "_atlas_call_id": start_call_id,
        "success": True,
        "job_id": job_id,
        "kind": kind,
        "cmd": meta["cmd"],
        "batch_id": batch_id,
        "supervisor_pid": proc.pid,
        "stdout_log": str(job_dir / "stdout.log"),
        "timeout_hint_seconds": timeout_hint,
        "hint": "Keep investigating other leads, then job.job_wait(job_id) "
                "(or job.job_wait_all() for the whole batch) to block until "
                "done and collect — cheaper than polling job_status.",
    }


@mcp.tool()
@output_safe
def job_start_plaso_timeline(
    evidence_path: str,
    storage_file: str,
    parsers: Optional[str] = None,
    timezone: str = "UTC",
) -> dict:
    """
    Start a FULL plaso timeline (log2timeline) as a detached background job.
    Same command as plaso.plaso_create_timeline, but returns immediately with
    a job_id instead of blocking the session for up to hours on large images.
    Poll with job_status; retrieve results with job_collect.
    """
    return _start_job("plaso_timeline", {
        "evidence_path": evidence_path, "storage_file": storage_file,
        "parsers": parsers, "timezone": timezone,
    })


@mcp.tool()
@output_safe
def job_start_plaso_targeted(
    evidence_path: str,
    storage_file: str,
    artifact_filters: str,
    timezone: str = "UTC",
) -> dict:
    """
    Start a targeted plaso timeline (artifact filters) as a background job.
    Same command as plaso.plaso_create_targeted. See job_start_plaso_timeline.
    """
    return _start_job("plaso_targeted", {
        "evidence_path": evidence_path, "storage_file": storage_file,
        "artifact_filters": artifact_filters, "timezone": timezone,
    })


@mcp.tool()
@output_safe
def job_start_bulk_extractor(
    image_path: str,
    output_dir: str,
    threads: int = 4,
    scanners: Optional[str] = None,
) -> dict:
    """
    Start a bulk_extractor feature scan as a detached background job.
    Same command as carve.bulk_extractor_scan — see that tool for parameters.
    Poll with job_status; retrieve results with job_collect.
    """
    return _start_job("bulk_extractor", {
        "image_path": image_path, "output_dir": output_dir,
        "threads": threads, "scanners": scanners,
    })


@mcp.tool()
@output_safe
def job_start_foremost_carve(
    image_path: str,
    output_dir: str,
    file_types: Optional[str] = None,
    config_file: Optional[str] = None,
) -> dict:
    """
    Start a foremost signature carve as a detached background job.
    Same command as carve.foremost_carve — see that tool for parameters.
    """
    return _start_job("foremost", {
        "image_path": image_path, "output_dir": output_dir,
        "file_types": file_types, "config_file": config_file,
    })


@mcp.tool()
@output_safe
def job_start_scalpel_carve(
    image_path: str,
    output_dir: str,
    config_file: str = "",
) -> dict:
    """
    Start a scalpel signature carve as a detached background job.
    Same command as carve.scalpel_carve — see that tool for parameters;
    config_file omitted means Atlas's own configuration.
    """
    config_file = config_file or _carving.SCALPEL_CONF
    refused = _carving._scalpel_conf_refusal(config_file)
    if refused:
        return refused
    return _start_job("scalpel", {
        "image_path": image_path, "output_dir": output_dir,
        "config_file": config_file,
    })


@mcp.tool()
@output_safe
def job_start_hayabusa(
    evtx_path: str,
    output_dir: str,
    min_level: str = "informational",
) -> dict:
    """
    Run hayabusa.triage as a detached background job, for event-log sets
    too large to wait on. It writes the same JSONL as the direct call; once
    job_collect reports it done, summarise it with hayabusa.summary.
    """
    if _hayabusa._binary() is None or _hayabusa._rules() is None:
        return {"success": False, "error": _hayabusa._NOT_INSTALLED}
    refused = _hayabusa._level_error(min_level)
    if refused:
        return refused
    assert_output_safe(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(
        output_dir, f"hayabusa_{unique_output_stem(evtx_path)}.jsonl")
    result = _start_job("hayabusa_triage", {
        "evtx_path": evtx_path, "output_path": output_path,
        "min_level": min_level,
    })
    if result.get("success"):
        result["output_path"] = output_path
        result["hint"] = (result.get("hint", "") +
                          " Then hayabusa.summary(hayabusa_jsonl_path=output_path).")
    return result


@mcp.tool()
@output_safe
def job_start_image_extract(images: list[str] | str, paths: list[str] | str, dest: str = "") -> dict:
    """
    Copy files or folders out of several disk images as one background job,
    so that one parser call over the copies reads them all.
    images: image paths or host labels, or "all" for every disk image of the case.
    paths: paths inside the volume, the same for every image; a glob matches
        across folders (Users/*/NTUSER.DAT), a path ending in "/" copies that folder.
    dest: the folder for the copies, one subfolder per image (a new folder
        under analysis/extracted when empty).
    The contents index resolves every image and path; what it does not list
    is returned in "unmatched". job.job_wait(job_id) then gives the folder,
    the number copied and each failure.
    """
    from core import contents_index as ci
    from core.paths import active_case_dir
    if not ci.extract_job_on():
        return {"success": False, "error": "The batch image extract is off in this run: "
                                           + ci.handle_clause() + "."}
    case = active_case_dir()
    jobs_root = _jobs_root()
    if not case or jobs_root is None:
        return {"success": False, "error": "No case context — start the execution log first "
                                           "(misc.start_execution_log)."}
    croot = Path(case)
    specs = [images] if isinstance(images, str) else [str(i) for i in images or []]
    pats = [paths] if isinstance(paths, str) else [str(p) for p in paths or []]
    pats = [p for p in pats if p.strip().strip("/\\")]
    unmatched: list[str] = []
    if [x.strip().casefold() for x in specs] == ["all"]:
        chosen = ci._case_images(croot)
    else:
        chosen = []
        for spec in specs:
            img, why = ci._match_image(croot, spec)
            if img is None:
                unmatched.append(why)
            elif img not in chosen:
                chosen.append(img)
    if not chosen or not pats:
        return {"success": False, "unmatched": unmatched,
                "error": "Name at least one image of the case and one path inside it."}
    from tools.sleuthkit import _metadata_timeout, _tsk_readable
    listed = {i["image"] for i in ci.listed_images(case)}
    stems = [Path(i["rel"]).stem for i in chosen]
    items: list[dict] = []
    seen: set[int] = set()
    for img, stem in zip(chosen, stems):
        device, refusal = _tsk_readable(img["abs"])
        if refusal:
            unmatched.append(f"{img['rel']}: {refusal.get('error')}")
            continue
        sub = stem if stems.count(stem) == 1 else img["rel"].replace("/", "_")
        for pat in pats:
            rows = ci.entries_matching(case, img["rel"], pat)
            if not rows:
                unmatched.append(f"{img['rel']}: {pat}: " + ("no entry of its listing matches" if img["rel"] in listed
                                                             else "the image is not listed in the contents index"))
            for r in rows:
                if r["entry_id"] in seen:
                    continue
                seen.add(r["entry_id"])
                # A file already copied out of the image (a handle read, an
                # earlier job) is copied from that copy, not read again.
                reuse = None if r["is_dir"] else ci.reusable_copy(case, r["entry_id"], r["size"])
                items.append({"reuse": str(croot / reuse["copy_path"]) if reuse else "","entry_id": r["entry_id"], "image": img["rel"], "path": r["path"], "sub": sub,
                              "device": device, "offset": r["volume"], "inode": str(r["inode"]),
                              "is_dir": r["is_dir"], "size": r["size"],
                              # The per-call deadline of the synchronous tool doing the same copy.
                              "timeout": (scale_timeout(VOL_TIMEOUT * 3, device) if r["is_dir"]
                                          else _metadata_timeout(device))})
    if not items:
        return {"success": False, "unmatched": unmatched,
                "error": "No path matched an entry of the named images; tsk.index_find(host, pattern) "
                         "lists what each holds."}
    key = hashlib.sha256(json.dumps([[i["entry_id"] for i in items], dest]).encode()).hexdigest()[:12]
    out_dir = Path(dest) if dest and os.path.isabs(dest) else croot / (dest or f"{ci.EXTRACT_ROOT}/batch-{key}")
    assert_output_safe(str(out_dir))
    for i in items:
        i["dest"] = str(out_dir / i.pop("sub") / i["path"])
    total = sum(int(i["size"] or 0) for i in items)
    mdir = jobs_root / "manifests"
    mdir.mkdir(parents=True, exist_ok=True)
    manifest = mdir / f"image_extract_{key}.json"
    manifest.write_text(json.dumps({
        "items": items, "result": str(mdir / f"image_extract_{key}.result.json"),
        "seconds": max(VOL_TIMEOUT, math.ceil(total / (max(MIN_THROUGHPUT_MB_S, 1) * 1_048_576)))},
        indent=1), encoding="utf-8")
    result = _start_job("image_extract", {"manifest": str(manifest), "output_dir": str(out_dir)})
    result["unmatched"] = unmatched
    if result.get("success"):
        result.update(folder=ci._rel(croot, out_dir), items=len(items), bytes=total,
                      hint="Keep investigating, then job.job_wait(job_id); one parser call over the "
                           "folder then reads every copy of its type.")
    return result


def _image_extract_summary(meta: dict, record: bool) -> dict:
    """The batch extract's outcome from its result file: the folder, the
    number of copies, their bytes and each failure. On the first collect
    every copy is tied to the index entry it came from, with the collect
    call as the call that made it."""
    params = meta.get("params") or {}
    try:
        with open(params["manifest"], encoding="utf-8") as f:
            manifest = json.load(f)
        with open(manifest["result"], encoding="utf-8") as f:
            done = json.load(f)["items"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        return {"copied": 0, "result_error": f"the job left no readable result: {e}"}
    from core import contents_index as ci
    from core.paths import active_case_dir
    case = active_case_dir()
    asked = {i["entry_id"]: i for i in manifest.get("items") or []}
    ok = [r for r in done if r.get("ok")]
    if record and case and ci.copy_provenance_on():
        for r in ok:
            if (asked.get(r["entry_id"]) or {}).get("is_dir"):
                # The folder and every file in it, each tied to its own entry.
                ci.record_folder_copy(case, r["dest"], int(r["entry_id"]), meta.get("collect_call_id"))
            else:
                ci.record_copy(case, r["dest"], int(r["entry_id"]), meta.get("collect_call_id"),
                               r.get("size"), r.get("sha256") or "")
    folder = str(params.get("output_dir") or "")
    rel = (lambda p: ci._rel(Path(case), p)) if case else (lambda p: p)
    subs = sorted({rel(os.path.join(folder, Path(r["dest"]).relative_to(folder).parts[0])) for r in ok
                   if folder and Path(r["dest"]).is_relative_to(folder)})
    failures = [f"{(asked.get(r['entry_id']) or {}).get('image', '?')}::"
                f"{(asked.get(r['entry_id']) or {}).get('path', '?')}: {r.get('error')}"
                for r in done if not r.get("ok")]
    return {"folder": rel(folder) if folder else "", "image_folders": subs, "copied": len(ok),
            "bytes": sum(int(r.get("size") or 0) for r in ok), "failures": failures}


def _job_state(job_dir: Path, meta: dict) -> str:
    if (job_dir / "exit_code").is_file():
        if meta.get("aborted_reason") == "cancelled":
            return "aborted"   # a cancel ends a job as it did before its outcome was recorded
        try:
            rc = int((job_dir / "exit_code").read_text().strip())
        except ValueError:
            return "failed"
        return "finished" if rc == 0 else "failed"
    pid = meta.get("supervisor_pid", 0)
    if pid and _pid_alive(pid):
        return "running"
    return "aborted"  # supervisor gone without writing an exit code


def _status_impl(job_id: str) -> dict:
    job_dir, meta, err = _load_job(job_id)
    if err:
        return err

    state = _job_state(job_dir, meta)
    elapsed = round(time.time() - meta.get("started_ts", time.time()), 1)
    hint = meta.get("timeout_hint_seconds", 0)

    tail: list[str] = []
    log_path = job_dir / "stdout.log"
    if log_path.is_file():
        try:
            with open(log_path, "rb") as f:
                f.seek(max(0, log_path.stat().st_size - 16384))
                tail = f.read().decode("utf-8", errors="replace").splitlines()[-40:]
        except OSError:
            pass

    result = {
        "success": True,
        "job_id": job_id,
        "kind": meta.get("kind"),
        "state": state,
        "elapsed_seconds": elapsed,
        "timeout_hint_seconds": hint,
        "over_budget": bool(hint) and state == "running" and elapsed > hint,
        "exit_code": meta.get("exit_code"),
        "log_tail": tail,
        "stdout_log": str(log_path),
    }
    if meta.get("aborted_reason"):
        result["aborted_reason"] = meta["aborted_reason"]
        result["aborted_detail"] = meta.get("aborted_detail")
    if state == "finished" or state == "failed":
        result["hint"] = "Run job.job_collect(job_id) to record and read the result."
    return result


@mcp.tool()
def job_status(job_id: str) -> dict:
    """
    Status of a background job: running / finished / failed / aborted,
    elapsed vs its size-scaled budget hint, and the last 40 log lines.
    """
    return _status_impl(job_id)


def _credit_collected(job_id: str, collect_call_id: int) -> None:
    """The run's coverage record learns what the collected job read: the
    evidence its start names, under the tool that started it, when the read
    rule takes the collect for a read (core.coverage_ledger: a job that
    finished and that Atlas did not stop). The start is found by the job's
    id in the trace. Best effort: the recount reaches the same answer."""
    try:
        from core.coverage_ledger import _entry_tool, observe_tool_paths
        from core.execution_log import log
        prefix = f"[background job {job_id}] "
        start = next((e for e in log._entries if str(e.get("cmd") or "").startswith(prefix)), None)
        case = log.case_dir()
        if start is None or not case:
            return
        observe_tool_paths(case, tool_name=_entry_tool(start), cmd_or_args=str(start.get("cmd") or ""),
                           success=True, result_text=json.dumps({"_atlas_call_id": collect_call_id}))
    except Exception:  # noqa: BLE001 - the recount credits it from the trace
        pass


def _collect_impl(job_id: str) -> dict:
    job_dir, meta, err = _load_job(job_id)
    if err:
        return err

    state = _job_state(job_dir, meta)
    if state == "running":
        return {"success": False, "job_id": job_id, "state": state,
                "error": "Job still running — poll job_status, collect later."}
    if state == "aborted":
        return {"success": False, "job_id": job_id, "state": state,
                "error": "Supervisor died without recording an exit code "
                         "(host reboot or manual kill). Check stdout.log: "
                         f"{job_dir / 'stdout.log'}"}

    exit_code = int(meta.get("exit_code", -1))
    log_path = job_dir / "stdout.log"

    stdout = ""
    truncated = False
    if log_path.is_file():
        size = log_path.stat().st_size
        with open(log_path, "rb") as f:
            data = f.read(OUTPUT_CAP)
        stdout = data.decode("utf-8", errors="replace")
        if size > OUTPUT_CAP:
            truncated = True
        stdout, line_truncated = _apply_line_cap(stdout, MAX_TOOL_OUTPUT_LINES)
        truncated = truncated or line_truncated

    started = meta.get("started_ts")
    finished = meta.get("finished_utc")
    elapsed = 0.0
    if started:
        try:
            end = time.mktime(time.strptime(finished, "%Y-%m-%dT%H:%M:%SZ")) \
                - time.timezone if finished else time.time()
            elapsed = round(max(0.0, end - started), 1)
        except (ValueError, TypeError):
            elapsed = 0.0

    already_collected = bool(meta.get("collected"))
    if not already_collected:
        from core.execution_log import log
        parents = [meta["start_call_id"]] if meta.get("start_call_id") else None
        cid = log.record_tool_call(
            cmd=f"[background job {job_id} collected] {meta.get('cmd', '')}",
            success=exit_code == 0,
            truncated=truncated,
            retries=0,
            exit_code=exit_code,
            elapsed_seconds=elapsed,
            stdout_excerpt=stdout,
            input_call_ids=parents,
            stdout_file=str(log_path),
        )
        meta["collected"] = True
        meta["collect_call_id"] = cid
        from tools.jobs_runner import merge_meta
        merge_meta(str(job_dir), {"collected": True, "collect_call_id": cid}, base=meta)
        _credit_collected(job_id, cid)
        # Index the FULL job log server-side (jobs_runner is a separate
        # process and must never touch the index — see core/evidence_index).
        # Best-effort: an index failure must not fail the collect.
        try:
            from core import evidence_index
            if log_path.is_file():
                with open(log_path, "r", encoding="utf-8",
                          errors="replace") as f:
                    full_text = f.read(evidence_index.MAX_INDEXED_BYTES + 1)
                evidence_index.index_output(
                    call_id=cid,
                    tool=str(meta.get("kind") or "job"),
                    text=full_text,
                    source_path=str(log_path))
        except Exception as e:
            import sys
            print(f"[Atlas WARN] job output indexing failed for {job_id}: {e}",
                  file=sys.stderr)

    result = {
        "success": exit_code == 0,
        "job_id": job_id,
        "kind": meta.get("kind"),
        "state": state,
        "exit_code": exit_code,
        "elapsed_seconds": elapsed,
        "truncated": truncated,
        "stdout": stdout,
        "stdout_file": str(log_path),
        "already_collected": already_collected,
        "_atlas_call_id": meta.get("collect_call_id"),
        "params": meta.get("params", {}),
    }
    if meta.get("kind") == "image_extract":
        result.update(_image_extract_summary(meta, record=not already_collected))
    return result


@mcp.tool()
def job_collect(job_id: str) -> dict:
    """
    Collect a finished background job: returns the capped tool output (full
    log path in stdout_file) and records the completion in the execution
    trace, linked to the job's start entry. Errors if the job is still
    running. Idempotent — re-collecting returns the result without re-logging.
    """
    return _collect_impl(job_id)


# ── Blocking waits ──────────────────────────────────────────────────────────
# job_status costs one full agent turn per poll; these block server-side so
# "wait for the foundation batch" is one call, not a poll loop.

_WAIT_POLL_START = 2.0
_WAIT_POLL_MAX = 15.0
_WAIT_TIMEOUT_CAP = 7200


def _wait_impl(job_id: str, deadline: float, collect: bool) -> dict:
    job_dir, meta, err = _load_job(job_id)
    if err:
        return err
    poll = _WAIT_POLL_START
    started = time.monotonic()
    state = _job_state(job_dir, meta)
    while state == "running" and time.monotonic() < deadline:
        time.sleep(min(poll, max(0.1, deadline - time.monotonic())))
        poll = min(poll * 1.5, _WAIT_POLL_MAX)
        state = _job_state(job_dir, meta)
    waited = round(time.monotonic() - started, 1)
    if state == "running":
        result = _status_impl(job_id)
        result.update({
            "success": False, "timed_out_wait": True,
            "waited_seconds": waited,
            "hint": ("Still running after the wait timeout — job_wait "
                     "again, keep working other leads, or job_cancel."),
        })
        return result
    result = _collect_impl(job_id) if collect else _status_impl(job_id)
    result["waited_seconds"] = waited
    return result


@mcp.tool()
def job_wait(job_id: str, timeout: int = 1800, collect: bool = True) -> dict:
    """
    Block until a background job finishes (or `timeout` seconds pass), then
    collect and return its result — one call instead of a job_status poll
    per agent turn. collect=False returns only the final status. On wait
    timeout the job keeps running; wait again or keep working.
    """
    deadline = time.monotonic() + max(1, min(int(timeout), _WAIT_TIMEOUT_CAP))
    return _wait_impl(job_id, deadline, collect)


@mcp.tool()
def job_wait_all(job_ids: Optional[list] = None,
                 batch_id: Optional[str] = None,
                 timeout: int = 1800, collect: bool = True) -> dict:
    """
    Block until a whole set of background jobs finishes, then collect each.
    Selection: explicit job_ids > batch_id (jobs started under the same
    DAIR batch share one — it is in every job_start_* result) > every job
    currently running. Returns per-job results plus a summary; on timeout,
    still-running job_ids are listed and keep running.
    """
    root = _jobs_root()
    if root is None:
        return {"success": False,
                "error": "No case context — start the execution log first "
                         "(misc.start_execution_log)."}
    targets: list[str] = []
    if job_ids:
        targets = [str(j) for j in job_ids]
    else:
        for meta_path in sorted(root.glob("*/meta.json")):
            try:
                with open(meta_path) as f:
                    m = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            if batch_id is not None:
                if m.get("batch_id") == batch_id:
                    targets.append(m["job_id"])
            elif _job_state(meta_path.parent, m) == "running":
                targets.append(m["job_id"])
    if not targets:
        return {"success": True, "jobs": {}, "finished": [], "timed_out": [],
                "note": ("no matching jobs — nothing running"
                         if batch_id is None
                         else f"no jobs with batch_id {batch_id!r}")}

    deadline = time.monotonic() + max(1, min(int(timeout), _WAIT_TIMEOUT_CAP))
    results: dict[str, dict] = {}
    for job_id in targets:
        results[job_id] = _wait_impl(job_id, deadline, collect)
    timed_out = [j for j, r in results.items() if r.get("timed_out_wait")]
    return {
        "success": not timed_out,
        "jobs": results,
        "finished": [j for j in targets if j not in timed_out],
        "timed_out": timed_out,
        "hint": ("" if not timed_out else
                 "Timed-out jobs keep running — job_wait them individually "
                 "or keep working and collect later."),
    }


def _proc_identity(pid: int) -> tuple[str, list[str]] | None:
    """(start time in clock ticks since boot, argv) of a live process, read
    from /proc; None when it cannot be read."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        start = stat.rsplit(")", 1)[1].split()[19]
        raw = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", errors="replace")
        return start, [a for a in raw.split("\0") if a]
    except (OSError, IndexError):
        return None


def _supervisor_mismatch(job_dir: Path, meta: dict) -> str:
    """Why the job's recorded supervisor may not be signalled, "" when it
    is verified: a pid read back from a file hours later must still be
    the supervisor this job started, leading its own process group, not
    this server's group, running this job's runner command and (when
    recorded) started at the recorded time."""
    pid = meta.get("supervisor_pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return "the job records no supervisor process"
    try:
        if pid in (os.getpgrp(), os.getsid(0)):
            return "the recorded supervisor is in this server's own process group"
        if os.getpgid(pid) != pid:
            return "the recorded pid no longer leads its own process group"
    except ProcessLookupError:
        return "the recorded supervisor is gone"
    except OSError as exc:
        return f"the recorded supervisor cannot be inspected ({exc})"
    ident = _proc_identity(pid)
    if ident is None:
        return "the recorded supervisor's identity cannot be read from /proc"
    start, argv = ident
    if argv[1:] != ["-m", "tools.jobs_runner", str(job_dir)]:
        return "the recorded pid now runs another command"
    if meta.get("supervisor_start") and start != meta["supervisor_start"]:
        return "the recorded pid now belongs to a process started at another time"
    return ""


@mcp.tool()
def job_cancel(job_id: str) -> dict:
    """
    Cancel a running background job: SIGTERM to the process group of the
    job's supervisor, after checking that the recorded pid is still that
    supervisor. The supervisor stops the tool and everything it started
    and records the outcome; nothing is escalated with sudo here.
    """
    job_dir, meta, err = _load_job(job_id)
    if err:
        return err

    state = _job_state(job_dir, meta)
    if state != "running":
        return {"success": False, "job_id": job_id, "state": state,
                "error": f"Job is not running (state: {state})."}

    why = _supervisor_mismatch(job_dir, meta)
    if why:
        return {"success": False, "job_id": job_id,
                "error": f"Cancel refused: {why}; nothing was signalled."}
    pgid = meta["supervisor_pid"]
    killed_via = "killpg"
    try:
        os.killpg(pgid, signal.SIGTERM)
    except PermissionError:
        return {"success": False, "job_id": job_id,
                "error": ("Cancel failed: no process of the job's group accepts a signal from "
                          "this user (its command runs as root); nothing was escalated.")}
    except ProcessLookupError:
        return {"success": False, "job_id": job_id,
                "error": "Process group already gone."}

    try:
        from core.execution_log import log
        log.record_tool_call(
            cmd=f"[background job {job_id} cancelled] {meta.get('cmd', '')}",
            success=True,
            truncated=False,
            retries=0,
            exit_code=-15,
            stdout_excerpt=f"[job cancelled via {killed_via}]",
            input_call_ids=[meta["start_call_id"]] if meta.get("start_call_id") else None,
        )
    except Exception:
        pass  # cancellation succeeded; trace failure shouldn't mask that

    return {"success": True, "job_id": job_id, "cancelled_via": killed_via,
            "note": ("SIGTERM sent to the job's supervisor; it stops the tool and "
                     "everything it started and records the outcome.")}


@mcp.tool()
def job_list() -> dict:
    """List all background jobs for the current case with their states."""
    root = _jobs_root()
    if root is None:
        return {"success": False,
                "error": "No case context — start the execution log first "
                         "(misc.start_execution_log)."}
    jobs = []
    if root.is_dir():
        for entry in sorted(root.iterdir()):
            meta_path = entry / "meta.json"
            if not meta_path.is_file():
                continue
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
            except (OSError, json.JSONDecodeError):
                jobs.append({"job_id": entry.name, "state": "unreadable"})
                continue
            jobs.append({
                "job_id": meta.get("job_id", entry.name),
                "kind": meta.get("kind"),
                "state": _job_state(entry, meta),
                "started_utc": meta.get("started_utc"),
                "exit_code": meta.get("exit_code"),
                "collected": bool(meta.get("collected")),
            })
    return {"success": True, "jobs": jobs, "count": len(jobs)}
