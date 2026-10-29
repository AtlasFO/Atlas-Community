"""The code survey of each evidence item (ATLAS_EVIDENCE_DISPOSITION, step
2): what the item holds, as the input of its triage, never a judgement of
what matters. Format-wide samples only:

- a disk image: its host's line of the listing digest and the item's class
  histogram (files per content class, with the empty ones);
- a collected tree or a loose file: the class histogram, and for a log its
  record count and first and last record;
- an archive: the class histogram of its members (zip and tar, read with
  the standard library; other formats by size only);
- a memory image: one info-class header (OS build, system time), run as a
  background job, never a serial process listing;
- a capture: its size.

Cached per item in .atlas/evidence_survey.json, keyed by what the survey
read (the listing generation, the file's size and mtime, the job's state).
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Optional

SURVEY_NAME = "evidence_survey.json"
# The longest survey text one triage call reads (its 2 to 4 KB input).
MAX_SURVEY_CHARS = 3500
_LINE_CHARS = 300
# A text file up to this size is counted line by line; a larger one is
# estimated (the survey never reads a multi-gigabyte log whole).
_COUNT_BYTES = 64 << 20


def _cache_path(case_dir) -> Path:
    return Path(case_dir).resolve() / ".atlas" / SURVEY_NAME


def _load(case_dir) -> dict[str, Any]:
    try:
        data = json.loads(_cache_path(case_dir).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(case_dir, data: dict[str, Any]) -> None:
    p = _cache_path(case_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    os.replace(tmp, p)


def _abs(case_dir, rel: str) -> Path:
    return Path(case_dir).resolve() / rel


def _stat_key(path: Path) -> str:
    try:
        st = path.stat()
        return f"{st.st_size}:{st.st_mtime_ns}"
    except OSError:
        return "missing"


def _histogram(ledger: dict[str, Any], item_id: str) -> list[str]:
    rows = sorted(((c["label"], c["files"], c.get("empty", 0)) for c in (ledger.get("classes") or {}).values()
                   if isinstance(c, dict) and c.get("item") == item_id), key=lambda r: (-r[1], r[0]))
    return [f"- {label}: {n:,} files" + (f" ({e:,} appear empty)" if e else "") for label, n, e in rows]


def _log_sample(path: Path) -> list[str]:
    """Record count and first and last record of a log file."""
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        from core import evtx_reader as R
        if not R.available():
            return ["event log: the reader is not installed here"]
        counts = R.chunk_counts(path)
        if counts is None:
            return ["event log: the chunk headers do not read"]
        first = last = None
        for _ci, _ri, xml, stamp in R.iter_from(path, ""):
            if xml is not None:
                first = (stamp, xml)
                break
        tail_chunk = max(0, len(counts) - 1)
        for _ci, _ri, xml, stamp in R.iter_from(path, f"{tail_chunk}:0"):
            if xml is not None:
                last = (stamp, xml)
        out = [f"event log: {sum(counts):,} records in {len(counts)} chunks"]
        for label, rec in (("first", first), ("last", last)):
            if rec:
                out.append(f"{label} record at {rec[0]}: {' '.join(rec[1].split())[:_LINE_CHARS]}")
        return out
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(64 * 1024)
            fh.seek(max(0, size - 64 * 1024))
            tail = fh.read()
    except OSError:
        return []
    if b"\0" in head[:4096]:
        return [f"binary file, {size:,} bytes"]
    lines = [x for x in head.decode("utf-8", "replace").splitlines() if x.strip()]
    last = [x for x in tail.decode("utf-8", "replace").splitlines() if x.strip()]
    if size <= _COUNT_BYTES:
        with open(path, "rb") as fh:
            count = sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(1 << 20), b""))
        out = [f"text: {count:,} lines, {size:,} bytes"]
    else:
        # A large log is not read whole for a survey: its lines are
        # estimated from the first block's line length.
        per = max(1, len(head) // max(1, head.count(b"\n")))
        out = [f"text: about {size // per:,} lines (estimated from its size), {size:,} bytes"]
    if lines:
        out.append(f"first line: {lines[0][:_LINE_CHARS]}")
        if len(lines) > 1:
            out.append(f"second line: {lines[1][:_LINE_CHARS]}")
    if last:
        out.append(f"last line: {last[-1][:_LINE_CHARS]}")
    return out


def _archive_histogram(path: Path) -> list[str]:
    import tarfile
    import zipfile
    from core.artifact_value import artifact_score
    names: list[tuple[str, int]] = []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                names = [(i.filename, i.file_size) for i in z.infolist() if not i.is_dir()]
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                names = [(m.name, m.size) for m in t.getmembers() if m.isfile()]
        else:
            return [f"archive of {path.stat().st_size:,} bytes; its members are listed when it is opened"]
    except (OSError, zipfile.BadZipFile, tarfile.TarError) as e:
        return [f"archive does not open: {type(e).__name__}"]
    hist: dict[str, int] = {}
    for name, size in names:
        _s, why = artifact_score(name, size)
        label = why.replace(" (appears empty)", "") if why else "other files"
        hist[label] = hist.get(label, 0) + 1
    return [f"archive: {len(names):,} files"] + [f"- {k}: {v:,} files" for k, v in
                                                 sorted(hist.items(), key=lambda kv: (-kv[1], kv[0]))]


# At most this many memory header passes run at once: each reads a whole
# memory image, so more in parallel only contend for the same disk (a guard
# per resource, never a cap on the run); the next starts on a later pass.
MAX_MEMORY_HEADERS = 2
_START_LOCK = threading.Lock()


def _running_headers(cache: dict[str, Any]) -> int:
    from tools import jobs as J
    n = 0
    for entry in cache.values():
        if isinstance(entry, dict) and entry.get("state") == "running" and entry.get("job_id"):
            job_dir, meta, err = J._load_job(str(entry["job_id"]))
            if not err and job_dir is not None and J._job_state(job_dir, meta or {}) == "running":
                n += 1
    return n


def _batch_on() -> bool:
    try:
        from core.memory_batch import batch_on
        return batch_on()
    except Exception:  # noqa: BLE001
        return False


def _batch_header(case_dir, ledger: dict[str, Any], item: dict[str, Any]) -> tuple[list[str], str, str]:
    """The info header from the case's memory batch (core.memory_batch),
    started once for every memory item: read from the result store when the
    batch has run windows.info on this image. (lines, job id, state)."""
    from core import memory_batch as MB
    from core import vol_cache as V
    images = [str(_abs(case_dir, i["path"])) for i in (ledger.get("items") or {}).values()
              if isinstance(i, dict) and i.get("kind") == "memory"]
    image = str(_abs(case_dir, item["path"]))
    try:
        r = MB.ensure(case_dir, images or [image])
    except Exception as e:  # noqa: BLE001
        return [f"memory header not started: {type(e).__name__}"], "", "unstarted"
    job = str(r.get("job_id") or "")
    if not job:
        return [f"memory header not started: {str(r.get('error') or 'no background jobs here')[:160]}"], "", \
            "unstarted"
    try:
        from tools import volatility as VV
        hit = V.lookup(case_dir, V.key_for(case_dir, image, "windows.info", None, vol_bin=VV.VOL,
                                           symbol_dir=VV.vol3_symbols()))
    except Exception:  # noqa: BLE001
        hit = None
    if hit is None:
        st = ((MB.status(case_dir).get("images") or {}).get(image) or {}).get("plugins") or {}
        if st.get("windows.info") == "failed":
            return [f"memory header: the info pass failed (memory batch, job {job})"], job, "failed"
        return [f"memory header pending (memory batch, background job {job})"], job, "running"
    try:
        rows = json.loads(V.stored_text(hit))
    except ValueError:
        return [f"memory header: the memory batch gave no readable info (job {job})"], job, "failed"
    lines = ["memory header (one info pass):"]
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict) and r.get("Variable"):
            lines.append(f"- {r['Variable']}: {str(r.get('Value'))[:120]}")
    return lines, job, "finished"


def _memory_header(case_dir, item: dict[str, Any], job: str) -> tuple[list[str], str, str]:
    """The info header from its background job: started once, read when it
    has finished. (lines, job id, state) with state running, finished,
    failed or unstarted."""
    from tools import jobs as J
    if not job:
        try:
            r = J._start_job("memory_info", {"image_path": str(_abs(case_dir, item["path"]))})
        except Exception as e:  # noqa: BLE001
            return [f"memory header not started: {type(e).__name__}"], "", "unstarted"
        job = str(r.get("job_id") or "")
        if not job:
            return [f"memory header not started: {str(r.get('error') or 'no background jobs here')[:160]}"], \
                "", "unstarted"
    job_dir, meta, err = J._load_job(job)
    if err or job_dir is None:
        return [f"memory header: job {job} not found"], job, "failed"
    state = J._job_state(job_dir, meta or {})
    if state == "running":
        return [f"memory header pending (background job {job})"], job, "running"
    if state != "finished":
        return [f"memory header: the info pass {state} (job {job})"], job, "failed"
    try:
        rows = json.loads((job_dir / "stdout.log").read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return [f"memory header: job {job} gave no readable output"], job, "failed"
    lines = ["memory header (one info pass):"]
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict) and r.get("Variable"):
            lines.append(f"- {r['Variable']}: {str(r.get('Value'))[:120]}")
    return lines, job, "finished"


def survey_item(case_dir: str | os.PathLike, ledger: dict[str, Any], item: dict[str, Any],
                cache: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """{"key", "text", ...} of one item's survey (cached by ``key``)."""
    own_cache = cache is None
    cache = cache if cache is not None else _load(case_dir)
    iid = item["id"]
    cached = cache.get(iid) or {}
    kind = str(item.get("kind") or "")
    path = _abs(case_dir, item["path"])
    head = [f"ITEM {item['path']} ({kind}{', host ' + item['host'] if item.get('host') else ''})"]
    if kind == "image":
        from core.contents_index import listing_digest, listing_generation
        key = f"image:{listing_generation(case_dir)}:{len(ledger.get('classes') or {})}"
        if cached.get("key") == key:
            return cached
        digest = listing_digest(case_dir, hosts=[item["host"]] if item.get("host") else None, bound=1)
        body = [line for line in digest.get("lines") or [] if not line[:1].isdigit()][:1]
        body += ["content classes:"] + (_histogram(ledger, iid) or ["- none listed"])
    elif kind == "memory" and _batch_on():
        if cached.get("state") == "finished" and str(cached.get("key") or "").startswith("memory-batch:"):
            return cached
        body, job, state = _batch_header(case_dir, ledger, item)
        out = {"key": f"memory-batch:{state}", "job_id": job, "state": state,
               "text": "\n".join(head + body)[:MAX_SURVEY_CHARS]}
        cache[iid] = out
        if own_cache:
            _save(case_dir, cache)
        return out
    elif kind == "memory":
        retries = int(cached.get("retries") or 0)
        if cached.get("state") == "finished" or (cached.get("state") == "failed" and retries >= 1):
            return cached
        job = str(cached.get("job_id") or "")
        if cached.get("state") == "failed":
            job, retries = "", retries + 1            # one more pass for a failed header
        with _START_LOCK:
            if not job and _running_headers(cache) >= MAX_MEMORY_HEADERS:
                body, state = [f"memory header queued: it starts when one of the {MAX_MEMORY_HEADERS} "
                               "running header passes ends"], "queued"
            else:
                body, job, state = _memory_header(case_dir, item, job)
            out = {"key": f"memory:{job}:{state}", "job_id": job, "state": state, "retries": retries,
                   "text": "\n".join(head + body)[:MAX_SURVEY_CHARS]}
            cache[iid] = out
            if job and own_cache:
                _save(case_dir, cache)              # a started job is never started twice
        return out
    elif kind == "archive":
        key = f"archive:{_stat_key(path)}"
        if cached.get("key") == key:
            return cached
        body = _archive_histogram(path)
    elif kind == "capture":
        key = f"capture:{_stat_key(path)}"
        if cached.get("key") == key:
            return cached
        body = [f"capture of {path.stat().st_size:,} bytes" if path.exists() else "capture not found"]
    else:
        key = f"{kind}:{_stat_key(path)}:{len(ledger.get('classes') or {})}"
        if cached.get("key") == key:
            return cached
        body = []
        if kind == "file" and path.is_file():
            body += _log_sample(path)
        hist = _histogram(ledger, iid)
        if hist:
            body += ["content classes:"] + hist
    out = {"key": key, "text": "\n".join(head + body)[:MAX_SURVEY_CHARS]}
    cache[iid] = out
    return out


def survey_all(case_dir: str | os.PathLike, ledger: Optional[dict[str, Any]] = None) -> dict[str, dict[str, Any]]:
    """Every item's survey, cached; {item id: survey}."""
    from core.coverage_ledger import load_ledger
    ledger = ledger if ledger is not None else load_ledger(case_dir)
    cache = _load(case_dir)
    before = json.dumps(cache, sort_keys=True, default=str)
    out = {}
    for iid, item in (ledger.get("items") or {}).items():
        if isinstance(item, dict):
            try:
                out[iid] = survey_item(case_dir, ledger, item, cache)
            except Exception as e:  # noqa: BLE001 - one item's survey never stops the rest
                out[iid] = {"key": "error", "text": f"ITEM {item.get('path')}: survey failed ({type(e).__name__})"}
    if json.dumps(cache, sort_keys=True, default=str) != before:
        _save(case_dir, cache)
    return out
