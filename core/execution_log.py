"""Execution trace log — records tool calls, reason calls, and findings per case."""
import contextvars
import itertools
import fcntl
import hashlib
import json
import os
import sys
import tempfile
import threading
import datetime
from dataclasses import dataclass, field
from typing import Optional

# The MCP tool the current tool_call was invoked through (e.g. "misc_batch_run",
# "strings_strings_grep"). Set by core.middleware.on_call_tool around the tool
# body; read by record_tool_call so every self-logged subprocess entry records
# which typed tool it came from. Without this the trace only holds the internal
# subprocess cmd ("strings -a …"), so reviewers can't tell a typed tool from a
# raw shell verb run via the generic batch executor.
current_mcp_tool: "contextvars.ContextVar[str | None]" = contextvars.ContextVar(
    "current_mcp_tool", default=None)
# One id per model tool call, set by the middleware. A tool that shells out
# more than once per call (an ASCII and a UTF-16 strings pass, say) records
# one entry per subprocess; the id lets action windows count the call once.
current_action_id: "contextvars.ContextVar[int | None]" = contextvars.ContextVar(
    "current_action_id", default=None)
_action_seq = itertools.count(1)


def next_action_id() -> int:
    return next(_action_seq)


def action_key(entry: dict) -> object:
    """Groups entries by the model action that produced them."""
    return entry.get("action_id") or ("entry", entry.get("call_id"), id(entry))

# Evidence reference for the in-flight tool call (an image/mount path argument
# such as "evidence/host01.raw" or "mnt/host01/..."). Set by
# core.middleware.on_call_tool from the call's arguments; read by
# record_tool_call so multi-host traces record which evidence each tool ran
# against. Host resolution (path → hostname) happens at report time via the
# case evidence table — the trace only needs the raw reference.
current_evidence_ref: "contextvars.ContextVar[str | None]" = contextvars.ContextVar(
    "current_evidence_ref", default=None)

# Shared lock file with the PostToolUse hook. Both writers acquire this
# exclusive lock around their read-merge-write cycles so they never lose
# each other's entries to a race.
_TRACE_LOCK_FILE = os.path.expanduser("~/.cache/atlas/hook.lock")
# Call-id counters: one file per trace, in counters/ beside this file, so the
# processes that write a trace never hand out the same id. Runs of other cases
# never touch it, so a fresh start elsewhere cannot rewind this trace's
# numbering (hook entries number from their own 1e9+ range). The single file
# remains for a caller that names no trace.
_CALL_ID_COUNTER_FILE = os.path.expanduser("~/.cache/atlas/call_id.counter")


# How much of a tool's output the trace keeps inline. 600 characters left
# every table result's rows out of the trace, so the citation check never
# saw the address or time a finding quoted and downgraded it. Anything longer than this is kept whole on disk
# next to the trace (tool-output/) and referenced as stdout_file.
try:
    from core.envfile import env_int as _env_int
    TRACE_EXCERPT_CHARS = _env_int("ATLAS_TRACE_EXCERPT_CHARS", 4000)
except Exception:  # noqa: BLE001
    TRACE_EXCERPT_CHARS = 4000


def _canonical_entry_json(entry: dict) -> str:
    """Deterministic serialization used for chain hashing. Must survive a
    JSON round-trip unchanged (verify recomputes it from the parsed line)."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def _chain_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.blake2b((prev_hash + canonical).encode("utf-8"),
                           digest_size=32).hexdigest()


def _mirror_entry_id(entry: dict):
    """Stable identity for already-mirrored dedup: the call_id when present
    (MCP entries are monotonic, hook entries use the 1e9+ range), else a
    content hash."""
    cid = entry.get("call_id")
    if cid is not None:
        return cid
    return "h:" + _chain_hash("", _canonical_entry_json(entry))


def verify_trace_chain(path: str) -> dict:
    """Recompute the hash chain of a <trace>.jsonl mirror.

    Returns {"ok": True, "entries": n} when every line chains to its
    predecessor and matches its own content hash; otherwise the 1-based
    line number and what broke. Any edit, reorder, or deletion of a
    journaled entry breaks the chain from that line onward.
    """
    try:
        f = open(path, encoding="utf-8")
    except OSError as e:
        return {"ok": False, "line": 0, "error": f"cannot open: {e}"}
    prev = ""
    count = 0
    with f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                return {"ok": False, "line": i, "error": "unparseable line"}
            if rec.get("prev_hash", "") != prev:
                return {"ok": False, "line": i,
                        "error": "chain broken — prev_hash does not match "
                                 "the previous line (entry removed, "
                                 "reordered, or inserted?)"}
            expected = _chain_hash(prev, _canonical_entry_json(
                rec.get("entry") or {}))
            if expected != rec.get("entry_hash"):
                return {"ok": False, "line": i,
                        "error": "entry content does not match its hash "
                                 "(entry altered after journaling?)"}
            prev = expected
            count += 1
    return {"ok": True, "entries": count, "path": path}


def _scan_trace_max_cid(trace_path: str) -> int:
    """Return max call_id present in the trace file, or 0 if missing/empty."""
    if not trace_path or not os.path.exists(trace_path):
        return 0
    try:
        with open(trace_path) as f:
            existing = json.load(f).get("entries", []) or []
        if not existing:
            return 0
        return max(int(e.get("call_id", 0) or 0) for e in existing)
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return 0


def _counter_file(trace_path: Optional[str]) -> str:
    """The counter file of a trace: counters/<16 hex digits of the sha256 of
    the trace's real path>.json in the directory of _CALL_ID_COUNTER_FILE,
    resolved at call time so a test that moves that file moves this too."""
    if not trace_path:
        return _CALL_ID_COUNTER_FILE
    real = os.path.realpath(os.path.abspath(trace_path))
    key = hashlib.sha256(real.encode("utf-8")).hexdigest()[:16]
    return os.path.join(os.path.dirname(_CALL_ID_COUNTER_FILE), "counters", f"{key}.json")


def _next_shared_call_id(trace_path: Optional[str] = None, in_memory_seq: int = 0,
                         counter_file: Optional[str] = None) -> int:
    """Atomically increment and return the next call_id of a trace.

    Every writer of the trace calls this, so their ids form one dense
    monotonic sequence per trace. `counter_file` is the trace's counter as
    its log resolved it at configure time; without it the file is derived
    from `trace_path`.

    Returns `max(counter_file, trace_max+1, in_memory_seq+1)` — so even if the
    counter file is stale (hand-edited, race-reset between writers, lost) the
    returned cid is provably greater than any cid present in the trace OR in
    the calling process's in-memory ExecutionLog state. Duplicates become
    impossible by construction; the counter file becomes a fast-path *cache*,
    not a source of truth.
    """
    counter_file = counter_file or _counter_file(trace_path)
    os.makedirs(os.path.dirname(_TRACE_LOCK_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(counter_file), exist_ok=True)
    lock_fp = open(_TRACE_LOCK_FILE, "w")
    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        # Read counter file (the cheap fast path)
        try:
            with open(counter_file) as f:
                counter_n = int(json.load(f).get("next", 1))
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            counter_n = 1
        # Validate counter against actual on-disk + in-memory state.
        # in_memory_seq is the calling ExecutionLog's last assigned cid; the
        # trace scan is the cross-process safety net (e.g. for the hook).
        trace_max = _scan_trace_max_cid(trace_path) if trace_path else 0
        n = max(counter_n, trace_max + 1, in_memory_seq + 1)
        if n != counter_n:
            # Stale counter detected — log once so corruption is visible.
            print(
                f"[Atlas WARN] _next_shared_call_id: stale counter file "
                f"(was {counter_n}, returning {n}; trace_max={trace_max} "
                f"in_memory_seq={in_memory_seq})",
                file=sys.stderr,
            )
        tmp = counter_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"next": n + 1}, f)
        os.replace(tmp, counter_file)
        return n
    finally:
        try:
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fp.close()

# Written on every configure() so the singleton can auto-recover after a server restart.
_SESSION_FILE = os.path.expanduser("~/.cache/atlas/session.json")

# Per-case "this run was cleared at T" markers. clear_case_run writes one;
# configure() reads it and refuses to resume any trace entry that predates the
# newest clear — so a stale MCP process that re-flushes a dead run's entries to
# disk after a clear can't have them resurrected into a fresh run's trace.
_CLEAR_MARKER_DIR = os.path.expanduser("~/.cache/atlas/clear_markers")
# Per-case liveness beacon: {pid, path, ts}. configure() checks it so a second
# server process configuring the same case path logs a loud split-brain WARN
# (two servers writing one trace is what let the resurrection happen).
_BEACON_DIR = os.path.expanduser("~/.cache/atlas/beacons")


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def as_text(value: object) -> str:
    """A prose field as one string. A model may hand a list or a mapping
    where a sentence was asked for; every reader of the trace expects text,
    so the log stores text."""
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(t for t in (as_text(v) for v in value) if t)
    return str(value)


def _warn(msg: str) -> None:
    print(f"[Atlas WARN] {msg}", file=sys.stderr)


def _case_key(case_dir: str) -> str:
    """Stable filesystem-safe key for a case's absolute directory. Both
    clear_case_run (has case_dir) and configure (derives it from the trace
    path) compute the same key so markers/beacons line up."""
    import hashlib
    return hashlib.sha256(os.path.abspath(case_dir).encode()).hexdigest()[:16]


def _case_max_call_id(case_dir: str | None) -> int:
    """The highest call id any persisted state of the case refers to."""
    if not case_dir:
        return 0
    try:
        with open(os.path.join(case_dir, ".atlas", "claim_graph.json"),
                  encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return 0
    top = 0
    for n in (data.get("nodes") or {}).values() if isinstance(data, dict) else []:
        if not isinstance(n, dict):
            continue
        vals = [n.get("finding_call_id"), n.get("linked_call_id")]
        vals += list(n.get("input_call_ids") or [])
        vals += list(n.get("merged_finding_call_ids") or [])
        vals += [e.get("call_id") for e in (n.get("evidence") or [])
                 if isinstance(e, dict)]
        for v in vals:
            try:
                top = max(top, int(v or 0))
            except (TypeError, ValueError):
                pass
    return top


def drop_beacon_if_under(case_dir: str) -> tuple[bool, str]:
    """Remove the session beacon when it points into `case_dir` or cannot be
    read; the beacon of another case's live run stays. Returns
    (removed, error)."""
    if not os.path.exists(_SESSION_FILE):
        return False, ""
    try:
        with open(_SESSION_FILE, encoding="utf-8") as f:
            raw = str((json.load(f) or {}).get("path") or "")
    except (OSError, ValueError, AttributeError):
        raw = ""
    if raw:
        beacon = os.path.realpath(raw)
        base = os.path.realpath(case_dir)
        if beacon != base and not beacon.startswith(base + os.sep):
            return False, ""
    try:
        os.remove(_SESSION_FILE)
        return True, ""
    except OSError as e:
        return False, str(e)


def _case_dir_for_trace(path: str) -> str:
    """Walk up from a trace path past an analysis/exports/reports segment to
    the case directory — mirrors start_execution_log's derivation."""
    parent = os.path.dirname(os.path.abspath(path))
    if os.path.basename(parent) in ("analysis", "exports", "reports"):
        return os.path.dirname(parent)
    return parent


def case_dir_for_trace(path: str) -> str:
    """The case directory a trace file belongs to (``_case_dir_for_trace``),
    for callers outside this module."""
    return _case_dir_for_trace(path)


def _cwd_case_dir() -> Optional[str]:
    """The case directory the process runs in (a case brief is present), or
    None when it was launched from an arbitrary directory."""
    cwd = os.getcwd()
    if any(os.path.exists(os.path.join(cwd, n)) for n in ("CASE.md", "CLAUDE.md")):
        return cwd
    return None


# One notice per process for each kind of guessed binding (below).
_BINDING_NOTED: set[str] = set()


def _beacon_is_unambiguous(trace_path: str) -> bool:
    """Whether a process outside any case directory may follow the session
    beacon. The beacon is one slot per host: with more than one run alive
    it names only the run started last, so the restore does not guess and
    says so once. With one run alive and it the beacon's case, the restore
    binds but says that this process now writes into a live run's trace.
    Inside a case directory the directory decides (_beacon_is_foreign)."""
    if _cwd_case_dir():
        return True
    try:
        from core.run_state import live_runs, run_status
        live = live_runs()
    except Exception:  # noqa: BLE001 - no answer is no reason to stop binding
        return True
    if len(live) > 1:
        if "ambiguous" not in _BINDING_NOTED:
            _BINDING_NOTED.add("ambiguous")
            _warn(f"session beacon not followed: {len(live)} runs are live on this host "
                  f"({', '.join(live)}); start_execution_log names the case this process "
                  "writes to")
        return False
    case = os.path.realpath(_case_dir_for_trace(trace_path))
    pid = run_status(case).get("pid") if any(os.path.realpath(c) == case for c in live) else None
    if pid and str(pid) != str(os.getpid()) and "live" not in _BINDING_NOTED:
        _BINDING_NOTED.add("live")
        _warn(f"session beacon followed into {case}, whose run is live in pid {pid}: this "
              "process now writes into that run's trace")
    return True


def _beacon_is_foreign(trace_path: str) -> bool:
    """The session beacon names the trace an MCP server restarted from an
    arbitrary directory should resume. A run launched inside a different
    case (``--case``, the dashboard) must not inherit it: the log would bind
    to the old case and refuse every write into the new one."""
    here = _cwd_case_dir()
    if not here:
        return False
    return os.path.realpath(_case_dir_for_trace(trace_path)) != os.path.realpath(here)


def _parse_ts(s: object) -> Optional[datetime.datetime]:
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _ts_ge(entry_ts: object, marker_ts: object) -> bool:
    """True if entry_ts is at or after marker_ts. An unparseable/missing entry
    ts sorts as older-than-marker (→ discard); an unparseable marker keeps the
    entry (fail-open, we never drop good data on a bad marker)."""
    m = _parse_ts(marker_ts)
    if m is None:
        return True
    e = _parse_ts(entry_ts)
    if e is None:
        return False
    return e >= m


def is_trace_opened(entry: dict) -> bool:
    """A session's trace-open mark, in the current form or the older one
    (a system_error with category ``trace_initialized``)."""
    return (entry.get("type") == "trace_opened"
            or (entry.get("type") == "system_error"
                and entry.get("category") == "trace_initialized"))


def _touched(entry: dict) -> None:
    """Count an edit of an entry already written. A second writer of the trace
    that holds the older copy takes this one on its next flush instead of
    writing the old one back."""
    entry["_rev"] = int(entry.get("_rev") or 0) + 1


def _entry_order(entry: dict) -> tuple:
    ts = _parse_ts(entry.get("ts"))
    cid = entry.get("call_id")
    return (ts.timestamp() if ts else 0.0, cid if isinstance(cid, int) else 0)


def write_clear_marker(case_dir: str) -> Optional[str]:
    """Record that `case_dir` was cleared at now(). Returns the marker path,
    or None on failure. Read by configure() via read_clear_marker_ts."""
    try:
        os.makedirs(_CLEAR_MARKER_DIR, exist_ok=True)
        marker = os.path.join(_CLEAR_MARKER_DIR, _case_key(case_dir) + ".json")
        tmp = marker + ".tmp"
        # Microsecond precision (entries are second-resolution): an entry
        # recorded in the very same wall-clock second as the clear still sorts
        # strictly *before* the marker and is treated as pre-clear residue.
        cleared_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(tmp, "w") as f:
            json.dump(
                {"case_dir": os.path.abspath(case_dir), "cleared_at": cleared_at}, f
            )
        os.replace(tmp, marker)
        return marker
    except OSError as e:
        _warn(f"could not write clear marker for {case_dir}: {e}")
        return None


def read_clear_marker_ts(case_dir: str) -> Optional[str]:
    """ISO timestamp of the most recent clear_case_run for `case_dir`, or None
    if the case has never been cleared (or the marker is unreadable)."""
    try:
        marker = os.path.join(_CLEAR_MARKER_DIR, _case_key(case_dir) + ".json")
        with open(marker) as f:
            return json.load(f).get("cleared_at")
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return None


# The one liveness test for a recorded pid (core.run_state).
from core.run_state import pid_alive as _pid_alive  # noqa: E402


def _check_and_write_beacon(case_dir: str, path: str) -> None:
    """Best-effort split-brain guard. If a *live* process already holds this
    case's beacon with a different pid, emit a loud WARN, then stamp our own
    pid. Never raises — a beacon problem must not break configure()."""
    try:
        os.makedirs(_BEACON_DIR, exist_ok=True)
        beacon = os.path.join(_BEACON_DIR, _case_key(case_dir) + ".json")
        try:
            with open(beacon) as f:
                prev = json.load(f)
            prev_pid = int(prev.get("pid") or 0)
            if prev_pid and prev_pid != os.getpid() and _pid_alive(prev_pid):
                _warn(
                    f"split-brain: case trace {path!r} is already held by live "
                    f"MCP process pid={prev_pid} (this is pid={os.getpid()}). "
                    f"Two servers writing one trace can resurrect a dead run's "
                    f"entries into this run — stop the older server."
                )
        except (OSError, json.JSONDecodeError, ValueError, TypeError):
            pass
        tmp = beacon + ".tmp"
        with open(tmp, "w") as f:
            json.dump(
                {"pid": os.getpid(), "path": os.path.abspath(path), "ts": _utcnow()},
                f,
            )
        os.replace(tmp, beacon)
    except OSError:
        pass


def _build_phase_index(entries: list[dict]) -> list[dict]:
    """Walk entries once; return phase blocks for TOC + transition headers.

    Each block: {phase, start_cid, end_cid, anchor}. A phase begins at the first
    dair_call announcing it and continues until the next dair_call shows a
    different current_phase (or the trace ends).
    """
    blocks: list[dict] = []
    current_phase = ""
    current_block: dict | None = None
    phase_count: dict[str, int] = {}
    for e in entries:
        if e.get("type") == "dair_call":
            phase = e.get("current_phase", "") or "unknown"
            cid = e.get("call_id", 0)
            if phase != current_phase:
                if current_block:
                    current_block["end_cid"] = cid - 1
                phase_count[phase] = phase_count.get(phase, 0) + 1
                anchor = f"phase-{phase.lower()}-{phase_count[phase]}"
                current_block = {
                    "phase": phase,
                    "start_cid": cid,
                    "end_cid": entries[-1].get("call_id", cid) if entries else cid,
                    "anchor": anchor,
                }
                blocks.append(current_block)
                current_phase = phase
    if current_block and entries:
        current_block["end_cid"] = entries[-1].get("call_id", current_block["start_cid"])
    return blocks


def is_disposition(entry: object) -> bool:
    """A narration entry recording work done and its empty outcome: an
    indicator searched and not found, a sweep completed empty. Kept apart
    from findings so the finding ledger, the claim graph and the report
    carry conclusions only, while the values it names still count as
    ruled on."""
    return (isinstance(entry, dict)
            and entry.get("type") == "investigation_narration"
            and entry.get("kind") == "disposition")


def _render_entries(case_id: str | None, entries: list[dict]) -> str:
    """Shared markdown renderer used by both to_markdown() and export()."""
    lines = [f"# Execution Trace — {case_id or 'unknown'}\n"]

    # Markdown navigability: Table of Contents listing phases encountered.
    phase_blocks = _build_phase_index(entries)
    if phase_blocks:
        lines.append("## Contents\n")
        for blk in phase_blocks:
            lines.append(
                f"- [{blk['phase']}](#{blk['anchor']}) — entries #{blk['start_cid']}–#{blk['end_cid']}"
            )
        lines.append("")

    # Markdown navigability: lookup table for evidence-chain rendering on
    # finding entries.
    by_call_id = {e.get("call_id"): e for e in entries if e.get("call_id")}
    phase_start_set = {(blk["start_cid"], blk["anchor"], blk["phase"]) for blk in phase_blocks}
    phase_start_by_cid = {start_cid: (anchor, phase) for start_cid, anchor, phase in phase_start_set}

    for e in entries:
        ts = e.get("ts", "")
        t = e.get("type", "")
        cid = e.get("call_id", "")
        prefix = f"[#{cid}] " if cid else ""
        # Markdown navigability: emit a phase anchor + header right before
        # its starting dair_call.
        if cid in phase_start_by_cid:
            anchor, phase = phase_start_by_cid[cid]
            lines.append(f"\n<a id=\"{anchor}\"></a>")
            lines.append(f"## Phase: {phase}\n")
        if t == "tool_call":
            if e.get("timed_out"):
                status = "TIMEOUT"
            elif e.get("success"):
                status = "OK"
            else:
                status = "FAIL"
            retries = f" ({e['retries']} retries)" if e.get("retries") else ""
            trunc = " [TRUNCATED]" if e.get("truncated") else ""
            elapsed = f" {e['elapsed_seconds']}s" if e.get("elapsed_seconds") else ""
            violation = f" PROTOCOL_VIOLATION: {e['protocol_violation']}" if e.get("protocol_violation") else ""
            lines.append(f"- `{ts}` {prefix}**TOOL** `{e.get('cmd', '')}`  → {status}{retries}{trunc}{elapsed}{violation}")
            if not e.get("success") and e.get("stderr"):
                lines.append(f"  - stderr: {e['stderr'][:200]}")
            if e.get("stdout_excerpt"):
                lines.append(f"  - output: {e['stdout_excerpt'][:300]}")
        elif t == "reason_call":
            status = "OK" if e.get("success") else "FAIL"
            tok_in = e.get("input_tokens", 0)
            tok_out = e.get("output_tokens", 0)
            tok_str = f" tokens: in={tok_in} out={tok_out}" if tok_in or tok_out else ""
            lines.append(f"- `{ts}` {prefix}**REASON** `{e.get('tool', '')}`  → {status}{tok_str}")
            if e.get("conclusion"):
                lines.append(f"  - conclusion: {e['conclusion'][:400]}")
            if e.get("directives", {}).get("priority_tools"):
                lines.append(f"  - priority_tools: {e['directives']['priority_tools']}")
            for i, audit in enumerate(e.get("evidence_audit") or []):
                not_provided = sum(
                    1 for v in audit.values()
                    if isinstance(v, str) and v.upper() == "NOT PROVIDED"
                )
                flag = f" WARNING: {not_provided}×NOT_PROVIDED" if not_provided >= 2 else ""
                lines.append(
                    f"  - audit[{i}]: claim=\"{audit.get('claim', '')[:80]}\" "
                    f"tool={audit.get('tool', '?')}{flag}"
                )
        elif t == "call_initiated":
            backend = e.get("backend", "")
            inputs = e.get("inputs", {})
            input_str = " ".join(f"{k}={str(v)[:40]!r}" for k, v in inputs.items())
            lines.append(
                f"- `{ts}` {prefix}**→ CALL** `{e.get('tool', '')}` "
                f"via {backend} [{input_str}]"
            )
        elif t == "call_abandoned":
            lines.append(
                f"- `{ts}` {prefix}**ABANDONED** `{e.get('tool', '')}` "
                f"reason: {e.get('reason', '')[:200]}"
            )
        elif t == "dair_call":
            phase = e.get("current_phase", "")
            next_p = e.get("next_phase", "")
            action = e.get("stack_action", "stay")
            transition = e.get("transition_recommended", False)
            rationale = e.get("transition_rationale") or e.get("phase_rationale", "")
            if e.get("verification_satisfied"):
                lines.append("\n---\n### Verification Satisfied")
                lines.append("*Core IOCs verified — residual uncertainty accepted. Transitioning to Scope.*\n---")
            if transition and next_p:
                if action == "push" and next_p == "Verification":
                    lines.append(f"\n---\n### ↳ Verification — Internal Challenge")
                    lines.append(f"*Reason: {rationale[:200]}*\n---")
                elif action == "pop":
                    lines.append(f"\n---\n### ↑ Returning to: {next_p}")
                    lines.append(f"*Verification complete — resuming {next_p}*\n---")
                else:
                    lines.append(f"\n---\n### Phase Transition: {phase} → {next_p}")
                    lines.append(f"*Reason: {rationale[:200]}*\n---")
            else:
                tok_in, tok_out = e.get("input_tokens", 0), e.get("output_tokens", 0)
                tok_str = f" tokens: in={tok_in} out={tok_out}" if tok_in or tok_out else ""
                lines.append(
                    f"- `{ts}` {prefix}**DAIR** phase={phase} action={action}{tok_str}"
                )
            if e.get("investigation_focus"):
                lines.append(f"  - focus: {as_text(e['investigation_focus'])[:200]}")
            challenges = e.get("verification_challenges") or []
            if challenges:
                lines.append("  \n  #### Verification Challenges")
                lines.append("  | Claim | Method | Result | Confidence Impact |")
                lines.append("  |-------|--------|--------|-------------------|")
                for c in challenges:
                    claim = c.get("claim", "")[:60]
                    method = c.get("challenge_method", "")[:40]
                    verified = c.get("verified")
                    impact = c.get("confidence_impact", "—")
                    if verified is True:
                        result_str = "CONFIRMED"
                    elif verified is False:
                        result_str = f"REFUTED — {c.get('notes', '')[:40]}"
                    else:
                        result_str = "PENDING"
                    lines.append(f"  | {claim} | {method} | {result_str} | {impact} |")
            rec = e.get("recommended_actions") or []
            if rec:
                lines.append("  \n  **Recommended Actions (for IR team):**")
                for item in rec:
                    lines.append(f"  - {item}")
        elif t == "investigation_narration":
            refs = (
                f" [from #{', #'.join(str(i) for i in e['input_call_ids'])}]"
                if e.get("input_call_ids") else ""
            )
            label = "DISPOSITION" if is_disposition(e) else "AGENT"
            lines.append(f"- `{ts}` {prefix}**{label}**{refs} {e.get('content', '')[:300]}")
        elif t == "finding":
            conf = e.get("confidence", "").upper()
            linked = e.get("linked_call_id", 0)
            link_str = f" ← tool call #{linked}" if linked else ""
            lines.append(f"- `{ts}` {prefix}**FINDING** [{conf}] {e.get('description', '')}{link_str}")
            if e.get("host"):
                lines.append(f"  - host: {e['host']}")
            if e.get("source"):
                lines.append(f"  - source: {e['source']}")
            if e.get("tested_hypothesis_id"):
                lines.append(f"  - tests hypothesis: {e['tested_hypothesis_id']}")
            # Markdown navigability: Evidence Chain — render the linked
            # tool/reason entry inline.
            linked_entry = by_call_id.get(linked) if linked else None
            if linked_entry:
                ltype = linked_entry.get("type", "")
                if ltype == "tool_call":
                    cmd = (linked_entry.get("cmd") or "")[:80]
                    succ = "OK" if linked_entry.get("success") else "FAIL"
                    excerpt = (linked_entry.get("stdout_excerpt") or "")[:200]
                    lines.append(f"  - **Evidence Chain:** call #{linked} (`{cmd}`) — {succ}")
                    if excerpt:
                        lines.append(f"    - excerpt: {excerpt}")
                elif ltype == "reason_call":
                    rtool = linked_entry.get("tool", "")
                    lines.append(f"  - **Evidence Chain:** call #{linked} (reason `{rtool}`)")
        elif t == "self_correction":
            trigger = e.get("trigger", "")
            linked = e.get("linked_call_id", 0)
            link_str = f" (from #{linked})" if linked else ""
            lines.append(f"\n- `{ts}` {prefix}**SELF-CORRECTION** trigger: `{trigger}`{link_str}")
            if e.get("prior_belief"):
                lines.append(f"  - **prior:** {e['prior_belief'][:300]}")
            if e.get("new_belief"):
                lines.append(f"  - **revised:** {e['new_belief'][:300]}")
            if e.get("evidence"):
                lines.append(f"  - **evidence:** {e['evidence'][:300]}")
        else:
            lines.append(f"- `{ts}` {prefix}**[UNKNOWN TYPE: {t}]** {json.dumps(e)[:120]}")
    return "\n".join(lines) + "\n"


@dataclass
class LogIndex:
    """Pre-computed lookups over the entries list. Built lazily by
    ExecutionLog.index() and invalidated whenever an entry is appended
    (cheap version-counter check on access)."""
    by_call_id: dict[int, dict] = field(default_factory=dict)
    by_type: dict[str, list[dict]] = field(default_factory=dict)
    by_tool: dict[str, list[dict]] = field(default_factory=dict)
    findings_by_linked: dict[int, list[dict]] = field(default_factory=dict)
    hypotheses_by_id: dict[str, dict] = field(default_factory=dict)

    def recent(self, type_filter: str, window: list[dict]) -> list[dict]:
        """Return entries in `window` (a slice of recent entries) matching type_filter."""
        return [e for e in window if e.get("type") == type_filter]


def _extract_tool_from_entry(entry: dict) -> str:
    """Pick the canonical tool name for index lookup. Prefers explicit
    `tool` field (reason/dair calls); falls back to first token of `cmd`
    for tool_call entries — useful for `idx.by_tool['vol']`, etc."""
    tool = entry.get("tool")
    if tool:
        return tool
    cmd = entry.get("cmd") or ""
    if not cmd:
        return ""
    first = cmd.split()[0] if cmd else ""
    # Strip path prefix for binaries like /usr/local/bin/vol
    return os.path.basename(first)


class ExecutionLog:
    def __init__(self):
        self._entries: list[dict] = []
        self._path: Optional[str] = None
        self._case_id: Optional[str] = None
        self._seq: int = 0
        self._lock = threading.RLock()
        # DAIR phase state — the active phase + stack at write time. Each
        # record_* call stamps these onto its entry via _append_entry. State
        # is updated when record_dair_call processes a transition.
        self._current_phase: str = ""
        self._phase_stack: list[dict] = []   # [{phase, entry_reason, depth}, …]
        # call_id of the most recently completed dair_assess. Every tool call,
        # narration, and exception entry reads this and carries it as
        # input_call_ids so the trace forms a proper causal DAG:
        #   dair_call → [tool_calls, narrations, reason_calls] → findings
        # Reset to 0 on configure() so a new case starts without stale context.
        self._last_dair_cid: int = 0
        # Deferred-intent backlog latch (see core/deferred_intents.py).
        self._deferred_latch: bool = False
        self._deferred_latch_blocks: int = 0
        self._deferred_latch_assesses: int = 0
        # Lazy index cache — bumped on every mutation; rebuild on next index() call.
        self._index_version: int = 0
        # Hash-chained append-only mirror (<trace>.jsonl) state: which entry
        # ids are already journaled, the running chain hash, and the line
        # count. Re-initialised lazily whenever the mirror path changes or
        # the file disappears (clear_case_run).
        self._mirror: dict = {"path": None, "ids": set(),
                              "last_hash": "", "seq": 0}
        self._cached_index: Optional[tuple[int, LogIndex, int]] = None
        # When this log last took its entries from the trace (configure(), or
        # a clear it noticed): a clear of the case after that moment makes
        # what it held before the clear a dead run's residue.
        self._configured_at: Optional[datetime.datetime] = None

    def _drop_residue_if_cleared(self) -> None:
        """Must be called under self._lock. When the case was cleared after
        this log took its entries (another process ran clear_case_run while
        this one held the trace), the entries older than the clear are a dead
        run's residue: dropped here, so no later write puts them back, even
        when the clear deleted the trace file and there is nothing on disk to
        merge. A log configured after the clear is never touched, so entries
        a run records in the very second of its own clear stay."""
        if not self._path or self._configured_at is None:
            return
        marker = _parse_ts(read_clear_marker_ts(_case_dir_for_trace(self._path)))
        if marker is None or marker <= self._configured_at:
            return
        marker_ts = marker.isoformat()
        kept = [e for e in self._entries if _ts_ge(e.get("ts"), marker_ts)]
        if len(kept) != len(self._entries):
            self._entries = kept
            self._index_version += 1
            self._cached_index = None
            self._rehydrate_phase_state()
        self._configured_at = datetime.datetime.now(datetime.timezone.utc)

    def _next_id(self) -> int:
        # The trace's own counter keeps its ids one dense monotonic sequence.
        # _next_shared_call_id validates the counter against the on-disk trace
        # AND our in-memory seq, so a stale counter file (hand-edited or reset)
        # can never produce a duplicate cid.
        cid = _next_shared_call_id(self._path, in_memory_seq=self._seq,
                                   counter_file=getattr(self, "_counter_path", None))
        self._seq = cid  # kept for introspection / tests
        return cid

    def _append_entry(self, entry: dict) -> None:
        """Append `entry` and flush. Must be called under self._lock.

        Stamps `dair_phase` + `dair_depth` when phase state is known.
        setdefault() so callers can override (e.g. dair_call post-transition).
        """
        self._drop_residue_if_cleared()
        if self._current_phase:
            entry.setdefault("dair_phase", self._current_phase)
            entry.setdefault("dair_depth", len(self._phase_stack))
        self._entries.append(entry)
        self._index_version += 1
        self._flush()

    def index(self) -> LogIndex:
        """Return memoized indices over self._entries.

        First call after any append rebuilds in O(n); subsequent calls in O(1)
        until the next mutation. Used by gate checks, correlate.*, attribution,
        coverage_report — anywhere the trace needs to be queried by call_id,
        type, tool, or hypothesis_id.

        Cache key is ``(_index_version, len(_entries))``. Length is included
        because tests/probes sometimes mutate ``_entries`` directly (clear +
        append) without going through ``_append_entry``; without the length
        check those mutations left a stale ``by_call_id`` map and
        ``lineage_required`` falsely refused real call_ids
        (GATE-SUCCESS-UNREACHABLE class).
        """
        with self._lock:
            n = len(self._entries)
            cached = self._cached_index
            if (cached is not None
                    and cached[0] == self._index_version
                    and cached[2] == n):
                return cached[1]
            # Heal version when length drifted without an official append —
            # keeps the counter honest for the next _append_entry.
            if (cached is not None
                    and cached[0] == self._index_version
                    and cached[2] != n):
                self._index_version += 1
            idx = LogIndex()
            for e in self._entries:
                cid = e.get("call_id")
                if cid is not None:
                    idx.by_call_id[cid] = e
                t = e.get("type") or ""
                if t:
                    idx.by_type.setdefault(t, []).append(e)
                tool = _extract_tool_from_entry(e)
                if tool:
                    idx.by_tool.setdefault(tool, []).append(e)
                if t == "finding":
                    linked = e.get("linked_call_id") or 0
                    if linked:
                        idx.findings_by_linked.setdefault(linked, []).append(e)
                if t == "reason_call" and e.get("tool") == "reason_hypothesize":
                    hid = e.get("hypothesis_id")
                    if hid:
                        idx.hypotheses_by_id[hid] = e
            self._cached_index = (self._index_version, idx, n)
            return idx

    def last_n_window(self, n: int = 30) -> list[dict]:
        """Return the last n entries — used by gate checks for bounded look-back."""
        with self._lock:
            if len(self._entries) > n:
                return list(self._entries[-n:])
            return list(self._entries)

    def call_ids_since_last(self, entry_type: str = "dair_call",
                            kinds: tuple[str, ...] = ("tool_call", "reason_call"),
                            ) -> list[int]:
        """Call ids of the ``kinds`` entries recorded after the newest
        ``entry_type`` entry, all of them when there is none: the calls an
        assessment made now is summarising."""
        with self._lock:
            start = 0
            for i in range(len(self._entries) - 1, -1, -1):
                if self._entries[i].get("type") == entry_type:
                    start = i + 1
                    break
            return [int(e["call_id"]) for e in self._entries[start:]
                    if e.get("type") in kinds and e.get("call_id")]

    def gate_window(self, n: int = 30, reason_lookback: int = 150) -> list[dict]:
        """Gate look-back window: the last `n` entries, PLUS any `reason_call`
        within the last `reason_lookback` entries that the `n`-slice missed,
        merged in chronological order.

        The plain last-30 window aged a valid reason.confidence_score /
        cite_check / evaluate_finding out of view whenever the agent batched
        many tool calls between scoring a finding and recording it — the
        confidence_and_citation gate then refused a correctly-evidenced finding
        and the analyst downgraded the tier instead of re-scoring. That drove
        the recurring 0-CONFIRMED under-tiering. Widening ONLY the reason_call reach is safe: the matching
        gates still require the reason_call's message to contain this finding's
        description and enforce an anti-reuse floor (prior_dup_call_id), so a
        stale or unrelated score cannot satisfy the gate. dair_call / tool_call
        recency gates are unaffected because only reason_calls are added.
        """
        with self._lock:
            entries = self._entries
            base_slice = list(entries[-n:]) if len(entries) > n else list(entries)
            base_ids = {id(e) for e in base_slice}
            lookback = (entries[-reason_lookback:]
                        if len(entries) > reason_lookback else entries)
            extra = [e for e in lookback
                     if e.get("type") == "reason_call" and id(e) not in base_ids]
            # extra precedes base_slice chronologically (older reason_calls that
            # fell outside the n-window), so concatenation keeps overall order.
            return extra + base_slice if extra else base_slice

    def _apply_dair_transition(self, current_phase: str, stack_action: str,
                                next_phase: str, transition_rationale: str,
                                verification_satisfied: bool) -> None:
        """Update phase state based on a dair_call's declared transition.
        Must be called under self._lock, before the dair_call is appended.

        Returns nothing — mutates self._current_phase and self._phase_stack so
        the dair_call's own entry (and every subsequent entry) is stamped with
        the post-transition phase.
        """
        sa = (stack_action or "stay").lower()
        if sa == "push" and next_phase:
            self._phase_stack.append({
                "phase": next_phase,
                "entry_reason": transition_rationale or "",
                "depth": len(self._phase_stack),
            })
            self._current_phase = next_phase
        elif sa == "pop":
            # If the dair_call names a `next_phase`, pop until that phase is
            # at the top — this matches the agent's mental model ("I'm popping
            # back to Report") rather than blindly popping a single frame.
            if next_phase and self._phase_stack:
                while self._phase_stack and self._phase_stack[-1]["phase"] != next_phase:
                    self._phase_stack.pop()
                # If next_phase wasn't found anywhere, fall back to plain pop
                # on whatever was the top before this call.
                if not self._phase_stack:
                    self._phase_stack.append({
                        "phase": next_phase,
                        "entry_reason": "pop_fallback",
                        "depth": 0,
                    })
            elif self._phase_stack:
                self._phase_stack.pop()
            self._current_phase = (
                self._phase_stack[-1]["phase"] if self._phase_stack else ""
            )
        # stack_action == "stay" → no change to stack (but agent reconciliation below)

        # Triage-satisfied without explicit push: auto-advance to Collect so
        # subsequent entries are correctly attributed.
        if (verification_satisfied and sa == "stay"
                and (current_phase == "Triage" or self._current_phase == "Triage")):
            self._phase_stack.append({
                "phase": "Collect",
                "entry_reason": "verification_satisfied",
                "depth": len(self._phase_stack),
            })
            self._current_phase = "Collect"

        # First-ever dair_call (cold start, no transition): adopt the
        # declared current_phase AND push it onto the stack so depth is 1
        # at the root, 2 after a push, etc. — easier to read than depth=0
        # for the initial phase.
        if not self._current_phase and current_phase:
            self._current_phase = current_phase
            if not self._phase_stack:
                self._phase_stack.append({
                    "phase": current_phase,
                    "entry_reason": "initial_phase",
                    "depth": 0,
                })

        # Phase stack is sole authority. On stay, a stale agent-declared
        # current_phase must NOT rename the stack top — that created the
        # Collect↔Analyze oscillation. Only seed the stack when we have no phase yet (cold start).
        if (sa == "stay" and current_phase and not self._current_phase):
            self._current_phase = current_phase
            if not self._phase_stack:
                self._phase_stack.append({
                    "phase": current_phase,
                    "entry_reason": "initial_phase",
                    "depth": 0,
                })

    def _rehydrate_phase_state(self) -> None:
        """Replay the dair_call history to reconstruct current phase state.
        Used after configure() rehydrates an existing trace."""
        self._current_phase = ""
        self._phase_stack = []
        for e in self._entries:
            if e.get("type") != "dair_call":
                continue
            self._apply_dair_transition(
                current_phase=e.get("current_phase", "") or "",
                stack_action=e.get("stack_action", "") or "",
                next_phase=e.get("next_phase", "") or "",
                transition_rationale=e.get("transition_rationale", "") or "",
                verification_satisfied=bool(e.get("verification_satisfied")),
            )
        # If no dair_call has happened yet on the rehydrated trace, default
        # to Triage so subsequent entries are phased.
        if not self._current_phase:
            self._current_phase = "Triage"
            self._phase_stack = [{
                "phase": "Triage",
                "entry_reason": "session_resume_default",
                "depth": 0,
            }]

    def has_evidence_been_verified(self, evidence_path: str) -> bool:
        """True if a successful hash_verify_evidence_hash exists in the trace
        for this evidence_path. Used by the hash-verification feature to
        avoid re-running the check on the same evidence in one session."""
        with self._lock:
            for e in self._entries:
                if e.get("type") != "reason_call":
                    continue
                if e.get("tool") != "hash_verify_evidence_hash":
                    continue
                if not e.get("success"):
                    continue
                conclusion = e.get("conclusion", "") or ""
                if conclusion.startswith("VERIFIED:") and evidence_path in conclusion:
                    return True
            return False

    def configure(self, case_id: str, path: str,
                  save_session: bool = False) -> int:
        """Open or resume the trace log for case_id at path.

        If a valid trace file already exists at path with a matching case_id,
        rehydrates in-memory state and resumes appending without overwriting.
        Otherwise starts fresh. Returns the number of entries recovered (0 for
        a new case).

        save_session: when True, persist (case_id, path) to
            ~/.cache/atlas/session.json so a future MCP server boot
            auto-recovers this trace. Only the investigation's own start
            (start_execution_log, the CLI, the monitor) passes True; the
            default is False, so a test fixture, a probe or an ad-hoc
            script can never hijack the active investigation's recovery
            beacon and silently redirect tool calls to the wrong trace.
            When save_session=True is requested but the existing session
            points at a different case, a loud WARN is emitted before
            the overwrite happens.
        """
        with self._lock:
            try:
                with open(path) as f:
                    data = json.load(f)
                existing_id = data.get("case_id")
                if existing_id == case_id:
                    entries = data.get("entries", []) or []
                    # Stale-resurrection guard: if this case was cleared more
                    # recently than these entries, a stale process re-flushed a
                    # dead run's entries after clear_case_run. Refuse to resume
                    # them — keep only entries at/after the newest clear marker.
                    case_dir = _case_dir_for_trace(path)
                    marker_ts = read_clear_marker_ts(case_dir)
                    if marker_ts and entries:
                        kept = [e for e in entries if _ts_ge(e.get("ts"), marker_ts)]
                        discarded = len(entries) - len(kept)
                        if discarded:
                            _warn(
                                f"discarded {discarded} trace "
                                f"entr{'y' if discarded == 1 else 'ies'} at {path} "
                                f"predating the clear marker ({marker_ts}) for case "
                                f"{case_id!r}: a stale MCP process re-flushed a dead "
                                f"run's entries after clear_case_run. Continuing "
                                f"with {len(kept)} post-clear "
                                f"entr{'y' if len(kept) == 1 else 'ies'}."
                            )
                            entries = kept
                    # If every entry was stale residue, fall through to the
                    # fresh-start block below (do not resume an empty trace).
                    if entries:
                        self._entries = entries
                        self._seq = max(
                            max((e.get("call_id", 0) for e in entries), default=0),
                            _case_max_call_id(case_dir))
                        self._case_id = case_id
                        self._path = path
                        self._configured_at = datetime.datetime.now(datetime.timezone.utc)
                        self._index_version += 1  # invalidate any cached LogIndex
                        self._cached_index = None
                        self._rehydrate_phase_state()
                        self._sync_shared_counter()
                        self._flush()
                        if save_session:
                            self._save_session()
                            _check_and_write_beacon(case_dir, path)
                        return len(entries)
                elif existing_id:
                    _warn(
                        f"existing trace has case_id={existing_id!r}, "
                        f"overwriting with {case_id!r} at {path}"
                    )
            except OSError:
                pass  # file doesn't exist — normal for a new case
            except (json.JSONDecodeError, ValueError) as e:
                _warn(f"trace file corrupted at {path}, starting fresh: {e}")
            self._entries = []
            # A cleared trace restarts numbering, but the claim graph keeps
            # the ids of the findings that made it: a new finding reusing one
            # of those ids matched the old claim and overwrote its statement
            #. Ids stay monotonic per case.
            self._seq = _case_max_call_id(_case_dir_for_trace(path))
            self._last_dair_cid = 0
            self._deferred_latch = False
            self._deferred_latch_blocks = 0
            self._deferred_latch_assesses = 0
            self._case_id = case_id
            self._path = path
            self._configured_at = datetime.datetime.now(datetime.timezone.utc)
            # Default to Triage — the DAIR spec says every investigation starts
            # there ("with a confirmed positive detection already in hand"),
            # so every entry from session start should be stamped with a phase.
            # The first dair_assess will reconcile if the agent's declared
            # current_phase differs.
            self._current_phase = "Triage"
            self._phase_stack = [{
                "phase": "Triage",
                "entry_reason": "session_start_default",
                "depth": 0,
            }]
            self._index_version += 1
            self._cached_index = None
            self._sync_shared_counter()
            self._flush()
            if save_session:
                self._save_session()
                _check_and_write_beacon(_case_dir_for_trace(path), path)
            return 0

    def reset_for_clear(self, case_dir: str) -> dict:
        """In-process half of clear_case_run.

        clear_case_run deletes the on-disk trace, but the in-memory singleton
        still holds the dead run's entries — the next record_* would re-flush
        them straight back to disk, and a later configure() would resume them.
        This drops that in-memory state so the resurrection can't happen, and
        writes a timestamped clear marker so *other* server processes refuse to
        resume the same dead entries on their next configure().

        Only resets the singleton when it is currently bound to a trace under
        `case_dir`; a log serving a different case is left untouched. The clear
        marker is always written. Returns {"reset_in_process", "clear_marker"}.
        """
        with self._lock:
            marker = write_clear_marker(case_dir)
            abs_case = os.path.abspath(case_dir)
            reset = False
            if self._path is not None:
                abs_path = os.path.abspath(self._path)
                if abs_path == abs_case or abs_path.startswith(abs_case + os.sep):
                    self._entries = []
                    self._seq = 0
                    self._last_dair_cid = 0
                    self._deferred_latch = False
                    self._deferred_latch_blocks = 0
                    self._deferred_latch_assesses = 0
                    self._case_id = None
                    self._path = None
                    self._mirror = {"path": None, "ids": set(),
                                    "last_hash": "", "seq": 0}
                    self._current_phase = ""
                    self._phase_stack = []
                    self._index_version += 1
                    self._cached_index = None
                    reset = True
            return {"reset_in_process": reset, "clear_marker": marker}

    def _sync_shared_counter(self) -> None:
        """Write this trace's counter file to match self._seq + 1.

        Called from configure() after rehydrate / fresh-start so the next
        _next_shared_call_id() call returns the right id. Also covers the
        case where the counter file was deleted (e.g. by a reset) but the
        trace was not. When the existing counter is meaningfully behind
        the rehydrated self._seq, emit a WARN — it's a strong signal that
        the cache files were manually edited or the trace was restored from
        backup, and the next investigation might otherwise hit ID collisions.
        """
        # The key is fixed here, from the real path, so a later chdir
        # cannot move the trace to another counter.
        counter_file = _counter_file(self._path)
        self._counter_path = counter_file
        os.makedirs(os.path.dirname(counter_file), exist_ok=True)
        os.makedirs(os.path.dirname(_TRACE_LOCK_FILE), exist_ok=True)
        # Detect drift between counter and our rehydrated state — symptom of a
        # bad reset (cache cleared while trace preserved, or backup restore).
        # _next_shared_call_id corrects it automatically; this warning makes
        # it visible at session start.
        lock_fp = open(_TRACE_LOCK_FILE, "w")
        try:
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
            self._write_counter_locked(counter_file)
        finally:
            try:
                fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            lock_fp.close()

    def _write_counter_locked(self, counter_file: str) -> None:
        existing_counter = None
        try:
            with open(counter_file) as f:
                existing_counter = int(json.load(f).get("next", 0))
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            pass
        expected = self._seq + 1
        if existing_counter is not None and existing_counter < expected - 1:
            _warn(
                f"counter file drift detected at configure(): "
                f"counter says next={existing_counter} but trace max_cid={self._seq} "
                f"(rehydrating to next={expected}). Likely cause: cache files "
                f"manually edited or trace restored from backup. Use "
                f"`python -m tools.atlas_reset` for clean resets in future."
            )
        tmp = counter_file + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"next": expected}, f)
            os.replace(tmp, counter_file)
        except OSError as e:
            _warn(f"could not sync the trace's counter file: {e}")

    def _save_session(self) -> None:
        # Must be called under self._lock.
        # Surface cross-case overwrites loudly — if a previously active
        # session for a different case is still on disk and its trace dir
        # exists, that investigation will silently follow this one's path
        # on the next MCP server restart — an ad-hoc smoke script that
        # configures its own trace is enough to cause it.
        try:
            with open(_SESSION_FILE) as f:
                prior = json.load(f)
            prior_case = prior.get("case_id")
            prior_path = prior.get("path")
            if (prior_case and prior_path
                    and prior_case != self._case_id
                    and os.path.isdir(os.path.dirname(os.path.abspath(prior_path)))):
                _warn(
                    f"session.json overwrite: was case_id={prior_case!r} "
                    f"path={prior_path!r}; now {self._case_id!r} at "
                    f"{self._path!r}. If you're running a test or smoke "
                    f"script, pass save_session=False to configure()."
                )
        except (OSError, json.JSONDecodeError, ValueError):
            pass
        try:
            os.makedirs(os.path.dirname(_SESSION_FILE), exist_ok=True)
            # Persist the ABSOLUTE path so the UserPromptSubmit /
            # PostToolUse hooks can resolve it regardless of CWD. The
            # hooks read this beacon and write to `path` directly —
            # relative paths there silently no-op when the hook is
            # launched from a different working directory than the
            # one the MCP server happened to be in.
            abs_path = os.path.abspath(self._path) if self._path else self._path
            with open(_SESSION_FILE, "w") as f:
                json.dump({"case_id": self._case_id, "path": abs_path}, f)
        except OSError as e:
            _warn(f"session save failed — auto-recovery on restart will not work: {e}")

    def case_dir(self) -> Optional[str]:
        """Absolute path of the active case directory (parent of the
        analysis/exports/reports dir holding the trace), or None when no
        trace is configured. Attempts session-file / CWD auto-recovery
        first so a restarted MCP server still resolves against the right
        case. Used by core.middleware to resolve case-relative
        output/mount path arguments."""
        with self._lock:
            self._auto_recover()
            if not self._path:
                return None
            return _case_dir_for_trace(self._path)

    def trace_dir(self) -> Optional[str]:
        """Directory holding the trace file (the case's analysis/ dir), or
        None when the log is not configured. Public accessor so callers
        (e.g. the executor's spill-file logic) don't reach into _path."""
        with self._lock:
            if not self._path:
                return None
            return os.path.dirname(os.path.abspath(self._path))

    def trace_path(self) -> Optional[str]:
        """Absolute path of the configured trace file, or None."""
        with self._lock:
            if not self._path:
                return None
            return os.path.abspath(self._path)

    def _auto_recover(self) -> None:
        # Must be called under self._lock.
        if self._path is not None:
            return

        # 1) Session-file recovery (preserves cross-CWD MCP-server restart cases).
        try:
            with open(_SESSION_FILE) as f:
                s = json.load(f)
            case_id, path = s.get("case_id"), s.get("path")
            if case_id and path:
                # Reject stale sessions pointing to deleted directories
                # (e.g. pytest temp dirs).
                parent = os.path.dirname(os.path.abspath(path))
                if (os.path.isdir(parent) and not _beacon_is_foreign(path)
                        and _beacon_is_unambiguous(path)):
                    # save_session=False — we already read it from disk;
                    # rewriting under contention with another process can
                    # race on the file.
                    self.configure(case_id, path, save_session=False)
                    if self._path is not None:
                        return
        except (OSError, json.JSONDecodeError, ValueError):
            pass

        # 2) CWD-based recovery: if the MCP server is launched inside a real
        # case directory (case brief present AND analysis/<X>_trace.json
        # present), resume from that trace. Both signals are required so the
        # repo root, pytest tmp dirs, etc. never trigger this fallback.
        # Lets the agent skip start_execution_log on resume without losing
        # writes — every record_* call into an unconfigured log will lazily
        # bind to the case's existing trace.
        try:
            cwd = _cwd_case_dir()
            if not cwd:
                return
            trace_path = case_trace_document(cwd)
            if not trace_path:
                return
            basename = os.path.basename(trace_path)
            suffix = "_trace.json"
            if not basename.endswith(suffix):
                return
            case_id = basename[: -len(suffix)]
            # save_session=False — cwd-based recovery is best-effort and
            # shouldn't claim the session beacon out from under an
            # explicit start_execution_log running elsewhere.
            self.configure(case_id, trace_path, save_session=False)
        except OSError:
            pass

    def _flush(self) -> None:
        """Must be called under self._lock. Atomic write via temp file + rename.

        Read-merge-write: a trace can have several writers (a chat started on
        the case of a live run, the tool hook), each holding only the entries
        it wrote or read. The entries on disk are merged in first
        (_merged_for_write), so a flush never drops another writer's entries
        or undoes its edits.

        Every writer holds an exclusive fcntl flock on
        `~/.cache/atlas/hook.lock`, so the read/merge/write cycle is atomic
        cross-process.
        """
        if not self._path:
            return
        self._drop_residue_if_cleared()

        # Acquire the shared lock with the hook. Best-effort: if we can't
        # open the lock file (cache dir missing, etc.) skip the lock and
        # accept the small race window rather than dropping the flush.
        lock_fp = None
        try:
            os.makedirs(os.path.dirname(_TRACE_LOCK_FILE), exist_ok=True)
            lock_fp = open(_TRACE_LOCK_FILE, "w")
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        except OSError:
            lock_fp = None

        try:
            # 1) Read what's on disk and merge in what other writers added or
            # edited. A trace of another case at this path is not merged: the
            # write below replaces it, as a fresh configure() intends.
            entries = None
            try:
                with open(self._path) as f:
                    disk_data = json.load(f)
                if disk_data.get("case_id") == self._case_id:
                    entries = self._merged_for_write(disk_data.get("entries", []) or [])
            except (OSError, json.JSONDecodeError, ValueError, AttributeError):
                pass
            if entries is None:
                entries = list(self._entries)
            data_dict = {
                "schema_version": "2.0",
                "case_id": self._case_id,
                "entry_count": len(entries),
                "entries": entries,
            }

            data = json.dumps(data_dict, indent=2)

            # 3) Atomic write via temp + rename.
            dir_ = os.path.dirname(os.path.abspath(self._path))
            try:
                fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
                try:
                    with os.fdopen(fd, "w") as f:
                        f.write(data)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp, self._path)
                except Exception:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                    raise
            except OSError as e:
                _warn(f"trace flush failed ({self._path}): {e}")
                # Trace integrity is non-negotiable — bubble up so callers
                # (record_*, _log_tool, middleware) can surface a clear
                # ToolError instead of silently losing the entry.
                raise
            # 4) Append-only, hash-chained mirror. trace.json above is
            # read-merge-REWRITTEN per flush, so past entries stay mutable;
            # the .jsonl journal records each entry once, as first flushed,
            # chained to its predecessor — a reviewer can prove no journaled
            # entry was later altered or removed (verify_trace_chain).
            # Best-effort by contract: the mirror is an evidence layer on
            # top of the trace, never a reason to fail a record_*.
            try:
                self._mirror_append(data_dict.get("entries", []))
            except Exception as e:
                _warn(f"trace mirror append failed: {e}")
        finally:
            if lock_fp is not None:
                try:
                    fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
                lock_fp.close()

    def _merged_for_write(self, disk_entries: list) -> list:
        """Must be called under self._lock and the trace flock. The entries
        this flush writes: this log's own, plus those only on disk (another
        writer's), in time order. An entry both hold keeps the higher `_rev`,
        ours on a tie, and a newer disk copy updates ours in place, so this
        writer sees the other's edit. Another writer's new entries are
        written through but not taken into this log's list: the middleware
        tells a tool that logged itself from the growth of that list.
        Entries older than the case's newest clear are a dead run's residue
        and never come back (configure() applies the same rule on resume).
        Call ids cannot collide: every writer allocates them from the
        trace's shared counter."""
        marker_ts = read_clear_marker_ts(_case_dir_for_trace(self._path))
        ours = {_mirror_entry_id(e): e for e in self._entries}
        foreign: list = []
        for d in disk_entries:
            if not isinstance(d, dict):
                continue
            if marker_ts and not _ts_ge(d.get("ts"), marker_ts):
                continue
            mine = ours.get(_mirror_entry_id(d))
            if mine is None:
                foreign.append(d)
            elif int(d.get("_rev") or 0) > int(mine.get("_rev") or 0):
                mine.clear()
                mine.update(d)
                self._index_version += 1
                self._cached_index = None
        if not foreign:
            return list(self._entries)
        return sorted(list(self._entries) + foreign, key=_entry_order)

    # ── Hash-chained trace mirror ─────────────────────────────────────────────

    def _mirror_file(self) -> Optional[str]:
        if not self._path:
            return None
        base = self._path[:-5] if self._path.endswith(".json") else self._path
        return base + ".jsonl"

    def _mirror_init(self, path: str) -> None:
        """(Re)build mirror state from the existing journal. A corrupt tail
        is preserved as .corrupt-<ts> (evidence of the corruption) and the
        chain restarts fresh."""
        state = {"path": path, "ids": set(), "last_hash": "", "seq": 0,
                 "size": 0}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        rec = json.loads(line)
                        state["ids"].add(
                            _mirror_entry_id(rec.get("entry") or {}))
                        state["last_hash"] = rec.get("entry_hash", "")
                        state["seq"] = rec.get("seq", state["seq"] + 1)
                state["size"] = os.path.getsize(path)
            except (OSError, ValueError, KeyError) as e:
                _warn(f"trace mirror unreadable, rotating: {e}")
                try:
                    ts = datetime.datetime.now(datetime.timezone.utc
                                               ).strftime("%Y%m%dT%H%M%SZ")
                    os.replace(path, f"{path}.corrupt-{ts}")
                except OSError:
                    pass
                state = {"path": path, "ids": set(), "last_hash": "",
                         "seq": 0, "size": 0}
        self._mirror = state

    def _mirror_append(self, entries: list) -> None:
        """Must be called under self._lock (and inside the flock from
        _flush). Journals entries not yet mirrored, each chained to the
        previous line's hash. A journal that grew since this writer's own
        last append was extended by another writer of the trace: its tail
        is read again, so the chain continues from the real last line."""
        path = self._mirror_file()
        if path is None:
            return
        if (self._mirror["path"] != path or not os.path.exists(path)
                or os.path.getsize(path) != self._mirror.get("size")):
            self._mirror_init(path)
        st = self._mirror
        new = [e for e in entries if _mirror_entry_id(e) not in st["ids"]]
        if not new:
            return
        with open(path, "a", encoding="utf-8") as f:
            for e in new:
                canonical = _canonical_entry_json(e)
                h = _chain_hash(st["last_hash"], canonical)
                st["seq"] += 1
                f.write(json.dumps(
                    {"seq": st["seq"], "prev_hash": st["last_hash"],
                     "entry_hash": h, "entry": e},
                    ensure_ascii=False, default=str) + "\n")
                st["last_hash"] = h
                st["ids"].add(_mirror_entry_id(e))
            f.flush()
            os.fsync(f.fileno())
            st["size"] = os.fstat(f.fileno()).st_size

    # ── Record methods ────────────────────────────────────────────────────────

    def _require_configured(self, kind: str) -> None:
        """Raise if no trace path is set. Replaces the old warn-and-drop
        behaviour so callers can't silently lose entries when
        start_execution_log was skipped."""
        if self._path is None:
            raise RuntimeError(
                f"trace log not configured — cannot record {kind}. Call "
                f"misc.start_execution_log(case_id, output_path) at the start "
                f"of the investigation before any forensic tools."
            )

    def record_system_error(
        self,
        category: str,
        detail: str,
        input_call_ids: list[int] | None = None,
    ) -> int:
        """Loud-but-non-blocking system error: gate bug, dashboard probe
        failure, narration log failure, etc. Best-effort write — falls back
        to stderr on its own failure so we never throw an exception from a
        path that's already handling a failure."""
        with self._lock:
            if self._path is None:
                _warn(f"system_error pre-configure [{category}]: {detail[:200]}")
                return 0
            try:
                cid = self._next_id()
                entry: dict = {
                    "call_id": cid,
                    "type": "system_error",
                    "ts": _utcnow(),
                    "category": category,
                    "detail": detail[:2048],
                }
                if input_call_ids:
                    entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
                self._append_entry(entry)
                return cid
            except Exception as e:
                _warn(f"system_error log failed [{category}]: {e} | "
                      f"original: {detail[:200]}")
                return 0

    def record_trace_opened(self, detail: str) -> int:
        """The mark a session writes when it opens the trace: a self-test that
        recording works end to end, and where the session's entries begin.
        Not an error. Older traces carry it as a system_error with category
        ``trace_initialized``; readers accept both (``is_trace_opened``)."""
        with self._lock:
            self._require_configured("trace_opened")
            cid = self._next_id()
            self._append_entry({"call_id": cid, "type": "trace_opened",
                                "ts": _utcnow(), "detail": str(detail)[:512]})
            return cid

    def record_budget_wrapup(
        self,
        trigger: str,
        turn: int = 0,
        *,
        allow_synthesize_escape: "bool | None" = None,
    ) -> int:
        """Stamp a system-injected budget wrap-up into the trace.

        Written ONLY by the agent loop when it forces close-out near the turn
        or wall-clock budget (agent.loop._record_budget_wrapup_marker). The
        report gate (reason.pre_report_check) keys off this entry to relax
        unresolved *content-quality* blockers to documented limitations so an
        honest partial report can still be written instead of the deadlock
        that loses the deliverable entirely.

        ``allow_synthesize_escape`` must be True for the close-out gates
        (reason.synthesize outside Report; pre_report blocker relaxation) to
        honour the wrap-up. Exploration/belief stalls with an open coverage
        ledger stamp False so an early exit with open coverage cannot synthesize
        a hollow report. Default (None) derives from the trigger: hard stops
        (wall_clock / turn_budget / llm_deadline / llm_transport) permit close-out, soft
        triggers (progress_stall / quiet) do not — this keeps trigger and
        flag consistent for every caller.

        There is no MCP tool that emits ``type="budget_wrapup"`` — the agent
        cannot forge this entry to trip the relaxation early. Best-effort:
        returns 0 without raising if the log is not yet configured, so a
        wrap-up injected before start_execution_log never crashes the loop."""
        if allow_synthesize_escape is None:
            allow_synthesize_escape = trigger in (
                "wall_clock", "turn_budget", "llm_deadline", "llm_transport")
        with self._lock:
            if self._path is None:
                return 0
            try:
                cid = self._next_id()
                entry: dict = {
                    "call_id": cid,
                    "type": "budget_wrapup",
                    "ts": _utcnow(),
                    "trigger": trigger,
                    "turn": int(turn),
                    "allow_synthesize_escape": bool(allow_synthesize_escape),
                }
                self._append_entry(entry)
                return cid
            except Exception as e:
                _warn(f"budget_wrapup log failed [{trigger}]: {e}")
                return 0

    def record_curiosity_probe(
        self,
        rationale: str,
        seeded_by: str = "",
        input_call_ids: list[int] | None = None,
    ) -> int:
        """Log an exploratory 'curiosity_probe' — a read-only look the agent
        chose ITSELF, outside directives.priority_tools.

        Budget-gated by the caller (tools/_gates/curiosity_budget.py); this
        method only writes the entry. A probe carries NO evidentiary weight on
        its own: to support a finding its call_id must flow into reason.* /
        record_finding via input_call_ids, where the finding gates apply. So a
        probe can widen what gets looked at without ever loosening a gate.

        rationale  — the hunch + what would confirm or kill it (the audit hook).
        seeded_by  — hypothesis_id of the reason.hypothesize(mode="absence")
                     that motivated the probe, if any.
        """
        with self._lock:
            self._auto_recover()
            self._require_configured("curiosity_probe")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "curiosity_probe",
                "ts": _utcnow(),
                "probe_rationale": rationale,
                "seeded_by": seeded_by,
            }
            # Never an orphan in the causal DAG: default lineage to the most
            # recent dair_assess (mirrors tool_call / narration behavior).
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            elif self._last_dair_cid:
                entry["input_call_ids"] = [self._last_dair_cid]
            self._append_entry(entry)
            return cid

    def record_tool_call(
        self,
        cmd: str,
        success: bool,
        truncated: bool,
        retries: int,
        exit_code: int,
        stderr: str = "",
        elapsed_seconds: float = 0.0,
        stdout_excerpt: str = "",
        timed_out: bool = False,
        input_call_ids: list[int] | None = None,
        stdout_file: str = "",
        failure_class: str = "",
        evidence_ref: str = "",
        output_hash: str = "",
        vmdk_snapshot_warning: str = "",
        interrupted: bool = False,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"tool_call: {cmd[:80]}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "tool_call",
                "ts": _utcnow(),
                "cmd": cmd,
                "success": success,
                "truncated": truncated,
                "retries": retries,
                "exit_code": exit_code,
                "elapsed_seconds": elapsed_seconds,
                "stderr": stderr[:512] if stderr else "",
            }
            # Machine-readable failure taxonomy (gate_refusal / analyst_error /
            # tool_error) so trace consumers can weigh real tool defects
            # separately from protective refusals and bad-argument calls.
            # Callers that don't classify (executor self-logs on nonzero exit)
            # default to tool_error, so genuine tool errors are not left
            # unclassified while gate refusals are tagged.
            if not failure_class and not success:
                failure_class = "tool_error"
            if failure_class:
                entry["failure_class"] = failure_class
            # Stamp the invoking MCP tool (from the middleware contextvar) unless
            # the cmd already self-identifies as a "<py>:tool" baseline entry.
            _mcp = current_mcp_tool.get()
            if _mcp and not cmd.startswith("<py>:"):
                entry["mcp_tool"] = _mcp
            _aid = current_action_id.get()
            if _aid:
                entry["action_id"] = _aid
            # Which evidence image/mount the call ran against (multi-host
            # traces). Explicit param wins; else the middleware contextvar.
            _eref = evidence_ref or current_evidence_ref.get()
            if _eref:
                entry["evidence_ref"] = str(_eref)[:256]
            if timed_out:
                entry["timed_out"] = True
            if interrupted:
                # The run's own stop cut the call short: no failure of the tool.
                entry["interrupted"] = True
            if stdout_excerpt:
                entry["stdout_excerpt"] = stdout_excerpt[:TRACE_EXCERPT_CHARS]
                # Text in the output written for an automated reader is
                # named on the entry, so a finding that cites this call can
                # be checked against it (tools/_gates/instruction_text_grounding).
                try:
                    from core.instruction_text import find_instruction_like
                    hits = find_instruction_like(stdout_excerpt[:400_000])
                except Exception:  # noqa: BLE001 - a scan must never break logging
                    hits = []
                if hits:
                    entry["instruction_like_text"] = hits
            if stdout_file:
                entry["stdout_file"] = stdout_file
            # Digest of the FULL pre-truncation output: lets a reviewer
            # verify the quoted excerpt/spill file against what the tool
            # actually produced (the excerpt alone is unverifiable).
            if output_hash:
                entry["output_hash"] = output_hash
            # A base VMDK shadowed by snapshot deltas is frozen at snapshot
            # creation — stamped here so the temporal_negative_grounding gate
            # detects a frozen-base read from the trace directly, rather than
            # re-parsing (and mis-splitting) the command string.
            if vmdk_snapshot_warning:
                entry["vmdk_snapshot_warning"] = str(vmdk_snapshot_warning)[:512]
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            # Protocol audit: a tool_call must be preceded by an active DAIR batch.
            # Scan the last 20 entries; if no dair_call is present (and the log is
            # not empty), flag the tool_call as a protocol violation. The flag is
            # surfaced in trace.json and trace.md so silent skips are auditable.
            if self._entries:
                window = self._entries[-20:]
                has_recent_dair = any(e.get("type") == "dair_call" for e in window)
                if not has_recent_dair:
                    # Cold-start grace: the mandated pre-plan recon batch (hash
                    # verify, image mount, hive reads) legitimately runs before
                    # the first dair_assess. Only flag a missing-DAIR violation
                    # once the investigation has actually engaged DAIR at least
                    # once — i.e. a dair_call exists earlier in the trace but has
                    # aged out of the 20-entry window. Flagging pre-DAIR recon
                    # was a self-contradiction: the workflow mandates those reads.
                    ever_had_dair = any(
                        e.get("type") == "dair_call" for e in self._entries
                    )
                    if ever_had_dair:
                        entry["protocol_violation"] = "no_active_dair_batch"
            self._append_entry(entry)
            return entry["call_id"]

    def record_reason_call(
        self,
        tool: str,
        success: bool,
        conclusion: str,
        directives: dict,
        evidence_audit: list | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        hypothesis_id: str = "",
        inputs: dict | None = None,
        input_call_ids: list[int] | None = None,
        error: str = "",
        finish_reason: str = "",
        reasoning_tokens: int = 0,
        gate: str = "",
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"reason_call: {tool}")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "reason_call",
                "ts": _utcnow(),
                "tool": tool,
                "success": success,
                "conclusion": conclusion or "",
                "directives": directives,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            }
            if evidence_audit:
                entry["evidence_audit"] = evidence_audit
            if hypothesis_id:
                entry["hypothesis_id"] = hypothesis_id
            if inputs:
                entry["inputs"] = inputs
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            # Failure diagnostics — previously dropped, so empty gpt-5-mini
            # responses looked like silent 0-token fails.
            if error:
                entry["error"] = str(error)[:2000]
            if finish_reason:
                entry["finish_reason"] = str(finish_reason)[:64]
            if reasoning_tokens:
                entry["reasoning_tokens"] = int(reasoning_tokens)
            if gate:
                entry["gate"] = str(gate)[:80]
            self._append_entry(entry)
            return cid

    def update_reason_call(self, call_id: int, **fields) -> bool:
        """Stamp additional fields onto an already-recorded reason_call entry
        (e.g. `sub_hypotheses` parsed from the conclusion, or post-processed
        directives). Returns True if the entry was found and updated. Used by
        reason_hypothesize to attach per-hypothesis records after the model
        round-trip. Bumps the index version so the next index() rebuild sees the
        new fields. Non-None values only — never clobbers a field with None."""
        if not call_id:
            return False
        with self._lock:
            for e in self._entries:
                if e.get("call_id") == call_id and e.get("type") == "reason_call":
                    for k, v in fields.items():
                        if v is not None:
                            e[k] = v
                    _touched(e)
                    self._index_version += 1
                    self._flush()
                    return True
        return False

    # Entry types that are the model's own actions. Bookkeeping entries
    # (call_initiated, deferred_intent, call_abandoned, system_error …) used
    # to fill the DAIR window: 20 raw entries were only 7 tool calls, so a
    # cold DAIR window came back every second batch.
    ACTION_TYPES = frozenset({
        "tool_call", "reason_call", "dair_call", "finding", "self_correction",
        "investigation_narration", "curiosity_probe",
    })

    def recent_actions(self, n: int) -> list[dict]:
        """The entries of the last ``n`` model actions. Entries sharing an
        ``action_id`` came from one tool call and count as one action."""
        with self._lock:
            acts = [e for e in self._entries if e.get("type") in self.ACTION_TYPES]
        if n <= 0:
            return acts
        out: list[dict] = []
        keys: list[object] = []
        for e in reversed(acts):
            k = action_key(e)
            if k not in keys:
                if len(keys) == n:
                    break
                keys.append(k)
            out.append(e)
        out.reverse()
        return out

    def annotate_tool_call(self, call_id: int, **fields) -> bool:
        """Stamp additional fields onto an already-recorded tool_call entry
        (e.g. `coverage_window` = {start, end} of a parsed log, so the
        negative_completeness gate can tell whether a source actually covers a
        claim's time window). Mirrors update_reason_call: non-None values only,
        bumps the index version. Used by the log-parsing wrappers (ez.evtxecmd,
        misc.chainsaw_hunt) after they compute a log's event time-range."""
        if not call_id:
            return False
        with self._lock:
            for e in self._entries:
                if e.get("call_id") == call_id and e.get("type") == "tool_call":
                    for k, v in fields.items():
                        if v is not None:
                            e[k] = v
                    _touched(e)
                    self._index_version += 1
                    self._flush()
                    return True
        return False

    def record_self_correction(
        self,
        trigger: str,
        prior_belief: str,
        new_belief: str,
        evidence: str = "",
        linked_call_id: int = 0,
        input_call_ids: list[int] | None = None,
    ) -> int:
        """Record a first-class self-correction event in the trace.

        trigger: one of evaluate_challenged, dair_max_pass_cap, tool_failure_recovery,
                 hypothesis_refuted, verification_challenge_refuted, gate_refusal.
        """
        with self._lock:
            self._auto_recover()
            self._require_configured(f"self_correction: {trigger}")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "self_correction",
                "ts": _utcnow(),
                "trigger": trigger,
                "prior_belief": prior_belief,
                "new_belief": new_belief,
                "evidence": evidence,
                "linked_call_id": linked_call_id,
            }
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            self._append_entry(entry)
            return cid

    def record_call_initiated(
        self,
        tool: str,
        backend: str,
        inputs: dict,
        input_call_ids: list[int] | None = None,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"call_initiated: {tool}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "call_initiated",
                "ts": _utcnow(),
                "tool": tool,
                "backend": backend,
                "inputs": inputs,
            }
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            self._append_entry(entry)
            return entry["call_id"]

    def record_call_abandoned(
        self,
        tool: str,
        reason: str,
        input_call_ids: list[int] | None = None,
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"call_abandoned: {tool}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "call_abandoned",
                "ts": _utcnow(),
                "tool": tool,
                "reason": reason,
            }
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            self._append_entry(entry)
            return entry["call_id"]

    # ── Deferred intents (DAIR-batch recovery) ─────────────────────────────

    def _deferred_open_locked(self) -> list[dict]:
        return [
            e for e in self._entries
            if e.get("type") == "deferred_intent"
            and e.get("status") in ("open", "prescribed")
        ]

    def open_deferred_intents(self) -> list[dict]:
        with self._lock:
            self._auto_recover()
            return list(self._deferred_open_locked())

    def deferred_backlog_status(self) -> dict:
        """Return open/prescribed counts and latch state for the gate/UI."""
        from core.deferred_intents import (
            DEFERRED_BACKLOG_CAP,
            DEFERRED_BACKLOG_HYSTERESIS,
        )
        with self._lock:
            self._auto_recover()
            open_n = sum(
                1 for e in self._entries
                if e.get("type") == "deferred_intent"
                and e.get("status") == "open"
            )
            prescribed_n = sum(
                1 for e in self._entries
                if e.get("type") == "deferred_intent"
                and e.get("status") == "prescribed"
            )
            latched = bool(getattr(self, "_deferred_latch", False))
            if open_n >= DEFERRED_BACKLOG_CAP:
                latched = True
                self._deferred_latch = True
            return {
                "open": open_n,
                "prescribed": prescribed_n,
                "latched": latched,
                "cap": DEFERRED_BACKLOG_CAP,
                "hysteresis": DEFERRED_BACKLOG_HYSTERESIS,
                "latch_blocks": int(getattr(self, "_deferred_latch_blocks", 0)),
                "latch_assesses": int(
                    getattr(self, "_deferred_latch_assesses", 0)),
            }

    def record_deferred_intent(
        self,
        tool: str,
        args: dict | None,
        blocked_reason: str,
        input_call_ids: list[int] | None = None,
    ) -> dict:
        """Record or refresh a deferred forensic intent.

        Returns a result dict:
          ``{call_id, created|refreshed|unqueued, latched, open_count, ...}``
        New unique intents are refused (unqueued) while the latch is already
        engaged, so the backlog cannot grow without bound.
        """
        from core.deferred_intents import (
            DEFERRED_BACKLOG_CAP,
            args_fingerprint,
            args_summary,
            infer_kind,
            mcp_tool_to_dotted,
        )
        with self._lock:
            self._auto_recover()
            self._require_configured(f"deferred_intent: {tool}")
            fp = args_fingerprint(tool, args)
            open_entries = [
                e for e in self._entries
                if e.get("type") == "deferred_intent"
                and e.get("status") in ("open", "prescribed")
            ]
            for e in open_entries:
                if e.get("fingerprint") == fp:
                    e["block_count"] = int(e.get("block_count") or 1) + 1
                    e["last_blocked_ts"] = _utcnow()
                    e["blocked_reason"] = blocked_reason[:300]
                    _touched(e)
                    if getattr(self, "_deferred_latch", False):
                        self._deferred_latch_blocks = int(
                            getattr(self, "_deferred_latch_blocks", 0)) + 1
                    open_n = sum(
                        1 for x in self._entries
                        if x.get("type") == "deferred_intent"
                        and x.get("status") == "open")
                    if open_n >= DEFERRED_BACKLOG_CAP:
                        self._deferred_latch = True
                    return {
                        "call_id": e["call_id"],
                        "action": "refreshed",
                        "fingerprint": fp,
                        "block_count": e["block_count"],
                        "latched": bool(getattr(self, "_deferred_latch", False)),
                        "open_count": open_n,
                    }

            open_only = [e for e in open_entries if e.get("status") == "open"]
            latched = bool(getattr(self, "_deferred_latch", False))
            if latched or len(open_only) >= DEFERRED_BACKLOG_CAP:
                self._deferred_latch = True
                self._deferred_latch_blocks = int(
                    getattr(self, "_deferred_latch_blocks", 0)) + 1
                # Audit the refused enqueue without growing the open queue.
                cid = self._next_id()
                self._append_entry({
                    "call_id": cid,
                    "type": "deferred_intent",
                    "ts": _utcnow(),
                    "tool": tool,
                    "priority_tool": mcp_tool_to_dotted(tool),
                    "fingerprint": fp,
                    "args_summary": args_summary(args),
                    "blocked_reason": blocked_reason[:300],
                    "status": "unqueued",
                    "kind": infer_kind(tool, args),
                    "block_count": 1,
                    "note": "backlog latch — not enqueued; call dair_assess",
                })
                return {
                    "call_id": cid,
                    "action": "unqueued",
                    "fingerprint": fp,
                    "latched": True,
                    "open_count": len(open_only),
                }

            cid = self._next_id()
            entry = {
                "call_id": cid,
                "type": "deferred_intent",
                "ts": _utcnow(),
                "tool": tool,
                "priority_tool": mcp_tool_to_dotted(tool),
                "fingerprint": fp,
                "args_summary": args_summary(args),
                "blocked_reason": blocked_reason[:300],
                "status": "open",
                "kind": infer_kind(tool, args),
                "block_count": 1,
                "last_blocked_ts": _utcnow(),
            }
            if input_call_ids:
                entry["input_call_ids"] = [
                    int(c) for c in input_call_ids if c]
            if self._last_dair_cid:
                entry["parent_dair_cid"] = self._last_dair_cid
            self._append_entry(entry)
            open_n = len(open_only) + 1
            if open_n >= DEFERRED_BACKLOG_CAP:
                self._deferred_latch = True
                self._deferred_latch_blocks = 0
                self._deferred_latch_assesses = 0
            return {
                "call_id": cid,
                "action": "created",
                "fingerprint": fp,
                "block_count": 1,
                "latched": bool(getattr(self, "_deferred_latch", False)),
                "open_count": open_n,
            }

    def apply_deferred_dispositions(
        self,
        dispositions: list[dict] | None,
        dair_cid: int = 0,
    ) -> dict:
        """Apply DAIR promote/dismiss/keep decisions. Returns summary + promoted tools."""
        from core.deferred_intents import DEFERRED_BACKLOG_HYSTERESIS
        dispositions = dispositions or []
        promoted: list[str] = []
        applied: list[dict] = []
        with self._lock:
            self._auto_recover()
            by_id = {
                e.get("call_id"): e for e in self._entries
                if e.get("type") == "deferred_intent"
            }
            for d in dispositions:
                if not isinstance(d, dict):
                    continue
                cid = d.get("call_id")
                try:
                    key = int(cid)
                except (TypeError, ValueError):
                    continue
                action = (d.get("action") or "").strip().lower()
                note = str(d.get("note") or "")[:300]
                e = by_id.get(key)
                if not e or e.get("status") not in ("open", "prescribed"):
                    continue
                if action in ("promote", "dismiss", "keep"):
                    _touched(e)
                if action == "promote":
                    e["status"] = "prescribed"
                    e["prescribed_by_dair_cid"] = dair_cid or self._last_dair_cid
                    e["disposition_note"] = note
                    pt = e.get("priority_tool") or e.get("tool")
                    if pt and pt not in promoted:
                        promoted.append(pt)
                    applied.append({"call_id": e["call_id"], "action": "promote"})
                elif action == "dismiss":
                    e["status"] = "dismissed"
                    e["disposition_note"] = note or "dismissed by dair_assess"
                    applied.append({"call_id": e["call_id"], "action": "dismiss"})
                elif action == "keep":
                    e["disposition_note"] = note or "kept open"
                    applied.append({"call_id": e["call_id"], "action": "keep"})
            if getattr(self, "_deferred_latch", False):
                self._deferred_latch_assesses = int(
                    getattr(self, "_deferred_latch_assesses", 0)) + 1
            open_n = sum(
                1 for e in self._entries
                if e.get("type") == "deferred_intent"
                and e.get("status") == "open")
            if open_n <= DEFERRED_BACKLOG_HYSTERESIS:
                self._deferred_latch = False
                self._deferred_latch_blocks = 0
                self._deferred_latch_assesses = 0
            return {
                "applied": applied,
                "promoted_tools": promoted,
                "open_count": open_n,
                "latched": bool(getattr(self, "_deferred_latch", False)),
            }

    def resolve_deferred_intent(self, tool: str, args: dict | None = None) -> int | None:
        """Mark matching open/prescribed intent resolved after a successful tool run."""
        from core.deferred_intents import args_fingerprint, mcp_tool_to_dotted
        with self._lock:
            self._auto_recover()
            fp = args_fingerprint(tool, args)
            dotted = mcp_tool_to_dotted(tool)
            for e in self._entries:
                if e.get("type") != "deferred_intent":
                    continue
                if e.get("status") not in ("open", "prescribed"):
                    continue
                if e.get("fingerprint") == fp or e.get("tool") == tool \
                        or e.get("priority_tool") == dotted:
                    e["status"] = "resolved"
                    e["resolved_ts"] = _utcnow()
                    _touched(e)
                    return e.get("call_id")
            return None

    def relieve_deferred_backlog(
        self,
        target: int | None = None,
        reason: str = "backlog_pressure",
    ) -> dict:
        """Auto-dismiss lowest-priority open intents until open ≤ target.

        Curiosity-tagged intents are dismissed first, then lowest block_count,
        then oldest. Used after dair_assess fails to relieve a latched backlog
        and as the ultimate deadlock escape.
        """
        from core.deferred_intents import DEFERRED_BACKLOG_HYSTERESIS
        if target is None:
            target = DEFERRED_BACKLOG_HYSTERESIS
        with self._lock:
            self._auto_recover()
            open_entries = [
                e for e in self._entries
                if e.get("type") == "deferred_intent"
                and e.get("status") == "open"
            ]
            # Dismiss curiosity first, then low insistence, then oldest.
            open_entries.sort(
                key=lambda e: (
                    0 if e.get("kind") == "curiosity" else 1,
                    int(e.get("block_count") or 1),
                    int(e.get("call_id") or 0),
                )
            )
            dismissed: list[int] = []
            while len(open_entries) > target:
                e = open_entries.pop(0)
                e["status"] = "auto_dismissed"
                e["disposition_note"] = reason[:300]
                _touched(e)
                dismissed.append(e["call_id"])
            open_n = sum(
                1 for e in self._entries
                if e.get("type") == "deferred_intent"
                and e.get("status") == "open")
            if open_n <= DEFERRED_BACKLOG_HYSTERESIS:
                self._deferred_latch = False
                self._deferred_latch_blocks = 0
                self._deferred_latch_assesses = 0
            # Auditable event
            if dismissed:
                self._append_entry({
                    "call_id": self._next_id(),
                    "type": "deferred_backlog_relieve",
                    "ts": _utcnow(),
                    "reason": reason,
                    "dismissed_call_ids": dismissed,
                    "open_count": open_n,
                })
            return {
                "dismissed": dismissed,
                "open_count": open_n,
                "latched": bool(getattr(self, "_deferred_latch", False)),
                "reason": reason,
            }

    def deadlock_escape_deferred_intents(self) -> dict:
        """Last-resort: clear the latch by auto-dismissing down to hysteresis.

        Called when the agent ignores forced dair_assess nudges and would
        otherwise deadlock behind a full backlog.
        """
        result = self.relieve_deferred_backlog(
            reason="deadlock_escape — agent did not dispose backlog")
        try:
            self.record_system_error(
                "deferred_deadlock_escape",
                f"auto-dismissed {len(result.get('dismissed') or [])} "
                f"deferred intent(s); open={result.get('open_count')}",
            )
        except Exception:
            pass
        return result

    def record_dair_call(
        self,
        current_phase: str,
        phase_rationale: str,
        transition_recommended: bool,
        next_phase: str,
        transition_rationale: str,
        stack_action: str,
        investigation_focus: str,
        verification_satisfied: bool = False,
        verification_challenges: list = None,
        recommended_actions: list = None,
        directives: dict = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        inputs: dict | None = None,
        input_call_ids: list[int] | None = None,
        pending_pivots: list[str] | None = None,
        candidate_pivots: list[dict] | None = None,
        progress: dict | None = None,
        progress_snapshot: dict | None = None,
        work_order_enforced: str = "",
    ) -> int:
        with self._lock:
            self._auto_recover()
            self._require_configured(f"dair_call: phase={current_phase}")
            # Apply the transition BEFORE creating the entry so that
            # _append_entry stamps the dair_call entry itself with its
            # post-transition phase. Subsequent record_* calls inherit too.
            self._apply_dair_transition(
                current_phase=current_phase,
                stack_action=stack_action,
                next_phase=next_phase,
                transition_rationale=transition_rationale,
                verification_satisfied=verification_satisfied,
            )
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "dair_call",
                "ts": _utcnow(),
                "current_phase": current_phase,
                "phase_rationale": phase_rationale,
                "transition_recommended": transition_recommended,
                "next_phase": next_phase,
                "transition_rationale": transition_rationale,
                "stack_action": stack_action,
                "investigation_focus": as_text(investigation_focus),
                "verification_satisfied": verification_satisfied,
                "verification_challenges": verification_challenges or [],
                "recommended_actions": recommended_actions or [],
                "directives": directives or {},
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            }
            if inputs:
                entry["inputs"] = inputs
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            if pending_pivots:
                entry["pending_pivots"] = [str(h) for h in pending_pivots if h]
            if candidate_pivots:
                entry["candidate_pivots"] = [
                    p for p in candidate_pivots
                    if isinstance(p, dict) and p.get("value")
                ]
            # Which enforcement valve rewrote this cycle's work order /
            # transition ("refuse_latch", "report_entry_coverage", …).
            # Without this the trace cannot distinguish a model-chosen
            # transition from a valve-forced one — exactly the blind spot
            # that hid the refuse-latch Report jump.
            if work_order_enforced:
                entry["work_order_enforced"] = str(work_order_enforced)[:200]
            # progress: the ProgressDelta.to_dict() computed by
            # core.progress_signature for THIS cycle — explainable
            # (reasons/changed_dimensions), used by the productive-stall
            # valve and (later) wrap-up/refuse-latch decisions.
            # progress_snapshot: the ProgressSnapshot.to_dict() this delta was
            # computed against — stored so the NEXT dair_call can diff
            # against it without re-deriving state. Excluded from the value
            # returned to the LLM (irrelevant/bulky); trace-only.
            if progress:
                entry["progress"] = progress
            if progress_snapshot:
                entry["progress_snapshot"] = progress_snapshot
            self._append_entry(entry)
            self._last_dair_cid = cid
            return cid

    def record_finding(
        self,
        description: str,
        confidence: str,
        source: str = "",
        linked_call_id: int = 0,
        tested_hypothesis_id: str = "",
        gate_metadata: dict | None = None,
        input_call_ids: list[int] | None = None,
        host: str = "",
    ) -> int:
        """Record a finding entry.

        host: which system/host the finding belongs to (evidence-table hostname,
        e.g. "WS01", "DC01"). Structural field for multi-host cases — the
        per-host disposition table and killchain per_host buckets group on it.

        gate_metadata: optional dict of explicit foreign keys stamped by the
        record_finding gates — gated_by_evaluate_call_id,
        gated_by_confidence_call_id, gated_by_cite_check_call_id,
        gated_by_hypothesize_call_id, validated_techniques. Stored on the
        entry so consumers (Process view, accuracy report, synthesize) can
        traverse the audit chain via real call_ids instead of inferring
        links from substring matches.
        input_call_ids: agent-declared upstream lineage — list of
        _atlas_call_id values that informed this finding (complements
        linked_call_id which is 1:1 evidence; this is N:M lineage).
        """
        with self._lock:
            self._auto_recover()
            self._require_configured(f"finding: {description[:60]}")
            cid = self._next_id()
            entry: dict = {
                "call_id": cid,
                "type": "finding",
                "ts": _utcnow(),
                "description": description,
                "confidence": confidence,
                "source": source,
                "linked_call_id": linked_call_id,
            }
            if host:
                entry["host"] = str(host)[:128]
            if tested_hypothesis_id:
                entry["tested_hypothesis_id"] = tested_hypothesis_id
            if input_call_ids:
                entry["input_call_ids"] = [int(c) for c in input_call_ids if c]
            if gate_metadata:
                for k, v in gate_metadata.items():
                    if v:  # skip empty / 0 — keeps entries small
                        entry[k] = v
            self._append_entry(entry)
            return cid

    def record_agent_message(
        self,
        content: str,
        input_call_ids: list[int] | None = None,
        kind: str = "",
    ) -> int:
        """``kind`` marks a narration subtype. ``"disposition"`` is a record
        of work done and its empty outcome, kept apart from findings so that
        documenting a search never reads as a conclusion about the case."""
        content = as_text(content)
        with self._lock:
            self._auto_recover()
            self._require_configured(f"agent_message: {content[:60]}")
            entry: dict = {
                "call_id": self._next_id(),
                "type": "investigation_narration",
                "ts": _utcnow(),
                "content": content[:2000],
            }
            if kind:
                entry["kind"] = kind
            if input_call_ids:
                entry["input_call_ids"] = input_call_ids
            self._append_entry(entry)
            return entry["call_id"]

    # ── Read / export ─────────────────────────────────────────────────────────

    def to_json(self) -> dict:
        # Must be called under self._lock when used from _flush().
        return {
            "schema_version": "2.0",
            "case_id": self._case_id,
            "entry_count": len(self._entries),
            "entries": list(self._entries),  # snapshot
        }

    def to_markdown(self) -> str:
        with self._lock:
            return _render_entries(self._case_id, list(self._entries))

    def export(self, path: str) -> dict:
        """Write JSON and Markdown to <path>.json and <path>.md.

        Falls back to reading the flushed analysis JSON file when the in-memory
        log is empty — handles MCP server restarts mid-investigation where the
        singleton state is lost but the on-disk file survives.

        Returns {"entry_count": int, "json_wrote": bool, "md_wrote": bool}.
        """
        with self._lock:
            self._auto_recover()
            data = self.to_json()
            fallback_path = self._path

        if data["entry_count"] == 0 and fallback_path:
            try:
                with open(fallback_path) as f:
                    data = json.load(f)
            except OSError as e:
                _warn(f"export fallback read failed ({fallback_path}): {e}")
            except (json.JSONDecodeError, ValueError) as e:
                _warn(f"export fallback file corrupted ({fallback_path}): {e}")

        entry_count = data.get("entry_count", 0)
        json_ok = md_ok = False
        try:
            with open(path + ".json", "w") as f:
                json.dump(data, f, indent=2)
            json_ok = True
        except OSError as e:
            _warn(f"export JSON write failed ({path}.json): {e}")
        try:
            with open(path + ".md", "w") as f:
                f.write(_render_entries(data.get("case_id"), data.get("entries", [])))
            md_ok = True
        except OSError as e:
            _warn(f"export MD write failed ({path}.md): {e}")

        return {
            "entry_count": entry_count,
            "json_wrote": json_ok,
            "md_wrote": md_ok,
        }


log = ExecutionLog()  # module-level singleton


def case_trace_document(case_dir: str | os.PathLike,
                        suffix: str = "_trace.json") -> Optional[str]:
    """The case's trace document under analysis/: the one its case id names
    (the name a run writes, core.paths.detect_case_id), else the newest
    written. One choice for every reader that does not hold the live log,
    so a second document beside it (another case id, a copy) is never read
    as this case's trace. A case with no document of its own is read from
    the newest one there is: one foreign run at most, never two merged."""
    import glob
    analysis = os.path.join(str(case_dir), "analysis")
    docs = glob.glob(os.path.join(glob.escape(analysis), "*" + suffix))
    if not docs:
        return None
    try:
        from core.paths import detect_case_id
        named = os.path.join(analysis, detect_case_id(case_dir) + suffix)
        if os.path.isfile(named):
            return named
    except Exception:  # noqa: BLE001 - the newest document still answers
        pass

    def mtime(p: str) -> float:
        try:
            return os.path.getmtime(p)
        except OSError:
            return 0.0
    # Equal times (a coarse clock, two writes in one tick) fall back to the
    # name order, so the choice never depends on the order the file system
    # lists the documents in.
    return max(sorted(docs), key=mtime)


def _trace_entries_on_disk(case_root: str) -> Optional[list[dict]]:
    """The entries of the case's trace (case_trace_document), None when it
    has none. The document (``<CASE>_trace.json``) is read rather than its
    ``.jsonl`` mirror: the mirror journals each entry once, before the
    annotations a call gets afterwards (its arguments, how much of its
    result was shown)."""
    doc = case_trace_document(case_root)
    mirror = None if doc else case_trace_document(case_root, "_trace.jsonl")
    if not doc and not mirror:
        return None
    out: list[dict] = []
    if doc:
        try:
            with open(doc, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return out
        entries = data.get("entries") if isinstance(data, dict) else data
        return [e for e in entries or [] if isinstance(e, dict)]
    try:
        with open(mirror, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                e = row.get("entry") if isinstance(row, dict) and isinstance(row.get("entry"), dict) else row
                if isinstance(e, dict):
                    out.append(e)
    except OSError:
        pass
    return out


def trace_tool_calls(case_dir: str | os.PathLike) -> Optional[list[dict]]:
    """The tool calls a case's trace holds, oldest first; None when the case
    has no trace. The live log when it is this case's (it holds the trace and
    what this process recorded since), the trace on disk otherwise. Entries
    from before the case's last clear belong to a dead run and are left out,
    as configure() leaves them out."""
    root = os.path.realpath(str(case_dir))
    live = log.trace_path()
    if live and os.path.realpath(_case_dir_for_trace(live)) == root:
        with log._lock:
            entries: Optional[list[dict]] = list(log._entries)
    else:
        entries = _trace_entries_on_disk(root)
        if entries is None:
            return None
        marker = read_clear_marker_ts(root)
        if marker:
            entries = [e for e in entries if _ts_ge(e.get("ts"), marker)]
    return [e for e in entries or [] if e.get("type") == "tool_call"]
