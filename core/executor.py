"""Safe subprocess executor for SIFT forensic tools."""
import os
import re
import subprocess
import shlex
import signal
import threading
import time
import asyncio
from collections import deque
from typing import Any
from .paths import (OUTPUT_CAP, MAX_TOOL_OUTPUT_LINES, assert_output_safe,
                    DEFAULT_TIMEOUT, VOL_TIMEOUT, resolve_spill_dir,
                    spill_file_path)

_TRUNCATION_FOOTER = (
    "\n[TRUNCATED — {n} lines omitted. Use a targeted follow-up query "
    "with focus_paths or focus_pids to retrieve specific records.]\n"
)

# Read size for streaming subprocess pipes.
_CHUNK = 65536

# Matches Volatility 3 progress lines: "\rProgress:  33.01\t\tdescription\r"
_PROGRESS_RE = re.compile(r"^Progress:\s+[\d.]+\t", re.MULTILINE)

# Comparison/search tools use exit code 1 to report a *result*, not an error:
# cmp/diff exit 1 = "files differ", grep family exit 1 = "no match". Counting
# these as tool failures inflated the reviewer's failure rate and tripped the
# stall detector's high_failure_rate on healthy runs. Only exit 1 is expected; exit ≥2 from these tools is genuine trouble.
_EXPECTED_NONZERO_VERBS = frozenset(
    {"cmp", "diff", "grep", "egrep", "fgrep", "zgrep", "zdiff",
     # ngrep is the grep family for packets and keeps its convention: exit 1
     # is "no packet matched", which for a capture search is a result a
     # negative finding may cite, not a broken call.
     "ngrep"})


# Programs that only wrap the real one. ``sudo ngrep`` is ngrep, and the
# exit-code conventions belong to ngrep, not to sudo.
_WRAPPER_VERBS = frozenset({"sudo", "doas", "env", "timeout", "nice", "ionice", "stdbuf"})
# Per wrapper, the options that consume the following word.
_WRAPPER_ARG_OPTS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-p", "-C", "-h", "-r", "-t", "-U", "-D", "-T"}),
    "doas": frozenset({"-u", "-C"}),
    "nice": frozenset({"-n"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "env": frozenset({"-u", "-C", "-S"}),
    "timeout": frozenset({"-s", "-k"}),
}


def _cmd_verb(cmd: Any) -> str:
    """The program a command runs, seen through its wrappers: ``sudo -n
    ngrep``, ``timeout 300 tcpdump`` and ``env X=1 zeek`` name ngrep,
    tcpdump and zeek."""
    if isinstance(cmd, list):
        parts = [str(p) for p in cmd]
    elif isinstance(cmd, str) and cmd:
        parts = cmd.split()
    else:
        return ""
    i = 0
    while i < len(parts):
        word = os.path.basename(parts[i])
        if word not in _WRAPPER_VERBS:
            return word
        arg_opts = _WRAPPER_ARG_OPTS.get(word, frozenset())
        i += 1
        while i < len(parts) and (parts[i].startswith("-")
                                  or (word == "env" and "=" in parts[i])):
            if parts[i] in arg_opts:
                i += 1
            i += 1
        if word == "timeout" and i < len(parts):
            i += 1  # the duration
    return ""


def _memguard_preexec():
    """Return a preexec_fn that caps the child's address space, or None.

    Controlled by ATLAS_TOOL_MEM_CAP_MB. When set (>0), each spawned tool child
    gets an RLIMIT_AS ceiling, so a memory-hungry tool (Volatility3 / YARA over
    a multi-GB image on a small host) fails inside its own process with a
    citable MemoryError instead of triggering a host-wide OOM kill that takes
    down the whole investigation. This caps ONLY the tool child; the agent stays
    unconstrained. Default unset ⇒ returns None ⇒ no behavior change.

    preexec_fn runs after fork, before exec, in the child — POSIX only. On any
    platform without resource/fork semantics it silently no-ops.
    """
    raw = os.environ.get("ATLAS_TOOL_MEM_CAP_MB", "").strip()
    if not raw:
        return None
    try:
        cap_bytes = int(raw) * 1024 * 1024
        if cap_bytes <= 0:
            return None
    except ValueError:
        return None
    try:
        import resource
    except ImportError:
        return None

    def _apply():  # pragma: no cover - runs in the forked child
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            new_hard = cap_bytes if hard == resource.RLIM_INFINITY else min(cap_bytes, hard)
            resource.setrlimit(resource.RLIMIT_AS, (cap_bytes, new_hard))
        except (ValueError, OSError):
            pass

    return _apply


# A tool told where to write has said what success looks like: files in that
# directory. Some report a rejected argument by printing their usage and
# exiting 0, which reads here as a clean run that happened to find nothing —
# indistinguishable, from the exit code alone, from an image that really holds
# nothing. The difference is visible in what the tool said while writing
# nothing, and the cost of missing it is a whole stage: an unusable extractor
# list silently carved zero files, and the work that depended on those files
# was then done against hand-cut substitutes for the rest of the run.
_USAGE_BANNER_RE = re.compile(
    r"(?im)^\s*usage\s*[:\[]|"                           # usage: prog [-x]
    r"(?:\[-[^\]\n]{0,40}\]\s*){2,}|"                    # prog [-v|-h] [-t <x>]
    r"\b(?:unknown|invalid|unrecognized|no such)\b.{0,40}?"
    r"\b(?:option|argument|type|scanner|format|file type)\b|"
    r"\btry\s+[`'\"]?\S+\s+--help")                      # try 'prog --help'


def _output_file_count(output_dir: str) -> int:
    """Files the tool left behind, at any depth. -1 when it cannot be read."""
    try:
        return sum(len(files) for _root, _dirs, files in os.walk(output_dir))
    except OSError:
        return -1


def _flag_wrote_nothing(result: dict, output_dir: str | None) -> None:
    """Turn a silent argument rejection into the failure it is.

    Only when all three hold: a directory was named, nothing was written to
    it, and the tool's own output explains itself in the language of a
    misused command line. An image that genuinely carries nothing to recover
    still succeeds, because it says nothing while doing so.
    """
    if not output_dir or not result.get("success"):
        return
    if _output_file_count(output_dir) != 0:
        return
    said = f"{result.get('stderr') or ''}\n{result.get('stdout') or ''}"
    if not _USAGE_BANNER_RE.search(said):
        return
    result["success"] = False
    result["failure_class"] = "analyst_error"
    result["wrote_no_output"] = True
    first = next((ln.strip() for ln in said.splitlines() if ln.strip()), "")
    result["stderr"] = (
        f"{result.get('stderr') or ''}\n"
        f"[Atlas] {os.path.basename(str(result.get('cmd') or 'the tool').split()[0])} "
        f"wrote no files to {output_dir} and reported a usage or argument "
        f"error, so it rejected the command line rather than finding nothing: "
        f"{first[:200]}. Fix the arguments and run it again — an option list "
        f"is refused whole, so one unsupported value disables the rest."
    ).strip()


# A tool spawned under sudo writes its output as root; the run's own later
# reads and its case clear need it back (core.paths). The job runner calls
# the same helper for the tools it supervises.
from .paths import reclaim_output_ownership as _reclaim_sudo_output


def _classify_failure(result: dict) -> str:
    """failure_class for a completed subprocess result.

    "" when it succeeded; "expected_nonzero" for a comparison/search verb
    exiting 1 (a result, not a failure); "tool_error" otherwise.

    Preserve explicit classes already set on the result (e.g. sudo_auth from
    preflight) — overwriting them to tool_error hides privilege failures
    from Access Stage / analytics.
    """
    if result.get("success"):
        return ""
    prior = str(result.get("failure_class") or "").strip()
    if prior and prior not in ("tool_error",):
        return prior
    # A disk-space fail-safe refusal is infrastructure protection working as
    # designed (the volume hit the ATLAS_MIN_FREE_DISK floor), not a tool defect.
    # Counting it as a tool_error inflates the failure rate and misleads the
    # reviewer on a disk-starved host. Classed like
    # gate_refusal / expected_nonzero so the failure-rate accounting excludes it.
    if result.get("disk_low"):
        return "disk_floor"
    if (result.get("exit_code") == 1
            and _cmd_verb(result.get("cmd")) in _EXPECTED_NONZERO_VERBS):
        return "expected_nonzero"
    return "tool_error"


def _apply_line_cap(text: str, max_lines: int,
                    extra_omitted: int = 0) -> tuple[str, bool]:
    """Trim text to max_lines, appending a footer if trimmed.

    extra_omitted: lines already discarded upstream (byte-cap overflow in the
    streaming reader) so the footer count reflects the true total.
    """
    lines = text.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return text, False
    omitted = len(lines) - max_lines + extra_omitted
    return "".join(lines[:max_lines]) + _TRUNCATION_FOOTER.format(n=omitted), True


def _spill_target_dir() -> str | None:
    """Spill directory for full tool output, or None to skip spilling."""
    try:
        from core.execution_log import log
        trace_dir = log.trace_dir()
    except Exception:
        trace_dir = None
    return resolve_spill_dir(trace_dir)


class _CappedStdout:
    """Streaming stdout sink: retains at most `cap` bytes in memory while
    fully draining the pipe. Once output overflows the cap, the FULL stdout
    is teed to a spill file (retained prefix first) so truncation never
    loses data. Spill failures are swallowed — the cap-only behavior is the
    fallback, never an error."""

    def __init__(self, cap: int = OUTPUT_CAP, cmd0: str = "tool"):
        self._cap = cap
        self._cmd0 = cmd0
        self._buf = bytearray()
        self.total_bytes = 0
        self.omitted_newlines = 0
        self.spill_path: str | None = None
        self._spill_fh = None
        self._spill_failed = False

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.total_bytes += len(chunk)
        room = self._cap - len(self._buf)
        retained = chunk[:room] if room > 0 else b""
        excess = chunk[len(retained):]
        if retained:
            self._buf += retained
        if excess:
            self.omitted_newlines += excess.count(b"\n")
            self._tee(excess)

    def _tee(self, data: bytes) -> None:
        if self._spill_failed:
            return
        try:
            if self._spill_fh is None:
                spill_dir = _spill_target_dir()
                if spill_dir is None:
                    self._spill_failed = True
                    return
                path = spill_file_path(spill_dir, self._cmd0)
                self._spill_fh = open(path, "wb")
                self._spill_fh.write(bytes(self._buf))
                self.spill_path = path
            if data:
                self._spill_fh.write(data)
        except Exception:
            self._abort_spill()

    def spill_retained(self) -> None:
        """Spill the in-memory buffer when no byte overflow occurred but the
        output is still being truncated (line cap). One-shot write."""
        if self._spill_fh is None and self.spill_path is None:
            self._tee(b"")
        self.close()

    def _abort_spill(self) -> None:
        try:
            if self._spill_fh is not None:
                self._spill_fh.close()
            if self.spill_path:
                os.unlink(self.spill_path)
        except Exception:
            pass
        self._spill_fh = None
        self.spill_path = None
        self._spill_failed = True

    def close(self) -> None:
        if self._spill_fh is not None:
            try:
                self._spill_fh.close()
            except Exception:
                self._abort_spill()
            finally:
                self._spill_fh = None

    @property
    def byte_truncated(self) -> bool:
        return self.total_bytes > self._cap

    def text(self) -> str:
        return bytes(self._buf).decode("utf-8", errors="replace")


class _StderrAccumulator:
    """Incremental, bounded stderr parser matching _parse_stderr semantics:
    error text capped at 4096 chars, rolling last-20 progress lines."""

    def __init__(self):
        self._buf = b""
        self._errors: list[str] = []
        self._err_len = 0
        self._progress: deque[str] = deque(maxlen=20)

    def feed(self, chunk: bytes) -> None:
        self._buf += chunk
        parts = re.split(rb"[\r\n]+", self._buf)
        self._buf = parts[-1]
        for part in parts[:-1]:
            self.add_line(part.decode("utf-8", errors="replace"))

    def add_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        if re.match(r"Progress:\s+[\d.]+\t", line):
            self._progress.append(line)
        elif self._err_len < 4096:
            self._errors.append(line)
            self._err_len += len(line) + 1

    def finish(self) -> tuple[str, list[str]]:
        if self._buf:
            self.add_line(self._buf.decode("utf-8", errors="replace"))
            self._buf = b""
        return "\n".join(self._errors)[:4096], list(self._progress)


# Children still running, so a stop can end them. A tool call runs in a
# worker thread; the signal that stops the run reaches only the main thread,
# which then waits at interpreter exit for a child that runs to its own
# timeout — hours on a large image.
_ACTIVE_CHILDREN: set = set()
_ACTIVE_LOCK = threading.Lock()
_STOP_EVENT = threading.Event()


def _track_child(proc) -> None:
    with _ACTIVE_LOCK:
        _ACTIVE_CHILDREN.add(proc)


def _untrack_child(proc) -> None:
    with _ACTIVE_LOCK:
        _ACTIVE_CHILDREN.discard(proc)


def _stop_requested() -> bool:
    return _STOP_EVENT.is_set()


def _child_running(proc) -> bool:
    if hasattr(proc, "poll"):
        return proc.poll() is None
    return getattr(proc, "returncode", None) is None


# How long a stopped tool's process group gets to exit on SIGTERM before
# SIGKILL. This is per tool call; the dashboard's STOP_GRACE_SECONDS is the
# grace a whole run gets.
TOOL_STOP_GRACE_SECONDS = float(os.environ.get("ATLAS_TOOL_STOP_GRACE_SECONDS") or 5)


def _spawned(proc, cmd):
    """Record the process group Atlas created for ``proc`` (it was started
    with start_new_session, so the group id is its pid), from the pid the
    spawn returned: never recomputed when the group is signalled. Also
    whether ``cmd`` runs through sudo, for a stop that comes from the run
    rather than the tool's own timeout."""
    proc._atlas_group = proc.pid
    proc._atlas_via_sudo = _via_sudo(cmd)
    if proc._atlas_via_sudo:
        from core.privileged_kill import start_time
        proc._atlas_group_start = start_time(proc.pid)
    return proc


def _signal_created_group(proc, sig: int) -> str:
    """Signal the process group Atlas created for ``proc``: "sent", "gone"
    or "refused:<why>". Only the group recorded at spawn is ever signalled,
    never our own group or session, and a refusal is reported, never
    escalated (no sudo kill)."""
    target = getattr(proc, "_atlas_group", None)
    if not isinstance(target, int) or isinstance(target, bool) or target <= 1:
        return "refused:no group was created for this process"
    if target != getattr(proc, "pid", None):
        return "refused:the recorded group is not the spawned leader"
    try:
        if target in (os.getpgrp(), os.getsid(0)):
            return "refused:our own group"
    except OSError:
        return "refused:our own group is unknown"
    try:
        os.killpg(target, sig)
        return "sent"
    except ProcessLookupError:
        return "gone"
    except PermissionError:
        return "refused:permission"


def _stop_outcome(proc, leader_exited: bool, via_sudo: bool) -> bool:
    """SIGKILL to what is left of the group; True when the stop may be
    incomplete. A command run through sudo stays in the created group (no
    terminal, so sudo gives it no session of its own) but runs as root or as
    a user it drops to, which no signal of ours reaches. For a tool Atlas
    started through sudo, the group is then killed as root with the same
    grant (core.privileged_kill); any other tool is never escalated."""
    probe = _signal_created_group(proc, 0)
    incomplete = (via_sudo and not leader_exited) or probe == "refused:permission"
    group = getattr(proc, "_atlas_group", None)
    leader_start = getattr(proc, "_atlas_group_start", None)
    # With the leader reaped, only its recorded start time tells our group's
    # number from one handed to another process: no record, no escalation.
    if (incomplete and via_sudo and isinstance(group, int) and not isinstance(group, bool)
            and group == getattr(proc, "pid", None)
            and (not leader_exited or isinstance(leader_start, str))):
        from core.privileged_kill import kill_group_as_root
        if kill_group_as_root(group, leader_start):
            incomplete = False
    # Set before SIGKILL: the runner waiting on the leader reads it as soon
    # as the leader is reaped.
    proc._atlas_stop_incomplete = incomplete
    if not leader_exited or probe == "sent":
        _signal_created_group(proc, signal.SIGKILL)
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
    return incomplete


def _stop_tool(proc, grace: float = TOOL_STOP_GRACE_SECONDS, *, via_sudo: bool = False) -> bool:
    """Stop a tool and everything it started: SIGTERM to its created group
    (sudo relays it to its command), up to ``grace`` seconds for the leader,
    then SIGKILL to whatever remains. Returns True when the stop may be
    incomplete (see _stop_outcome)."""
    if _signal_created_group(proc, signal.SIGTERM).startswith("refused"):
        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass
    try:
        proc.wait(timeout=max(0.0, grace))
        exited = True
    except subprocess.TimeoutExpired:
        exited = False
    incomplete = _stop_outcome(proc, exited, via_sudo)
    if not exited:
        proc.wait()   # reap the leader after SIGKILL
    return incomplete


async def _astop_tool(proc, grace: float = TOOL_STOP_GRACE_SECONDS, *, via_sudo: bool = False) -> bool:
    """_stop_tool for a process started by asyncio."""
    if _signal_created_group(proc, signal.SIGTERM).startswith("refused"):
        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=max(0.0, grace))
        exited = True
    except asyncio.TimeoutError:
        exited = False
    incomplete = _stop_outcome(proc, exited, via_sudo)
    if not exited:
        await proc.wait()   # reap the leader after SIGKILL
    return incomplete


def _via_sudo(cmd: list[str]) -> bool:
    return bool(cmd) and os.path.basename(str(cmd[0])) == "sudo"


def _note_incomplete_stop(result: dict, cmd: list[str]) -> None:
    result["stop_incomplete"] = True
    result["stderr"] = ((result.get("stderr") or "").rstrip() + (
        "\nThe tool was stopped, but the command it ran through sudo outlived the stop "
        "request and may still be running as root: " + " ".join(cmd)[:300])).lstrip()


def terminate_active_children(grace: float = 2.0) -> int:
    """End every tool subprocess still running because the run is stopping,
    with everything each one started: SIGTERM to its created group, then
    SIGKILL after ``grace`` seconds. Returns how many were signalled; their
    tool results come back marked ``interrupted``."""
    _STOP_EVENT.set()
    with _ACTIVE_LOCK:
        procs = list(_ACTIVE_CHILDREN)
    for proc in procs:
        try:
            if _child_running(proc) and _signal_created_group(proc, signal.SIGTERM).startswith("refused"):
                proc.terminate()
        except Exception:  # noqa: BLE001
            pass
    deadline = time.monotonic() + max(0.0, grace)
    for proc in procs:
        try:
            if hasattr(proc, "poll"):
                try:
                    proc.wait(timeout=max(0.0, deadline - time.monotonic()))
                    exited = True
                except subprocess.TimeoutExpired:
                    exited = False
            else:
                while _child_running(proc) and time.monotonic() < deadline:
                    time.sleep(0.05)
                exited = not _child_running(proc)
            _stop_outcome(proc, exited, bool(getattr(proc, "_atlas_via_sudo", False)))
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
    return len(procs)


def _collect_stdout(result: dict, stdout_sink, line_cap: int | None,
                    stdout_filter) -> None:
    """Move what the sink retained into result["stdout"] under the byte and
    line caps, keeping the full output on disk when either cut it. One
    collection for a command that finished and one that was stopped: what a
    tool wrote before its budget ran out is its output, not nothing."""
    stdout = stdout_sink.text()
    if stdout_sink.byte_truncated:
        result["truncated"] = True
    if line_cap is not None:
        stdout, line_truncated = _apply_line_cap(
            stdout, line_cap, extra_omitted=stdout_sink.omitted_newlines)
        if line_truncated:
            result["truncated"] = True
    if result["truncated"]:
        # Ensure the FULL output survives truncation on disk.
        stdout_sink.spill_retained()
        if stdout_sink.spill_path:
            result["stdout_file"] = stdout_sink.spill_path
    result["stdout"] = stdout_filter(stdout) if stdout_filter else stdout


def _timeout_message(timeout, cmd: list[str], result: dict, stdout_sink) -> str:
    """The timeout as the model should read it: the budget ran out, and what
    the tool had written by then is in the result, not lost. The leading
    sentence is the form other code matches on."""
    text = f"Command timed out after {timeout}s: {' '.join(cmd)}"
    if not (result.get("stdout") or "").strip():
        return text + ". It had written no output by then."
    lines = stdout_sink.text().count("\n") + stdout_sink.omitted_newlines
    where = "stdout"
    if result.get("truncated") and result.get("stdout_file"):
        where = ("stdout, cut at the output cap; the full copy is at "
                 + result["stdout_file"])
    return (f"{text}. What it had written by then is kept ({lines} line"
            f"{'s' if lines != 1 else ''}, in {where}). Use it before running "
            "the tool again: a re-run over the same or a narrower target "
            "repeats this work.")


def _pump(stream, feed) -> None:
    """Drain a subprocess pipe into a sink. Always drains to EOF even if the
    sink misbehaves — an undrained pipe deadlocks the child."""
    try:
        while True:
            chunk = stream.read(_CHUNK)
            if not chunk:
                break
            try:
                feed(chunk)
            except Exception:
                pass  # keep draining
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _parse_stderr(raw: str) -> tuple[str, list[str]]:
    """Split raw stderr into (error_text, progress_lines).

    Progress lines (\rProgress: XX.XX\t...) are extracted into a list for
    the trace log and stripped from the stored stderr so error messages
    are not crowded out by the 4096-char cap.
    """
    progress: list[str] = []
    errors: list[str] = []
    for line in re.split(r"[\r\n]+", raw):
        line = line.strip()
        if not line:
            continue
        if re.match(r"Progress:\s+[\d.]+\t", line):
            progress.append(line)
        else:
            errors.append(line)
    return "\n".join(errors)[:4096], progress[-20:]


def _annotate_vmdk_snapshot(result: dict, cmd: list[str]) -> None:
    """Attach a warning when the command targets a snapshot-shadowed VMDK.

    A base/-flat VMDK with sibling snapshot deltas is FROZEN at snapshot
    creation time — any tool reading it sees the pre-snapshot state, which
    reads like "the system stopped on <snapshot date>". Advisory only (one listdir, no descriptor reads); never
    fails the call.
    """
    try:
        from core.vmdk import snapshot_warning
        for token in cmd:
            if not token.lower().endswith(".vmdk"):
                continue
            warning = snapshot_warning(token)
            if warning:
                result["vmdk_snapshot_warning"] = warning
                return
    except Exception:
        pass


def retain_output_text(text: str, cmd0: str) -> str:
    """Keep a tool's whole output on disk when the trace excerpt would cut it;
    returns the file path or "". Shared by subprocess and Python tools."""
    try:
        from core.execution_log import TRACE_EXCERPT_CHARS
    except Exception:  # noqa: BLE001
        TRACE_EXCERPT_CHARS = 4000
    if len(text or "") <= TRACE_EXCERPT_CHARS:
        return ""
    try:
        spill_dir = _spill_target_dir()
        if spill_dir is None:
            return ""
        path = spill_file_path(spill_dir, str(cmd0 or "tool").split(" ", 1)[0].rsplit("/", 1)[-1])
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
        return path
    except Exception:  # noqa: BLE001
        return ""


def _retain_full_stdout(result: dict) -> str:
    path = retain_output_text(result.get("stdout") or "", str(result.get("cmd") or "tool"))
    if path:
        result["stdout_file"] = path
    return path


# Programs whose *silent* exit 1 is an answer rather than an error: nothing on
# stdout, nothing on stderr, status 1. mmls does this for an image with no
# partition table (a superfloppy volume, a reformatted key) — the correct
# reading is "open it as a single filesystem", and a bare failure carrying no
# text gives the model nothing to act on. Only the silent shape qualifies:
# these programs write their genuine errors to stderr.
_SILENT_EXIT1_ANSWERS: dict[str, str] = {
    "mmls": ("no partition table: the image carries no volume system. Read "
             "it as a single filesystem — tsk.fsstat / tsk.fls on the image "
             "without an offset."),
}


def _apply_exit_conventions(result: dict) -> None:
    """Turn a program's documented exit-code convention into the result it
    stands for, before the entry is logged and returned. Mutates in place."""
    if result.get("success") or result.get("exit_code") != 1:
        return
    if (result.get("stderr") or "").strip():
        return
    verb = _cmd_verb(result.get("cmd"))
    # grep family and cmp/diff: exit 1 is the answer "nothing matched" /
    # "files differ". Handing it to the model as a failure sent it to
    # investigate a broken tool that had just answered its question.
    if verb in _EXPECTED_NONZERO_VERBS:
        result["success"] = True
        result["no_match"] = True
        result["answer_from_exit_code"] = True
        if not (result.get("stdout") or "").strip():
            result["stdout"] = f"{verb}: no match"
        return
    if (result.get("stdout") or "").strip():
        return
    answer = _SILENT_EXIT1_ANSWERS.get(verb)
    if not answer:
        return
    result["success"] = True
    result["stdout"] = answer
    result["answer_from_exit_code"] = True


def _log_tool(result: dict) -> None:
    """Write a tool_call trace entry for the just-run command.

    Trace integrity is required for the audit story — if recording the entry
    fails (disk full, perms, log not configured), re-raise so the caller
    sees a structured error instead of returning a tool result with a
    fabricated `_atlas_call_id: 0`. The middleware wraps the raise into a
    ToolError that the agent must read.
    """
    _apply_exit_conventions(result)
    try:
        from core.execution_log import log
        parent = [log._last_dair_cid] if log._last_dair_cid else None
        spill = result.get("stdout_file", "") or _retain_full_stdout(result)
        cid = log.record_tool_call(
            cmd=result["cmd"],
            success=result["success"],
            truncated=result["truncated"],
            retries=result["retries"],
            exit_code=result["exit_code"],
            stderr=result["stderr"],
            elapsed_seconds=result.get("elapsed_seconds", 0.0),
            stdout_excerpt=result.get("stdout", ""),
            timed_out=result.get("timed_out", False),
            interrupted=bool(result.get("interrupted")),
            input_call_ids=parent,
            stdout_file=spill,
            # Subprocess failures are tool breakage by definition: gate
            # refusals and bad arguments are classified in the middleware
            # before any process is spawned, so an unsuccessful result here
            # can only be the tool itself erroring. Without this default the
            # most common failure shape (nonzero exit) carried no
            # failure_class at all. Exception: comparison/search verbs exiting 1 are
            # reporting a result ("differ"/"no match"), not failing.
            failure_class=_classify_failure(result),
            output_hash=_output_hash(result),
            vmdk_snapshot_warning=result.get("vmdk_snapshot_warning", ""),
        )
        result["_atlas_call_id"] = cid
    except Exception as e:
        import sys
        print(f"[Atlas WARN] _log_tool failed for {result.get('cmd', '?')[:80]}: {e}",
              file=sys.stderr)
        raise
    # Outside the try above: index failures must never fail the tool call
    # (trace integrity re-raises; the FTS index is best-effort by contract).
    _index_output_best_effort(result, cid)


def _output_hash(result: dict) -> str:
    """blake2b over the FULL pre-truncation output — the spill file bytes
    when the in-memory copy was truncated, else the retained stdout. Empty
    string on any failure (the hash is evidence support, not a gate)."""
    try:
        import hashlib
        h = hashlib.blake2b(digest_size=32)
        spill = result.get("stdout_file") or ""
        if spill and os.path.isfile(spill):
            with open(spill, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        else:
            h.update((result.get("stdout") or "").encode(
                "utf-8", errors="replace"))
        return "blake2b:" + h.hexdigest()
    except Exception:
        return ""


def _index_output_best_effort(result: dict, call_id: int) -> None:
    """Feed the FULL tool output into the per-case FTS evidence index —
    the spill file when the in-memory copy was truncated, else the buffer.
    Runs only here, in the server process (see core/evidence_index.py's
    concurrency contract)."""
    try:
        from core import evidence_index
        text = result.get("stdout") or ""
        spill = result.get("stdout_file") or ""
        if spill and os.path.isfile(spill):
            with open(spill, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(evidence_index.MAX_INDEXED_BYTES + 1)
        evidence_index.index_output(
            call_id=call_id,
            tool=_cmd_verb(result.get("cmd")) or "tool",
            text=text,
            source_path=spill,
        )
    except Exception as e:
        import sys
        print(f"[Atlas WARN] evidence indexing failed for call {call_id}: {e}",
              file=sys.stderr)


def _sudo_auth_preflight(cmd: list[str]) -> dict[str, Any] | None:
    """Return a failure result if ``sudo -n`` cannot run; else None.

    Prevents interactive password waits that burn the full tool timeout.
    """
    try:
        probe = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False, "stdout": "",
            "stderr": (
                "sudo -n true timed out — refusing to launch "
                "password-gated sudo tool."
            ),
            "exit_code": -1, "elapsed_seconds": 5.0, "truncated": False,
            "cmd": " ".join(["sudo"] + list(cmd)),
            "retries": 0, "progress_lines": [],
            "failure_class": "sudo_auth",
            "timed_out": True,
        }
    except Exception:
        return None
    if probe.returncode == 0:
        return None
    err = (probe.stderr or probe.stdout or "").strip()
    if not err:
        err = "sudo: a password is required"
    return {
        "success": False, "stdout": "",
        "stderr": (
            f"{err} — non-interactive sudo failed; refuse to wait for a "
            f"password prompt. Prefer file-backed tools that do not need "
            f"elevation (tsk.mmls/tsk.fls on analysis/*.raw need no sudo), "
            f"or configure passwordless sudo for this privileged tool "
            f"(mount/loop/carve)."
        ),
        "exit_code": probe.returncode,
        "elapsed_seconds": 0.0, "truncated": False,
        "cmd": " ".join(["sudo"] + list(cmd)),
        "retries": 0, "progress_lines": [],
        "failure_class": "sudo_auth",
    }


def run(
    cmd: list[str] | str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    output_dir: str | None = None,
    needs_sudo: bool = False,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    line_cap: int | None = MAX_TOOL_OUTPUT_LINES,
    stdin_path: str | None = None,
    stdout_filter=None,
) -> dict[str, Any]:
    """
    Execute a forensic tool command safely.

    stdout_filter: applied to the captured stdout before it is returned and
    before the trace records it, for a wrapper that knows what its tool
    prints about itself (a banner is not output).

    Returns dict with keys: success, stdout, stderr, exit_code, truncated,
    cmd, retries, elapsed_seconds, progress_lines.
    Never raises — all errors are captured in the return value.
    Does NOT retry on TimeoutExpired — a timeout means the tool needs more
    time or missing symbols; retrying just wastes time.

    stdin_path: feed this file to the tool on stdin. Only needed for tools
    whose file-input flag is broken and that read stdin instead (bstrings).
    """
    if output_dir:
        assert_output_safe(output_dir)
        # The tool writes here; make sure "here" exists. A case reset to
        # evidence/ and CASE.md has no exports/, and qemu-img then reports
        # "No such file or directory" for the raw image it is asked to
        # write there.
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError:
            pass  # the tool's own error names the path

    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    # subprocess.run() with a list does not shell-expand ~ — expand explicitly
    cmd = [os.path.expanduser(a) if a.startswith("~") else a for a in cmd]

    # Solution-material gate: second enforcement layer behind the middleware
    # arg scan, catching paths a tool builds internally from its inputs.
    # Argv is command material, never prose, so the substring check also
    # applies — it catches interpreter payloads (`python3 -c "...open(
    # 'ground_truth.json')..."`) that are not path-shaped.
    from core.paths import (SOLUTION_BLOCK_MESSAGE,
                            contains_solution_reference, is_solution_path)
    blocked = next((a for a in cmd if is_solution_path(a)
                    or contains_solution_reference(a)), None)
    if blocked:
        result = {
            "success": False, "stdout": "",
            "stderr": f"Blocked argument '{blocked[:200]}': {SOLUTION_BLOCK_MESSAGE}",
            "exit_code": -1, "elapsed_seconds": 0.0, "truncated": False,
            "cmd": " ".join(cmd), "retries": 0, "progress_lines": [],
        }
        _log_tool(result)
        return result

    if needs_sudo and cmd[0] != "sudo":
        # Fail fast when sudo cannot run non-interactively. Password prompts
        # otherwise hang until the full tool timeout.
        _sudo_block = _sudo_auth_preflight(cmd)
        if _sudo_block is not None:
            _log_tool(_sudo_block)
            return _sudo_block
        cmd = ["sudo"] + cmd

    # Remote-SIFT: when enabled, execute on the external VM instead of locally.
    # Off by default (remote_config() returns None), so local runs are unchanged.
    from core import remote as _remote
    if _remote.is_enabled():
        if stdin_path:
            result = {
                "success": False, "stdout": "",
                "stderr": "stdin_path is not supported over remote-SIFT — the "
                          "local file cannot be piped to the remote tool.",
                "exit_code": -1, "elapsed_seconds": 0.0, "truncated": False,
                "cmd": " ".join(cmd), "retries": 0, "progress_lines": [],
            }
            _log_tool(result)
            return result
        result = _remote.run_remote(cmd, timeout=timeout, cwd=cwd,
                                    line_cap=line_cap)
        _log_tool(result)
        return result

    # Disk-space fail-safe: refuse to launch a local tool when the volume that
    # would hold its output is already below the floor. Prevents a case run
    # from exhausting the VM/host disk (half-written carves, corrupt DBs).
    # Checks output_dir if given, else the cwd the tool writes into.
    from core import diskguard as _diskguard
    _disk = _diskguard.check(output_dir or cwd)
    if not _disk["ok"]:
        result = {
            "success": False, "stdout": "",
            "stderr": _diskguard.message(_disk, cmd[0] if cmd else "tool"),
            "exit_code": -1, "elapsed_seconds": 0.0, "truncated": False,
            "cmd": " ".join(cmd), "retries": 0, "progress_lines": [],
            "disk_low": True,
        }
        _log_tool(result)
        return result

    result: dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "elapsed_seconds": 0.0,
        "truncated": False,
        "cmd": " ".join(cmd),
        "retries": 0,
        "progress_lines": [],
    }

    # Integrity: whatever this command does, the evidence it names must be
    # the same afterwards. A stat snapshot costs nothing; a silent
    # modification costs the case (core/evidence_guard.py).
    try:
        from core.evidence_guard import snapshot_evidence_refs
        _ev_before = snapshot_evidence_refs(cmd)
    except Exception:  # noqa: BLE001
        _ev_before = None

    start = time.perf_counter()
    stdout_sink = _CappedStdout(cap=OUTPUT_CAP, cmd0=cmd[0] if cmd else "tool")
    stderr_acc = _StderrAccumulator()
    stdin_fh = None
    proc = None

    try:
        if stdin_path:
            stdin_fh = open(os.path.expanduser(stdin_path), "rb")
        # Stream both pipes in reader threads: the child's full output is
        # drained (and, past the cap, teed to a spill file) without ever
        # holding more than OUTPUT_CAP bytes of stdout in memory.
        proc = _spawned(subprocess.Popen(
            cmd,
            stdin=stdin_fh,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            preexec_fn=_memguard_preexec(),
            start_new_session=True,
        ), cmd)
        _track_child(proc)
        t_out = threading.Thread(target=_pump, args=(proc.stdout, stdout_sink.feed),
                                 daemon=True)
        t_err = threading.Thread(target=_pump, args=(proc.stderr, stderr_acc.feed),
                                 daemon=True)
        t_out.start()
        t_err.start()

        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            incomplete = _stop_tool(proc, via_sudo=_via_sudo(cmd))
            t_out.join(timeout=10)
            t_err.join(timeout=10)
            result["timed_out"] = True
            _collect_stdout(result, stdout_sink, line_cap, stdout_filter)
            _, result["progress_lines"] = stderr_acc.finish()
            result["stderr"] = _timeout_message(timeout, cmd, result, stdout_sink)
            if incomplete:
                _note_incomplete_stop(result, cmd)
        else:
            t_out.join(timeout=30)
            t_err.join(timeout=30)
            result["exit_code"] = returncode
            result["success"] = returncode == 0
            if returncode < 0 and _stop_requested():
                # Ended by terminate_active_children(): the run is stopping,
                # not the tool failing.
                result["interrupted"] = True
                result["stderr"] = "interrupted: the run was stopped while this tool ran"

            _collect_stdout(result, stdout_sink, line_cap, stdout_filter)
            result["stderr"], result["progress_lines"] = stderr_acc.finish()
            if result.get("interrupted") and getattr(proc, "_atlas_stop_incomplete", False):
                _note_incomplete_stop(result, cmd)
            if _ev_before:
                try:
                    from core.evidence_guard import evidence_changes
                    _changed = evidence_changes(_ev_before, cmd)
                except Exception:  # noqa: BLE001
                    _changed = []
                if _changed:
                    # Not a warning: a tool that altered evidence produced
                    # no usable result, whatever its exit code said.
                    result["evidence_modified"] = _changed
                    result["success"] = False
                    result["stderr"] = (
                        "EVIDENCE MODIFIED by this command — "
                        + "; ".join(f"{c['path']} ({c['change']})" for c in _changed[:6])
                        + ". Evidence is read-only; the result is refused. "
                        + result["stderr"])

    except FileNotFoundError as e:
        result["stderr"] = f"Tool not found: {e}"

    except Exception as e:
        result["stderr"] = f"Executor error: {e}"

    finally:
        if proc is not None:
            _untrack_child(proc)
        stdout_sink.close()
        if stdin_fh is not None:
            stdin_fh.close()

    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)

    # A sudo-spawned carver leaves output root-owned and unreadable to later
    # typed tools — hand ownership back to the invoking user before logging.
    if needs_sudo and output_dir and not _remote.is_enabled():
        _reclaim_sudo_output(output_dir)

    _flag_wrote_nothing(result, output_dir)
    _annotate_vmdk_snapshot(result, cmd)
    _log_tool(result)
    return result


async def run_with_progress(
    cmd: list[str],
    ctx: Any,  # fastmcp.Context — typed as Any to avoid importing fastmcp in core
    *,
    timeout: int = VOL_TIMEOUT,
    output_dir: str | None = None,
    line_cap: int | None = MAX_TOOL_OUTPUT_LINES,
    stdout_filter=None,
) -> dict[str, Any]:
    """
    Async variant of run() that streams stderr progress lines to ctx.report_progress().
    Use this for long-running tools (vol_psscan, vol_filescan, etc.) where real-time
    feedback matters. ctx must be a fastmcp.Context injected by FastMCP.
    """
    if output_dir:
        assert_output_safe(output_dir)

    # subprocess does not shell-expand ~ in list args — expand explicitly
    cmd = [os.path.expanduser(a) if a.startswith("~") else a for a in cmd]

    # Remote-SIFT: delegate to the (non-streaming) remote runner in a thread so
    # this coroutine stays responsive. Progress streaming is lost over SSH, but
    # the tool still runs on the VM. Off by default.
    from core import remote as _remote
    if _remote.is_enabled():
        result = await asyncio.to_thread(
            _remote.run_remote, cmd, timeout=timeout, line_cap=line_cap)
        _log_tool(result)
        return result

    # Disk-space fail-safe — see core.executor.run for rationale.
    from core import diskguard as _diskguard
    _disk = _diskguard.check(output_dir)
    if not _disk["ok"]:
        result = {
            "success": False, "stdout": "",
            "stderr": _diskguard.message(_disk, cmd[0] if cmd else "tool"),
            "exit_code": -1, "elapsed_seconds": 0.0, "truncated": False,
            "cmd": " ".join(cmd), "retries": 0, "progress_lines": [],
            "disk_low": True,
        }
        _log_tool(result)
        return result

    result: dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "elapsed_seconds": 0.0,
        "truncated": False,
        "cmd": " ".join(cmd),
        "retries": 0,
        "progress_lines": [],
    }

    start = time.perf_counter()
    stdout_sink = _CappedStdout(cap=OUTPUT_CAP, cmd0=cmd[0] if cmd else "tool")
    stderr_acc = _StderrAccumulator()
    proc = None

    try:
        proc = _spawned(await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=_memguard_preexec(),
            start_new_session=True,
        ), cmd)
        _track_child(proc)

        async def _drain_stderr() -> None:
            # Read in chunks and split on \r or \n — Volatility writes progress
            # with \r (carriage return), not \n, so line-based iteration misses them.
            buf = b""
            while True:
                if proc.stderr is None:
                    break
                chunk = await proc.stderr.read(512)
                if not chunk:
                    break
                buf += chunk
                parts = re.split(rb"[\r\n]+", buf)
                buf = parts[-1]
                for part in parts[:-1]:
                    line = part.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    stderr_acc.add_line(line)
                    if ctx is not None:
                        elapsed = time.perf_counter() - start
                        try:
                            await ctx.report_progress(elapsed, float(timeout), line[:120])
                        except Exception as _progress_err:
                            # Don't let progress-reporting bugs interrupt the
                            # tool run, but surface them in the trace so
                            # they're not invisible.
                            import sys as _sys
                            print(f"[Atlas WARN] progress_drain failed: "
                                  f"{_progress_err}", file=_sys.stderr)
                            try:
                                from core.execution_log import log as _log
                                _log.record_system_error(
                                    "progress_drain",
                                    f"report_progress raised "
                                    f"{type(_progress_err).__name__}: "
                                    f"{_progress_err}",
                                )
                            except Exception:
                                pass
            # flush any remaining bytes
            if buf:
                line = buf.decode("utf-8", errors="replace").strip()
                if line:
                    stderr_acc.add_line(line)

        async def _drain_stdout() -> None:
            if proc.stdout is None:
                return
            while True:
                chunk = await proc.stdout.read(_CHUNK)
                if not chunk:
                    break
                try:
                    stdout_sink.feed(chunk)
                except Exception:
                    pass  # keep draining — an undrained pipe stalls the child

        try:
            await asyncio.wait_for(
                asyncio.gather(_drain_stdout(), _drain_stderr()),
                timeout=float(timeout),
            )
        except asyncio.TimeoutError:
            incomplete = await _astop_tool(proc, via_sudo=_via_sudo(cmd))
            await proc.communicate()
            result["timed_out"] = True
            _collect_stdout(result, stdout_sink, line_cap, stdout_filter)
            stdout_sink.close()
            result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
            _, result["progress_lines"] = stderr_acc.finish()
            result["stderr"] = _timeout_message(timeout, cmd, result, stdout_sink)
            if incomplete:
                _note_incomplete_stop(result, cmd)
            _log_tool(result)
            return result

        await proc.wait()

        _collect_stdout(result, stdout_sink, line_cap, stdout_filter)
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0
        result["stderr"], result["progress_lines"] = stderr_acc.finish()
        if proc.returncode < 0 and _stop_requested():
            # Ended by terminate_active_children(): the run is stopping.
            result["interrupted"] = True
            if getattr(proc, "_atlas_stop_incomplete", False):
                _note_incomplete_stop(result, cmd)

    except Exception as e:
        result["stderr"] = f"Executor error: {e}"

    finally:
        if proc is not None:
            _untrack_child(proc)
        stdout_sink.close()

    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
    _annotate_vmdk_snapshot(result, cmd)
    _log_tool(result)
    return result


# What every EZ Tools binary prints about itself before its output: the
# author line and the project link. Read as output, they became the most
# recurrent "indicators" of a run, in no finding and in every tool call.
_EZ_BANNER_RE = re.compile(
    r"^(?:Author:\s.*|https?://github\.com/EricZimmerman/\S*)[ \t]*\r?\n?",
    re.MULTILINE)


def strip_ez_banner(stdout: str) -> str:
    return _EZ_BANNER_RE.sub("", stdout or "")


def run_dotnet(
    dll_path: str,
    args: list[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    output_dir: str | None = None,
    stdin_path: str | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    """Run an EZ Tools .NET binary via dotnet runtime.

    cwd: working directory for the tool. Worth setting for tools that drop
    byproducts wherever they were started — SQLECmd extracts a 3.4 MB
    libSQLite.Interop.so into its cwd on every run, which otherwise lands in
    whatever directory Atlas was launched from. Pass absolute paths in args when
    setting this, since relative ones would resolve against it.
    """
    cmd = ["dotnet", dll_path] + args
    return run(cmd, timeout=timeout, output_dir=output_dir,
               stdin_path=stdin_path, cwd=cwd, stdout_filter=strip_ez_banner)


def run_with_output_file(
    cmd: list[str] | str,
    *,
    output_path: str,
    mode: str = "w",
    timeout: int = DEFAULT_TIMEOUT,
    needs_sudo: bool = False,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    """
    Execute a forensic tool with stdout redirected to output_path.

    Use this when the tool's stdout *is* the artifact (icat → file contents,
    blkls → raw blocks, mactime → CSV, a log parser → JSON, etc.). The standard
    run() captures stdout in memory and would be wrong for binary or large
    outputs. Returns the standard executor result dict with `output_path`
    added and a synthetic stdout summary.

    mode: "w" for text, "wb" for binary.
    """
    assert_output_safe(output_path)
    parent = os.path.dirname(os.path.abspath(output_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    cmd = [os.path.expanduser(a) if a.startswith("~") else a for a in cmd]
    if needs_sudo and cmd[0] != "sudo":
        cmd = ["sudo"] + cmd

    # Remote-SIFT: stream the remote tool's stdout back into the LOCAL output
    # file (for stdout-IS-artifact tools). Off by default.
    from core import remote as _remote
    if _remote.is_enabled():
        result = _remote.run_remote(cmd, timeout=timeout, cwd=cwd,
                                    line_cap=None, stdout_file=output_path)
        _log_tool(result)
        return result

    result: dict[str, Any] = {
        "success": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "elapsed_seconds": 0.0,
        "truncated": False,
        "cmd": " ".join(cmd),
        "retries": 0,
        "progress_lines": [],
        "output_path": output_path,
    }

    start = time.perf_counter()
    # Write beside the target and move into place only on success: a
    # failed icat (wrong offset) used to leave a 0-byte file where a good
    # extraction had been.
    tmp_path = f"{output_path}.part-{os.getpid()}"
    stop_incomplete = False

    try:
        with open(tmp_path, mode) as f:
            proc = _spawned(subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                env=env,
                cwd=cwd,
                preexec_fn=_memguard_preexec(),
                start_new_session=True,
            ), cmd)
            _track_child(proc)
            try:
                _, stderr_bytes = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_incomplete = _stop_tool(proc, via_sudo=_via_sudo(cmd))
                proc.communicate()
                raise
            finally:
                _untrack_child(proc)
        result["exit_code"] = proc.returncode
        result["success"] = proc.returncode == 0
        if proc.returncode < 0 and _stop_requested():
            result["interrupted"] = True
        if result["success"]:
            os.replace(tmp_path, output_path)
            result["stdout"] = f"Output written to {output_path}"
        else:
            result["stdout"] = (f"Nothing written to {output_path} (exit "
                                f"{proc.returncode}); any earlier file there is untouched")
        stderr_raw = (stderr_bytes or b"").decode("utf-8", errors="replace")
        result["stderr"], result["progress_lines"] = _parse_stderr(stderr_raw)
        if result.get("interrupted"):
            result["stderr"] = "interrupted: the run was stopped while this tool ran"
            if getattr(proc, "_atlas_stop_incomplete", False):
                _note_incomplete_stop(result, cmd)

    except subprocess.TimeoutExpired:
        result["stderr"] = f"Command timed out after {timeout}s: {' '.join(cmd)}"
        result["timed_out"] = True
        if stop_incomplete:
            _note_incomplete_stop(result, cmd)

    except FileNotFoundError as e:
        result["stderr"] = f"Tool not found: {e}"

    except Exception as e:
        result["stderr"] = f"Executor error: {e}"

    if not result["success"]:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
    result["elapsed_seconds"] = round(time.perf_counter() - start, 1)
    _annotate_vmdk_snapshot(result, cmd)
    _log_tool(result)
    return result
