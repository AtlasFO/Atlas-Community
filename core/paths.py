"""Evidence path constants and read-only enforcement."""
import glob
import inspect
import itertools
import math
import os
import re
import shutil
import stat as stat_mod
import subprocess
import time
from functools import wraps
from pathlib import Path

from core.envfile import env_int

# Paths that must never be written to
READ_ONLY_PREFIXES = (
    "/cases/",
    "/mnt/",
    "/media/",
)

# Path segments treated like evidence (case-local mounts, evidence trees).
# Consumed by is_evidence_path / assert_output_safe — not decorative.
READ_ONLY_SEGMENTS = ("evidence", "mnt")

# Maximum subprocess output returned to the LLM (bytes)
OUTPUT_CAP = 51_200  # 50 KB

# Maximum tool output lines returned to the agent (line-based cap)
MAX_TOOL_OUTPUT_LINES = 150

# ── Configurable timeouts (seconds) ─────────────────────────────────────────
# Override via environment variables — useful on slow hardware (WSL2, USB drives).

DEFAULT_TIMEOUT  = env_int("ATLAS_DEFAULT_TIMEOUT", 300)
VOL_TIMEOUT      = env_int("ATLAS_VOL_TIMEOUT", 600)
PLASO_TIMEOUT    = env_int("ATLAS_PLASO_TIMEOUT", 21600)
# Wall-clock budget for one reasoning or director model call. These bound a
# connection that has stopped answering, not a model that is still writing:
# both calls carry the whole case state, so what they cost grows with the
# investigation, and a budget set for an early call cuts a later one off in
# the middle of a legitimate answer. Cutting one is not a cheap loss. The gate
# that admits a report asks for its blockers to be resolved through
# synthesize, and the documented way to record a dead end is written through
# synthesize as well, so a synthesize that never returns leaves the gate
# asking for something no answer can supply. Connect is bounded separately at
# the call site, so an endpoint that is simply down still fails in seconds.
REASON_TIMEOUT   = env_int("ATLAS_REASON_TIMEOUT", 300)
DAIR_TIMEOUT     = env_int("ATLAS_DAIR_TIMEOUT", 300)
# Wall-clock budget for one report-section model call. A section carries the
# whole case state and asks for prose per finding, so a legitimate answer
# takes minutes; past the budget the section is written deterministically and
# marked, and the run moves on instead of waiting for an answer that may never
# come.
REPORT_SECTION_TIMEOUT = env_int("ATLAS_REPORT_SECTION_TIMEOUT", 900)
# Visible tokens one narrative section may use. There was no ceiling here at
# all: the request went out without a limit parameter, so the endpoint's own
# default decided, which is truncation on one provider and a completion that
# runs until the watchdog stops waiting on another. A section that needs more
# than this is not a section; raise it if a report genuinely wants longer prose.
# Watchdog budget for pure-Python hashing of large evidence files (memory raws,
# multi-GB E01s). Subprocess hashers (ssdeep, hashdeep) inherit DEFAULT_TIMEOUT
# from `core.executor.run`.
HASH_TIMEOUT     = env_int("ATLAS_HASH_TIMEOUT", 900)

# Assumed worst-case evidence read throughput for size-scaled timeouts.
# <= 0 disables scaling (scale_timeout returns the base unchanged).
MIN_THROUGHPUT_MB_S = env_int("ATLAS_MIN_THROUGHPUT_MB_S", 20)

# Full-file custody hashing cap for verify_evidence_hash. Evidence larger
# than this gets a fast sampled fingerprint instead of a full read — a
# large flat VMDK on a network mount takes hours of sequential I/O before
# any analysis starts. Full hashing still happens when
# the caller passes an expected hash to verify or force_full=True.
# <= 0 disables the cap (always full-hash).
FULL_HASH_MAX_GB = env_int("ATLAS_FULL_HASH_MAX_GB", 16)

# Segment glob cap for multi-part E01 sets — guards against pathological dirs.
_MAX_EWF_SEGMENTS = 1000


def _input_size_bytes(path: str) -> int:
    """Best-effort size of a tool input. Directories and unstatable paths
    contribute 0. A `.E01` first segment sums its sibling segments (`.E02`,
    `.EX01`, …) since ewfverify/log2timeline read the whole set."""
    try:
        p = os.path.expanduser(path)
        st = os.stat(p)
    except (OSError, ValueError, TypeError):
        return 0
    if stat_mod.S_ISDIR(st.st_mode):
        return 0
    stem, ext = os.path.splitext(p)
    if ext.lower() == ".e01":
        total = 0
        for i, seg in enumerate(glob.iglob(glob.escape(stem) + ".[eE]*")):
            if i >= _MAX_EWF_SEGMENTS:
                break
            try:
                seg_st = os.stat(seg)
                if not stat_mod.S_ISDIR(seg_st.st_mode):
                    total += seg_st.st_size
            except OSError:
                continue
        return total or st.st_size
    return st.st_size


def unique_output_stem(input_path: str, default: str = "out") -> str:
    """File-name stem for output derived from ``input_path``: its sanitised
    name plus 8 hex characters of a digest of the full path, so the same file
    name on two hosts ("Logs", "$MFT") never writes to the same output."""
    import hashlib
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(input_path).stem) or default
    digest = hashlib.sha1(str(Path(input_path).resolve()).encode()).hexdigest()[:8]
    return f"{name}_{digest}"


def scale_timeout(base_timeout: int, *input_paths: str | None,
                  min_throughput_mb_s: int | None = None) -> int:
    """Scale a timeout to the size of the evidence being read.

    Returns max(base_timeout, total_input_bytes / throughput) so the
    env-configured base always remains the floor. Paths that are missing,
    unstatable, or directories contribute nothing — the base is returned
    unchanged, matching pre-scaling behavior for small/absent inputs.
    """
    tp = MIN_THROUGHPUT_MB_S if min_throughput_mb_s is None else min_throughput_mb_s
    if tp <= 0:
        return base_timeout
    total = sum(_input_size_bytes(p) for p in input_paths if p)
    if total <= 0:
        return base_timeout
    return max(base_timeout, math.ceil(total / (tp * 1_048_576)))


# ── Network-storage detection ────────────────────────────────────────────────
# Evidence symlinked from network storage (CIFS/NFS/sshfs/WSL2 9p) makes every
# full-sequential read ~10-50x slower than local disk. Tools use this to tag
# results with a warning instead of silently burning hours.

_NETWORK_FSTYPES = frozenset({
    "cifs", "smb3", "smbfs", "nfs", "nfs3", "nfs4", "9p", "drvfs", "davfs",
    "afs", "ceph", "fuse.ceph", "glusterfs", "fuse.glusterfs", "lustre",
    "fuse.sshfs", "fuse.rclone", "fuse.s3fs", "fuse.gcsfuse", "fuse.juicefs",
})


def path_fstype(path: str, proc_mounts: str = "/proc/mounts") -> str:
    """Filesystem type of the mount holding `path` (symlinks resolved).

    Longest-mountpoint match over /proc/mounts; "" when undeterminable.
    `proc_mounts` is overridable for tests (same convention as core.mounts).
    """
    try:
        real = os.path.realpath(os.path.expanduser(path))
        best_len, best_type = -1, ""
        with open(proc_mounts, encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.split()
                if len(fields) < 3:
                    continue
                # Octal escapes in mountpoints (\040 = space)
                mnt = fields[1].encode().decode("unicode_escape")
                if (real == mnt or real.startswith(mnt.rstrip("/") + "/")) \
                        and len(mnt) > best_len:
                    best_len, best_type = len(mnt), fields[2]
        return best_type
    except OSError:
        return ""


def is_network_path(path: str, proc_mounts: str = "/proc/mounts") -> bool:
    """True when `path` resolves onto a network filesystem."""
    return path_fstype(path, proc_mounts=proc_mounts).lower() \
        in _NETWORK_FSTYPES


# ── Full-output spill files ──────────────────────────────────────────────────
# When tool stdout exceeds OUTPUT_CAP / MAX_TOOL_OUTPUT_LINES, the executor
# writes the untruncated output to a spill file so nothing is lost to the cap.

_SPILL_SEQ = itertools.count()


def resolve_spill_dir(trace_dir: str | None = None) -> str | None:
    """Directory for full-output spill files, or None to skip spilling.

    Prefers <trace_dir>/tool-output when the execution log is configured,
    else ./analysis/tool-output when the cwd looks like a case directory.
    Never raises — any failure (including an evidence-path resolution)
    returns None so the caller degrades to cap-only behavior.
    """
    try:
        if trace_dir:
            base = os.path.join(trace_dir, "tool-output")
        elif os.path.isdir("analysis"):
            base = os.path.join(os.getcwd(), "analysis", "tool-output")
        else:
            return None
        assert_output_safe(base)
        os.makedirs(base, exist_ok=True)
        return base
    except Exception:
        return None


def spill_file_path(spill_dir: str, cmd0: str) -> str:
    """Unique spill filename: <UTC ts>_<pid>_<seq>_<tool>.stdout.

    call_id is only assigned after the run completes, so uniqueness comes
    from timestamp + pid + a process-local counter instead.
    """
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    tool = os.path.basename(cmd0)[:40] or "tool"
    return os.path.join(spill_dir, f"{ts}_{os.getpid()}_{next(_SPILL_SEQ)}_{tool}.stdout")


# ── Training solution material blocklist ────────────────────────────────────
# Train cases ship answer keys next to the evidence (cases/<case>/Solution/,
# answers.json). The analyst must never read them, or it answers from the key
# instead of from the evidence. Enforced at both choke points:
# NarrationMiddleware scans every MCP tool argument, core.executor.run scans
# every argv token. The accuracy grader is exempted by tool name in the
# middleware since scoring a finished run against the key is its whole job.

SOLUTION_SEGMENTS = frozenset(
    {"solution", "solutions", "answer_key", "answer-key", "answerkey"})
SOLUTION_BASENAMES = frozenset(
    {"answers.json", "answers.yaml", "answers.yml", "answers.txt",
     "answers.md", "answers.csv", "answer_key.json", "solution.json",
     "solutions.json", "ground_truth.json"})

_PATH_SPLIT_RE = re.compile(r"[/\\]+")

# A ground truth in another language or version is the same key
# (ground_truth.en.json, ground_truth.v2.json).
_GT_VARIANT = r"ground_truth(?:\.[\w-]+)?\.json"
_GT_VARIANT_RE = re.compile(_GT_VARIANT, re.IGNORECASE)


def is_answer_key_name(name: str) -> bool:
    """Whether a file name is an answer key's: one of SOLUTION_BASENAMES or
    a ground-truth variant. The one name test the basename gate, the
    realpath registry and the stash share (core.brain.answer_key)."""
    n = (name or "").lower()
    return n in SOLUTION_BASENAMES or bool(_GT_VARIANT_RE.fullmatch(n))


# ── Positive-identifier answer-key gate ──────────────────────────────────────
# SOLUTION_BASENAMES/SOLUTION_SEGMENTS above is a fixed denylist that only
# matches intact tokens, leaving two structural blind spots the string layer
# cannot close: (1) a split-token interpreter payload that rebuilds a blocked
# basename by concatenation, and (2) the real key reached under a different
# name (a symlink `key.yaml -> ground_truth.json`, a `../` path, a case-variant,
# a mount view). The robust complement is to resolve the case's ACTUAL grading
# file(s) once at run setup and block them by REALPATH: any argument that
# resolves to a registered answer-key file is denied however it is spelled.
#
# Process-global by design: the FastMCP server, executor, and jobs runner all
# run in the analyst's own process (in-process client), so a set populated once
# at setup is visible at every enforcement point. The accuracy grader reads the
# key with a plain open() and is exempt at the middleware (SOLUTION_GATE_
# ALLOWLIST) and never routes through the executor/jobs gate, so server-side
# scoring is unaffected. Populated by register_answer_keys() (agent.cli at run
# start; tools.misc.start_execution_log for the standalone MCP server).

_BLOCKED_ANSWER_KEYS: set[str] = set()

# A realpath() resolve on every string argument would be wasteful; a real
# answer-key path is short, while an interpreter payload or a multi-KB query
# string is not (and a split-token payload never resolves to the key anyway —
# the filesystem stash covers that residual). Skip values longer than this.
_MAX_ANSWER_KEY_PATH_LEN = 4096


def register_answer_keys(case_dir) -> list[str]:
    """Record the realpath of every answer-key file the framework recognises
    for ``case_dir`` so the gate blocks the real file regardless of how it is
    later referenced. Idempotent (a set) and best-effort — never raises;
    returns the realpaths newly added."""
    added: list[str] = []
    try:
        from core.brain.answer_key import answer_key_paths
        for p in answer_key_paths(case_dir):
            try:
                rp = os.path.realpath(p)
            except (OSError, ValueError):
                continue
            if rp and rp not in _BLOCKED_ANSWER_KEYS:
                _BLOCKED_ANSWER_KEYS.add(rp)
                added.append(rp)
    except Exception:
        pass
    return added


def registered_answer_keys() -> frozenset:
    """The realpaths currently blocked by the positive-identifier gate."""
    return frozenset(_BLOCKED_ANSWER_KEYS)


def clear_registered_answer_keys() -> None:
    """Drop all registered answer-key realpaths (run reset / test isolation)."""
    _BLOCKED_ANSWER_KEYS.clear()


def _is_registered_answer_key(value: str) -> bool:
    """True if ``value`` resolves to a registered answer-key realpath."""
    if not _BLOCKED_ANSWER_KEYS or not value:
        return False
    if len(value) > _MAX_ANSWER_KEY_PATH_LEN:
        return False
    try:
        rp = os.path.realpath(os.path.expanduser(value))
    except (OSError, ValueError, TypeError):
        return False
    return rp in _BLOCKED_ANSWER_KEYS


def _under_mounted_evidence(value: str) -> bool:
    try:
        rp = os.path.realpath(os.path.expanduser(value))
    except (ValueError, TypeError):
        return False
    return rp.startswith(("/mnt/", "/media/"))


def is_solution_path(value: str) -> bool:
    """True if a string points into training solution material.

    Only path-shaped strings are flagged (a blocked basename, or a blocked
    segment between path separators) so free-text arguments containing the
    word "solution" pass. The /mnt//media exemption applies ONLY to the
    Solution/ *folder* heuristic — a suspect's own "Solutions" directory
    inside mounted evidence is legitimate. A known answer-key BASENAME
    (ground_truth.json, answers.json, ...) is blocked everywhere, including
    under a mount: nothing legitimately named that should be auto-read, and
    exempting it let a key shipped inside the image (or a case dir bind-
    mounted under /media) bypass every gate layer. A path that RESOLVES to a
    registered answer-key file (register_answer_keys) is blocked no matter how
    it is spelled — this catches a renamed reference (`key.yaml` symlinked to
    the real key), a relative path, or a mount view of it.
    """
    if not value or not isinstance(value, str):
        return False
    v = value.strip().strip("'\"")
    if _is_registered_answer_key(v):
        return True
    if is_answer_key_name(os.path.basename(v.rstrip("/\\"))):
        return True
    if _under_mounted_evidence(v):
        return False  # only the folder-segment heuristic is mount-exempt
    parts = [s.lower() for s in _PATH_SPLIT_RE.split(v) if s]
    if len(parts) < 2:
        return False  # not path-shaped — bare words are never flagged
    return any(p in SOLUTION_SEGMENTS for p in parts)


SOLUTION_BLOCK_MESSAGE = (
    "Access to training solution material (Solution/, answers.json, ...) is "
    "blocked: findings must come from the evidence itself. Re-derive the "
    "answer from forensic artifacts."
)

# Interpreter payloads defeat the path-shaped check: a single argv token like
# `python3 -c "open('ground_truth.json').read()"` has no path separator and
# its basename is the whole string, so is_solution_path passes it. This
# regex flags solution material *mentioned inside* command text. Only apply
# it to command material (executor argv, cmd/script/query tool args) — a
# finding description that merely mentions "ground_truth.json" is prose,
# not an access attempt.
_BASENAME_ALT = "|".join(re.escape(b) for b in sorted(SOLUTION_BASENAMES))
_SEGMENT_ALT = "|".join(re.escape(s) for s in sorted(SOLUTION_SEGMENTS))
# A known answer-key basename anywhere in the text — blocked even under a
# mount (see is_solution_path).
_SOLUTION_BASENAME_RE = re.compile(r"\b(?:" + _BASENAME_ALT + "|" + _GT_VARIANT + r")\b",
                                   re.IGNORECASE)
# A blocked segment adjacent to a path separator: "Solution/answers",
# "cases/x/Solution/", "cat cases/x/Solution". Mount-exempt.
_SOLUTION_SEGMENT_RE = re.compile(
    r"(?:(?<![\w.-])(?:" + _SEGMENT_ALT + r")(?=[/\\]))"
    + r"|(?:(?<=[/\\])(?:" + _SEGMENT_ALT + r")(?![\w.-]))",
    re.IGNORECASE)


def contains_solution_reference(value: str) -> bool:
    """True if command text references training solution material anywhere
    inside it. A known answer-key basename is flagged unconditionally; the
    Solution/-folder segment heuristic is exempt under mounted evidence
    (same split as is_solution_path)."""
    if not value or not isinstance(value, str):
        return False
    v = value.strip().strip("'\"")
    if _SOLUTION_BASENAME_RE.search(v):
        return True
    if _under_mounted_evidence(v):
        return False
    return bool(_SOLUTION_SEGMENT_RE.search(v))


# ── Answer-key stash (filesystem belt for graded, non-mirror runs) ────────────
# The gate above blocks *references* to the key; a determined split-token
# interpreter payload that rebuilds a relative basename still can't be pattern-
# matched. For a graded `atlas train` run that executes IN the case directory
# (no --output-dir mirror to exclude the key), agent.cli moves the answer-key
# file(s) out of the analyst's tree for the analyst phase and restores them
# before the reviewer/grader read them — so a payload that dodges the gate
# finds nothing to open. Mirror runs (--output-dir) already omit the
# key, so the caller only stashes non-mirror runs (and stashing a shared real-
# case key from concurrent cells would race). A per-file `.orig` sidecar lets a
# crash-interrupted stash self-heal on the next run; answer keys are also git-
# tracked, a second safety net.

def _answer_key_stash_root() -> str:
    """Directory that holds stashed answer-key files. Overridable via
    ATLAS_ANSWER_KEY_STASH_DIR (test isolation)."""
    override = os.environ.get("ATLAS_ANSWER_KEY_STASH_DIR")
    if override:
        return os.path.expanduser(override)
    return os.path.join(os.path.expanduser("~/.cache/atlas"), "answer-key-stash")


def _stash_base(root: str, original_realpath: str) -> str:
    import hashlib
    digest = hashlib.sha256(original_realpath.encode("utf-8")).hexdigest()
    return os.path.join(root, digest)


def stash_answer_keys(case_dir) -> list[dict]:
    """Move the case's answer-key file(s) out of the analyst's tree. Returns a
    list of {"original", "stash"} records for restore_answer_keys(). Best-
    effort: a file that cannot be moved is skipped (the pattern + realpath gate
    still guard it) and never raises into the run."""
    import shutil
    from core.brain.answer_key import answer_key_paths
    root = _answer_key_stash_root()
    records: list[dict] = []
    try:
        os.makedirs(root, exist_ok=True)
    except OSError:
        return records
    for p in answer_key_paths(case_dir):
        original = os.path.realpath(p)
        base = _stash_base(root, original)
        stash, sidecar = base + ".key", base + ".orig"
        try:
            # Sidecar first so a crash between the two leaves a recoverable
            # mapping; if the move then fails, the original is still in place
            # and the stray sidecar is cleaned up.
            with open(sidecar, "w", encoding="utf-8") as f:
                f.write(original)
            shutil.move(original, stash)
        except OSError:
            try:
                if os.path.exists(sidecar) and not os.path.exists(stash):
                    os.remove(sidecar)
            except OSError:
                pass
            continue
        records.append({"original": original, "stash": stash})
    return records


def restore_answer_keys(records) -> list[str]:
    """Move stashed answer-key file(s) back. If the original reappeared while
    stashed (git restore, a concurrent run), the on-disk copy wins and the
    stash is dropped rather than clobbering it. Returns originals restored."""
    import shutil
    restored: list[str] = []
    for rec in records or []:
        original, stash = rec.get("original"), rec.get("stash")
        if not original or not stash:
            continue
        sidecar = stash + ".orig"
        try:
            if os.path.exists(stash):
                if os.path.exists(original):
                    os.remove(stash)
                else:
                    shutil.move(stash, original)
                    restored.append(original)
            if os.path.exists(sidecar):
                os.remove(sidecar)
        except OSError:
            continue
    return restored


def recover_stashed_answer_keys(case_dir=None) -> list[str]:
    """Restore answer-key files orphaned by a crash-interrupted stash, reading
    the `.orig` sidecars. With ``case_dir``, only files whose original lives
    under it are restored; otherwise the whole stash root is swept. Returns the
    originals restored."""
    import glob
    import shutil
    root = _answer_key_stash_root()
    if not os.path.isdir(root):
        return []
    scope = os.path.realpath(str(case_dir)) if case_dir else None
    restored: list[str] = []
    for sidecar in glob.glob(os.path.join(glob.escape(root), "*.orig")):
        try:
            with open(sidecar, encoding="utf-8") as f:
                original = f.read().strip()
        except OSError:
            continue
        if not original:
            continue
        rp = os.path.realpath(original)
        if scope and rp != scope and not rp.startswith(scope + os.sep):
            continue
        stash = sidecar[:-len(".orig")] + ".key"
        try:
            if os.path.exists(original):
                if os.path.exists(stash):
                    os.remove(stash)     # original already present — stash stale
            elif os.path.exists(stash):
                shutil.move(stash, original)
                restored.append(original)
            os.remove(sidecar)
        except OSError:
            continue
    return restored


def parse_case_id_from_text(text: str) -> str | None:
    """Extract a Case ID from CASE.md / CLAUDE.md body text.

    Accepts template form ``**Case ID:** ID``, table ``| **Case ID** | ID |``,
    ``**Case ID**: ID``, and bare ``case_id: ID`` / ``Case ID: ID``.
    """
    if not text:
        return None
    # Colon may sit inside or outside the bold markers (template vs table).
    m = re.search(r"\*\*Case ID:?\*\*[:\s|]+([A-Za-z0-9_\-]+)", text)
    if m:
        return m.group(1)
    m = re.search(r"case[_\s]id[:\s|]+([A-Za-z0-9_\-]+)", text, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def detect_case_id(case_dir: str | os.PathLike) -> str:
    """Best-effort case_id discovery: `**Case ID**` (then any `case_id`) in
    CASE.md or CLAUDE.md, falling back to the directory basename. Works in
    --output-dir mirrors too — _prepare_output_dir symlinks the case brief in, and
    the mirror's own basename (`run-1`) is useless.

    Parsing lives in parse_case_id_from_text, which dashboard/serve.py and
    tools/atlas_reset.py now call as well — they used to carry hand-copied
    regexes, and that divergence is what let the `**Case ID:** X` blind spot
    survive in three committed demo briefs."""
    case_dir = str(case_dir)
    brief_seen = False
    for name in ("CASE.md", "CLAUDE.md"):
        md = os.path.join(case_dir, name)
        if not os.path.exists(md):
            continue
        try:
            with open(md) as f:
                text = f.read(8192)
        except OSError:
            continue
        brief_seen = True
        cid = parse_case_id_from_text(text)
        if cid:
            return cid
    fallback = os.path.basename(os.path.abspath(case_dir))
    if brief_seen:
        # Only a brief that EXISTS and still yields no id is a defect signal —
        # that is the failure this warning was added for, and it used to be
        # silent. No brief at all is a documented path (see above), and warning
        # there would bury the real case in noise.
        import logging
        logging.getLogger(__name__).warning(
            "detect_case_id: no Case ID in CASE.md/CLAUDE.md under %s; "
            "falling back to directory basename %r",
            case_dir,
            fallback,
        )
    return fallback


# A case's own output directories. Under a read-only prefix such as
# /cases/, everything is evidence *except* what the case itself writes —
# without this exception a case living at /cases/X could not write its own
# reports/ (assert_output_safe refused them) and `cp evidence/x analysis/x`
# read as an evidence write.
CASE_OUTPUT_SEGMENTS = ("analysis", "exports", "reports", ".atlas", "tool-output")


def is_evidence_path(path: str) -> bool:
    """Return True if path is under a protected evidence location."""
    p = os.path.realpath(path)
    parts = Path(p).parts
    for i, seg in enumerate(parts):
        if seg in READ_ONLY_SEGMENTS:
            return True
        if seg in CASE_OUTPUT_SEGMENTS and i > 0:
            return False          # a case output dir, not yet inside evidence/
    return any(p.startswith(prefix) for prefix in READ_ONLY_PREFIXES)


def active_case_dir() -> str | None:
    """The case directory of the run in progress, or None outside a run."""
    try:
        from core.execution_log import log
        cd = log.case_dir()
    except Exception:
        return None
    return str(cd) if cd else None


def _real_anchor(path: str) -> str:
    """``realpath`` of a path that may not exist yet: resolve the deepest
    existing ancestor (so a symlink out of the case is seen) and keep the
    rest as written."""
    p = os.path.abspath(os.path.expanduser(path))
    rest: list[str] = []
    while not os.path.lexists(p):
        head, tail = os.path.split(p)
        if not tail or head == p:
            break
        rest.append(tail)
        p = head
    return os.path.join(os.path.realpath(p), *reversed(rest))


def is_inside(path: str, root: str) -> bool:
    """True when ``path`` (existing or not) resolves under ``root``."""
    r = os.path.realpath(root)
    a = _real_anchor(path)
    return a == r or a.startswith(r.rstrip(os.sep) + os.sep)


def output_roots(case_dir: str) -> list[str]:
    """Where a run may write: its own case directory and the temp dir."""
    import tempfile
    return [case_dir, tempfile.gettempdir()]


def assert_output_safe(path: str) -> None:
    """Raise ValueError if an output path is inside evidence or, during a
    run, outside the case.

    Only evidence was refused before, so ``output_csv="/home/me/x.csv"``
    (or ``~/.ssh/authorized_keys``) went through: the middleware's scope
    gate skips paths that do not exist yet, and an output never does. A
    line in an evidence file telling the agent where to write is the
    obvious way to abuse that.
    """
    if is_evidence_path(path):
        raise ValueError(
            f"Output path '{path}' is inside a protected evidence directory. "
            "Write outputs to ./analysis/, ./exports/, or ./reports/ only."
        )
    case = active_case_dir()
    if not case:
        return
    cand = os.path.expanduser(str(path))
    if not os.path.isabs(cand):
        cand = os.path.join(case, cand)
    if not any(is_inside(cand, r) for r in output_roots(case)):
        raise ValueError(
            f"Output path '{path}' is outside the case directory. "
            "Write outputs to the case's ./analysis/, ./exports/ or "
            "./reports/ only."
        )
    # The path is inside the case, so its parent may be made here: a tool
    # that opens an output under a directory named for the first time
    # otherwise fails on the open, whatever the tool. Created only after
    # the check above and at the resolved location it checked, so a parent
    # is never made anywhere the guard would not let a file go.
    try:
        os.makedirs(os.path.dirname(_real_anchor(cand)), exist_ok=True)
    except OSError:
        pass  # the tool's own error names the path


def reclaim_output_ownership(path: str) -> bool:
    """Hand a tree written by a tool that ran as root back to this user.

    A tool spawned under sudo leaves its output owned by root: later reads
    by the run's own tools fail with permission denied, and a case clear
    cannot remove the tree, so a run started as fresh inherits it unseen.
    The sudoers grant already covers chown. Best-effort and never raises;
    True when the tree is ours afterwards. ``-n`` so a missing grant fails
    at once instead of waiting on a password prompt.
    """
    try:
        if not path or not os.path.isdir(path):
            return False
        owner = f"{os.getuid()}:{os.getgid()}"
        res = subprocess.run(["sudo", "-n", "chown", "-R", owner, path],
                             stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             timeout=300, check=False)
        return res.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def ensure_mount_point(path: str) -> dict | None:
    """Create a mount-point directory, escalating to sudo for system paths.

    Mount tools previously called os.makedirs as the unprivileged server
    user, so a system mount point like /mnt/ewf_pc raised PermissionError
    as a raw traceback instead of a tool result.
    Returns None on success, or a run()-shaped error dict for the caller
    to return as the tool result.
    """
    try:
        os.makedirs(path, exist_ok=True)
        return None
    except PermissionError:
        pass
    case = active_case_dir()
    if is_evidence_path(path) and not (case and is_inside(path, case)):
        # A system mount tree (/mnt, /media) is protected like evidence:
        # the executor refuses anything created there, so say so instead
        # of creating a root-owned directory the refusal then reports as
        # "evidence modified".
        return {
            "success": False, "stdout": "", "exit_code": 1, "truncated": False,
            "stderr": (
                f"Cannot use '{path}' as a mount point: system mount trees "
                "are protected like evidence. Use a case-relative mount "
                "point such as <case>/mnt/<image>/... instead."),
        }
    from .executor import run  # function-level: executor imports paths
    res = run(["mkdir", "-p", path], needs_sudo=True)
    if res.get("success"):
        return None
    res["stderr"] = (
        f"Cannot create mount point '{path}' (permission denied, sudo "
        "mkdir also failed). Use a case-relative mount point such as "
        "<case>/mnt/... instead of a system path. "
        + (res.get("stderr") or "")
    )
    return res


# Common output-parameter names across tool modules. The @output_safe
# decorator scans wrapped function signatures for any of these and validates
# the value at call-time. Centralising this means tool bodies do not need to
# repeat assert_output_safe() for every output param.
_OUTPUT_PARAM_NAMES = (
    "output_path",
    "output_dir",
    "output_file",
    "output_pcap",
    "output_csv",
    "output_json",
    "output_manifest",
    "storage_file",
)

# Mount-point parameter names across the mount tools (ewf.*, img.*).
MOUNT_PARAM_NAMES = (
    "mount_point",
    "ewf_mount_point",
    "fs_mount_point",
)

# Parameters whose relative values mean "under the case directory". The MCP
# server's CWD is the repo root, not the case dir, so a relative value passed
# straight to subprocess/open() lands under the repo root. core.middleware resolves these against the active
# case directory before the tool body runs, or refuses when no case is active.
CASE_PATH_PARAM_NAMES = _OUTPUT_PARAM_NAMES + MOUNT_PARAM_NAMES + ("link_dir",)

# Input filesystem arguments that must already exist when provided. Symmetric
# to @_OUTPUT_PARAM_NAMES / @output_safe: without a shared gate, tools treat a
# missing directory/file as "empty success" (hash_directory on a nonexistent
# path returned success=True, file_count=0). Middleware refuses these before
# the tool body runs. Mount/output params are intentionally excluded — those
# are created by the tool.
INPUT_PATH_PARAM_NAMES = (
    "file_path",
    "file1",
    "file2",
    "directory",
    "dir_path",
    "path",
    "image_path",
    "memory_path",
    "evtx_path",
    "hive_path",
    "pcap_path",
    "evidence_path",
    "input_path",
    "source_path",
    "target_path",
    "dump_path",
    "artifact_path",
    "timeline_path",
    "csv_path",
    "json_path",
    "rules_path",
    "yara_path",
    "binary_path",
)


def output_safe(func):
    """Decorator that validates any output_* / storage_file kwarg against the
    evidence read-only policy before calling the wrapped function.

    Apply BELOW @mcp.tool() so MCP introspects the original signature:

        @mcp.tool()
        @output_safe
        def my_tool(image: str, output_dir: str) -> dict: ...
    """
    sig = inspect.signature(func)
    relevant = tuple(n for n in _OUTPUT_PARAM_NAMES if n in sig.parameters)
    if not relevant:
        return func

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            bound = sig.bind_partial(*args, **kwargs)
        except TypeError:
            # Signature mismatch — let the wrapped function raise its own error.
            return func(*args, **kwargs)
        for name in relevant:
            value = bound.arguments.get(name)
            if value:
                assert_output_safe(value)
        return func(*args, **kwargs)

    return wrapper


def resolve_path_ci(path: str) -> tuple[str, bool]:
    """Walk path components case-insensitively on the real filesystem.

    Returns (resolved_path, was_corrected). was_corrected=True means at least
    one component was case-folded to match an actual directory entry.
    If a component has no match the original path is returned with was_corrected=False
    so callers can report a clean not-found error.
    """
    path = os.path.normpath(os.path.expanduser(path))
    parts = Path(path).parts          # e.g. ('/', 'mnt', 'host01', 'Windows', ...)
    current = parts[0]                # '/'
    corrected = False
    for part in parts[1:]:
        try:
            entries = os.listdir(current)
        except (PermissionError, NotADirectoryError, FileNotFoundError):
            return path, False
        if part in entries:
            current = os.path.join(current, part)
        else:
            lower = part.lower()
            matches = [e for e in entries if e.lower() == lower]
            if matches:
                current = os.path.join(current, matches[0])
                corrected = True
            else:
                return path, False    # component missing — caller handles not-found
    return current, corrected


# vol3_bin and vol3_symbols locate Volatility and its symbol tables for
# tools/volatility.py. Like that file, to the extent the Volatility Software
# License 1.0 treats them as part of an Addition, they are offered under that
# licence in addition to Atlas's own (see THIRD-PARTY.md).
def vol3_bin() -> str:
    """Resolve the Volatility 3 binary.

    SIFT Workstation installs it at /usr/local/bin/vol; a standalone install
    (install.sh, no pre-existing SIFT base) installs it via pip into the
    project venv and puts it on PATH instead. Check both, in that order of
    explicitness: an explicit override, then PATH, then the SIFT default so
    behavior on a SIFT Workstation is unchanged.
    """
    return (os.environ.get("ATLAS_VOL3_BIN")
            or shutil.which("vol")
            or "/usr/local/bin/vol")


def vol3_symbols() -> str:
    """Return writable Volatility 3 symbol cache directory, creating it if needed."""
    # Use `or` so an empty VOLATILITY_SYMBOLS env var falls back to the default
    path = os.environ.get("VOLATILITY_SYMBOLS") or os.path.expanduser("~/.cache/volatility3/symbols")
    os.makedirs(path, exist_ok=True)
    return path


def ez_tool(name: str, subdir: str | None = None) -> str:
    base = "/opt/zimmermantools"
    if subdir:
        return f"dotnet {base}/{subdir}/{name}.dll"
    return f"dotnet {base}/{name}.dll"


def ensure_venv_on_path() -> str:
    """Put the running interpreter's bin directory first on PATH so console
    scripts installed with the Python dependencies (capa, floss, olevba,
    mraptor, …) are found by the tool wrappers whatever PATH the service
    or shell started with. Returns the resulting PATH."""
    import sys

    parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    # The interpreter's bin first, then every install root a forensic program
    # may live in. A wrapper that runs a bare name (net.zeek_analyze -> zeek)
    # can only find it through PATH, so resolution and execution have to agree
    # about where programs are.
    prepend: list[str] = []
    for directory in (os.path.join(sys.prefix, "bin"), *_tool_dirs()):
        # Order matters and is the interpreter's bin first: a console script
        # installed with Atlas's own dependencies must win over a system copy.
        if (os.path.isdir(directory) and directory not in parts
                and directory not in prepend):
            prepend.append(directory)
    os.environ["PATH"] = os.pathsep.join(prepend + parts)
    return os.environ["PATH"]


# ── one way to find a forensic program ───────────────────────────────────────
# Wrappers used to spell this three different ways: `shutil.which(name)`, a
# hardcoded "/usr/local/bin/<name>", or `which() or "/usr/local/bin/<name>"`.
# The hardcoded form ignores PATH entirely, so a program installed anywhere
# else is invisible to the wrapper while `missing_binaries()` — which asks
# PATH — reports it present. The manifest and the wrapper have to ask the
# same question, and this is it.
def _tool_dirs() -> tuple[str, ...]:
    """Where a forensic program can live, beyond PATH.

    The running interpreter's bin directory comes first: console scripts
    installed with the Python dependencies (capa, floss, hindsight,
    pe-carver, usn.py) live there, and a caller that never prepared PATH —
    the installer's verification step, a dashboard request — would otherwise
    report every one of them missing.
    """
    import glob
    import sys

    # Packages that install under /opt keep their own bin directory and put
    # nothing on PATH: zeek ships /opt/zeek/bin/zeek, and a system with it
    # installed still reported the tool missing — and net.zeek_analyze, which
    # runs the bare name, would have failed for the same reason.
    opt_bins = tuple(sorted(d for d in glob.glob("/opt/*/bin") if os.path.isdir(d)))
    return (
        os.path.join(sys.prefix, "bin"),
        "/usr/local/bin",
        *opt_bins,
        os.path.expanduser("~/.local/bin"),
    )


def tool_program(name: str, *extra_dirs: str) -> "str | None":
    """Absolute path to a forensic program, or None when it is not installed.

    Order: ``ATLAS_BIN_<NAME>`` override, PATH (which covers the venv bin
    once ``ensure_venv_on_path`` has run), then the conventional install
    directories. ``extra_dirs`` is for tools with their own install root.
    """
    import shutil

    if not name:
        return None
    env_key = "ATLAS_BIN_" + re.sub(r"[^A-Za-z0-9]+", "_", name).upper()
    override = os.environ.get(env_key)
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    found = shutil.which(name)
    if found:
        return found
    for directory in (*extra_dirs, *_tool_dirs()):
        cand = os.path.join(os.path.expanduser(directory), name)
        if not os.path.isfile(cand):
            continue
        # A Python script installed by pip may arrive without the execute
        # bit (pyhindsight ships hindsight.py mode 0644): it is still
        # perfectly runnable through the interpreter — see program_argv.
        if os.access(cand, os.X_OK) or cand.endswith(".py"):
            return cand
    return None


def program_argv(program: str) -> list[str]:
    """The argv prefix that actually runs ``program``.

    A ``.py`` the kernel cannot exec — no execute bit ("Permission denied"),
    or no ``#!`` line ("Exec format error", a package module copied as a
    file) — still runs through this interpreter, so a program the operator
    did install works.
    """
    import sys

    if program and program.endswith(".py") and (
            not os.access(program, os.X_OK) or not _has_interpreter_line(program)):
        return [sys.executable, program]
    return [program]


def _has_interpreter_line(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        # Unreadable: exec it as it is and let the executor report why.
        return True


def missing_program_result(tool: str, name: str, install_hint: str = "") -> dict:
    """The refusal a wrapper returns when its program is not installed.

    A bare OSError from the executor reads to the model like a broken call
    it should retry; this says the program is absent and what installs it.
    """
    hint = install_hint or f"install {name} and re-run, or ask the operator to"
    return {
        "success": False,
        "error": f"{tool}: {name} is not installed on this system",
        "hint": hint + " — every other tool remains available.",
        "gate": "program_missing",
        "program": name,
        "stdout": "",
        "stderr": "",
        "exit_code": 127,
    }
