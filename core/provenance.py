"""What a tool call read, and which call wrote each file of the run.

``citation_class`` says what kind of record a trace entry is (what a tool
read, the run's own words, a lookup). This module says what the call was
pointed at, which that class does not ask: the paths it named as input,
each classed by where it resolves, never by the names of its segments.

- Under the case's ``evidence/`` or ``mnt/`` tree, or under a mount point
  or device of the access plan: **evidence**, with the host the evidence
  links give the image.
- Under the case's output tree (``analysis/``, ``exports/``, ``reports/``,
  ``.atlas/``, ``tool-output/``, ``CASE.md``): **derived** when a fixed tool
  produced the file from evidence or derived input, **own** otherwise. Which
  call produced a file is the attribution ledger's answer
  (``.atlas/output_provenance.json``, written around every tool call from a
  stat snapshot of the output tree); an extracted copy the contents index
  registered is derived whatever a record says, and a folder of such copies
  is derived when no same-kind file of the run's own sits beside them; a
  file no record or copy attributes is derived only when it predates the
  run's first call (intake's own parsers), else own, fail closed. A path
  that names no content (absent, an empty folder) is no input beside a
  derived one. A scripted call (an interpreter given a program) writes the
  run's own material whatever the program read, because the program's text
  can put the analyst's words into the file.
- Outside the case: **own**.

A call's class follows its inputs: ``evidence`` or ``derived`` when it names
such a path and no own path, ``own`` when it names an own path, ``unplaced``
when it names no path (a table addressed by id, a correlation tool).
"""
from __future__ import annotations

from core.store_lock import locked as _locked

import functools
import json
import os
import re
import threading
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

LEDGER_FILE = ".atlas/output_provenance.json"
# The output tree the snapshot walks. ``tool-output/`` holds the spills of
# the calls themselves, ``.atlas/`` the run's own state and ``CASE.md`` the
# brief: all own by containment, never a parser's output, so the walk skips
# them. The run's state files that live under ``analysis/`` (the trace, the
# transcript, the evidence index, the Brain's state, a parser's memo) are
# written by Atlas itself in-process, during or between calls, and are
# skipped by name (see _state_file_names); a file a later read of them
# shows is the run's own material, never a sighting.
_SNAPSHOT_DIRS = ("analysis", "exports", "reports")
_SNAPSHOT_SKIP_DIRS = frozenset({"tool-output"})
# The public interpreter programs a scripted call hands a program to: an
# argument of theirs is code, so their written files carry the analyst's
# words. Universal tool names, not case knowledge.
INTERPRETERS = frozenset({
    "python", "python3", "python2", "pypy", "pypy3", "bash", "sh", "zsh", "dash", "ksh",
    "perl", "ruby", "node", "nodejs", "pwsh", "powershell", "lua", "php", "awk", "gawk",
})

_LOCK = threading.RLock()
_CACHE: dict[tuple[str, int], dict[str, Any]] = {}
_FIRST_CALL_TS: dict[str, float] = {}


def _case_root(case_dir: str | os.PathLike | None) -> str:
    if case_dir:
        return os.path.realpath(str(case_dir))
    try:
        from core.claim_graph import resolve_case_dir
        active = resolve_case_dir(None)
    except Exception:  # noqa: BLE001
        active = None
    return os.path.realpath(active) if active else ""


def _under(path: str, root: str) -> bool:
    return bool(root) and (path == root or path.startswith(root.rstrip(os.sep) + os.sep))


def _forms(token: str, root: str) -> tuple[str, str]:
    """The absolute spelling of a path token and its resolved form. Both
    are tested, so a link from the evidence tree to an image kept elsewhere
    stays evidence by its spelling, and a link from the output tree into
    evidence is evidence by where it resolves."""
    absolute = os.path.normpath(os.path.join(root or os.getcwd(), token))
    return absolute, os.path.realpath(absolute)


def _plan_images(root: str) -> list[tuple[str, dict, str]]:
    """(image path, mount result, auto-mount folder) of each image of the
    access plan: the one reading of the plan's reach (_plan_reach,
    plan_mounts)."""
    try:
        from core.mount_plan import load_mount_plan, mount_dir_for
        plan = load_mount_plan(root)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for img in plan.get("images") or []:
        if isinstance(img, dict) and img.get("path"):
            path = str(img["path"])
            out.append((path, img.get("mount_result") or {}, mount_dir_for(root, path, img)))
    return out


def _plan_reach(root: str) -> tuple[list[tuple[str, str]], list[str]]:
    """(resolved mount points and devices with their image path, resolved
    image paths) from the access plan."""
    reach: list[tuple[str, str]] = []
    images: list[str] = []
    for path, mr, folder in _plan_images(root):
        images.append(os.path.realpath(path if os.path.isabs(path) else os.path.join(root, path)))
        for point in (str(mr.get("mount_point") or ""), str(mr.get("ewf_device") or ""), folder):
            if point:
                reach.append((os.path.realpath(point), path))
    return reach, images


def plan_mounts(root: str) -> list[tuple[str, str, int | None]]:
    """(resolved filesystem mount point, image path, mounted volume's offset
    in sectors or None when the plan has none) of each filesystem the access
    plan mounted from an image: a mount the plan found gone (stale) or that
    failed is none."""
    out = []
    for path, mr, _folder in _plan_images(root):
        point = str(mr.get("mount_point") or "")
        if point and not mr.get("stale") and mr.get("success") is not False:
            off = mr.get("volume_offset_sectors")
            out.append((os.path.realpath(point), path, int(off) if off is not None else None))
    return out


# Public programs that run another program given later on their command
# line ("timeout 300 python3 x.py", "env A=1 python3 x.py", "xargs -a l
# python3 x.py"). Universal tool names, not case knowledge.
WRAPPERS = frozenset({
    "timeout", "env", "nice", "ionice", "sudo", "doas", "xargs", "stdbuf", "nohup",
    "time", "exec", "command", "setsid", "unbuffer", "parallel",
})
# The shell's own literal writers: with an output redirect, their argument
# text (the analyst's words) becomes the file.
_LITERAL_WRITERS = frozenset({"echo", "printf"})
_SHELL_OPERATORS = frozenset({";", "&&", "||", "|", "&", "|&", ";;", "(", ")"})
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>"})


def _program_name(token: str) -> str:
    program = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".py"):
        program = program.removesuffix(suffix)
    return program


def _is_interpreter(token: str) -> bool:
    program = _program_name(token)
    return program in INTERPRETERS or program.rstrip("0123456789.") in INTERPRETERS


def _simple_commands(cmd: str) -> list[list[str]]:
    """``cmd`` split into its simple commands at the shell's list and pipe
    operators, each as its tokens (quotes honoured, redirects as their own
    tokens). An unbalanced quote falls back to whitespace splitting."""
    import shlex
    try:
        lexer = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = cmd.split()
    commands: list[list[str]] = [[]]
    for tok in tokens:
        if tok in _SHELL_OPERATORS:
            commands.append([])
        else:
            commands[-1].append(tok)
    return [c for c in commands if c]


def _scripted_command(words: list[str], *, modules_run: bool = False, root: str = "") -> bool:
    """One simple command hands a program to an interpreter or writes a
    literal into a file. Leading variable assignments are skipped; behind a
    wrapper program any interpreter token counts (fail closed: a wrapped
    grep for the word "python" reads as scripted). ``modules_run``: an
    interpreter told to run an installed module (``python3 -m <module>``)
    runs a tool, not the analyst's code. An interpreter running a script
    file installed before the run (outside the case, older than the trace's
    first entry; the rules-file test) runs a fixed tool; a script in the
    case, one written during the run, ``-c`` and a script on stdin stay
    scripted."""
    i = 0
    while i < len(words) and "=" in words[i] and not words[i].startswith(("-", "=")):
        i += 1
    if i >= len(words):
        return False
    program = _program_name(words[i])
    if _is_interpreter(words[i]):
        if modules_run and "-m" in words[i + 1:i + 3]:
            return False
        return not _installed_script(words[i + 1:], root)
    if program in WRAPPERS:
        k = next((j for j in range(i + 1, len(words)) if _is_interpreter(words[j])), None)
        return k is not None and _scripted_command(words[k:], modules_run=modules_run, root=root)
    if program in _LITERAL_WRITERS:
        return any(w in _REDIRECTS for w in words[i + 1:])
    return False


def _installed_script(args: list[str], root: str) -> bool:
    """Whether an interpreter's operand is a script file installed before
    the run: outside the case, its mtime and ctime older than the trace's
    first entry. Options are skipped; ``-c`` and no operand (a script on
    stdin or a heredoc) are never installed scripts."""
    import os
    for k, w in enumerate(args):
        if w in ("-c", "-"):
            return False
        if w.startswith("-"):
            continue
        path = w
        break
    else:
        return False
    if not root or not os.path.isfile(path):
        return False
    real = os.path.realpath(path)
    if _under(real, os.path.realpath(root)):
        return False
    first = _first_call_time(root)
    try:
        st = os.stat(real)
    except OSError:
        return False
    return bool(first) and max(st.st_mtime, st.st_ctime) < first


def is_scripted(entry: dict, case_dir: str | os.PathLike | None = None) -> bool:
    """A call that hands a program to an interpreter, writes a literal into
    a file, or writes a case document: its written files are the run's own
    material. Every simple command of a shell line is tested, so an
    interpreter behind a wrapper, a "cd x &&" or a pipe is seen. With the
    case known, an installed tool script run by its interpreter is a fixed
    tool (_installed_script)."""
    cmd = str(entry.get("cmd") or "")
    if cmd.startswith("<py>:misc_write_"):
        return True
    root = _case_root(case_dir) if case_dir is not None else ""
    return any(_scripted_command(words, root=root) for words in _simple_commands(cmd))


# Runtimes that are handed a tool's own program file (an assembly, a jar):
# the file is the program, not an input. Universal tool names.
_PROGRAM_RUNTIMES = frozenset({"dotnet", "mono", "java"})
# Options that name a tool's own resources (Volatility 3's symbol, plugin
# and cache directories): never an input the call read evidence from.
# Public command-line options of a published tool, not case knowledge.
_RESOURCE_OPTIONS = frozenset({"-s", "--symbol-dirs", "-p", "--plugin-dirs", "--cache-path"})
# The programs those options belong to (Volatility 3 as a binary, a script or
# an installed module): other programs use the same letters for other things
# (ls -s, du -s, unzip -p name a size or a pipe, not a resource directory).
_RESOURCE_OPTION_PROGRAMS = frozenset({"vol", "vol3", "volatility", "volatility3"})


def _not_inputs(cmd: str) -> set[str]:
    """The tokens of ``cmd`` that are a program rather than a file it read:
    each simple command's program (behind assignments and wrapper
    programs), the assembly or jar a runtime is handed, and the value of an
    option naming the tool's own resource directory."""
    out: set[str] = set()
    for words in _simple_commands(cmd):
        i = 0
        while i < len(words) and "=" in words[i] and not words[i].startswith(("-", "=")):
            i += 1
        while i < len(words) and _program_name(words[i]) in WRAPPERS:
            i += 1
            while i < len(words) and (words[i].startswith("-") or words[i].isdigit() or "=" in words[i]):
                i += 1
        if i >= len(words):
            continue
        out.add(words[i])
        rest = words[i + 1:]
        if _is_interpreter(words[i]) and "-m" in rest[:2]:
            k = rest.index("-m")
            if k + 1 < len(rest):
                out.add(rest[k + 1])
        runtime = _program_name(words[i])
        module = rest[rest.index("-m") + 1] if "-m" in rest[:2] and rest.index("-m") + 1 < len(rest) else ""
        volatility = (runtime in _RESOURCE_OPTION_PROGRAMS
                      or _program_name(module) in _RESOURCE_OPTION_PROGRAMS
                      or (_is_interpreter(words[i]) and rest
                          and _program_name(rest[0]) in _RESOURCE_OPTION_PROGRAMS))
        if runtime in _PROGRAM_RUNTIMES:
            if runtime == "java" and "-jar" in rest and rest.index("-jar") + 1 < len(rest):
                out.add(rest[rest.index("-jar") + 1])
            elif runtime != "java":
                first = next((w for w in rest if not w.startswith("-")), "")
                if first:
                    out.add(first)
        for k, w in enumerate(rest if volatility else []):
            if w in _RESOURCE_OPTIONS and k + 1 < len(rest):
                out.add(rest[k + 1])
            elif "=" in w and w.split("=", 1)[0] in _RESOURCE_OPTIONS:
                out.add(w.split("=", 1)[1])
    return {t for t in out if t}


def _ledger_path(root: str) -> Path:
    return Path(root) / LEDGER_FILE


# {ledger path: ((size, mtime), files)}: the output ledger is read per trace
# call by the read rule (input_tokens); one parse per version of the file.
_LEDGER_MEMO: dict[str, tuple[tuple, dict[str, dict[str, Any]]]] = {}


def load_ledger(case_dir: str | os.PathLike | None) -> dict[str, dict[str, Any]]:
    """``{relative path: {"call": id, "class": "derived" | "own"}}`` (a copy;
    parsed once per version of the file)."""
    root = _case_root(case_dir)
    if not root:
        return {}
    path = _ledger_path(root)
    try:
        st = path.stat()
        version = (st.st_size, st.st_mtime_ns)
    except OSError:
        return {}
    hit = _LEDGER_MEMO.get(str(path))
    if hit is not None and hit[0] == version:
        return dict(hit[1])
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    files = files if isinstance(files, dict) else {}
    if len(_LEDGER_MEMO) > 64:
        _LEDGER_MEMO.clear()
    _LEDGER_MEMO[str(path)] = (version, files)
    return dict(files)


def _save_ledger(root: str, files: dict[str, dict[str, Any]]) -> None:
    path = _ledger_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"files": files}, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


@functools.cache
def _state_file_names() -> tuple[frozenset[str], tuple[str, ...], tuple[str, ...]]:
    """(exact names, name prefixes, name suffixes) of the run's state files
    under the output tree, from the core modules that define them."""
    from core.evidence_index import INDEX_FILE
    from core.run_state import TRACE_SUFFIXES, TRANSCRIPT_PREFIX
    from core.state_files import STATE_FILE_NAMES
    return STATE_FILE_NAMES, (INDEX_FILE, TRANSCRIPT_PREFIX), TRACE_SUFFIXES


def is_state_file(name: str) -> bool:
    """The base name ``name`` is one of the run's own state files."""
    exact, prefixes, suffixes = _state_file_names()
    return name in exact or name.startswith(prefixes) or name.endswith(suffixes)


def output_snapshot(case_dir: str | os.PathLike | None) -> dict[str, tuple[int, int]]:
    """``{relative path: (size, mtime_ns)}`` of every file under the output
    tree, without the spills and the run's state files. One walk; the class
    of cost the coverage ledger's directory description already pays.
    ponytail: a full stat walk per call; prune by directory mtime if a VM
    run shows the walk in the per-call latency."""
    root = _case_root(case_dir)
    out: dict[str, tuple[int, int]] = {}
    if not root:
        return out
    for top in _SNAPSHOT_DIRS:
        base = os.path.join(root, top)
        if not os.path.isdir(base):
            continue
        stack = [base]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name not in _SNAPSHOT_SKIP_DIRS:
                                    stack.append(entry.path)
                                continue
                            if is_state_file(entry.name) or entry.name.endswith(".tmp"):
                                continue
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        out[os.path.relpath(entry.path, root)] = (st.st_size, st.st_mtime_ns)
            except OSError:
                continue
    return out


@_locked
def record_outputs(case_dir: str | os.PathLike | None,
                   entries: dict | Sequence[dict],
                   before: dict[str, tuple[int, int]],
                   after: dict[str, tuple[int, int]]) -> list[str]:
    """Attribute every file that is new or changed between the snapshots
    to the call ``entries`` records: ``derived`` for a fixed tool over
    evidence or derived input, ``own`` for a scripted call, a document write
    or a fixed tool over own input. One window may hold several calls (the
    batch runner's concurrent entries): the files are own when any of them
    is, and attributed to that call, else to the last. A file a different
    call already changed is own whatever either call was (fail closed: a
    file two calls wrote is not one parser's table). Returns the paths
    recorded. Ceiling: a rewrite that leaves the size unchanged within one
    tick of the kernel's coarse file clock is invisible to the stat diff
    and keeps the earlier record."""
    root = _case_root(case_dir)
    batch = [entries] if isinstance(entries, dict) else [e for e in entries or () if isinstance(e, dict)]
    if not root or not batch:
        return []
    changed = [p for p, st in after.items() if before.get(p) != st]
    if not changed:
        return []

    def klass_of(entry: dict) -> str:
        if is_scripted(entry, root):
            return "own"
        inputs = call_provenance(entry, root, produced=changed)["class"]
        return "derived" if inputs in ("evidence", "derived") else "own"
    classes = [klass_of(e) for e in batch]
    owner = next((e for e, k in zip(batch, classes) if k == "own"), batch[-1])
    klass = "own" if "own" in classes else "derived"
    cid = owner.get("call_id")
    with _LOCK:
        files = load_ledger(root)
        before_records = dict(files)
        for rel in changed:
            prev = files.get(rel)
            if prev and prev.get("call") != cid:
                # The mark keeps _classify from re-deriving the record from
                # the first writer alone.
                files[rel] = {"call": prev.get("call"), "class": "own", "rewritten_by": cid}
                continue
            files[rel] = {"call": cid, "class": klass}
        if files != before_records:
            _save_ledger(root, files)
            _CACHE.clear()  # the class of a call reading these files may change
            _FOLDER_MEMO.clear()
    return changed


def _first_call_time(root: str) -> float:
    """When the run's first recorded call happened, as a timestamp; 0 when
    no trace is readable. A file older than that under the output tree was
    written by intake's own parsers."""
    if root in _FIRST_CALL_TS:
        return _FIRST_CALL_TS[root]
    stamp = 0.0
    try:
        from core.execution_log import log
        entries = log._entries
        for e in entries:
            ts = str(e.get("ts") or "")
            if ts:
                from datetime import datetime, timezone
                moment = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if moment.tzinfo is None:
                    moment = moment.replace(tzinfo=timezone.utc)
                stamp = moment.timestamp()
                break
    except Exception:  # noqa: BLE001
        stamp = 0.0
    if stamp:
        _FIRST_CALL_TS[root] = stamp
    return stamp


def _output_params(entry: dict) -> set[str]:
    """The paths this call named as its outputs, by parameter name."""
    from core.indicators import _parsed_args
    from core.paths import output_paths
    args, _keys = _parsed_args(entry)
    return set(output_paths(args)) if isinstance(args, dict) else set()


# The run's own documents as a call names them: the ledger's tokenizer knows
# the evidence and analysis trees, not the state directory, the report tree
# or the brief, and a read of those must class as own, not as unplaced.
_OWN_DOCUMENT_RE = re.compile(r"(?<![\w/.-])(?:\.atlas|reports|tool-output)/[^\s\"'`,;)]+|(?<![\w/.-])CASE\.md\b")


def path_tokens(entry: dict, root: str | os.PathLike | None = None) -> list[str]:
    """The path tokens a call names, as written (the ledger's tokenizer over
    its command, arguments and evidence reference, plus the run's own
    documents). A token the tokenizer also found inside a longer one (the
    case-relative tail of an absolute path) is dropped. With ``root``, an
    argument value that is an existing path of the case or an image handle
    is one token whole
    (core.evidence_identity.argument_paths): the text tokenizer stops at a
    space, so a path with one ("Root - Mailbox") came out as a fragment that
    names nothing."""
    from core.coverage_ledger import _blob_paths
    from core.evidence_identity import call_args
    # The arguments as the lenient reader gives them: a value the record's
    # 400-character cut ended inside is dropped, never read as a shorter
    # path (a folder above the file the call read).
    parsed = call_args(entry) if entry.get("args") else {}
    args = json.dumps(parsed, default=str) if parsed else str(entry.get("args") or "")
    blob = " ".join([str(entry.get("cmd") or ""), args, str(entry.get("evidence_ref") or "")])
    found = list(dict.fromkeys(_blob_paths(blob) + [m.group(0) for m in _OWN_DOCUMENT_RE.finditer(blob)]))
    if root:
        from core.evidence_identity import argument_paths
        base = os.path.abspath(str(root)).rstrip(os.sep) + os.sep
        # A path parameter's value is one path, spaces and all, whether or not
        # it exists now (a mount gone after the run, a case read elsewhere);
        # so is the evidence reference (core.middleware._extract_evidence_ref),
        # the one whole name of a call that logged its command and no arguments.
        from core.paths import is_path_param
        named = {x.strip() for k, v in parsed.items() if is_path_param(k)
                 for x in (v if isinstance(v, list) else [v]) if isinstance(x, str)}
        whole = [w for w in argument_paths(entry) if " " in w and (
            "::" in w or w in named or os.path.exists(w if os.path.isabs(w) else os.path.join(str(root), w)))]
        ref = str(entry.get("evidence_ref") or "").strip()
        if " " in ref and "\n" not in ref and ref not in whole:
            whole.append(ref)
        def in_case(t: str) -> str:
            return (t[len(base):] if t.startswith(base) else t).rstrip("/")
        # A path the command line holds unquoted with a space in it (the
        # program's argument list joined back with spaces): the token cut at
        # the space, extended over the next words while that names an
        # existing path of the case (at most four words).
        cmd = str(entry.get("cmd") or "")
        for t in list(found):
            here = t if os.path.isabs(t) else os.path.join(str(root), t)
            if os.path.exists(here) or t not in cmd:
                continue
            words = cmd[cmd.index(t) + len(t):].split(" ")[1:5]
            for k in range(1, len(words) + 1):
                longer = t + " " + " ".join(words[:k])
                if os.path.exists(longer if os.path.isabs(longer) else os.path.join(str(root), longer)):
                    whole.append(longer)
                    break
        rel = [in_case(w) for w in whole]
        # The command line's copy of such a path, cut at its first space, is
        # a fragment of it (in its absolute or case-relative spelling).
        found = [t for t in found if not any(r.startswith(in_case(t) + " ") for r in rel)]
        found = list(dict.fromkeys(whole + found))
    return [t for t in found if not any(o != t and t in o for o in found)]


def _entry_end(entry: dict) -> float:
    """When a call's trace entry was written (the end of the call), as a
    timestamp; 0 when it carries none."""
    try:
        from datetime import datetime, timezone
        moment = datetime.fromisoformat(str(entry.get("ts") or "").replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    except ValueError:
        return 0.0


def _registered_copy(root: str, rel: str) -> dict[str, Any] | None:
    """The contents index's record of an extracted copy at ``rel``: the
    index states where the file came from, so no mtime guess is needed,
    while the file is the one registered (its size, and its sha256 when
    stored: a later writer of the path made another file)."""
    try:
        from core.contents_index import copy_map, copy_provenance_on, copy_source, copy_unchanged
        # The map (one query, remembered while the index is unchanged) says
        # whether to ask; most paths a call names are no copy.
        if not copy_provenance_on() or rel.replace(os.sep, "/").casefold() not in copy_map(root):
            return None
        record = copy_source(root, rel)
        return record if record and copy_unchanged(root, record, rel) else None
    except Exception:  # noqa: BLE001
        return None


def _producer_hosts(producer: dict | None, root: str, depth: int) -> frozenset[str]:
    if not producer or depth >= 8:
        return frozenset()
    return frozenset(call_provenance(producer, root, _depth=depth + 1)["hosts"])


def _rederived(record: dict[str, Any], real: str, root: str, by_call: dict[int, dict],
               depth: int) -> str:
    """The class a record's producer call has now. A record is a cache of
    its producer's class at record time, which a fix to the classing can
    leave stale (a resumed run, a replay). Re-derived only when the file is
    as its producer left it: no second writer marked (``rewritten_by``) and
    not changed after the producer's entry was written (a legacy ledger has
    no mark). ponytail: a second writer within ~1 s of the first one's end
    on a legacy ledger is missed; fresh records carry the mark."""
    producer = by_call.get(record.get("call")) if isinstance(record.get("call"), int) else None
    if not producer or depth >= 8 or record.get("rewritten_by") is not None:
        return "own"
    end = _entry_end(producer)
    try:
        if not end or os.stat(real).st_mtime >= end + 2:
            return "own"
    except OSError:
        return "own"
    if is_scripted(producer, root):
        return "own"
    inputs = call_provenance(producer, root, _depth=depth + 1)["class"]
    return "derived" if inputs in ("evidence", "derived") else "own"


_FOLDER_MEMO: dict[tuple, tuple[tuple[tuple[str, int], ...], Any]] = {}


def _recorded_folder(rel: str, real: str, root: str, ledger: dict[str, dict[str, Any]],
                     by_call: dict[int, dict], depth: int, tool: str) -> tuple[str, frozenset[str], None] | None:
    """A folder the attribution ledger holds files of, by the files on disk
    under it: derived, with the producers' hosts, when every file of the
    kind the tool reads is a derived record or a registered copy; own when
    one is neither (a file the run wrote there by a shell redirect or a
    script has no record); None when it holds no file of that kind.
    Remembered per folder while the directories the walk saw keep their
    mtimes (a file added or removed anywhere below changes its own
    directory's), the ledger file is unchanged (a record rewritten in place
    keeps the ledger's length) and the copies keep their count."""
    try:
        from core.contents_index import copy_map, copy_provenance_on
        registered = copy_map(root) if copy_provenance_on() else {}
    except Exception:  # noqa: BLE001
        registered = {}
    try:
        st = _ledger_path(root).stat()
        led_sig: tuple = (st.st_mtime_ns, st.st_size)
    except OSError:
        led_sig = (len(ledger),)
    key = (root, rel, tool, led_sig, len(registered))
    hit = _FOLDER_MEMO.get(key)
    if hit is not None:
        try:
            if all(os.stat(d).st_mtime_ns == m for d, m in hit[0]):
                return hit[1]
        except OSError:
            pass
    from core.input_kind import reads_kind
    dirs: list[tuple[str, int]] = []
    hosts: set[str] = set()
    of_kind = 0
    result: tuple[str, frozenset[str], None] | None = None
    stack = [real]
    while stack and result is None:
        d = stack.pop()
        try:
            dirs.append((d, os.stat(d).st_mtime_ns))
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                stack.append(e.path)
                continue
            path = rel.rstrip("/") + "/" + os.path.relpath(e.path, real).replace(os.sep, "/")
            if reads_kind(tool, e.path) is False:
                continue
            copy = registered.get(path.casefold())
            if copy is not None:
                hosts.add(str(copy.get("host") or ""))
            elif path in ledger:
                klass, found, _p = _classify(path, root, [], [], ledger, by_call, depth, tool)
                if klass != "derived":
                    result = ("own", frozenset(), None)
                    break
                hosts |= found
            else:
                result = ("own", frozenset(), None)
                break
            of_kind += 1
    if result is None and of_kind:
        result = ("derived", frozenset(h for h in hosts if h), None)
    if len(_FOLDER_MEMO) > 1000:
        _FOLDER_MEMO.clear()
    if not stack:                       # a stopped walk saw only part of the tree
        _FOLDER_MEMO[key] = (tuple(dirs), result)
    return result


def _classify_dir(rel: str, real: str, root: str, ledger: dict[str, dict[str, Any]],
                  by_call: dict[int, dict], depth: int, tool: str) -> tuple[str, frozenset[str], int | None]:
    """A folder a call names: the contents index decides. Registered copies
    of the kind the tool reads make it derived, with every copy's host,
    unless a file under it that is no registered copy, of that kind, is the
    run's own (a same-kind mix is own). Files of other kinds (a partial
    download, a note) are not what the tool reads. A folder with no
    registered copy that the attribution ledger holds files of is classed by
    its files (_recorded_folder: an extractor's output folder is derived
    like each file in it); any other keeps the mtime rule; an empty one
    holds no input."""
    try:
        from core.contents_index import copies_under, copy_map, copy_provenance_on
        copies = copies_under(root, rel, tool) if copy_provenance_on() else []
        registered = copy_map(root) if copies else {}
    except Exception:  # noqa: BLE001
        copies, registered = [], {}
    if copies:
        from core.input_kind import reads_kind
        prefix = rel.rstrip("/") + "/"
        for path, record in ledger.items():
            if (not path.startswith(prefix) or record.get("class") == "derived"
                    or path.casefold() in registered):
                continue
            full = os.path.join(root, path)
            if reads_kind(tool, full) is not False and _classify(
                    path, root, [], [], ledger, by_call, depth, tool)[0] != "derived":
                return "own", frozenset(), None
        return "derived", frozenset(c["host"] for c in copies if c.get("host")), None
    prefix = rel.rstrip("/") + "/"
    if any(p.startswith(prefix) for p in ledger):
        found = _recorded_folder(rel, real, root, ledger, by_call, depth, tool)
        if found is not None:
            return found
    try:
        with os.scandir(real) as it:
            if next(it, None) is None:
                return "missing", frozenset(), None
        mtime = os.stat(real).st_mtime
    except OSError:
        return "missing", frozenset(), None
    first = _first_call_time(root)
    return ("derived" if first and mtime < first else "own"), frozenset(), None


def _image_for(absolute: str, real: str, root: str, reach: list[tuple[str, str]],
               images: list[str]) -> str:
    """The absolute image a path belongs to: the image behind the mount
    point or device the path lies under (the access plan's reach), the image
    file itself, or an evidence file outside the plan (its own image); ""
    for a path in no image. The one reach rule: ``_classify`` classes a
    call's inputs by it and ``image_for_path`` answers the read rule by it."""
    evidence_roots = [os.path.join(root, "evidence"), os.path.join(root, "mnt")]
    evidence_roots += [os.path.realpath(r) for r in list(evidence_roots)]
    for form in (absolute, real):
        for point, image in reach:
            if _under(form, point):
                return os.path.join(root, image) if not os.path.isabs(image) else image
        if any(_under(form, r) for r in evidence_roots) or form in images:
            return form
    return ""


def image_for_path(path: str, case_dir: str | os.PathLike | None) -> str:
    """The case-relative image a path belongs to, as the contents index
    names it (``_image_for`` made relative to the case root); "" for a path
    in no image. What coverage_ledger.images_read asks for each path a read
    touched."""
    root = _case_root(case_dir)
    if not root or not path:
        return ""
    absolute, real = _forms(str(path), root)
    reach, images = _plan_reach(root)
    image = _image_for(absolute, real, root, reach, images)
    if not image:
        return ""
    for base in (root, os.path.realpath(root)):
        for form in (image, os.path.realpath(image)):
            if _under(form, base):
                return os.path.relpath(form, base).replace(os.sep, "/")
    return image


def _classify(token: str, root: str, reach: list[tuple[str, str]], images: list[str],
              ledger: dict[str, dict[str, Any]], by_call: dict[int, dict],
              depth: int, tool: str = "") -> tuple[str, frozenset[str], int | None]:
    """``(class, hosts, producing call id)`` of one input path. ``missing``
    for a path that names no content (absent, or an empty folder)."""
    absolute, real = _forms(token, root)
    forms = (absolute, real)
    image_for = _image_for(absolute, real, root, reach, images)
    if image_for:
        host = ""
        try:
            from core.evidence_links import host_for_image
            host = host_for_image(image_for, root) or host_for_image(absolute, root)
        except Exception:  # noqa: BLE001
            host = ""
        return "evidence", frozenset({host} if host else ()), None
    # The run's own state, its spills and the brief are own wherever they
    # sit; a parser's table under analysis/, exports/ or reports/ is what
    # the ledger decides.
    own_roots = [os.path.join(root, ".atlas"), os.path.join(root, "tool-output"),
                 os.path.join(root, "analysis", "tool-output"), os.path.join(root, "CASE.md")]
    own_roots += [os.path.realpath(r) for r in list(own_roots)]
    if any(_under(f, r) for f in forms for r in own_roots):
        return "own", frozenset(), None
    output_roots = [os.path.join(root, seg) for seg in _SNAPSHOT_DIRS]
    output_roots += [os.path.realpath(r) for r in list(output_roots)]
    if not any(_under(f, r) for f in forms for r in output_roots):
        roots = (root, os.path.realpath(root))
        if not any(_under(f, r) for f in forms for r in roots):
            return "outside", frozenset(), None
        return ("own" if os.path.lexists(real) or os.path.lexists(absolute) else "missing"), frozenset(), None
    rel = os.path.relpath(real, root) if _under(real, root) else os.path.relpath(absolute, root)
    if os.path.isdir(real):
        return _classify_dir(rel, real, root, ledger, by_call, depth, tool)
    copy = _registered_copy(root, rel)
    if copy:
        return "derived", frozenset({copy["host"]} if copy.get("host") else ()), copy.get("call_id")
    record = ledger.get(rel)
    if record:
        klass = record.get("class") if record.get("class") == "derived" else _rederived(
            record, real, root, by_call, depth)
        if klass != "derived":
            return "own", frozenset(), record.get("call")
        producer = by_call.get(record.get("call")) if isinstance(record.get("call"), int) else None
        return "derived", _producer_hosts(producer, root, depth), record.get("call")
    try:
        mtime = os.stat(real).st_mtime
    except OSError:
        return "missing", frozenset(), None
    first = _first_call_time(root)
    if first and mtime < first:
        return "derived", frozenset(), None
    return "own", frozenset(), None


def input_tokens(entry: dict, root: str | os.PathLike | None, args: dict | None = None, *,
                 produced: Iterable[str] = ()) -> list[str]:
    """The path tokens a call read from, as written: its path tokens
    (path_tokens, plus the typed ``args`` when the caller has them) less the
    call's outputs (its output parameters, the files the attribution ledger
    gives it, ``produced``) and the programs it ran. The one input rule:
    call_provenance classes these, core.evidence_identity.call_reads names
    what they read."""
    root = _case_root(root)
    if not isinstance(entry, dict) or not root:
        return []
    tokens = list(path_tokens(entry, root))
    if args:
        from core.evidence_identity import argument_paths
        tokens += [t for t in argument_paths(entry, args) if t not in tokens]
    if not tokens:
        return []
    outputs = {_forms(p, root)[1] for p in _output_params(entry)}
    if args:
        from core.paths import output_paths
        outputs |= {_forms(p, root)[1] for p in output_paths(args)}
    outputs |= {os.path.realpath(os.path.join(root, rel)) for rel in produced}
    cid = entry.get("call_id")
    for rel, rec in load_ledger(root).items():
        if rec.get("call") == cid:
            outputs.add(os.path.realpath(os.path.join(root, rel)))
    programs = _not_inputs(str(entry.get("cmd") or ""))
    program_reals = {_forms(t, root)[1] for t in programs}
    out: list[str] = []
    for token in dict.fromkeys(tokens):
        real = _forms(token, root)[1]
        if real in outputs or any(o.startswith(real.rstrip(os.sep) + os.sep) for o in outputs) \
                or token in programs or real in program_reals:
            continue
        out.append(token)
    return out


def call_provenance(entry: dict, case_dir: str | os.PathLike | None = None, *,
                    produced: Iterable[str] = (), _depth: int = 0) -> dict[str, Any]:
    """``{"class", "paths", "hosts", "inherited"}`` of a call: its class by
    its inputs, the resolved paths it read, the hosts behind them, and the
    request strings of every call in its derived inputs' producer chain
    (so a value a program named reaches the reader of the file it wrote).
    ``produced`` names files (case-relative) this call is being attributed
    at the moment, before the ledger holds them. Cached per call id and case
    for the process; a call with ``produced`` is not cached."""
    root = _case_root(case_dir)
    cid = entry.get("call_id") if isinstance(entry, dict) else None
    key = (root, int(cid)) if isinstance(cid, int) and not produced else None
    if key is not None and key in _CACHE:
        return _CACHE[key]
    result: dict[str, Any] = {"class": "unplaced", "paths": frozenset(), "hosts": set(), "inherited": frozenset()}
    if not isinstance(entry, dict):
        return result
    tokens = input_tokens(entry, root, produced=produced)
    if not tokens or not root:
        if key is not None:
            _CACHE[key] = result
        return result
    ledger = load_ledger(root)
    reach, images = _plan_reach(root)
    try:
        from core.execution_log import log
        by_call = log.index().by_call_id or {}
    except Exception:  # noqa: BLE001
        by_call = {}
    classes: set[str] = set()
    paths: set[str] = set()
    hosts: set[str] = set()
    inherited: set[str] = set()
    tool = str(entry.get("mcp_tool") or entry.get("cmd") or "")
    for token in tokens:
        real = _forms(token, root)[1]
        klass, found, producer = _classify(token, root, reach, images, ledger, by_call, _depth, tool)
        classes.add(klass)
        paths.add(real)
        hosts |= found
        if klass == "derived" and producer is not None and _depth < 8:
            chain = by_call.get(producer)
            if chain:
                from core.indicators import request_strings
                inherited |= request_strings(chain)
                inherited |= call_provenance(chain, root, _depth=_depth + 1)["inherited"]
    if "outside" in classes:
        # A file outside the case is the analyst's own material when it is
        # the call's only input, or when the call runs a program the analyst
        # wrote; beside an evidence or derived input it is the tool's own
        # resource (rules, a config) and says nothing about what was read.
        cmd = str(entry.get("cmd") or "")
        scripted = cmd.startswith("<py>:misc_write_") or any(
            _scripted_command(words, modules_run=True, root=root) for words in _simple_commands(cmd))
        if classes == {"outside"} or scripted:
            classes = (classes - {"outside"}) | {"own"}
        else:
            classes.discard("outside")
    if "missing" in classes:
        # A path that names no content read nothing: beside a derived input
        # it is where the tool was told to write; with nothing derived
        # behind the call it stays own (fail closed).
        classes.discard("missing")
        if "derived" not in classes:
            classes.add("own")
    if not classes:
        klass = "unplaced"
    elif "own" in classes:
        klass = "own"
    elif "evidence" in classes:
        klass = "evidence"
    else:
        klass = "derived"
    result = {"class": klass, "paths": frozenset(paths), "hosts": hosts, "inherited": frozenset(inherited)}
    if key is not None:
        _CACHE[key] = result
    return result


def reset_cache() -> None:
    """Forget the cached classes (a new case, a test)."""
    with _LOCK:
        _CACHE.clear()
        _FIRST_CALL_TS.clear()
        _FOLDER_MEMO.clear()
