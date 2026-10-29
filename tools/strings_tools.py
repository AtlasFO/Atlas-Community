"""String extraction, file identification, and metadata tools."""
import errno
import os
import shutil
import uuid
from typing import Optional, Union
from fastmcp import FastMCP

from tools import media_types as MT
from core import run, output_safe, DEFAULT_TIMEOUT
from core.paths import assert_output_safe

mcp = FastMCP("strings")


def _refuse_directory(file_path: str, tool: str) -> Optional[dict]:
    """The gate's refusal (wrong_input_kind) for a folder handed to a reader
    of one file's bytes, None for anything else. The program exits 1 on a
    folder, and that exit read as a tool failure to investigate (the latch
    nudged turn after turn), while the input was of the wrong kind; a gate
    refusal is recorded as one and creates no investigate debt."""
    if not os.path.isdir(file_path):
        return None
    return {"success": False, "gate": "wrong_input_kind", "failure_class": "wrong_input_kind",
            "error": f"{tool} reads the bytes of one file; {file_path!r} is a directory",
            "path": file_path,
            "use_instead": "misc.list_evidence_dir to list the directory, then this tool on one file of it"}


@mcp.tool()
@output_safe
def strings_extract(
    file_path: str,
    min_length: int = 8,
    unicode: bool = True,
    output_path: Optional[str] = None,
) -> dict:
    """
    Extract printable ASCII and Unicode strings from a binary file.
    min_length: minimum string length (default 8 reduces noise).
    unicode: also extract Unicode (UTF-16LE) strings.
    """
    from core.paths import assert_output_safe, resolve_path_ci

    resolved, corrected = resolve_path_ci(file_path)
    if not os.path.exists(resolved):
        return {
            "success": False,
            "error": f"file not found on mounted filesystem: {file_path}",
            "hint": "File may have been deleted post-execution. Use vol_vol_dumpfiles --pid <PID> to extract from memory.",
            "ascii_lines": 0,
            "unicode_lines": 0,
            "ascii_stdout": "",
            "unicode_stdout": "",
            "output_path": output_path,
        }
    file_path = resolved
    if (refused := _refuse_directory(file_path, "strings_extract")):
        return refused

    results = {}

    # ASCII strings
    ascii_cmd = ["strings", "-a", "-n", str(min_length), file_path]
    results["ascii"] = run(ascii_cmd)

    # Unicode strings
    if unicode:
        uni_cmd = ["strings", "-a", "-el", "-n", str(min_length), file_path]
        results["unicode"] = run(uni_cmd)

    def _full(res: dict) -> str:
        """The complete output: the executor spills anything beyond the
        in-chat cap to a file, and that file — not the preview — is what an
        output_path must receive. A large $MFT listing written from the preview
        holds a few hundred lines, and every later search of it is a false
        negative."""
        spill = res.get("stdout_file") or ""
        if spill and os.path.isfile(spill):
            try:
                with open(spill, "r", encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except OSError:
                pass
        return res.get("stdout", "") or ""

    combined = _full(results["ascii"]) + "\n" + _full(results.get("unicode", {}))

    if output_path:
        assert_output_safe(output_path)
        with open(output_path, "w") as f:
            f.write(combined)

    return {
        "success": results["ascii"]["success"],
        "output_lines": combined.count("\n"),
        "ascii_lines": len(results["ascii"].get("stdout", "").splitlines()),
        "unicode_lines": len(results.get("unicode", {}).get("stdout", "").splitlines()),
        "ascii_stdout": results["ascii"].get("stdout", ""),
        "unicode_stdout": results.get("unicode", {}).get("stdout", ""),
        "output_path": output_path,
        "stderr": results["ascii"].get("stderr", ""),
        "path_resolved": file_path if corrected else None,
    }


def _full_output(res: dict) -> str:
    """Everything a call printed: the spill file when the executor cut the
    in-memory copy, else the buffer."""
    spill = (res or {}).get("stdout_file") or ""
    if spill and os.path.isfile(spill):
        try:
            with open(spill, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            pass
    return (res or {}).get("stdout", "") or ""


def _kept_path(file_path: str, min_length: int, wide: bool) -> tuple[str, str]:
    """``(path, identity prefix)`` of the kept extraction of one strings pass,
    beside the run's spills (analysis/tool-output, which no evidence walk
    reads), ("", "") where nothing spills or for a file it cannot stat. The
    file is known by device, inode, size, mtime and ctime: a changed file is
    a new extraction, and so is a renamed one, since a rename sets ctime. ctime counts because a copy
    over the file in place (cp -p, rsync --inplace) can keep inode, size and
    mtime, and no user tool sets ctime."""
    from core.executor import _spill_target_dir
    spills = _spill_target_dir()
    if not spills:
        return "", ""
    try:
        st = os.stat(file_path)
    except OSError:
        return "", ""
    d = os.path.join(spills, "strings-cache")
    ident = f"{st.st_dev}-{st.st_ino}-"
    name = f"{ident}{st.st_size}-{st.st_mtime_ns}-{st.st_ctime_ns}-n{min_length}-{'el' if wide else 'a'}.txt"
    return os.path.join(d, name), ident


def _keep_extraction(res: dict, path: str, ident: str) -> None:
    """Keep a complete pass under ``path``: its spill linked, not copied, so
    the first call's output is on disk once. Extractions of an earlier state
    of the same file are removed, so a file holds at most one kept
    extraction per length and encoding. Never raises."""
    spill = str(res.get("stdout_file") or "")
    if (res.get("success") is not True or res.get("timed_out") or res.get("exit_code")
            or (res.get("truncated") and not os.path.isfile(spill))):
        return
    d, own = os.path.dirname(path), os.path.basename(path)
    current = own.rsplit("-n", 1)[0] + "-n"
    # One name per call: threads of one process keep at once, and a shared
    # name would let one call copy into the other's link of its own spill.
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    try:
        os.makedirs(d, exist_ok=True)
        for name in os.listdir(d):
            if name.startswith(ident) and not name.startswith(current):
                os.remove(os.path.join(d, name))
        if spill and os.path.isfile(spill):
            try:
                os.link(spill, tmp)
            except OSError as e:
                if e.errno != errno.EXDEV:
                    return            # nothing kept; the next call runs again
                shutil.copyfile(spill, tmp)
        else:
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(res.get("stdout") or "")
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _strings_pass(file_path: str, min_length: int, wide: bool, timeout: int) -> tuple[str, dict]:
    """``(full output, result)`` of one strings pass. Within a case the
    output of a pass over the same file state, length and encoding is read
    from the kept extraction instead of running again: a hunt of several
    calls over one disk image extracts it once, and its output is stored
    once, not once per call."""
    path, ident = _kept_path(file_path, min_length, wide)
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(), {"success": True, "stdout": "", "extraction_reused": True}
        except OSError:
            pass
    res = run(["strings", "-a", *(["-el"] if wide else []), "-n", str(min_length), file_path],
              timeout=timeout)
    if path:
        _keep_extraction(res, path, ident)
    return _full_output(res), res


@mcp.tool()
@output_safe
def strings_grep(file_path: str, pattern: Union[str, list[str]], min_length: int = 4,
                 case_insensitive: bool = True) -> dict:
    """
    Extract strings from a file and filter by regex pattern.
    Useful for targeted IOC hunting: URLs, IPs, domain names, commands.

    pattern: one regex, or a list of regexes searched in the SAME pass.
        Extraction is what costs time on a large input, not matching, so
        hunting six indicators in one call is six times cheaper than six
        calls. ``matches_by_pattern`` reports the hit count per pattern.

    The timeout scales with the size of the input: a disk image needs far
    more than the default, and a search that is killed returns nothing.
    """
    import re
    from core.paths import resolve_path_ci, scale_timeout

    resolved, _ = resolve_path_ci(file_path)
    if not os.path.exists(resolved):
        return {
            "success": False,
            "error": f"file not found: {file_path}",
            "hint": "Use vol_vol_dumpfiles to extract from memory.",
            "matches": [],
        }
    file_path = resolved
    if (refused := _refuse_directory(file_path, "strings_grep")):
        return refused

    patterns = [pattern] if isinstance(pattern, str) else list(pattern or [])
    patterns = [p for p in patterns if str(p).strip()]
    if not patterns:
        # An empty pattern matches every line: on a disk image that is a
        # dump, not a search. Say so instead of returning the whole file.
        return {"success": False, "matches": [],
                "error": "no pattern given — pass a regex, or a list of them",
                "hint": "to list a file's strings use strings.strings_extract"}
    flags = re.IGNORECASE if case_insensitive else 0
    regexes = []
    for p in patterns:
        try:
            regexes.append((str(p), re.compile(str(p), flags)))
        except re.error as e:
            return {"success": False, "error": f"Invalid regex {p!r}: {e}"}

    # One extraction serves every pattern, and both passes get a timeout
    # scaled to the input: the fixed default killed every search over a disk
    # image at ten minutes, twice per call, and returned nothing.
    timeout = scale_timeout(DEFAULT_TIMEOUT, file_path)
    # Run strings twice: ASCII and UTF-16LE (memory images and Windows
    # artifacts carry many strings only as UTF-16LE)
    ascii_text, ascii_result = _strings_pass(file_path, min_length, False, timeout)
    unicode_text, unicode_result = _strings_pass(file_path, min_length, True, timeout)
    if not ascii_result["success"] and not ascii_result["stdout"] \
            and not unicode_result["success"] and not unicode_result["stdout"]:
        return ascii_result

    # Search the complete output. The executor caps ``stdout`` and spills
    # the rest to a file; grepping the preview reports a name absent
    # from a long directory listing that holds it, and the model then
    # records the directory as missing. Same fault class as strings_extract's output file.
    by_pattern: dict[str, list[str]] = {p: [] for p, _rx in regexes}
    ascii_matches: list[str] = []
    unicode_matches: list[str] = []
    for lines, bucket in (
        (ascii_text.splitlines(), ascii_matches),
        (unicode_text.splitlines(), unicode_matches),
    ):
        for line in lines:
            hit = False
            for p, rx in regexes:
                if rx.search(line):
                    by_pattern[p].append(line)
                    hit = True
            if hit:
                # The line is reported once; every indicator it carries is
                # counted, or hunting six IOCs at once would understate five
                # of them whenever one line matched several.
                bucket.append(line)
    return {
        "success": True,
        "file": file_path,
        "pattern": patterns[0] if len(patterns) == 1 else patterns,
        "match_count": len(ascii_matches) + len(unicode_matches),
        "ascii_match_count": len(ascii_matches),
        "unicode_match_count": len(unicode_matches),
        "matches": ascii_matches + unicode_matches,
        "matches_by_pattern": {p: len(v) for p, v in by_pattern.items()},
        "timeout_seconds": timeout,
        **({"extraction_reused": True} if ascii_result.get("extraction_reused")
           or unicode_result.get("extraction_reused") else {}),
    }


@mcp.tool()
@output_safe
def file_identify(file_path: str) -> dict:
    """Identify file type using magic bytes (libmagic). More reliable than extension."""
    return run(["file", file_path])


@mcp.tool()
@output_safe
def file_identify_directory(directory: str) -> dict:
    """Identify file types for all files in a directory."""
    return run(["file", "-r", directory], timeout=120)


@mcp.tool()
@output_safe
def hexdump(file_path: str, length: int = 256, offset: int = 0) -> dict:
    """
    Display file content as hex dump.
    length: number of bytes to dump (default 256).
    offset: byte offset to start from.
    """
    from core.paths import resolve_path_ci
    file_path, _ = resolve_path_ci(file_path)
    if (refused := _refuse_directory(file_path, "hexdump")):
        return refused
    cmd = ["hexdump", "-C", "-n", str(length), "-s", str(offset), file_path]
    return run(cmd)


@mcp.tool()
@output_safe
def xxd_dump(file_path: str, length: int = 256, offset: int = 0) -> dict:
    """
    Display file content as xxd hex dump (more readable than hexdump for some cases).
    length: number of bytes to dump.
    offset: byte offset to start from.
    """
    from core.paths import resolve_path_ci
    file_path, _ = resolve_path_ci(file_path)
    if (refused := _refuse_directory(file_path, "xxd_dump")):
        return refused
    cmd = ["xxd", "-l", str(length), "-s", str(offset), file_path]
    return run(cmd)


# What exiftool reads, from its own supported-formats list: the metadata of
# images, audio and video, PDF and Office documents, and executables.
_EXIFTOOL_READS = [*MT.IMAGE_ANY, *MT.AUDIO_ANY, *MT.VIDEO_ANY, *MT.PDF, *MT.OFFICE, *MT.PE]


@mcp.tool(meta={"reads": _EXIFTOOL_READS, "depth": "metadata"})
@output_safe
def exiftool_metadata(file_path: str) -> dict:
    """Extract EXIF and metadata from files (images, Office docs, PDFs, executables)."""
    return run(["exiftool", file_path])


@mcp.tool()     # declares nothing: it takes a folder, not a file of a type (exiftool_metadata is the file reader)
@output_safe
def exiftool_batch(directory: str, recursive: bool = True) -> dict:
    """Extract EXIF metadata from all files in a directory."""
    cmd = ["exiftool"]
    if recursive:
        cmd.append("-r")
    cmd.append(directory)
    return run(cmd, timeout=300)


@mcp.tool()
@output_safe
def stat_file(file_path: str) -> dict:
    """Display filesystem metadata for a file: timestamps, permissions, inode, size."""
    return run(["stat", file_path])


@mcp.tool(meta={"reads": list(MT.PE)})      # FLOSS: PE files (its documented input)
@output_safe
def floss_extract(
    file_path: str,
    min_length: int = 6,
    output_path: Optional[str] = None,
) -> dict:
    """
    Extract obfuscated, stacked, and decoded strings from a malware sample
    using FLARE's floss. Catches C2 URLs, decoded keys, and stack-built strings
    that plain `strings` misses.

    file_path: PE/ELF binary or shellcode buffer.
    min_length: minimum reported string length.
    output_path: optional JSON report destination (under analysis/exports/reports).
    """
    if output_path:
        assert_output_safe(output_path)
    if (refused := _refuse_directory(file_path, "floss_extract")):
        return refused
    binary = shutil.which("floss")
    if not binary:
        return {"success": False, "error":
                "floss not installed — pip install flare-floss"}
    cmd = [binary, "-n", str(min_length)]
    if output_path:
        cmd += ["-j", output_path]
    cmd.append(file_path)
    return run(cmd, timeout=600)


_TEXT_ENCODINGS = ("utf-8", "cp1252", "latin-1")


def _detect_text_encoding(head: bytes) -> str:
    """Encoding of a text file from its first bytes: a BOM when present,
    otherwise the NUL pattern of UTF-16 without one, otherwise UTF-8 with a
    single-byte fallback."""
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"           # the codec consumes the BOM
    sample = head[:4096]
    if len(sample) >= 4 and sample.count(b"\x00") > len(sample) // 4:
        even = sample[1::2].count(b"\x00")
        odd = sample[0::2].count(b"\x00")
        return "utf-16-le" if even > odd else "utf-16-be"
    for enc in _TEXT_ENCODINGS:
        try:
            sample.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "latin-1"


@mcp.tool()
@output_safe
def read_text(
    file_path: str,
    max_lines: int = 200,
    start_line: int = 1,
    grep: Optional[str] = None,
    output_path: Optional[str] = None,
) -> dict:
    """
    Read a text document (XML, JSON, INI, script, log, task definition) as
    decoded text — the reader for files that are neither binary containers
    (strings.*) nor tabular exports (table.*). Detects UTF-8, UTF-16 with or
    without a BOM, and single-byte encodings.
    max_lines: lines returned per call; start_line: 1-based first line, for
        paging through a long file.
    grep: optional case-insensitive regex — only matching lines are returned,
        each prefixed with its line number.
    output_path: optionally write the whole decoded text (UTF-8) under
        analysis/ or exports/ for other tools.
    """
    import re
    from core.paths import resolve_path_ci
    path, _ = resolve_path_ci(os.path.expanduser(file_path))
    if (refused := _refuse_directory(path, "read_text")):
        return refused
    if not os.path.isfile(path):
        return {"success": False, "error": f"not a file: {file_path}"}
    size = os.path.getsize(path)
    cap = 64 * 1024 * 1024
    with open(path, "rb") as fh:
        raw = fh.read(cap)
    encoding = _detect_text_encoding(raw[:65536])
    text = raw.decode(encoding, errors="replace")
    lines = text.splitlines()
    rx = None
    if grep:
        try:
            rx = re.compile(grep, re.IGNORECASE)
        except re.error as e:
            return {"success": False, "error": f"invalid grep pattern: {e}"}
    start = max(1, int(start_line or 1))
    limit = max(1, int(max_lines or 200))
    if rx is not None:
        hits = [(i, ln) for i, ln in enumerate(lines, 1) if i >= start and rx.search(ln)]
        shown = [f"{i}: {ln}" for i, ln in hits[:limit]]
        truncated = len(hits) > limit
        last = hits[:limit][-1][0] if hits else start
    else:
        window = lines[start - 1:start - 1 + limit]
        shown = window
        truncated = (start - 1 + limit) < len(lines)
        last = start - 1 + len(window)
    result = {
        "success": True,
        "path": path,
        "encoding": encoding,
        "size_bytes": size,
        "total_lines": len(lines),
        "line_range": [start, last],
        "truncated": truncated or size > cap,
        "lines": shown,
    }
    if truncated:
        result["next_start_line"] = last + 1
    if output_path:
        assert_output_safe(output_path)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as out:
            out.write(text)
        result["output_path"] = output_path
    return result
