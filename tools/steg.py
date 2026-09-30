"""Steganography: what a carrier image hides, extracted with the tool that
matches how it was hidden.

steghide (JPEG, BMP, WAV, AU), outguess (JPEG, PNM) and jpseek (JPEG, the
jphide 0.3 line) each read only what their own embedder wrote, so extraction
is tried per tool and the first that produces data wins. Passphrases come
from the case (a note, a document, another credential): the tool tries the
ones it is given, or none, and guesses nothing. Several carriers and
several passphrases are walked in one call, carrier by carrier, so a search
over the candidates the evidence offers ends in a payload or in a negative
that names every cell it covered.
"""
from __future__ import annotations

import os
import tempfile

from fastmcp import FastMCP

from core import DEFAULT_TIMEOUT, output_safe, run
from core.candidates import candidates
from core.paths import assert_output_safe, missing_program_result, tool_program

mcp = FastMCP("steg")


def _steghide(program: str, image: str, out: str, passphrase: str) -> list[str]:
    return [program, "extract", "-sf", image, "-xf", out, "-p", passphrase, "-f"]


def _outguess(program: str, image: str, out: str, passphrase: str) -> list[str]:
    argv = [program]
    if passphrase:
        argv += ["-k", passphrase]
    return argv + ["-r", image, out]


def _jpseek(program: str, image: str, out: str, passphrase: str) -> list[str]:
    return [program, image, out]  # the passphrase is read from stdin


# File signatures common to what a carrier hides, each at the offset its
# format puts it: an extractor writes the hidden file as it was, so its
# signature is where the format says. Matched as bytes, never searched for:
# noise from a wrong passphrase holds any short byte pair somewhere. Not
# exhaustive on purpose: the printable-text check below catches text
# payloads that carry no signature. A PDF whose producer put bytes before
# "%PDF" is not recognised; hidden PDFs are written by the embedder as-is.
_PAYLOAD_MAGICS: tuple[tuple[int, bytes, str], ...] = (
    (0, b"\xff\xd8\xff", "jpeg"), (0, b"\x89PNG\r\n\x1a\n", "png"), (0, b"GIF8", "gif"),
    (0, b"BM", "bmp"), (0, b"%PDF", "pdf"), (0, b"PK\x03\x04", "zip"), (0, b"PK\x05\x06", "zip"),
    (0, b"Rar!\x1a\x07", "rar"), (0, b"7z\xbc\xaf\x27\x1c", "7z"), (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"), (0, b"\xfd7zXZ\x00", "xz"), (257, b"ustar", "tar"),
    (0, b"\x7fELF", "elf"), (0, b"MZ", "pe"), (0, b"OggS", "ogg"), (0, b"RIFF", "riff"),
    (0, b"ID3", "mp3"), (0, b"-----BEGIN", "pem"), (0, b"SQLite format 3\x00", "sqlite"),
    (0, b"\xd0\xcf\x11\xe0", "ole"), (0, b"{\\rtf", "rtf"),
)


def _confirms(kind: str, head: bytes, size: int, path: str) -> bool:
    """A two-byte signature starts one noise file in about 65,000, so for
    those formats the header's own structure confirms it: a BMP states its
    file size, a PE header's e_lfanew points at "PE" and two NUL bytes, and gzip names
    deflate as its method. Longer signatures confirm themselves."""
    if kind == "bmp":
        return len(head) >= 6 and int.from_bytes(head[2:6], "little") == size
    if kind == "pe":
        if len(head) < 0x40:
            return False
        at = int.from_bytes(head[0x3C:0x40], "little")
        try:
            with open(path, "rb") as f:
                f.seek(at)
                return f.read(4) == b"PE\x00\x00"
        except OSError:
            return False
    if kind == "gzip":
        return len(head) >= 3 and head[2] == 8
    return True


# Fraction of a text sample that must be printable for it to read as a text
# payload rather than binary noise.
_TEXT_PRINTABLE_MIN = 0.85


def _classify_payload(path: str) -> tuple[bool, str]:
    """``(is_payload, kind)`` for an extractor's output. A recognised file
    signature or mostly-printable text is a plausible payload; anything else
    is noise, which is what an extractor writes when the passphrase is wrong.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
        size = os.path.getsize(path)
    except OSError:
        return False, "unreadable"
    if not head:
        return False, "empty"
    for offset, magic, kind in _PAYLOAD_MAGICS:
        if head[offset:offset + len(magic)] == magic and _confirms(kind, head, size, path):
            return True, kind
    sample = head[:1024]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(sample) >= _TEXT_PRINTABLE_MIN:
        return True, "text"
    return False, "no recognizable structure"


# program, argv builder, what it reads, how to install it, passphrase on stdin
EXTRACTORS = (
    ("steghide", _steghide, "JPEG, BMP, WAV, AU (steghide embeddings)", "apt steghide", False),
    ("outguess", _outguess, "JPEG, PNM (outguess embeddings)", "apt outguess", False),
    ("jpseek", _jpseek, ("JPEG (jphide embeddings of the Linux 0.3 line; JPHS for Windows "
                         "0.5x writes a format this jpseek cannot read)"),
     "re-run ./install.sh (it builds jphs), or build github.com/h3xx/jphs by hand", True),
)
_COVERS = {name: covers for name, _, covers, _, _ in EXTRACTORS}


def _available() -> tuple[list[tuple], list[dict]]:
    have, missing = [], []
    for name, build, covers, install, via_stdin in EXTRACTORS:
        program = tool_program(name)
        if program:
            have.append((name, program, build, via_stdin))
        else:
            missing.append({"program": name, "covers": covers, "install": install})
    return have, missing


@mcp.tool()
def steg_status() -> dict:
    """Which steganography extractors are installed and what each reads."""
    have, missing = _available()
    return {
        "success": True,
        "available": [{"program": n, "path": p, "covers": _COVERS[n]} for n, p, _, _ in have],
        "missing": missing,
    }


@mcp.tool()
@output_safe
def steg_extract(image_path: str | list[str], output_dir: str,
                 passphrase: str | list[str] = "", method: str = "auto") -> dict:
    """
    Extract data hidden in a carrier image, or search several carriers and
    several passphrases in one call.
    image_path: one carrier, or a list of carriers to try in turn.
    passphrase: taken from the evidence; one value, or a list of candidates
    tried against every carrier; empty when none. With one carrier and one
    passphrase the result is that extraction; with more it reports every
    payload recovered and, when there is none, the complete grid that was
    tried (carriers x passphrases x extractors), which is a reportable
    negative for those candidates. A miss is a completed examination:
    success is true and recovered is empty. Only a carrier that is not a
    file, an unknown method or a missing extractor is a failure.
    method: auto (every installed extractor in turn: steghide, outguess,
    jpseek) or one of them.
    Each extractor reads only what its own embedder wrote, so a miss by one
    says nothing about the others. The output lands in
    output_dir/<image name>.<method>.out; identify it (strings.file_type)
    before drawing on it, since a wrong passphrase can yield noise.
    """
    carriers = candidates(image_path)
    if not carriers:
        return {"success": False, "error": "image_path names no carrier"}
    not_files = [c for c in carriers if not os.path.isfile(c)]
    if not_files:
        return {"success": False,
                "error": ("not a file: " + ", ".join(not_files[:5])
                          + (" ..." if len(not_files) > 5 else ""))}
    passes = candidates(passphrase, keep_empty=True) or [""]
    assert_output_safe(output_dir)
    have, missing = _available()
    if method != "auto":
        if method not in _COVERS:
            return {"success": False,
                    "error": f"unknown method {method!r}; one of auto, " + ", ".join(_COVERS)}
        have = [h for h in have if h[0] == method]
        if not have:
            hint = next(m["install"] for m in missing if m["program"] == method)
            return missing_program_result("steg.steg_extract", method, hint)
    if not have:
        return {**missing_program_result(
            "steg.steg_extract", "steghide, outguess or jpseek",
            "apt install steghide outguess; ./install.sh builds jpseek"),
            "missing": missing}
    os.makedirs(output_dir, exist_ok=True)

    recovered: list[dict] = []
    noise: dict[str, int] = {}
    last_attempts: list[dict] = []
    cells = 0
    for image in carriers:
        for pw in passes:
            cells += 1
            hit, attempts = _extract_one(image, output_dir, pw, have)
            last_attempts = attempts
            for a in attempts:
                if a["output_bytes"] > 0 and not hit:
                    noise[a["method"]] = noise.get(a["method"], 0) + 1
            if hit:
                recovered.append({**hit, "image_path": image, "passphrase": pw})
                break   # a carrier hides one payload; the rest of its column is moot

    extractors = [name for name, _, _, _ in have]
    if len(carriers) == 1 and len(passes) == 1:
        if recovered:
            return {**recovered[0], "attempts": last_attempts, "missing": missing,
                    "note": ("identify and hash the output before drawing on it; the "
                             "passphrase used and its source belong in the finding")}
        return _negative_single(passes[0], last_attempts, missing)

    grid = {"carriers": len(carriers), "passphrases": len(passes),
            "extractors": extractors, "cells_tried": cells, "missing": missing}
    if recovered:
        return {"success": True, "recovered": recovered,
                "artifact_paths": [r["output_path"] for r in recovered], **grid,
                "note": ("identify and hash each output before drawing on it; the "
                         "carrier, the passphrase and its source belong in the finding")}
    # A miss is a completed examination of every carrier, not a failed call:
    # the coverage ledger credits only successful calls, and a citation gate
    # refuses a failed one as support, so a negative reported as failure
    # left the carriers it had read unexamined on paper and uncitable.
    return {
        "success": True, "recovered": [], **grid, "noise": noise,
        "negative": (f"nothing recoverable: {len(carriers)} carrier(s) x {len(passes)} "
                     f"passphrase(s) tried with {', '.join(extractors)}, no cell produced "
                     "a recognizable payload"),
        "next_step": (
            "this negative covers what the installed extractors read, with these "
            "carriers and passphrases: record it as a disposition "
            "(misc.record_agent_message with disposition=True) naming the counts, not "
            "as a finding, and widen it only with candidates the evidence offers. It "
            "does not show that nothing is hidden: data embedded by another tool or "
            "version (JPHS for Windows 0.5x among them) or by an extractor that is not "
            "installed (see missing) cannot be read here, so state that limit wherever "
            "the negative is reported"),
    }


def _extract_one(image_path: str, output_dir: str, passphrase: str,
                 have: list[tuple]) -> tuple[dict | None, list[dict]]:
    """One carrier against one passphrase with every extractor in ``have``:
    ``(payload result or None, attempts)``."""
    base = os.path.basename(image_path)
    attempts: list[dict] = []
    for name, program, build, via_stdin in have:
        out = os.path.join(output_dir, f"{base}.{name}.out")
        if os.path.exists(out):
            os.remove(out)
        stdin_path = None
        if via_stdin:
            fd, stdin_path = tempfile.mkstemp(prefix=".steg-pass-", dir=output_dir)
            with os.fdopen(fd, "w") as f:
                f.write(passphrase + "\n")
        try:
            res = run(build(program, image_path, out, passphrase),
                      timeout=DEFAULT_TIMEOUT, stdin_path=stdin_path)
        finally:
            if stdin_path:
                os.remove(stdin_path)
        size = os.path.getsize(out) if os.path.isfile(out) else 0
        is_payload, kind = _classify_payload(out) if size > 0 else (False, "empty")
        attempts.append({"method": name, "exit_code": res.get("exit_code"),
                         "output_bytes": size, "payload_kind": kind,
                         "stderr": (res.get("stderr") or "")[:300]})
        # A recognised payload from a run that succeeded is a real extraction.
        # Bytes with no structure are what outguess and jpseek write when the
        # passphrase is wrong, and a run that failed extracted nothing whatever
        # its bytes look like, so every other output is removed: a leftover file
        # would read as a result to whoever lists the folder. Keep looking with
        # the remaining extractors instead of stopping here.
        if size > 0 and res.get("success") and is_payload:
            return ({"success": True, "method": name, "output_path": out,
                     "output_bytes": size, "payload_kind": kind,
                     "artifact_paths": [out]}, attempts)
        if os.path.isfile(out):
            os.remove(out)
    return None, attempts


def _negative_single(passphrase: str, attempts: list[dict], missing: list[dict]) -> dict:
    with_pass = f"with passphrase {passphrase!r}" if passphrase else "without a passphrase"
    produced_noise = any(a["output_bytes"] > 0 for a in attempts)
    return {
        "success": True, "recovered": [],
        "negative": (f"no installed extractor recovered a recognizable payload {with_pass}"
                     if produced_noise else
                     f"no installed extractor produced data {with_pass}"),
        "attempts": attempts, "missing": missing,
        "next_step": (
            ("an extractor wrote bytes with no recognizable structure, which is what a "
             "wrong passphrase yields — take candidate passphrases from the evidence "
             "(notes, documents, other credentials), not guesses, and pass them as a "
             "list to try them all at once; "
             if produced_noise else
             "try passphrases found in the evidence (notes, documents, other "
             "credentials), not guesses, passed as a list to try them all at once; ")
            + "data hidden by another tool or version (JPHS for Windows 0.5x among "
            "them) or by an extractor that is not installed (see missing) cannot be "
            "read here, so a miss does not show that nothing is hidden"),
    }
