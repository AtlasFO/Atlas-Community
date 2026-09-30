"""Archive extraction — zip/tar/gz via Python's stdlib, 7z/rar via the
external `7z`/`unrar` binaries (no solid stdlib support for either format).

Evidence archives are untrusted input by definition — a crafted member name
or an absurd compression ratio is exactly what a hostile sample would carry.
The stdlib-backed tools here validate every member's destination path stays
inside output_dir (Zip Slip: '../', absolute paths, symlink members) and cap
total uncompressed size (zip-bomb style archives) before writing anything to
disk. The 7z/unrar tools shell out to those binaries directly and rely on
their own (current, actively maintained) extraction safety rather than
re-implementing it — a different trust model, noted per-tool below.
"""
from __future__ import annotations

import gzip
import os
import shutil
import tarfile
import zipfile
from typing import Optional

from fastmcp import FastMCP

from core import output_safe, run
from core.candidates import candidates

mcp = FastMCP("archives")

# A single member (or many small ones) inflating past this before extraction
# finishes is almost certainly a zip bomb, not legitimate evidence — refuse
# rather than fill the disk.
MAX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024 * 1024  # 20 GiB


def _safe_dest(output_dir: str, member_name: str) -> Optional[str]:
    """Resolve an archive member's extraction path, refusing anything that
    would land outside output_dir. Returns None if the member is unsafe.
    """
    root = os.path.realpath(output_dir)
    dest = os.path.realpath(os.path.join(root, member_name))
    if dest == root or dest.startswith(root + os.sep):
        return dest
    return None


# What an extractor's complaint means for the next step. Order matters: a
# misaligned or truncated archive also fails its encrypted-member checksum,
# and 7-Zip then guesses "Wrong password?" — the structural cause wins.
_ARCHIVE_DIAGNOSES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("misaligned_carve",
     ("headers error", "unconfirmed start of archive", "bad magic number",
      "can not open the file as archive", "is not a supported archive",
      "not a zip file", "missing central directory"),
     "The archive's start or length is wrong, not the password: find the real "
     "archive header in the source (bin.binwalk_scan reports offsets) and carve "
     "again from that offset. Trying more passwords will not help."),
    ("truncated",
     ("unexpected end of archive", "unexpected end of data", "unexpected eof",
      "truncated", "premature end"),
     "The archive ends early: recover the rest of the stream or carve with a "
     "larger length. A password will not help."),
    ("wrong_password",
     ("wrong password", "bad password", "password required", "incorrect password",
      "data error in encrypted file", "crc failed in the encrypted file"),
     "The structure is intact and the password is wrong: take candidates from "
     "the evidence (documents, notes, other credentials), not from guesses."),
)


def diagnose_extraction(text: str) -> tuple[str, str]:
    """``(diagnosis, next_step)`` for an extractor's output, ``("", "")`` when
    nothing recognisable is in it."""
    low = (text or "").lower()
    for diagnosis, needles, next_step in _ARCHIVE_DIAGNOSES:
        if any(n in low for n in needles):
            return diagnosis, next_step
    return "", ""


def _with_diagnosis(result: dict, *texts: str) -> dict:
    if result.get("success"):
        return result
    diagnosis, next_step = diagnose_extraction(" ".join(t for t in texts if t))
    if diagnosis:
        result["diagnosis"] = diagnosis
        result["next_step"] = next_step
    return result


def _with_candidates(extract, password) -> dict:
    """Run ``extract(password)`` for each candidate password in turn; the
    first extraction that succeeds is the result and names the password
    that opened the archive. With no candidates the archive is tried without
    one. When none works the last failure is reported with the count."""
    tried = candidates(password) or [None]
    result: dict = {}
    for pw in tried:
        result = extract(pw)
        if result.get("success"):
            if len(tried) > 1 or pw is not None:
                result["password_used"] = pw
            return result
    if len(tried) > 1:
        result["passwords_tried"] = len(tried)
        result["hint"] = (f"none of the {len(tried)} candidate passwords opened the "
                          "archive (the last attempt is reported)")
    return result


@mcp.tool()
@output_safe
def zip_extract(archive_path: str, output_dir: str,
                password: str | list[str] | None = None) -> dict:
    """
    Extract a .zip archive (checked by file signature, not extension).
    password: for AES/ZipCrypto-protected zips; one password, or a list of
    candidates tried in turn (the one that opened the archive is reported).
    """
    if not zipfile.is_zipfile(archive_path):
        return {"success": False,
                "error": f"{archive_path} is not a zip file (checked by signature, not extension)"}
    os.makedirs(output_dir, exist_ok=True)
    return _with_candidates(lambda pw: _zip_extract_with(archive_path, output_dir, pw),
                            password)


def _zip_extract_with(archive_path: str, output_dir: str, password: Optional[str]) -> dict:
    try:
        with zipfile.ZipFile(archive_path) as zf:
            if password is not None:
                zf.setpassword(password.encode())
            infos = zf.infolist()
            total = sum(i.file_size for i in infos)
            if total > MAX_UNCOMPRESSED_BYTES:
                return {"success": False,
                        "error": f"refusing to extract — {total} uncompressed bytes exceeds the "
                                 f"{MAX_UNCOMPRESSED_BYTES}-byte cap (possible zip bomb)"}
            for info in infos:
                if _safe_dest(output_dir, info.filename) is None:
                    return {"success": False,
                            "error": f"refusing to extract member outside output_dir: "
                                     f"{info.filename!r} (Zip Slip)"}
            zf.extractall(output_dir)
            names = zf.namelist()
    except RuntimeError as e:
        # zipfile raises a bare RuntimeError for "Bad password" / password required.
        return _with_diagnosis(
            {"success": False, "error": f"extraction failed (wrong/missing password?): {e}"},
            str(e))
    except zipfile.BadZipFile as e:
        # A carved or truncated archive: the central directory parsed but a
        # member header is not where it should be.
        return _with_diagnosis({"success": False, "error": f"extraction failed: {e}"},
                               str(e))
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "output_dir": output_dir, "member_count": len(names),
            "uncompressed_bytes": total}


@mcp.tool()
@output_safe
def tar_extract(archive_path: str, output_dir: str) -> dict:
    """
    Extract a .tar, .tar.gz/.tgz, .tar.bz2/.tbz2, or .tar.xz archive
    (compression auto-detected by tarfile, not inferred from the filename).
    """
    if not tarfile.is_tarfile(archive_path):
        return {"success": False,
                "error": f"{archive_path} is not a tar-family archive (checked by signature, not extension)"}
    os.makedirs(output_dir, exist_ok=True)
    try:
        with tarfile.open(archive_path) as tf:
            members = tf.getmembers()
            total = sum(m.size for m in members if m.isfile())
            if total > MAX_UNCOMPRESSED_BYTES:
                return {"success": False,
                        "error": f"refusing to extract — {total} uncompressed bytes exceeds the "
                                 f"{MAX_UNCOMPRESSED_BYTES}-byte cap (possible zip bomb)"}
            for m in members:
                # Symlink/hardlink members are a separate, sharper vector than
                # plain path traversal: even a member whose own name looks
                # safe can point anywhere on the filesystem once extracted.
                if m.issym() or m.islnk():
                    return {"success": False,
                            "error": f"refusing to extract symlink/hardlink member "
                                     f"{m.name!r} — can point outside output_dir"}
                if _safe_dest(output_dir, m.name) is None:
                    return {"success": False,
                            "error": f"refusing to extract member outside output_dir: "
                                     f"{m.name!r} (Zip Slip)"}
            # Belt-and-suspenders on top of the member checks above: Python
            # 3.12+'s "data" filter additionally strips device files and
            # dangerous permission/ownership bits. 3.11 builds from before
            # the 3.11.4 backport (PEP 706) lack it, hence the guard.
            extract_kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tf.extractall(output_dir, **extract_kwargs)
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "output_dir": output_dir, "member_count": len(members),
            "uncompressed_bytes": total}


@mcp.tool()
@output_safe
def gzip_extract(archive_path: str, output_path: str) -> dict:
    """
    Decompress a single .gz-compressed file (not a tar.gz container — use
    tar_extract for those) to output_path. Streamed with the same size cap
    as zip_extract/tar_extract, against a gzip-bomb style file.
    """
    with open(archive_path, "rb") as f:
        magic = f.read(2)
    if magic != b"\x1f\x8b":
        return {"success": False, "error": f"{archive_path} is not gzip-compressed (bad magic bytes)"}
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    written = 0
    try:
        with gzip.open(archive_path, "rb") as src, open(output_path, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UNCOMPRESSED_BYTES:
                    dst.close()
                    os.remove(output_path)
                    return {"success": False,
                            "error": f"refusing to continue — exceeded the "
                                     f"{MAX_UNCOMPRESSED_BYTES}-byte cap (possible gzip bomb)"}
                dst.write(chunk)
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "output_path": output_path, "uncompressed_bytes": written}


@mcp.tool()
@output_safe
def archive_extract_7z(archive_path: str, output_dir: str,
                       password: str | list[str] | None = None) -> dict:
    """
    Extract a .7z archive via the external `7z` binary (p7zip-full).
    Relies on 7-Zip's own extraction safety rather than re-validating
    members here — a different trust model than zip_extract/tar_extract.
    password: one password, or a list of candidates tried in turn.
    """
    binary = shutil.which("7z") or shutil.which("7za")
    if not binary:
        return {"success": False, "error": "7z not installed — apt install p7zip-full"}
    os.makedirs(output_dir, exist_ok=True)

    def _extract(pw):
        # -p<pw> (or bare -p — refuses instead of hanging on an interactive
        # prompt when the archive is encrypted and no password was given).
        cmd = [binary, "x", archive_path, f"-o{output_dir}", "-y",
               f"-p{pw}" if pw is not None else "-p"]
        result = run(cmd, timeout=1800)
        return _with_diagnosis(result, str(result.get("stdout") or ""),
                               str(result.get("stderr") or ""))
    return _with_candidates(_extract, password)


@mcp.tool()
@output_safe
def archive_extract_rar(archive_path: str, output_dir: str,
                        password: str | list[str] | None = None) -> dict:
    """
    Extract a .rar archive via the external `unrar` binary.
    Relies on unrar's own extraction safety rather than re-validating
    members here — a different trust model than zip_extract/tar_extract.
    password: one password, or a list of candidates tried in turn.
    """
    binary = shutil.which("unrar")
    if not binary:
        return {"success": False, "error": "unrar not installed — apt install unrar"}
    os.makedirs(output_dir, exist_ok=True)

    def _extract(pw):
        # -p- disables the interactive password prompt (fails cleanly instead of
        # hanging) when the archive is encrypted and no password was given.
        cmd = [binary, "x", "-y", f"-p{pw}" if pw is not None else "-p-",
               archive_path, os.path.join(output_dir, "")]
        return run(cmd, timeout=1800)
    return _with_candidates(_extract, password)
