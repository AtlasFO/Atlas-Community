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
import struct
import tarfile
import zipfile
from typing import Optional

from fastmcp import FastMCP

from tools import media_types as MT

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
      "not a zip file", "missing central directory", "invalid header"),
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
    """Diagnosis from a program's own text (7z, unrar, tarfile's fixed
    messages): never from a text that carries a member's name, which could
    be written to read like a needle."""
    if result.get("success"):
        return result
    diagnosis, next_step = diagnose_extraction(" ".join(t for t in texts if t))
    if diagnosis:
        result["diagnosis"] = diagnosis
        result["next_step"] = next_step
    return result


_NEXT_STEP = {diagnosis: step for diagnosis, _needles, step in _ARCHIVE_DIAGNOSES}


def _diagnosed(result: dict, diagnosis: str) -> dict:
    """The diagnosis the code established (a structure probe, an exception
    type), with the table's next step; no scan of the message."""
    result["diagnosis"] = diagnosis
    result["next_step"] = _NEXT_STEP[diagnosis]
    return result


def _shown(name: str) -> str:
    """A member name as the model-read message shows it: JSON-quoted and
    escaped, so a name forges no line and no needle of the message."""
    from core.coverage_ledger import shown_name  # loaded after the tool modules
    return shown_name(name)


_ZIP_LOCAL_HEADER = struct.Struct("<4sHHHHHIIIHH")

# The heads of zipfile's own BadZipFile messages that name a structure
# fault (a header or directory not where the directory says, a cut, a
# corrupt record); "Bad CRC-32 for file ..." is not one of them.
_ZIP_STRUCTURE_HEADS = ("Bad magic number", "Truncated", "Bad offset", "Corrupt",
                        "File is not a zip file", "File name in directory",
                        "Zip64 end of central directory")


def _zip_structure(path: str) -> tuple[str, str]:
    """``(diagnosis, fact)`` for a file the zip module refused, which means
    it found no end-of-central-directory record. The fact is what a
    bounded read of the head shows (30 bytes and the first member's name,
    a 16-bit length) beside the file's size. ``truncated`` only when the
    first member declares more bytes than the file holds; a declared size
    that fits, or none declared (a data descriptor, zip64), stays
    ``misaligned_carve`` with that said: the start or the length is wrong
    and the bytes do not say which."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(_ZIP_LOCAL_HEADER.size)
        if len(head) < _ZIP_LOCAL_HEADER.size or head[:4] != b"PK\x03\x04":
            return "misaligned_carve", ("no zip local file header at offset 0 and no "
                                        "end-of-central-directory record")
        (_sig, _ver, flags, _method, _t, _d, _crc, csize, _usize,
         nlen, xlen) = _ZIP_LOCAL_HEADER.unpack(head)
        name = f.read(nlen).decode("utf-8", "replace")
    fact = (f"a zip local file header at offset 0 (first member {_shown(name)}) but no "
            "end-of-central-directory record")
    if flags & 0x8 or csize == 0xFFFFFFFF:
        return "misaligned_carve", fact + "; the member's size is not declared in its local header"
    need = _ZIP_LOCAL_HEADER.size + nlen + xlen + csize
    if need > size:
        return "truncated", (fact + f"; the first member declares {need} bytes and the file "
                             f"has {size}: cut short")
    return "misaligned_carve", fact + f"; the first member's {need} bytes fit in the file's {size}"


def _tar_structure(path: str) -> tuple[str, str]:
    """``(diagnosis, fact)`` for a file the tar module refused, from a walk
    of the 512-byte headers it holds: a ustar or GNU header carries "ustar"
    at offset 257 and its entry's size in octal at 124, and an archive ends
    with two zero blocks. ``truncated`` when an entry's data runs past the
    file's end or the file ends where the next header should start; a pax
    or long-name record (typeflag x, g, L, K) is an entry, not a member."""
    size = os.path.getsize(path)
    offset = 0
    member = ""
    with open(path, "rb") as f:
        block = f.read(512)
        if len(block) < 512 or block[257:262] != b"ustar":
            return "misaligned_carve", ("no tar header at offset 0 (no ustar magic) and no compressed "
                                        "stream the tar module could read a header from")
        for _ in range(4096):  # bounded: one header per step, each read whole
            if len(block) < 512:
                return "truncated", (f"tar headers from offset 0 (first member {_shown(member)}); the "
                                     f"next header should start at offset {offset} and the file has "
                                     f"{size}, with no end-of-archive blocks: cut short")
            if block[257:262] != b"ustar":
                break
            name = block[:100].split(b"\x00", 1)[0].decode("utf-8", "replace")
            try:
                declared = int(block[124:136].split(b"\x00", 1)[0].strip() or b"0", 8)
            except ValueError:
                return "misaligned_carve", (f"a tar header at offset {offset} (entry {_shown(name)}) "
                                            "with an unreadable size field")
            if not member and block[156:157] not in (b"x", b"g", b"L", b"K"):
                member = name
            if offset + 512 + declared > size:
                return "truncated", (f"tar headers from offset 0; the entry {_shown(name)} declares "
                                     f"{declared} bytes from offset {offset + 512} and the file has "
                                     f"{size}: cut short")
            offset += 512 + declared + (-declared % 512)
            f.seek(offset)
            block = f.read(512)
    return "misaligned_carve", (f"tar headers from offset 0 (first member {_shown(member)}) the tar "
                                f"module could not read; every entry's declared bytes fit in the "
                                f"file's {size}")


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


@mcp.tool(meta={"reads": list(MT.ZIP)})
@output_safe
def zip_extract(archive_path: str, output_dir: str,
                password: str | list[str] | None = None) -> dict:
    """
    Extract a .zip archive (judged by its structure, not its name).
    password: for AES/ZipCrypto-protected zips; one password, or a list of
    candidates tried in turn (the one that opened the archive is reported).
    """
    if not zipfile.is_zipfile(archive_path):
        try:
            diagnosis, fact = _zip_structure(archive_path)
        except OSError as e:
            return {"success": False, "error": f"{archive_path}: {e}"}
        return _diagnosed({"success": False,
                           "error": f"{archive_path} is not a zip the archive module can open: {fact}"},
                          diagnosis)
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
        # zipfile's RuntimeError is its password complaint ("Bad password",
        # "password required"): the diagnosis follows the type, not the
        # text, which carries the member's name.
        return _diagnosed(
            {"success": False, "error": f"extraction failed (wrong/missing password?): {e}"},
            "wrong_password")
    except zipfile.BadZipFile as e:
        # The central directory parsed and a member did not: zipfile's own
        # message head says which kind (the member's name, when it follows
        # the head, is not looked at). A structural head is a carve that
        # joined the wrong pieces or starts off; a checksum mismatch is
        # corrupt data or, on a ZipCrypto member, a wrong candidate the
        # one-byte check let through, so it says that and advises nothing
        # on passwords.
        text = str(e)
        if text.startswith(_ZIP_STRUCTURE_HEADS):
            return _diagnosed({"success": False, "error": f"extraction failed: {text}"},
                              "misaligned_carve")
        if text.startswith("Bad CRC-32"):
            return {"success": False,
                    "error": (f"extraction failed: {text}: the member's data does not match "
                              "its checksum (corrupt data, or on a ZipCrypto member a wrong "
                              "candidate the check byte let through)")}
        return {"success": False, "error": f"extraction failed: {text}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "output_dir": output_dir, "member_count": len(names),
            "uncompressed_bytes": total}


@mcp.tool(meta={"reads": [*MT.TAR, *MT.GZIP, *MT.BZIP2, *MT.XZ]})
@output_safe
def tar_extract(archive_path: str, output_dir: str) -> dict:
    """
    Extract a .tar, .tar.gz/.tgz, .tar.bz2/.tbz2, or .tar.xz archive
    (compression judged by the tar module from the bytes, not the name).
    """
    if not tarfile.is_tarfile(archive_path):
        try:
            diagnosis, fact = _tar_structure(archive_path)
        except OSError as e:
            return {"success": False, "error": f"{archive_path}: {e}"}
        return _diagnosed({"success": False,
                           "error": f"{archive_path} is not a tar-family archive the tar module "
                                    f"can open: {fact}"},
                          diagnosis)
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
    except tarfile.ReadError as e:
        # The first header read, a later one did not. tarfile's fixed texts
        # ("unexpected end of data", "invalid header") carry no member name.
        return _with_diagnosis({"success": False, "error": str(e)}, str(e))
    except EOFError as e:
        # The compressed stream ended before its end marker: cut short.
        return _diagnosed({"success": False, "error": f"the compressed stream ended early: {e}"},
                          "truncated")
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "output_dir": output_dir, "member_count": len(members),
            "uncompressed_bytes": total}


@mcp.tool(meta={"reads": list(MT.GZIP)})
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
        return _diagnosed({"success": False,
                           "error": f"{archive_path} is not gzip-compressed (no gzip magic at offset 0)"},
                          "misaligned_carve")
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
    except EOFError as e:
        # The stream ended before its end marker: cut short.
        return _diagnosed({"success": False, "error": f"the compressed stream ended early: {e}"},
                          "truncated")
    except gzip.BadGzipFile as e:
        # The magic was there; the header behind it is not gzip's.
        return _diagnosed({"success": False, "error": str(e)}, "misaligned_carve")
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "output_path": output_path, "uncompressed_bytes": written}


@mcp.tool(meta={"reads": list(MT.SEVEN_ZIP)})
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


@mcp.tool(meta={"reads": list(MT.RAR)})
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
