"""Media types: the vocabulary a tool declares what it reads in
(``@mcp.tool(meta={"reads": [...]})``), and the two ways an input is brought
to it: its content (libmagic) and its name (the extension table).

Universal file-format knowledge, pinned here: the IANA registry's types, with
the spellings libmagic (file 5.39 to 5.46) gives beside them where they
differ, since the content route must match any of them; the extension table
is pinned so a host's /etc/mime.types does not change what a name means.
Capability vocabulary only: nothing here says what to look for in a file, and
no tool is named.

A declaration is a list of ``type/subtype`` strings; ``image/*``, ``audio/*``
and ``video/*`` are the only wildcards (a metadata reader of every image is a
real capability; ``application/*`` would be no declaration at all).
"""
from __future__ import annotations

import os
import sys

# Each tuple: the IANA type first, then the spellings libmagic has used.
JPEG = ("image/jpeg",)
BMP = ("image/bmp", "image/x-ms-bmp")
PNM = ("image/x-portable-pixmap", "image/x-portable-graymap", "image/x-portable-bitmap",
       "image/x-portable-anymap")
WAV = ("audio/x-wav", "audio/wav", "audio/vnd.wave")
AU = ("audio/basic",)
IMAGE_ANY = ("image/*",)
AUDIO_ANY = ("audio/*",)
VIDEO_ANY = ("video/*",)
PDF = ("application/pdf",)
# Office documents: the OLE2 containers (a generic OLE container is what
# libmagic says of one it cannot name), the OOXML packages and their
# macro-enabled forms.
OFFICE = ("application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
          "application/vnd.ms-office", "application/x-ole-storage", "application/CDFV2",
          "application/CDFV2-encrypted",
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
          "application/vnd.openxmlformats-officedocument.presentationml.presentation",
          "application/vnd.ms-word.document.macroEnabled.12", "application/vnd.ms-excel.sheet.macroEnabled.12",
          "application/vnd.ms-powerpoint.presentation.macroEnabled.12")
PE = ("application/vnd.microsoft.portable-executable", "application/x-dosexec", "application/x-msdos-program")
ELF = ("application/x-executable", "application/x-sharedlib", "application/x-pie-executable",
       "application/x-object")
MACHO = ("application/x-mach-binary",)
ZIP = ("application/zip",)
SEVEN_ZIP = ("application/x-7z-compressed",)
RAR = ("application/vnd.rar", "application/x-rar", "application/x-rar-compressed")
GZIP = ("application/gzip", "application/x-gzip")
TAR = ("application/x-tar",)
BZIP2 = ("application/x-bzip2",)
XZ = ("application/x-xz",)
JAVASCRIPT = ("text/javascript", "application/javascript", "application/x-javascript")
# A generic OLE2 container, as libmagic names one it cannot place.
OLE_GENERIC = ("application/x-ole-storage", "application/CDFV2", "application/CDFV2-encrypted",
               "application/vnd.ms-office")
# The OOXML spreadsheets (what openpyxl reads): two of the Office entries.
SPREADSHEET_OOXML = (OFFICE[8], OFFICE[11])

# Each spelling to the first of its family: what a line for the model shows,
# so a type appears once however many spellings the matcher takes.
CANONICAL: dict[str, str] = {s: fam[0] for fam in (JPEG, BMP, PNM, WAV, AU, PE, ELF, MACHO, RAR, GZIP,
                                                   JAVASCRIPT, OLE_GENERIC) for s in fam}

# A file name's type, by its extension (lower case, no dot). Only the kinds a
# tool declares are needed here; a name outside the table has no name type,
# and the content route still types the file when it is on disk.
EXTENSIONS: dict[str, str] = {
    "jpg": JPEG[0], "jpeg": JPEG[0], "jpe": JPEG[0], "png": "image/png", "gif": "image/gif", "bmp": BMP[0],
    "tif": "image/tiff", "tiff": "image/tiff", "webp": "image/webp",
    "pnm": PNM[0], "ppm": PNM[0], "pgm": PNM[1], "pbm": PNM[2],
    "wav": WAV[0], "au": AU[0], "mp3": "audio/mpeg", "mp4": "video/mp4", "avi": "video/x-msvideo",
    "mov": "video/quicktime",
    "pdf": PDF[0],
    "doc": OFFICE[0], "dot": OFFICE[0], "xls": OFFICE[1], "xlt": OFFICE[1], "ppt": OFFICE[2], "pps": OFFICE[2],
    "docx": OFFICE[7], "xlsx": OFFICE[8], "pptx": OFFICE[9],
    "docm": OFFICE[10], "xlsm": OFFICE[11], "pptm": OFFICE[12],
    "exe": PE[0], "dll": PE[0], "sys": PE[0], "scr": PE[0], "ocx": PE[0], "cpl": PE[0], "drv": PE[0],
    "so": ELF[1], "elf": ELF[0],
    "zip": ZIP[0], "7z": SEVEN_ZIP[0], "rar": RAR[0], "gz": GZIP[0], "tgz": GZIP[0], "tar": TAR[0],
    "bz2": BZIP2[0], "tbz2": BZIP2[0], "xz": XZ[0], "txz": XZ[0],
    "js": JAVASCRIPT[0],
}

_MAGIC_WARNED = False


def content_type(path: str) -> str:
    """The media type of the file at ``path`` by its content (libmagic), ""
    when the path is no file here or libmagic is not available (said once
    on stderr: the name route still types the file)."""
    global _MAGIC_WARNED
    p = str(path or "")
    if not p or not os.path.isfile(p):
        return ""
    try:
        import magic
        return str(magic.from_file(p, mime=True) or "")
    except Exception as e:  # noqa: BLE001 - fail-open to the name route
        if not _MAGIC_WARNED:
            _MAGIC_WARNED = True
            print(f"[Atlas] libmagic is not available ({e.__class__.__name__}): inputs are typed by name only",
                  file=sys.stderr)
        return ""


def name_type(path: str) -> str:
    """The media type a file name claims, by its extension; "" outside the table."""
    base = str(path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    ext = base.rsplit(".", 1)[-1].lower() if "." in base[1:] else ""
    return EXTENSIONS.get(ext, "")


def candidates(path: str) -> list[str]:
    """The types an input may be read as: by content first (when the file is
    on disk), then by name; each once. A carved file named by its carver or a
    renamed payload matches by content, an OLE document libmagic calls a
    generic container matches by name."""
    return list(dict.fromkeys(t for t in (content_type(path), name_type(path)) if t))


def matches(declared, types) -> bool:
    """Whether any declared pattern takes any of the candidate types: an exact
    type, or ``image/*``-style on the top-level type."""
    want = [str(d) for d in (declared or [])]
    for t in types or ():
        top = t.split("/", 1)[0]
        for d in want:
            if d == t or (d.endswith("/*") and d[:-2] == top):
                return True
    return False
