"""Typed forensic-entity extraction and canonicalization.

Shared matching primitive for the accuracy scorer (tools/accuracy.py) and the
ground-truth exposure audit (core/brain/gt_exposure.py): "do these two texts
reference the same artifact?" must survive formatting differences — case,
path-separator style, hash casing, IPv6 compression, timestamp precision —
that defeat plain token overlap.

``extract(text)`` returns a set of canonical entity strings, each prefixed
with its type (``ip:``, ``md5:``, ``path:``, ``file:``, ...). Two texts
reference the same artifact iff their canonical sets intersect.

Extraction is span-consuming in priority order: once a region of text is
claimed by a higher-priority pattern (a MITRE ID, a Windows path), lower
patterns (bare hex, filenames) cannot re-match inside it. This keeps
``T1059.001`` from also surfacing as filename ``t1059.001``.

Timestamps canonicalize to minute resolution in UTC
— sub-minute skew between artifact sources is normal, cross-minute skew is a
different event.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone

# Priority-ordered patterns. Order matters: earlier patterns consume their
# spans and shadow later ones.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_FLAG_RE = re.compile(r"\b(?:flag|ctf|htb|thm|key)\{[^}]{2,}\}", re.IGNORECASE)
# A URL never carries a raw backtick, closing quote or brace: in prose those
# are the code span or quotation around it.
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]`”’»}]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
# Windows paths: the directories a profile lives in carry spaces ("Documents
# and Settings", "Program Files", "Application Data"), so a segment that is
# followed by another backslash may contain any character Windows allows in a
# name, spaces included; the final segment stops at whitespace, as prose
# follows it. A path that stopped at the first space shattered into location
# words ("data", "microsoft") that then looked like the artifacts a finding
# was about.
_WIN_SEGMENT = r"(?:[^\\/:*?\"<>|\r\n`]+?\\)*"
_WIN_TAIL = r"[^\s\\/:*?\"'<>|,;`]*"
_UNC_RE = re.compile(r"\\\\[\w.-]+\\" + _WIN_SEGMENT + _WIN_TAIL)
_WIN_PATH_RE = re.compile(r"\b[A-Za-z]:\\" + _WIN_SEGMENT + _WIN_TAIL)
_REG_RE = re.compile(
    r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR|HKCC)\\" + _WIN_SEGMENT + _WIN_TAIL,
    re.IGNORECASE)
_UNIX_PATH_RE = re.compile(r"(?<![\w.])/(?:[\w.+-]+/)+[\w.+-]+")
# A UTC offset lies within +-14:00; "22:21-22:26" is a time range, and its
# second half must not be read as the first half's offset.
_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?"
    r"(?:Z|[+-](?:0\d|1[0-4]):?[0-5]\d)?\b")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_CAND_RE = re.compile(r"\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,64}\b")
# The first label must contain a letter, so version numbers ("3.14") and a
# cut digits-only name ("624_4625.csv") stay out. A stem may hold dots ("setupapi.dev.log", "jquery.min.js"); the extension is
# the last label, which _is_file_name checks against the extension list. A
# label after a dot carries no hyphen, so a Prefetch name
# ("ERASER.EXE-1A2B3C4D.pf") still yields the program it names.
_FILENAME_RE = re.compile(
    r"\b(?=[\w#@$-]{0,63}[A-Za-z])[\w#@$-]{1,64}(?:\.[\w#@$]{1,64}){0,4}\.[A-Za-z0-9]{1,5}\b")
# DOMAIN\user — exactly two components (a trailing backslash means it is a
# relative Windows path fragment, not an account). Still collides with prose
# like "Windows\Temp"; harmless, since an entity only matters when BOTH texts
# contain the same canonical form.
_ACCOUNT_RE = re.compile(
    r"\b([A-Za-z][\w-]{1,30})\\([A-Za-z][\w.$-]{1,30})\b(?!\\)")

_HASH_TYPE_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


# What prose wraps around a path: closing quotes and code-span backticks, and
# a closing bracket the path itself never opened.
_CLOSING_QUOTES = "`'\"\u201d\u2019\u00bb"
_OPENER_OF = {")": "(", "]": "[", "}": "{"}


def _strip_closers(raw: str) -> str:
    """``raw`` without the sentence marks, closing quotes and unbalanced
    closing brackets that follow a path in prose. They nest ("(see
    `C:\\x.exe`.)"), so stripping runs to a fixpoint; a bracket is stripped
    only while the match holds more of it than of its opener, which keeps
    "Program Files (x86)" and "report(1).pdf". Ceiling: a name whose last
    character is a genuinely unbalanced closer loses it."""
    s = raw
    while True:
        prev = s
        s = s.rstrip(".,;:").rstrip(_CLOSING_QUOTES)
        if s and s[-1] in _OPENER_OF and s.count(s[-1]) > s.count(_OPENER_OF[s[-1]]):
            s = s[:-1]
        if s == prev:
            return s


def _canon_path(raw: str) -> str:
    p = _strip_closers(raw.strip()).replace("\\", "/").lower()
    while "//" in p[2:]:  # keep a leading // for UNC roots
        p = p[:2] + p[2:].replace("//", "/")
    return p.rstrip("/")


def _basename_entity(canon_path: str) -> str | None:
    base = canon_path.rsplit("/", 1)[-1]
    if "." in base and _FILENAME_RE.fullmatch(base):
        return f"file:{base}"
    return None


def _canon_ipv4(raw: str) -> str | None:
    parts = raw.split(".")
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o > 255 for o in octets):
        return None
    return "ip:" + ".".join(str(o) for o in octets)


def _canon_ipv6(raw: str) -> str | None:
    if raw.count(":") < 2:
        return None
    try:
        return "ip:" + ipaddress.ip_address(raw).compressed
    except ValueError:
        return None


def _canon_timestamp(raw: str) -> str | None:
    txt = raw.strip().replace(" ", "T")
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    # Normalize +HHMM offsets to +HH:MM for fromisoformat.
    m = re.search(r"([+-]\d{2})(\d{2})$", txt)
    if m:
        txt = txt[:m.start()] + f"{m.group(1)}:{m.group(2)}"
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # naive timestamps read as UTC
    dt = dt.astimezone(timezone.utc)
    return f"ts:{dt.strftime('%Y-%m-%dT%H:%M')}"


def _canon_hex(raw: str) -> str:
    kind = _HASH_TYPE_BY_LEN.get(len(raw), "hex")
    return f"{kind}:{raw.lower()}"


# (pattern, handler) in consumption priority order. Handlers return the
# canonical entity string(s) for a match, or nothing to reject it (the span
# is then NOT consumed, so lower-priority patterns may still claim it).
def _extractors():
    return (
        (_CVE_RE, lambda m: [f"cve:{m.group(0).upper()}"]),
        (_MITRE_RE, lambda m: [f"technique:{m.group(0).upper()}"]),
        (_FLAG_RE, lambda m: [f"flag:{m.group(0).lower()}"]),
        (_URL_RE, lambda m: [f"url:{m.group(0).rstrip('.,;:').lower()}"]),
        (_EMAIL_RE, _email_entity),
        (_UNC_RE, _path_entities),
        (_WIN_PATH_RE, _path_entities),
        (_REG_RE, lambda m: [f"reg:{_canon_path(m.group(0))}"]),
        (_UNIX_PATH_RE, _path_entities),
        (_TS_RE, lambda m: _wrap(_canon_timestamp(m.group(0)))),
        (_IPV4_RE, lambda m: _wrap(_canon_ipv4(m.group(0)))),
        (_IPV6_CAND_RE, lambda m: _wrap(_canon_ipv6(m.group(0)))),
        (_HEX_RE, lambda m: [_canon_hex(m.group(0))]),
        (_FILENAME_RE, _file_entity),
        (_ACCOUNT_RE, _account_entity),
    )


# Extensions files actually carry — knowledge about file types, not about
# any case. A bare "name.ext" token is a file only with one of these; a
# path (see _path_entities) is a file whatever its extension. This is the
# one list: core.ioc_catalog._KNOWN_FILE_EXT is this object. "com" is not
# in it: a bare "name.com" is a web domain far more often than a DOS
# program, and a path ending in .com stays a file through the path rule.
# Ten entries are delegated top-level domains too (cab java md mov pf pl py
# sh so zip); in forensic text they name files.
FILE_EXTENSIONS = frozenset("""
exe dll sys drv ocx cpl scr pif msi msp msu cab jar class apk ipa dmg pkg
ps1 psm1 psd1 bat cmd vbs vbe js jse wsf wsh hta py pyc pyw rb pl sh bash zsh
php asp aspx jsp lnk url inf reg hve hive dat evtx evt etl jrs pf db sqlite sqlite3 mdb
zip rar 7z gz bz2 xz tar tgz iso img vhd vhdx vmdk e01 ex01 raw dd bin mem dmp
doc docx docm xls xlsx xlsm ppt pptx pptm pdf rtf odt ods txt log csv tsv json
jsonl xml yaml yml html htm eml msg pst ost dbx mbx mbox wab nk2 oab pab pem crt cer key p12 pfx cfg ini
conf plist tmp bak old swp torrent lock
jpg jpeg png gif bmp tif tiff webp heic svg ico psd mp3 mp4 m4a wav flac ogg avi mkv mov wmv webm
pcap pcapng cap mft edb wal
so dylib ko elf deb rpm phtml shtml cgi war
md go ts css java
""".split())

# The file classes a request names by a head noun ("an executable", "the
# documents", "the log file"), and the extensions of each: universal
# file-type knowledge beside FILE_EXTENSIONS, never a case's. A file with no
# extension or one listed under no class is of no class.
FILE_CLASSES = {
    "executable": frozenset("exe dll sys scr com msi cpl ocx drv pif elf so dylib ko apk jar".split()),
    "script": frozenset("ps1 psm1 psd1 bat cmd vbs vbe js jse wsf wsh hta py pyw rb pl sh bash zsh php".split()),
    "document": frozenset("doc docx docm xls xlsx xlsm ppt pptx pptm pdf rtf odt ods odp txt".split()),
    "archive": frozenset("zip rar 7z gz bz2 xz tar tgz cab".split()),
    "log": frozenset("log evtx evt etl".split()),
}
FILE_CLASS_NOUNS = {
    "executable": "executable", "executables": "executable", "binary": "executable",
    "binaries": "executable", "script": "script", "scripts": "script",
    "document": "document", "documents": "document", "archive": "archive",
    "archives": "archive", "log": "log", "logs": "log", "logfile": "log", "logfiles": "log",
}


def file_class_of(name: str) -> str:
    """The class of a file name by its extension, "" for none."""
    ext = str(name or "").rsplit(".", 1)[-1].lower() if "." in str(name or "") else ""
    return next((cls for cls, exts in FILE_CLASSES.items() if ext in exts), "")


_VERSIONISH_RE = re.compile(r"^[A-Za-z]?\d+(?:\.\d+)+$")


def _is_file_name(tok: str) -> bool:
    """``rclone.exe`` is a file; ``v1.70`` is a version and ``jane.doe`` a
    person, though both match the shape. Treating them as files sent the
    investigation grepping every source for "1.70"."""
    if _VERSIONISH_RE.match(tok):
        return False
    stem, _, ext = tok.rpartition(".")
    # ".docx" in "Office .docx/.pptx files" is an extension named on its
    # own, not a file.
    if not stem:
        return False
    ext = ext.lower()
    return not ext.isdigit() and ext in FILE_EXTENSIONS


_JSON_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b",
                 "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _unescape_json_text(raw: str) -> str:
    """Decode JSON escapes without needing the document to be complete.

    ``\\\\`` is read before ``\\n``, so a separator that JSON doubled comes
    back as one backslash and is not mistaken for the start of an escape.
    An unknown escape is left as written rather than dropped.
    """
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = raw[i + 1] if i + 1 < n else ""
        if nxt in _JSON_ESCAPES:
            out.append(_JSON_ESCAPES[nxt])
            i += 2
        elif nxt == "u" and i + 6 <= n:
            try:
                out.append(chr(int(raw[i + 2:i + 6], 16)))
                i += 6
            except ValueError:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def scan_text(raw: str) -> str:
    """A trace excerpt as the text the tool actually printed.

    A structured result is stored in the trace as JSON, so a newline inside
    one is not a newline but the two characters backslash and ``n``. Scanning
    that form directly reads an escape as though it were part of a name: a
    listing whose lines run ``…image.bmp`` then ``-rwx------`` becomes the
    single token ``image.bmp\\n-rwx------``, and the account rule, the one
    rule that treats a backslash as a separator, reports an account that
    nothing in the evidence ever named. An indicator no finding can honestly
    name is one a gate can go on asking for.

    Decoding is the exact inverse of how the excerpt was written, so it is
    safe where blind unescaping is not: JSON wrote a Windows separator as a
    double backslash, and decoding restores the one path meant rather than
    cutting ``C:\\notes.txt`` at a newline that was never there. Text that is
    not JSON, a finding's own description most of all, comes back unchanged.
    """
    if not raw or "\\" not in raw:
        return raw or ""
    if raw.lstrip()[:1] not in ("{", "["):
        return raw
    try:
        decoded = json.loads(raw)
    except (ValueError, TypeError):
        # An excerpt is kept only up to a length cap, so the JSON usually
        # arrives cut mid-string and will never parse. That is the common
        # case, not the rare one: decode the escapes in place instead, which
        # needs no closing brace. Reading ``\\`` first is what keeps a
        # Windows separator whole.
        return _unescape_json_text(raw)
    if not isinstance(decoded, (dict, list)):
        return raw
    out: list[str] = []

    def _walk(node) -> None:
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                out.append(str(key))
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)
        elif node is not None:
            out.append(str(node))

    _walk(decoded)
    return "\n".join(out)


def _file_entity(m: re.Match) -> list[str]:
    tok = m.group(0)
    return [f"file:{tok.lower()}"] if _is_file_name(tok) else []


def _account_entity(m: re.Match) -> list[str]:
    """DOMAIN\\user, unless the backslash is the text escape of a tab, a
    newline or a carriage return before a capitalised word
    ("login\\tOperator"). Ceiling: a real user name that starts
    with t, n or r and then a capital ("CORP\\tAdmin") is missed."""
    user = m.group(2)
    if len(user) > 1 and user[0] in "tnr" and user[1].isupper():
        return []
    return [f"account:{m.group(1).lower()}/{user.lower()}"]


def _email_entity(m: re.Match) -> list[str]:
    """An address, unless its last label is a file extension that is not a
    delegated top-level domain: "Notes@Work.lnk" is a file name. Extensions
    that are delegated domains too (zip, md, com) stay addresses; without
    the domain list nothing is reclassified."""
    tok = m.group(0)
    last = tok.rsplit(".", 1)[-1].lower()
    try:
        from core.ioc_catalog import _tlds
        delegated = _tlds()
    except Exception:  # noqa: BLE001 - the address stays an address
        return [f"email:{tok.lower()}"]
    if delegated and last not in delegated and last in FILE_EXTENSIONS:
        return [f"file:{tok.lower()}"]
    return [f"email:{tok.lower()}"]


_DOTTED_NAME_RE = re.compile(
    r"(?i)(?<![\w@./\\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?![\w@/\\-]|\.\w)")


def domain_spans(text: str) -> list[tuple[str, int]]:
    """The domain names a text names outside its URLs and addresses, as
    written, with their offsets: a whole dotted name whose last label is a
    delegated top-level domain or a special-use suffix
    (core.indicators._delegated_host) and no file extension
    (FILE_EXTENSIONS). Opt-in for the readers that want sites: extract()
    has no domain type, because the gates that read it would then ask every
    finding that names a site for evidence of that site."""
    from core.indicators import _delegated_host

    def _blank(m: re.Match) -> str:
        return " " * len(m.group(0))

    text = text or ""
    plain = _EMAIL_RE.sub(_blank, _URL_RE.sub(_blank, text))
    out: list[tuple[str, int]] = []
    for m in _DOTTED_NAME_RE.finditer(plain):
        name = m.group(1)
        if name.rsplit(".", 1)[-1].lower() in FILE_EXTENSIONS:
            continue
        if _delegated_host(name):
            out.append((text[m.start(1):m.end(1)], m.start(1)))
    return out


def domains_in(text: str) -> set[str]:
    """domain_spans' names, lower-cased."""
    return {name.lower() for name, _ in domain_spans(text)}


def _wrap(value: str | None) -> list[str]:
    return [value] if value else []


def _path_entities(m: re.Match) -> list[str]:
    canon = _canon_path(m.group(0))
    out = [f"path:{canon}"]
    base = _basename_entity(canon)
    if base:
        out.append(base)
    if canon.startswith("//"):  # UNC: the host is an entity of its own
        host = canon[2:].split("/", 1)[0]
        if host:
            out.append(f"host:{host}")
    return out


def extract(text: str) -> set[str]:
    """All canonical entities in ``text`` (see module docstring for types)."""
    if not text:
        return set()
    # Text that arrives JSON-escaped carries every backslash doubled; a
    # real UNC path has only its leading pair doubled. When no single
    # backslash exists at all, the doubling is escaping — otherwise
    # ``C:\\Windows\\System32`` reads as a UNC path with host "Windows".
    if "\\\\" in text and not re.search(r"(?<!\\)\\(?!\\)", text):
        text = text.replace("\\\\", "\\")
    consumed: list[tuple[int, int]] = []
    found: set[str] = set()
    for pattern, handler in _extractors():
        for m in pattern.finditer(text):
            span = m.span()
            if any(s < span[1] and span[0] < e for s, e in consumed):
                continue
            entities = handler(m)
            if entities:
                found.update(entities)
                consumed.append(span)
    return found


# Entity types distinctive enough that one shared value between two texts is
# strong evidence they describe the same artifact. Deliberately excludes
# technique:/cve:/reg:/host:/path: — those recur across unrelated contexts
# (every run mentions T1059; C:/windows/system32 is in every disk).
DISCRIMINATIVE_TYPES = frozenset(
    {"md5", "sha1", "sha256", "hex", "email", "ip", "url", "flag",
     "file", "account", "ts"})


def discriminative(entities: set[str]) -> set[str]:
    """Subset of ``entities`` whose type is near-unique per artifact."""
    return {e for e in entities if e.split(":", 1)[0] in DISCRIMINATIVE_TYPES}


# Directory names that say where a file lives in a case layout or a system
# tree, not which artifact it is. Shared between two texts they prove no
# common subject.
_STRUCTURAL_DIRS = frozenset({
    "evidence", "analysis", "exports", "reports", "cases", "case",
    "home", "tmp", "mnt", "media", "var", "usr", "opt", "etc", "dev",
    "proc", "root", "windows", "system32", "users", "temp",
    # The directories every Windows installation has under which a user's
    # or a program's files live: they say where in the profile tree a file
    # sits, not which file it is. A finding about a mail store under
    # "Application Data\Microsoft\Outlook Express" is not about "microsoft".
    "documents and settings", "program files", "program files (x86)",
    "programdata", "application data", "appdata", "local", "locallow",
    "roaming", "local settings", "microsoft", "winnt", "all users",
    "default user", "default", "system volume information", "identities",
    "start menu", "programs", "common files",
})


def artifact_tokens(text: str) -> set[str]:
    """The concrete artifact names a text refers to: file basenames and the
    distinctive directory names of any paths, lower-cased.

    This is what two texts must share to be about the same evidence — a
    finding and the tool calls it cites, or a finding and the recent calls
    lineage is inferred from. Prose, addresses and hashes are left out on
    purpose: a shared IP proves two texts mention the same indicator, not
    that one read the artifact the other describes.
    """
    tokens: set[str] = set()

    def _add_path(value: str) -> None:
        for part in value.replace("\\", "/").split("/"):
            low = part.strip().lower()
            if len(low) >= 3 and low not in _STRUCTURAL_DIRS:
                tokens.add(low)

    for ent in extract(text):
        kind, _, value = ent.partition(":")
        if kind == "file":
            tokens.add(value)
        elif kind == "path":
            _add_path(value)
    # Case-relative paths (``exports/carved/x.bin``) have no leading slash
    # and are not paths to the extractor above, yet they are how a case
    # refers to its own artifacts. A slash-separated run of segments is a
    # path when it ends in a file name, starts in a case directory or is
    # deep enough; a bare pair such as a ``user/password`` credential is not.
    # A URL is an indicator, not an artifact: its path part must not be
    # read again as a relative path of the case, or a finding that quotes
    # an XML namespace names "office", "2004" and "omml" as evidence no
    # call could have read.
    plain = _URL_RE.sub(" ", text or "")
    for m in _REL_PATH_RE.finditer(plain):
        if _looks_like_artifact_path(m.group(0)):
            _add_path(m.group(0))
    return tokens


def _looks_like_artifact_path(value: str) -> bool:
    parts = [p for p in value.replace("\\", "/").split("/") if p]
    if not parts:
        return False
    if parts[0].lower() in _STRUCTURAL_DIRS:
        return True
    # Three or more segments are a path when something in them is shaped
    # like one — a segment with a dot, or one mixing letters and digits
    # (a host name, a stem), or a file at the end. A run of bare words
    # ("System/lsass/svchost", "read/write/execute") is a list in prose,
    # and so is a run of numbers ("215/38088/38090", ports and pids);
    # naming their pieces as artifacts refused findings for evidence no
    # call could have read.
    if len(parts) >= 3 and (
            _is_file_name(parts[-1])
            or any("." in p
                   or (any(ch.isdigit() for ch in p) and not p.isdigit())
                   for p in parts)):
        return True
    # A bare pair is a path only when it ends in what a bare token would
    # have to be to count as a file. Any dotted tail let protocol versions
    # and dot-rendered binary ("HTTP/1.1..Acc", "Mozilla/4.0") through as
    # artifacts, and a finding about traffic then named things no call
    # could ever have read.
    return _is_file_name(parts[-1])


# The lookbehind excludes every character a segment may contain: a path
# starts at a name, never inside one, or an absolute path with a hyphenated
# directory also yields the tail of that directory as a second "path".
_REL_PATH_RE = re.compile(r"(?<![\w.+$/\\-])(?:[\w.+$-]+[/\\])+[\w.+$-]+")


# ── format knowledge: a URL that names a document format, not a place ────
#
# XML namespaces, schema locations and DOCTYPE identifiers are URLs by
# spelling only: every document of the format carries the same one, so it
# recurs in any evidence that holds such documents and says nothing about
# the case. Knowledge of the formats, the way the extension table is, and
# deliberately narrow: an indicator suppressed by mistake is lost silently,
# a namespace let through costs one ruling. So the authorities are named
# host by host and matched exactly (lists.w3.org archives attachments,
# validator.w3.org fetches what its query names), a path prefix is required
# where the host also serves what people contribute, a query string never
# belongs to a namespace, a fragment may only be a bare term (a URL hidden
# in a fragment is kept by the extractor as part of the outer one), and an
# authority that is not a plain host name (userinfo, a port, a backslash, a
# percent escape) fails closed, whatever a browser would make of it.
#
# Each entry names the format whose identifiers it publishes:
#   schemas.microsoft.com       Office, Windows event-record and Task Scheduler XML
#   schemas.openxmlformats.org  OOXML (docx/xlsx/pptx) namespaces and relationships
#   www.w3.org, w3.org          XHTML, XML Schema, SVG, XLink, RDF, MathML namespaces
#                               and DTDs, under the trees that hold them
#   ns.adobe.com                XMP metadata namespaces in PDF, JPEG and PSD
#   schemas.xmlsoap.org         SOAP/WSDL and the ADFS claim-type URIs in sign-in logs
#   purl.org (/dc/)             Dublin Core, in every docx core.xml
#   docs.oasis-open.org         OASIS WS-* and ODF namespaces
#   schemas.android.com         Android manifests
#   iptc.org (/std/)            IPTC photo metadata in XMP
_W3C_NAMESPACE_PATHS = re.compile(r"^/(?:\d{4}/|tr/|xml/|graphics/|ns/|markup/|math/)")
_NAMESPACE_AUTHORITIES: dict[str, "re.Pattern[str] | None"] = {
    "schemas.microsoft.com": None,
    "schemas.openxmlformats.org": None,
    "www.w3.org": _W3C_NAMESPACE_PATHS,
    "w3.org": _W3C_NAMESPACE_PATHS,
    "ns.adobe.com": None,
    "schemas.xmlsoap.org": None,
    "purl.org": re.compile(r"^/dc/"),
    "docs.oasis-open.org": None,
    "schemas.android.com": None,
    "iptc.org": re.compile(r"^/std/"),
}
_PLAIN_HOST_RE = re.compile(r"^[a-z0-9.-]+$")
_BARE_FRAGMENT_RE = re.compile(r"^[a-z0-9._-]*$")


def is_format_namespace_url(value: str) -> bool:
    """True for a URL, or a bare host, that a listed namespace authority
    publishes as a document-format identifier (an XML namespace, a schema
    location, a DOCTYPE identifier). Such a value is in every document of
    its format and is never demanded of the analyst as an indicator."""
    raw = str(value or "").strip().lower()
    if not raw or "?" in raw:
        return False
    if "://" in raw:
        scheme, _, rest = raw.partition("://")
        if scheme not in ("http", "https"):
            return False
    else:
        rest = raw
    rest, _, fragment = rest.partition("#")
    if not _BARE_FRAGMENT_RE.match(fragment):
        return False
    authority, slash, path = rest.partition("/")
    if not _PLAIN_HOST_RE.match(authority):
        return False
    # A dot segment or an encoded one walks out of the namespace tree.
    if any(seg in (".", "..") or "%2e" in seg for seg in path.split("/")):
        return False
    if authority.endswith("."):
        authority = authority[:-1]
        if authority.endswith("."):
            return False
    if authority not in _NAMESPACE_AUTHORITIES:
        return False
    prefixes = _NAMESPACE_AUTHORITIES[authority]
    if prefixes is None:
        return True
    return bool(slash) and prefixes.match("/" + path) is not None


# ── content words, and how one statement stands to another ──────────────

# Function words excluded from matching. Kept minimal and generic — no
# DFIR-domain terms, which carry signal (e.g. "deleted", "confidential").
_STOPWORDS = frozenset("""
the and for from with was were are has have had that this these those not its
into onto via per during between then than when where which while been being
also after before both each all any but his her their our your can could did
does doing done down out over under only same some such more most other own
""".split())

# No backslash in the token class: UNC paths and Windows paths split into
# components so \\10.0.0.5\finance_share matches a finding that cites the
# IP or the share name separately.
_CONTENT_TOKEN_RE = re.compile(r"[A-Za-z0-9_.#@:-]{3,}")
# fat32 / utc-5-style tokens also contribute their alpha stem (fat, utc) so a
# ground truth saying "FAT" matches a finding saying "FAT32".
_NUMERIC_SUFFIX_RE = re.compile(r"^([a-z]{3,})\d{1,4}$")


def content_words(text: str) -> set[str]:
    """Lowercase tokens of three or more characters, minus stopwords.

    The matching primitive between trace findings and ground-truth items,
    and between two findings. No heavyweight NLP: token-set containment is
    enough for statements about the same evidence.
    """
    toks = {t.strip(".:-") for t in _CONTENT_TOKEN_RE.findall(text.lower())}
    toks = {t for t in toks if len(t) >= 3 and t not in _STOPWORDS}
    stems = set()
    for t in toks:
        m = _NUMERIC_SUFFIX_RE.match(t)
        if m:
            stems.add(m.group(1))
    return toks | stems


NUMBER_RE = re.compile(r"\d+(?:[.:,/-]\d+)*")


def adds_information(new: str, old: str) -> bool:
    """``new`` says something ``old`` does not: a further canonical entity
    (file, address, hash, account, time, site) or a further number (a
    count, a size, a port)."""
    if discriminative(extract(new)) - discriminative(extract(old)):
        return True
    if domains_in(new) - domains_in(old):
        return True
    return bool(set(NUMBER_RE.findall(new or "")) - set(NUMBER_RE.findall(old or "")))


def negation_words(text: str):
    """The negator words of ``text`` (core.ir_playbook's list and "-n't"
    forms), read from whitespace-separated words stripped of punctuation, so
    a negator inside a value ("email=none@example.org") does not count."""
    from collections import Counter
    from core.ir_playbook import _NEGATORS
    words = (w.strip(".,;:!?()[]{}\"'").lower() for w in (text or "").split())
    return Counter(w for w in words if w in _NEGATORS or w.endswith("n't"))


def relation(new: str, old: str, *, threshold: float, ignore_negation: bool = False,
             elaborates: bool = False) -> tuple[str, float] | None:
    """How statement ``new`` stands to ``old``: ``("restates", share of
    new's content words old carries)`` when new adds no entity or number,
    ``("refines", share of old's words new carries)`` when it adds one, or
    None. ``threshold`` is the share that counts; 0 or less answers None.

    Judged on content words alone, without the scorer's entity boosts, so a
    shared address never folds two different events; when both texts name
    artifacts they must share one, so one event on two files stays two
    findings; and a statement is never related to its own negation ("not"
    is no content word) unless ``ignore_negation`` asks how the two would
    stand without it. With ``elaborates``, a statement that carries old's
    words and adds nothing but says more is ``("elaborates", share of
    old's words new carries)``: the same fact reworded. Lexical: a host name
    without digits is a plain word, and a paraphrase with other verbs does
    not relate.
    """
    if threshold <= 0:
        return None
    new_tokens, old_tokens = content_words(new), content_words(old)
    if len(new_tokens) < 3:
        return None
    shared = new_tokens & old_tokens
    if len(shared) < 3:
        return None
    mine, theirs = artifact_tokens(new), artifact_tokens(old)
    if mine and theirs and not (mine & theirs):
        return None
    if not ignore_negation and negation_words(new) != negation_words(old):
        return None
    cover_new = len(shared) / len(new_tokens)
    cover_old = len(shared) / len(old_tokens)
    adds = adds_information(new, old)
    if cover_new >= threshold and not adds:
        return "restates", cover_new
    if cover_old >= threshold and adds:
        return "refines", cover_old
    if elaborates and cover_old >= threshold:
        return "elaborates", cover_old
    return None
