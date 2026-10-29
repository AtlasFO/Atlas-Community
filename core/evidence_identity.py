"""What evidence a token of a call names, as one identity, and what a call read.

The same file inside an image is written in many forms over a run: an index
handle with or without its volume offset, a registered extracted copy, a
path under the image's readable form, an icat argument list, a case path.
``identify`` turns each into the identities the contents index gives it:
``("entry", <entry id>)`` for a file the index lists, ``("file", <case-
relative path>)`` for a case file the index does not tie to an entry.

``call_reads`` is the one reader of a call: what its input tokens
(core.provenance.input_tokens), its command line's icat form and its
parser's own ``processed`` report name, split into what it read (content),
what a parser reported processing (processed) and what it only named
(listed: a listing tool's tokens, a folder, an ambiguous handle), with the
images it named in-image. Every site that decides "was this read" asks it;
none parses a call's text itself (tests/core/test_identity_pin.py).

``argument_paths`` gives the path-shaped values of a call's arguments whole,
read from the typed (or leniently parsed) arguments, so a path with a space
in it ("Root - Mailbox", "Windows PowerShell.evtx") is one token; a text
tokenizer over the command line cannot know where such a path ends.

Mechanism only: no tool or artifact names.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Iterable, NamedTuple, Optional

# A folder expansion stops here and says how far it got.
# ponytail: a fixed bound per expansion; a streaming credit per call lifts it.
FOLDER_BOUND = 5000

Identity = tuple[str, Any]

# The Sleuth Kit's argument order for one object: -o <offset> <image> <inode>
# (an NTFS address carries its type and id: 1234-128-1); icat without -o
# reads the filesystem at sector 0, the one volume of an image without a
# partition table, with its other flags (-f/-i/-b take a value); icat is
# the program run (a command's head, after a separator or sudo, by its
# path), not a word of another command. Public tool syntax.
_ICAT_RE = re.compile(r"(?:^|\s)-o\s+(?P<off>\d+)\s+(?P<img>\S+)\s+(?P<inode>\d+(?:-\d+-\d+)?)(?:\s|$)"
                      r"|(?:^|[;&|(]|\bsudo)\s*(?:\S*/)?icat(?:\s+-[fib]\s+\S+|\s+-[hrRsvV]+)*\s+(?P<img0>(?!-)\S+)\s+"
                      r"(?P<inode0>\d+(?:-\d+-\d+)?)(?:\s|$)")

# The entries at one path of an image, keyed by the host the image's rows
# carry so entries_host_path (host, path NOCASE) serves the lookup.
AT_SQL = ("SELECT id, volume FROM entries WHERE host IS ? AND path = ? COLLATE NOCASE AND image = ? "
          "AND origin = 'image' AND version_of IS NULL")

_LOCK = threading.Lock()
_NAMES: dict[tuple, "Named"] = {}
_READS: dict[tuple, dict[str, Any]] = {}
_MEMO_MAX = 50_000


class Named(NamedTuple):
    """What one token names: its identities, the image it named in-image
    ("" for none), whether it is a folder, the expansion's (kept, total)
    when a folder bound cut it, and whether an offset-less handle matched
    entries on more than one volume (no content credit for such a name)."""
    ids: frozenset
    image: str = ""
    folder: bool = False
    cut: Optional[tuple[int, int]] = None
    ambiguous: bool = False
    inner: frozenset = frozenset()       # {("inner", image, path)}: the path in the image, any volume
    # {("file", rel)}: a path under a mount, also read as the case path it is
    # (what a volume file or folder the case knows by that path matches),
    # whichever volume's entry the read names.
    paths: frozenset = frozenset()


_NOTHING = Named(frozenset())


def _rel(root: Path, value: str) -> str:
    from core.contents_index import _rel as rel
    return rel(root, value).replace("\\", "/").strip("/")


def _moved(path: str) -> str:
    """The case-relative tail of an absolute path written under another
    root (a case recorded on one machine and read on another): from the
    first case directory it names (core.coverage_ledger._norm_rel), "" when
    it names none."""
    from core.coverage_ledger import _CASE_SUBDIRS, _norm_rel
    tail = _norm_rel(path)
    return tail if tail.startswith(_CASE_SUBDIRS) and not tail.startswith("evidence//") else ""


# {case: (the copies' count and highest rowid, {case path, case-folded:
# the registered copies at or under it})}: Resolver.copies_at.
_COPIES_AT: dict[str, tuple[tuple, dict[str, int]]] = {}


def argument_paths(entry: dict, args: Optional[dict] = None) -> list[str]:
    """The call's path-shaped argument values, whole: each string (or list
    element) holding a separator or an image handle's "::". ``args``: the
    typed arguments when the caller has them, else the entry's recorded
    ones read leniently (core.indicators._parsed_args)."""
    args = call_args(entry, args)
    out: list[str] = []
    for v in args.values():
        for s in (v if isinstance(v, list) else [v]):
            if isinstance(s, str) and ("/" in s or "\\" in s or "::" in s) and "\n" not in s and len(s) <= 1024:
                s = s.strip()
                if s and s not in out:
                    out.append(s)
    return out


_DRIVE_RE = re.compile(r"^(?:[a-z]:|[a-z](?=/))/?", re.IGNORECASE)
# A parser's source label in front of a path ("OS:/C/...", "TSK:/..."): the
# label of a timeline's filename column, not a path segment.
_SOURCE_LABEL_RE = re.compile(r"^[a-z][a-z0-9]{1,7}:/+", re.IGNORECASE)


def norm_inner(p: str) -> str:
    """A path inside an image case-folded, one separator, no leading slash,
    source label or drive: the form an ``("inner", image, path)`` identity
    holds, so "C:\\Users\\x", "/Users/x" and "C/Users/x" are one path."""
    s = str(p or "").replace("\\", "/").strip().casefold()
    s = _SOURCE_LABEL_RE.sub("", s, count=1).strip("/")
    s = re.sub(r"/+", "/", s)
    s = _DRIVE_RE.sub("", s, count=1)
    return s.strip("/")


def call_args(entry: dict, args: Optional[dict] = None) -> dict:
    """A call's arguments: the typed ones when the caller has them, else
    the entry's recorded ones read leniently (a record cut mid-value still
    gives its whole fields)."""
    if isinstance(args, dict):
        return args
    from core.indicators import _parsed_args
    parsed, _keys = _parsed_args(entry)
    return parsed if isinstance(parsed, dict) else {}


class Resolver:
    """One connection, one read of the image meta and the case images, for
    many lookups (a recount over a whole trace). Lookups inside an image are
    keyed by the image's host so the index's (host, path) index serves them:
    by the image alone the planner walks every row of the image (hundreds
    of thousands on a full disk) per lookup. ``con``: a connection the caller
    holds (the index builder's), else one of its own."""

    def __init__(self, case_dir: str | os.PathLike, con=None):
        from core import contents_index as ci
        self.ci = ci
        self.root = Path(case_dir)
        self._own = con is None
        self.con = ci._connect(self.root) if con is None else con
        self._meta: Optional[dict[str, dict[str, Any]]] = None
        self._hosts: dict[str, Any] = {}
        self._images: dict[str, Any] = {}
        self._readables: Optional[list[tuple[str, str, Optional[int], bool]]] = None
        self._copies: Optional[tuple[dict[str, int], bool]] = None
        self.generation = self._generation()
        # The image listings alone (the generation without the copies and
        # entries counters): what a recorded call's read set is keyed by.
        self.listings = (self.generation[0], self.generation[2]) if len(self.generation) == 3 else self.generation

    def close(self) -> None:
        if self._own and self.con is not None:
            self.con.close()
        self.con = None

    def __enter__(self) -> "Resolver":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- the index as read once -------------------------------------------------
    def meta(self) -> dict[str, dict[str, Any]]:
        if self._meta is None:
            self._meta = {}
            if self.con is not None:
                for key, raw in self.con.execute("SELECT key, value FROM meta WHERE key LIKE 'image:%'"):
                    try:
                        self._meta[key[6:]] = json.loads(raw) or {}
                    except (TypeError, ValueError):
                        self._meta[key[6:]] = {}
        return self._meta

    def _generation(self) -> tuple:
        """What a cached name depends on: the registered copies, the entries
        (a new listing, an export's own entries) and the image listings."""
        if self.con is None:
            return (str(self.root),)
        c = tuple(self.con.execute("SELECT COUNT(*), MAX(rowid) FROM copies").fetchone() or ())
        c += tuple(self.con.execute("SELECT MAX(rowid) FROM entries").fetchone() or ())
        m = hashlib.blake2b(json.dumps(sorted(self.meta().items()), sort_keys=True, default=str).encode(),
                            digest_size=8).hexdigest()
        return (str(self.root), c, m)

    def host(self, image: str) -> Any:
        """The host value the image's rows carry (one indexed probe)."""
        if image not in self._hosts:
            row = self.con.execute("SELECT host FROM entries WHERE image = ? LIMIT 1", (image,)).fetchone() \
                if self.con is not None else None
            self._hosts[image] = row[0] if row else None
        return self._hosts[image]

    def match_image(self, part: str) -> Optional[dict[str, Any]]:
        if part not in self._images:
            self._images[part] = self.ci._match_image(self.root, part)[0]
        return self._images[part]

    def at(self, image: str, inner: str, volume: Optional[int] = None, *,
           live_only: bool = False) -> list[tuple[int, Any]]:
        """(entry id, volume) of the live entries at ``inner`` in the image
        (one volume when given), deleted ones after live ones; ``live_only``:
        no deleted one (what a mounted filesystem shows)."""
        if self.con is None or not inner:
            return []
        q = (AT_SQL + (" AND volume IS ?" if volume is not None else "")
             + (" AND deleted = 0" if live_only else "") + " ORDER BY deleted, id")
        params = [self.host(image), inner, image] + ([volume] if volume is not None else [])
        return [(int(r[0]), r[1]) for r in self.con.execute(q, params)]

    def readables(self) -> list[tuple[str, str, Optional[int], bool]]:
        """(readable form, image, volume, mounted) of every form the run reads
        an image through, case-relative: the index meta's ``readable`` (the
        device, raw view or image file the listing read: any volume) and each
        filesystem the access plan mounted from the image
        (core.provenance.plan_mounts: its volume when the plan recorded it,
        else None)."""
        if self._readables is None:
            out: list[tuple[str, str, Optional[int], bool]] = []
            for image, m in self.meta().items():
                readable = str(m.get("readable") or "").replace("\\", "/").strip("/")
                if readable:
                    out.append((readable, image, None, False))
            from core.provenance import plan_mounts
            real_root = os.path.realpath(self.root)
            for point, image_path, volume in plan_mounts(str(self.root)):
                image = _rel(self.root, image_path)
                rel = os.path.relpath(point, real_root).replace(os.sep, "/")
                if image in self.meta() and not rel.startswith(".."):
                    out.append((rel.strip("/"), image, volume, True))
            self._readables = out
        return self._readables

    def by_readable_form(self, value: str) -> Optional[tuple[str, str, Optional[int], bool]]:
        """(image, inner path, volume, mounted) when ``value`` lies under one
        of an image's readable forms (readables)."""
        rel = _rel(self.root, value)
        low = rel.casefold()
        for readable, image, volume, mounted in self.readables():
            r = readable.casefold()
            if low == r:
                return image, "", volume, mounted
            if low.startswith(r + "/"):
                return image, rel[len(readable) + 1:], volume, mounted
        return None

    def by_readable(self, value: str) -> Optional[tuple[str, str]]:
        """(image, inner path) when ``value`` lies under a readable form of an
        image (readables)."""
        hit = self.by_readable_form(value)
        return (hit[0], hit[1]) if hit else None

    def copies_at(self) -> tuple[dict[str, int], bool]:
        """{case path, case-folded: the registered copies at or under it}
        (the copies a name resolves, entry_id set), remembered per case and
        the copies' part of the generation, and whether they are this
        resolver's generation's copies (none registered since it was read):
        a name cached under the generation lacks a later copy, so only
        such counts may be kept beside a set resolved from it."""
        if self._copies is None:
            sig = tuple(self.generation[1][:2]) if len(self.generation) == 3 else ()
            hit = _COPIES_AT.get(str(self.root))
            if hit is None or hit[0] != sig:
                counts: dict[str, int] = {}
                for path in self.copies():
                    parts = path.split("/")
                    for i in range(1, len(parts) + 1):
                        k = "/".join(parts[:i])
                        counts[k] = counts.get(k, 0) + 1
                now = tuple(self.con.execute("SELECT COUNT(*), MAX(rowid) FROM copies").fetchone() or ()) \
                    if self.con is not None else ()
                hit = (now, counts)
                if now == sig:
                    with _LOCK:
                        _COPIES_AT[str(self.root)] = hit
            self._copies = (hit[1], hit[0] == sig)
        return self._copies

    def copies(self) -> dict[str, int]:
        """{copy path (case-relative, case-folded): entry id} of every
        registered copy, one query."""
        if self.con is None:
            return {}
        return {str(p).casefold(): int(e) for p, e in self.con.execute(
            "SELECT copy_path, entry_id FROM copies WHERE entry_id IS NOT NULL")}

    def where(self, ids: Iterable[int]) -> dict[int, tuple[Any, str, Any, str]]:
        """{entry id: (host, image, volume, path)}, in batches."""
        out: dict[int, tuple[Any, str, Any, str]] = {}
        want = sorted({int(i) for i in ids})
        for k in range(0, len(want), 500):
            chunk = want[k:k + 500]
            if self.con is None:
                break
            for r in self.con.execute(f"SELECT id, host, image, volume, path FROM entries WHERE id IN "
                                      f"({','.join('?' * len(chunk))})", chunk):
                out[int(r[0])] = (r[1], r[2], r[3], r[4])
        return out

    # -- one token ------------------------------------------------------------
    def name(self, token: str, tool: str = "") -> Named:
        """What a token names (memoised by case, token, tool and the index
        generation)."""
        value = str(token or "").strip().strip("\"'")
        if not value:
            return _NOTHING
        key = (self.generation, value, tool)
        hit = _NAMES.get(key)
        if hit is None:
            hit = self._name(value, tool)
            # Only what the index answered is kept: a case file or folder
            # is looked at again (it may exist now, or hold more files).
            if any(k == "entry" for k, _i in hit.ids) or "::" in value or _ICAT_RE.search(" " + value + " "):
                with _LOCK:
                    if len(_NAMES) > _MEMO_MAX:
                        _NAMES.clear()
                    _NAMES[key] = hit
        return hit

    def _name(self, value: str, tool: str) -> Named:
        root, con = self.root, self.con
        m = self.ci.HANDLE_RE.match(value)
        if m and con is not None:
            img = self.match_image(m.group("image").split("@", 1)[0])
            if img is None:
                return _NOTHING
            inner = m.group("path").replace("\\", "/").strip().strip("/")
            offset = int(m.group("offset")) if m.group("offset") else None
            rows = self.at(img["rel"], inner, offset)
            return Named(frozenset(("entry", i) for i, _v in rows), img["rel"],
                         ambiguous=offset is None and len({v for _i, v in rows}) > 1,
                         inner=frozenset({("inner", img["rel"], norm_inner(inner))}))
        if m:
            img = self.match_image(m.group("image").split("@", 1)[0])
            rel = img["rel"] if img else _rel(root, m.group("image").split("@", 1)[0])
            return Named(frozenset(), rel, inner=frozenset({("inner", rel, norm_inner(m.group("path")))}))
        icat = _ICAT_RE.search(" " + value + " ")
        if icat and con is not None:
            token = icat.group("img") or icat.group("img0")
            hit = self.by_readable(token)
            image = hit[0] if hit else _rel(root, token)
            inode = icat.group("inode") or icat.group("inode0")
            # The exact inode, and a bare number's dashed forms ("5" names
            # "5-128-1") as a range the (image, inode) index serves ("5-" up
            # to, not including, "5."); a LIKE scanned every row of the image.
            if "-" in inode:
                rows = con.execute("SELECT id FROM entries WHERE image = ? AND volume IS ? AND origin = 'image' "
                                   "AND inode = ?", (image, int(icat.group("off") or 0), inode)).fetchall()
            else:
                rows = con.execute("SELECT id FROM entries WHERE image = ? AND volume IS ? AND origin = 'image' "
                                   "AND (inode = ? OR (inode >= ? AND inode < ?))",
                                   (image, int(icat.group("off") or 0), inode, inode + "-", inode + ".")).fetchall()
            return Named(frozenset(("entry", int(r[0])) for r in rows), image if image in self.meta() else "")
        rel = _rel(root, value)
        if os.path.isabs(rel):
            rel = _moved(rel)
        if not rel or rel == "." or os.path.isabs(rel) or rel.startswith(".."):
            return _NOTHING
        if con is not None:
            row = con.execute("SELECT entry_id FROM copies WHERE copy_path = ?", (rel,)).fetchone()
            if row is not None and row[0] is not None:
                # A copy is the entry it was extracted from, and a case file.
                return Named(frozenset({("entry", int(row[0])), ("file", rel)}))
            hit = self.by_readable_form(rel)
            if hit:
                image, inner, volume, mounted = hit
                # A mounted filesystem shows its live files only; without the
                # mounted volume's offset a path on several volumes names
                # every volume's entry, so the read is listed, not content
                # (an offset-less handle's rule).
                rows = self.at(image, inner, volume, live_only=mounted) if inner else []
                return Named(frozenset(("entry", i) for i, _v in rows), image,
                             ambiguous=mounted and volume is None and len({v for _i, v in rows}) > 1,
                             inner=frozenset({("inner", image, norm_inner(inner))}) if inner else frozenset(),
                             paths=frozenset({("file", rel)}) if mounted else frozenset())
        path = root / rel
        image = rel if rel in self.meta() else self._plan_image(rel)
        if path.is_dir():
            if con is not None:
                copies = self.ci.copies_under(root, rel, tool)
                if copies:
                    ids: set = set()
                    paths = [str(c["copy_path"]) for c in copies]
                    for i in range(0, len(paths), 500):
                        chunk = paths[i:i + 500]
                        ids |= {("entry", int(r[0])) for r in con.execute(
                            f"SELECT entry_id FROM copies WHERE copy_path IN ({','.join('?' * len(chunk))})", chunk)}
                    return Named(frozenset(ids), image, folder=True)
            found, total = folder_files(root, rel)
            return Named(frozenset(("file", f) for f in found), image, folder=True,
                         cut=(len(found), total) if len(found) < total else None)
        # A case path is that file whether or not it is on this disk now (a
        # case read where its evidence was not copied, a file since removed).
        return Named(frozenset({("file", rel)}), image)

    def _plan_images(self) -> list[tuple[str, str]]:
        """(image path, source) of the access plan's images, case-relative:
        a raw export of an image names its source (the plan's ``source``)."""
        if not hasattr(self, "_plan"):
            self._plan: list[tuple[str, str]] = []
            try:
                from core.mount_plan import load_mount_plan
                for img in load_mount_plan(self.root).get("images") or []:
                    if isinstance(img, dict) and img.get("path"):
                        self._plan.append((_rel(self.root, str(img["path"])),
                                           _rel(self.root, str(img.get("source") or "")) if img.get("source") else ""))
            except Exception:  # noqa: BLE001 - no plan: the image file alone names itself
                pass
        return self._plan

    def _plan_image(self, rel: str) -> str:
        """The image a case path reaches through the access plan (a mount
        point, a device, the image file, a raw export of it:
        core.provenance.image_for_path), the export's source when the plan
        names one; "" for none."""
        if not rel.startswith(("evidence/", "mnt/", "exports/")):
            return ""
        from core.provenance import image_for_path
        image = image_for_path(rel, self.root) or ""
        for path, source in self._plan_images():
            if image == path or rel == path:
                return source or path
        # An image file of the evidence tree; a raw-device node under mnt/
        # the plan does not reach is no image of its own.
        return image if image.startswith("evidence/") and (self.root / image).is_file() else ""

    def source_entry(self, cell: str) -> Optional[int]:
        """The one entry an export row's source cell names (a registered
        copy, a handle, a path under the readable form), None when it names
        none or more than one."""
        ids = [i for k, i in self.name(cell).ids if k == "entry"]
        return int(ids[0]) if len(ids) == 1 else None


def identify(case_dir: str | os.PathLike, token: str, *, tool: str = "") -> frozenset[Identity]:
    """The identities a token names (see the module docstring). A handle
    without an offset on an image of several volumes names every volume's
    entry at that path, or none: never the first. The case root, and a
    token the case does not know, name nothing. A folder names the
    registered copies below it (those ``tool``'s input kind takes), else its
    files, up to FOLDER_BOUND (``Named.cut`` says how many there were)."""
    if not case_dir or not str(token or "").strip():
        return frozenset()
    with Resolver(case_dir) as r:
        n = r.name(token, tool)
        return n.ids | n.paths


def identities_of(case_dir: str | os.PathLike, tokens: Iterable[str], *, tool: str = "") -> frozenset[Identity]:
    """The union of the identities of several tokens."""
    out: set[Identity] = set()
    with Resolver(case_dir) as r:
        for t in tokens:
            n = r.name(t, tool)
            out |= n.ids | n.paths
    return frozenset(out)


def image_path(case_dir: str | os.PathLike, token: str) -> Optional[tuple[str, str]]:
    """(image, inner path) a token names inside an image: a handle, or a
    path under the image's readable form; ("<image>", "") for the readable
    form or the image itself; None for anything else."""
    value = str(token or "").strip().strip("\"'")
    if not value or not case_dir:
        return None
    root = Path(case_dir)
    from core import contents_index as ci
    m = ci.HANDLE_RE.match(value)
    if m:
        img, _err = ci._match_image(root, m.group("image").split("@", 1)[0])
        return (img["rel"], m.group("path").replace("\\", "/").strip().strip("/")) if img else None
    with Resolver(root) as r:
        if r.con is None:
            return None
        hit = r.by_readable(value)
        if hit:
            return hit
        rel = _rel(root, value)
        return (rel, "") if rel in r.meta() else None


def listing_complete(case_dir: str | os.PathLike, image: str) -> bool:
    """Whether the index holds the image's whole listing (meta complete)."""
    with Resolver(case_dir) as r:
        m = r.meta().get(image) or {}
        return bool(m.get("listed")) and bool(m.get("complete"))


def folder_files(root: Path, rel: str, bound: Optional[int] = None) -> tuple[list[str], int]:
    """The case-relative files below a case folder, at most ``bound``
    (FOLDER_BOUND), and how many there are (the caller says "N of M" when
    they differ)."""
    bound = FOLDER_BOUND if bound is None else bound
    found: list[str] = []
    total = 0
    for dirpath, _dirs, files in os.walk(Path(root) / rel):
        for name in files:
            total += 1
            if len(found) < bound:
                found.append(_rel(Path(root), os.path.join(dirpath, name)))
    return found, total


def _entry_tool(entry: dict) -> str:
    """The tool the read rule names a call by (as artifact_value's reading
    calls do): the analyst tool's listed name, else the command's program."""
    from core.coverage_ledger import _entry_tool as tool_of
    name = tool_of(entry)
    if name:
        return name
    tool = str(entry.get("mcp_tool") or entry.get("tool") or "")
    if not tool:
        cmd = str(entry.get("cmd") or "")
        tool = cmd[5:] if cmd.startswith("<py>:") else (cmd.split() or [""])[0]
    return tool.split(":")[-1]


def call_reads(case_dir: str | os.PathLike, entry: dict, args: Optional[dict] = None, *,
               resolver: Optional[Resolver] = None) -> dict[str, Any]:
    """What a call read, from its own record (and its typed ``args`` when
    the caller has them, live): ``content`` (identities a content tool read
    by name), ``processed`` (what its parser reported processing: the
    ``processed`` stamp), ``listed`` (identities it only named: a listing
    tool's, a folder's expansion, an offset-less handle that matched several
    volumes), ``folder`` (what it reached through a folder it was pointed
    at, with ``folders`` the folders: a content tool reads the folder as a
    whole, no file of it on its own), ``images`` (the images it named
    in-image or by file: a handle,
    the readable form, an icat argument list, a mount, the image file; a
    copy of a file names no image) and ``cut`` ([(token, kept, total)] for a
    folder the bound stopped: "N of M"). Whether the call succeeded is the
    caller's question. Memoised by case, call id, the entry's record time
    (a fresh start numbers its calls from one again), revision, the args
    and the image listings (Resolver.listings): a call's read set is fixed
    once its record and the listings it names stand, so a copy registered
    or an export indexed later (the generation's counters, which move with
    every extraction) resolves only calls not yet seen, never the whole
    trace again. The one exception is a copy registered later at or under
    a path the call named (a background job's copies are registered when
    the job is collected, and its output can be read before that): each
    set keeps the copies counted at or under the call's paths, and a call
    whose count moved is resolved again. An export adds no image entry and
    no copy, so it changes no set."""
    empty = {"content": frozenset(), "processed": frozenset(), "listed": frozenset(), "folder": frozenset(),
             "folders": frozenset(), "images": frozenset(), "cut": ()}
    if not case_dir or not isinstance(entry, dict):
        return empty
    own = resolver is None
    r = resolver or Resolver(case_dir)
    try:
        digest = json.dumps(args, sort_keys=True, default=str) if args else ""
        key = (r.listings, entry.get("call_id"), str(entry.get("ts") or ""), entry.get("_rev"),
               str(entry.get("args") or ""), digest,
               json.dumps(entry.get("processed"), sort_keys=True, default=str) if entry.get("processed") else "",
               str(entry.get("cmd") or ""), str(entry.get("evidence_ref") or ""))
        if entry.get("call_id") is None:
            return _call_reads(r, entry, args)
        counts, current = r.copies_at()
        hit = _READS.get(key)
        if hit is not None and all(counts.get(p, 0) == n for p, n in hit[1]):
            return hit[0]
        named: set[str] = set()
        out = _call_reads(r, entry, args, named)
        if current:
            with _LOCK:
                if len(_READS) > _MEMO_MAX:
                    _READS.clear()
                _READS[key] = (out, tuple((p, counts.get(p, 0)) for p in {x.casefold() for x in named if x}))
        return out
    finally:
        if own:
            r.close()


def _call_reads(r: Resolver, entry: dict, args: Optional[dict], named: Optional[set] = None) -> dict[str, Any]:
    """call_reads' resolution; ``named`` collects the case paths the call
    named (a file a token or its processed stamp names, a folder it was
    pointed at, an output)."""
    from core.coverage_ledger import reads_content
    from core.provenance import input_tokens
    tool = _entry_tool(entry)
    content_tool = bool(tool) and reads_content(tool)
    content: set = set()
    listed: set = set()
    folder: set = set()
    folders: set = set()
    images: set = set()
    cut: list = []
    tokens = input_tokens(entry, r.root, args)
    cmd = str(entry.get("cmd") or "")
    if _ICAT_RE.search(" " + cmd + " "):
        tokens.append(cmd)
    named = set() if named is None else named
    for tok in tokens:
        n = r.name(tok, tool)
        if n.image:
            images.add(n.image)
        if n.cut:
            cut.append((tok, n.cut[0], n.cut[1]))
        if n.folder:
            folder |= n.ids
            path = _rel(r.root, tok)
            folders.add(path)
            named.add(path)
        else:
            named.update(p for k, p in n.ids | n.paths if k == "file")
        if n.folder or n.ambiguous or not content_tool:
            listed |= n.ids | n.inner
        else:
            content |= n.ids | n.inner
        # The mount path was read as named, whatever volume its entries are on.
        if content_tool and not n.folder:
            content |= n.paths
        else:
            listed |= n.paths
    # An extraction read what it extracted: an output that is a registered
    # copy names the entry the copy was taken from (never the copy itself,
    # which the call wrote).
    if content_tool and r.con is not None:
        from core.paths import output_paths
        for out in output_paths(call_args(entry, args)):
            rel = _rel(r.root, out)
            named.add(rel)
            row = r.con.execute("SELECT entry_id FROM copies WHERE copy_path = ?", (rel,)).fetchone()
            if row is not None and row[0] is not None:
                content.add(("entry", int(row[0])))
    # An image named beside a path inside it (an argument that is no case
    # path: icat's image and path, a reader's image and inner path): that
    # path in each image the call named, as the call wrote it.
    if images:
        for v in call_args(entry, args).values():
            for x in (v if isinstance(v, list) else [v]):
                if not isinstance(x, str) or "::" in x or not ("/" in x or "\\" in x) or "\n" in x:
                    continue
                rel = _rel(r.root, x)
                if rel.startswith(("evidence/", "analysis/", "exports/", "mnt/", "reports/")) or \
                        (r.root / rel).exists():
                    continue
                inner = norm_inner(x)
                if inner:
                    target = content if content_tool else listed
                    target |= {("inner", img, inner) for img in images}
    processed: set = set()
    for f in (entry.get("processed") or {}).get("files") or []:
        n = r.name(str((f or {}).get("path") or ""))
        if not n.folder:                   # a report names files; a folder in it credits nothing
            processed |= n.ids | n.paths
            named.update(p for k, p in n.ids | n.paths if k == "file")
    return {"content": frozenset(content), "processed": frozenset(processed),
            "listed": frozenset(listed - content), "folder": frozenset(folder), "folders": frozenset(folders),
            "images": frozenset(images), "cut": tuple(cut)}


def record_extraction(case_dir: str | os.PathLike, entry: dict, args: Optional[dict],
                      reads: dict[str, Any], call_id: Any) -> bool:
    """Register the file an icat wrote as a copy of the entry it read, so a
    later read of the file reads that entry: the call's command is an icat
    of one object, its reads name one entry, its one output is a file in
    the case of the entry's size (a slack read, a cut write or a transform
    of another size is no copy), stored with its sha256 (or, above the
    per-file input bound, by its size alone). The caller says
    the call succeeded. Returns whether a copy was registered."""
    from core import contents_index as ci
    if not case_dir or not ci.copy_provenance_on() or not _ICAT_RE.search(" " + str(entry.get("cmd") or "") + " "):
        return False
    ids = [t[1] for t in reads.get("content") or () if t and t[0] == "entry"]
    from core.paths import output_paths
    outs = output_paths(call_args(entry, args))
    if len(ids) != 1 or len(outs) != 1:
        return False
    root = Path(case_dir)
    rel = _rel(root, outs[0])
    if not rel or os.path.isabs(rel) or rel.startswith("..") or not (root / rel).is_file():
        return False
    con = ci._connect(root)
    if con is None:
        return False
    try:
        row = con.execute("SELECT size FROM entries WHERE id = ?", (int(ids[0]),)).fetchone()
    finally:
        con.close()
    size = (root / rel).stat().st_size
    if row is None or row[0] is None or int(row[0]) != size:
        return False
    cid = int(call_id) if str(call_id or "").isdigit() else None
    # The hash costs a read of the whole file inside the tool call: above the
    # per-file input bound the copy is registered by its size alone, and the
    # record says so (ci.SIZE_ONLY).
    from core.input_scale import MAX_FILE_BYTES
    sha = ci.file_sha256(root / rel) if size <= MAX_FILE_BYTES else ci.SIZE_ONLY
    ci.record_copy(root, str(root / rel), int(ids[0]), cid, size, sha)
    return True


def reset_cache() -> None:
    """Forget the memoised names and reads (a test, a new case)."""
    with _LOCK:
        _NAMES.clear()
        _READS.clear()
        _COPIES_AT.clear()
