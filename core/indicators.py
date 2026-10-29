"""Typed indicators: what a finding names, stated by the analyst with a type
and a side, checked against the evidence it cites.

A prose-parsed indicator guesses what a value is from the verbs around it;
a typed row says it. Each row is ``{type, value, side}`` with an optional
``first_seen`` and ``last_seen``. Every value must appear in the output of
a call the finding cites, read the way the citation gate reads it, after
the normalisation its type needs (a path with either separator and with or
without its drive letter or mount root, a registry key under any hive
root, a defanged URL, a MAC with any separator). A value the cited outputs
do not show is dropped with the reason; the finding itself is never
refused over it. The frame (incident, or the examination of the subject's
own device) and the side decide what a responder does with the row.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import threading
from typing import Any, Iterable

from core.table_rows import ECHO_KEYS

TYPES = ("ip", "mac", "domain", "url", "email", "hash", "path", "file", "registry",
         "service", "task", "account", "host", "serial", "cloud_resource",
         "credential_id", "pattern")
SIDES = ("attacker", "victim", "subject", "third_party")
# ATLAS_IOC_ROLES: a value the evidence shows without showing whose
# it is; listed with its sighting and no use until a later row states it.
UNDETERMINED = "undetermined"


def roles_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_IOC_ROLES", True)


def sides() -> tuple[str, ...]:
    return SIDES + ((UNDETERMINED,) if roles_on() else ())
FRAMES = ("incident", "subject", "neutral")
USES = ("block", "hunt", "contain", "request", "scope", "identify", "review")
MAX_VALUE = 300
SPILL_READ_CHARS = 500_000
INDEXED_CHARS = 8_000_000

_HIVE_ROOTS = ("hkey_local_machine", "hkey_current_user", "hkey_users", "hkey_classes_root",
               "hkey_current_config", "hklm", "hkcu", "hku", "hkcr", "hkcc", "root",
               "software", "system", "sam", "security", "ntuser.dat", "ntuser", "usrclass.dat")
_DEFANG = (("hxxps://", "https://"), ("hxxp://", "http://"), ("[.]", "."), ("(.)", "."),
           ("[:]", ":"), ("[://]", "://"), ("[at]", "@"))
_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}[:.-]?){5}[0-9a-f]{2}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z0-9-]{2,}$")
# An address, local-part@domain: a mail address, a UPN, a Kerberos principal.
# The domain in DNS label syntax (letters, digits, inner hyphens, 1-63 a
# label) under a top label of letters or an IDN's xn-- form. A lexical shape,
# no list of domains: the last label is a host's, never a file extension,
# whatever it spells (com, pl, sh).
_ADDRESS_RE = re.compile(r"[^@\s\\/]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                         r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})", re.IGNORECASE)
_SERIAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,}$")
# The ranges a perimeter block cannot reach: the host is contained instead.
_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128"))
# Addresses no block list should carry: some firewall syntaxes read 0.0.0.0
# as "any", and multicast, broadcast and reserved space name no host.
_NEVER_BLOCK_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::/128", "ff00::/8"))


# ── rows ────────────────────────────────────────────────────────────────

def refang(value: str) -> str:
    low = value
    for a, b in _DEFANG:
        low = low.replace(a, b).replace(a.upper(), b)
    return low


# The names a model reaches for: the canonical type, its common spellings,
# and the suffixes it likes to add.
_TYPE_ALIASES = {"ipv4": "ip", "ipv6": "ip", "ip_addr": "ip", "ipaddress": "ip",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "file_hash": "hash", "md5_hash": "hash",
    "sha1_hash": "hash", "sha256_hash": "hash", "filehash": "hash",
    "filename": "file", "file_name": "file", "binary": "file", "executable": "file",
    "process": "file", "process_name": "file", "image": "file", "tool": "file", "script": "file",
    "file_path": "path", "filepath": "path", "full_path": "path", "directory": "path", "folder": "path",
    "hostname": "host", "computer": "host", "computer_name": "host", "machine": "host",
    "user": "account", "username": "account", "user_account": "account", "account_name": "account",
    "user_name": "account", "principal": "account", "sid": "account",
    "reg": "registry", "regkey": "registry", "registry_key": "registry", "registry_path": "registry",
    "registry_value": "registry", "scheduled_task": "task", "service_name": "service",
    "key_id": "credential_id", "access_key": "credential_id", "access_key_id": "credential_id",
    "api_key": "credential_id", "token": "credential_id", "credential": "credential_id",
    "bucket": "cloud_resource", "s3_bucket": "cloud_resource", "cloud_account": "cloud_resource",
    "mutex": "pattern", "user_agent": "pattern", "useragent": "pattern",
    "fqdn": "domain", "dns": "domain", "hostname_fqdn": "domain", "mac_addr": "mac",
    "email_address": "email", "mail": "email", "sha_256": "hash", "sha_1": "hash"}


def canonical_type(kind: Any) -> str:
    """The canonical indicator type for the name given to it."""
    kind = str(kind or "").strip().lower().replace("-", "_").replace(" ", "_")
    for suffix in ("_address", "_name", "_value", "_string"):
        if kind.endswith(suffix) and kind[:-len(suffix)] in TYPES:
            kind = kind[:-len(suffix)]
    return _TYPE_ALIASES.get(kind, kind)


def normalize_row(row: Any) -> tuple[dict[str, Any] | None, str]:
    """``(row, "")`` with the type, value and side canonical, or
    ``(None, reason)`` when the row cannot be an indicator."""
    if not isinstance(row, dict):
        return None, "a row is an object with type, value and side"
    kind = canonical_type(row.get("type"))
    value = " ".join(str(row.get("value") or "").split()).strip("`'\" ")
    side = str(row.get("side") or "").strip().lower().replace("-", "_").replace(" ", "_")
    side = {"third": "third_party", "thirdparty": "third_party", "other": "third_party",
            "adversary": "attacker", "actor": "attacker", "owner": "victim",
            "suspect": "subject", "person": "subject"}.get(side, side)
    if roles_on() and side in ("unknown", "unclear", "undecided"):
        side = UNDETERMINED
    if kind not in TYPES:
        return None, f"unknown type {kind!r} (one of {', '.join(TYPES)})"
    if side not in sides():
        return None, f"unknown side {side!r} (one of {', '.join(sides())})"
    if not value or len(value) > MAX_VALUE or "\n" in value:
        return None, "a value is one line of at most 300 characters"
    value, why = _shape(kind, value)
    if why:
        return None, why
    out = {"type": kind, "value": value, "side": side}
    for key in ("first_seen", "last_seen"):
        if row.get(key):
            out[key] = str(row[key]).strip()
    if kind in ("host", "account") and row.get("attacker_from"):
        from core.incident_window import window_notes_on
        if window_notes_on():
            # When the attacker first acted on this host or with this
            # account: a statement of its own, never first_seen's reuse.
            out["attacker_from"] = str(row["attacker_from"]).strip()
    return out, ""


def account_is_a_file(value: str) -> bool:
    """An account value written as a program or script file name, such as a
    process image (ATLAS_ACCOUNT_SHAPE): a process is not an account. Only
    the executable and script classes count, and only with a stem of three
    or more characters: a short dotted user name (jo.py, li.so) or one that
    ends in another class's extension (jane.zip) stays an account. An
    address (_ADDRESS_RE: a UPN, a mail address, a Kerberos principal) is
    read before any extension and stays an account. Ceiling: a file named
    like an address (setup@v2.exe) typed as an account stays an account."""
    from core.envfile import env_flag
    if not env_flag("ATLAS_ACCOUNT_SHAPE", True):
        return False
    from core.entities import file_class_of
    base = value.replace("/", "\\").rsplit("\\", 1)[-1]
    if _ADDRESS_RE.fullmatch(base):
        return False
    stem = base.rsplit(".", 1)[0] if "." in base else ""
    return file_class_of(base) in ("executable", "script") and len(stem) >= 3


# An account written with a qualifier, DOMAIN\name, where the qualifier or the
# name may hold single spaces (NT AUTHORITY\SYSTEM, a display name). A lexical
# shape of account notation, a few words on each side; anything longer is
# prose, not an account.
_QUALIFIED_ACCOUNT_RE = re.compile(r"[^\\\s]+(?: [^\\\s]+)*\\[^\\\s]+(?: [^\\\s]+)*")


def _qualified_account(value: str) -> bool:
    from core.envfile import env_flag
    if not env_flag("ATLAS_ACCOUNT_SHAPE", True) or not _QUALIFIED_ACCOUNT_RE.fullmatch(value):
        return False
    return all(len(side.split()) <= 3 for side in value.split("\\"))


_HASH_LABEL_RE = re.compile(r"(md5|sha-?1|sha-?256)\s*[:=]\s*([0-9a-f]+)")
_HASH_SIZES = {"md5": 32, "sha1": 40, "sha256": 64}


def _shape(kind: str, value: str) -> tuple[str, str]:
    low = value.lower()
    if kind == "ip":
        core = value.rsplit(":", 1)[0] if re.fullmatch(r"\d+\.\d+\.\d+\.\d+:\d+", value) else value
        try:
            return str(ipaddress.ip_address(core.strip("[]"))), ""
        except ValueError:
            return value, f"{value!r} is not an IP address"
    if kind == "mac":
        bare = re.sub(r"[^0-9a-f]", "", low)
        if not _MAC_RE.match(low) or len(bare) != 12:
            return value, f"{value!r} is not a MAC address"
        return ":".join(bare[i:i + 2] for i in range(0, 12, 2)), ""
    if kind == "hash":
        # A digest written with its algorithm in front ("sha256:<hex>") is
        # that digest when the name fits its length (the algorithms' public
        # digest sizes).
        labelled = _HASH_LABEL_RE.fullmatch(low)
        if labelled and len(labelled.group(2)) == _HASH_SIZES[labelled.group(1).replace("-", "")]:
            low = labelled.group(2)
        if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", low):
            if re.fullmatch(r"[0-9a-f]+", low):
                return value, (f"{len(low)} hex characters; the hash type takes an MD5 (32), "
                               "a SHA-1 (40) or a SHA-256 (64)")
            return value, f"{value!r} is not an MD5, SHA-1 or SHA-256 hash"
        return low, ""
    if kind == "email":
        if not _EMAIL_RE.match(low) or not _delegated_host(low.rsplit("@", 1)[-1]):
            return value, f"{value!r} is not an email address at a real domain"
        return low, ""
    if kind == "url":
        plain = refang(value)
        if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://\S+$", plain):
            return value, f"{value!r} is not a URL (scheme://host...)"
        return plain, ""
    if kind == "domain":
        if " " in value or not _delegated_host(low):
            return value, f"{value!r} is not a domain name under a real top-level domain"
        return low.rstrip("."), ""
    if kind == "registry":
        if "\\" not in value and "/" not in value:
            return value, f"{value!r} is not a registry key path"
        return value, ""
    if kind == "path":
        if "\\" not in value and "/" not in value:
            return value, f"{value!r} has no path separator; use type file for a bare name"
        return value, ""
    if kind == "serial":
        if not _SERIAL_RE.match(value):
            return value, f"{value!r} is not a device serial (8 or more letters and digits)"
        return value.upper(), ""
    if kind in ("host", "account", "file"):
        if " " in value and kind != "file" and not (kind == "account" and _qualified_account(value)):
            return value, f"a {kind} has no spaces: {value!r}"
        if kind == "account" and account_is_a_file(value):
            return value, f"{value!r} names a file, not an account: type it as file"
        return value, ""
    return value, ""


def _delegated_host(name: str) -> bool:
    """A typed name is a domain when its last label is delegated or a
    special-use suffix, whatever its other labels look like: the analyst
    stated the type, and presence still checks the value."""
    low = name.lower().rstrip(".")
    labels = low.split(".")
    if len(labels) < 2 or not all(labels):
        return False
    try:
        from core.ioc_catalog import _SPECIAL_USE_RE, _tlds
        return labels[-1] in _tlds() or _SPECIAL_USE_RE.search(low) is not None
    except Exception:  # noqa: BLE001
        return True


def _domain_kind(name: str) -> str:
    try:
        from core.ioc_catalog import _dotted_kind
        return _dotted_kind(name)
    except Exception:  # noqa: BLE001
        return "domain" if "." in name else ""


# ── presence in the cited evidence ───────────────────────────────────────

def _norm_path(text: str) -> str:
    text = text.lower().replace("\\", "/")
    return re.sub(r"(?<![a-z0-9])[a-z]:/", "/", text)


# Atlas mounts an image under <case>/mnt/<image>/fs (or root): a value the
# model copied from a listing carries that prefix, the in-image path does
# not. Only this leading mount root may be dropped from a value.
_MOUNT_ROOT_RE = re.compile(r"^(?:.*/)?mnt/[^/]+/(?:fs|root|vol\d*)/")


def _path_core(kind: str, value: str) -> str:
    """The whole normalised value without its drive letter, hive root or
    mount root: what must appear, at a component boundary, in the text."""
    norm = _norm_registry(value.lower()) if kind == "registry" else _norm_path(value.lower())
    norm = _MOUNT_ROOT_RE.sub("", norm)
    if kind == "registry":
        norm = _strip_hive(norm)
    return norm.strip("/")


def _norm_registry(text: str) -> str:
    text = _norm_path(text)
    text = re.sub(r"(?:currentcontrolset|controlset00\d)", "controlset", text)
    return text


def _strip_hive(key: str) -> str:
    parts = [p for p in key.split("/") if p]
    while parts and parts[0] in _HIVE_ROOTS:
        parts = parts[1:]
    return "/".join(parts)


def _found(kind: str, value: str, text: str) -> bool:
    """Whether ``text`` (the output of a cited call, as scan_text left it)
    shows ``value`` under the normalisation its type needs."""
    low = text.lower()
    if kind in ("path", "registry"):
        norm_text = _norm_registry(low) if kind == "registry" else _norm_path(low)
        core = _path_core(kind, value)
        if not core:
            return False
        # the whole value, at a component boundary: a text path may carry a
        # mount root before it, never a different directory inside it
        return re.search(r"(?:^|[^a-z0-9._$-])" + re.escape(core) + r"(?![a-z0-9._$-])", norm_text) is not None
    if kind == "ip":
        forms = {value}
        try:
            ip = ipaddress.ip_address(value)
            if ip.version == 6:
                forms |= {ip.compressed, ip.exploded}
        except ValueError:
            pass
        # An address may carry one trailing port part, as tcpdump and ngrep
        # print it ("203.0.113.5.80"); two or more dotted numbers after it
        # make it the head of a longer run (an OID, a version), not this one.
        return any(re.search(r"(?<![\d.])" + re.escape(f) + r"(?!\d)(?!\.\d{1,5}\.\d)(?!\.\d{6})", low)
                   if ":" not in f
                   else re.search(r"(?<![0-9a-f:])" + re.escape(f) + r"(?![0-9a-f:])", low)
                   for f in forms)
    if kind == "mac":
        bare = value.replace(":", "")
        forms = {value, bare, "-".join(value.split(":")), ".".join(bare[i:i + 4] for i in range(0, 12, 4))}
        return any(f in low for f in forms)
    if kind == "url":
        plain = refang(low)
        v = value.lower()
        return v in plain or v.split("://", 1)[-1] in plain
    if kind == "hash":
        return re.search(r"(?<![0-9a-f])" + re.escape(value.lower()) + r"(?![0-9a-f])", low) is not None
    if kind in ("cloud_resource", "credential_id", "service", "task"):
        return re.search(r"(?<![a-z0-9_-])" + re.escape(value.lower()) + r"(?![a-z0-9_-])", low) is not None
    if kind == "pattern":
        return value.lower().lstrip("*") in low
    if kind == "account":
        names = {value.lower(), value.lower().split("\\")[-1].split("@")[0]}
        return any(re.search(r"(?<![a-z0-9._-])" + re.escape(n) + r"(?![a-z0-9-])", low) for n in names)
    return re.search(r"(?<![a-z0-9._-])" + re.escape(value.lower()) + r"(?![a-z0-9-])", low) is not None


def _evidence_entries(call_ids: Iterable[int]) -> list[tuple[int, dict]]:
    """The cited calls whose output is evidence: what a tool printed, never
    the analyst's own words (reasoning, claim and correlation calls) and
    never an outside lookup, whose output restates the value it was asked
    about (core.forensic_citation.citation_class)."""
    try:
        from core.execution_log import log
        from core.forensic_citation import citation_class
        by = log.index().by_call_id or {}
    except Exception:  # noqa: BLE001
        return []
    out = []
    for cid in call_ids:
        entry = by.get(int(cid)) if str(cid).strip().lstrip("-").isdigit() else None
        if isinstance(entry, dict) and citation_class(entry) == "evidence":
            out.append((int(cid), entry))
    return out


# ── what a call printed ──────────────────────────────────────────────────
#
# The one echo-free output reader. Every presence judgement in the program
# (the record-time check below, the citation row test, the pivot credit,
# the knowledge index scan, the traceability audit) reads a call's output
# through request_strings, printed_rows and printed_text, so one rule says
# what a tool printed and what it only repeated of its request.

# The fields a wrapper prints its own command line in.
_BANNER_KEYS = ("command", "command_line", "cmdline", "cmd", "argv", "invocation")
_STRING_FIELD_RE = re.compile(r'"([^"\\]+)"\s*:\s*"((?:[^"\\]|\\.)*)(?:"\s*,?|$)')
# A value of a cut argument string is read only when its closing quote stands:
# the tail the cut ended is a key with no value (a cut path is a different
# path, a folder above the one the call named).
_CLOSED_FIELD_RE = re.compile(r'"([^"\\]+)"\s*:\s*"((?:[^"\\]|\\.)*)"')
# The keys of a cut argument string, read leniently: a JSON text cut at 400
# characters no longer parses, and the key list must still cover it.
_KEY_RE = re.compile(r'"([A-Za-z_][\w-]*)"\s*:')
_QUOTED_RE = re.compile(r"'([^']{3,})'|\"([^\"]{3,})\"")
# A result that holds no row: a count of zero or an empty list under a row
# key, and no list of records anywhere at its top level, whole or cut. A
# result with rows under one key and an empty list under another holds rows.
_COUNT_KEYS = ("result_count", "count", "hit_count", "match_count", "matched_rows", "row_count",
               "total", "total_hits", "n_hits", "num_hits", "num_results", "records_matched")
_ROW_KEYS = ("results", "hits", "matches", "rows", "records", "items", "events", "entries", "lines", "files")
_HEADER_KEYS = ("columns", "headers", "fields")
_ZERO_SIGNAL_RE = re.compile(
    r'"(?:' + "|".join(_COUNT_KEYS) + r')"\s*:\s*0(?![.\d])|"(?:' + "|".join(_ROW_KEYS) + r')"\s*:\s*\[\s*\]')
_ROWS_PRESENT_RE = re.compile(r'"[^"\\]+"\s*:\s*\[\s*[{\[]|"(?:' + "|".join(_ROW_KEYS) + r')"\s*:\s*\[\s*[^\]\s]')
# The clause a command-line tool prints instead of rows (a line, or the
# part of a line between semicolons): that clause says nothing, the file it
# names included; what else the output prints stands.
_NO_ROW_VERBS = r"matched|found|returned|selected"
_NO_ROWS_CLAUSE_RE = re.compile(
    r"(?im)[^;\n]*(?<![\d.])(?:0|no|zero)\s+(?:records?|rows?|hits?|matches|results?|events?|entries|files?)"
    r"\s+(?:" + _NO_ROW_VERBS + r")\b[^;\n]*")
# A labelled line of a command-line tool's output. It is the tool's banner,
# restating its invocation or its filter, when its value is made of the
# call's own words (the recorded command line and arguments); a line under
# the same label whose value comes from the data (a process's command line,
# a shortcut's arguments, a subscription's query) stays.
# The words a tool labels its request with (command line, pattern, query,
# a search ...): its banner's vocabulary, shared by the labelled-line rule
# and the echo-line rule (_echo_line).
_REQUEST_LABELS = (r"command\s*line|cmd(?:\s*line)?|arguments?|args|argv|usage|invocation|parameters|"
                   r"options|search(?:ing)?(?:\s+for|\s+pattern)?|pattern|query|filter|keywords?|looking\s+for")
_LABELLED_LINE_RE = re.compile(r"(?im)^[ \t]*(?:" + _REQUEST_LABELS + r")\s*[:=][ \t]*(.*)$")
# A line's words that say it reports a request: a request label (as a word
# stem: searched, searching), or how many rows matched or were found;
# never a command's switch (-Pattern, -Filter), which is data.
_ECHO_WORD_RE = re.compile(r"(?i)(?<![-\w])(?:" + _REQUEST_LABELS + r"|searched|match(?:es|ing)?|" + _NO_ROW_VERBS
                           + r")\b")


def _echo_free_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_IOC_ECHO_FREE")


def _parsed_args(entry: dict) -> tuple[Any, frozenset[str]]:
    """The call's recorded arguments as data, and their keys. A string that
    parses (JSON, or a Python literal) is read whole; one the trace cut is
    read leniently as the key-value pairs it still shows."""
    args = entry.get("args")
    if isinstance(args, str) and len(args) < 20_000:
        import ast
        import json
        parsed: Any = None
        try:
            parsed = json.loads(args)
        except ValueError:
            try:
                parsed = ast.literal_eval(args)
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                parsed = None
        if isinstance(parsed, (dict, list, tuple)):
            args = parsed
        else:
            keys = frozenset(_KEY_RE.findall(args))
            pairs = {k: _unescaped(v) for k, v in _CLOSED_FIELD_RE.findall(args)}
            return pairs, keys | frozenset(pairs)
    keys = frozenset(k for k in args if isinstance(k, str)) if isinstance(args, dict) else frozenset()
    return args, keys


def request_strings(entry: dict) -> frozenset[str]:
    """What the call was given, folded: the string values of its recorded
    arguments and its evidence reference, and for a shell command its quoted
    literals and path-shaped tokens; three characters or more. What an
    output repeats of them shows nothing."""
    values: set[str] = set()

    def walk(x: Any) -> None:
        if isinstance(x, str):
            values.add(x.casefold())
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                walk(v)

    args, _keys = _parsed_args(entry)
    walk(args)
    walk(entry.get("evidence_ref"))
    cmd = str(entry.get("cmd") or "")
    if cmd and not cmd.startswith("<py>:"):
        for m in _QUOTED_RE.finditer(cmd):
            values.add((m.group(1) or m.group(2)).casefold())
        try:
            from core.coverage_ledger import _blob_paths
            values.update(p.casefold() for p in _blob_paths(cmd))
        except Exception:  # noqa: BLE001
            pass
    return frozenset(v for v in values if len(v) >= 3)


def _argument_keys(entry: dict) -> frozenset[str]:
    """The keys a result echoes the request under: the call's own argument
    keys, the shared echo list and a wrapper's command-line fields, always
    all three."""
    return _parsed_args(entry)[1] | ECHO_KEYS | frozenset(_BANNER_KEYS)


def _request_tokens(entry: dict, request: frozenset[str]) -> frozenset[str]:
    """The call's own words as single tokens: its command line, its request
    values and the words those are made of."""
    tokens = set(str(entry.get("cmd") or "").casefold().split()) | set(request)
    for value in request:
        tokens.update(value.split())
    return frozenset(tokens)


def _is_banner(value: str, tokens: frozenset[str]) -> bool:
    """A labelled line's value is the tool's banner when every word of it is
    one of the call's own words; the first word may instead be the program's
    own name (the base name of a command token, with or without .exe). A
    value with any other word is data."""
    words = value.casefold().split()
    if not words:
        return True
    programs = {t.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".exe") for t in tokens}
    first = words[0] in tokens or words[0].removesuffix(".exe") in programs
    return first and all(w in tokens for w in words[1:])


def _unescaped(value: str) -> str:
    import json
    try:
        return json.loads('"' + value + '"')
    except ValueError:
        return value.replace('\\"', '"').replace("\\\\", "\\")


def _drop_key_object(s: str, key: str) -> str:
    """``s`` without every ``"key": {...}`` object (balanced, string-aware;
    one the text cuts short is dropped to the end)."""
    out: list[str] = []
    i = 0
    pat = re.compile(r'"%s"\s*:\s*\{' % re.escape(key))
    while True:
        m = pat.search(s, i)
        if not m:
            out.append(s[i:])
            return "".join(out)
        out.append(s[i:m.start()])
        j, depth, in_str, esc = m.end(), 1, False, False
        while j < len(s) and depth:
            ch = s[j]
            if in_str:
                esc, in_str = (False, True) if esc else (ch == "\\", ch != '"')
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            j += 1
        i = j
        if i < len(s) and s[i] == ",":
            i += 1


def _echo_field_re(keys: frozenset[str]) -> re.Pattern:
    return re.compile(
        r'"(?:' + "|".join(map(re.escape, sorted(keys))) + r')"\s*:\s*"(?:[^"\\]|\\.)*(?:"\s*,?|$)')


def _strip_request(text: str, request: frozenset[str], *, fields: bool = True,
                   keys: frozenset[str] = frozenset()) -> str:
    """``text`` without the fields under the echo keys (the shared list and
    ``keys``) and the search alternatives and, with ``fields``, without every
    string field whose value is one the call was given."""
    text = _echo_field_re(keys | ECHO_KEYS | frozenset(_BANNER_KEYS)).sub(
        "", _drop_key_object(text, "alternatives"))
    if request and fields:
        text = _STRING_FIELD_RE.sub(
            lambda m: "" if _unescaped(m.group(2)).casefold() in request else m.group(0), text)
    return text


def _without_echo_fields(s: str, request: frozenset[str], keys: frozenset[str]) -> str:
    """The JSON text ``s`` (whole or cut) with the request stripped from its
    head, the part before the first nested container (the rows), where a
    data column may carry the same name. A cut flat record is all head, so
    it loses its request fields the way a parsed one does."""
    s = _drop_key_object(s, "alternatives")
    cut = _first_container(s)
    return _strip_request(s[:cut], request, keys=keys) + s[cut:]


def _first_container(s: str) -> int:
    """Offset of the first array or object nested in the JSON text ``s``
    (outside its strings), or its length."""
    in_str = esc = False
    for i, ch in enumerate(s[1:], 1):
        if in_str:
            esc, in_str = (False, True) if esc else (ch == "\\", ch != '"')
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            return i
    return len(s)


def _row_lists(data: dict) -> list[list]:
    """The lists of records at the result's top level: any non-empty list
    under a row key, and any non-empty list of records (a tool's lines are
    rows too)."""
    return [v for k, v in data.items()
            if isinstance(v, list) and v and (k in _ROW_KEYS or isinstance(v[0], (dict, list)))]


# A count by the lexical shape of its key (finding_count, total_engines,
# shown, num_hits): a tally of the result, no field of the record.
_COUNT_SHAPED_KEY_RE = re.compile(r"(?:^|_)(?:count|total|scanned|shown|returned)(?:_|$)|^(?:num|n)_", re.I)
# A size by the lexical shape of its key (size_bytes, uncompressed_bytes,
# length): what a result measured, unlike a time or a tally it kept.
_SIZE_SHAPED_KEY_RE = re.compile(r"(?:^|_)(?:size|bytes|length)(?:_|$)", re.I)


def _says_more(rest: dict, request: frozenset[str]) -> bool:
    """Whether a record's fields beside those that repeat the request carry
    a result: a list of records, a size, or an entity (core.entities) that
    is not the request again. A failed record (success false), a flag, a
    count, a time, a list of names or a message restating the request
    carries none."""
    if rest.get("success") is False:
        return False
    from core.entities import discriminative, extract
    for k, v in rest.items():
        if isinstance(v, bool) or v is None or k in _COUNT_KEYS or _COUNT_SHAPED_KEY_RE.search(k):
            continue
        if isinstance(v, list):
            if any(isinstance(x, dict) and x for x in v):
                return True
        elif isinstance(v, (int, float)):
            if v and _SIZE_SHAPED_KEY_RE.search(k):
                return True
        elif isinstance(v, str):
            for ent in discriminative(extract(v)):
                value = ent.split(":", 1)[-1].casefold()
                if not any(value in r or (len(r) >= 4 and r in value) for r in request):
                    return True
    return False


# A sentence by lexical shape: four or more plain words (letters only, a
# closing punctuation mark allowed). A hash, a path, an id, a number, a
# command line or a short label has fewer; a lexical shape, not analysis.
# ponytail: a sentence carrying digits or a path in most of its words
# ("scanned 12 files in C:/x") reads as no prose and stays a field.
_PLAIN_WORD_RE = re.compile(r"(?:^|(?<=\s))[^\W\d_]+[.,;:!?)]?(?=\s|$)")


def _is_prose(text: str) -> bool:
    return len(_PLAIN_WORD_RE.findall(text)) >= 4


def _no_rows(data: dict) -> bool:
    if _row_lists(data):
        return False
    if any(v == 0 and v is not False for v in (data.get(k) for k in _COUNT_KEYS)):
        return True
    return any(data.get(k) == [] for k in _ROW_KEYS)


def _no_rows_text(s: str) -> bool:
    """_no_rows for a JSON text that does not parse (cut short)."""
    return _ROWS_PRESENT_RE.search(s) is None and _ZERO_SIGNAL_RE.search(s) is not None


def _output_text(entry: dict, limit: int) -> str:
    """The spill when the entry has one (read up to ``limit`` characters),
    else the excerpt; never both, since the excerpt is the spill's head and
    reading both would count rows twice."""
    sf = entry.get("stdout_file")
    if sf:
        try:
            with open(str(sf), encoding="utf-8", errors="replace") as fh:
                return fh.read(limit)
        except OSError:
            pass
    return str(entry.get("stdout_excerpt") or "")


def flat_records(items: Any, mark: bool = True) -> list[dict]:
    """A JSON record list with the records it nests (a plugin's
    ``__children``) as rows of their own: depth first, each after its
    parent; values as JSON gave them. ``mark``: each row given ``_row`` (its
    place, from 1) and, when the list nests, ``_depth`` (0 at the top), so a
    tree keeps its shape in a flat table. Linear in the records."""
    items = items if isinstance(items, list) else []
    nests = mark and any(isinstance(r, dict) and r.get("__children") for r in items)
    out: list[dict] = []
    todo = [(r, 0) for r in reversed(items)]
    while todo:
        r, depth = todo.pop()
        if not isinstance(r, dict):
            continue
        kids = r.get("__children")
        row = {k: v for k, v in r.items() if k != "__children"}
        if mark:
            row["_row"] = len(out) + 1
        if nests:
            row["_depth"] = depth
        out.append(row)
        if isinstance(kids, list):
            todo.extend((k, depth + 1) for k in reversed(kids))
    return out


# Saved outputs split by flat_records, per file by its size and mtime: the
# bases of one submit over one large output parse it once. Bounded by the
# bytes of the files held (parsed rows take about three times their file in
# memory): the oldest go first, and an output larger than the whole bound is
# parsed for its call and not kept. Beside threads read the map too: every
# change of the cache holds the lock.
_FLAT_CACHE: "dict[tuple, list[dict] | None]" = {}
_FLAT_CACHE_BYTES = 200_000_000
_FLAT_LOCK = threading.Lock()
_FLAT_INFLIGHT: "dict[tuple, threading.Event]" = {}      # files a reader is parsing now


def _flat_cached(key: tuple) -> tuple[bool, list[dict] | None]:
    with _FLAT_LOCK:
        if key not in _FLAT_CACHE:
            return False, None
        rows = _FLAT_CACHE.pop(key)
        _FLAT_CACHE[key] = rows                            # most recent last
        return True, rows


def _flat_keep(key: tuple, rows: list[dict] | None) -> None:
    size = key[1]
    if size > _FLAT_CACHE_BYTES:
        return
    with _FLAT_LOCK:
        _FLAT_CACHE[key] = rows
        while sum(k[1] for k in _FLAT_CACHE) > _FLAT_CACHE_BYTES:
            _FLAT_CACHE.pop(next(iter(_FLAT_CACHE)))


def _flat_parse(text: str) -> list[dict] | None:
    import json
    try:
        data = json.loads(text) if text.lstrip()[:1] == "[" else None
    except ValueError:
        data = None
    return flat_records(data) if isinstance(data, list) and data and all(isinstance(r, dict) for r in data) \
        else None


def flat_rows_of(entry: dict) -> list[dict] | None:
    """flat_records of a call's saved output when it is a JSON array of
    records (a plugin's JSON rendering), read whole: the spill file, else
    the excerpt of an output that was not cut. None when the output is no
    record array. The view (core.tool_result_view.render_record_view) and
    the map (_rows_of, for an entry the view marked rows_split "flat") read
    rows through this one function. One reader parses a file at a time: a
    second reader of the same file waits for the first one's rows instead
    of holding a second parse in memory."""
    sf = str(entry.get("stdout_file") or "")
    if not sf:
        # The excerpt is the whole output only when nothing was cut.
        return None if entry.get("truncated") else _flat_parse(str(entry.get("stdout_excerpt") or ""))
    try:
        st = os.stat(sf)
    except OSError:
        return None
    key = (sf, st.st_size, st.st_mtime_ns)
    while True:
        hit, rows = _flat_cached(key)
        if hit:
            return rows
        with _FLAT_LOCK:
            busy = _FLAT_INFLIGHT.get(key)
            if busy is None:
                mine = _FLAT_INFLIGHT[key] = threading.Event()
        if busy is None:
            break
        busy.wait()                     # its rows are cached now, or it was too large to keep: parse then
    try:
        try:
            with open(sf, encoding="utf-8", errors="replace") as fh:
                rows = _flat_parse(fh.read())
        except OSError:
            return None
        _flat_keep(key, rows)
        return rows
    finally:
        with _FLAT_LOCK:
            _FLAT_INFLIGHT.pop(key, None)
        mine.set()


def _rows_of(entry: dict, raw: str, *, windowed: bool = False) -> tuple[list[Any], list[str]]:
    """The records the output ``raw`` of ``entry`` holds, as data, with the
    table's header when the result names one. A JSON result that reports no
    hit is empty; its ``alternatives`` object (which parts of the analyst's
    pattern matched a row, not what the row holds) goes; every top-level
    field under one of the call's argument keys or the shared echo keys
    goes, and one whose value is one of the request strings when the record
    says nothing more (_says_more), in a flat record too; the elements of its
    row lists are the rows, else the rest is one row. A cut JSON text loses
    the request from its head and its lines are the rows. Plain text loses a
    command-line tool's banner lines, zero-row clauses and the lines that
    only echo the request (_echo_line); its lines are the rows. An output
    the row view showed flat (rows_split "flat") is its flat_rows_of, unless
    ``windowed``: ``raw`` is then a piece of the output (an excerpt), read
    as it stands."""
    import json
    s = raw.lstrip()
    if not s:
        return [], []
    if not windowed and entry.get("rows_split") == "flat" and s[:1] == "[":
        # Shown as the flat row view: its "#n" names a flat row, so the map
        # reads the rows the view showed. Older entries keep their split.
        flat = flat_rows_of(entry)
        if flat is not None:
            return flat, []
    request = request_strings(entry)
    keys = _argument_keys(entry)
    if s[0] in "{[":
        try:
            data = json.loads(s)
        except ValueError:
            data = None
        if isinstance(data, list):
            return [r for r in data if r not in (None, "", [], {})], []
        if isinstance(data, dict):
            if _no_rows(data):
                return [], []
            data.pop("alternatives", None)
            rows = _row_lists(data)
            # A list under a row key, or of records that carry a count, makes
            # the result a result set: its other fields are its header
            # (counts, the request, a summary, notes), never a row. Records
            # under any other key belong to a record (the files of the same
            # content beside a hash).
            result_set = any(isinstance(data.get(k), list) for k in _ROW_KEYS) or any(
                isinstance(r, dict) and any(c in r for c in _COUNT_KEYS) for lst in rows for r in lst)
            # The fields under the call's argument keys (and the shared echo
            # keys) repeat the request, beside row lists and in a flat record
            # alike. A field whose value the call was given repeats it only
            # when the record says nothing more (_says_more): a not-found
            # record ({"username": X, "exists": false}) names X only because
            # X was asked for, while a result names its subject that way (the
            # file a hash is of, the password an archive opened with). A
            # flat record keeps its other fields as its data.
            for key in list(data):
                if key in keys:
                    data.pop(key)
            echoed = [k for k, v in data.items() if isinstance(v, str) and v.casefold() in request]
            if echoed and not _says_more({k: v for k, v in data.items() if k not in echoed}, request):
                for key in echoed:
                    data.pop(key)
            headers = next((v for v in (data.get(k) for k in _HEADER_KEYS)
                            if isinstance(v, list) and v and all(isinstance(h, str) for h in v)), [])
            if rows:
                # A record's own fields beside the records it lists (a hash
                # beside the files of the same content) are one more row,
                # after the listed ones so a row's place does not move;
                # counts and the tool's prose about the result are no field
                # of it.
                own = {} if result_set else {
                    k: v for k, v in data.items() if isinstance(v, (str, int, float)) and not isinstance(v, bool)
                    and k not in _COUNT_KEYS and not _COUNT_SHAPED_KEY_RE.search(k)
                    and not (isinstance(v, str) and _is_prose(v))}
                return [r for lst in rows for r in lst] + ([own] if own else []), headers
            return [data], headers
        if _no_rows_text(s):
            return [], []
        text = _without_echo_fields(s, request, keys)
        return [ln for ln in text.splitlines() if ln.strip()], []
    tokens = _request_tokens(entry, request)
    text = _LABELLED_LINE_RE.sub(lambda m: "" if _is_banner(m.group(1), tokens) else m.group(0), raw)
    text = _NO_ROWS_CLAUSE_RE.sub("", text)
    return [ln for ln in text.splitlines() if ln.strip() and not _echo_line(ln, request)], []


# A path-shaped token (a drive or slash path): what a tool names when it
# says where it searched.
_PATH_TOKEN_RE = re.compile(r"[A-Za-z]:[\\/]\S*|\S+[\\/]\S+")
# What a data line keeps beside a value: a digit, or a field separator.
_DATA_MARK_RE = re.compile(r"[0-9|,;:=\t]")


def _echo_line(line: str, request: frozenset[str]) -> bool:
    """A line that only says what the tool was asked: it holds a request
    string, and once the request strings and the paths are taken out no
    digit and no field separator is left and a word of the request banner
    is (\"searching for 'x' in <path>\"). A data line that holds the
    searched value keeps a time, a count or a separator beside it (a quoted
    CSV field, key=\"value\", a record's "Field": "value") or has no banner
    word (a command line, a log sentence, the bare value) and stays whole."""
    low = line.casefold()
    hits = [r for r in request if len(r) >= 3 and r in low]
    if not hits:
        return False
    for r in sorted(hits, key=len, reverse=True):
        low = low.replace(r, " ")
    rest = _PATH_TOKEN_RE.sub(" ", low)
    return not _DATA_MARK_RE.search(rest) and bool(_ECHO_WORD_RE.search(rest))


def _row_text(row: Any) -> str:
    import json
    from core.entities import scan_text
    text = row if isinstance(row, str) else json.dumps(row, ensure_ascii=False, default=str)
    return scan_text(text).lower()


def _legacy_printed_text(entry: dict, text: str | None) -> str:
    """The reader before the echo-free rule: the excerpt with the echo keys
    popped from a parsed result, and the spill's head, both."""
    import json
    from core.entities import scan_text
    if text is not None:
        return scan_text(text)

    def without_echo(raw: str) -> str:
        stripped = raw.strip()
        if not stripped.startswith("{"):
            return raw
        try:
            data = json.loads(stripped)
        except ValueError:
            return raw
        if not isinstance(data, dict):
            return raw
        if data.get("result_count") == 0 or data.get("results") == [] or data.get("hits") == [] \
                or data.get("matches") == [] or data.get("count") == 0:
            return ""
        for key in ECHO_KEYS:
            data.pop(key, None)
        return json.dumps(data)

    parts = [scan_text(without_echo(str(entry.get("stdout_excerpt") or "")))]
    sf = entry.get("stdout_file")
    if sf:
        try:
            with open(str(sf), encoding="utf-8", errors="replace") as fh:
                parts.append(scan_text(fh.read(SPILL_READ_CHARS)))
        except OSError:
            pass
    return " ".join(parts)


def printed_rows(entry: dict, *, text: str | None = None,
                 limit: int = SPILL_READ_CHARS) -> list[str]:
    """The rows the call printed, lower-cased, with the request removed
    (_rows_of). Read from the spill when the entry has one, up to ``limit``
    characters, else from the excerpt; ``text`` reads a piece of the output
    the caller holds instead (an index window, a spill read further), under
    the same rule. With ATLAS_IOC_ECHO_FREE off, the reader before this one:
    its whole text as one row."""
    if not _echo_free_on():
        legacy = _legacy_printed_text(entry, text)
        return [legacy.lower()] if legacy.strip() else []
    raw = _output_text(entry, limit) if text is None else text
    rows, _headers = _rows_of(entry, raw)
    out = []
    for row in rows:
        line = _row_text(row)
        if line.strip():
            out.append(line)
    return out


_ROWS_TEXT: dict[tuple, str] = {}
_ROWS_TEXT_CHARS = [0]


def rows_text(entry: dict, *, text: str | None = None, windowed: bool = False,
              limit: int = SPILL_READ_CHARS) -> str:
    """The rows the call printed (_rows_of), as they print: case kept, one
    row a line, the request and a result set's header left out. ``text``
    with ``windowed`` reads that piece of the output as it stands (an
    excerpt); without ``text`` the output is read (the spill up to
    ``limit``), remembered per spill version. ponytail: the memo is bounded
    by total characters and cleared whole when full."""
    import json
    key = None
    if text is None and entry.get("stdout_file"):
        try:
            st = os.stat(str(entry["stdout_file"]))
            key = (str(entry["stdout_file"]), st.st_size, st.st_mtime_ns, limit, entry.get("call_id"))
        except OSError:
            key = None
        if key is not None and key in _ROWS_TEXT:
            return _ROWS_TEXT[key]
    raw = _output_text(entry, limit) if text is None else text
    rows, _headers = _rows_of(entry, raw, windowed=windowed)
    out = "\n".join(r if isinstance(r, str) else json.dumps(r, ensure_ascii=False, default=str) for r in rows)
    if key is not None:
        if _ROWS_TEXT_CHARS[0] + len(out) > 50_000_000:
            _ROWS_TEXT.clear()
            _ROWS_TEXT_CHARS[0] = 0
        _ROWS_TEXT[key] = out
        _ROWS_TEXT_CHARS[0] += len(out)
    return out


def printed_text(entry: dict, *, text: str | None = None) -> str:
    """The printed rows as one text, for the readers that want text."""
    return "\n".join(printed_rows(entry, text=text))

# ── sightings: where in the evidence a value was seen ────────────────────

_SCAN_CHUNK = 1 << 20
_FILE_TERMS: dict[tuple[str, int, int], dict[str, bool]] = {}
# The host column of published tool outputs (Plaso l2tcsv, EvtxECmd and the
# common SIEM exports): format knowledge, like the time columns.
_HOST_COLUMNS = ("host", "computer", "computername", "hostname", "machinename", "devicename")
DROP_REASON_NO_SIGHTING = (
    "no tool output of this case that read evidence shows it; a value only the brief, the threat "
    "context, a finding or a file this run wrote names is context until a call shows it")


def _sightings_on() -> bool:
    """Sightings are on when asked (ATLAS_IOC_SIGHTINGS), and whenever the
    echo-free reader is on: the reader alone would drop the rows whose only
    cited evidence was an echo although other calls show them."""
    from core.envfile import env_flag
    return env_flag("ATLAS_IOC_SIGHTINGS") or _echo_free_on()


def file_holds(path: str | os.PathLike, terms: list[str]) -> set[str]:
    """The terms whose literal text the file holds, read as bytes in UTF-8
    and UTF-16LE, case-insensitive for ASCII letters. Cached per file state
    (real path, size, mtime) and term for the process, so a refresh every
    turn reads a file again only for a term it was not yet asked about."""
    try:
        st = os.stat(path)
    except OSError:
        return set()
    key = (os.path.realpath(path), st.st_size, st.st_mtime_ns)
    known = _FILE_TERMS.setdefault(key, {})
    todo = [t for t in dict.fromkeys(terms) if t not in known]
    if todo:
        forms = {t: (t.encode("utf-8"), t.encode("utf-16-le")) for t in todo}
        keep = max(len(b) for pair in forms.values() for b in pair) - 1
        found: set[str] = set()
        tail = b""
        try:
            with open(path, "rb") as fh:
                while len(found) < len(todo):
                    chunk = fh.read(_SCAN_CHUNK)
                    if not chunk:
                        break
                    buf = tail + chunk.lower()
                    for t, pair in forms.items():
                        if t not in found and (pair[0] in buf or pair[1] in buf):
                            found.add(t)
                    tail = buf[-keep:] if keep > 0 else b""
        except OSError:
            return {t for t in terms if known.get(t)}
        for t in todo:
            known[t] = t in found
    return {t for t in terms if known.get(t)}


def _entry_tool(entry: dict) -> str:
    cmd = str(entry.get("cmd") or "")
    first = cmd.split(None, 1)[0] if cmd.strip() else ""
    return first.removeprefix("<py>:").rsplit("/", 1)[-1][:60]


def _echoed_text(entry: dict, raw: str) -> str:
    """The request as the result itself restates it: the fields under the
    echo keys and the search alternatives of a parsed result, or the head
    of a cut one. A value standing there was named by the call."""
    import json
    s = raw.lstrip()
    if not s.startswith("{"):
        return ""
    try:
        data = json.loads(s)
    except ValueError:
        return s[:_first_container(s)]
    if not isinstance(data, dict):
        return ""
    keys = _argument_keys(entry) | {"alternatives"}
    echo = {k: v for k, v in data.items() if k in keys}
    return json.dumps(echo, ensure_ascii=False, default=str) if echo else ""


def _search_terms(entry: dict, inherited: frozenset[str]) -> frozenset[str]:
    """What the call searched for: its request strings and those inherited
    through its derived inputs, without the path tokens of its command (a
    value inside the path of the file a call read is the file's name)."""
    from core.provenance import path_tokens
    paths = {p.casefold() for p in path_tokens(entry)}
    return frozenset(s for s in (request_strings(entry) | inherited) if s not in paths)


def _row_carries_more(row: Any, headers: list[str], value: str, terms: frozenset[str]) -> bool:
    """The row states a moment (in its time columns or its text, in any form
    the timestamp parser reads), or with the value and every search term
    removed still holds a discriminative entity: a log line, a table row, a
    match with a path around it. A program printing its argument, a bare
    echo line and a ``<value> 0`` row fail."""
    from core.entities import discriminative, extract
    if _row_moment(row, headers):
        return True
    rest = _row_text(row)
    for term in sorted({value.lower(), *terms}, key=len, reverse=True):
        if term:
            rest = rest.replace(term, " ")
    return bool(discriminative(extract(rest)))


def _row_cells(row: Any, headers: list[str]) -> tuple[list[str], list[str]]:
    """``(headers, cells)`` of a row object: a mapping's keys and values, a
    list with the table's header, a text line with neither."""
    if isinstance(row, dict):
        return [str(k) for k in row], ["" if v is None else str(v) for v in row.values()]
    if isinstance(row, (list, tuple)):
        return list(headers), ["" if v is None else str(v) for v in row]
    return [], []


def _row_moment(row: Any, headers: list[str]) -> str:
    """The moment a row states, as "YYYY-MM-DD HH:MM:SS", or ""."""
    from core.evidence_index import _parse_timestamp
    from core.table_rows import row_time, time_columns
    hdrs, cells = _row_cells(row, headers)
    iso = ""
    if hdrs:
        cols = time_columns(hdrs, [cells])
        if cols:
            iso = row_time(cells, cols)
    if not iso:
        iso = _parse_timestamp(_row_text(row)) or ""
    return iso.replace("T", " ")[:19] if iso else ""


def _row_host(row: Any, headers: list[str], hosts: list[str]) -> str:
    """The case host a row names in its host column, else anywhere in it."""
    from core.forensic_citation import host_mentioned
    hdrs, cells = _row_cells(row, headers)
    candidates = [c for h, c in zip(hdrs, cells) if _clean_header(h) in _HOST_COLUMNS and c]
    for text in candidates or [_row_text(row)]:
        for label in sorted(hosts, key=len, reverse=True):
            if host_mentioned(label, text):
                return label
    return ""


def _clean_header(header: str) -> str:
    return str(header or "").lstrip("\ufeff").strip().lower()


def _case_hosts(case_dir: str | os.PathLike | None) -> list[str]:
    if not case_dir:
        return []
    try:
        from core.forensic_citation import known_case_hosts
        return known_case_hosts(case_dir)
    except Exception:  # noqa: BLE001
        return []


def _sighting(kind: str, value: str, cid: int, entry: dict, *, cited: bool, claim_host: str,
              case_dir: str | os.PathLike | None, text: str | None = None) -> dict[str, Any] | None:
    """The sighting of ``value`` in the output of one call, or None when the
    call shows it nowhere: a call of class own shows nothing; a call that
    named the value (its request, an inherited request, its own echo fields)
    shows it only in a row that carries more than the value."""
    from core.provenance import call_provenance
    prov = call_provenance(entry, case_dir)
    if prov["class"] == "own":
        return None
    raw = _output_text(entry, SPILL_READ_CHARS) if text is None else text
    rows, headers = _rows_of(entry, raw)
    showing = [r for r in rows if _found(kind, value, _row_text(r))]
    if not showing:
        return None
    terms = _search_terms(entry, prov["inherited"])
    named = (any(_found(kind, value, t) for t in terms)
             or _found(kind, value, _echoed_text(entry, raw).lower()))
    if named:
        showing = [r for r in showing if _row_carries_more(r, headers, value, terms)]
        if not showing:
            return None
    hosts = _case_hosts(case_dir)
    moments = [m for m in (_row_moment(r, headers) for r in showing) if m]
    host = next((h for h in (_row_host(r, headers, hosts) for r in showing) if h), "")
    if not host and prov["hosts"]:
        host = sorted(prov["hosts"])[0]
    if not host and claim_host and prov["class"] in ("evidence", "derived"):
        host = claim_host
    return {"call": int(cid), "tool": _entry_tool(entry), "host": host, "cited": cited,
            "located": bool(host) or prov["class"] in ("evidence", "derived"),
            "first": min(moments) if moments else "", "last": max(moments) if moments else "",
            "rows": len(showing)}


def _evidence_calls(by: dict[int, dict]) -> list[tuple[int, dict]]:
    """Every call of the run whose output is evidence, ran, and is not a
    count entry (whose rows are totals, not records)."""
    from core.forensic_citation import citation_class
    out = []
    for cid, e in by.items():
        if (isinstance(e, dict) and e.get("type") == "tool_call" and e.get("success") is not False
                and str(e.get("kind") or "") != "count" and citation_class(e) == "evidence"):
            out.append((int(cid), e))
    return out


def sightings(kind: str, value: str, cited_ids: Iterable[int], *, claim_host: str = "",
              case_dir: str | os.PathLike | None = None, limit: int = 8) -> list[dict[str, Any]]:
    """Where the evidence shows ``value``: the cited evidence calls first,
    then every other evidence call of the run through the index (the
    finding host's calls queried first), then the spills the index does not
    hold, by bytes. Each sighting names the call, its tool, the host behind
    it, whether the finding cited the call, whether it is located (a host or
    an evidence path stands behind it), the first and last moment of its
    showing rows and their count. Stops at ``limit`` confirmed sightings;
    hosts not yet covered are confirmed before a second sighting on one."""
    try:
        from core.execution_log import log
        by = log.index().by_call_id or {}
    except Exception:  # noqa: BLE001
        by = {}
    out: list[dict[str, Any]] = []
    done: set[int] = set()
    # A call cited twice (a merged twin's ids, a re-cited call) is one sighting.
    cited = list(dict.fromkeys(int(c) for c in cited_ids if str(c).strip().lstrip("-").isdigit()))
    for cid, entry in _evidence_entries(cited):
        if cid in done:
            continue
        done.add(cid)
        s = _sighting(kind, value, cid, entry, cited=True, claim_host=claim_host, case_dir=case_dir)
        if s:
            out.append(s)
    others = [(cid, e) for cid, e in _evidence_calls(by) if cid not in done]
    if not others or len(out) >= limit:
        return out[:limit]
    from core.forensic_citation import host_mentioned
    if claim_host:
        others.sort(key=lambda ce: not host_mentioned(
            claim_host, " ".join(str(ce[1].get(k) or "") for k in ("evidence_ref", "cmd", "args"))))
    ids = [cid for cid, _e in others]
    hits: list[tuple[int, str]] = []
    try:
        from core.evidence_index import find_in_calls
        hits = find_in_calls(_query_core(kind, value), ids)
    except Exception:  # noqa: BLE001
        hits = []

    def covered() -> set[str]:
        return {s["host"] for s in out if s["host"]}

    def take(cid: int, entry: dict, text: str | None) -> None:
        if cid in done or len(out) >= limit:
            return
        s = _sighting(kind, value, cid, entry, cited=False, claim_host=claim_host, case_dir=case_dir, text=text)
        if s is None:
            return
        done.add(cid)
        if len(out) >= limit:
            return
        # A host the list does not cover yet is worth more than a second
        # sighting on one it does.
        if s["host"] and s["host"] in covered() and len(out) >= limit - 1:
            return
        out.append(s)

    for cid, window in hits:
        if cid in by:
            take(cid, by[cid], window)
    if len(out) >= limit:
        return out
    # The unindexed tail: calls whose spill the index does not hold, or
    # holds only in part, scanned by bytes and confirmed on the rows.
    try:
        from core.evidence_index import MAX_INDEXED_BYTES, indexed_call_ids
        indexed = indexed_call_ids()
    except Exception:  # noqa: BLE001
        indexed, MAX_INDEXED_BYTES = set(), 0
    term = _query_core(kind, value).lower()
    for cid, entry in others:
        if cid in done or len(out) >= limit:
            continue
        spill = str(entry.get("stdout_file") or "")
        if not spill:
            if cid not in indexed:
                take(cid, entry, None)
            continue
        try:
            size = os.stat(spill).st_size
        except OSError:
            continue
        if cid in indexed and size <= MAX_INDEXED_BYTES:
            continue
        if term and file_holds(spill, [term]):
            take(cid, entry, None)
    return out


def seen_text(row: dict[str, Any]) -> str:
    """One line saying where a kept row was seen, for the tool result:
    "call 412 on CORP-WS05, 2031-03-01 08:12 to 2031-03-09 17:40 (37 rows);
    call 518 on CORP-WS01 (not cited by this finding)"."""
    parts = []
    for s in row.get("sightings") or []:
        bit = f"call {s.get('call')}"
        if s.get("host"):
            bit += f" on {s['host']}"
        if s.get("first"):
            span = s["first"][:16]
            if s.get("last") and s["last"] != s["first"]:
                span += f" to {s['last'][:16]}"
            bit += f", {span}"
        if s.get("rows"):
            bit += f" ({s['rows']} row{'s' if s['rows'] != 1 else ''})"
        if not s.get("cited"):
            bit += " (not cited by this finding)"
        if not s.get("located"):
            bit += " (location unresolved)"
        parts.append(bit)
    return "; ".join(parts)


def refresh_sightings(case_dir: str | os.PathLike | None, *, per_turn: int | None = 8) -> int:
    """Check the typed rows recorded before sightings existed (no
    ``sightings`` key) against the evidence and store what was found, up to
    ``per_turn`` rows a call (a pacing bound for the backfill of an old
    state over a few turns, not a cap: the report-time pass passes None and
    finishes). Returns the number of rows checked. Never raises."""
    if not case_dir or not _sightings_on():
        return 0
    try:
        from core.claim_graph import is_current_belief, load_graph, set_claim_indicators
        graph = load_graph(case_dir)
    except Exception:  # noqa: BLE001
        return 0
    checked = 0
    for node_id, node in list((graph.get("nodes") or {}).items()):
        if per_turn is not None and checked >= per_turn:
            break
        if not isinstance(node, dict) or node.get("kind") not in ("claim", "conclusion") \
                or not is_current_belief(node):
            continue
        legacy = [r for r in (node.get("indicators") or [])
                  if isinstance(r, dict) and r.get("type") and r.get("value") and "sightings" not in r]
        if not legacy:
            continue
        cited = [int(node["source_finding_call_id"])] if node.get("source_finding_call_id") else []
        cited += [int(c) for c in (node.get("input_call_ids") or []) if c]
        updated = []
        for row in legacy:
            if per_turn is not None and checked >= per_turn:
                break
            try:
                found = sightings(row["type"], row["value"], cited, claim_host=str(node.get("host") or ""),
                                  case_dir=case_dir)
            except Exception:  # noqa: BLE001
                continue
            new = dict(row)
            _apply_sightings(new, found)
            updated.append(new)
            checked += 1
        if updated:
            try:
                set_claim_indicators(case_dir, node_id, updated)
            except Exception:  # noqa: BLE001
                pass
    try:
        _refresh_named_values(case_dir, graph)
    except Exception:  # noqa: BLE001 - the cache is a convenience; build_catalog reads what is there
        pass
    return checked


PROSE_SIGHTINGS_FILE = ".atlas/prose_sightings.json"


def sighted_catalog_on() -> bool:
    """ATLAS_IOC_SIGHTED_CATALOG (default on): the indicator lists keep a
    value where a tool output that read evidence shows it; what is only
    named (in prose, a step, the brief, the threat context) is context."""
    from core.envfile import env_flag
    return env_flag("ATLAS_IOC_SIGHTED_CATALOG")


def load_named_sightings(case_dir: str | os.PathLike | None) -> dict[str, list[dict[str, Any]]]:
    """``{"type|value": [sightings]}`` for the values named without a typed
    row (prose candidates, recommendation steps, the brief, the threat
    context), as refresh_sightings last checked them. A value absent from
    the map is unchecked. A plain file read: build_catalog never writes it."""
    if not case_dir:
        return {}
    try:
        import json
        data = json.loads((Path(case_dir) / PROSE_SIGHTINGS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    values = data.get("values") if isinstance(data, dict) else None
    return values if isinstance(values, dict) else {}


def named_key(kind: str, value: str) -> str:
    return f"{kind}|{str(value).lower()}"


def named_values(case_dir: str | os.PathLike, graph: dict[str, Any]) -> dict[str, tuple[str, str]]:
    """``named_key -> (type, value)`` for every value named without a typed
    row: the prose candidates of current beliefs and recommendation steps,
    the typed rows refused at record time because no call showed them (a
    later call may), the brief's indicators and the active threat-context
    rows."""
    from core.ioc_catalog import _candidates, _normalize_statement, adversary_tool_terms
    terms = adversary_tool_terms()
    out: dict[str, tuple[str, str]] = {}
    for node in (graph.get("nodes") or {}).values():
        if not isinstance(node, dict) or node.get("status") in ("superseded", "withdrawn") \
                or node.get("kind") == "observation":
            continue
        for kind, value in _candidates(_normalize_statement(str(node.get("statement") or "")), terms):
            out.setdefault(named_key(kind, value), (kind, value))
        if node.get("kind") in ("claim", "conclusion"):
            for d in node.get("indicators_dropped") or []:
                if isinstance(d, dict) and d.get("refusal") == "presence" and d.get("type") and d.get("value"):
                    out.setdefault(named_key(str(d["type"]), str(d["value"])), (str(d["type"]), str(d["value"])))
    for kind, value in brief_values(case_dir) + threat_values(case_dir):
        out.setdefault(named_key(kind, value), (kind, value))
    return out


_ENTITY_CATEGORY = {"host": "domain", "md5": "hash", "sha1": "hash", "sha256": "hash", "reg": "registry"}


def brief_values(case_dir: str | os.PathLike) -> list[tuple[str, str]]:
    """The brief's indicators as (type, value) (core.case_knowledge)."""
    try:
        from core.case_knowledge import prior_indicators
        keys = prior_indicators(case_dir)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for key in keys:
        kind, _, value = str(key).partition(":")
        if value:
            out.append((_ENTITY_CATEGORY.get(kind, kind), value))
    return out


def threat_values(case_dir: str | os.PathLike) -> list[tuple[str, str]]:
    """The active threat-context rows as (type, value) (core.threat_context)."""
    try:
        from core.threat_context import active_rows
        return [(str(r.get("type") or ""), str(r.get("value") or "")) for r in active_rows(case_dir)
                if r.get("type") and r.get("value")]
    except Exception:  # noqa: BLE001
        return []


def _refresh_named_values(case_dir: str | os.PathLike, graph: dict[str, Any]) -> None:
    """Check the values named without a typed row against the evidence and
    write ``.atlas/prose_sightings.json``: values not yet checked, and the
    values checked earlier with no sighting whenever the index gained
    sources since (a value a later call shows becomes reviewable on the next
    turn, not only at report time). Index-backed, so cheap per value."""
    if not sighted_catalog_on():
        return
    import json
    path = Path(case_dir) / PROSE_SIGHTINGS_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    values: dict[str, list] = dict(data.get("values") or {}) if isinstance(data, dict) else {}
    try:
        from core.evidence_index import stats
        sources = int(stats().get("sources") or 0)
    except Exception:  # noqa: BLE001
        sources = 0
    grown = sources != int((data or {}).get("index_sources") or 0)
    changed = False
    for key, (kind, value) in named_values(case_dir, graph).items():
        if key in values and (values[key] or not grown):
            continue
        try:
            found = sightings(kind, value, [], case_dir=case_dir)
        except Exception:  # noqa: BLE001
            continue
        values[key] = found
        changed = True
    if changed or grown:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"index_sources": sources, "values": values}, default=str), encoding="utf-8")
        os.replace(tmp, path)


def _check_attacker_from(row: dict[str, Any], texts: list[str]) -> None:
    """attacker_from stands only when an output of the cited or sighting
    calls shows that moment, like first_seen; else it is dropped with a
    note. Never replaced by a sighting's time: it says when the attacker
    acted, not when the value appears."""
    canon = _timestamp_present(row["attacker_from"], texts)
    if canon:
        row["attacker_from"] = canon
    else:
        row["attacker_from_note"] = "not shown by the cited outputs; dropped"
        del row["attacker_from"]


def _apply_sightings(row: dict[str, Any], found: list[dict[str, Any]]) -> None:
    """Store the sightings on a row with the dates they give: the minimum
    and maximum over the dated sightings (``seen_basis: "sightings"``); a
    stated time stands only when no sighting carries one."""
    row["sightings"] = found
    dated = [s for s in found if s.get("first")]
    if dated:
        row["first_seen"] = min(s["first"] for s in dated)
        row["last_seen"] = max(s.get("last") or s["first"] for s in dated)
        row["seen_basis"] = "sightings"
    elif found:
        row["seen_basis"] = "stated" if (row.get("first_seen") or row.get("last_seen")) else "none"
    else:
        row["seen_basis"] = "none"


def _query_core(kind: str, value: str) -> str:
    if kind in ("path", "registry"):
        # one window must hold the whole query: the last component alone
        parts = [p for p in _norm_path(value.lower()).split("/") if p]
        return parts[-1] if parts else value
    if kind == "url":
        plain = refang(value.lower()).split("://", 1)[-1]
        return plain.split("?")[0]
    if kind == "account":
        return value.split("\\")[-1].split("@")[0]
    return value


def _in_index(kind: str, value: str, call_ids: list[int]) -> bool:
    """The full-output index, restricted to the cited calls, confirmed on
    the window text after the same normalisation."""
    try:
        from core.evidence_index import find_in_calls
        from core.execution_log import log
        hits = find_in_calls(_query_core(kind, value), call_ids)
        by = log.index().by_call_id or {}
    except Exception:  # noqa: BLE001
        return False
    return any(_found(kind, value, printed_text(by.get(cid) or {}, text=text)) for cid, text in hits)


def _timestamp_present(stamp: str, texts: list[str]) -> str:
    """The stamp in its canonical form when a cited output shows it in any
    of its forms, else ``""``."""
    try:
        from core.forensic_citation import normalize_timestamp
    except Exception:  # noqa: BLE001
        return ""
    canon = normalize_timestamp(stamp)
    if not canon:
        return ""
    date, _, rest = canon.partition(" ")
    clock = rest.split(" ")[0]
    forms = {f"{date} {clock}", f"{date}t{clock}", f"{date}/{clock}"}
    forms |= {f.replace("-", "/") for f in list(forms)}
    if clock.endswith(":00"):
        forms |= {f[:-3] for f in list(forms)}
    for t in texts:
        low = t.lower()
        if any(f in low for f in forms):
            return canon
    return ""


# The lengths of an MD5, a SHA-1 and a SHA-256 in hex: universal knowledge,
# the same three the hash type accepts.
_DIGEST_LENGTHS = (32, 40, 64)
_HEX_RUN_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{32,64}(?![0-9a-f])")


def within_edits(a: str, b: str, k: int = 2) -> int | None:
    """The edit distance between ``a`` and ``b`` when it is at most ``k``,
    else None (bounded Levenshtein: a row whose minimum passes ``k`` ends it)."""
    if abs(len(a) - len(b)) > k:
        return None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        if min(cur) > k:
            return None
        prev = cur
    return prev[-1] if prev[-1] <= k else None


def _near_digest(value: str, texts: list[str]) -> tuple[str, int] | None:
    """The one digest in the cited outputs that a typed hash is a slip of: a
    32/40/64-hex run within two edits of it that shares its first or last
    eight characters. Hashes only: two real digests are never that close,
    two addresses or names often are. None for no candidate or several.
    A candidate is a regex-checked run of hex digits, so naming it in a
    reason the model reads carries no text from the evidence beyond it.
    ponytail: only the outputs as read for presence (the spill read up to
    SPILL_READ_CHARS); a digest further into a spill is not suggested."""
    v = value.lower()
    if not re.fullmatch(r"[0-9a-f]{30,66}", v):
        return None
    found: dict[str, int] = {}
    for text in texts:
        for m in _HEX_RUN_RE.finditer(text.lower()):
            run = m.group(0)
            if (len(run) not in _DIGEST_LENGTHS or run == v or run in found
                    or (run[:8] != v[:8] and run[-8:] != v[-8:])):
                continue
            distance = within_edits(v, run)
            if distance is not None:
                found[run] = distance
                if len(found) > 1:
                    return None
    return next(iter(found.items())) if len(found) == 1 else None


def _dropped(kind: Any, value: Any, reason: str, texts: list[str] | None,
             refusal: str) -> dict[str, str]:
    """A refused row as it is kept and shown: its canonical type, the value
    on one line without the quotes around it (at most 80 characters), the
    reason, why it was refused (``refusal``: "shape", a value of no such
    type, or "presence", a value its cited calls do not show), and for a
    hash the digest in the cited output it is a slip of."""
    out = {"type": canonical_type(kind)[:24],
           "value": " ".join(str(value or "").split()).strip("`'\" ")[:80],
           "reason": reason[:240], "refusal": refusal}
    if out["type"] == "hash" and texts:
        near = _near_digest(out["value"], texts)
        if near:
            out["suggested"] = near[0]
            out["reason"] += (f"; the cited output shows {near[0]}, {near[1]} character(s) "
                              "apart: type that value")
    return out


def _shown_by_cited(row: dict[str, Any], ids: list[int], texts: list[str]) -> str:
    """The presence rule before sightings: the value in the cited outputs
    (spill read up to SPILL_READ_CHARS, then the index) or the reason it is
    not. Kept as the path ATLAS_IOC_SIGHTINGS off restores."""
    if not ids:
        return ("the finding cites no evidence call whose output could show it (reasoning, "
                "claim and correlation calls are the analyst's own words)")
    if not any(_found(row["type"], row["value"], t) for t in texts) and not _in_index(row["type"], row["value"], ids):
        return (f"not in the output of the cited calls {ids[:8]} (spill read up to "
                f"{SPILL_READ_CHARS:,} characters, index up to {INDEXED_CHARS:,}); cite the call that shows it")
    return ""


def validate(rows: Iterable[Any], *, call_ids: Iterable[int], case_dir: str | os.PathLike | None,
             frame: str = "incident", host: str = "") -> dict[str, Any]:
    """Every row checked in order: shape, a sighting (where a tool output of
    this case that read evidence shows the value: the cited calls first,
    then any other call), the dates the sightings give or the stated ones,
    own-asset re-siding. Returns ``kept`` (each row with its ``sightings``
    and ``seen_basis``), ``dropped`` (with reasons) and ``resided`` (the
    rows whose side the own-asset set changed). ``host`` is the finding's
    host, the fallback host of a sighting in evidence whose rows name none.
    With ATLAS_IOC_SIGHTINGS off the cited outputs alone decide."""
    evidence = _evidence_entries(call_ids)
    ids = [cid for cid, _e in evidence]
    texts = [printed_text(e) for _cid, e in evidence]
    by_sightings = _sightings_on()
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, str]] = []
    resided: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    assets = None
    subject_ids: set[str] | None = None

    def own_asset(row: dict[str, Any]) -> dict[str, Any] | None:
        nonlocal assets
        if case_dir is None:
            return None
        if assets is None:
            try:
                from core.own_assets import own_assets
                assets = own_assets(case_dir)
            except Exception:  # noqa: BLE001
                assets = {"values": {}, "hosts": []}
        return _own(assets, row)
    for raw in rows or []:
        row, why = normalize_row(raw)
        if row is None:
            given = raw if isinstance(raw, dict) else {"value": raw}
            dropped.append(_dropped(given.get("type"), given.get("value"), why, texts, "shape"))
            continue
        key = (row["type"], row["value"].lower())
        if key in seen:
            continue
        seen.add(key)
        if by_sightings:
            found = sightings(row["type"], row["value"], ids, claim_host=host, case_dir=case_dir)
            if not found:
                d = _dropped(row["type"], row["value"], DROP_REASON_NO_SIGHTING, texts, "presence")
                if row.get("side"):
                    d["side"] = str(row["side"])[:24]      # the stated role, kept for a later sighting
                    if d["side"] == "attacker" and own_asset(row):
                        d["side"] = _own_side(frame)
                dropped.append(d)
                continue
            stated = {k: row[k] for k in ("first_seen", "last_seen") if row.get(k)}
            _apply_sightings(row, found)
            if row.get("attacker_from"):
                _check_attacker_from(row, texts + [printed_text(e) for cid, e in _evidence_entries(
                    [s["call"] for s in found]) if cid not in ids])
            if row["seen_basis"] != "sightings":
                shown_texts = texts + [printed_text(e) for cid, e in _evidence_entries(
                    [s["call"] for s in found]) if cid not in ids]
                for key_, stamp in stated.items():
                    canon = _timestamp_present(stamp, shown_texts)
                    if canon:
                        row[key_] = canon
                    else:
                        row[f"{key_}_note"] = "not shown by the outputs that show the value; dropped"
                        del row[key_]
                if not any(row.get(k) for k in ("first_seen", "last_seen")):
                    row["seen_basis"] = "none"
        else:
            reason = _shown_by_cited(row, ids, texts)
            if reason:
                dropped.append(_dropped(row["type"], row["value"], reason, texts if ids else None, "presence"))
                continue
            for key_ in ("first_seen", "last_seen"):
                if row.get(key_):
                    canon = _timestamp_present(row[key_], texts)
                    if canon:
                        row[key_] = canon
                    else:
                        row[f"{key_}_note"] = "not shown by the cited outputs; dropped"
                        del row[key_]
            if row.get("attacker_from"):
                _check_attacker_from(row, texts)
        if case_dir is not None:
            hit = own_asset(row)
            if hit and row["side"] == "attacker":
                new_side = _own_side(frame)
                if new_side == UNDETERMINED:
                    # No owner named: an asset the brief lists is nobody's
                    # side here, and a stated attacker on it is not taken.
                    row["side"] = new_side
                    row["note"] = (f"stated attacker, matches an asset the brief lists "
                                   f"({hit.get('host') or hit.get('value')}); no owner is named, so no side is taken")
                else:
                    row["side"], row["compromised"] = new_side, True
                    row["note"] = f"stated attacker, matches own asset {hit.get('host') or hit.get('value')}"
                resided.append(dict(row))
            elif hit and row["side"] not in ("subject",):
                row["own_asset"] = True
            if row["side"] == "attacker":
                # An insider on the owner's system: a value the brief gives
                # for the subject is the subject's whatever the analyst said.
                if subject_ids is None:
                    from core.case_config import get_subject_identifiers
                    subject_ids = get_subject_identifiers(case_dir)
                if _subject_value(row, subject_ids):
                    row["side"] = "subject"
                    row["note"] = "stated attacker, is an identifier the brief gives for the subject"
                    resided.append(dict(row))
        kept.append(row)
    return {"kept": kept, "dropped": dropped, "resided": resided}


def _subject_value(row: dict[str, Any], ids: set[str]) -> bool:
    """Whether the row's value is one the brief gives for the subject: the
    value itself, or an account's bare name."""
    if not ids:
        return False
    v = str(row.get("value") or "").casefold()
    if v in ids:
        return True
    return row.get("type") == "account" and v.split("\\")[-1].split("@")[0] in ids


def _own(assets: dict[str, Any], row: dict[str, Any]) -> dict[str, Any] | None:
    try:
        from core.own_assets import lookup
    except Exception:  # noqa: BLE001
        return None
    kind = row["type"] if row["type"] in ("ip", "host", "domain", "account", "serial") else ""
    if row["type"] in ("url", "email"):
        host = refang(row["value"]).split("://")[-1].split("/")[0].split("@")[-1].split(":")[0]
        return lookup(assets, host, "host") or lookup(assets, host, "domain")
    return lookup(assets, row["value"], kind) if kind else None


# ── frame and use ───────────────────────────────────────────────────────

def frame_for(case_dir: str | os.PathLike | None) -> str:
    """The engagement frame, from what the brief states: subject when the
    device belongs to the person under investigation, or when the brief
    states no owner and names a subject (its Subject row); incident when
    the owner is the victim; neutral otherwise. Neutral assumes no side:
    the rows are what the evidence shows, sided only where a finding's own
    basis states the side (the frame is never read from the
    brief's wording). A victim-owned device stays an incident whatever else
    the brief names: its owner still owes remediation, and an insider on it
    is sided as the subject at record time."""
    try:
        from core.case_config import get_system_owner, names_subject
        owner = get_system_owner(case_dir) if case_dir else "unknown"
        if owner == "suspect":
            return "subject"
        if owner == "victim":
            return "incident"
        return "subject" if names_subject(case_dir) else "neutral"
    except Exception:  # noqa: BLE001
        return "neutral"


def _own_side(frame: str) -> str:
    """The side of an asset the brief lists: the subject's in the subject
    frame, the victim's in the incident frame, nobody's (undetermined) in
    the neutral frame."""
    return {"subject": "subject", "incident": "victim"}.get(frame, UNDETERMINED)


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in _INTERNAL_NETS)


def _never_block(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in _NEVER_BLOCK_NETS)


def shared_mark(kind: str, value: str) -> dict[str, str] | None:
    """The published shared-infrastructure mark of a value
    (core.shared_infrastructure.mark): a shared edge, a vendor service or a
    popular name; None when unmarked or the switch is off."""
    try:
        from core.shared_infrastructure import mark
        return mark(kind, refang(value) if kind in ("ip", "domain", "url", "email") else value)
    except Exception:  # noqa: BLE001
        return None


def use_for(frame: str, side: str, kind: str, value: str = "") -> list[str]:
    """What a responder does with a row: the use-label table, review for
    every combination it does not name. In the subject frame a value held
    by a provider keeps its request beside any identify use; in the
    incident frame a private address is contained, never blocked at the
    perimeter, and an unspecified, multicast or reserved address is never
    a block item."""
    if side == UNDETERMINED:
        return ["review"]      # whose it is is not stated: listed, no use yet
    low = (value or "").lower()
    at_provider = kind in ("cloud_resource", "credential_id", "email") or (kind == "account" and "@" in low)
    if frame == "subject":
        uses: list[str] = []
        if kind in ("hash", "file") and side != "victim":
            uses.append("hunt")
        elif side in ("subject", "victim", "attacker") or (
                side == "third_party" and kind in ("email", "account", "ip", "domain", "mac")):
            uses.append("identify")
        if at_provider:
            uses.append("request")
        return uses or ["review"]
    if side == "attacker":
        # A published shared edge or a vendor's own service name serves
        # every site or tenant behind it: hunted, never blocked; the name the
        # attacker used (the tenant, the path, the account) is the block
        # item (core.shared_infrastructure, ATLAS_IOC_SHARED_EDGE). The same
        # class of rule as the private-address and never-block rules below.
        mark = shared_mark(kind, value) if kind in ("ip", "domain", "url", "email") else None
        if kind == "ip":
            if _never_block(value):
                return ["review"]
            if is_private_ip(value):
                return ["hunt", "scope"]
            return ["hunt"] if mark and mark["mark"] == "shared_edge" else ["block"]
        if kind in ("domain", "url", "email"):
            host = refang(low).split("://")[-1].split("/")[0].split("@")[-1]
            if host.rstrip(".").endswith(".onion"):
                return ["hunt"]
            return ["hunt"] if mark and mark["mark"] == "vendor_service" else ["block"]
        if kind in ("file", "path", "hash", "registry", "service", "task", "pattern", "host", "mac", "serial"):
            return ["hunt"]
        if kind == "account":
            return ["contain", "hunt"]
        if kind == "cloud_resource":
            return ["request"]
        if kind == "credential_id":
            return ["hunt"]
        return ["review"]
    if side == "victim":
        return ["scope"]
    if side == "subject":
        # An insider on the owner's system: a value a provider holds is
        # identified and requested, a local account identified and contained.
        if at_provider:
            return ["identify", "request"]
        return ["identify", "contain"] if kind == "account" else ["identify"]
    if side == "third_party" and at_provider:
        return ["request"]   # made through counsel or law enforcement
    return ["review"]


def rows_of(node: dict[str, Any]) -> list[dict[str, Any]]:
    """The typed rows a claim node carries."""
    return [r for r in (node.get("indicators") or []) if isinstance(r, dict) and r.get("type") in TYPES]


# ── completeness: findings that should have yielded indicators ───────────

_INDICATOR_TACTICS = frozenset({"initial-access", "persistence", "command-and-control",
                                "exfiltration", "credential-access"})
_INDICATOR_CLASSES = frozenset({"malware", "exfiltration", "credential_compromise", "domain_compromise"})


def _tactics_of(technique_ids: Iterable[str]) -> set[str]:
    try:
        import json
        from pathlib import Path
        table = json.loads((Path(__file__).resolve().parents[1] / "share" / ".common" /
                            "mitre_techniques.json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return set()
    # The table nests its entries under "techniques" and states the tactics
    # as one comma-separated title-case string ("Initial Access, Persistence").
    entries = table.get("techniques") if isinstance(table, dict) and isinstance(table.get("techniques"), dict) else table
    out: set[str] = set()
    for tid in technique_ids:
        tid = str(tid).strip().upper()
        entry = (entries.get(tid) or entries.get(tid.split(".")[0])) if isinstance(entries, dict) else None
        tactic = (entry or {}).get("tactic") if isinstance(entry, dict) else None
        parts = tactic if isinstance(tactic, list) else str(tactic or "").split(",")
        for t in parts:
            t = str(t or "").strip()
            if t:
                out.add(t.lower().replace(" ", "-"))
    return out


def report_warning(case_dir: str | os.PathLike | None, finding_entries: list[dict]) -> str:
    """One advisory naming the substantiated findings whose techniques or
    wording describe initial access, persistence, command and control,
    exfiltration or credential access, yet which carry no typed indicator.
    Empty when every such finding has rows."""
    if not case_dir:
        return ""
    try:
        from core.claim_graph import load_graph
        from core.ir_playbook import classify
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        return ""
    missing: list[str] = []
    for e in finding_entries:
        if str(e.get("confidence") or "").upper() not in ("CONFIRMED", "LIKELY"):
            continue
        cid = str(e.get("claim_id") or "")
        node = nodes.get(cid) if cid else None
        if not isinstance(node, dict) or node.get("status") in ("superseded", "withdrawn"):
            continue
        if rows_of(node):
            continue
        techniques = ((e.get("gate_metadata") or {}).get("validated_techniques")
                      or e.get("mitre_techniques") or [])
        labels = sorted(_tactics_of(techniques) & _INDICATOR_TACTICS)
        labels += sorted(set(classify(str(e.get("description") or ""), asserted=True)) & _INDICATOR_CLASSES)
        if labels:
            missing.append(f"{cid} ({', '.join(labels[:3])})")
        if len(missing) >= 8:
            break
    if not missing:
        return ""
    return (f"{len(missing)} substantiated finding(s) describing initial access, persistence, "
            "command and control, exfiltration or credential access carry no typed indicator: "
            + "; ".join(missing) + ". The indicator list (block, hunt, scope and request items) is "
            "built from typed rows: call claim.add_indicators(claim_id, [{type, value, side}]) with each "
            "value taken from the finding's cited output.")


def dropped_warning(case_dir: str | os.PathLike | None) -> str:
    """One advisory naming the typed indicators of substantiated findings
    that were refused when recorded and are in no indicator list. Read from
    the catalog, so the advisory and the indicator file agree. Never a
    blocker: where the cited output does not show a value, its listing
    under "Not exported" is where it ends."""
    if not case_dir:
        return ""
    try:
        from core.ioc_catalog import build_catalog
        catalog = build_catalog(case_dir)
        rows = [r for r in list(catalog.get("not_exported") or []) + list(catalog.get("refused_presence") or [])
                if str(r.get("confidence") or "").upper() in ("CONFIRMED", "LIKELY")]
    except Exception:  # noqa: BLE001
        return ""
    sighted = bool(catalog.get("sighted"))
    if not rows:
        return ""

    def name(r: dict[str, Any], *, call: bool = False) -> str:
        value = str(r.get("value") or "")
        out = f"{(r.get('claim_ids') or ['?'])[0]} '{value[:24]}{'…' if len(value) > 24 else ''}'"
        if call and r.get("finding_call_ids"):
            out += f" (finding call {r['finding_call_ids'][0]})"
        if r.get("suggested"):
            out += f" (the cited output shows {r['suggested']})"
        return out

    # A value its cited calls do not show cannot be repaired on the claim:
    # claim.add_indicators checks the same calls again.
    malformed = [r for r in rows if r.get("refusal") != "presence"]
    unshown = [r for r in rows if r.get("refusal") == "presence"]
    parts = [f"{len(rows)} typed indicator(s) of substantiated findings were refused when "
             "recorded and are in no indicator list."]
    if malformed:
        parts.append("Malformed: " + "; ".join(name(r) for r in malformed[:8])
                     + ". Re-type each from the cited output with "
                     "claim.add_indicators(claim_id, [{type, value, side}]).")
    if unshown and sighted:
        # The sighted catalogue lists such a value as context: named, not
        # seen in this evidence.
        parts.append("No tool output of this run shows: "
                     + "; ".join(name(r, call=True) for r in unshown[:8])
                     + ". Each is listed as context (named but not seen); it moves to review when a "
                     "call shows it. To state its role, re-record the finding citing that call, with "
                     "supersedes=<its finding call>.")
    elif unshown:
        parts.append("Not shown by the finding's cited calls: "
                     + "; ".join(name(r, call=True) for r in unshown[:8])
                     + ". Re-record the finding citing the call that shows the value, with "
                     "supersedes=<its finding call>, or leave it out.")
    if sighted and unshown:
        parts.append("A value left as it is stays listed in the indicator file for the reader, "
                     "under 'Named but not seen' or 'Not exported'; nothing here blocks the report.")
    else:
        parts.append("A value left as it is stays listed under 'Not exported' in the indicator "
                     "file for the reader; nothing here blocks the report.")
    return " ".join(parts)
