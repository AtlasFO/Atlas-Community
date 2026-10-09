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
import re
from typing import Any, Iterable

TYPES = ("ip", "mac", "domain", "url", "email", "hash", "path", "file", "registry",
         "service", "task", "account", "host", "serial", "cloud_resource",
         "credential_id", "pattern")
SIDES = ("attacker", "victim", "subject", "third_party")
FRAMES = ("incident", "subject")
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
    if kind not in TYPES:
        return None, f"unknown type {kind!r} (one of {', '.join(TYPES)})"
    if side not in SIDES:
        return None, f"unknown side {side!r} (one of {', '.join(SIDES)})"
    if not value or len(value) > MAX_VALUE or "\n" in value:
        return None, "a value is one line of at most 300 characters"
    value, why = _shape(kind, value)
    if why:
        return None, why
    out = {"type": kind, "value": value, "side": side}
    for key in ("first_seen", "last_seen"):
        if row.get(key):
            out[key] = str(row[key]).strip()
    return out, ""


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
        if " " in value and kind != "file":
            return value, f"a {kind} has no spaces: {value!r}"
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
        return any(re.search(r"(?<![\d.])" + re.escape(f) + r"(?!\d|\.\d)", low) if ":" not in f
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


_ECHO_KEYS = ("query", "sanitized_query", "pattern", "patterns", "term", "terms", "keyword",
              "keywords", "search", "needle", "regex", "expression")


def _without_request_echo(text: str) -> str:
    """A search tool's JSON output repeats the request it was given; that
    echo shows nothing. The request keys are dropped, and an output that
    reports no result is read as empty."""
    stripped = text.strip()
    if not stripped.startswith("{"):
        return text
    try:
        import json
        data = json.loads(stripped)
    except ValueError:
        return text
    if not isinstance(data, dict):
        return text
    if data.get("result_count") == 0 or data.get("results") == [] or data.get("hits") == [] \
            or data.get("matches") == [] or data.get("count") == 0:
        return ""
    for key in _ECHO_KEYS:
        data.pop(key, None)
    return json.dumps(data)


def _printed_text(entry: dict) -> str:
    """What the tool printed: the stored excerpt and the spill, never the
    command line, which is the analyst's own text, and never the request a
    search tool echoes back."""
    from core.entities import scan_text
    parts = [scan_text(_without_request_echo(str(entry.get("stdout_excerpt") or "")))]
    sf = entry.get("stdout_file")
    if sf:
        try:
            with open(str(sf), encoding="utf-8", errors="replace") as fh:
                parts.append(scan_text(fh.read(SPILL_READ_CHARS)))
        except OSError:
            pass
    return " ".join(parts)


def _cited_texts(call_ids: Iterable[int]) -> list[str]:
    return [_printed_text(e) for _cid, e in _evidence_entries(call_ids)]


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
        from core.entities import scan_text
        from core.evidence_index import find_in_calls
        hits = find_in_calls(_query_core(kind, value), call_ids)
    except Exception:  # noqa: BLE001
        return False
    return any(_found(kind, value, scan_text(text)) for _cid, text in hits)


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


def validate(rows: Iterable[Any], *, call_ids: Iterable[int], case_dir: str | os.PathLike | None,
             frame: str = "incident") -> dict[str, Any]:
    """Every row checked in order: shape, presence in the cited outputs
    (spill read up to 500,000 characters, then the index), timestamps,
    own-asset re-siding. Returns ``kept``, ``dropped`` (with reasons) and
    ``resided`` (the rows whose side the own-asset set changed)."""
    evidence = _evidence_entries(call_ids)
    ids = [cid for cid, _e in evidence]
    texts = [_printed_text(e) for _cid, e in evidence]
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, str]] = []
    resided: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    assets = None
    subject_ids: set[str] | None = None
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
        if not ids:
            dropped.append(_dropped(row["type"], row["value"], (
                "the finding cites no evidence call whose output could show it (reasoning, "
                "claim and correlation calls are the analyst's own words)"), None, "presence"))
            continue
        if not any(_found(row["type"], row["value"], t) for t in texts) and not _in_index(row["type"], row["value"], ids):
            dropped.append(_dropped(row["type"], row["value"], (
                f"not in the output of the cited calls {ids[:8]} (spill read up to "
                f"{SPILL_READ_CHARS:,} characters, index up to {INDEXED_CHARS:,}); cite the call that shows it"),
                texts, "presence"))
            continue
        for key_ in ("first_seen", "last_seen"):
            if row.get(key_):
                canon = _timestamp_present(row[key_], texts)
                if canon:
                    row[key_] = canon
                else:
                    row[f"{key_}_note"] = "not shown by the cited outputs; dropped"
                    del row[key_]
        if case_dir is not None:
            if assets is None:
                try:
                    from core.own_assets import own_assets
                    assets = own_assets(case_dir)
                except Exception:  # noqa: BLE001
                    assets = {"values": {}, "hosts": []}
            hit = _own(assets, row)
            if hit and row["side"] == "attacker":
                new_side = "subject" if frame == "subject" else "victim"
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
    """The engagement frame: subject when the device belongs to the person
    under investigation, or when the brief states no owner (or an unknown
    one) and names a subject; incident otherwise. A victim-owned device
    stays an incident whatever else the brief names: its owner still owes
    remediation, and an insider on it is sided as the subject at record
    time."""
    try:
        from core.case_config import get_system_owner, names_subject
        owner = get_system_owner(case_dir) if case_dir else "unknown"
        if owner == "suspect":
            return "subject"
        if owner == "victim":
            return "incident"
        return "subject" if names_subject(case_dir) else "incident"
    except Exception:  # noqa: BLE001
        return "incident"


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


def use_for(frame: str, side: str, kind: str, value: str = "") -> list[str]:
    """What a responder does with a row: the use-label table, review for
    every combination it does not name. In the subject frame a value held
    by a provider keeps its request beside any identify use; in the
    incident frame a private address is contained, never blocked at the
    perimeter, and an unspecified, multicast or reserved address is never
    a block item."""
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
        if kind == "ip":
            if _never_block(value):
                return ["review"]
            return ["hunt", "scope"] if is_private_ip(value) else ["block"]
        if kind in ("domain", "url", "email"):
            host = refang(low).split("://")[-1].split("/")[0].split("@")[-1]
            return ["hunt"] if host.rstrip(".").endswith(".onion") else ["block"]
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
        rows = [r for r in build_catalog(case_dir).get("not_exported") or []
                if str(r.get("confidence") or "").upper() in ("CONFIRMED", "LIKELY")]
    except Exception:  # noqa: BLE001
        return ""
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
    if unshown:
        parts.append("Not shown by the finding's cited calls: "
                     + "; ".join(name(r, call=True) for r in unshown[:8])
                     + ". Re-record the finding citing the call that shows the value, with "
                     "supersedes=<its finding call>, or leave it out.")
    parts.append("A value left as it is stays listed under 'Not exported' in the indicator "
                 "file for the reader; nothing here blocks the report.")
    return " ".join(parts)
