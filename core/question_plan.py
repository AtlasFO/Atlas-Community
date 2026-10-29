"""The sources of the work order: the per-question plan with its
anchors, the source behind a question's index-only claims, absence
contradictions and the proposals the director adopts or keeps.

Nothing here maps a question to an artefact. The plan's reads are model
output; code restates what the question and the brief say (the anchors),
validates the reads against what exists (hosts, files, tools) and turns the
run's own provenance (the rows a claim rests on, a claim the index
contradicts) into reads owed.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

# Dates by their lexical shape: ISO, numeric with slashes, and month names
# (English) before or after the day. Universal date shapes, not case data.
_MONTHS = ("january|february|march|april|may|june|july|august|september|october|november|december|"
           "jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec")
_DATE_RE = re.compile(
    rf"\b\d{{4}}-\d{{2}}-\d{{2}}\b|\b\d{{1,2}}/\d{{1,2}}/\d{{2,4}}\b"
    rf"|\b(?:{_MONTHS})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}\b"
    rf"|\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:{_MONTHS})\.?,?\s+\d{{4}}\b", re.IGNORECASE)
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'(])|\n+")

PLAN_SYS = (
    "You plan the reads that answer one investigation question. You get the question, what the brief says about "
    "it, the evidence the case holds per host and the reading tools. Return 1 to 5 reads that would answer the "
    "question, the most direct first. Each read names one host, one source (a file in the case, or a path inside "
    "that host's image), one tool from the list, and why in under 15 words. Prefer the artefact that records the "
    "event over an index that mentions it. Start with sources that are already records or summaries and are quick "
    "to read; use them to find the first values and hosts, then go deeper where they point. Read a slow source when "
    "a quicker one cannot answer the question. "
    "A read of a timeline needs a search pattern; give a time window when "
    "the question or the brief gives one. Use only hosts, files and tools named below.\n"
    "Answer with JSON only: {\"reads\":[{\"host\":\"\",\"source\":\"\",\"tool\":\"\",\"pattern\":\"\","
    "\"window\":\"\",\"why\":\"\"}]}"
)


PLAN_LISTING_RULE = (
    " INSIDE THE IMAGES says what each host's image holds; LISTING shows the files at the places named for this "
    "question, and a read may name a handle from it (image::path) as its source. A listed file is not read until "
    "a read is planned for it.")

LOCATE_SYS = (
    "You locate where the records that answer one investigation question would be written on the case's hosts. "
    "You get the question, what the brief says, and what each host's disk image holds. Name up to four places: "
    "a host (or * for every host), a path glob inside its image with forward slashes and no drive letter (the "
    "form <folder>/<subfolder>/*.<ext>), and why in under 15 words.\n"
    "Answer with JSON only: {\"places\":[{\"host\":\"\",\"glob\":\"\",\"why\":\"\"}]}"
)


def plan_listing_on() -> bool:
    """C2 item 1 (ATLAS_PLAN_LISTING): the plan sees what each image holds
    and the files at the places a LOCATE call names."""
    from core.contents_index import index_on
    from core.envfile import env_flag
    return index_on() and env_flag("ATLAS_PLAN_LISTING", True)


def plan_view_rule() -> str:
    """The rule of the optional view per part (ATLAS_MAP_VIEWS): what a
    list part's rows range over, its columns from the incident map's own
    computations. The lists are the map's mechanism, no question shape."""
    from core.incident_map import EVENT_KINDS, IncidentMap, LABELS
    cols = IncidentMap.view_columns
    return (" A view is only for a part whose answer lists several rows, one per host, account, file, endpoint or "
            "event; a part that asks for one value (one time, one name, one count, yes or no) gets no view. Such a "
            "list part may name a view: the part "
            "id, what its rows range over (host, account, file, endpoint, or event:<kind> with kind one of "
            f"{', '.join(EVENT_KINDS)}), an optional where (label {', '.join(LABELS)}; host; after; before) and the "
            f"columns its answer needs. Host rows: {', '.join(cols('host'))}. Account, file and endpoint rows: "
            f"{', '.join(cols('file'))}. Event rows: {', '.join(cols('event:other'))}. The rows are "
            "filled from the recorded findings.")


def plan_system() -> str:
    """PLAN_SYS with the rules of the blocks the switches add."""
    text = PLAN_SYS
    if plan_listing_on():
        head, _, tail = text.partition("\nAnswer with JSON only:")
        text = head + PLAN_LISTING_RULE + "\nAnswer with JSON only:" + tail
    from core.incident_map import views_on
    if views_on():
        head, _, tail = text.partition("\nAnswer with JSON only:")
        tail = tail.rstrip()
        text = (head + plan_view_rule() + "\nAnswer with JSON only:" + tail[:-1]
                + ',"views":[{"part":"","over":"","where":{},"columns":[]}]}')
    return text


# ── anchors ───────────────────────────────────────────────────────────────

def _narrative(case_dir: str) -> list[tuple[str, str]]:
    from core.case_knowledge import narrative_sections
    from core.investigation_tasks import read_case_markdown
    try:
        return narrative_sections(read_case_markdown(case_dir))
    except Exception:  # noqa: BLE001
        return []


def dated_sentences(text: str) -> list[str]:
    """The sentences of ``text`` that carry a date, verbatim."""
    out = []
    for sent in _SENTENCE_RE.split(text or ""):
        sent = " ".join(sent.split())
        if sent and _DATE_RE.search(sent):
            out.append(sent)
    return out


def question_anchors(case_dir: str, task: dict) -> str:
    """The ANCHORS block: the case hosts the question and the brief's
    narrative name, the brief's parsed indicators by kind, and every dated
    sentence of the question or the narrative verbatim with where it stands.
    Offered, never imposed; code gives no date a meaning."""
    from core.forensic_citation import host_mentioned, known_case_hosts
    hosts = known_case_hosts(case_dir)
    question = " ".join([str(task.get("text") or "")]
                        + [str(p.get("text") or "") for p in task.get("parts") or [] if isinstance(p, dict)])
    narrative = _narrative(case_dir)
    brief_text = "\n".join(body for _h, body in narrative)
    in_q = [h for h in hosts if host_mentioned(h, question)]
    in_brief = [h for h in hosts if host_mentioned(h, brief_text)]
    lines = ["ANCHORS (from the question and the brief; use them to place the reads in hosts and time):",
             f"- hosts the question names: {', '.join(in_q) or 'none'}",
             f"- hosts the brief names: {', '.join(in_brief) or 'none'}"]
    try:
        from core.case_knowledge import read
        indicators = list((read(case_dir).get("indicators") or {}).keys())
    except Exception:  # noqa: BLE001
        indicators = []
    by_kind: dict[str, list[str]] = {}
    for ent in sorted(indicators):
        kind, _, value = str(ent).partition(":")
        by_kind.setdefault(kind, []).append(value)
    names = {"account": "accounts", "file": "files and paths", "path": "files and paths", "ip": "addresses",
             "domain": "domains", "url": "urls", "email": "e-mail addresses", "md5": "hashes", "sha1": "hashes",
             "sha256": "hashes"}
    merged: dict[str, list[str]] = {}
    for kind, values in by_kind.items():
        merged.setdefault(names.get(kind, kind), []).extend(values)
    for label, values in merged.items():
        lines.append(f"- {label} the brief names: {', '.join(values[:12])}")
    for sent in dated_sentences(question):
        lines.append(f'- dated sentence (question): "{sent[:300]}"')
    for heading, body in narrative:
        for sent in dated_sentences(body):
            lines.append(f'- dated sentence (brief, {heading or "head"}): "{sent[:300]}"')
    return "\n".join(lines)


# ── the plan ──────────────────────────────────────────────────────────────

def reading_tools() -> list[tuple[str, str]]:
    """The manifest's tools that read content or search, with their
    capability's purpose as the one line."""
    from core.work_order import is_reading_tool
    try:
        from tools.tool_capabilities import tool_capability_manifest
        caps = tool_capability_manifest().get("capabilities") or []
    except Exception:  # noqa: BLE001
        return []
    out: list[tuple[str, str]] = []
    for cap in caps:
        for t in cap.get("tools") or []:
            if is_reading_tool(t):
                out.append((t, str(cap.get("purpose") or "")[:100]))
    # Every registered reader of an input format, also those no manifest
    # capability lists (the registry is the source; the manifest only adds
    # a purpose line).
    try:
        from core.work_order import listed
        from tools.tool_capabilities import readers_by_format, registered_tool_schemas
        have = {listed(t) for t, _p in out}
        for label, readers in readers_by_format(registered_tool_schemas()).items():
            for r in readers:
                if listed(r) not in have and is_reading_tool(r):
                    out.append((r, f"reads {label}"[:100]))
                    have.add(listed(r))
    except Exception:  # noqa: BLE001
        pass
    return list(dict.fromkeys(out))


def host_files(case_dir: str) -> dict[str, list[str]]:
    """Per host, the evidence files the ledger lists whose path names it;
    "" holds the files no host label names."""
    from core.forensic_citation import host_mentioned, known_case_hosts
    hosts = known_case_hosts(case_dir)
    try:
        from core.coverage_ledger import load_ledger
        paths = sorted(str(u.get("path")) for u in (load_ledger(case_dir).get("units") or {}).values()
                       if isinstance(u, dict) and u.get("path"))
    except Exception:  # noqa: BLE001
        paths = []
    from core.evidence_links import host_of_path, host_of_path_on
    on = host_of_path_on()
    out: dict[str, list[str]] = {}
    for p in paths:
        owner = host_of_path(case_dir, p, hosts) if on else next((h for h in hosts if host_mentioned(h, p)), "")
        out.setdefault(owner, []).append(p)
    return out


# How many sources of one host the plan message names (a display bound
# per host, disclosed with the count it leaves out; containers are always
# named, so no image is hidden behind tables).
SOURCES_PER_HOST = 12


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def source_facts(case_dir: str) -> dict[str, dict]:
    """Per evidence path, what code knows of its form and cost: a parsed
    table's rows, time span and hosts (core.contents_index's exports), a
    container's kind (the ledger's items) and every file's size (stat).
    Properties of the evidence only, never a name."""
    from core.contents_index import export_facts
    tables = export_facts(case_dir)
    try:
        from core.coverage_ledger import load_ledger
        kinds = {str(i.get("path")): str(i.get("kind") or "") for i in (load_ledger(case_dir).get("items") or {}).values()
                 if isinstance(i, dict)}
    except Exception:  # noqa: BLE001
        kinds = {}
    out: dict[str, dict] = {}
    for path, t in tables.items():
        out[path] = {"form": "table", **t}
    for path, kind in kinds.items():
        if path not in out and kind in ("image", "memory", "archive"):
            out[path] = {"form": kind}
    return out


_FORM_WORDS = {"table": "parsed table", "image": "disk image", "memory": "memory image", "archive": "archive"}


def _moment(t: Any) -> str:
    """A time in one comparable form (date and time joined by a space)."""
    return str(t or "").strip().replace("T", " ")[:19]


def _fact(case_dir: str, path: str, f: dict, start: str) -> str:
    form = str(f.get("form") or "file")
    if form == "table":
        if not f.get("rows"):
            return f"{path} [parsed table, empty]"
        span = f", {f['first']} to {f['last']}" if f.get("first") and f.get("last") else ""
        before = (", ends before the earliest stated start"
                  if start and f.get("last") and _moment(f["last"]) < _moment(start) else "")
        hosts = f", spans {len(f['hosts'])} hosts" if len(f.get("hosts") or []) > 1 else ""
        return f"{path} [parsed table, {int(f['rows']):,} rows{span}{hosts}{before}]"
    try:
        size = _size(os.path.getsize(os.path.join(case_dir, path)))
    except OSError:
        size = ""
    return f"{path} [{_FORM_WORDS.get(form, 'file')}" + (f", {size}" if size else "") + "]"


def _rank(f: dict, case_dir: str, path: str) -> tuple:
    """Quick first: tables with rows, then empty tables, then the rest
    smallest first (a property order)."""
    if f.get("form") == "table":
        return (0 if f.get("rows") else 1, 0)
    try:
        size = float(os.path.getsize(os.path.join(case_dir, path)))
    except OSError:
        size = float("inf")                              # an unknown size after the known ones
    return (2, size)


def source_lines(case_dir: str) -> list[str]:
    """EVIDENCE PER HOST with each source's form and cost (source_facts),
    quick sources first; a table spanning several hosts is named once under
    SPANNING HOSTS. The per-host bound says what it leaves out."""
    try:
        facts = source_facts(case_dir)
    except Exception:  # noqa: BLE001
        facts = {}
    try:
        from core.evidence_leave import window_start
        start = str(window_start(case_dir) or "")
    except Exception:  # noqa: BLE001
        start = ""
    spanning = sorted(p for p, f in facts.items() if f.get("form") == "table" and len(f.get("hosts") or []) > 1)
    lines = ["EVIDENCE PER HOST (each source with its form, and rows and time span or size):"]
    for host, files in host_files(case_dir).items():
        own = sorted((p for p in files if p not in spanning), key=lambda p: _rank(facts.get(p, {}), case_dir, p))
        containers = [p for p in own if facts.get(p, {}).get("form") in ("image", "memory", "archive")]
        rest = [p for p in own if p not in containers]
        shown = rest[:max(0, SOURCES_PER_HOST - len(containers))]
        left = rest[len(shown):]
        listed = sorted(shown + containers, key=lambda p: _rank(facts.get(p, {}), case_dir, p))
        if not listed and not left:
            continue
        tables = sum(1 for p in left if facts.get(p, {}).get("form") == "table")
        lines.append(f"- {host or '(no host label)'}: " + "; ".join(_fact(case_dir, p, facts.get(p, {}), start)
                                                                   for p in listed)
                     + (f" ({len(left)} more of this host not listed: {tables} tables, {len(left) - tables} other)"
                        if left else ""))
    if spanning:
        lines.append("SPANNING HOSTS (each named once):")
        lines += [f"- {_fact(case_dir, p, facts[p], start)}" for p in spanning]
    return lines


def _question_head(task: dict) -> list[str]:
    parts = [f"QUESTION {task.get('id')}: {task.get('text') or ''}"]
    for p in task.get("parts") or []:
        if isinstance(p, dict) and p.get("text"):
            parts.append(f"- part {p.get('id')}: {p['text']}")
    return parts


def digest_block(case_dir: str) -> str:
    """INSIDE THE IMAGES: the listing digest, one line per host (bounded)."""
    from core.contents_index import listing_digest
    lines = listing_digest(case_dir).get("lines") or []
    return ("INSIDE THE IMAGES (per host: files, commonest extensions, the largest trees few other hosts "
            "hold):\n" + "\n".join(f"- {line}" for line in lines)) if lines else ""


def plan_message(case_dir: str, task: dict, tools: list[tuple[str, str]], extra: str = "", *,
                 listing: str = "") -> str:
    from core.case_knowledge import read
    parts = [f"QUESTION {task.get('id')}: {task.get('text') or ''}"]
    for p in task.get("parts") or []:
        if isinstance(p, dict) and p.get("text"):
            parts.append(f"- part {p.get('id')}: {p['text']}")
    parts.append("")
    parts.append(question_anchors(case_dir, task))
    try:
        prior = str(read(case_dir).get("text") or "")
    except Exception:  # noqa: BLE001
        prior = ""
    if prior:
        parts += ["", "WHAT THE BRIEF SAYS IS KNOWN:", prior[:3000]]
    parts += ["", *source_lines(case_dir)]
    if plan_listing_on():
        digest = digest_block(case_dir)
        if digest:
            parts += ["", digest]
        if listing:
            parts += ["", listing]
    parts += ["", "READING TOOLS:"] + [f"- {t}: {why}" for t, why in tools]
    if extra:
        parts += ["", extra]
    return "\n".join(parts)


def parse_json_key(text: str, key: str) -> list | None:
    """The list under ``key`` of the first JSON object in a reply that has
    it; prose around the JSON is ignored. None when no object has it."""
    s = str(text or "")
    for start in [m.start() for m in re.finditer(r"\{", s)]:
        depth = 0
        for i in range(start, len(s)):
            depth += {"{": 1, "}": -1}.get(s[i], 0)
            if depth == 0:
                try:
                    data = json.loads(s[start:i + 1])
                except ValueError:
                    break
                if isinstance(data, dict) and isinstance(data.get(key), list):
                    return data[key]
                break
    return None


def _norm_glob(glob: str) -> str:
    g = str(glob or "").strip().replace("\\", "/")
    g = re.sub(r"^([A-Za-z]):/", r"\1/", g).lstrip("/")
    return g


def parse_locate(case_dir: str, text: str) -> tuple[list[dict], list[str]]:
    """The places of a LOCATE reply ({host, glob, why}, up to four) and the
    reasons places were dropped (an unknown host, no glob)."""
    from core.forensic_citation import known_case_hosts
    hosts = {h.casefold(): h for h in known_case_hosts(case_dir)}
    places, dropped = [], []
    for p in (parse_json_key(text, "places") or [])[:4]:
        if not isinstance(p, dict):
            continue
        glob, host = _norm_glob(p.get("glob")), str(p.get("host") or "").strip()
        if not glob:
            dropped.append(f"{host or '?'}: no glob")
            continue
        if host in ("", "*"):
            host = ""
        elif host.casefold() in hosts:
            host = hosts[host.casefold()]
        else:
            dropped.append(f"{host}: not a host of this case")
            continue
        places.append({"host": host, "glob": glob, "why": str(p.get("why") or "")[:120]})
    return places, dropped


# Display bound of one LISTING place (the summary states its total).
LISTING_DIRS = 12


def listing_block(case_dir: str, places: list[dict], dropped: list[str] = ()) -> str:
    """LISTING: per place, the directories of the index holding its matches
    (a glob not anchored at the image root also matches below any folder)."""
    from core.contents_index import find_summary, summary_lines
    lines = ["LISTING (the files the contents index holds at the places named for this question):"]
    for p in places:
        shape = find_summary(case_dir, pattern=p["glob"], host=p["host"], bound=LISTING_DIRS)
        if not shape["total_files"] and not p["glob"].startswith("*"):
            shape = find_summary(case_dir, pattern="*/" + p["glob"], host=p["host"], bound=LISTING_DIRS)
        where = f"{p['host'] or 'every host'} {p['glob']}"
        if not shape["total_files"]:
            lines.append(f"- {where}: no listing entry matches")
            continue
        lines.append(f"- {where}: {shape['total_files']} files in {shape['total_dirs']} directories")
        lines += [f"  {line}" for line in summary_lines(shape)]
    for d in dropped:
        lines.append(f"- dropped: {d}")
    return "\n".join(lines)


def locate_places(case_dir: str, task: dict) -> dict:
    """The LOCATE call: the places the model names for one question, and
    the LISTING block of what the index holds there. {"places", "dropped",
    "listing", "empty"}."""
    from tools.reasoning import _ask
    user = "\n".join(_question_head(task) + ["", question_anchors(case_dir, task)])
    try:
        from core.case_knowledge import read
        prior = str(read(case_dir).get("text") or "")
    except Exception:  # noqa: BLE001
        prior = ""
    if prior:
        user += "\n\nWHAT THE BRIEF SAYS IS KNOWN:\n" + prior[:3000]
    digest = digest_block(case_dir)
    if digest:
        user += "\n\n" + digest
    result = _ask(LOCATE_SYS, user, _tool_name="reason_locate_question")
    places, dropped = parse_locate(case_dir, str(result.get("conclusion") or ""))
    if not places:
        return {"places": [], "dropped": dropped, "listing": "", "empty": True}
    return {"places": places, "dropped": dropped, "listing": listing_block(case_dir, places, dropped),
            "empty": False}


def parse_plan(text: str) -> list[dict]:
    """The reads of a plan reply; prose around the JSON is ignored."""
    s = str(text or "")
    for start in [m.start() for m in re.finditer(r"\{", s)]:
        depth = 0
        for i in range(start, len(s)):
            depth += {"{": 1, "}": -1}.get(s[i], 0)
            if depth == 0:
                try:
                    data = json.loads(s[start:i + 1])
                except ValueError:
                    break
                if isinstance(data, dict) and isinstance(data.get("reads"), list):
                    return [r for r in data["reads"] if isinstance(r, dict)]
                break
    return []


def _case_files(case_dir: str) -> list[str]:
    try:
        from core.coverage_ledger import load_ledger
        return [str(u.get("path")) for u in (load_ledger(case_dir).get("units") or {}).values()
                if isinstance(u, dict) and u.get("path")]
    except Exception:  # noqa: BLE001
        return []


def validate_read(case_dir: str, read: dict, tools: set[str]) -> dict | None:
    """A plan read as an item's tool and target, or None when it names a
    host, file or tool that does not exist, or a table read without a
    pattern. One rewrite: an inner path that a case file ends with at a
    segment boundary becomes that case file."""
    return check_read(case_dir, read, tools)[0]


def check_read(case_dir: str, read: dict, tools: set[str]) -> tuple[dict | None, str]:
    """``validate_read`` with the reason a read is refused ("" when valid):
    the first read of check_reads."""
    reads, why = check_reads(case_dir, read, tools)
    return (reads[0] if reads else None), why


def check_reads(case_dir: str, read: dict, tools: set[str]) -> tuple[list[dict], str]:
    """The reads a planned read stands for, and why there are none. A
    source that is no case file and no image handle is an inner path of the
    host's image: it stands when the host's listing holds it, or when no
    listing is indexed to check against. Else, when it names one of the
    host's content classes (the triage's labels), it stands for that
    class's top files, each read saying which of how many it is; else it is
    refused, naming the host's classes."""
    unit = _unit_class(case_dir, str(read.get("source") or ""))
    if unit is not None:
        # A ledger unit id (as the map's pending-evidence lines print a
        # class) stands for its class: its label on its item's host.
        read = {**read, "source": unit[0], "host": read.get("host") or unit[1]}
    v, why = _check_one(case_dir, read, tools)
    if v is None:
        return [], why
    t = v["target"]
    source = str(read.get("source") or "").strip()
    host = str(t.get("host") or "")
    # An image no evidence link ties to a host is checked against its own
    # listing; with none indexed yet the read stands, as a host's does.
    image = "" if host else str(t.get("path") or "")
    from core.contents_index import class_handles, handle_missing, holds_path
    # A handle is checked by the lookup a read of it runs (resolve's), and
    # refused only against a complete listing: an invented or template path
    # in an image is no read.
    if "::" in source:
        missing = handle_missing(case_dir, source)
    else:
        missing = bool(t.get("inner_path")) and holds_path(case_dir, host, t["inner_path"], image=image) is False
    if not missing:
        wrong = _kind_refusal(case_dir, v)
        if wrong:
            return [], wrong
        if not t.get("inner_path") and t.get("path"):
            inner, absent = image_input(case_dir, v["tool"], str(t["path"]))
            if absent:
                return [], absent
            if inner:
                return [{**v, "target": {**t, "inner_path": inner}}], ""
        return [v], ""
    handles, total = class_handles(case_dir, host, source, image=image)
    out = []
    for k, h in enumerate(handles, 1):
        v2, _w = _check_one(case_dir, {**read, "source": h}, tools)
        if v2 is not None and not _kind_refusal(case_dir, v2):
            v2["why"] = (f"{v2['why']} (class {source!r}: file {k} of {total})").strip()[:240]
            out.append(v2)
    if out:
        return out, ""
    labels = _class_labels(case_dir, host, image)
    return [], (f"{source} is neither a file the listing of {host or image} holds nor one of its content classes"
                + (f" (its classes: {', '.join(labels[:10])})" if labels else ""))


def _unit_class(case_dir: str, source: str) -> tuple[str, str] | None:
    """(label, host) of the content class a ledger unit id names
    ("<item>#<hash>"), None for anything else."""
    if "#" not in source:
        return None
    try:
        from core.coverage_ledger import load_ledger
        led = load_ledger(case_dir)
    except Exception:  # noqa: BLE001
        return None
    c = (led.get("classes") or {}).get(source.strip())
    if not isinstance(c, dict) or not c.get("label"):
        return None
    item = (led.get("items") or {}).get(c.get("item")) or {}
    return str(c["label"]), str(item.get("host") or "")


def _item_kind(case_dir: str, path: str) -> str:
    """The ledger kind of the evidence item at ``path`` ("" when unknown)."""
    try:
        from core.coverage_ledger import _norm_rel, load_ledger
        want = _norm_rel(str(path)).casefold()
        for i in (load_ledger(case_dir).get("items") or {}).values():
            if isinstance(i, dict) and _norm_rel(str(i.get("path") or "")).casefold() == want:
                return str(i.get("kind") or "")
    except Exception:  # noqa: BLE001
        pass
    return ""


def _kind_refusal(case_dir: str, v: dict) -> str:
    """Why a read pairs a tool with an input it cannot read
    (core.input_kind.reads_kind), naming that input's readers; "" when the
    pair holds or the kind is not known."""
    import os
    from core.input_kind import _HIVE_TOOL_RE, reads_kind
    t, tool = v["target"], str(v.get("tool") or "")
    inner, path = str(t.get("inner_path") or ""), str(t.get("path") or "")
    if inner and _HIVE_TOOL_RE.search(tool):
        return ""                                  # a hive inside an image is read from its copy
    kind = "" if inner else _item_kind(case_dir, path)
    probe = inner or os.path.join(str(case_dir), path)
    if reads_kind(tool, probe, kind) is not False:
        return ""
    try:
        from core.evidence_leave import readers_for
        from tools.tool_capabilities import readers_for_input
        readers = readers_for(kind) if kind else readers_for_input(probe)[1]
    except Exception:  # noqa: BLE001
        readers = []
    what = f"a {kind} item" if kind else (inner or path).rsplit("/", 1)[-1]
    return (f"{tool} cannot read {inner or path} ({what})"
            + (f"; its readers: {', '.join(readers[:6])}" if readers else ""))


def _class_labels(case_dir: str, host: str, image: str = "") -> list[str]:
    """The content-class labels of a host's evidence items (the coverage
    ledger's classes, as the triage names them); with no host, those of the
    item at ``image``."""
    try:
        from core.coverage_ledger import load_ledger
        led = load_ledger(case_dir)
    except Exception:  # noqa: BLE001
        return []
    if host or not image:
        items = {iid for iid, i in (led.get("items") or {}).items()
                 if isinstance(i, dict) and str(i.get("host") or "").casefold() == str(host or "").casefold()}
    else:
        items = {iid for iid, i in (led.get("items") or {}).items()
                 if isinstance(i, dict) and str(i.get("path") or "").casefold() == image.casefold()}
    return sorted({str(c.get("label")) for c in (led.get("classes") or {}).values()
                   if isinstance(c, dict) and c.get("item") in items and c.get("label")})


def _check_one(case_dir: str, read: dict, tools: set[str]) -> tuple[dict | None, str]:
    """One read checked as written (check_reads adds the listing check)."""
    from core.coverage_ledger import _any_path_match, _norm_rel
    from core.forensic_citation import known_case_hosts
    from core.work_order import _host_image, _is_case_file, listed, tool_kind
    tool = str(read.get("tool") or "").strip()
    dotted = {t: t for t in tools} | {listed(t): t for t in tools}
    if listed(tool) not in {listed(t) for t in tools}:
        return None, f"{tool or 'no tool'} is not a reading tool of this run"
    from core.work_order import takes_target
    if not takes_target(_input_schema(tool)):
        return None, f"{tool} takes no input that can name a file, so a read by it never closes"
    if tool_kind(tool) == "search" and not str(read.get("pattern") or "").strip():
        return None, "a search needs a pattern"
    try:
        from tools.tool_capabilities import generic_text_refusal
        routed = generic_text_refusal(tool, str(read.get("source") or ""), pattern=str(read.get("pattern") or ""))
    except Exception:  # noqa: BLE001
        routed = ""
    if routed:
        return None, routed
    hosts = known_case_hosts(case_dir)
    host = str(read.get("host") or "").strip()
    src0 = str(read.get("source") or "").strip()
    if not host and "::" in src0:
        # A handle's image names its host through the Evidence Links.
        try:
            from pathlib import Path as _P
            from core import contents_index as _ci
            m0 = _ci.HANDLE_RE.match(src0)
            img0 = _ci._match_image(_P(case_dir), m0.group("image"))[0] if m0 else None
            host = str((img0 or {}).get("host") or "")
        except Exception:  # noqa: BLE001
            host = ""
    if hosts:
        match = next((h for h in hosts if h.casefold() == host.casefold()), None)
        if match is None:
            return None, f"host {host or '(none)'} is not a host of this case"
        host = match
    else:
        host = ""
    source = str(read.get("source") or "").strip()
    if not source:
        return None, "no source named"
    target: dict[str, Any] = {"host": host, "pattern": str(read.get("pattern") or ""),
                              "window": str(read.get("window") or "") or None}
    # An image handle (<image>::<path>, as the host view offers them) names
    # the image and the path inside it: split, never kept whole as a path.
    try:
        from pathlib import Path as _P
        from core import contents_index as _ci
        m = _ci.HANDLE_RE.match(source) if _ci.looks_like_handle(source) else None
        if m:
            img, why = _ci._match_image(_P(case_dir), m.group("image"))
            if img is None:
                return None, why
            target["path"] = img["rel"]
            target["inner_path"] = m.group("path").replace("\\", "/").strip().strip("/")
            if not target["host"]:
                target["host"] = img.get("host") or ""
            return {"tool": dotted.get(tool, dotted.get(listed(tool), tool)), "target": target,
                    "why": str(read.get("why") or "")[:200]}, ""
    except Exception:  # noqa: BLE001 - not a handle the index knows: read as written
        pass
    if _is_case_file(case_dir, source):
        target["path"] = source
    else:
        norm = _norm_rel(source.replace("\\", "/").lstrip("/")).casefold()
        case_match = next((p for p in _case_files(case_dir)
                           if _any_path_match(_norm_rel(p).casefold(), {norm})), None)
        if case_match:
            target["path"] = case_match
        else:
            image = _host_image(case_dir, host) if host else _single_image(case_dir)
            if not image:
                return None, f"{source} is no case file, and no image of {host or 'the case'} holds it"
            target["path"] = image
            target["inner_path"] = source
            if not host:
                try:
                    from core.evidence_links import host_for_image
                    target["host"] = host_for_image(image, case_dir) or ""
                except Exception:  # noqa: BLE001
                    pass
    return {"tool": dotted.get(tool, dotted.get(listed(tool), tool)), "target": target,
            "why": str(read.get("why") or "")[:200]}, ""


def _input_schema(tool: str) -> dict | None:
    """The registered input schema of ``tool`` (any spelling), None when the
    registry is not readable or does not know the tool."""
    try:
        from core.work_order import listed
        from tools.tool_capabilities import registered_tool_schemas
        want = listed(tool)
        return next((params for name, params, _d in registered_tool_schemas() if listed(name) == want), None)
    except Exception:  # noqa: BLE001
        return None


def _input_names(tool: str) -> tuple[str, ...]:
    """The names the input file of ``tool`` (any spelling) has in a
    filesystem listing, as its registration declares them (meta
    "input_names": the tool's own input format, never a case's); () when it
    declares none or the registry is not readable."""
    try:
        from core.work_order import listed
        from tools.tool_capabilities import registered_tool_schemas
        want = listed(tool)
        for entry in registered_tool_schemas():
            if listed(entry[0]) == want:
                meta = entry[3] if len(entry) > 3 and isinstance(entry[3], dict) else {}
                return tuple(str(n) for n in meta.get("input_names") or ())
    except Exception:  # noqa: BLE001
        pass
    return ()


def _inherited_input(tool: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(the producers, their input names) of a reader whose input is
    another reader's output (meta "input_from"): the names only when every
    producer declares some, else none (an undeclared producer could read
    anything)."""
    try:
        from core.work_order import listed
        from tools.tool_capabilities import registered_tool_schemas
        want = listed(tool)
        for entry in registered_tool_schemas():
            if listed(entry[0]) == want:
                meta = entry[3] if len(entry) > 3 and isinstance(entry[3], dict) else {}
                producers = tuple(str(p) for p in meta.get("input_from") or ())
                names = [_input_names(p) for p in producers]
                if producers and all(names):
                    return producers, tuple(n for ns in names for n in ns)
    except Exception:  # noqa: BLE001
        pass
    return (), ()


def image_input(case_dir: str, tool: str, image: str) -> tuple[str, str]:
    """A read of a whole disk image by a reader whose input is one file in
    the image's filesystem, by a name the reader declares (_input_names):
    (its path, "") when the image's listing holds one live file of that name
    on one volume, so the read names that file; ("", why) when the complete
    listing of every volume holds no file of that name, deleted ones
    included, so the read has no input there; ("", "") when the read stands
    as named (no declaration, no such listing, or several files of that
    name, on one volume or on several: a bare inner path would pick one).
    A reader of another reader's output (meta "input_from") is judged by its
    producers' declared input, absence only: its read is never rewritten."""
    names = _input_names(tool)
    producers: tuple[str, ...] = ()
    if not names:
        # A reader of another reader's output has no input in the image of
        # its own; its producers' input decides whether it has one at all.
        producers, names = _inherited_input(tool)
    if not names or not image:
        return "", ""
    try:
        from core.contents_index import input_entries
        rows = input_entries(case_dir, image, names)
    except Exception:  # noqa: BLE001 - no index to check against: as named
        return "", ""
    if rows is None:
        return "", ""
    if not rows:
        if producers:
            return "", (f"it reads the output of {', '.join(producers)}, whose input {', '.join(names)} is not "
                        f"listed in the complete listing of {image}")
        return "", (f"it reads {', '.join(names)}; no file of {'that name' if len(names) == 1 else 'these names'} "
                    f"is listed in the complete listing of {image}")
    if producers:
        return "", ""                       # its input is the producer's output: never rewritten
    live = [p for _vol, p, deleted in rows if not deleted]
    return (live[0], "") if len(live) == 1 else ("", "")


def _single_image(case_dir: str) -> str:
    from core.work_order import _MEMORY_EXT_RE, _is_container
    disks = [p for p in _case_files(case_dir) if _is_container(p) and not _MEMORY_EXT_RE.search(p)]
    return disks[0] if len(disks) == 1 else ""


def plan_question(log, case_dir: str, task: dict, tools: list[tuple[str, str]] | None = None,
                  extra: str = "") -> dict:
    """One focused reason-role call for one question; its valid reads
    become due plan items. With ATLAS_PLAN_LISTING a LOCATE call first
    names the places to look and the plan sees what the index holds there
    (an empty LOCATE reply falls back to the one plan call). Returns
    {"items", "invalid", "empty", "locate"}."""
    from tools.reasoning import _ask
    tools = tools if tools is not None else reading_tools()
    located: dict = {}
    from core.contents_index import db_path
    if plan_listing_on() and db_path(case_dir).is_file():
        try:
            located = locate_places(case_dir, task)
        except Exception as e:  # noqa: BLE001 - the plan runs without the check
            located = {"empty": True, "error": str(e)[:200]}
    user = plan_message(case_dir, task, tools, extra, listing=located.get("listing", ""))
    result = _ask(plan_system(), user, _tool_name="reason_plan_question")
    reply = str(result.get("conclusion") or "")
    reads = parse_plan(reply)
    names = {t for t, _w in tools}
    made, invalid, refused = [], 0, []
    for r in reads[:5]:
        checked, why = check_reads(case_dir, r, names)
        if not checked:
            invalid += 1
            # Why each read was refused, kept for the run's record: a plan
            # with no valid read says what was wrong with each.
            refused.append({"host": str(r.get("host") or "")[:80], "source": str(r.get("source") or "")[:200],
                            "tool": str(r.get("tool") or "")[:80], "why": " ".join(str(why).split())[:300]})
            continue
        for v in checked:
            made.append(log.add_work_item("plan", [str(task.get("id"))], v["tool"], v["target"], v["why"],
                                          source_ref={"kind": "reason_call",
                                                      "call_id": result.get("_atlas_call_id")}))
    reason = ""
    if not made:
        # Why the question has no plan, never left unsaid.
        if result.get("gate") == "reply_length_cut":
            reason = ("the plan reply was cut at the one-answer allowance twice "
                      "(the second ask one thinking level lower)")
        elif result.get("error"):
            reason = " ".join(str(result["error"]).split())[:200]
        elif not reads:
            reason = "the plan reply held no read"
        else:
            reason = f"none of its {len(reads)} read(s) named a host, source and reading tool of this case"
    views = declare_plan_views(case_dir, task, reply)
    return {"items": made, "invalid": invalid, "refused": refused, "empty": not made, "reads": len(reads),
            "reason": reason, "views": views,
            "locate": {k: located.get(k) for k in ("places", "dropped", "empty", "error") if k in located}}


def declare_plan_views(case_dir: str, task: dict, reply: str) -> dict:
    """The plan reply's views, declared on the incident map for the parts of
    this question (ATLAS_MAP_VIEWS); {"declared", "notes"}."""
    from core import incident_map
    out: dict = {"declared": 0, "notes": []}
    if not incident_map.views_on():
        return out
    parts = {str(p.get("id")) for p in task.get("parts") or [] if isinstance(p, dict) and p.get("id")}
    views = [v for v in parse_json_key(reply, "views") or [] if isinstance(v, dict) and v.get("over")]
    if not views:
        return out
    m = incident_map.open(case_dir)
    if m is None:
        return out
    for v in views:
        part = str(v.get("part") or "")
        if part not in parts:
            out["notes"].append(f"view for unknown part {part!r}")
            continue
        r = m.declare_view(str(task.get("id")), part, v, _by="plan")
        out["declared"] += int(r["ok"])
        out["notes"] += r["notes"]
    return out


def planned_task_ids(log) -> set[str]:
    """The questions a plan call already ran for in this trace."""
    out: set[str] = set()
    for e in log._entries:
        if e.get("type") == "reason_call" and e.get("tool") == "reason_plan_question":
            m = re.match(r"QUESTION (task-\d+)", str((e.get("inputs") or {}).get("user_message") or ""))
            if m:
                out.add(m.group(1))
    return out


# ── the source behind a question's index-only claims ─────────────────────

_PATTERN_ARG_KEYS = ("pattern", "patterns", "query", "regex", "expression", "where", "term", "terms", "keyword")


def _norm_ident(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", str(value or "")).replace("\\", "/").casefold()


def claim_identifiers(statement: str) -> list[str]:
    """The claim's identifiers: entities of a discriminative type other than
    a time, and paths whose last component is not a structural folder."""
    from core.entities import DISCRIMINATIVE_TYPES, _STRUCTURAL_DIRS, extract
    out: list[str] = []
    for ent in extract(statement or ""):
        kind, _, value = ent.partition(":")
        if kind in DISCRIMINATIVE_TYPES and kind != "ts":
            out.append(value)
        elif kind == "path":
            last = value.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].casefold()
            if last and last not in _STRUCTURAL_DIRS:
                out.append(value)
    return sorted({_norm_ident(v) for v in out if v})


def _call_patterns(entry: dict) -> str:
    from core.indicators import _parsed_args
    args, _k = _parsed_args(entry)
    bits: list[str] = []
    if isinstance(args, dict):
        for k, v in args.items():
            if k in _PATTERN_ARG_KEYS and isinstance(v, str):
                bits.append(v)
            elif isinstance(v, list):
                bits += [str(x) for x in v if isinstance(x, str)]
    return _norm_ident(" ".join(bits))


def _rows_of_call(entry: dict) -> list[dict]:
    """The rows a table call returned (its spill when it has one)."""
    text = ""
    sf = entry.get("stdout_file")
    if sf:
        try:
            with open(str(sf), encoding="utf-8", errors="replace") as fh:
                text = fh.read(8_000_000)
        except OSError:
            text = ""
    text = text or str(entry.get("stdout_excerpt") or "")
    try:
        data = json.loads(text[text.index("{"):]) if "{" in text else {}
    except ValueError:
        return []
    for key in ("hits", "rows", "results", "matches"):
        rows = data.get(key) if isinstance(data, dict) else None
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
    return []


def _fold(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def source_items_for_question(log, case_dir: str, task: dict) -> list[dict]:
    """For each claim linked to the question, the rows of its cited table
    calls that the claim's own identifiers tie to it give (host, source
    file); each source no call has read becomes a due item (origin source)
    whose target is the row's raw filename as a hint. The identifier must
    occur in the cited call's pattern arguments and in the row: the claim
    states X, cites a call that searched for X, and the row holds X."""
    from core.claim_graph import load_graph
    from core.forensic_citation import host_mentioned, known_case_hosts
    from core.table_rows import HOST_COLUMNS, PATH_COLUMNS
    tid = str(task.get("id") or "")
    claim_ids = set(task.get("related_claim_ids") or [])
    for p in task.get("parts") or []:
        if isinstance(p, dict):
            claim_ids |= set(p.get("claim_ids") or [])
    if not claim_ids:
        return []
    try:
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        return []
    hosts = known_case_hosts(case_dir)
    by_id = log.index().by_call_id or {}
    made: list[dict] = []
    elsewhere: list[str] = []          # sources the case does not hold
    for cid in sorted(claim_ids):
        node = nodes.get(cid)
        if not isinstance(node, dict) or node.get("status") in ("superseded", "withdrawn"):
            continue
        idents = claim_identifiers(str(node.get("statement") or ""))
        if not idents:
            continue
        calls = [node.get("source_finding_call_id")] + list(node.get("input_call_ids") or [])
        calls += [ev.get("call_id") for ev in node.get("evidence") or [] if isinstance(ev, dict)]
        for call_id in dict.fromkeys(c for c in calls if isinstance(c, int)):
            entry = by_id.get(call_id)
            if not isinstance(entry, dict) or entry.get("type") != "tool_call":
                continue
            searched = _call_patterns(entry)
            wanted = [i for i in idents if i and i in searched]
            if not wanted:
                continue
            for row in _rows_of_call(entry):
                cells = {k: str(v) for k, v in row.items() if not str(k).startswith("_") and v not in (None, "")}
                text = _norm_ident(" ".join(cells.values()))
                if not any(i in text for i in wanted):
                    continue
                fname = next((v for k, v in cells.items() if _fold(k) in PATH_COLUMNS), "")
                if not fname:
                    continue
                last = _norm_ident(fname.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1])
                rest = text.replace(_norm_ident(fname), " ")
                if not any(i in rest or i in last for i in wanted):
                    continue          # the match is a folder of the path only
                hostcell = " ".join(v for k, v in cells.items() if _fold(k) in HOST_COLUMNS)
                from core.evidence_links import host_of_path, host_of_path_on
                if host_of_path_on():
                    # The host column is text; the source path is a file name.
                    host = next((h for h in hosts if host_mentioned(h, hostcell)), "") \
                        or host_of_path(case_dir, fname, hosts)
                else:
                    host = next((h for h in hosts if host_mentioned(h, hostcell + " " + fname)), "")
                if not host:
                    host = next((h for h in hosts if host_mentioned(h, str(entry.get("cmd") or "")
                                                                    + str(entry.get("args") or ""))), "")
                why = (f"rows behind {cid} were parsed from {fname} on {host or 'the case'}; "
                       "no call has read it")
                target: dict = {"host": host, "source_hint": fname}
                if source_in_case_on():
                    # Only a source the case holds is a read: a case file,
                    # or a file of a listed image (the index's suffix join).
                    held = _source_in_case(case_dir, host, fname)
                    if held is None:
                        if fname not in elsewhere:
                            elsewhere.append(fname)
                        continue
                    target = held
                made.append(log.add_work_item("source", [tid], "", target, why,
                                              source_ref={"kind": "claim", "claim_id": cid, "call_id": call_id}))
    if elsewhere:
        # Disclosed, never due: the rows came from a collection the case
        # does not hold, so no read can reach them.
        note = log.add_work_item("source", [tid], "", {"host": "", "source_hint": "(not in this case)"},
                                 "rows from a source not found among the case's files or listed images",
                                 status="dismissed",
                                 source_ref={"kind": "elsewhere"})
        note["outcome"] = (f"rows from a source not found among the case's files or listed images: "
                           f"{len(elsewhere)} "
                           f"(for example {elsewhere[0][:160]})")
        made.append(note)
    return made


def source_in_case_on() -> bool:
    """ATLAS_SOURCE_IN_CASE: a claim's row source becomes an item
    only when the case holds it."""
    from core.envfile import env_flag
    return env_flag("ATLAS_SOURCE_IN_CASE", True)


def _source_in_case(case_dir: str, host: str, fname: str) -> dict | None:
    """The target a row's source path resolves to in the case: a case file
    (by its path or its tail, on the row's host), else an image and the path
    inside it through the contents index; None when the case holds neither.
    Several case files on the row's host hold the tail (the same standard
    path in several collections): the source is in the case but not one
    file, so the target keeps the path as a hint, unpinned."""
    from core.coverage_ledger import _any_path_match, _norm_rel
    from core.evidence_links import host_for_image
    from core.work_order import _is_case_file
    src = fname.replace("\\", "/").strip()
    if _is_case_file(case_dir, src):
        return {"host": host, "path": src}
    # The row's path as the case holds it (case-relative), and as written
    # inside a collection (no drive or mount prefix), at three components or
    # more so a bare standard tail does not match every collection.
    inner = re.sub(r"^[a-z0-9_]+:/+", "", src.lstrip("/").casefold())
    norms = {_norm_rel(src.lstrip("/")).casefold()} | ({inner} if inner.count("/") >= 2 else set())
    hits = [p for p in _case_files(case_dir) if _any_path_match(_norm_rel(p).casefold(), norms)]
    if hits:
        # A multi-host triage collection held as files repeats the standard
        # paths per host: a row's source is its own host's file. A file the
        # links give no host is kept only when no file of the host matches.
        owner = {p: host_for_image(p, case_dir).casefold() for p in hits}
        mine = [p for p in hits if host and owner[p] == host.casefold()] or \
               [p for p in hits if not owner[p] or not host]
        if len(mine) == 1:
            return {"host": host or host_for_image(mine[0], case_dir), "path": mine[0]}
        if len(mine) > 1:
            return {"host": host, "source_hint": fname}
    try:
        from core import contents_index as ci
        found = ci.resolve_source(case_dir, host, src) if ci.index_on() else None
    except Exception:  # noqa: BLE001
        found = None
    if found:
        return {"host": found["host"] or host, "path": found["image"], "inner_path": found["inner_path"]}
    return None


# ── absence contradictions and proposals ─────────────────────────────────

def absence_items(log, case_dir: str) -> list[dict]:
    """A claim says an artefact is absent while the case's index lists it:
    a due item to read it on the claim's host; a clash whose claim carries
    no host in a case with several hosts is a proposal."""
    from core.artifact_value import contradicted_absence_claims
    from core.forensic_citation import known_case_hosts
    many = len(known_case_hosts(case_dir)) > 1
    made = []
    for c in contradicted_absence_claims(case_dir):
        host = str(c.get("claim_host") or "")
        status = "proposed" if (not host and many) else "due"
        target = {"host": host or str(c.get("host") or "")}
        if c.get("path"):
            target["path"] = str(c["path"])
        else:
            target["source_hint"] = str(c.get("artifact") or "")
        why = (f"{c.get('claim_id')} says this does not occur; the case index lists "
               f"{c.get('artifact')} ({c.get('indexed_by') or 'index'})")
        made.append(log.add_work_item("absence", _tasks_of_claim(case_dir, c.get("claim_id")), "",
                                      target, why, status=status,
                                      source_ref={"kind": "claim", "claim_id": c.get("claim_id")}))
    return made


def _tasks_of_claim(case_dir: str, claim_id) -> list[str]:
    try:
        from core.investigation_tasks import load_tasks
        out = []
        for t in load_tasks(case_dir).get("tasks") or []:
            ids = set(t.get("related_claim_ids") or [])
            for p in t.get("parts") or []:
                if isinstance(p, dict):
                    ids |= set(p.get("claim_ids") or [])
            if claim_id in ids:
                out.append(str(t.get("id")))
        return out
    except Exception:  # noqa: BLE001
        return []


def proposal_items(log, case_dir: str) -> list[dict]:
    """Proposals for the director: unread high-value artefacts of the case
    index (origin index) and series read in part (origin series)."""
    made = []
    try:
        from core.artifact_value import unexamined_high_value
        from core.contents_index import host_view_on, view_items
        if host_view_on():
            # The contents index's rows in the host-first view's order, after
            # the other unread artefacts (a mounted volume's, a file's).
            unread = [u for u in unexamined_high_value(case_dir, limit=10_000)
                      if not str(u.get("source") or "").startswith("index:")][:12]
            unread += view_items(case_dir, limit=12)
        else:
            unread = unexamined_high_value(case_dir, limit=12)
        for u in unread:
            target = {"host": str(u.get("host") or "")}
            if u.get("path"):
                target["path"] = str(u["path"])
            else:
                target["source_hint"] = str(u.get("lpath") or u.get("name") or "")
            if u.get("handle"):
                target["handle"] = str(u["handle"])
            made.append(log.add_work_item("index", [], "", target,
                                          f"the case index lists {u.get('name')} and no call read it",
                                          status="proposed", source_ref={"kind": "index", "key": u.get("key")}))
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.source_sets import partially_examined_series
        for sr in partially_examined_series(case_dir):
            made.append(log.add_work_item(
                "series", [], "", None,
                f"{sr['examined']} of {sr['total']} {sr['pattern']} under {sr['directory']} read",
                status="proposed", source_ref={"kind": "series", "directory": sr["directory"]}))
    except Exception:  # noqa: BLE001
        pass
    return made
