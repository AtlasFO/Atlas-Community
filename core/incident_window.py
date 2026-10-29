"""The incident window the model itself stated (C2 item 4,
ATLAS_WINDOW_NOTES): when the attacker first acted on each host and with
each account, from the ``attacker_from`` of host and account rows on
current beliefs at LIKELY or stronger. A finding or an answer that leads
with an earlier time gets a note asking why that row is the attacker's,
never a refusal. The model's ``first_seen`` (when a value first appears in
a log) is not a window and is never read as one."""
from __future__ import annotations

import os
import re
from typing import Any, Optional

_STRONG = ("LIKELY", "CONFIRMED")

# A stated moment: an ISO-like date with a time (the forms the anchors use).
# To the second it may carry any offset; to the minute only the zones the
# index parser reads there ("09:00-10:30" is a span, its end not read).
from core.evidence_index import MINUTE_ZONE as _MINUTE_ZONE  # noqa: E402

_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
                      r"|(?![:\d])" + _MINUTE_ZONE + ")")


def window_notes_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_WINDOW_NOTES", True)


def map_window_on() -> bool:
    """ATLAS_MAP_WINDOW (with ATLAS_INCIDENT_MAP): the window comes
    from the incident map's anchored rule, same output shape."""
    from core.envfile import env_flag
    from core.incident_map import map_on
    return map_on() and env_flag("ATLAS_MAP_WINDOW", True)


def _iso(text: str) -> str:
    from core.table_rows import _parse_timestamp
    return (_parse_timestamp(str(text or "").strip()) or "").replace("T", " ")


def leading_time(statement: str) -> str:
    """The first moment a statement states, normalised; "" for none."""
    m = _TIME_RE.search(str(statement or ""))
    return _iso(m.group(0)) if m else ""


def trace_mark() -> int:
    """The newest call id of the trace: where a note is raised."""
    try:
        from core.execution_log import log
        return max((int(e.get("call_id") or 0) for e in getattr(log, "_entries", None) or []), default=0)
    except Exception:  # noqa: BLE001
        return 0


def answered_after(statement: str, mark: int) -> bool:
    """Whether a SUPPORTED evaluation (reason.evaluate_finding) of the
    statement came after trace position ``mark``: an evaluation made
    before a note never answers it. The one rule for a held start and a
    noted event of the incident map."""
    try:
        from core.conclusion_door import _VERDICT_RE
        from core.execution_log import log
        from tools._gates._match import find_reason_call, normalize_desc
        entry = find_reason_call(list(getattr(log, "_entries", None) or []), "reason_evaluate_finding",
                                 normalize_desc(statement), after_call_id=int(mark or 0))
    except Exception:  # noqa: BLE001
        return False
    m = _VERDICT_RE.search(str((entry or {}).get("conclusion") or ""))
    return bool(m and m.group(1).upper() == "SUPPORTED")


def _noted_stands(node: dict[str, Any]) -> bool:
    """A start stated by a claim that drew a window note counts once a
    SUPPORTED evaluation of the claim comes after the note (its trace
    position, window_noted_mark); a re-record that answers the note is a
    new claim without the mark."""
    return answered_after(str(node.get("statement") or ""), int(node.get("window_noted_mark") or 0))


def incident_window(graph: dict[str, Any], exclude: tuple[str, ...] | set[str] = (),
                    rows: tuple | list = (), case_dir: str | os.PathLike | None = None) -> dict[str, Any]:
    """{"hosts": {host: [(time, claim), ...]}, "accounts": {...}, "estate":
    (time, claim) or None, "attacker_accounts", "own_accounts",
    "compromised": {account: time or ""}, "noted": [(kind, value, time,
    claim)]}; each host's and account's list earliest first (the earliest
    is its start). ``exclude``: claims whose rows do not count (a finding
    is judged against the window without its own rows); ``rows``: (claim,
    type, value) rows that do not count (the rows a finding merged into a
    standing claim brought). A start stated by
    a claim that drew a note and stands unsupported is listed under
    "noted", never a start. With ``case_dir`` and the map window on, the
    incident map computes it (core.incident_map.IncidentMap.window: inbound
    edges and fine events anchor too, and hosts with attacker labels and no
    start of their own are listed under "unanchored")."""
    if case_dir and map_window_on():
        try:
            from core import incident_map
            m = incident_map.open(case_dir)
            if m is not None:
                return m.window(exclude, rows)
        except Exception:  # noqa: BLE001 - the typed rows still give a window
            pass
    from core.claim_graph import is_current_belief
    hosts: dict[str, list[tuple[str, str]]] = {}
    accounts: dict[str, list[tuple[str, str]]] = {}
    sides: dict[str, set[str]] = {}
    noted: list[tuple[str, str, str, str]] = []
    skip_rows = {(str(c), str(t), str(v).lower()) for c, t, v in rows}
    for cid, n in (graph.get("nodes") or {}).items():
        if not isinstance(n, dict) or n.get("kind") not in ("claim", "conclusion") or not is_current_belief(n):
            continue
        if str(cid) in exclude:
            continue
        strong = str(n.get("confidence") or "").upper() in _STRONG
        held = bool(n.get("window_noted")) and not _noted_stands(n)
        for r in n.get("indicators") or []:
            if not isinstance(r, dict):
                continue
            kind, value = str(r.get("type") or ""), str(r.get("value") or "")
            if kind == "account" and value:
                sides.setdefault(value, set()).add(str(r.get("side") or ""))
            t = _iso(r.get("attacker_from") or "") if strong else ""
            if not t or kind not in ("host", "account") or not value:
                continue
            if (str(cid), kind, value.lower()) in skip_rows:
                continue
            if held:
                noted.append((kind, value, t, str(cid)))
                continue
            (hosts if kind == "host" else accounts).setdefault(value, []).append((t, str(cid)))
    for d in (hosts, accounts):
        for k in d:
            d[k] = sorted(set(d[k]))
    starts = [v[0] for v in hosts.values()]
    # An account a belief says the attacker acted with (attacker_from) is
    # compromised whatever side it is typed on: the organisation's account
    # the attacker used, never the organisation's own activity.
    acted = {a for a in accounts}
    attacker = sorted(a for a, s in sides.items() if s == {"attacker"})
    own = sorted(a for a, s in sides.items() if "attacker" not in s and s & {"victim", "subject"} and a not in acted)
    both = sorted(a for a, s in sides.items() if s & {"victim", "subject"} and ("attacker" in s or a in acted))
    return {"hosts": hosts, "accounts": accounts, "estate": min(starts) if starts else None,
            "attacker_accounts": attacker, "own_accounts": own, **split_own(own, sides),
            "compromised": {a: (accounts.get(a) or [("", "")])[0][0] for a in both}, "noted": noted}


def split_own(own: list[str], sides: dict[str, set[str]]) -> dict[str, list[str]]:
    """The accounts not typed as the attacker's, by whose they are: the
    subject's (any row sides it with the person under investigation) and
    the victim's (the rest). ``own_accounts`` stays their union."""
    subject = [a for a in own if "subject" in sides.get(a, ())]
    return {"subject_accounts": subject, "victim_accounts": [a for a in own if a not in subject]}


def window_in_frame(window: dict[str, Any], frame: str) -> dict[str, Any]:
    """The window as the case's frame may state it (core.indicators.frame_for):
    whole in the incident frame. Outside it the brief names no victim of an
    intrusion, so an attacker label with no stated time states no window:
    the hosts listed for having one (``unanchored``) are left out unless a
    start is stated. Stated starts, accounts typed as the attacker's and
    accounts the attacker used stay, since evidence of an intruder speaks
    in any frame. window_lines and the exit's lines read the frame from it."""
    w = dict(window)
    w["frame"] = frame
    if frame != "incident" and not (w.get("estate") or w.get("hosts") or w.get("accounts")):
        w["unanchored"] = []
    return w


def _host_start(window: dict[str, Any], host: str) -> Optional[tuple[str, str]]:
    for h, starts in window["hosts"].items():
        if host and h.casefold() == host.casefold():
            return starts[0]
    return None


def before_window(window: dict[str, Any], host: str, statement: str) -> Optional[dict[str, str]]:
    """When a statement leads with a time before its host's first attacker
    activity (the estate start when the host has none): the times and the
    claims that state them; else None."""
    lead = leading_time(statement)
    if not lead:
        return None
    start = _host_start(window, host)
    estate = window.get("estate")
    ref = start or estate
    if not ref or lead >= ref[0]:
        return None
    return {"lead": lead, "host": host or "", "host_start": start[0] if start else "",
            "host_claim": start[1] if start else "", "estate_start": estate[0] if estate else "",
            "estate_claim": estate[1] if estate else ""}


def window_note(case_dir: str | os.PathLike, statement: str, host: str, claim_id: str = "",
                rows: tuple | list = ()) -> str:
    """The record-time note for a finding leading with a time before the
    window the other current beliefs state (the finding's own rows never
    move the window it is judged against); "" when none."""
    if not window_notes_on():
        return ""
    from core.claim_graph import load_graph
    hit = before_window(incident_window(load_graph(case_dir), exclude={claim_id} if claim_id else (),
                                        rows=rows, case_dir=case_dir), host, statement)
    if not hit:
        return ""
    where = (f"the current beliefs place the first attacker activity on {hit['host']} at {hit['host_start']} "
             f"({hit['host_claim']})" if hit["host_start"] else
             f"the current beliefs state no attacker activity on {hit['host'] or 'this host'}")
    estate = (f" and in the estate at {hit['estate_start']} ({hit['estate_claim']})"
              if hit["estate_start"] else "")
    return (f"This finding leads with {hit['lead']}{' on ' + hit['host'] if hit['host'] else ''}; {where}{estate}. "
            "Say why this row is the attacker's, or record it as the owner's activity.")


def claim_is_new(case_dir: str | os.PathLike, result: dict[str, Any], mirror: Any, finding_call_id: Any) -> bool:
    """Whether the record created its claim: the mirror's own word when it
    gives one, else the claim node whose source finding is this record's
    call (a claim merged into keeps its own source finding)."""
    if isinstance(mirror, dict) and "created" in mirror:
        return bool(mirror["created"])
    cid = str(result.get("claim_id") or "")
    if not cid or not finding_call_id:
        return False
    try:
        from core.claim_graph import load_graph
        node = (load_graph(case_dir).get("nodes") or {}).get(cid) or {}
        return str(node.get("source_finding_call_id") or "") == str(finding_call_id)
    except Exception:  # noqa: BLE001
        return False


def note_after_record(case_dir: str | os.PathLike, result: dict[str, Any], statement: str, host: str, *,
                      created: bool) -> str:
    """The window note for a finding just recorded (``result`` is the
    record's result), and the mark that holds a noted new claim's starts.
    A new claim is judged without its own rows; a finding merged into a
    standing claim is judged without the window rows it brought, and the
    survivor is never marked (its starts that counted stay counted). A
    new claim is marked unless it replaced a claim that itself drew the
    note (a re-record answering it)."""
    from core.claim_graph import load_graph, mark_window_noted
    cid = str(result.get("claim_id") or "")
    brought = [(cid, str(r.get("type") or ""), str(r.get("value") or ""))
               for r in result.get("indicators_kept") or [] if r.get("attacker_from")]
    note = window_note(case_dir, statement, host, claim_id=cid if created else "",
                       rows=() if created else brought)
    if note and cid and created:
        nodes = load_graph(case_dir).get("nodes") or {}
        answers = any((nodes.get(str(result.get(k) or "")) or {}).get("window_noted")
                      for k in ("superseded_claim_id", "also_superseded_claim_id"))
        if not answers:
            mark_window_noted(case_dir, cid, mark=trace_mark())
    return note


# What the window states about an attacker: without any of it, a case
# outside the incident frame gets no WINDOW block at all.
_ATTACKER_DATA = ("estate", "hosts", "accounts", "attacker_accounts", "compromised", "noted", "unanchored")


def window_lines(window: dict[str, Any]) -> list[tuple[str, str]]:
    """The composer's WINDOW block as (id, text) lines t1, t2, ..., in the
    words of the window's frame (window_in_frame; incident when unset). In
    the incident frame one line says no belief states a window when none
    does, and the victim's accounts are the organisation's. Outside it the
    absence of a start is no fact to state (no attacker is presumed), the
    victim's accounts are the system owner's, and a window with no attacker
    data gives no line. The subject's accounts are the subject's in any
    frame."""
    incident = window.get("frame", "incident") == "incident"
    if not incident and not any(window.get(k) for k in _ATTACKER_DATA):
        return []
    lines: list[str] = []
    if window.get("estate"):
        t, c = window["estate"]
        lines.append(f"first attacker activity in the estate: {t} ({c})")
    for h, starts in sorted(window["hosts"].items()):
        lines.append(f"first attacker activity on {h}: {starts[0][0]} ({starts[0][1]})"
                     + ("; also stated: " + ", ".join(f"{t} ({c})" for t, c in starts[1:]) if len(starts) > 1 else ""))
    for a, starts in sorted(window["accounts"].items()):
        lines.append(f"first attacker use of account {a}: {starts[0][0]} ({starts[0][1]})")
    if window.get("attacker_accounts"):
        lines.append("accounts typed as the attacker's: " + ", ".join(window["attacker_accounts"][:12]))
    victim = window["victim_accounts"] if "victim_accounts" in window else window.get("own_accounts") or []
    if victim:
        lines.append(("accounts typed only as the organisation's: " if incident
                      else "accounts typed as the system owner's: ") + ", ".join(victim[:12]))
    if window.get("subject_accounts"):
        lines.append("accounts typed as the subject's: " + ", ".join(window["subject_accounts"][:12]))
    if window.get("compromised"):
        lines.append(("the organisation's accounts the attacker used: " if incident
                      else "accounts of the owner or the subject the attacker used: ") + ", ".join(
            f"{a}{' from ' + t if t else ''}" for a, t in sorted(window["compromised"].items())[:12]))
    unanchored = window.get("unanchored") or []
    if unanchored and window.get("estate"):
        lines.append("no start stated for " + ", ".join(unanchored[:12])
                     + f"{' and more' if len(unanchored) > 12 else ''}: they take the estate start "
                     f"{window['estate'][0]}; if that start is itself before the intrusion, their earlier "
                     "activity reads as inside the window")
    elif unanchored:
        lines.append("attacker labels and no anchor stated on: " + ", ".join(unanchored[:12])
                     + (" and more" if len(unanchored) > 12 else ""))
    for kind, value, t, c in window.get("noted") or []:
        lines.append(f"stated by a noted claim, not yet a window: first attacker activity "
                     f"{'on' if kind == 'host' else 'with account'} {value} at {t} ({c})")
    if incident and not window.get("estate"):
        lines.insert(0, "no host window: no belief states when the attacker first acted on a host"
                     if window.get("accounts") else "no belief states when the attacker first acted (no window)")
    return [(f"t{i}", text) for i, text in enumerate(lines, 1)]
