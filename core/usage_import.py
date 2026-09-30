"""Runs from before the usage ledger, added to it from their case folders.

The ledger records a call when the transport makes it, so a run made before
a host had the ledger exists only in its case folder. The folder keeps what
each call spent: the analyst's turns in the run's transcript
(``analysis/agent_transcript_<stamp>.jsonl``; a fresh start moves the
previous run's transcript and trace to ``.atlas/run_history/trace-<stamp>/``)
and the reasoning and director calls in the case trace beside it. A run is
added once, under the key the live ledger uses (the brief's case id and the
transcript's stamp); a run the ledger has rows for, or settled before, is
left alone.

Nothing the folder does not keep is invented: report and reviewer calls,
a chat's own turns, the starved rungs of a turn, and who started the run are
missing from an added run. The trace does not say which process made a
reasoning or director call, so a run takes the ones made within its own
span: a chat's calls outside every run's span are left out, one inside a
run's span is counted with that run. Two configured providers at one host
serving one model leave a call's provider undecided; it keeps the host. A
transcript whose ``run_start`` does not name every role's model cannot tie
the reasoning and director calls to a model and is not added.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator, Optional

from core import usage_ledger

# The roles the transport records for the analyst's turns and the director's
# calls (agent.llm._AGENT_ROLE, tools.dair._DAIR_ROLE); a reasoning call is
# recorded under its tool's name, which the trace keeps as ``tool``.
AGENT_ROLE = "agent"
DAIR_ROLE = "dair"

# A run-history record that ends this close before a transcript starts is
# the same command's preparation step and names the command.
_TRIGGER_GAP = timedelta(minutes=10)


def _ts(raw) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _jsonl(path: Path) -> Iterator[dict]:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    yield obj
    except OSError:
        return


def netloc(url: str) -> str:
    """The host part the transport records for a client without a provider
    name; a bare host comes back as it is."""
    return (url or "").split("//", 1)[-1].split("/", 1)[0]


def configured() -> list[tuple[str, str, str]]:
    """(name, base URL, model) of every provider this process can resolve."""
    from core import providers
    out = []
    for name in providers.names():
        try:
            p = providers.resolve(name)
        except Exception:  # noqa: BLE001 - an unusable entry labels nothing
            continue
        out.append((name, p.base_url or "", p.model or ""))
    return out


def provider_for(url: str, model: str,
                 known: Optional[list[tuple[str, str, str]]] = None) -> str:
    """The configured provider a call to ``model`` at ``url`` (or at a bare
    host) went to: the one there serving the model, else the only one there.
    Empty when no provider or more than one fits."""
    host = netloc(url)
    here = [(n, m) for n, u, m in (configured() if known is None else known)
            if host and netloc(u) == host]
    serving = [n for n, m in here if m == model]
    if len(serving) == 1:
        return serving[0]
    return here[0][0] if len(here) == 1 else ""


def _role_provider(url: str, model: str, known: list[tuple[str, str, str]]) -> str:
    """For a call whose endpoint the history does not name: the one provider
    serving the model, else as for the run's own endpoint."""
    serving = [n for n, _u, m in known if m == model]
    if len(serving) == 1:
        return serving[0]
    return provider_for(url, model, known) or netloc(url)


def _has_role_map(path: Path) -> bool:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            first = json.loads(fh.readline() or "{}")
    except (OSError, ValueError):
        return False
    return (isinstance(first, dict) and first.get("event") == "run_start"
            and isinstance(first.get("roles"), dict))


def _triggers(case_dir: Path) -> list[tuple[datetime, str]]:
    out = []
    for rec in (case_dir / ".atlas" / "run_history").glob("run-*.json"):
        try:
            data = json.loads(rec.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        end = _ts(data.get("finished_at")) or _ts(data.get("started_at"))
        trigger = str(data.get("trigger") or "")
        if end and trigger:
            out.append((end, trigger))
    return out


def _command(triggers: list[tuple[datetime, str]], start: datetime) -> str:
    near = [(end, trig) for end, trig in triggers
            if start - _TRIGGER_GAP <= end <= start + timedelta(seconds=5)]
    if near:
        trigger = max(near)[1]
        if trigger.startswith("cli-") and len(trigger) > 4:
            return trigger[4:]
    return "run"


def run_rows(transcript: Path, known: list[tuple[str, str, str]],
             triggers: list[tuple[datetime, str]]) -> list[dict]:
    """One ledger row per call the run's transcript and trace recorded."""
    starts: list[tuple[datetime, dict, str, str]] = []
    turns: list[tuple[datetime, dict]] = []
    last: Optional[datetime] = None
    for event in _jsonl(transcript):
        ts = _ts(event.get("ts"))
        if ts is None:
            continue
        last = ts if last is None or ts > last else last
        kind = event.get("event")
        if kind == "run_start":
            roles = event.get("roles")
            starts.append((ts, roles if isinstance(roles, dict) else {},
                           str(event.get("base_url") or ""), str(event.get("model") or "")))
        elif kind == "assistant" and starts:
            turns.append((ts, event))
    if not starts or last is None:
        return []

    def segment(ts: datetime) -> tuple[datetime, dict, str, str]:
        return max((s for s in starts if s[0] <= ts), default=starts[0],
                   key=lambda s: s[0])

    command = _command(triggers, starts[0][0])
    base = {"command": command, "started_by": ""}
    rows = []
    for ts, event in turns:
        _start, roles, url, run_model = segment(ts)
        model = str(roles.get("analyst") or run_model)
        counts = [int(event.get(k) or 0) for k in
                  ("input_tokens", "output_tokens", "cached_tokens", "reasoning_tokens")]
        rows.append({**base, "ts": _iso(ts), "role": AGENT_ROLE, "model": model,
                     "provider": provider_for(url, model, known) or netloc(url),
                     "input_tokens": counts[0], "output_tokens": counts[1],
                     "cached_tokens": counts[2], "reasoning_tokens": counts[3],
                     "usage_reported": any(counts),
                     "status": "cut" if event.get("cut_reason") else "ok"})
    # The trace keeps seconds; a call in the run's first second is the run's.
    window_start = starts[0][0].replace(microsecond=0)
    for trace in sorted(transcript.parent.glob("*_trace.jsonl")):
        for line in _jsonl(trace):
            entry = line.get("entry") if isinstance(line.get("entry"), dict) else line
            kind = entry.get("type")
            if kind not in ("reason_call", "dair_call"):
                continue
            ts = _ts(entry.get("ts"))
            if ts is None or not window_start <= ts <= last:
                continue
            tokens_in = int(entry.get("input_tokens") or 0)
            tokens_out = int(entry.get("output_tokens") or 0)
            if not (tokens_in or tokens_out):
                continue
            _start, roles, url, _run_model = segment(ts)
            model = str(roles.get("reason" if kind == "reason_call" else "dair") or "")
            if not model:
                continue
            rows.append({**base, "ts": _iso(ts),
                         "role": (str(entry.get("tool") or "reason")
                                  if kind == "reason_call" else DAIR_ROLE),
                         "model": model, "provider": _role_provider(url, model, known),
                         "input_tokens": tokens_in, "output_tokens": tokens_out,
                         "cached_tokens": 0,
                         "reasoning_tokens": int(entry.get("reasoning_tokens") or 0),
                         "usage_reported": True, "status": "ok"})
    return rows


def _transcripts(root: Path, busy: Callable[[str], bool]) -> Iterator[tuple[Path, Path]]:
    try:
        cases = sorted(p for p in root.iterdir()
                       if p.is_dir() and not p.name.startswith("."))
    except OSError:
        return
    for case_dir in cases:
        current = sorted(case_dir.glob("analysis/agent_transcript_*.jsonl"))
        # The newest transcript of a case whose agent is working may be a
        # run still being written; it is added once the run is over.
        if current and busy(str(case_dir)):
            current = current[:-1]
        for transcript in current:
            yield case_dir, transcript
        for transcript in sorted(case_dir.glob(
                ".atlas/run_history/trace-*/agent_transcript_*.jsonl")):
            yield case_dir, transcript


def import_history(cases_root: str,
                   busy: Callable[[str], bool] = lambda _case: False) -> dict:
    """Add every finished run under ``cases_root`` the ledger does not know.
    Returns how many runs and calls were added; a ledger that cannot be read
    or written stops the pass and is reported, never raised."""
    # ponytail: every pass walks the whole cases root (a glob per case and a
    # set lookup per transcript; only unknown runs are parsed). Skip cases
    # by folder mtime once a root holds more than a few hundred cases.
    from core.paths import detect_case_id
    added = {"runs": 0, "calls": 0}
    try:
        seen = usage_ledger.run_keys()
    except sqlite3.Error as exc:
        return {**added, "error": f"the usage ledger could not be read: {exc}"}
    known: Optional[list[tuple[str, str, str]]] = None
    case_ids: dict[Path, str] = {}
    triggers: dict[Path, list] = {}
    for case_dir, transcript in _transcripts(Path(cases_root), busy):
        if case_dir not in case_ids:
            case_ids[case_dir] = detect_case_id(case_dir) or case_dir.name
        key = (case_ids[case_dir], transcript.stem.rsplit("_", 1)[-1])
        if key in seen or not _has_role_map(transcript):
            continue
        if known is None:
            known = configured()
        if case_dir not in triggers:
            triggers[case_dir] = _triggers(case_dir)
        rows = run_rows(transcript, known, triggers[case_dir])
        try:
            if usage_ledger.import_run(key[0], key[1], rows):
                added["runs"] += 1
                added["calls"] += len(rows)
        except sqlite3.Error as exc:
            return {**added, "error": f"the usage ledger could not be written: {exc}"}
    return added
