"""The Atlas dashboard as an ASGI application (Starlette).

``create_app(cases_root)`` returns the application; ``dashboard/serve.py``
is the launcher that binds it with uvicorn, resolves TLS and writes the
discovery file. Everything a request needs — session lookup, role gating,
the case-scoped read models, static pages and raw case files — is here.

Layout of this module:

- read helpers: case listing, token totals, alerts, response state (pure
  functions over the cases root, reused by the CLI tests);
- request helpers: JSON responses, session cookie, role gate, CSRF check;
- ``GET_ROUTES`` / ``POST_PUBLIC`` / ``POST_GATED``: one function per
  endpoint, keyed by the endpoint name under ``/_dashboard/api/``. The
  tables are the routing; a handler never decides who may call it, the
  dispatcher does (``auth.ROUTE_MIN_ROLE`` through ``auth.can_access``);
- static pages/assets and raw case files through ``StaticFiles`` (ETag +
  304, no symlink escape, no directory listings);
- ``/_dashboard/api/events``: the server-sent change stream (``events.py``)
  that tells each tab *that* a case changed, so it re-fetches at once
  instead of on a timer.

Handlers are plain synchronous functions and run on the thread pool, so the
file-reading read models stay exactly as they are.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import sys
import threading
import time
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from sse_starlette import EventSourceResponse, ServerSentEvent

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import (
    FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response,
)
from starlette.routing import Route
from starlette.staticfiles import NotModifiedResponse, StaticFiles

from dashboard import auth
from dashboard import listen
try:
    from dashboard.events import ChangeFeed
except ImportError:  # watchfiles missing: a code pull without pip install
    ChangeFeed = None

SESSION_COOKIE = "atlas_session"
# Endpoints reachable with no session at all (the login flow itself, and the
# static assets/pages needed to render it). Everything else needs a valid
# session; per-endpoint role requirements are auth.ROUTE_MIN_ROLE, applied
# through auth.can_access.
PUBLIC_API_ENDPOINTS = frozenset({
    "bootstrap_status", "bootstrap", "login", "logout", "whoami",
    "password_reset/request", "password_reset/confirm",
})
PUBLIC_ASSET_NAMES = frozenset({"login.html", "reset_password.html"})
# assets/ (css/js) and vendor/ (third-party libs) stay public so an
# unauthenticated login.html can actually render — the page files
# themselves (PUBLIC_ASSET_NAMES) are the only individually-listed exception.
PUBLIC_ASSET_PREFIXES = ("assets/", "vendor/")

DASHBOARD_SRC = os.path.dirname(os.path.abspath(__file__))
# What is served from DASHBOARD_SRC, which also holds the server's own Python:
# the top-level pages and the files of the static directories (one level, no
# dotfiles). The pages load nothing else.
DASHBOARD_PAGE_RE = re.compile(r"[A-Za-z0-9_-]+\.html")
DASHBOARD_STATIC_RE = re.compile(
    "(?:" + "|".join(re.escape(p) for p in PUBLIC_ASSET_PREFIXES) + r")(?!\.)[A-Za-z0-9_.-]+")
DASHBOARD_PREFIX = "/_dashboard/"
API_PREFIX = "/_dashboard/api/"
TRACE_RE = re.compile(r".*_trace\.json$", re.IGNORECASE)

# JSON POST bodies are small; the one upload endpoint gets its own budget.
BODY_LIMIT = 65536
BODY_LIMITS = {
    # A zipped addon (base64-encoded) is bigger than the 64KB every other
    # config POST body is capped at — 10MB raw upload budget (~7.5MB of
    # actual zip once base64's ~33% overhead is accounted for), generous
    # for "a few Python files" per docs/addons.md.
    "config/plugins/upload": 10 * 1024 * 1024,
}


# ── read helpers ──────────────────────────────────────────────────────────

_GLOBE_NOTE_DIRS = ("memory", "wiki", "logs", "inbox")
_globe_rebuild_lock = threading.Lock()


def _newest_note_mtime(brain_root: str) -> float | None:
    newest = None
    for d in _GLOBE_NOTE_DIRS:
        for dirpath, _dirs, files in os.walk(os.path.join(brain_root, d)):
            for f in files:
                if not f.endswith(".md"):
                    continue
                try:
                    m = os.path.getmtime(os.path.join(dirpath, f))
                except OSError:
                    continue
                if newest is None or m > newest:
                    newest = m
    return newest


def _maybe_rebuild_globe(brain_root: str, globe_path: str) -> None:
    """Regenerate brain-globe.json when any brain note is newer than it.
    Best-effort: on any failure the caller serves whatever is on disk."""
    newest = _newest_note_mtime(brain_root)
    if newest is None:  # empty brain: keep the endpoint's 404 hint
        return
    try:
        if os.path.getmtime(globe_path) >= newest:
            return
    except OSError:
        pass  # missing file counts as stale
    if os.path.isfile(globe_path):
        try:
            with open(globe_path, encoding="utf-8") as fh:
                existing = json.load(fh)
            # a focused view (atlas brain globe --case/--topic/--mode) was
            # generated deliberately — don't clobber it with a full rebuild
            if (existing.get("mode", "full") != "full"
                    or existing.get("case") or existing.get("topic")):
                return
        except (OSError, json.JSONDecodeError):
            pass
    with _globe_rebuild_lock:
        try:  # another request may have rebuilt while we waited on the lock
            if os.path.getmtime(globe_path) >= newest:
                return
        except OSError:
            pass
        try:
            from core.brain import globe as brain_globe
            data = brain_globe.build()
            os.makedirs(os.path.dirname(globe_path), exist_ok=True)
            tmp = globe_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1)
            os.replace(tmp, globe_path)
        except Exception:  # noqa: BLE001
            return


def _detect_case_id(case_dir: str) -> str | None:
    from core.paths import parse_case_id_from_text
    for name in ("CASE.md", "CLAUDE.md"):
        md = os.path.join(case_dir, name)
        if not os.path.exists(md):
            continue
        try:
            with open(md) as f:
                text = f.read(8192)
        except OSError:
            continue
        cid = parse_case_id_from_text(text)
        if cid:
            return cid
    return None


def case_token_totals(case_dir: str) -> dict:
    """LLM tokens for one case from the usage ledger: every run and every
    role (the analyst, the reasoning and director calls, the report, the
    reviewer and the answer calls), earlier runs imported from their case
    folders included. The traces and transcripts are no source: nudge events
    log a reply twice, the report and reviewer calls are in neither, and a
    fresh start moves the trace."""
    try:
        from core import usage_ledger
        from core.paths import detect_case_id
        case_id = detect_case_id(case_dir) or os.path.basename(os.path.normpath(case_dir))
        t = usage_ledger.totals(case_id)
    except Exception:  # noqa: BLE001 - an unreadable ledger shows no figure
        t = {"input_tokens": 0, "output_tokens": 0}
    return {
        "input_tokens": t["input_tokens"],
        "output_tokens": t["output_tokens"],
        "total_tokens": t["input_tokens"] + t["output_tokens"],
    }


def list_cases(cases_root: str) -> list[dict]:
    """One-level scan under cases_root for case dirs and their trace files."""
    out: list[dict] = []
    try:
        entries = sorted(os.listdir(cases_root))
    except OSError:
        return out
    for name in entries:
        if name.startswith(".") or name == "_dashboard":
            continue
        case_dir = os.path.join(cases_root, name)
        if not os.path.isdir(case_dir):
            continue
        analysis = os.path.join(case_dir, "analysis")
        traces: list[dict] = []
        if os.path.isdir(analysis):
            try:
                for fn in sorted(os.listdir(analysis)):
                    if not TRACE_RE.match(fn):
                        continue
                    p = os.path.join(analysis, fn)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    traces.append({
                        "name": fn,
                        "path": f"/{name}/analysis/{fn}",
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                    })
            except OSError:
                pass
        traces.sort(key=lambda t: t["mtime"], reverse=True)
        tokens = case_token_totals(case_dir)
        out.append({
            "case_id": _detect_case_id(case_dir) or name,
            "case_dir": name,
            "traces": traces,
            "tokens": tokens,
        })
    return out


# ── Live response read model (stdlib-only JSON globbing) ──────────────────
#
# The READ path stays import-free of Atlas modules: it just globs the on-disk
# JSON the MCP tools already write under <case>/monitoring/. The write
# (approval) path lazily imports response.gates — see _post_approval.

def _safe_case_dir(cases_root: str, case: str) -> str | None:
    """Resolve a ?case= folder name to an existing dir, rejecting traversal
    and symlink escapes (a case name that is itself a symlink pointing
    outside cases_root, or realpath disagreeing with the plain join for any
    other reason, must never resolve to somewhere outside cases_root)."""
    if not case or case.startswith(".") or "/" in case or "\\" in case \
            or ".." in case.split("/"):
        return None
    full = os.path.join(cases_root, case)
    if not os.path.isdir(full):
        return None
    real_root = os.path.realpath(cases_root)
    real_full = os.path.realpath(full)
    if real_full != real_root and not real_full.startswith(real_root + os.sep):
        return None
    return full


def _read_json(path: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _glob_json(dir_path: str, pattern: re.Pattern) -> list[dict]:
    out: list[dict] = []
    try:
        names = sorted(os.listdir(dir_path))
    except OSError:
        return out
    for fn in names:
        if not pattern.match(fn):
            continue
        rec = _read_json(os.path.join(dir_path, fn))
        if isinstance(rec, dict):
            out.append(rec)
    return out


_ALERT_RE = re.compile(r"^\d+_.*\.json$")
_ACT_RE = re.compile(r"^ACT-\d+\.json$")


def _ci_resolve_urlpath(cases_root: str, urlpath: str) -> str | None:
    """Case-insensitively resolve a document-root-relative URL path against the
    real filesystem. Returns a corrected `/`-joined URL path when every
    component matches (case-folded) an existing entry and at least one needed
    folding, else None. Defense-in-depth for deep links whose filename casing
    drifted from disk (the classic trace 404). Rejects traversal.
    """
    parts = [p for p in urlpath.split("/") if p]
    if not parts or any(p == ".." for p in parts):
        return None
    current = cases_root
    out: list[str] = []
    corrected = False
    for part in parts:
        try:
            entries = os.listdir(current)
        except OSError:
            return None
        if part in entries:
            match = part
        else:
            lowered = [e for e in entries if e.lower() == part.lower()]
            if len(lowered) != 1:
                return None
            match = lowered[0]
            corrected = True
        out.append(match)
        current = os.path.join(current, match)
    return "/" + "/".join(out) if corrected else None


def list_alerts(case_dir: str) -> list[dict]:
    """All alert files under <case>/monitoring/alerts, newest first by seq."""
    alerts = _glob_json(os.path.join(case_dir, "monitoring", "alerts"), _ALERT_RE)
    alerts.sort(key=lambda a: a.get("seq", 0), reverse=True)
    return alerts


def response_state(case_dir: str) -> dict:
    """Merge suggestions + executions + approvals + open investigation into one
    view. Pending = a suggestion with no execution record yet, keyed by
    action_id so the panel can show approve/deny controls."""
    resp = os.path.join(case_dir, "monitoring", "response")
    suggestions = _glob_json(os.path.join(resp, "suggestions"), _ACT_RE)
    executions = {r.get("action_id"): r
                  for r in _glob_json(os.path.join(resp, "executions"), _ACT_RE)}
    approvals = {r.get("action_id"): r
                 for r in _glob_json(os.path.join(resp, "approvals"), _ACT_RE)}
    now = int(time.time())
    pending: list[dict] = []
    for sug in suggestions:
        aid = sug.get("action_id")
        approval = approvals.get(aid)
        approved = bool(approval and approval.get("expires_at_epoch", 0) >= now)
        pending.append({
            "action_id": aid,
            "detector": sug.get("detector"),
            "description": sug.get("description"),
            "manual_command": sug.get("manual_command"),
            "risk": sug.get("risk"),
            "reversible": sug.get("reversible"),
            "advisory_velo_artifact": sug.get("advisory_velo_artifact"),
            "unresolved_placeholders": sug.get("unresolved_placeholders") or [],
            "denied": bool(sug.get("denied")),
            "approved": approved,
            "executed": aid in executions,
            "status": (
                "executed" if aid in executions
                else "denied" if sug.get("denied")
                else "approved" if approved
                else "needs_approval"
            ),
        })
    open_inv = _read_json(os.path.join(case_dir, "monitoring",
                                       "_open_investigation.json"))
    return {
        "actions": pending,
        "executions": list(executions.values()),
        "open_investigation": open_inv,
    }


class _NonceStore:
    """Per-server single-use nonce ledger. A nonce is issued only by a
    secret-gated GET and consumed exactly once by a POST — this is what makes
    the approval surface CSRF-/replay-safe (a cross-origin page cannot read the
    issued nonce under the browser same-origin policy)."""

    def __init__(self, ttl: int = 300, cap: int = 512):
        self._lock = threading.Lock()
        self._nonces: dict[str, float] = {}
        self._ttl = ttl
        self._cap = cap

    def _prune(self, now: float) -> None:
        for k in [k for k, exp in self._nonces.items() if exp < now]:
            self._nonces.pop(k, None)

    def issue(self) -> str:
        nonce = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            self._prune(now)
            if len(self._nonces) >= self._cap:
                oldest = min(self._nonces, key=self._nonces.get)
                self._nonces.pop(oldest, None)
            self._nonces[nonce] = now + self._ttl
        return nonce

    def consume(self, nonce: str) -> bool:
        if not nonce:
            return False
        now = time.time()
        with self._lock:
            self._prune(now)
            exp = self._nonces.pop(nonce, None)
        return exp is not None and exp >= now


_IMAGE_CONTENT_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
}


def _is_cacheable_image(rel: str) -> bool:
    return os.path.splitext(rel)[1].lower() in _IMAGE_CONTENT_TYPES


def _guess_content_type(rel: str) -> str:
    if rel.endswith(".html"):
        return "text/html; charset=utf-8"
    if rel.endswith(".js"):
        return "application/javascript; charset=utf-8"
    if rel.endswith(".css"):
        return "text/css; charset=utf-8"
    if rel.endswith(".json"):
        return "application/json; charset=utf-8"
    if rel.endswith(".svg"):
        return "image/svg+xml"
    ext = os.path.splitext(rel)[1].lower()
    return _IMAGE_CONTENT_TYPES.get(ext, "application/octet-stream")


# Markup, script, style and SVG (markup too): what the dashboard serves as
# active from its own files, readable as text when a case holds it.
_CASE_TEXT_EXTENSIONS = frozenset({".html", ".js", ".css", ".svg"})


def _case_content_type(rel: str) -> str:
    """A case file's type, from a closed list a browser never runs or applies:
    JSON and raster images keep theirs (the trace viewer reads the one, an
    image is an image), what would run comes as plain text, and anything else
    is a download. With nosniff, no page can then run a script or a style
    sheet from a case file, whatever the dashboard's own mapping learns later.
    """
    ext = os.path.splitext(rel)[1].lower()
    if ext == ".json":
        return "application/json; charset=utf-8"
    if ext in _IMAGE_CONTENT_TYPES:
        return _IMAGE_CONTENT_TYPES[ext]
    if ext in _CASE_TEXT_EXTENSIONS:
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


# ── application context and request helpers ───────────────────────────────

class Ctx:
    """What every handler needs besides the request: where the cases live,
    whether we speak TLS (cookie flags, reset links), and the nonce ledger."""

    def __init__(self, cases_root: str, *, use_tls: bool,
                 host_allowlist: frozenset[str] | None):
        self.cases_root = cases_root
        self.use_tls = use_tls
        self.host_allowlist = host_allowlist
        self.nonces = _NonceStore()

    @property
    def secure_cookies(self) -> bool:
        return (self.use_tls
                or os.environ.get("ATLAS_DASHBOARD_SECURE_COOKIES") == "1")


def _json(obj, status: int = 200) -> JSONResponse:
    return JSONResponse(obj, status_code=status,
                        headers={"Cache-Control": "no-store"})


def _error_json(prefix: str, exc: Exception, status: int = 503) -> JSONResponse:
    """Logs the full exception server-side (may contain paths/detail not safe
    to hand back once callers can be non-admin sessions) and returns only the
    exception class name to the client."""
    sys.stderr.write(f"[dashboard] {prefix}: {exc.__class__.__name__}: {exc}\n")
    return _json({"error": f"{prefix}: {exc.__class__.__name__}"}, status)


def _bytes(body: bytes, *, content_type: str, filename: str) -> Response:
    # Header values travel as Latin-1: a name that needs escaping (one outside
    # it, or one holding a quote) goes in RFC 6266's filename*= form, the way
    # Starlette's FileResponse writes it.
    from urllib.parse import quote
    quoted = quote(filename)
    disposition = (f'attachment; filename="{filename}"' if quoted == filename
                   else f"attachment; filename*=utf-8''{quoted}")
    return Response(body, media_type=content_type, headers={
        "Content-Disposition": disposition,
        "Cache-Control": "no-store",
    })


def _case_404(case: str) -> JSONResponse:
    return _json({"error": f"unknown or invalid case {case!r}"}, 404)


def _session_token(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _current_user(request: Request):
    return auth.get_session_user(_session_token(request))


def _client_ip(request: Request) -> str:
    """The client address as the server reports it, kept only when it parses
    as an address: with proxy headers trusted from the loopback, a local
    connection can put any text into X-Forwarded-For."""
    host = getattr(getattr(request, "client", None), "host", "") or ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return "unparseable" if host else ""


def _set_session_cookie(resp: Response, token: str, ctx: Ctx) -> None:
    # The cookie may outlive the session; the server-side deadline decides.
    # The cookie may not outlive the session it carries: both follow the
    # admin's absolute limit, read now rather than at import.
    resp.set_cookie(SESSION_COOKIE, token,
                    max_age=int(auth.session_max_hours() * 3600),
                    path="/", httponly=True, secure=ctx.secure_cookies,
                    samesite="lax")


def _clear_session_cookie(resp: Response, ctx: Ctx) -> None:
    resp.delete_cookie(SESSION_COOKIE, path="/", httponly=True,
                       secure=ctx.secure_cookies, samesite="lax")


def _path_and_query(request: Request) -> str:
    """The page a request asked for, query included (a deep link to a case
    must come back to that case after sign-in)."""
    query = request.url.query
    return request.url.path + ("?" + query if query else "")


def _redirect_to_login(next_path: str) -> RedirectResponse:
    from urllib.parse import quote
    return RedirectResponse(
        f"{DASHBOARD_PREFIX}login.html?next={quote(next_path, safe='')}",
        status_code=302)


def _require_role(request: Request, endpoint: str):
    """Returns (user, None) if allowed, else (None, response)."""
    user = _current_user(request)
    if user is None:
        return None, _json({"error": "authentication required"}, 401)
    if not auth.can_access(user, endpoint):
        return None, _json({"error": "insufficient role"}, 403)
    return user, None


def _csrf_ok(ctx: Ctx, request: Request) -> bool:
    """CSRF guard for the mutating JSON endpoints. A cross-origin page cannot
    send application/json without a CORS preflight this server never answers,
    so requiring JSON already blocks blind CSRF; when an Origin header is
    present we additionally require it to match our own host."""
    ctype = (request.headers.get("content-type") or "").split(";")[0]
    if ctype.strip().lower() != "application/json":
        return False
    origin = request.headers.get("origin")
    if origin:
        parsed_origin = urlparse(origin)
        if ctx.host_allowlist is not None and not listen.host_header_allowed(
                parsed_origin.netloc, ctx.host_allowlist):
            return False
        host = request.headers.get("host") or ""
        if origin not in (f"http://{host}", f"https://{host}"):
            return False
    return True


async def _read_body(request: Request, max_bytes: int) -> dict | None:
    try:
        length = int(request.headers.get("content-length") or 0)
    except ValueError:
        return None
    if length <= 0 or length > max_bytes:
        return None
    raw = await request.body()
    if len(raw) > max_bytes:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


# ── GET handlers: (ctx, request, query) -> Response ───────────────────────

def _get_bootstrap_status(ctx, request, q):
    return _json({"needs_setup": not auth.has_any_users()})


def _get_whoami(ctx, request, q):
    user = _current_user(request)
    if user is None:
        return _json({"authenticated": False})
    return _json({
        "authenticated": True,
        "user": {"id": user.id, "username": user.username,
                 "email": user.email, "role": user.role},
        "viewer_chat_enabled": auth.viewer_chat_enabled(),
    })


def _get_cases(ctx, request, q):
    return _json({"cases_root": ctx.cases_root,
                  "cases": list_cases(ctx.cases_root)})


def _get_runs_active(ctx, request, q):
    # Case-wide on purpose: the shell's activity indicator has to report a
    # live run whichever case is selected, and name the cases it found.
    # Deliberately cheaper than "cases", which stats every trace file — this
    # one is polled on a timer.
    from dashboard import read_models, run_manager
    running = read_models.active_runs(ctx.cases_root)
    # A run the dashboard started shows at once, before its first status
    # write (a few seconds after the start).
    listed = {r.get("case_dir") for r in running}
    for sess in run_manager.MANAGER.alive_sessions():
        if sess.case_name not in listed:
            running.append({
                "case_dir": sess.case_name, "case_id": sess.case_name, "activity": "starting",
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sess.started_at)),
                "started_by": sess.started_by})
    return _json({"running": running})


def _get_tokens(ctx, request, q):
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    return _json({"case": os.path.basename(full), **case_token_totals(full)})


def _get_alerts(ctx, request, q):
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    return _json({"alerts": list_alerts(full)})


def _get_response(ctx, request, q):
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    return _json(response_state(full))


def _get_nonce(ctx, request, q):
    """Issue a single-use approval nonce. Secret-gated: the caller must
    present the shared secret, so a nonce is never handed to an
    unauthenticated (e.g. cross-origin) request."""
    try:
        from response import gates
    except Exception:  # noqa: BLE001
        return _json({"error": "approval subsystem unavailable"}, 503)
    refusal = gates.check_dashboard_secret(
        request.headers.get("x-atlas-approval-secret"))
    if refusal:
        return _json(refusal, refusal.get("http_status", 403))
    return _json({"nonce": ctx.nonces.issue()})


def _get_brain_globe(ctx, request, q):
    """Serve the Brain Earth JSON (fixed path only — no parameters, no
    traversal surface), rebuilding it in-process when any brain note is newer
    than the file so the globe stays live."""
    brain_root = os.environ.get("ATLAS_BRAIN_ROOT") or os.path.join(
        os.path.dirname(DASHBOARD_SRC), "brain")
    globe = os.path.join(brain_root, "analytics", "globe", "brain-globe.json")
    _maybe_rebuild_globe(brain_root, globe)
    if not os.path.isfile(globe):
        return _json({"error": "no Brain Earth data — run `atlas brain globe` "
                               "first"}, 404)
    try:
        with open(globe, encoding="utf-8") as fh:
            return _json(json.load(fh))
    except (OSError, json.JSONDecodeError) as e:
        return _json({"error": f"unreadable brain-globe.json: "
                               f"{e.__class__.__name__}"}, 500)


def _get_brain_candidates(ctx, request, q):
    """Pending memory candidates awaiting human review (read-only —
    promotion goes through the POST brain/review dual gate)."""
    try:
        from core.brain import frontmatter
        from core.brain.review_candidates import list_candidates
        items = []
        for it in list_candidates():
            path = it.pop("path")
            try:
                _, body, _ = frontmatter.parse(
                    path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                body = ""
            items.append({**it, "name": path.name, "body": body})
        return _json({"candidates": items})
    except Exception as e:  # noqa: BLE001
        return _error_json("brain unavailable", e)


def _get_brain_search(ctx, request, q):
    query = (q.get("q") or "").strip()
    if not query:
        return _json({"error": "q required"}, 400)
    try:
        limit = int(q.get("limit") or "10")
    except ValueError:
        limit = 10
    try:
        from core.brain.search import search
        hits = search(query, limit=max(1, min(limit, 25)))
        return _json({
            "query": query,
            "hits": [{
                "title": h.title,
                "path": h.rel_path,
                "type": h.type,
                "score": h.score,
                "snippet": h.snippet,
                "updated": h.updated,
            } for h in hits],
        })
    except Exception as e:  # noqa: BLE001
        return _error_json("brain search failed", e)


def _get_brain_learn_status(ctx, request, q):
    case = (q.get("case") or "").strip()
    if not case:
        return _json({"status": None})
    full = _safe_case_dir(ctx.cases_root, case)
    if full is None:
        return _json({"error": "unknown case"}, 404)
    path = os.path.join(full, ".atlas", "brain_learn.json")
    if not os.path.isfile(path):
        return _json({"status": None})
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return _json(data if isinstance(data, dict) else {"status": "unknown"})
    except (OSError, json.JSONDecodeError) as e:
        return _error_json("learn_status unavailable", e, 500)


def _get_chat_poll(ctx, request, q):
    """Chat events for a case after cursor `since`, plus busy/alive flags.
    Requires analyst+ (or viewer with the chat toggle on) — see
    auth.ROUTE_MIN_ROLE."""
    case = q.get("case", "")
    if _safe_case_dir(ctx.cases_root, case) is None:
        return _case_404(case)
    try:
        since = int(q.get("since") or "0")
    except (ValueError, TypeError):
        since = 0
    try:
        from dashboard import chat
        session = chat.MANAGER.peek(case)
    except Exception as e:  # noqa: BLE001
        return _error_json("chat poll failed", e)
    if session is None:
        return _json({"events": [], "total": 0, "busy": False, "alive": False})
    return _json(session.snapshot(since))


def _get_claim_graph(ctx, request, q):
    """Serve <case>/.atlas/claim_graph.json for Claim View."""
    case = q.get("case", "")
    full = _safe_case_dir(ctx.cases_root, case)
    if full is None:
        return _case_404(case)
    path = os.path.join(full, ".atlas", "claim_graph.json")
    data = _read_json(path)
    if data is None:
        return _json({"error": "no claim_graph.json — run an investigation "
                               "or atlas rerun first",
                      "case": case, "path": ".atlas/claim_graph.json"}, 404)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    return _json({"case": case, "mtime": mtime, "graph": data})


def _get_evidence_board(ctx, request, q):
    """The claim graph arranged for Case Findings: hosts, version
    chains, attention flags and band counts on top of the raw graph."""
    case = q.get("case", "")
    full = _safe_case_dir(ctx.cases_root, case)
    if full is None:
        return _case_404(case)
    from dashboard import read_models
    data = read_models.evidence_board(full)
    if data.get("graph") is None:
        return _json({"error": "no claim_graph.json — run an investigation "
                               "or atlas rerun first",
                      "case": case, "path": ".atlas/claim_graph.json"}, 404)
    return _json({"case": case, **data})


def _get_investigation_state(ctx, request, q):
    """Full Current Investigation State snapshot (compact by default)."""
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    compact = (q.get("compact") or "1").lower() not in ("0", "false", "no")
    try:
        from core.investigation_state import build_current_investigation_state
        return _json(build_current_investigation_state(full, compact=compact))
    except Exception as e:  # noqa: BLE001
        return _error_json("investigation_state unavailable", e)


def _get_investigation_board(ctx, request, q):
    """Per-case investigation tasks + plan for the Investigation Board.

    Strictly scoped to the requested case directory — never mixes cases.
    """
    case = q.get("case", "")
    full = _safe_case_dir(ctx.cases_root, case)
    if full is None:
        return _case_404(case)
    try:
        from core.investigation_tasks import load_tasks
        from core.investigation_plan import load_plan
        store = load_tasks(full)
        plan = load_plan(full)
        tasks = list(store.get("tasks") or [])
        counts: dict[str, int] = {}
        for t in tasks:
            st = t.get("status") or "unknown"
            counts[st] = counts.get(st, 0) + 1
        mtimes = []
        for rel in (".atlas/investigation_tasks.json",
                    ".atlas/investigation_plan.json"):
            p = os.path.join(full, rel)
            try:
                mtimes.append(os.path.getmtime(p))
            except OSError:
                pass
        mtime = max(mtimes) if mtimes else None
        busy = False
        try:
            # Best-effort: recent agent transcript growth ≈ working
            analysis = os.path.join(full, "analysis")
            if os.path.isdir(analysis):
                newest = None
                for name in os.listdir(analysis):
                    if name.startswith("agent_transcript_") and name.endswith(".jsonl"):
                        tp = os.path.join(analysis, name)
                        try:
                            mt = os.path.getmtime(tp)
                        except OSError:
                            continue
                        if newest is None or mt > newest:
                            newest = mt
                if newest is not None and (time.time() - newest) < 90:
                    busy = True
        except Exception:  # noqa: BLE001
            busy = False
        return _json({
            "case": case,
            "case_id": store.get("case_id") or plan.get("case_id") or "",
            "mtime": mtime,
            "busy": busy,
            "tasks": tasks,
            "counts": counts,
            "plan": {
                "updated_at": plan.get("updated_at"),
                "steps": plan.get("steps") or [],
                "actionable_task_ids": plan.get("actionable_task_ids") or [],
                "blocked_task_ids": plan.get("blocked_task_ids") or [],
                "focus_hosts": plan.get("focus_hosts") or [],
            },
        })
    except Exception as e:  # noqa: BLE001
        return _error_json("investigation_board unavailable", e)


def _get_case_overview(ctx, request, q):
    """Investigator-facing Case Overview projection (read-only).

    Aggregates questions (with derived answers), claim summary, activity,
    evidence and report status in one case-scoped call. Answers are
    projections of the claim graph — see dashboard/read_models.py for the
    architectural decision.
    """
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    try:
        from dashboard import read_models
        return _json(read_models.case_overview(full))
    except Exception as e:  # noqa: BLE001
        return _error_json("case_overview unavailable", e)


def _get_questions(ctx, request, q):
    """Questions view projection: CASE.md-derived tasks with answers derived
    from the claim graph (never stored separately)."""
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    try:
        from dashboard import read_models
        out = read_models.questions_projection(full)
        out["busy"] = read_models.agent_busy(full)
        return _json(out)
    except Exception as e:  # noqa: BLE001
        return _error_json("questions unavailable", e)


def _get_brain_knowledge(ctx, request, q):
    """Browsable list of durable Brain knowledge (wiki + memory).

    Read-only; excludes confidential notes unless the caller presents the
    approval secret (same gate as the write endpoints).
    """
    try:
        from core.brain import store
        notes = []
        for note in store.iter_notes(include_confidential=False):
            meta = note.meta or {}
            notes.append({
                "title": note.title,
                "type": note.type,
                "tags": note.tags,
                "path": note.rel_path,
                "updated": str(meta.get("updated") or meta.get("created") or ""),
                "case": meta.get("case") or meta.get("source_case"),
                "body": (note.body or "").strip()[:2000],
            })
        notes.sort(key=lambda n: n["updated"], reverse=True)
        return _json({"notes": notes, "count": len(notes)})
    except Exception as e:  # noqa: BLE001
        return _error_json("brain unavailable", e)


def _get_report_export(ctx, request, q):
    """One report file as markdown, HTML or PDF.

    The name is looked up in the listing the Report tab is built from
    (read_models.list_report_files), never joined to a directory here: every
    report the tab lists can be downloaded, including one that sits in a
    rerun snapshot, and the download is the file the tab previews.

    Markdown is served as it stands; the other two are rendered on request
    from that same file, so what a reader downloads always matches the report
    on disk rather than a copy that went stale when the run wrote again.
    """
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    fmt = (q.get("format") or "md").strip().lower()
    if fmt not in ("md", "markdown", "html", "pdf"):
        return _json({"error": f"unsupported format {fmt!r} — "
                               "use md, html or pdf"}, 400)
    from dashboard import read_models
    name = os.path.basename(q.get("name") or "")
    entry = next((f for f in read_models.list_report_files(full)
                  if f["kind"] == "report" and f["name"] == name), None)
    # The listing keeps to the case's own reports directory already; this
    # route reads what it is given, so it checks that again itself.
    root = os.path.realpath(os.path.join(full, "reports"))
    source = os.path.realpath(entry["abs_path"]) if entry else ""
    if not source.startswith(root + os.sep) or not os.path.isfile(source):
        return _json({"error": "no such report file for this case"}, 404)
    case = os.path.basename(full)
    stem = os.path.splitext(name)[0]
    try:
        from pathlib import Path as _Path
        raw = _Path(source).read_bytes()
    except OSError as e:  # noqa: BLE001
        return _error_json("report unreadable", e)
    if fmt in ("md", "markdown"):
        return _bytes(raw, content_type="text/markdown", filename=name)
    # The renderers take text. A byte that is not UTF-8 shows as U+FFFD in
    # the rendered copy; the Markdown download above keeps the exact bytes.
    text = raw.decode("utf-8", errors="replace")
    if fmt == "html":
        from agent.report import render_html
        body = render_html(text, title=f"{case} report")
        return _bytes(body.encode("utf-8"), content_type="text/html",
                      filename=f"{stem}.html")
    from core.report_pdf import render_pdf
    try:
        data = render_pdf(text, title=f"{case} report", case_id=case)
    except RuntimeError as e:  # fpdf2 absent — say so, do not 500
        return _json({"error": str(e)}, 503)
    except Exception as e:  # noqa: BLE001
        return _error_json("pdf render failed", e)
    return _bytes(data, content_type="application/pdf",
                  filename=f"{stem}.pdf")


def _get_report_bundle(ctx, request, q):
    """ZIP of all report deliverables for a case (markdown + timeline).

    Case-scoped; excludes process traces and internal snapshots.
    """
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    try:
        from dashboard import read_models
        data = read_models.build_report_bundle_zip(full)
    except Exception as e:  # noqa: BLE001
        return _error_json("report_bundle unavailable", e)
    if not data:
        return _json({"error": "no report files available for this case"}, 404)
    case = os.path.basename(full)
    return _bytes(data, content_type="application/zip",
                  filename=f"{case}_reports.zip")


def _get_timeline_template(ctx, request, q):
    """Empty master_timeline.tsv header — only when timeline plugin is on.

    Optional ``?case=`` is accepted for deep-link symmetry but unused; the
    template is the plugin's column schema, not case data.
    """
    try:
        from dashboard import read_models
        tsv = read_models.timeline_template_tsv()
    except Exception as e:  # noqa: BLE001
        return _error_json("timeline_template unavailable", e)
    if tsv is None:
        return _json({"error": "timeline_builder plugin is not active"}, 404)
    return _bytes(tsv.encode("utf-8"),
                  content_type="text/tab-separated-values; charset=utf-8",
                  filename="master_timeline_template.tsv")


def _get_capabilities(ctx, request, q):
    """Dashboard feature flags (e.g. whether Timeline nav should appear)."""
    try:
        from dashboard import read_models
        active = read_models.timeline_plugin_active()
    except Exception:  # noqa: BLE001
        active = False
    return _json({"timeline_plugin_active": active})


def _get_config_llm(ctx, request, q):
    from dashboard import config_llm
    return _json(config_llm.list_providers())


def _get_config_effort(ctx, request, q):
    from dashboard import config_effort
    return _json(config_effort.settings())


def _get_config_osint(ctx, request, q):
    from dashboard import config_osint
    return _json(config_osint.status())


def _get_config_tool(ctx, request, q):
    return _json({"viewer_chat_enabled": auth.viewer_chat_enabled()})


def _get_config_users(ctx, request, q):
    return _json({"users": [
        {"id": u.id, "username": u.username, "email": u.email,
         "role": u.role, "is_active": u.is_active, "created_at": u.created_at}
        for u in auth.list_users()]})


def _get_config_mail(ctx, request, q):
    from core import mail
    return _json(mail.status())


def _get_config_mitre(ctx, request, q):
    from dashboard import config_mitre
    return _json(config_mitre.status())


def _get_config_session(ctx, request, q):
    # Session limits: how long a signed-in user stays signed in.
    return _json(auth.session_limits())


def _get_config_share(ctx, request, q):
    from dashboard import config_share
    return _json(config_share.status())


def _get_config_plugins(ctx, request, q):
    from dashboard import config_plugins
    return _json(config_plugins.status())


def _get_config_tools(ctx, request, q):
    # Tool health: every program a tool needs, whether it is on this machine,
    # and what should have installed it. Read-only.
    from core.tool_health import probe
    return _json(probe())


def _get_case_recommendations(ctx, request, q):
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    # Derived from the claim graph on every request, like the IOC view.
    try:
        from dashboard.read_models import recommendation_catalog
        return _json(recommendation_catalog(full))
    except Exception as e:  # noqa: BLE001
        return _error_json("case/recommendations failed", e)


def _get_case_iocs(ctx, request, q):
    full = _safe_case_dir(ctx.cases_root, q.get("case", ""))
    if full is None:
        return _case_404(q.get("case", ""))
    # Derived live from the claim graph on every request, so the tab is
    # current mid-run without the loop paying for it — same contract as the
    # other read models. Never raises: an IOC view must not be able to break
    # the dashboard.
    try:
        from dashboard.read_models import ioc_catalog_with_context
        catalog = ioc_catalog_with_context(full)
        catalog["case"] = os.path.basename(full)
        return _json(catalog)
    except Exception as e:  # noqa: BLE001
        return _error_json("case/iocs failed", e)


def _get_case_md(ctx, request, q):
    case = q.get("case", "")
    if _safe_case_dir(ctx.cases_root, case) is None:
        return _case_404(case)
    from dashboard import case_admin
    try:
        return _json(case_admin.read_case_md(ctx.cases_root, case))
    except case_admin.CaseAdminError as exc:
        return _json({"error": str(exc)}, 400)


def _get_case_run_options(ctx, request, q):
    from dashboard import run_options
    mode = q.get("mode") or "run"
    try:
        return _json({"mode": mode, "options": list(run_options.spec(mode)),
                      "modes": list(run_options.MODES)})
    except run_options.OptionsError as exc:
        return _json({"error": str(exc)}, 400)


def _get_case_run_status(ctx, request, q):
    case = q.get("case", "")
    full = _safe_case_dir(ctx.cases_root, case)
    if full is None:
        return _case_404(case)
    # Whether the case ran before decides the first action the page offers:
    # continue from what changed, or a first run.
    from core.run_state import prior_run_exists
    prior = {"prior_run": prior_run_exists(full)}
    from dashboard import run_manager
    sess = run_manager.MANAGER.get(case)
    if sess is not None and sess.alive:
        return _json({**sess.status(), "dashboard_tracked": True,
                      "external": False, **prior})
    # No live session in this dashboard process's run_manager — but that
    # only means *this dashboard* isn't running it now. Check whether some
    # other process (an `atlas run` from the CLI, or a previous dashboard
    # process before a restart) has it going, via the pid agent/loop.py
    # records in run_status.json. "external" tells the frontend this is a
    # real, live run it can see and must not let Start/Stop touch —
    # dashboard/run_manager.py has no Popen handle for it and can't safely
    # start a second run over it or stop it. A session whose own process
    # has ended is consulted only when nothing else is running: reporting
    # it first showed "run finished" over a live run started from the CLI
    # after the dashboard's own run had been stopped.
    from dashboard import read_models
    running = read_models.run_process_alive(full)
    if not running and sess is not None:
        return _json(_with_elapsed({**sess.status(), "dashboard_tracked": True,
                                    "external": False, **prior}))
    on_disk = read_models._run_status(full) if running else {}
    return _json(_with_elapsed({"case": case, "running": running,
                                "dashboard_tracked": False, "external": running, **on_disk,
                                **prior}))


def _with_elapsed(status: dict) -> dict:
    """A live run's time since its start, on this server's clock: the
    status file's duration is a per-turn snapshot and stands still while a
    turn runs long."""
    if status.get("running"):
        from dashboard import read_models
        elapsed = read_models.seconds_since(status.get("started_at"))
        if elapsed is not None:
            status["elapsed_seconds"] = round(elapsed)
    return status


def _get_config_activity(ctx, request, q):
    try:
        limit = int(q.get("limit") or 500)
    except ValueError:
        limit = 500
    events, count = auth.list_activity(limit)
    return _json({"events": events, "count": count,
                  "retention_days": auth.activity_retention_days()})


def _get_config_activity_export(ctx, request, q):
    import csv
    import io
    import time
    from core.csv_safe import csv_safe
    cols = ("id", "ts", "event", "username", "role", "case_id", "detail", "ip")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    auth.prune_activity()
    for row in auth.all_activity():
        writer.writerow([csv_safe(row[c]) for c in cols])
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return _bytes(buf.getvalue().encode("utf-8"),
                  content_type="text/csv; charset=utf-8",
                  filename=f"atlas-activity-{stamp}.csv")


def _post_config_activity_clear(ctx, request, body):
    removed = auth.clear_activity(user=_current_user(request),
                                  ip=_client_ip(request))
    return _json({"removed": removed})


def _post_config_activity_retention(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        days = auth.set_activity_retention(
            body.get("days"), user=_current_user(request),
            ip=_client_ip(request))
    except auth.AuthError as exc:
        return _json({"error": str(exc)}, 400)
    return _json({"retention_days": days})


def _usage_prices() -> tuple[dict, str]:
    try:
        prices = json.loads(auth.get_setting("llm_prices", "") or "{}")
    except ValueError:
        prices = {}
    if not isinstance(prices, dict):
        prices = {}
    return prices, (auth.get_setting("llm_price_currency", "EUR") or "EUR")


def _usage_window(q):
    period = "week" if q.get("period") == "week" else "month"
    try:
        months = max(1, min(int(q.get("months") or 12), 60))
    except ValueError:
        months = 12
    return period, months


def _get_config_usage(ctx, request, q):
    from core import usage_import, usage_ledger
    from dashboard import read_models
    # Runs from before the ledger are added from their case folders first;
    # a run already known, recorded live or deleted, is never touched.
    imported = usage_import.import_history(ctx.cases_root, busy=read_models.agent_busy)
    period, months = _usage_window(q)
    prices, currency = _usage_prices()
    since = usage_ledger.window_start(period, months).isoformat()
    data = usage_ledger.aggregate(usage_ledger.daily_rows(since), period, prices)
    data.update({"currency": currency, "since": since, "months": months,
                 "imported": imported})
    return _json(data)


def _get_config_usage_export(ctx, request, q):
    import csv
    import io
    import time
    from core import usage_ledger
    from core.csv_safe import csv_safe
    period, months = _usage_window(q)
    prices, currency = _usage_prices()
    since = usage_ledger.window_start(period, months).isoformat()
    merged: dict = {}
    for r in usage_ledger.daily_rows(since):
        # Each day counts in its own period, as on the page: a run that
        # crosses a period boundary is one row in each.
        pk = usage_ledger.period_key(r["day"], period)
        k = (pk, r["case_id"], r["run_id"], r["command"], r["started_by"],
             r["provider"], r["model"])
        m = merged.setdefault(k, {**r, "period": pk, "calls": 0, "input": 0,
                                  "output": 0, "cached": 0, "reasoning": 0,
                                  "unreported": 0})
        for f in ("calls", "input", "output", "cached", "reasoning", "unreported"):
            m[f] += int(r.get(f) or 0)
        m["first_ts"] = min(m["first_ts"], r["first_ts"])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(("period", "case_id", "run_id", "started", "command",
                     "started_by", "provider", "model", "calls",
                     "calls_without_usage", "input_tokens", "output_tokens",
                     "cached_tokens", "reasoning_tokens", "cost", "currency"))
    for m in sorted(merged.values(), key=lambda x: x["first_ts"], reverse=True):
        cost = usage_ledger.row_cost(m, prices)
        writer.writerow([csv_safe(v) for v in (
            m["period"], m["case_id"],
            m["run_id"], m["first_ts"], m["command"], m["started_by"],
            m["provider"], m["model"], m["calls"], m["unreported"], m["input"],
            m["output"], m["cached"], m["reasoning"],
            "" if cost is None else f"{cost:.4f}", currency)])
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return _bytes(buf.getvalue().encode("utf-8"),
                  content_type="text/csv; charset=utf-8",
                  filename=f"atlas-usage-{stamp}.csv")


def _post_config_usage_clear(ctx, request, body):
    from datetime import date
    from core import usage_ledger
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    import sqlite3
    before = str(body.get("before") or "").strip()
    if body.get("all") is True:
        what = "all entries"
    elif before:
        try:
            date.fromisoformat(before)
        except ValueError:
            return _json({"error": "before must be a date (YYYY-MM-DD)"}, 400)
        what = f"entries before {before}"
    else:
        return _json({"error": "say what to remove: all, or before a date"}, 400)
    try:
        removed = usage_ledger.clear(before if body.get("all") is not True else None)
    except sqlite3.Error as exc:
        return _json({"error": f"the usage ledger could not be changed: {exc}"}, 503)
    auth.log_event("usage_cleared", user=_current_user(request),
                   detail=f"{what}: {removed} rows removed", ip=_client_ip(request))
    return _json({"removed": removed})


def _get_config_usage_prices(ctx, request, q):
    import sqlite3
    from dashboard import usage_prices
    try:
        return _json(usage_prices.sync())
    except sqlite3.Error as exc:
        return _json({"error": f"the usage ledger could not be read: {exc}"}, 503)


def _post_config_usage_prices_save(ctx, request, body):
    from dashboard import usage_prices
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        usage_prices.save(body)
    except usage_prices.PriceError as exc:
        return _json({"error": str(exc)}, 400)
    return _get_config_usage_prices(ctx, request, {})


def _post_config_usage_prices_delete(ctx, request, body):
    from dashboard import usage_prices
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        usage_prices.delete(str(body.get("key") or ""))
    except usage_prices.PriceError as exc:
        return _json({"error": str(exc)}, 400)
    return _get_config_usage_prices(ctx, request, {})


GET_ROUTES = {
    "bootstrap_status": _get_bootstrap_status,
    "whoami": _get_whoami,
    "cases": _get_cases,
    "runs/active": _get_runs_active,
    "tokens": _get_tokens,
    "alerts": _get_alerts,
    "response": _get_response,
    "approval/nonce": _get_nonce,
    "brain/globe": _get_brain_globe,
    "brain/candidates": _get_brain_candidates,
    "brain/search": _get_brain_search,
    "brain/learn_status": _get_brain_learn_status,
    "chat/poll": _get_chat_poll,
    "claim_graph": _get_claim_graph,
    "evidence_board": _get_evidence_board,
    "investigation_state": _get_investigation_state,
    "investigation_board": _get_investigation_board,
    "investigation_tasks": _get_investigation_board,
    "case_overview": _get_case_overview,
    "questions": _get_questions,
    "brain/knowledge": _get_brain_knowledge,
    "report_export": _get_report_export,
    "report_bundle": _get_report_bundle,
    "timeline_template": _get_timeline_template,
    "capabilities": _get_capabilities,
    "config/llm": _get_config_llm,
    "config/effort": _get_config_effort,
    "config/osint": _get_config_osint,
    "config/tool": _get_config_tool,
    "config/users": _get_config_users,
    "config/activity": _get_config_activity,
    "config/activity/export": _get_config_activity_export,
    "config/usage": _get_config_usage,
    "config/usage/export": _get_config_usage_export,
    "config/usage/prices": _get_config_usage_prices,
    "config/mail": _get_config_mail,
    "config/session": _get_config_session,
    "config/mitre": _get_config_mitre,
    "config/share": _get_config_share,
    "config/plugins": _get_config_plugins,
    "config/tools": _get_config_tools,
    "case/iocs": _get_case_iocs,
    "case/recommendations": _get_case_recommendations,
    "case/case_md": _get_case_md,
    "case/run/options": _get_case_run_options,
    "case/run/status": _get_case_run_status,
}


# ── POST handlers: (ctx, request, body) -> Response ───────────────────────

def _post_bootstrap(ctx, request, body):
    """Create the first admin account. Only works while zero users exist — a
    race between two concurrent bootstrap requests is resolved by the users
    table's UNIQUE constraint (one wins, the other gets 'username or email
    already in use')."""
    if auth.has_any_users():
        return _json({"error": "setup already completed"}, 403)
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        user = auth.create_user(str(body.get("username") or "").strip(),
                                str(body.get("email") or "").strip(),
                                str(body.get("password") or ""), "admin")
    except auth.AuthError as exc:
        return _json({"error": str(exc)}, 400)
    auth.log_event("bootstrap", user=user, ip=_client_ip(request))
    resp = _json({"success": True})
    _set_session_cookie(resp, auth.create_session(user.id), ctx)
    return resp


def _log_login_failed(request: Request, username: str, reason: str) -> None:
    """A failed sign-in names the account only when the typed name is one:
    anything else may be a password typed into the wrong field, or text
    shaped to mislead whoever reads the log. An attempt on a real account
    carries its id, so guessing against it stands out."""
    ip = _client_ip(request)
    account = (auth.get_user_by_username(username)
               if auth.validate_username(username) is None else None)
    if account is None:
        auth.log_event("login_failed", username="(unknown account)",
                       detail=reason, ip=ip)
        return
    auth.log_event("login_failed", user=account, detail=reason, ip=ip)


def _post_login(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    username = str(body.get("username") or "").strip()
    try:
        user = auth.verify_login(username, str(body.get("password") or ""))
    except auth.AuthError as exc:
        _log_login_failed(request, username, str(exc))
        return _json({"error": str(exc)}, 401)
    auth.log_event("login", user=user, ip=_client_ip(request))
    resp = _json({"success": True})
    _set_session_cookie(resp, auth.create_session(user.id), ctx)
    return resp


def _post_logout(ctx, request, body):
    token = _session_token(request)
    if token:
        user = auth.get_session_user(token)
        auth.revoke_session(token)
        if user is not None:
            auth.log_event("logout", user=user, ip=_client_ip(request))
    resp = _json({"success": True})
    _clear_session_cookie(resp, ctx)
    return resp


def _post_password_reset_request(ctx, request, body):
    """Always returns the same generic response regardless of whether the
    email matches an account — never lets a caller probe for which emails
    are registered."""
    from core import mail
    email = str((body or {}).get("email") or "").strip()
    generic = {"success": True, "message":
               "If that email is registered, a reset link has been sent."}
    user = auth.get_user_by_email(email) if email else None
    if user is not None and user.is_active:
        token = auth.create_password_reset_token(user.id)
        auth.log_event("reset_requested", user=user, ip=_client_ip(request))
        host = request.headers.get("host", "127.0.0.1")
        scheme = "https" if ctx.use_tls else "http"
        reset_url = (f"{scheme}://{host}{DASHBOARD_PREFIX}"
                     f"reset_password.html?token={token}")
        try:
            mail.send_password_reset_email(user.email, reset_url)
        except mail.MailError as exc:
            # Log server-side; the caller still gets the generic response —
            # an SMTP misconfiguration must not leak account existence either.
            sys.stderr.write(f"[dashboard] password reset email failed "
                             f"for user {user.id}: {exc}\n")
    return _json(generic)


def _post_password_reset_confirm(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    token = str(body.get("token") or "")
    new_password = str(body.get("password") or "")
    # Validate BEFORE consuming the token — it's single-use, so a validation
    # failure here must not burn the user's one reset link.
    password_err = auth.validate_password(new_password)
    if password_err:
        return _json({"error": password_err}, 400)
    user_id = auth.consume_password_reset_token(token)
    if user_id is None:
        return _json({"error": "reset link is invalid or has expired"}, 400)
    auth.set_password(user_id, new_password)
    auth.log_event("reset_completed", user=auth.get_user_by_id(user_id),
                   ip=_client_ip(request))
    return _json({"success": True})


def _post_config_llm_probe(ctx, request, body):
    from dashboard import config_llm
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    return _json(config_llm.probe(
        str(body.get("base_url") or ""), str(body.get("api_key") or ""),
        auth_header=str(body.get("auth_header") or ""),
        auth_prefix=body.get("auth_prefix"),
        model=str(body.get("model") or ""),
        name=str(body.get("name") or "")))


def _post_config_llm_save(ctx, request, body):
    from dashboard import config_llm
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(config_llm.save_provider(body))
    except config_llm.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_llm_role(ctx, request, body):
    """One role's provider, from the Settings page's Roles in a run table."""
    from dashboard import config_llm
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(config_llm.assign_role(str(body.get("role") or ""),
                                            str(body.get("provider") or "")))
    except config_llm.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_llm_delete(ctx, request, body):
    from dashboard import config_llm
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(config_llm.delete_provider(str(body.get("name") or "")))
    except config_llm.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_osint_save(ctx, request, body):
    from dashboard import config_osint
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(config_osint.save_config(body))
    except config_osint.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_tool_save(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    auth.set_viewer_chat_enabled(bool(body.get("viewer_chat_enabled")))
    return _json({"viewer_chat_enabled": auth.viewer_chat_enabled()})


def _post_config_mail_save(ctx, request, body):
    from core import mail
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(mail.save_config(body))
    except mail.MailError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_mitre_refresh(ctx, request, body):
    from dashboard import config_mitre
    result = config_mitre.start_refresh()
    return _json(result, 200 if result.get("success") else 409)


def _post_config_session_save(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(auth.set_session_limits(body.get("idle_hours"),
                                             body.get("max_hours")))
    except ValueError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_effort_save(ctx, request, body):
    from dashboard import config_effort
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(config_effort.save(body))
    except (ValueError, FileNotFoundError) as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_mail_test(ctx, request, body):
    from core import mail
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    return _json(mail.test_connection(body))


def _post_config_plugins_enable(ctx, request, body):
    from dashboard import config_plugins
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(config_plugins.enable(str(body.get("name") or "")))
    except config_plugins.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_plugins_disable(ctx, request, body):
    from dashboard import config_plugins
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(config_plugins.disable(str(body.get("name") or "")))
    except config_plugins.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_plugins_upload(ctx, request, body):
    from dashboard import config_plugins
    if body is None:
        return _json({"error": "invalid request body, or upload exceeds the "
                               "10MB limit"}, 400)
    try:
        return _json(config_plugins.upload(str(body.get("name") or ""),
                                           str(body.get("zip_b64") or "")))
    except config_plugins.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_share_enable(ctx, request, body):
    from dashboard import config_share
    try:
        return _json({"success": True, **config_share.enable()})
    except config_share.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_share_disable(ctx, request, body):
    from dashboard import config_share
    try:
        return _json({"success": True, **config_share.disable()})
    except config_share.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_share_set_password(ctx, request, body):
    from dashboard import config_share
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(config_share.save_password(body))
    except config_share.ConfigError as exc:
        return _json({"error": str(exc)}, 400)


def _post_config_users_create(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        user = auth.create_user(
            str(body.get("username") or "").strip(),
            str(body.get("email") or "").strip(),
            str(body.get("password") or ""),
            str(body.get("role") or "viewer"))
    except auth.AuthError as exc:
        return _json({"error": str(exc)}, 400)
    auth.log_event("user_created", user=_current_user(request),
                   detail=f"{user.username} ({user.role})",
                   ip=_client_ip(request))
    return _json({"success": True, "user": {
        "id": user.id, "username": user.username, "email": user.email,
        "role": user.role, "is_active": user.is_active}})


def _user_id_or_400(body):
    try:
        return int(body.get("user_id")), None
    except (TypeError, ValueError):
        return None, _json({"error": "invalid user_id"}, 400)


def _post_config_users_update_role(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    user_id, err = _user_id_or_400(body)
    if err is not None:
        return err
    current = _current_user(request)
    if current is not None and current.id == user_id:
        return _json({"error": "cannot change your own role"}, 400)
    target = auth.get_user_by_id(user_id)
    try:
        auth.update_user_role(user_id, str(body.get("role") or ""))
    except auth.AuthError as exc:
        return _json({"error": str(exc)}, 400)
    auth.log_event("role_changed", user=current,
                   detail=f"{target.username if target else user_id}: "
                          f"{target.role if target else '?'} -> "
                          f"{str(body.get('role') or '')}",
                   ip=_client_ip(request))
    return _json({"success": True})


def _post_config_users_set_active(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    user_id, err = _user_id_or_400(body)
    if err is not None:
        return err
    current = _current_user(request)
    if current is not None and current.id == user_id:
        return _json({"error": "cannot deactivate your own account"}, 400)
    target = auth.get_user_by_id(user_id)
    try:
        auth.set_user_active(user_id, bool(body.get("active")))
    except auth.AuthError as exc:
        return _json({"error": str(exc)}, 400)
    auth.log_event("user_enabled" if body.get("active") else "user_disabled",
                   user=current,
                   detail=target.username if target else str(user_id),
                   ip=_client_ip(request))
    return _json({"success": True})


def _post_config_users_delete(ctx, request, body):
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    user_id, err = _user_id_or_400(body)
    if err is not None:
        return err
    current = _current_user(request)
    if current is not None and current.id == user_id:
        return _json({"error": "cannot delete your own account"}, 400)
    target = auth.get_user_by_id(user_id)
    try:
        auth.delete_user(user_id)
    except auth.AuthError as exc:
        return _json({"error": str(exc)}, 400)
    auth.log_event("user_deleted", user=current,
                   detail=target.username if target else str(user_id),
                   ip=_client_ip(request))
    return _json({"success": True})


def _post_config_users_reset_password(ctx, request, body):
    """Admin-set password — distinct from the self-service token flow
    (_post_password_reset_confirm): no token needed, the admin is already
    authenticated at "admin" role. Still goes through auth.set_password(), so
    it gets the same validation and revokes every existing session for that
    user."""
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    user_id, err = _user_id_or_400(body)
    if err is not None:
        return err
    target = auth.get_user_by_id(user_id)
    try:
        auth.set_password(user_id, str(body.get("new_password") or ""))
    except auth.AuthError as exc:
        return _json({"error": str(exc)}, 400)
    auth.log_event("password_set", user=_current_user(request),
                   detail=target.username if target else str(user_id),
                   ip=_client_ip(request))
    return _json({"success": True})


def _post_case_create(ctx, request, body):
    from dashboard import case_admin
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    requests = body.get("requests") or []
    if not isinstance(requests, list):
        requests = []
    try:
        case_dir = case_admin.create_case(
            ctx.cases_root, str(body.get("case_id") or "").strip(),
            requests=[str(r) for r in requests],
            language=str(body.get("language") or ""))
    except case_admin.CaseAdminError as exc:
        return _json({"error": str(exc)}, 400)
    return _json({"success": True, "case_dir": str(case_dir)})


def _post_case_recommendation_state(ctx, request, body):
    """Open / done / dismissed — the responder's bookkeeping. Analyst and
    admin only (the route table says so); the actor is recorded."""
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    case = str(body.get("case") or "").strip()
    full = _safe_case_dir(ctx.cases_root, case)
    if full is None:
        return _case_404(case)
    user = _current_user(request)
    from core.claim_graph import set_recommendation_state
    result = set_recommendation_state(
        full, str(body.get("id") or ""), str(body.get("state") or ""),
        actor=getattr(user, "username", "") or "",
        note=str(body.get("note") or ""))
    return _json(result, 200 if result.get("success") else 400)


def _post_case_md_save(ctx, request, body):
    from dashboard import case_admin
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    case = str(body.get("case") or "").strip()
    if _safe_case_dir(ctx.cases_root, case) is None:
        return _case_404(case)
    try:
        return _json(case_admin.write_case_md(
            ctx.cases_root, case, str(body.get("content") or "")))
    except case_admin.CaseAdminError as exc:
        return _json({"error": str(exc)}, 400)


def _post_case_md_autofill_propose(ctx, request, body):
    """Scan evidence/, propose confident Evidence Links rows, and ask the
    connected analyst LLM about anything a plain extension check couldn't
    place. Never writes to disk — see autofill_preview."""
    from core import case_autofill
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    case = str(body.get("case") or "").strip()
    case_dir = _safe_case_dir(ctx.cases_root, case)
    if case_dir is None:
        return _case_404(case)
    proposal = case_autofill.build_proposal(case_dir)
    resolved = []
    prior = proposal["prior_knowledge"]
    rewrite = None
    if proposal["unsure"] or prior:
        from agent.llm import LLMError, LLMHubClient
        from core import providers
        client = LLMHubClient(
            provider=providers.role_name("ATLAS_AGENT_PROVIDER"))
        try:
            _ = client.provider
        except Exception as e:  # noqa: BLE001
            return _json({"error": str(e)}, 400)
        if not client.api_key:
            return _json({"error": "no API key for the configured analyst "
                                   "provider"}, 400)
        import time as _time
        from core import usage_ledger
        actor = str(getattr(_current_user(request), "username", "") or "")
        try:
            from pathlib import Path as _Path
            from core.paths import detect_case_id
            with usage_ledger.context(
                    case_id=detect_case_id(_Path(case_dir)) or _Path(case_dir).name,
                    command="autofill", started_by=actor,
                    run_id="autofill-" + _time.strftime("%Y%m%dT%H%M%SZ",
                                                        _time.gmtime())):
                if proposal["unsure"]:
                    resolved = case_autofill.ask_llm_about_unsure(
                        proposal["unsure"], client)
                if prior:
                    rewrite = case_autofill.ask_llm_to_reformat_prior_knowledge(
                        prior, client)
        except LLMError as e:
            return _json({"error": f"LLM call failed: {e}"}, 502)
    return _json({
        "rows": proposal["rows"],
        "unsure": resolved,
        "investigation_requests_empty":
            proposal["investigation_requests_empty"],
        "standard_request": case_autofill.STANDARD_REQUEST,
        # The section as written and, when the model shaped it, the bullets
        # to put there, the requests to move out, and any indicator lost.
        "prior_knowledge": {"original": prior, "rewrite": rewrite},
    })


def _post_case_md_autofill_preview(ctx, request, body):
    """Splice accepted rows into CASE.md text and return it — the browser
    loads the result into the existing editor/Save flow rather than this
    endpoint writing anything itself."""
    from core import case_autofill
    from core.evidence_links import read_case_md
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    case = str(body.get("case") or "").strip()
    case_dir = _safe_case_dir(ctx.cases_root, case)
    if case_dir is None:
        return _case_404(case)
    rows = body.get("rows")
    if not isinstance(rows, list):
        return _json({"error": "rows must be a list"}, 400)
    rows = [r for r in rows if isinstance(r, dict)]
    prior = body.get("prior_knowledge")
    prior = prior if isinstance(prior, dict) else {}
    bullets = [str(b) for b in prior.get("bullets") or [] if str(b).strip()]
    moved = [str(r) for r in prior.get("requests") or [] if str(r).strip()]
    current_md = read_case_md(case_dir)
    try:
        content = case_autofill.splice_case_md(
            current_md, rows,
            add_standard_request=bool(body.get("add_standard_request")))
        if bullets:
            content = case_autofill.splice_prior_knowledge(
                content, bullets, requests=moved)
    except ValueError as e:
        return _json({"error": str(e)}, 400)
    return _json({"content": content})


def _post_case_delete(ctx, request, body):
    from dashboard import case_admin
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(case_admin.delete_case(
            ctx.cases_root, str(body.get("case_id") or "").strip(),
            purge=bool(body.get("purge"))))
    except case_admin.CaseAdminError as exc:
        return _json({"error": str(exc)}, 400)


def _post_case_move(ctx, request, body):
    from dashboard import case_admin
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    try:
        return _json(case_admin.move_case(
            ctx.cases_root, str(body.get("case_id") or "").strip(),
            str(body.get("new_case_id") or "").strip()))
    except case_admin.CaseAdminError as exc:
        return _json({"error": str(exc)}, 400)


def _post_case_run_start(ctx, request, body):
    from dashboard import run_manager
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    case = str(body.get("case") or "").strip()
    if _safe_case_dir(ctx.cases_root, case) is None:
        return _case_404(case)
    mode = str(body.get("mode") or "run").strip()
    options = body.get("options")
    if not isinstance(options, dict):
        options = {}
    # Whoever pressed Start gets the mail when it ends — a run outlives the
    # tab. No address, or no mail server, simply means no notification.
    user = _current_user(request)
    notify = (getattr(user, "email", "") or "") if user else ""
    try:
        sess = run_manager.MANAGER.start(
            ctx.cases_root, case, mode=mode, options=options,
            notify_email=notify,
            started_by=(getattr(user, "username", "") or "") if user else "")
    except run_manager.RunError as exc:
        return _json({"error": str(exc)}, 400)
    # The mode and the flags of its checkboxes and fixed choices; typed
    # text (a question, a model, a path, a host) stays out of the log.
    from dashboard import run_options
    auth.log_event("run_start", user=user, case_id=case,
                   detail=" ".join([mode] + run_options.summary_argv(mode, options)),
                   ip=_client_ip(request))
    return _json({"success": True, "status": sess.status()})


def _post_case_run_stop(ctx, request, body):
    from dashboard import run_manager
    if body is None:
        return _json({"error": "invalid request body"}, 400)
    case = str(body.get("case") or "").strip()
    user = _current_user(request)
    try:
        result = run_manager.MANAGER.stop(
            case, actor=getattr(user, "username", "") or "",
            actor_role=getattr(user, "role", "") or "")
    except run_manager.RunForbidden as exc:
        return _json({"error": str(exc)}, 403)
    except run_manager.RunError as exc:
        return _json({"error": str(exc)}, 400)
    auth.log_event("run_stop", user=user, case_id=case,
                   ip=_client_ip(request))
    return _json(result)


def _approval_gate(ctx, request, body):
    """The dual gate shared by the approval and brain-review writes: shared
    secret header, then a single-use nonce from the body. Returns a refusal
    response, or None when both keys check out."""
    try:
        from response import gates
    except Exception:  # noqa: BLE001
        return _json({"error": "approval subsystem unavailable"}, 503)
    refusal = gates.check_dashboard_secret(
        request.headers.get("x-atlas-approval-secret"))
    if refusal:
        return _json(refusal, refusal.get("http_status", 403))
    if body is None:
        return _json({"error": "invalid JSON body"}, 400)
    if not ctx.nonces.consume(str(body.get("nonce") or "")):
        return _json({"gate": "dashboard_approval",
                      "error": "missing, expired, or already-used nonce."}, 403)
    return None


def _post_brain_review(ctx, request, body):
    """Approve or reject one staged memory candidate — the browser
    counterpart of `atlas brain approve/reject`. Writes durable memory, so it
    sits behind the same dual gate as response approvals: shared secret
    header + single-use nonce."""
    refused = _approval_gate(ctx, request, body)
    if refused is not None:
        return refused
    # basename() strips any traversal; the .md suffix requirement rejects the
    # remaining oddballs ("..", dotfiles).
    name = os.path.basename(str(body.get("candidate") or ""))
    decision = str(body.get("decision") or "").lower()
    if not name.endswith(".md") or decision not in ("approve", "reject"):
        return _json({"error": "candidate (*.md filename) and decision "
                               "(approve|reject) required"}, 400)
    try:
        from core.brain import store
        cand = store.brain_root() / "inbox/memory-candidates" / name
        if decision == "approve":
            from core.brain.approve import approve
            dest = approve(cand, yes=True)
            return _json({"success": True, "decision": "approved",
                          "destination": str(dest)})
        reason = str(body.get("reason") or "").strip()
        if not reason:
            return _json({"error": "a rejection reason is required — it is "
                                   "the audit record"}, 400)
        from core.brain.reject import reject
        archived = reject(cand, reason, yes=True)
        return _json({"success": True, "decision": "rejected",
                      "archived": str(archived)})
    except Exception as e:  # noqa: BLE001
        return _error_json("brain review failed", e, 400)


def _post_brain_edit(ctx, request, body):
    """Edit a pending candidate's proposed entry / title before approve."""
    refused = _approval_gate(ctx, request, body)
    if refused is not None:
        return refused
    name = os.path.basename(str(body.get("candidate") or ""))
    if not name.endswith(".md"):
        return _json({"error": "candidate *.md required"}, 400)
    try:
        from core.brain.edit import edit_candidate
        path = edit_candidate(
            name,
            proposed_entry=body.get("proposed_entry"),
            title=body.get("title"),
            why_reusable=body.get("why_reusable"),
            clear_sensitive=bool(body.get("clear_sensitive")),
        )
        return _json({"success": True, "path": str(path), "name": path.name})
    except Exception as e:  # noqa: BLE001
        return _error_json("brain edit failed", e, 400)


def _post_approval(ctx, request, body):
    refused = _approval_gate(ctx, request, body)
    if refused is not None:
        return refused
    from response import gates
    case = str(body.get("case") or "")
    action_id = str(body.get("action_id") or "")
    decision = str(body.get("decision") or "approve").lower()
    if _safe_case_dir(ctx.cases_root, case) is None:
        return _json({"error": f"unknown case {case!r}"}, 404)
    if not action_id:
        return _json({"error": "action_id required"}, 400)
    if decision == "deny":
        result = gates.deny_dashboard_action(case, action_id)
        return _json({"success": True, **result})
    # key 1: operator typed the action_id verbatim
    operator_text = str(body.get("operator_text") or "")
    refusal = gates.check_dashboard_operator_text(action_id, operator_text)
    if refusal:
        return _json(refusal, refusal.get("http_status", 400))
    record = gates.issue_dashboard_approval(case, action_id, operator_text)
    return _json({"success": True, "action_id": action_id, "approval": record})


def _post_chat_send(ctx, request, body):
    """Forward a user message to the case's chat worker (spawned on first
    use). Behaves like `bin/atlas chat`; the worker runs in its own process
    with cwd=case_dir."""
    if body is None:
        return _json({"error": "invalid JSON body"}, 400)
    case = str(body.get("case") or "")
    if _safe_case_dir(ctx.cases_root, case) is None:
        return _json({"error": f"unknown case {case!r}"}, 404)
    message = str(body.get("message") or "").strip()
    if not message:
        return _json({"error": "message required"}, 400)
    if len(message) > 8000:
        return _json({"error": "message too long (max 8000 chars)"}, 400)
    # The worker is shared by everyone who chats about this case; the role
    # travels with the message so a viewer's turn cannot change the case.
    role = str(getattr(_current_user(request), "role", "") or "")
    try:
        from dashboard import chat
        session = chat.MANAGER.get_or_spawn(ctx.cases_root, case)
    except Exception as e:  # noqa: BLE001
        return _error_json("chat unavailable", e)
    result = session.send(
        message, role=role,
        user=str(getattr(_current_user(request), "username", "") or ""))
    status = 200 if result.get("ok") else (409 if result.get("busy") else 502)
    return _json(result, status)


POST_PUBLIC = {
    "bootstrap": _post_bootstrap,
    "login": _post_login,
    "logout": _post_logout,
    "password_reset/request": _post_password_reset_request,
    "password_reset/confirm": _post_password_reset_confirm,
}

# Role-gated (auth.ROUTE_MIN_ROLE) and CSRF-checked: every mutating endpoint
# must be a same-origin application/json POST.
POST_GATED = {
    "approval": _post_approval,
    "brain/review": _post_brain_review,
    "brain/edit": _post_brain_edit,
    "chat/send": _post_chat_send,
    "config/llm/save": _post_config_llm_save,
    "config/llm/delete": _post_config_llm_delete,
    "config/llm/probe": _post_config_llm_probe,
    "config/llm/role": _post_config_llm_role,
    "config/osint/save": _post_config_osint_save,
    "config/tool/save": _post_config_tool_save,
    "config/mail/save": _post_config_mail_save,
    "config/mail/test": _post_config_mail_test,
    "config/session/save": _post_config_session_save,
    "config/effort/save": _post_config_effort_save,
    "config/mitre/refresh": _post_config_mitre_refresh,
    "config/share/enable": _post_config_share_enable,
    "config/share/disable": _post_config_share_disable,
    "config/share/set_password": _post_config_share_set_password,
    "config/users/create": _post_config_users_create,
    "config/users/update_role": _post_config_users_update_role,
    "config/users/set_active": _post_config_users_set_active,
    "config/users/delete": _post_config_users_delete,
    "config/users/reset_password": _post_config_users_reset_password,
    "config/activity/clear": _post_config_activity_clear,
    "config/activity/retention": _post_config_activity_retention,
    "config/usage/clear": _post_config_usage_clear,
    "config/usage/prices/save": _post_config_usage_prices_save,
    "config/usage/prices/delete": _post_config_usage_prices_delete,
    "config/plugins/enable": _post_config_plugins_enable,
    "config/plugins/disable": _post_config_plugins_disable,
    "config/plugins/upload": _post_config_plugins_upload,
    "case/create": _post_case_create,
    "case/recommendations/state": _post_case_recommendation_state,
    "case/case_md/save": _post_case_md_save,
    "case/case_md/autofill_propose": _post_case_md_autofill_propose,
    "case/case_md/autofill_preview": _post_case_md_autofill_preview,
    "case/delete": _post_case_delete,
    "case/move": _post_case_move,
    "case/run/start": _post_case_run_start,
    "case/run/stop": _post_case_run_stop,
}


# ── static files ──────────────────────────────────────────────────────────

class _Files(StaticFiles):
    """StaticFiles with the dashboard's content types and cache policy.
    Symlinks may not lead outside the directory and directories are never
    listed.

    ``cache_control`` is the policy for everything but images: the pages and
    scripts use ``no-cache`` (revalidated with ETag/304, so an edit is picked
    up on the next reload without re-downloading unchanged files) while case
    files use ``no-store`` — evidence and findings do not belong in a browser
    cache. A binary image under the dashboard may be cached for a day.

    ``content_type`` maps a path to its type, and ``policy``, when given,
    replaces the dashboard's Content-Security-Policy, with nosniff set here,
    on every answer that carries a file (a 304 or a refusal carries none):
    case files are served as data (_case_content_type, CASE_FILE_POLICY)."""

    def __init__(self, *, directory: str, cache_control: str,
                 content_type=_guess_content_type, policy: str = ""):
        super().__init__(directory=directory)
        self.cache_control = cache_control
        self.content_type = content_type
        self.policy = policy

    def file_response(self, full_path, stat_result, scope, status_code=200):
        # A case under a handling stop never serves an image or a video.
        try:
            from core.handling_stop import dashboard_refuses
            refused = dashboard_refuses(full_path)
        except Exception:  # noqa: BLE001
            refused = False
        if refused:
            from starlette.responses import PlainTextResponse
            return PlainTextResponse("refused: a handling stop stands for this case; the file is an image or a video",
                                     status_code=403, headers={"cache-control": "no-store"})
        resp = FileResponse(full_path, status_code=status_code,
                            stat_result=stat_result,
                            media_type=self.content_type(str(full_path)))
        cacheable = (self.cache_control != "no-store"
                     and _is_cacheable_image(str(full_path)))
        resp.headers["cache-control"] = (
            "public, max-age=86400" if cacheable else self.cache_control)
        if self.policy:
            resp.headers["content-security-policy"] = self.policy
            resp.headers["x-content-type-options"] = "nosniff"
        if self.is_not_modified(resp.headers, Headers(scope=scope)):
            return NotModifiedResponse(resp.headers)
        return resp


class _HostAndHeaders:
    """Two things every response needs, as one pure-ASGI middleware: a Host
    header we never bound is refused (400, before any routing), and every
    answer carries the browser hardening headers."""

    def __init__(self, app, allowlist: frozenset[str] | None):
        self.app = app
        self.allowlist = allowlist

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.allowlist is not None and not listen.host_header_allowed(
                Headers(scope=scope).get("host", ""), self.allowlist):
            return await PlainTextResponse("invalid Host", 400)(scope, receive, send)

        async def send_hardened(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message["headers"])
                headers.setdefault("x-content-type-options", "nosniff")
                headers.setdefault("x-frame-options", "DENY")
                headers.setdefault("referrer-policy", "same-origin")
                headers.setdefault("content-security-policy",
                                   CONTENT_SECURITY_POLICY)
            await send(message)

        await self.app(scope, receive, send_hardened)


# The dashboard is entirely self-hosted: no external script, style, font or
# image, no fetch to another origin, no eval and no worker. That makes a strict
# policy cheap. 'unsafe-inline' is unavoidable for scripts and styles because
# every page carries its own inline <script> and one page uses inline event
# handlers, so this does not stop an injected inline script — the escaping in
# assets/shell.js is what does that. What it does stop is the step after: a
# payload cannot pull code from another origin, embed a plugin, retarget a form
# to collect what a viewer types, rewrite relative URLs through <base>, or frame
# the dashboard inside another page.
CONTENT_SECURITY_POLICY = "; ".join((
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
))

# A case file is data the dashboard reads (evidence, the run's analysis, its
# reports), never part of the dashboard. Opened as a page, it is answered with
# this policy in place of the dashboard's: a sandbox, so it gets an origin of
# its own and no script, form or plugin, and nothing it may load. Inline style
# only lays out the browser's own view of an image or a text. The directives
# that do not fall back to default-src are named as well.
CASE_FILE_POLICY = "; ".join((
    "sandbox",
    "default-src 'none'",
    "style-src 'unsafe-inline'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
))


# ── the application ───────────────────────────────────────────────────────

def create_app(cases_root: str, *, use_tls: bool = False,
               host_allowlist: frozenset[str] | None = None) -> Starlette:
    ctx = Ctx(cases_root, use_tls=use_tls, host_allowlist=host_allowlist)
    pages = _Files(directory=DASHBOARD_SRC, cache_control="no-cache")
    case_files = _Files(directory=cases_root, cache_control="no-store",
                        content_type=_case_content_type,
                        policy=CASE_FILE_POLICY)
    feed = ChangeFeed(cases_root) if ChangeFeed is not None else None
    if feed is None:
        sys.stderr.write("[dashboard] live updates off: watchfiles is not "
                         "installed — run: pip install -r requirements.txt "
                         "(pages fall back to polling)\n")

    @asynccontextmanager
    async def lifespan(_app):
        if feed is not None:
            await feed.start()
        try:
            yield
        finally:
            if feed is not None:
                await feed.stop()

    # Session lookups touch SQLite; they run on the thread pool like the
    # handlers so the event loop only ever waits, never blocks.
    async def user_of(request: Request):
        return await run_in_threadpool(_current_user, request)

    async def gate(request: Request, endpoint: str):
        _user, refused = await run_in_threadpool(_require_role, request, endpoint)
        return refused

    async def root(request: Request):
        # Front door: the investigator-facing Case Overview. The trace viewer
        # stays available at dashboard.html (Process).
        dest = (f"{DASHBOARD_PREFIX}overview.html" if await user_of(request)
                else f"{DASHBOARD_PREFIX}login.html")
        return RedirectResponse(dest, status_code=302)

    async def events(request: Request):
        """The live change stream. Says which case changed, nothing more;
        the tab decides what to re-fetch. sse-starlette pings every 15s so
        an idle stream survives proxies, and ends the stream on shutdown."""
        refused = await gate(request, "events")
        if refused is not None:
            return refused
        if feed is None:
            # 204 is the one answer EventSource does not retry: the tab
            # stays on its fast timer instead of reconnecting every few
            # seconds to a feature that is not there.
            return Response(status_code=204)
        sub = feed.subscribe()

        async def stream():
            try:
                yield ServerSentEvent(data="{}", event="hello")
                async for cases in sub.events():
                    for case in sorted(cases):
                        yield ServerSentEvent(data=json.dumps({"case": case}),
                                              event="change")
            finally:
                sub.close()

        return EventSourceResponse(stream(), ping=15,
                                   headers={"Cache-Control": "no-store"})

    async def api_get(request: Request):
        endpoint = request.path_params["endpoint"]
        if endpoint not in PUBLIC_API_ENDPOINTS:
            refused = await gate(request, endpoint)
            if refused is not None:
                return refused
        handler = GET_ROUTES.get(endpoint)
        if handler is None:
            return _json({"error": f"unknown API endpoint: {endpoint}"}, 404)
        q = dict(request.query_params)
        # Safety net: a bug anywhere in a handler (or a module it lazily
        # imports) must answer with a diagnosable error, never a dropped
        # connection. Handlers that already catch their own expected errors
        # are unaffected; this only catches what escapes them.
        try:
            return await run_in_threadpool(handler, ctx, request, q)
        except Exception as e:  # noqa: BLE001
            return _error_json(f"{endpoint} failed", e)

    async def api_post(request: Request):
        endpoint = request.path_params["endpoint"]
        if endpoint in POST_PUBLIC:
            handler = POST_PUBLIC[endpoint]
            # Same footing as the gated POSTs: a page on another site must
            # not be able to sign the visitor in or out, or seed the
            # activity log with names it chose.
            if not _csrf_ok(ctx, request):
                return _json({"error": "request requires a same-origin "
                                       "application/json POST"}, 403)
        elif endpoint in POST_GATED:
            handler = POST_GATED[endpoint]
            refused = await gate(request, endpoint)
            if refused is not None:
                return refused
            if not _csrf_ok(ctx, request):
                return _json({"error": "request requires a same-origin "
                                       "application/json POST"}, 403)
        else:
            return _json({"error": "unknown endpoint"}, 404)
        body = await _read_body(request, BODY_LIMITS.get(endpoint, BODY_LIMIT))
        try:
            return await run_in_threadpool(handler, ctx, request, body)
        except Exception as e:  # noqa: BLE001
            return _error_json(f"{API_PREFIX}{endpoint} failed", e)

    async def dashboard_page(request: Request):
        rel = request.path_params["rel"]
        if rel in ("", "/"):
            rel = "dashboard.html"
        if ".." in rel.split("/") or rel.startswith("/"):
            return PlainTextResponse("forbidden", 403)
        # Decided on the path alone, before any session lookup: the server's
        # own files are not there for anyone, signed in or not.
        if not (DASHBOARD_PAGE_RE.fullmatch(rel) or DASHBOARD_STATIC_RE.fullmatch(rel)):
            return PlainTextResponse(f"not found: {rel}", 404)
        is_public = rel in PUBLIC_ASSET_NAMES or rel.startswith(PUBLIC_ASSET_PREFIXES)
        if not is_public and await user_of(request) is None:
            return _redirect_to_login(_path_and_query(request))
        # `dashboard.html` is the public URL — on disk the file is named
        # trace_viewer.html for historical reasons.
        on_disk = "trace_viewer.html" if rel == "dashboard.html" else rel
        try:
            return await pages.get_response(os.path.normpath(on_disk), request.scope)
        except HTTPException as exc:
            return PlainTextResponse(f"not found: {rel}", exc.status_code)

    async def case_file(request: Request):
        # Raw case-file fallback (report downloads, deep-linked JSON, etc.) —
        # same session requirement as the read-only API surface.
        if await user_of(request) is None:
            return _redirect_to_login(_path_and_query(request))
        path = request.path_params["path"]
        if ".." in path.split("/"):
            return PlainTextResponse("forbidden", 403)
        # Defense-in-depth: if a *.json deep link misses on exact casing,
        # retry a case-insensitive filesystem resolution before 404ing.
        if path.lower().endswith(".json") and not os.path.isfile(
                os.path.join(cases_root, path)):
            fixed = _ci_resolve_urlpath(cases_root, path)
            if fixed:
                path = fixed.lstrip("/")
        try:
            return await case_files.get_response(os.path.normpath(path), request.scope)
        except HTTPException as exc:
            return PlainTextResponse("not found", exc.status_code)

    return Starlette(
        lifespan=lifespan,
        routes=[
            Route("/", root),
            # No icon of its own yet; 204 keeps a browser's automatic
            # request from logging an error on every page.
            Route("/favicon.ico", lambda request: Response(status_code=204), methods=["GET"]),
            Route(f"{API_PREFIX}events", events, methods=["GET"]),
            Route(f"{API_PREFIX}{{endpoint:path}}", api_get, methods=["GET"]),
            Route(f"{API_PREFIX}{{endpoint:path}}", api_post, methods=["POST"]),
            Route(f"{DASHBOARD_PREFIX}{{rel:path}}", dashboard_page, methods=["GET"]),
            Route("/{path:path}", case_file, methods=["GET"]),
        ],
        middleware=[
            Middleware(_HostAndHeaders, allowlist=host_allowlist),
            Middleware(GZipMiddleware, minimum_size=1024),
        ],
    )
