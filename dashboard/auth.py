"""Dashboard user accounts, sessions, and RBAC — SQLite-backed.

Single-writer discipline matching core/evidence_index.py's precedent (the
only other SQLite usage in this codebase): one threading.Lock() around every
write, WAL mode, opened fresh per call rather than held open. This module
owns its own database (~/.config/atlas/dashboard/auth.db by default) —
separate from any case data and from .env/keyring-stored service
credentials (core/secrets.py), because user accounts are a materially
different kind of secret with a different lifecycle (many users, each with
their own password + sessions, versus a handful of shared API keys).

Password hashing: Argon2id via argon2-cffi (OWASP-recommended default).
Session tokens: secrets.token_urlsafe(), matching the one existing
precedent for secure token generation in this codebase
(dashboard/serve.py's _NonceStore).

Roles are a strict hierarchy: viewer < analyst < admin. The one exception is
runtime-configurable, not hardcoded: an admin can flip the "viewer_chat"
setting to grant viewers chat access without changing their role.
"""
from __future__ import annotations

import os
import re
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

DEFAULT_DB_PATH = Path(os.environ.get("ATLAS_DASHBOARD_DB")
                       or "~/.config/atlas/dashboard/auth.db").expanduser()

ROLES = ("viewer", "analyst", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}

# A session ends after an idle timeout counted from its last request, and in
# any case after an absolute cap counted from login; every request the
# dashboard answers slides the idle deadline forward, so a tab that is in use
# never logs itself out mid-shift. Both are set by an admin on the Config
# page (written to .env) and read per request, not at import: a limit an
# admin shortens has to take effect on the next request, not the next
# restart. Out-of-range or unreadable values fall back to the defaults —
# authentication must never fail because a setting is malformed.
DEFAULT_SESSION_IDLE_HOURS = 12.0
DEFAULT_SESSION_MAX_HOURS = 24.0 * 7
SESSION_IDLE_BOUNDS = (0.25, 24.0 * 30)
SESSION_MAX_BOUNDS = (0.25, 24.0 * 365)


def _bounded(value: float, default: float, bounds: tuple[float, float]) -> float:
    low, high = bounds
    return value if low <= value <= high else default


def session_idle_hours() -> float:
    """Hours of inactivity before a session ends."""
    from core.envfile import env_float
    return _bounded(env_float("ATLAS_SESSION_IDLE_HOURS",
                              DEFAULT_SESSION_IDLE_HOURS),
                    DEFAULT_SESSION_IDLE_HOURS, SESSION_IDLE_BOUNDS)


def session_max_hours() -> float:
    """Hours after login before a session ends whatever the user does.

    Never below the idle limit: an absolute cap under the idle timeout would
    silently make the idle setting meaningless.
    """
    from core.envfile import env_float
    idle = session_idle_hours()
    value = _bounded(env_float("ATLAS_SESSION_MAX_HOURS",
                               DEFAULT_SESSION_MAX_HOURS),
                     DEFAULT_SESSION_MAX_HOURS, SESSION_MAX_BOUNDS)
    return max(value, idle)


def session_limits() -> dict:
    """What the Config page shows, including whether each is the default."""
    idle, cap = session_idle_hours(), session_max_hours()
    return {
        "idle_hours": idle,
        "max_hours": cap,
        "idle_is_default": idle == DEFAULT_SESSION_IDLE_HOURS,
        "max_is_default": cap == DEFAULT_SESSION_MAX_HOURS,
        "idle_bounds": list(SESSION_IDLE_BOUNDS),
        "max_bounds": list(SESSION_MAX_BOUNDS),
    }


def set_session_limits(idle_hours: float, max_hours: float) -> dict:
    """Write both limits to .env and this process's environment.

    Takes effect on the next request: a request is checked against the
    deadline stored with its session, then sets a new one from these values,
    so a shortened limit applies from each session's next request on.
    """
    from pathlib import Path as _Path

    from core import envfile
    try:
        idle = float(idle_hours)
        cap = float(max_hours)
    except (TypeError, ValueError) as exc:
        raise ValueError("session limits must be numbers (hours)") from exc
    low, high = SESSION_IDLE_BOUNDS
    if not low <= idle <= high:
        raise ValueError(f"idle limit must be between {low} and {high} hours")
    low, high = SESSION_MAX_BOUNDS
    if not low <= cap <= high:
        raise ValueError(f"absolute limit must be between {low} and {high} hours")
    if cap < idle:
        raise ValueError(
            "the absolute limit cannot be shorter than the idle limit")
    env_path = envfile.resolve(_Path(__file__).resolve().parents[1])
    updates = {"ATLAS_SESSION_IDLE_HOURS": f"{idle:g}",
               "ATLAS_SESSION_MAX_HOURS": f"{cap:g}"}
    with envfile.lock():
        envfile.set_values(env_path, updates)
        for key, value in updates.items():
            os.environ[key] = value
    return session_limits()
RESET_TOKEN_TTL_MINUTES = 30
LOCKOUT_MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 15
LOCKOUT_DURATION_MINUTES = 15
MIN_PASSWORD_LENGTH = 8

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_hasher = PasswordHasher()
_write_lock = threading.Lock()


class AuthError(Exception):
    """Raised for validation/uniqueness failures — always safe to show the user."""


@dataclass(frozen=True)
class User:
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str


def role_at_least(role: str, minimum: str) -> bool:
    """True if `role` is `minimum` or higher in the viewer<analyst<admin hierarchy."""
    return ROLE_RANK.get(role, -1) >= ROLE_RANK.get(minimum, 99)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expires_iso(minutes: int = 0, hours: int = 0) -> str:
    return (datetime.now(timezone.utc)
            + timedelta(minutes=minutes, hours=hours)).isoformat()


def _is_expired(iso_ts: str) -> bool:
    return datetime.fromisoformat(iso_ts) <= datetime.now(timezone.utc)


def db_path() -> Path:
    return DEFAULT_DB_PATH


@contextmanager
def _connect():
    db_path().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path()), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        yield conn
    finally:
        conn.close()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token        TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_reset_user ON password_reset_tokens(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL,
    attempted_at TEXT NOT NULL,
    success      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_username ON login_attempts(username, attempted_at);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    event    TEXT NOT NULL,
    user_id  INTEGER,
    username TEXT NOT NULL DEFAULT '',
    role     TEXT NOT NULL DEFAULT '',
    case_id  TEXT NOT NULL DEFAULT '',
    detail   TEXT NOT NULL DEFAULT '',
    ip       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity_log(ts);
"""


def init_db() -> None:
    """Idempotent schema creation — safe to call on every server startup."""
    with _write_lock, _connect() as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


def has_any_users() -> bool:
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return row is not None


# ── validation ────────────────────────────────────────────────────────────

def validate_username(username: str) -> Optional[str]:
    if not _USERNAME_RE.match(username or ""):
        return ("username must be 3-32 characters: letters, digits, "
                "underscore, or hyphen")
    return None


def validate_email(email: str) -> Optional[str]:
    if not _EMAIL_RE.match(email or ""):
        return "not a valid email address"
    return None


def validate_password(password: str) -> Optional[str]:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    return None


def validate_role(role: str) -> Optional[str]:
    if role not in ROLES:
        return f"role must be one of {', '.join(ROLES)}"
    return None


# ── users ─────────────────────────────────────────────────────────────────

def _row_to_user(row: sqlite3.Row) -> User:
    return User(id=row["id"], username=row["username"], email=row["email"],
               role=row["role"], is_active=bool(row["is_active"]),
               created_at=row["created_at"])


def create_user(username: str, email: str, password: str, role: str) -> User:
    for err in (validate_username(username), validate_email(email),
               validate_password(password), validate_role(role)):
        if err:
            raise AuthError(err)
    password_hash = _hasher.hash(password)
    with _write_lock, _connect() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash, role, "
                "is_active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                (username, email, password_hash, role, _now_iso()))
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise AuthError("username or email already in use") from exc
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (cur.lastrowid,)).fetchone()
        return _row_to_user(row)


def get_user_by_id(user_id: int) -> Optional[User]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?",
                           (user_id,)).fetchone()
        return _row_to_user(row) if row else None


def get_user_by_username(username: str) -> Optional[User]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                           (username,)).fetchone()
        return _row_to_user(row) if row else None


def get_user_by_email(email: str) -> Optional[User]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?",
                           (email,)).fetchone()
        return _row_to_user(row) if row else None


def list_users() -> list[User]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM users ORDER BY created_at ASC").fetchall()
        return [_row_to_user(r) for r in rows]


def update_user_role(user_id: int, role: str) -> None:
    if err := validate_role(role):
        raise AuthError(err)
    with _write_lock, _connect() as conn:
        cur = conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
        if cur.rowcount == 0:
            raise AuthError(f"no such user: {user_id}")


def set_user_active(user_id: int, active: bool) -> None:
    """Disable/re-enable an account. Disabling also revokes all sessions."""
    with _write_lock, _connect() as conn:
        cur = conn.execute("UPDATE users SET is_active = ? WHERE id = ?",
                    (1 if active else 0, user_id))
        if not active:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise AuthError(f"no such user: {user_id}")


def delete_user(user_id: int) -> None:
    with _write_lock, _connect() as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise AuthError(f"no such user: {user_id}")


def set_password(user_id: int, new_password: str) -> None:
    """Sets a new password and revokes every existing session for this user
    (a password change/reset must not leave old sessions valid)."""
    if err := validate_password(new_password):
        raise AuthError(err)
    password_hash = _hasher.hash(new_password)
    with _write_lock, _connect() as conn:
        cur = conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                    (password_hash, user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise AuthError(f"no such user: {user_id}")


# ── login / lockout ──────────────────────────────────────────────────────

def _record_attempt(username: str, success: bool) -> None:
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, attempted_at, success) "
            "VALUES (?, ?, ?)", (username, _now_iso(), 1 if success else 0))
        conn.commit()


def is_locked_out(username: str) -> bool:
    cutoff = (datetime.now(timezone.utc)
             - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)).isoformat()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT attempted_at, success FROM login_attempts "
            "WHERE username = ? AND attempted_at >= ? "
            "ORDER BY attempted_at DESC", (username, cutoff)).fetchall()
    failures = 0
    for r in rows:
        if r["success"]:
            break
        failures += 1
    if failures < LOCKOUT_MAX_ATTEMPTS:
        return False
    most_recent_failure = rows[0]["attempted_at"]
    locked_until = (datetime.fromisoformat(most_recent_failure)
                    + timedelta(minutes=LOCKOUT_DURATION_MINUTES))
    return datetime.now(timezone.utc) < locked_until


def verify_login(username: str, password: str) -> User:
    """Raises AuthError with a message safe to show the user (never reveals
    whether the username or the password was wrong — standard practice)."""
    if is_locked_out(username):
        raise AuthError(
            f"too many failed attempts — try again in "
            f"{LOCKOUT_DURATION_MINUTES} minutes")
    user = get_user_by_username(username)
    if user is None or not user.is_active:
        _record_attempt(username, False)
        raise AuthError("invalid username or password")
    with _connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?",
                           (user.id,)).fetchone()
    try:
        _hasher.verify(row["password_hash"], password)
    except (VerifyMismatchError, InvalidHash):
        _record_attempt(username, False)
        raise AuthError("invalid username or password")
    _record_attempt(username, True)
    if _hasher.check_needs_rehash(row["password_hash"]):
        with _write_lock, _connect() as conn:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                        (_hasher.hash(password), user.id))
            conn.commit()
    return user


# ── sessions ──────────────────────────────────────────────────────────────

def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at, "
            "last_seen_at) VALUES (?, ?, ?, ?, ?)",
            (token, user_id, _now_iso(), _expires_iso(hours=session_idle_hours()),
             _now_iso()))
        conn.commit()
    return token


def get_session_user(token: str) -> Optional[User]:
    """Validates + touches last_seen_at. Returns None for missing/expired/
    inactive-user sessions (never raises — this is the hot path every
    request goes through)."""
    if not token:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT user_id, expires_at, created_at FROM sessions "
            "WHERE token = ?", (token,)).fetchone()
    if row is None or _is_expired(row["expires_at"]):
        return None
    user = get_user_by_id(row["user_id"])
    if user is None or not user.is_active:
        return None
    # Sliding expiry: this request pushes the idle deadline out again, never
    # past the absolute cap counted from login.
    hard_stop = (datetime.fromisoformat(row["created_at"])
                 + timedelta(hours=session_max_hours())).isoformat()
    expires_at = min(_expires_iso(hours=session_idle_hours()), hard_stop)
    with _write_lock, _connect() as conn:
        conn.execute("UPDATE sessions SET last_seen_at = ?, expires_at = ? "
                     "WHERE token = ?", (_now_iso(), expires_at, token))
        conn.commit()
    return user


def revoke_session(token: str) -> None:
    with _write_lock, _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def revoke_all_sessions(user_id: int) -> None:
    with _write_lock, _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()


# ── password reset ───────────────────────────────────────────────────────

def create_password_reset_token(user_id: int) -> str:
    """Invalidates any previous unused tokens for this user first — only one
    live reset link at a time."""
    token = secrets.token_urlsafe(32)
    with _write_lock, _connect() as conn:
        conn.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL",
            (user_id,))
        conn.execute(
            "INSERT INTO password_reset_tokens (token, user_id, created_at, "
            "expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, _now_iso(),
             _expires_iso(minutes=RESET_TOKEN_TTL_MINUTES)))
        conn.commit()
    return token


def consume_password_reset_token(token: str) -> Optional[int]:
    """Single-use: returns the user_id and marks the token used, or None if
    the token is missing/expired/already used."""
    with _write_lock, _connect() as conn:
        row = conn.execute(
            "SELECT user_id, expires_at, used_at FROM password_reset_tokens "
            "WHERE token = ?", (token,)).fetchone()
        if row is None or row["used_at"] is not None or _is_expired(row["expires_at"]):
            return None
        conn.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE token = ?",
            (_now_iso(), token))
        conn.commit()
        return row["user_id"]


# ── settings (runtime-configurable toggles) ──────────────────────────────

def get_setting(key: str, default: str = "") -> str:
    with _connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?",
                           (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value))
        conn.commit()


def viewer_chat_enabled() -> bool:
    return get_setting("viewer_chat_enabled", "0") == "1"


def set_viewer_chat_enabled(enabled: bool) -> None:
    set_setting("viewer_chat_enabled", "1" if enabled else "0")


# ── activity log ─────────────────────────────────────────────────────────
# Who signed in or out, who started or stopped a run, who changed an
# account. Written by the request handlers that know the actor, pruned on
# every write and read by the retention the administrator sets, and never
# allowed to fail the action it records. Nothing here takes _write_lock
# while holding it: the lock is not reentrant and every request refreshes
# its session under it.

ACTIVITY_RETENTION_DEFAULT_DAYS = 90
ACTIVITY_RETENTION_MIN_DAYS = 1
ACTIVITY_RETENTION_MAX_DAYS = 3650
_ACTIVITY_RETENTION_KEY = "activity_log_retention_days"
_activity_write_failed = False


def activity_retention_days() -> int:
    """The retention in days, read per call like the session limits; an
    unset or out-of-range value means the default."""
    try:
        days = int(get_setting(_ACTIVITY_RETENTION_KEY, ""))
    except ValueError:
        return ACTIVITY_RETENTION_DEFAULT_DAYS
    if ACTIVITY_RETENTION_MIN_DAYS <= days <= ACTIVITY_RETENTION_MAX_DAYS:
        return days
    return ACTIVITY_RETENTION_DEFAULT_DAYS


def validate_activity_retention(days) -> Optional[str]:
    try:
        n = int(days)
    except (TypeError, ValueError):
        return "retention must be a whole number of days"
    if not ACTIVITY_RETENTION_MIN_DAYS <= n <= ACTIVITY_RETENTION_MAX_DAYS:
        return (f"retention must be between {ACTIVITY_RETENTION_MIN_DAYS} and "
                f"{ACTIVITY_RETENTION_MAX_DAYS} days")
    return None


def _prune_activity(conn, days: int) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    return conn.execute("DELETE FROM activity_log WHERE ts < ?",
                        (cutoff,)).rowcount


def _insert_activity(conn, event: str, *, user: Optional[User], username: str,
                     case_id: str, detail: str, ip: str) -> None:
    conn.execute(
        "INSERT INTO activity_log (ts, event, user_id, username, role, "
        "case_id, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (_now_iso(), event, user.id if user else None,
         user.username if user else (username or ""),
         user.role if user else "", case_id or "", detail or "", ip or ""))


def log_event(event: str, *, user: Optional[User] = None, username: str = "",
              case_id: str = "", detail: str = "", ip: str = "") -> None:
    """Record one event. Never raises: an audit write must not turn the
    action it records into an error, so a failure is reported once on
    stderr and the action goes on."""
    global _activity_write_failed
    try:
        days = activity_retention_days()
        with _write_lock, _connect() as conn:
            _prune_activity(conn, days)
            _insert_activity(conn, event, user=user, username=username,
                             case_id=case_id, detail=detail, ip=ip)
            conn.commit()
    except Exception as exc:  # noqa: BLE001
        if not _activity_write_failed:
            _activity_write_failed = True
            import sys
            sys.stderr.write(f"[dashboard] activity log write failed: {exc!r}\n")


def _activity_row(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "ts": row["ts"], "event": row["event"],
            "user_id": row["user_id"], "username": row["username"],
            "role": row["role"], "case_id": row["case_id"],
            "detail": row["detail"], "ip": row["ip"]}


def prune_activity() -> int:
    """Apply the retention now; the page load and the export call this so a
    row past its time never reaches a reader."""
    days = activity_retention_days()
    with _write_lock, _connect() as conn:
        removed = _prune_activity(conn, days)
        conn.commit()
    return int(removed)


def list_activity(limit: int = 500) -> tuple[list[dict], int]:
    """The newest `limit` rows (1..5000) and the total count, after pruning."""
    limit = max(1, min(int(limit), 5000))
    prune_activity()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM activity_log ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0]
    return [_activity_row(r) for r in rows], int(total)


def all_activity() -> list[dict]:
    """Every row, newest first, for the export."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM activity_log ORDER BY id DESC").fetchall()
    return [_activity_row(r) for r in rows]


def clear_activity(*, user: Optional[User], ip: str = "") -> int:
    """Remove every row and leave one row that says so, in one transaction,
    so a wiped log is visible as wiped."""
    with _write_lock, _connect() as conn:
        removed = conn.execute("DELETE FROM activity_log").rowcount
        _insert_activity(conn, "log_cleared", user=user, username="",
                         case_id="", detail=f"{removed} entries removed", ip=ip)
        conn.commit()
    return int(removed)


def set_activity_retention(days, *, user: Optional[User], ip: str = "") -> int:
    """Store the retention, prune to it and record the change with the old
    and the new value and the rows removed, in one transaction: lowering
    the retention removes rows just as a clear does."""
    err = validate_activity_retention(days)
    if err:
        raise AuthError(err)
    new = int(days)
    old = activity_retention_days()
    with _write_lock, _connect() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (_ACTIVITY_RETENTION_KEY, str(new)))
        removed = _prune_activity(conn, new)
        _insert_activity(conn, "retention_changed", user=user, username="",
                         case_id="",
                         detail=f"{old} -> {new} days, {removed} entries removed",
                         ip=ip)
        conn.commit()
    return new


# ── RBAC: route → minimum role ───────────────────────────────────────────
# Consulted once per request by serve.py's dispatch layer. "chat/send" and
# "chat/poll" are handled specially (see effective_min_role) because their
# requirement depends on the viewer_chat_enabled runtime setting, not just
# a fixed role.

ROUTE_MIN_ROLE: dict[str, str] = {
    # Read-only views — every authenticated role.
    "cases": "viewer",
    "tokens": "viewer",
    "case_overview": "viewer",
    "questions": "viewer",
    "claim_graph": "viewer",
    "evidence_board": "viewer",
    "investigation_state": "viewer",
    "investigation_board": "viewer",
    "investigation_tasks": "viewer",
    "report_export": "viewer",
    "report_bundle": "viewer",
    "case/iocs": "viewer",
    "case/recommendations": "viewer",
    "case/recommendations/state": "analyst",
    "timeline_template": "viewer",
    "capabilities": "viewer",
    "brain/globe": "analyst",
    "brain/knowledge": "analyst",
    "brain/search": "analyst",
    "brain/learn_status": "analyst",
    "alerts": "viewer",
    "response": "viewer",
    # Chat — analyst by default; viewer_chat_enabled setting can lower this
    # to "viewer" at request time (see effective_min_role).
    "chat/send": "analyst",
    "chat/poll": "analyst",
    # Operational / write actions. NOTE: approval/brain-review/brain-edit
    # also still require response/gates.py's dashboard-secret dual-key
    # check underneath this — RBAC controls who can reach the UI at all,
    # it does not replace that separate agent-cannot-self-approve gate.
    "approval/nonce": "analyst",
    "approval": "analyst",
    "brain/candidates": "analyst",
    "brain/review": "analyst",
    "brain/edit": "analyst",
    "case/create": "analyst",
    "case/run/start": "analyst",
    "case/run/stop": "analyst",
    "case/run/status": "viewer",
    # Case-wide "is anything running" for the shell indicator: same read-only
    # status information as case/run/status, so the same minimum role.
    "runs/active": "viewer",
    # Live change stream (server-sent events): says *that* a case changed,
    # never what — the same read-only footing as the status endpoints.
    "events": "viewer",
    "case/run/options": "analyst",
    "case/case_md": "viewer",
    "case/case_md/save": "analyst",
    "case/case_md/autofill_propose": "analyst",
    "case/case_md/autofill_preview": "analyst",
    # Admin-only: config page and everything under it.
    "config/llm": "admin",
    # Served by GET_ROUTES and not on the public allowlist, so it was already
    # admin by the fail-closed default; stated so the table is the whole answer.
    "config/tools": "admin",
    "config/effort": "admin",
    "config/effort/save": "admin",
    "config/llm/save": "admin",
    "config/llm/delete": "admin",
    "config/llm/probe": "admin",
    "config/llm/role": "admin",
    "config/osint": "admin",
    "config/osint/save": "admin",
    "config/tool": "admin",
    "config/mail": "admin",
    "config/session": "admin",
    "config/session/save": "admin",
    "config/mitre": "admin",
    "config/mitre/refresh": "admin",
    "config/mail/save": "admin",
    "config/mail/test": "admin",
    "config/share": "admin",
    "config/share/enable": "admin",
    "config/share/disable": "admin",
    "config/share/set_password": "admin",
    "config/plugins": "admin",
    "config/plugins/enable": "admin",
    "config/plugins/disable": "admin",
    "config/plugins/upload": "admin",
    "config/tool/save": "admin",
    "config/users": "admin",
    "config/users/create": "admin",
    "config/users/update_role": "admin",
    "config/users/set_active": "admin",
    "config/users/delete": "admin",
    "config/users/reset_password": "admin",
    "config/activity": "admin",
    "config/activity/export": "admin",
    "config/activity/clear": "admin",
    "config/activity/retention": "admin",
    "config/usage": "admin",
    "config/usage/export": "admin",
    "config/usage/clear": "admin",
    "config/usage/prices": "admin",
    "config/usage/prices/save": "admin",
    "config/usage/prices/delete": "admin",
    "case/delete": "admin",
    "case/move": "admin",
}


def effective_min_role(endpoint: str) -> str:
    """ROUTE_MIN_ROLE, with the viewer-chat runtime override applied."""
    minimum = ROUTE_MIN_ROLE.get(endpoint, "admin")  # unknown routes: fail closed
    if endpoint in ("chat/send", "chat/poll") and viewer_chat_enabled():
        return "viewer"
    return minimum


def can_access(user: Optional[User], endpoint: str) -> bool:
    if user is None or not user.is_active:
        return False
    return role_at_least(user.role, effective_min_role(endpoint))
