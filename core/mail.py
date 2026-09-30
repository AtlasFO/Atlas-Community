"""Outbound mail: password-reset links, and telling someone a run ended.

In core rather than dashboard/ because both send: the dashboard mails a
reset link, and a run mails its own outcome when ATLAS_RUN_NOTIFY_EMAIL
names a recipient — the CLI must not have to import the web layer to do
that.

Stdlib smtplib, no new dependency. Config lives in .env (same convention as
every other Atlas config surface — core/envfile.py is the writer the config
page uses), read fresh from os.environ on every send so a config-page
change takes effect on the next reset request without a dashboard restart
(the dashboard process must call load_dotenv() at startup and the config
page's save handler must also poke os.environ directly in the same
request — plain env-var writes on disk alone aren't picked up mid-process).

Deferred (per product decision, not built here): provider-specific
integrations (SendGrid/SES/etc.), send retries/queueing, template
customization beyond this one hardcoded reset-link body, deliverability
docs (SPF/DKIM/DMARC), IP-based rate limiting (a basic per-account cooldown
lives in dashboard/auth.py's password_reset_tokens table instead — creating
a new token invalidates the previous one, so rapid re-requests don't pile up).
"""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

from core import envfile

_REPO_ROOT = Path(__file__).resolve().parents[1]


class MailError(Exception):
    """Raised for missing config or a real SMTP failure — safe to log, not
    necessarily safe to show an end user (see dashboard/serve.py's caller,
    which always returns a generic response for password-reset requests
    regardless of send success, to avoid leaking account existence)."""


def is_configured() -> bool:
    return bool(os.environ.get("ATLAS_SMTP_HOST"))


def _config() -> dict:
    return {
        "host": os.environ.get("ATLAS_SMTP_HOST", ""),
        "port": envfile.env_int("ATLAS_SMTP_PORT", 587),
        "user": os.environ.get("ATLAS_SMTP_USER", ""),
        "password": os.environ.get("ATLAS_SMTP_PASSWORD", ""),
        "from_addr": (os.environ.get("ATLAS_SMTP_FROM")
                     or os.environ.get("ATLAS_SMTP_USER", "")),
        "starttls": os.environ.get("ATLAS_SMTP_STARTTLS", "1") != "0",
    }


def _smtp_connect(cfg: dict):
    """Connects (and authenticates, if a user is configured) per `cfg`.
    Returns an smtplib client to use as a context manager.

    Port 465 is implicit TLS by convention (Gmail, Office365, and most other
    providers that offer it) — the server expects a TLS handshake the moment
    the socket opens, so connecting plaintext and then calling starttls()
    fails there. That path only applies to other ports (587, 25, ...), where
    the `starttls` setting is honored as configured.
    """
    if cfg["port"] == 465:
        smtp = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=15)
    else:
        smtp = smtplib.SMTP(cfg["host"], cfg["port"], timeout=15)
        if cfg["starttls"]:
            smtp.starttls()
    if cfg["user"]:
        smtp.login(cfg["user"], cfg["password"])
    return smtp


def send_mail(to_addr: str, subject: str, body: str) -> None:
    cfg = _config()
    if not cfg["host"]:
        raise MailError("ATLAS_SMTP_HOST is not configured")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["from_addr"]
    msg["To"] = to_addr
    # Receiving servers expect both; the id's domain is the sender's, so no
    # reverse lookup of this host is needed to build it.
    from email.utils import formatdate, make_msgid, parseaddr
    sender = parseaddr(cfg["from_addr"])[1]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(
        domain=sender.rsplit("@", 1)[1] if "@" in sender else "localhost")
    msg.set_content(body)
    try:
        with _smtp_connect(cfg) as smtp:
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(f"SMTP send failed: {exc}") from exc


def test_connection(overrides: dict | None = None) -> dict:
    """Connects and authenticates without sending a message, so the config
    page can verify SMTP credentials work before relying on a real
    password-reset email to prove it.

    `overrides` lets the config page test the values currently typed in the
    form, not just what's already saved to .env — same "test before you
    save" flow as the LLM tab's probe. A blank/absent password falls back to
    the already-saved one (matches the "blank = unchanged" convention used
    for every stored secret in this codebase).
    """
    cfg = _config()
    if overrides:
        for key in ("host", "user", "from_addr"):
            if overrides.get(key) is not None:
                cfg[key] = str(overrides[key])
        if overrides.get("port") is not None:
            try:
                cfg["port"] = int(overrides["port"])
            except (TypeError, ValueError):
                return {"ok": False, "error": f"invalid port: {overrides['port']!r}"}
        if overrides.get("password"):
            cfg["password"] = str(overrides["password"])
        if "starttls" in overrides:
            cfg["starttls"] = bool(overrides["starttls"])
    if not cfg["host"]:
        return {"ok": False, "error": "ATLAS_SMTP_HOST is not configured"}
    try:
        with _smtp_connect(cfg):
            pass
    except (OSError, smtplib.SMTPException) as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "error": ""}


def send_password_reset_email(to_addr: str, reset_url: str) -> None:
    subject = "Atlas — password reset"
    body = (
        "A password reset was requested for your Atlas dashboard account.\n\n"
        f"Reset your password: {reset_url}\n\n"
        "This link expires in 30 minutes and can only be used once. "
        "If you didn't request this, you can ignore this email — your "
        "password has not been changed."
    )
    send_mail(to_addr, subject, body)


def send_run_finished_email(to_addr: str, case: str, status: dict) -> None:
    """Tell whoever started a run that it ended, and how.

    A run takes hours; the person who pressed Start is not watching the tab.
    The mail carries the outcome and the numbers that say whether it is worth
    opening now — never evidence, never findings: a mailbox is not a place
    for case content.
    """
    finish = str(status.get("finish_status") or "").strip()
    stopped = str(status.get("stopped_reason") or "").strip()
    headline = finish or stopped or "ended"
    subject = f"Atlas — run finished on {case} ({headline})"
    minutes = ""
    try:
        minutes = f"{float(status.get('duration_seconds') or 0) / 60:.0f} min"
    except (TypeError, ValueError):
        pass
    lines = [
        f"The Atlas run on case {case} has ended.",
        "",
        f"  Outcome:  {headline}",
    ]
    if stopped and stopped != headline:
        lines.append(f"  Stopped:  {stopped}")
    for label, key in (("Turns", "turns"), ("Tool calls", "tool_calls"),
                       ("Findings", "findings_recorded"),
                       ("Errors", "error_count")):
        value = status.get(key)
        if value is not None:
            lines.append(f"  {label + ':':10s}{value}")
    if minutes:
        lines.append(f"  Duration: {minutes}")
    lines += ["", "Open the case in the Atlas dashboard for the report and "
                  "the findings."]
    send_mail(to_addr, subject, "\n".join(lines))


def status() -> dict:
    """Config-page display — never returns the password."""
    cfg = _config()
    return {"configured": is_configured(), "host": cfg["host"], "port": cfg["port"],
           "user": cfg["user"], "from_addr": cfg["from_addr"],
           "starttls": cfg["starttls"]}


def save_config(data: dict) -> dict:
    """data: {host, port, user, password (""=unchanged), from_addr, starttls}."""
    env_path = envfile.resolve(_REPO_ROOT)
    if not env_path.is_file():
        raise MailError(
            f"no .env at {env_path} — create it first (cp .env.example .env)")
    updates = {
        "ATLAS_SMTP_HOST": str(data.get("host") or ""),
        "ATLAS_SMTP_PORT": str(data.get("port") or "587"),
        "ATLAS_SMTP_USER": str(data.get("user") or ""),
        "ATLAS_SMTP_FROM": str(data.get("from_addr") or ""),
        "ATLAS_SMTP_STARTTLS": "1" if data.get("starttls", True) else "0",
    }
    password = str(data.get("password") or "")
    with envfile.lock():
        envfile.set_values(env_path, updates)
        for key, value in updates.items():
            os.environ[key] = value
        if password:
            envfile.set_values(env_path, {"ATLAS_SMTP_PASSWORD": password})
            os.environ["ATLAS_SMTP_PASSWORD"] = password
    return status()
