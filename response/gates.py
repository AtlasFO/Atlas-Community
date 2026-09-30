"""Server-side gate checks for respond.* tools.

Three gates, all dual-key by design — the agent cannot self-approve
because every gate reaches back into the trace and demands evidence that
the operator put their literal text there.

- live_monitoring_scope     fires on every respond.* call
- approval_required         fires on execute_action / revert_action
- operator_text_required    fires on approve_action
"""
from __future__ import annotations
import json
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any, Optional

CASES_ROOT = Path(os.environ.get("ATLAS_CASES_ROOT") or os.path.expanduser("~/cases"))

# How long an approval token stays valid. Short by design — operators are
# expected to type "approve ACT-N" right before the agent calls execute.
APPROVAL_TTL_SECONDS = 600

# Dashboard-side approval opt-in. The browser approval controls are FAIL-CLOSED
# and OFF BY DEFAULT: the whole POST surface 403s unless this secret file exists
# with 0600 perms. Presence + possession of its contents is *key 2* of the dual
# key for the dashboard origin (see the equivalence argument on
# check_dashboard_secret).
DASHBOARD_SECRET_PATH = Path(
    os.environ.get("ATLAS_DASHBOARD_SECRET")
    or os.path.expanduser("~/.config/atlas/dashboard_approval_secret")
)

# How far back in the trace to look for the user_message that backs an
# approve_action call. Matches the standard "last 30 entries" window used
# by the record_finding gate stack so a multi-step investigation doesn't
# scroll the operator's approval out of range.
APPROVAL_LOOKBACK_ENTRIES = 30


def _approval_path(case_id: str, action_id: str) -> Path:
    return CASES_ROOT / case_id / "monitoring" / "response" / "approvals" / f"{action_id}.json"


def _suggestion_path(case_id: str, action_id: str) -> Path:
    return CASES_ROOT / case_id / "monitoring" / "response" / "suggestions" / f"{action_id}.json"


def _baseline_dir(case_id: str) -> Path:
    return CASES_ROOT / case_id / "monitoring" / "baselines"


def _refuse(gate: str, error: str, **extra) -> dict:
    out = {"success": False, "gate": gate, "error": error}
    out.update(extra)
    return out


# ─────────────────────────────────────────────────────────────────────────────

def check_live_monitoring_scope(case_id: str, client_id: Optional[str] = None) -> Optional[dict]:
    """Refuse if `case_id` isn't a live-monitoring case (no baselines)."""
    baselines = _baseline_dir(case_id)
    if not baselines.exists() or not any(baselines.iterdir()):
        return _refuse(
            "live_monitoring_scope",
            f"respond.* is restricted to active live-monitoring cases. "
            f"No baselines found under {baselines}. "
            f"Run monitor.baseline_capture against a client first.",
        )
    if client_id is not None:
        candidate = baselines / f"{client_id}.json"
        if not candidate.exists():
            return _refuse(
                "live_monitoring_scope",
                f"client_id {client_id!r} is not baselined for case {case_id!r}. "
                f"Expected baseline at {candidate}.",
            )
    return None


def check_operator_text(case_id: str, action_id: str, operator_text: str) -> Optional[dict]:
    """Refuse approve_action unless action_id is literally in operator_text
    AND a matching user_message exists in the recent trace.

    The recent-trace check is what makes this dual-key: the agent could
    *forge* operator_text in the function arg, but it cannot fabricate a
    `user_message` source entry — those come from the harness and carry
    the role/role-content fields the agent doesn't write."""
    if action_id not in operator_text:
        return _refuse(
            "operator_text_required",
            f"action_id {action_id!r} not literally present in operator_text. "
            f"Operator must type the action id verbatim (e.g. 'approve {action_id}').",
            operator_text_excerpt=operator_text[:240],
        )

    suggestion = _suggestion_path(case_id, action_id)
    if not suggestion.exists():
        return _refuse(
            "operator_text_required",
            f"no suggestion record found for action_id {action_id!r} at {suggestion}. "
            f"approve_action requires a prior respond.suggest_containment call.",
        )

    try:
        from core.execution_log import log
        entries = log.last_n_window(n=APPROVAL_LOOKBACK_ENTRIES)
    except Exception as e:  # noqa: BLE001
        return _refuse(
            "operator_text_required",
            f"trace not initialised — cannot verify operator message ({e})",
        )

    needle = operator_text.strip()
    matched = False
    for entry in entries:
        # The harness writes operator inputs as entries with type/source we
        # can recognise. We look for any recent entry where the content
        # equals operator_text and the source/type marks it as user-origin.
        content = (entry.get("content") or entry.get("user_message") or "").strip()
        if not content:
            continue
        source = entry.get("source", "")
        type_ = entry.get("type", "")
        role = (entry.get("role") or "")
        is_user_entry = (
            type_ == "user_message"
            or source == "claude_code_user_prompt"
            or "user_message" in source
            or "user_message" in type_
            or role == "user"
        )
        if needle == content and is_user_entry:
            matched = True
            break

    if not matched:
        return _refuse(
            "operator_text_required",
            f"could not find a recent user_message trace entry whose content matches operator_text. "
            f"The agent cannot self-approve — only operator-typed messages satisfy this gate. "
            f"Looked at the last {APPROVAL_LOOKBACK_ENTRIES} trace entries.",
        )
    return None


def issue_approval(case_id: str, action_id: str, operator_text: str) -> dict:
    """Persist an approval token for action_id; called by approve_action
    after the operator_text gate has passed."""
    path = _approval_path(case_id, action_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    record = {
        "action_id": action_id,
        "case_id": case_id,
        "operator_text": operator_text,
        "approval_token": token,
        "approved_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "expires_at_epoch": int(time.time()) + APPROVAL_TTL_SECONDS,
    }
    path.write_text(json.dumps(record, indent=2))
    return record


# ── Dashboard approval origin ────────────────────────────────────────────────
#
# The chat/agent approval path (check_operator_text + issue_approval) is
# dual-key:
#   key 1 = operator types text containing the action_id verbatim
#   key 2 = a matching user_message exists in the recent agent trace (proves the
#           text came from the harness, not the agent forging the arg)
#
# The dashboard operator acts through a browser, not the agent chat, so key 2's
# trace check does not apply. The dashboard path substitutes an *equivalent*
# second factor:
#   key 1 = operator types text containing the action_id verbatim  (unchanged)
#   key 2 = possession of the 0600 secret at DASHBOARD_SECRET_PATH, presented on
#           a request carrying a single-use, same-origin-issued nonce.
#
# Equivalence argument (documented per the plan): key 2 shifts from
# "harness-written user_message" to "secret+nonce possession". Both are readable
# only by a process running as the same OS user — a compromised same-user agent
# could read the trace *or* the secret file either way — so the trust boundary
# is identical and there is no regression. The nonce (issued only by a
# secret-gated same-origin GET, and single-use) is what stops a cross-origin
# page or replay from forging an approval; the browser same-origin policy keeps
# its value out of an attacker page's reach.


def dashboard_secret() -> Optional[str]:
    """Return the dashboard approval secret, or None if the feature is off.

    Fail-closed: returns None unless the file exists AND is a regular file with
    no group/other permission bits (0600 or stricter). A world/group-readable
    secret is treated as absent — better to disable approvals than honour a
    leaked secret."""
    path = DASHBOARD_SECRET_PATH
    try:
        st = path.stat()
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        return None
    try:
        value = path.read_text().strip()
    except OSError:
        return None
    return value or None


def check_dashboard_secret(presented: Optional[str]) -> Optional[dict]:
    """Gate the dashboard POST surface. Returns a refusal dict or None (ok).

    Fail-closed on every branch: no secret configured → 403; no/blank secret
    presented → 403; mismatch → 403. Uses a length-stable compare."""
    secret = dashboard_secret()
    if secret is None:
        return _refuse(
            "dashboard_approval",
            "dashboard approvals are disabled. Create "
            f"{DASHBOARD_SECRET_PATH} (mode 0600) with a shared secret to enable "
            "the browser approval controls.",
            http_status=403,
        )
    presented = (presented or "").strip()
    if not presented or not _consteq(presented, secret):
        return _refuse(
            "dashboard_approval",
            "missing or incorrect approval secret.",
            http_status=403,
        )
    return None


def _consteq(a: str, b: str) -> bool:
    """Constant-time-ish string compare (avoids early-exit timing leak)."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0


def issue_dashboard_approval(case_id: str, action_id: str, operator_text: str) -> dict:
    """Persist an approval token from the DASHBOARD origin.

    Writes the SAME token file that issue_approval writes, so
    check_approval / check_execution_permitted need zero changes — a
    dashboard-approved action is indistinguishable to the execution gate from a
    chat-approved one, by design. The `origin` field is additive audit metadata
    (existing consumers ignore it)."""
    path = _approval_path(case_id, action_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    record = {
        "action_id": action_id,
        "case_id": case_id,
        "operator_text": operator_text,
        "origin": "dashboard",
        "approval_token": token,
        "approved_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "expires_at_epoch": int(time.time()) + APPROVAL_TTL_SECONDS,
    }
    path.write_text(json.dumps(record, indent=2))
    return record


def deny_dashboard_action(case_id: str, action_id: str) -> dict:
    """Operator-denied via the dashboard: delete any approval token and stamp the
    suggestion `denied`. Idempotent — a missing token is not an error."""
    approval = _approval_path(case_id, action_id)
    removed = False
    try:
        approval.unlink()
        removed = True
    except OSError:
        pass
    suggestion = _suggestion_path(case_id, action_id)
    try:
        rec = json.loads(suggestion.read_text())
        rec["denied"] = True
        rec["denied_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        suggestion.write_text(json.dumps(rec, indent=2))
    except (OSError, json.JSONDecodeError):
        pass
    return {"action_id": action_id, "case_id": case_id, "denied": True,
            "token_removed": removed}


def check_dashboard_operator_text(action_id: str, operator_text: str) -> Optional[dict]:
    """Key 1 for the dashboard origin: action_id must be typed verbatim."""
    if not operator_text or action_id not in operator_text:
        return _refuse(
            "dashboard_approval",
            f"action_id {action_id!r} must be typed verbatim in the approval box "
            f"(e.g. 'approve {action_id}').",
            http_status=400,
            operator_text_excerpt=(operator_text or "")[:240],
        )
    return None


def check_approval(case_id: str, action_id: str) -> tuple[Optional[dict], Optional[dict]]:
    """Return (approval_record, refusal). Exactly one is non-None.

    refusal carries gate="approval_required" when no valid approval exists.
    """
    path = _approval_path(case_id, action_id)
    if not path.exists():
        return None, _refuse(
            "approval_required",
            f"no approval found for action_id {action_id!r}. "
            f"Operator must type 'approve {action_id}' and the agent must call "
            f"respond.approve_action before respond.execute_action.",
            expected_at=str(path),
        )
    try:
        record = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return None, _refuse("approval_required", f"approval record unreadable: {e}")

    if record.get("expires_at_epoch", 0) < int(time.time()):
        return None, _refuse(
            "approval_required",
            f"approval for {action_id!r} expired at "
            f"{record.get('approved_at_utc')!r}+{APPROVAL_TTL_SECONDS}s. "
            f"Operator must re-approve.",
        )
    return record, None


def check_execution_permitted(
    case_id: str, action_id: str, suggestion: dict, *, mode: str = "operator"
) -> Optional[dict]:
    """The single permission decision for respond.execute_action / revert_action.

    Composes the auto-protect policy with the existing approval gate:

      * If the action is server-classified AUTO (reversible AND low-risk) AND
        auto-protect is enabled for the case, permit with no approval token.
      * Otherwise (destructive, OR auto-protect disabled) fall through to
        check_approval — which requires a non-expired operator-issued token.

    `mode` is advisory (recorded for audit only). Permission is recomputed from
    disk every call, so passing mode='auto' on a destructive action does NOT
    bypass approval — classify() returns NEEDS_APPROVAL and the call falls into
    check_approval regardless. The agent therefore cannot self-execute a
    destructive action.
    """
    from response import policy
    tier = policy.classify(suggestion)
    if tier == policy.AUTO and policy.auto_protect_enabled(case_id):
        return None
    _, refusal = check_approval(case_id, action_id)
    return refusal
