"""Investigation run manager for the dashboard's start/stop controls.

Structurally parallel to dashboard/chat.py's ChatManager/ChatSession — one
tracked subprocess per case — but `atlas run` is a different shape of
program than the chat worker: it's a single long blocking call with no
stdin protocol, and it already writes its own status file
(<case_dir>/.atlas/run_status.json). So this module doesn't read a JSONL
event stream; it just owns the Popen handle (for "is it actually still
running" and "stop it") and lets the caller read run_status.json for the
rest, exactly as `atlas status` already does.

Real limitation, surfaced in the UI layer: "stop" only works for runs this
manager started (it needs the Popen handle) — a run started from the CLI
has no PID file today and can't be stopped from here.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from dashboard import run_options


class RunForbidden(Exception):
    """The requesting user may not act on this run."""


class RunError(Exception):
    """Raised for precondition failures — safe to show the caller."""


# agent.cli's `run` accepts --quiet (per-turn narration off, dashboard has
# no terminal to narrate to); `rerun` has no such flag — passing it would
# fail argparse. Both accept --json, which is how status()/stdout_tail stay
# machine-readable.
_BASE_FLAGS = {"run": ["--json", "--quiet"], "rerun": ["--json"]}


def build_cmd(case_dir: str, mode: str, extra_args: list[str]) -> list[str]:
    """`python -m agent.cli <mode> --case <case_dir> <mode's base flags>
    <extra_args>` — pure argv assembly, split out from RunSession so it's
    testable without spawning a real investigation subprocess."""
    return ([sys.executable, "-m", "agent.cli", mode, "--case", case_dir]
            + _BASE_FLAGS[mode] + extra_args)


class RunSession:
    def __init__(self, case_dir: str, case_name: str, repo_root: str,
                mode: str = "run", extra_args: Optional[list[str]] = None,
                notify_email: str = "", started_by: str = ""):
        self.case_dir = case_dir
        self.case_name = case_name
        self.mode = mode
        self.notify_email = (notify_email or "").strip()
        # The dashboard user who pressed Start: only they or an admin stop it.
        self.started_by = (started_by or "").strip()
        self.started_at = time.time()
        self._lock = threading.Lock()

        env = dict(os.environ)
        prior = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = repo_root + (os.pathsep + prior if prior else "")
        # Console scripts from the Python dependencies live in the venv's bin
        # directory, which a service unit's PATH does not include.
        venv_bin = os.path.join(sys.prefix, "bin")
        if os.path.isdir(venv_bin):
            env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
        # The run's start is when Start was pressed: the child reports its
        # elapsed time from it, the evidence stage before its loop included.
        env["ATLAS_RUN_STARTED_AT"] = self.started_at_utc()
        if self.notify_email:
            # This session watches the process and sends the notification, so
            # the child must not send a second one.
            env["ATLAS_RUN_NOTIFY_HANDLED"] = "1"
        if started_by:
            # The dashboard user who pressed Start, for the usage ledger.
            env["ATLAS_RUN_USER"] = started_by
        cmd = build_cmd(case_dir, mode, extra_args or [])
        # Own session: the hard stop below kills the run's whole process
        # group (agent and any tool child) without touching the dashboard.
        self.proc = subprocess.Popen(
            cmd, cwd=case_dir, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
            start_new_session=True,
        )
        self.stdout_tail: list[str] = []
        self._out_reader = threading.Thread(target=self._drain_stdout, daemon=True)
        self._out_reader.start()
        self._err_reader = threading.Thread(target=self._drain_stderr, daemon=True)
        self._err_reader.start()
        if self.notify_email:
            threading.Thread(target=self._notify_on_exit, daemon=True).start()

    def _notify_on_exit(self) -> None:
        """Mail the person who started this run once it ends.

        A run outlives the tab that started it, so the dashboard is where the
        ending is observed. Best-effort in every direction: no mail server, a
        refused message or an unreadable status must not touch the run or the
        dashboard.
        """
        try:
            self.proc.wait()
        except Exception:  # noqa: BLE001
            return
        try:
            from core import mail
            if not mail.is_configured():
                return
            status = {}
            try:
                from dashboard.read_models import _run_status
                status = _run_status(self.case_dir) or {}
            except Exception:  # noqa: BLE001 — send what we know
                pass
            mail.send_run_finished_email(self.notify_email, self.case_name,
                                         status)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(
                f"[run {self.case_name}] could not send the finished "
                f"notification: {exc!r}\n")

    def _drain_stdout(self) -> None:
        try:
            for line in self.proc.stdout:
                with self._lock:
                    self.stdout_tail.append(line.rstrip())
                    self.stdout_tail = self.stdout_tail[-200:]
        except Exception:  # noqa: BLE001
            pass

    def _drain_stderr(self) -> None:
        try:
            for line in self.proc.stderr:
                sys.stderr.write(f"[run {self.case_name}] {line.rstrip()}\n")
        except Exception:  # noqa: BLE001
            pass

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    def status(self) -> dict:
        run_status_path = Path(self.case_dir) / ".atlas" / "run_status.json"
        on_disk: dict = {}
        if run_status_path.is_file():
            try:
                on_disk = json.loads(run_status_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
        with self._lock:
            tail = list(self.stdout_tail[-20:])
        status = {
            "case": self.case_name, "mode": self.mode, "pid": self.proc.pid,
            "running": self.alive, "returncode": self.proc.returncode,
            "started_at": self.started_at, "started_by": self.started_by,
            "stdout_tail": tail, **on_disk,
        }
        # The run's status file carries the child's copy of the start; the
        # session's own stamp is the one Start set, and it stands.
        status["started_at"] = self.started_at_utc()
        return status

    def started_at_utc(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started_at))

    def stop(self) -> dict:
        if not self.alive:
            return {"success": True, "already_stopped": True}
        return _graceful_stop(self.proc)


# A stopped run still writes its report on the way out, which takes minutes
# when narrative sections are generated. Ten seconds to SIGKILL threw that
# report away; now the request returns at once and a watcher kills the
# process only if it has not finished within the grace period.
STOP_GRACE_SECONDS = float(os.environ.get("ATLAS_DASHBOARD_STOP_GRACE") or "900")


def _kill_run_group(proc) -> None:
    """SIGKILL the run's process group (falls back to the process alone)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            return
    try:
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        pass


def _graceful_stop(proc, grace: float | None = None) -> dict:
    grace = STOP_GRACE_SECONDS if grace is None else grace
    try:
        proc.send_signal(signal.SIGTERM)
    except Exception:  # noqa: BLE001
        return {"success": True, "already_stopped": True}
    try:
        proc.wait(timeout=min(3.0, grace))
        return {"success": True, "already_stopped": False, "stopping": False}
    except subprocess.TimeoutExpired:
        pass
    except Exception:  # noqa: BLE001
        return {"success": True, "already_stopped": False, "stopping": False}

    def _reap() -> None:
        try:
            proc.wait(timeout=max(0.0, grace - 3.0))
        except subprocess.TimeoutExpired:
            _kill_run_group(proc)
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=_reap, name="atlas-run-stop", daemon=True).start()
    return {"success": True, "already_stopped": False, "stopping": True,
            "grace_seconds": grace,
            "note": "stop requested; the run writes its report on the way out"}


def _lines(text) -> list[str]:
    """One item per non-empty line of a textarea's value."""
    return [line.strip() for line in str(text or "").splitlines() if line.strip()]


class RunManager:
    """Per-case RunSession registry — one active run per case at a time."""

    def __init__(self, repo_root: str):
        self.repo_root = repo_root
        self._sessions: dict[str, RunSession] = {}
        self._lock = threading.Lock()

    def start(self, cases_root: str, case_name: str, mode: str = "run",
             options: Optional[dict] = None,
             notify_email: str = "", started_by: str = "") -> RunSession:
        with self._lock:
            existing = self._sessions.get(case_name)
            if existing is not None and existing.alive:
                raise RunError(
                    f"a run is already in progress for {case_name!r}")
            case_dir = os.path.join(cases_root, case_name)
            if not os.path.isdir(case_dir):
                raise RunError(f"no such case: {case_name!r}")
            # The disabled Start button in the UI is a courtesy, not the
            # actual guard — without this check, a direct POST (or a stale
            # page whose button wasn't yet re-disabled) would spawn a
            # second `atlas run` racing an already-running CLI-started one
            # over the same case's evidence/analysis/claim graph. This
            # session has no Popen handle for that external process (that's
            # the whole reason it isn't in self._sessions), but the pid
            # agent/loop.py records in run_status.json is enough to detect
            # it's still alive.
            from dashboard.read_models import run_process_alive
            if run_process_alive(case_dir):
                raise RunError(
                    f"a run is already in progress for {case_name!r} "
                    f"(started outside this dashboard — stop it the same way)")
            # run_process_alive() above only catches a run that has already
            # written its pid to run_status.json — there is a real window
            # between an externally-started `atlas run`/`rerun` spawning and
            # its first status write. core.run_lock is held by that process
            # for its whole lifetime regardless of when it writes status, so
            # probing it here closes that window (the authoritative guard is
            # still the child process's own run_lock.acquire() in
            # agent/cli.py — this is just a fast, friendly precondition
            # check so the dashboard doesn't spawn a process doomed to lose
            # that race).
            from core import run_lock
            if run_lock.is_locked(case_dir):
                raise RunError(
                    f"a run is already in progress for {case_name!r} "
                    f"(started outside this dashboard — stop it the same way)")
            try:
                extra_args = run_options.build_argv(mode, options)
                local = run_options.local_options(mode, options)
            except run_options.OptionsError as exc:
                raise RunError(str(exc)) from exc
            # Questions and facts typed into the start dialog go into the
            # brief first, so the run reads them from CASE.md like any
            # other and the Brief tab shows them at once.
            questions = _lines(local.get("new_questions"))
            facts = _lines(local.get("new_context"))
            if questions or facts:
                from dashboard import case_admin
                try:
                    case_admin.append_to_brief(cases_root, case_name,
                                               requests=questions, facts=facts)
                except case_admin.CaseAdminError as exc:
                    raise RunError(str(exc)) from exc
            sess = RunSession(case_dir, case_name, self.repo_root,
                              mode=mode, extra_args=extra_args,
                              notify_email=notify_email,
                              started_by=started_by)
            self._sessions[case_name] = sess
            return sess

    def get(self, case_name: str) -> Optional[RunSession]:
        with self._lock:
            return self._sessions.get(case_name)

    def alive_sessions(self) -> list[RunSession]:
        with self._lock:
            return [s for s in self._sessions.values() if s.alive]

    def stop(self, case_name: str, *, actor: str = "", actor_role: str = "") -> dict:
        """Stop the case's run. A run with a recorded starter is stopped only
        by that user or an admin; one started without a name (before runs
        carried one) by any user the endpoint admits."""
        with self._lock:
            sess = self._sessions.get(case_name)
        if sess is None:
            raise RunError(
                f"no dashboard-tracked run for {case_name!r} — a run "
                f"started outside the dashboard cannot be stopped from here")
        from dashboard.auth import role_at_least
        if (sess.started_by and actor != sess.started_by
                and not role_at_least(actor_role or "", "admin")):
            raise RunForbidden(
                f"only {sess.started_by} or an administrator can stop this run")
        return sess.stop()

    def close_all(self) -> None:
        with self._lock:
            for sess in self._sessions.values():
                if sess.alive:
                    sess.stop()


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANAGER = RunManager(repo_root=_REPO_ROOT)
