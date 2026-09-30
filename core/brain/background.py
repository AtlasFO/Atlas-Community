"""Spawn non-blocking Brain learning jobs after an investigation finishes.

The investigator must never wait on learning. Reports and exit codes are
decided first; this module detaches a subprocess that runs
``python -m core.brain.learn``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def brain_learn_enabled() -> bool:
    if (os.environ.get("ATLAS_NO_BRAIN") or "").strip().lower() in (
            "1", "true", "yes", "on"):
        return False
    if (os.environ.get("ATLAS_NO_BRAIN_LEARN") or "").strip().lower() in (
            "1", "true", "yes", "on"):
        return False
    return True


def spawn_investigation_learn(
        case_dir: Path | str,
        *,
        case_id: str = "",
        question: str = "",
        review_text: str = "",
        verdict: str = "",
        command: str = "train",
        source_dir: Path | str | None = None) -> dict[str, Any]:
    """Detach a background learn process. Returns immediately.

    ``source_dir`` is where the run wrote its outputs when that is not the
    case itself (an ``--output-dir`` mirror): the digest reads them there,
    while the job, the status and the answer key stay with ``case_dir``.

    Writes ``.atlas/brain_learn_job.json`` and appends stdout/stderr to
    ``.atlas/brain_learn.log``. Status updates land in
    ``.atlas/brain_learn.json`` as the learner progresses.
    """
    if not brain_learn_enabled():
        return {"spawned": False, "reason": "disabled"}

    case_dir = Path(case_dir).resolve()
    atlas = case_dir / ".atlas"
    atlas.mkdir(parents=True, exist_ok=True)
    job_path = atlas / "brain_learn_job.json"
    log_path = atlas / "brain_learn.log"
    status_path = atlas / "brain_learn.json"

    job = {
        "case_dir": str(case_dir),
        "case_id": case_id or case_dir.name,
        "question": question or "",
        "review_text": review_text or "",
        "verdict": verdict or "",
        "command": command,
    }
    # The caller still holds the run lock: the case is read here, before a
    # fresh start of it can move the trace and wipe analysis/ and reports/.
    # The detached learner only reads the digest this leaves behind.
    try:
        from core.brain.learn import prepare_learn_inputs
        job.update(prepare_learn_inputs(
            Path(source_dir).resolve() if source_dir else case_dir, job["case_id"],
            question=job["question"], review_text=job["review_text"],
            verdict=job["verdict"]))
    except Exception as e:  # noqa: BLE001 - learning never fails the run
        status_path.write_text(json.dumps({
            "status": "failed",
            "case_id": job["case_id"],
            "error": f"digest: {e.__class__.__name__}: {e}",
        }, indent=2) + "\n", encoding="utf-8")
        return {"spawned": False, "reason": f"digest: {e}"}
    job_path.write_text(json.dumps(job, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    status_path.write_text(json.dumps({
        "status": "queued",
        "case_id": job["case_id"],
        "job_file": str(job_path),
    }, indent=2) + "\n", encoding="utf-8")

    # Prefer the same interpreter that is running atlas.
    py = sys.executable or "python3"
    cmd = [py, "-m", "core.brain.learn",
           "--case", str(case_dir),
           "--job-file", str(job_path)]
    env = os.environ.copy()
    # Ensure the Atlas repo root is importable even if cwd is the case dir.
    repo_root = Path(__file__).resolve().parents[2]
    prev = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (str(repo_root) + (os.pathsep + prev if prev else ""))

    log_f = open(log_path, "a", encoding="utf-8")  # noqa: SIM115 — child owns life
    try:
        log_f.write(f"\n--- spawn {' '.join(cmd)} ---\n")
        log_f.flush()
        proc = subprocess.Popen(
            cmd,
            cwd=str(repo_root),
            env=env,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as e:
        log_f.write(f"spawn failed: {e}\n")
        log_f.close()
        status_path.write_text(json.dumps({
            "status": "failed",
            "error": f"spawn: {e}",
        }, indent=2) + "\n", encoding="utf-8")
        return {"spawned": False, "reason": str(e), "log": str(log_path)}

    # Parent must not wait; leave the log handle to the child via dup in Popen.
    # Closing our FD is fine — the child's dup remains open.
    log_f.close()
    return {
        "spawned": True,
        "pid": proc.pid,
        "job_file": str(job_path),
        "log": str(log_path),
        "status_file": str(status_path),
    }
