"""Declarative spec for `atlas run` / `atlas rerun` options exposed on the
dashboard's Start Run panel, and the single choke point that turns a
validated ``{option_id: value}`` dict into a subprocess argv tail.

Mirrors the ``FIELDS`` tuple pattern dashboard/config_osint.py already uses
for declarative form fields: one list read by both the `case/run/options`
GET (drives the frontend form) and build_argv() (drives the actual
subprocess), so the two can't drift apart. See agent/cli.py's `run` and
`rerun` subparsers for the authoritative flag definitions this mirrors.

Deliberately excluded (CLI-only / not meaningful from a web dashboard):
--json, --quiet (run_manager always passes the right combination itself),
--interactive (needs a stdin protocol run_manager's subprocess doesn't
implement — RunSession launches with stdin=DEVNULL), --skip-sudo-check
(documented in agent/cli.py as tests/CI only), and run's --skin (terminal
UI theme, meaningless in --json/--quiet mode).
"""
from __future__ import annotations

from typing import Any


class OptionsError(Exception):
    """Raised for an unknown option id, wrong value shape, or a value
    outside a select field's choices — safe to show the caller."""


# The two ways to start and what each does, in one sentence each: the mode
# picker's labels and help come from here, so the page and the CLI's own
# descriptions say the same thing.
MODES: tuple[dict, ...] = (
    {"id": "rerun", "label": "Continue",
     "help": "Picks up what changed since the last run: evidence added under "
             "evidence/, questions and facts added to the brief, findings "
             "marked for review. Keeps everything else, and starts the "
             "investigator only when there is something to do."},
    {"id": "run", "label": "Start over",
     "help": "A full run: wipes the previous run's working files and report, "
             "keeps the findings and questions, and examines all evidence "
             "again."},
)

# Typed into the start dialog and written into the brief before the run
# starts, so the run reads them from CASE.md like anything else there.
# "local": the dashboard applies these itself; they never become argv.
_NEW_QUESTIONS = {
    "id": "new_questions", "flag": None, "local": True, "type": "textarea",
    "group": "basic", "label": "New questions for Atlas",
    "help": "One per line. Added to the brief's Investigation Requests before "
            "the run starts.",
}
_NEW_CONTEXT = {
    "id": "new_context", "flag": None, "local": True, "type": "textarea",
    "group": "basic", "label": "New context (what you now know)",
    "help": "One fact per line; not evidence. Added to the brief's 'What you "
            "already know'; findings that mention what it names are "
            "re-validated.",
}
_LANGUAGE = {
    "id": "language", "flag": "-L", "type": "select", "group": "basic",
    "label": "Report language", "choices": ["", "en", "de"],
    "help": "Persisted in .atlas/case_config.json.",
}
_MODEL = {
    "id": "model", "flag": "--model", "type": "text", "group": "advanced",
    "label": "Model override", "help": "Overrides LLMHUB_MODEL for this run only.",
}

RUN_OPTIONS: tuple[dict, ...] = (
    _NEW_QUESTIONS,
    _NEW_CONTEXT,
    _LANGUAGE,
    {"id": "question", "flag": "--question", "type": "text", "group": "advanced",
     "label": "Question / focus override",
     "help": "Optional override of CASE.md's Investigation Requests for this run."},
    {"id": "start_mode", "flag": None, "type": "select", "group": "basic",
     "label": "Start mode", "choices": ["", "fresh", "resume"],
     "help": "fresh: wipe analysis/exports/reports + ledger statuses before "
             "starting (claims/tasks kept). resume: continue an unfinished "
             "run's trace. Default: fresh unless a prior run is unfinished."},
    _MODEL,
    {"id": "case_id", "flag": "--case-id", "type": "text", "group": "advanced",
     "label": "Case ID override",
     "help": "Overrides the trace filename + anchor case ID (from CASE.md)."},
    {"id": "output_dir", "flag": "--output-dir", "type": "text", "group": "advanced",
     "label": "Output directory",
     "help": "Write analysis/exports/reports here instead of inside the case."},
    {"id": "all_tools", "flag": "--all-tools", "type": "checkbox", "group": "advanced",
     "label": "Expose all tools up front", "help": "Larger context per turn."},
    {"id": "no_brain", "flag": "--no-brain", "type": "checkbox", "group": "advanced",
     "label": "Disable Brain",
     "help": "No Brain injection or post-run learning for this investigation."},
    {"id": "capture_brain", "flag": "--capture-brain", "type": "checkbox", "group": "advanced",
     "label": "Capture legacy review bullets",
     "help": "Also stage legacy review/self-correction candidates."},
    {"id": "no_capture_brain", "flag": "--no-capture-brain", "type": "checkbox", "group": "advanced",
     "label": "Skip legacy review capture",
     "help": "Skip legacy review-bullet capture even if enabled by default."},
    {"id": "remote", "flag": "--remote", "type": "text", "group": "remote",
     "label": "Remote SIFT host",
     "help": "Run forensic tools on an external SIFT VM (host key in "
             "~/cases/.common/live_hosts.json)."},
    {"id": "remote_mode", "flag": "--remote-mode", "type": "select", "group": "remote",
     "label": "Remote mode", "choices": ["resident", "copy"],
     "help": "resident: evidence already on the VM. copy: rsync evidence up, "
             "sync outputs back."},
    {"id": "remote_workspace", "flag": "--remote-workspace", "type": "text", "group": "remote",
     "label": "Remote workspace dir",
     "help": "For remote mode 'copy'; default ~/atlas-workspace on the VM."},
)

RERUN_OPTIONS: tuple[dict, ...] = (
    _NEW_QUESTIONS,
    _NEW_CONTEXT,
    _LANGUAGE,
    _MODEL,
    {"id": "no_agent", "flag": "--no-agent", "type": "checkbox", "group": "basic",
     "label": "Record the changes only (no AI)",
     "help": "Catalog the evidence, update the brief and mark findings for "
             "review; do not start the investigator or rewrite the report."},
    {"id": "dry_run", "flag": "--dry-run", "type": "checkbox", "group": "basic",
     "label": "Dry run", "help": "Scan and diff without writing catalog updates."},
    {"id": "full_hash", "flag": "--full-hash", "type": "checkbox", "group": "advanced",
     "label": "Force full-file hashes", "help": "Even for large images."},
    {"id": "regenerate_sections", "flag": "--regenerate-sections", "type": "checkbox", "group": "advanced",
     "label": "Regenerate stale sections",
     "help": "AI-regenerate stale report projection sections then assemble "
             "(needs an LLM unless a deterministic fallback applies)."},
    {"id": "assemble_report", "flag": "--assemble-report", "type": "checkbox", "group": "advanced",
     "label": "Assemble report", "help": "Assemble deliverable from current projection (no LLM)."},
    {"id": "report_format", "flag": "--format", "type": "select", "group": "advanced",
     "label": "Report format", "choices": ["markdown", "md", "html", "json"],
     "help": "Used with 'Regenerate stale sections' or 'Assemble report'."},
    {"id": "diff", "flag": "--diff", "type": "text", "group": "advanced",
     "label": "Compare runs", "help": "RUN_A..RUN_B — compare two journal runs."},
    {"id": "list_runs", "flag": "--list-runs", "type": "checkbox", "group": "advanced",
     "label": "List journal runs",
     "help": "List investigation journal runs and milestones instead of rerunning."},
)

_BY_MODE = {"run": {o["id"]: o for o in RUN_OPTIONS},
            "rerun": {o["id"]: o for o in RERUN_OPTIONS}}


def spec(mode: str) -> tuple[dict, ...]:
    if mode not in ("run", "rerun"):
        raise OptionsError(f"unknown run mode: {mode!r}")
    return RUN_OPTIONS if mode == "run" else RERUN_OPTIONS


def local_options(mode: str, options: dict[str, Any] | None) -> dict[str, Any]:
    """The options the dashboard applies itself before spawning, as
    ``{option_id: value}``; unknown ids are left to build_argv to refuse."""
    fields = _BY_MODE.get(mode)
    if fields is None:
        raise OptionsError(f"unknown run mode: {mode!r}")
    return {opt_id: value for opt_id, value in (options or {}).items()
            if (fields.get(opt_id) or {}).get("local")}


def summary_argv(mode: str, options: dict[str, Any] | None) -> list[str]:
    """The flags a start sets through checkboxes and fixed choices, for a log
    line; free text (a question, a model, a path, a host) is left out."""
    fields = _BY_MODE.get(mode) or {}
    kept = {k: v for k, v in (options or {}).items()
            if (fields.get(k) or {}).get("type") in ("checkbox", "select")}
    try:
        return build_argv(mode, kept)
    except OptionsError:
        return []


def build_argv(mode: str, options: dict[str, Any] | None) -> list[str]:
    """Validated ``{option_id: value}`` -> CLI argv tail (no `atlas <mode>`
    / `--case` prefix; callers prepend that). Values are never handed to a
    shell — subprocess.Popen's list form already rules out injection — this
    validates for a *sane* command: unknown ids and off-menu select values
    are rejected rather than silently passed through or dropped."""
    fields = _BY_MODE.get(mode)
    if fields is None:
        raise OptionsError(f"unknown run mode: {mode!r}")
    argv: list[str] = []
    for opt_id, value in (options or {}).items():
        field = fields.get(opt_id)
        if field is None:
            raise OptionsError(f"unknown {mode} option: {opt_id!r}")
        if field.get("local"):
            continue  # applied by the dashboard before the start, never argv
        if field["type"] == "checkbox":
            if value:
                argv.append(field["flag"])
        elif field["type"] == "select":
            text = str(value or "").strip()
            if not text:
                continue
            if text not in field["choices"]:
                raise OptionsError(
                    f"{opt_id!r} must be one of {field['choices']!r}, got {text!r}")
            if opt_id == "start_mode":
                argv.append(f"--{text}")  # --fresh / --resume
            else:
                argv += [field["flag"], text]
        else:  # text
            text = str(value or "").strip()
            if text:
                argv += [field["flag"], text]
    return argv
