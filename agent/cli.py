"""`atlas` — command-line frontend for the Atlas analyst agent.

    atlas run   --case ~/Atlas/demo-cases/nitroba --question "who sent the email?"
    atlas train --case DIR -q "..."  fresh full run + independent run review
    atlas review --live [--trace P]  review an in-flight (stuck?) investigation
    atlas chat  [--case DIR]     interactive analyst session
    atlas models                 list model ids available on the LLM Hub
    atlas doctor                 show resolved backend configuration
    atlas rerun                  continue from what changed (evidence, questions, facts)
    atlas rerun --no-agent       record the changes only (evidence diff, brief, no AI)
    atlas rerun -q "..."         add a fact to the brief's 'What you already know', then continue
    atlas serve                  run the MCP server on stdio (for MCP clients)
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

# Whether a case was run before is one fact for the CLI and the dashboard
# alike; the private names stay for the run-isolation callers below.
from core.run_state import (
    prior_process_artifacts_present as _prior_process_artifacts_present,
    prior_run_is_terminal as _prior_run_is_terminal,
)


def _bootstrap_env() -> None:
    # Same precedence as server.py: repo .env first, then (optionally) GNOME
    # Keyring for anything still unset. Keyring is skipped when a primary LLM
    # key is already present — probing optional vault keys unlocks a GUI
    # “Unlock Keyring” dialog on WSL/desktop. Opt in with ATLAS_USE_KEYRING=1.
    from agent.prompts import REPO_ROOT
    load_dotenv(REPO_ROOT / ".env")
    load_dotenv()  # a case-local .env may add overrides for unset vars
    try:
        from core.secrets import load_into_environ
        filled = load_into_environ()
        if filled:
            print(f"[atlas] loaded from GNOME Keyring: {', '.join(filled)}",
                  file=sys.stderr)
    except Exception:
        pass


def _resolve_case(arg: str | None) -> Path | None:
    if arg:
        case = Path(arg).expanduser().resolve()
        if not case.is_dir():
            sys.exit(f"atlas: case directory not found: {case}")
        return case
    cwd = Path.cwd()
    markers = ("CASE.md", "CLAUDE.md", "evidence", "analysis")
    return cwd if any((cwd / m).exists() for m in markers) else None


CASE_OUTPUT_SUBDIRS = ("analysis", "exports", "reports")


def _ensure_case_layout(case_dir: Path) -> None:
    """Create the output subdirectories a run writes into.

    Only the case template ships them; a case reset to evidence/ and CASE.md,
    or one created by hand, has none, and the first tool that writes there
    fails for a reason the model cannot see in the evidence.
    """
    for sub in CASE_OUTPUT_SUBDIRS:
        try:
            (Path(case_dir) / sub).mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


def _prepare_output_dir(real_case: Path, out_dir: str) -> Path:
    """Set up an alternate output root so a run's analysis/exports/reports land
    outside the case directory while evidence stays read-only in place.

    The directory is turned into a self-contained "mirror case": the three
    output subdirs are created, and the real case's evidence/ and brief are
    symlinked in so cwd-relative tool resolution and the system prompt work
    unchanged. Evidence is reached through the symlink, whose realpath still
    resolves inside the protected evidence tree — so the read-only contract
    (core.paths.is_evidence_path) holds. Returns the effective case dir.
    """
    # The real case's grading file(s) must stay blocked even though the mirror
    # omits them: the mirror's evidence symlink can still resolve back to a key
    # under evidence/, and a determined path can point at the real case dir.
    from core import paths as _paths
    _paths.register_answer_keys(real_case)

    out = Path(out_dir).expanduser().resolve()
    if out == real_case.resolve():
        return real_case
    # A mirror run of a case under a handling stop would handle the same
    # evidence, through the symlink, outside the stop: the tool gates read
    # the stop from the mirror. A linked stop file would not hold either,
    # because the stop is rewritten atomically and a replace cuts the link.
    from core.handling_stop import STOP_FILE, state as _stop_state
    _stop = _stop_state(real_case)
    if _stop:
        sys.exit(f"atlas: a handling stop for {_stop.get('class')} material stands on "
                 f"{real_case} since {_stop.get('asserted_at')}: a run in another output "
                 "directory would handle that evidence outside the stop. Work on the case "
                 f"itself with --resume, or have the examiner lift the stop by removing {STOP_FILE}.")
    out.mkdir(parents=True, exist_ok=True)
    for sub in ("analysis", "exports", "reports"):
        (out / sub).mkdir(exist_ok=True)
    # Which case this mirror stands for: a handling stop asserted here must
    # also stand there (core.handling_stop.assert_stop).
    from core.handling_stop import MIRROR_MARKER
    (out / ".atlas").mkdir(exist_ok=True)
    (out / ".atlas" / MIRROR_MARKER).write_text(
        json.dumps({"real_case": str(real_case.resolve())}) + "\n", encoding="utf-8")
    ev = real_case / "evidence"
    link = out / "evidence"
    if ev.exists() and not link.exists():
        try:
            link.symlink_to(ev.resolve(), target_is_directory=True)
        except OSError:
            pass
    # engagement.yaml carries the client identity Tier-D brain injection keys
    # on — without the mirror the tier silently dies under --output-dir. It is
    # mirrored only for ungraded cases: ground_truth.json is deliberately not
    # mirrored (below), so in the mirror the Tier-D ground-truth gate cannot
    # see a grading key — mirroring the client identity anyway would let a
    # graded case bypass the gate.
    briefs = ["CASE.md", "CLAUDE.md"]
    from core.brain.answer_key import has_ground_truth
    if not has_ground_truth(real_case):
        briefs.append("engagement.yaml")
    for brief in briefs:
        src, dst = real_case / brief, out / brief
        if src.exists() and not dst.exists():
            try:
                dst.symlink_to(src.resolve())
            except OSError:
                try:
                    dst.write_text(src.read_text(encoding="utf-8"),
                                   encoding="utf-8")
                except OSError:
                    pass
    # Deliberately NOT mirrored: ground_truth.json. The analyst chdirs into
    # the mirror and can read files there — linking the answer key in would
    # let the model under review grade-inflate itself. The post-run reviewer
    # reads it from the real case instead (Reviewer gt_dir).
    return out


def _arm_exit_signals() -> None:
    """From here on a further stop signal must not abort the exit path: a
    second SIGTERM once interrupted the report projection mid-write and
    the run ended with no report. It now asks for a hurried report — the
    deterministic sections instead of the narrative ones."""
    try:
        import signal as _signal

        def _hurry(_signum, _frame):
            try:
                from core.report_projection import HURRY
                HURRY.set()
            except Exception:  # noqa: BLE001
                pass
        for sig in (_signal.SIGTERM, _signal.SIGINT):
            _signal.signal(sig, _hurry)
    except (ValueError, OSError):
        pass


def _stop_tool_children() -> None:
    """End tool subprocesses still running when the run stops, so the loop
    unblocks and the exit record and report get written."""
    try:
        from core.executor import terminate_active_children
        terminate_active_children()
    except Exception:  # noqa: BLE001
        pass


def _make_agent(args, case_dir: Path | None, command: str = "run"):
    from core.paths import ensure_venv_on_path
    ensure_venv_on_path()
    from agent.llm import LLMHubClient, LLMError
    from agent.toolbox import Toolbox
    from agent.loop import Agent
    from agent.tui import UI
    from core import providers

    if case_dir:
        # Tool modules and the execution log resolve the case from the
        # working directory.
        os.chdir(case_dir)
    ui = UI(quiet=getattr(args, "quiet", False),
            skin=getattr(args, "skin", None))
    # ATLAS_AGENT_PROVIDER names the analyst backend; empty is "not configured",
    # not a silent fall-through to the LLM hub.
    client = LLMHubClient(provider=providers.role_name("ATLAS_AGENT_PROVIDER"),
                          model=args.model
                          or os.environ.get("ATLAS_AGENT_MODEL") or "")
    # A misconfigured provider is a config error, not a traceback.
    try:
        provider = client.provider
        model = client.model
    except (providers.UnknownProvider, LLMError) as e:
        sys.exit(f"atlas: {e}")
    if not model:
        sys.exit(
            f"atlas: no model configured for provider {provider.name!r}. "
            f"Set the provider's MODEL var or pass --model."
        )
    from core.llm_setup import is_identity_model_id
    if is_identity_model_id(model):
        sys.exit(
            f"atlas: model {model!r} looks like a dashboard role or username, "
            f"not a model id. Set ATLAS_PROVIDER_*_MODEL / LLMHUB_MODEL to a "
            f"catalogue id (e.g. openai/gpt-4o-mini, GLM-5.2)."
        )
    if not client.api_key:
        key_var = ("LLMHUB_API_KEY" if provider.name == providers.DEFAULT_NAME
                   else providers.var(provider.name, "API_KEY"))
        sys.exit(f"atlas: no API key for provider {provider.name!r}. Set "
                 f"{key_var} (env, .env, or `bin/atlas-secret set {key_var}`).")
    # Short GET /models probe — adapt context window + char budget to the
    # live model metadata (no local LLM catalogue). Network failures are
    # fail-open; a catalogue miss (wrong model id) is a config error.
    try:
        from core.model_context import probe_and_apply
        result = probe_and_apply(provider, model, log=ui.info, warn=ui.warn)
        if getattr(result, "source", "") == "unknown_model":
            sys.exit(f"atlas: {result.error}")
    except Exception as _probe_exc:
        ui.warn(f"model context probe skipped: {_probe_exc}")
    # A tool list this model has already shown it cannot answer with a
    # function call is not sent again: the toolbox packs under what was
    # learned, and the rest loads on demand.
    from agent import toolbox as _toolbox_mod
    _toolbox_mod.set_learned_tool_ceiling(client.learned_max_tools())
    ui.info("starting MCP server in-process (tool discovery)…")
    loaded = None
    if case_dir:
        try:
            from core.evidence_profile import ensure_evidence_profile
            from tools.evidence_compat import suggested_core_namespaces
            profile = ensure_evidence_profile(case_dir)
            loaded = suggested_core_namespaces(profile)
            present = ", ".join(profile.get("present_classes") or []) or "(none)"
            ui.info(f"evidence profile: {profile.get('file_count', 0)} files; "
                    f"classes=[{present}]; core namespaces={list(loaded)}")
        except Exception as exc:
            ui.warn(f"evidence profile unavailable ({exc}); using default core "
                    f"namespaces")
    toolbox = Toolbox(loaded=loaded) if loaded else Toolbox()
    left_out = [ns for ns in (loaded or ()) if ns not in toolbox.loaded]
    if left_out:
        from agent.toolbox import max_openai_tools
        ui.warn(f"tool-schema budget ({toolbox.schema_count()}/"
                f"{max_openai_tools()}) left these suggested namespaces out "
                f"of the opening list: {', '.join(left_out)}; they load on "
                f"demand")
    if getattr(args, "all_tools", False):
        from agent.toolbox import MAX_OPENAI_TOOLS
        budget = toolbox.load_with_budget(toolbox.namespaces)
        if budget.get("refused"):
            refused_ns = ", ".join(item["namespace"] for item in budget["refused"])
            ui.warn(
                f"--all-tools hit the tool-schema budget "
                f"({budget['schema_count']}/{MAX_OPENAI_TOOLS}); "
                f"not loaded: {refused_ns}. "
                f"Override with ATLAS_AGENT_MAX_OPENAI_TOOLS if the provider "
                f"allows more than {MAX_OPENAI_TOOLS}."
            )
    ui.banner(model, client.base_url, case_dir,
              tools=len(toolbox.tools), namespaces=len(toolbox.namespaces),
              loaded=len(toolbox.loaded))
    # chat is always interactive; run gains it via --interactive.
    interactive = getattr(args, "interactive", False) or command == "chat"
    agent = Agent(client, toolbox, case_dir,
                  quiet=getattr(args, "quiet", False), ui=ui, command=command,
                  interactive=interactive)
    # Every model request of this process, and of the learner it spawns,
    # is recorded under this case, run and user; the run id is the
    # transcript's stamp, so a ledger run names its transcript.
    transcript = getattr(agent, "transcript_path", None)
    _configure_usage(case_dir, command,
                     Path(transcript).stem.rsplit("_", 1)[-1] if transcript else "")
    return agent


def _configure_usage(case_dir: Path | None, command: str, run_id: str = "") -> None:
    """The usage ledger's context for this process: the brief's case id, one
    run id per command (a command that configured first keeps its id when
    the agent starts later in the same case), the command and the user."""
    import getpass
    from datetime import datetime, timezone
    from core import usage_ledger
    from core.paths import detect_case_id
    case_id = (detect_case_id(case_dir) or case_dir.name) if case_dir else ""
    current = usage_ledger.current()
    if current.get("case_id") == case_id and current.get("run_id"):
        run_id = current["run_id"]
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - a uid without a name records none
        user = ""
    usage_ledger.configure(
        case_id=case_id,
        run_id=run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        command=command,
        started_by=os.environ.get("ATLAS_RUN_USER") or user)


def _add_skin_arg(parser: argparse.ArgumentParser) -> None:
    """Attach --skin to commands that show the animated LIVE dashboard."""
    from agent.tui import LIVE_SKINS
    parser.add_argument(
        "--skin", metavar="NAME", choices=sorted(LIVE_SKINS),
        default=None,
        help="LIVE dashboard animation skin (atlas|matrix|radar|wave|aquarium); "
             "overrides ATLAS_LIVE_SKIN and ~/.atlas/ui.json — "
             "set a default with `atlas skin NAME`",
    )


def cmd_skin(args) -> None:
    """List or persist the LIVE dashboard animation skin."""
    from agent.tui import (
        LIVE_SKINS, DEFAULT_LIVE_SKIN, resolve_live_skin, save_ui_prefs,
        ui_prefs_path, UI,
    )
    name = (getattr(args, "name", None) or "").strip().lower() or None
    if name:
        if name not in LIVE_SKINS:
            sys.exit(f"atlas skin: unknown skin {name!r}; choose from: "
                     + ", ".join(sorted(LIVE_SKINS)))
        path = save_ui_prefs({"live_skin": name})
        print(f"LIVE skin → {name}")
        print(f"saved in {path}")
        print(f"one-shot override: atlas run --skin {name} …")
    else:
        current = resolve_live_skin()
        print("LIVE dashboard skins")
        print(f"(active: {current}; default: {DEFAULT_LIVE_SKIN})\n")
        for key, desc in LIVE_SKINS.items():
            mark = "*" if key == current else " "
            print(f" {mark} {key:10}  {desc}")
        print("\nSet default:  atlas skin NAME")
        print("One-shot:     atlas run --skin NAME …")
        print("Env:          ATLAS_LIVE_SKIN=NAME")
        print(f"Prefs file:   {ui_prefs_path()}")
    if getattr(args, "preview", False):
        preview = name or resolve_live_skin()
        from rich.console import Console
        c = Console(force_terminal=True)
        ui = UI(console=c, skin=preview)
        ui.set_run_state(command="run", turn=3, tools=12, findings=2,
                         errors=0, infos=1, tokens=45678,
                         run_start=ui._clock() - 125.0,
                         activity="Following the USN trail")
        print()
        for i in range(6):
            c.print(ui._render_dashboard(frame=i * 3))
            if i < 5:
                print()



def _resolve_case_question(args, case_dir: Path) -> str:
    """Resolve investigation objectives: CLI -q override, else CASE.md tasks,
    else the standard objective.

    Never returns empty. A case with no stated question used to be refused,
    which turned "here is a disk, look at it" into an error the operator had
    to work around; the fallback asks the question that case is actually
    asking. `question_was_defaulted()` says whether it happened, so a run can
    say so rather than pretend an objective was given.
    """
    q = (getattr(args, "question", None) or "").strip()
    if q:
        return q
    from core.investigation_tasks import DEFAULT_OBJECTIVE, objectives_from_tasks
    derived = objectives_from_tasks(case_dir)
    if derived:
        return derived
    # Last resort: parse CASE.md without requiring a prior Plane A persist
    from core.investigation_tasks import parse_case_requests, read_case_markdown
    reqs = parse_case_requests(read_case_markdown(case_dir))
    if reqs:
        if len(reqs) == 1:
            return reqs[0]
        return "Investigate the following open requests:\n- " + "\n- ".join(reqs)
    return DEFAULT_OBJECTIVE


def question_was_defaulted(args, case_dir: Path) -> bool:
    """True when neither -q nor the case named an objective."""
    from core.investigation_tasks import DEFAULT_OBJECTIVE
    return _resolve_case_question(args, case_dir) == DEFAULT_OBJECTIVE and not (
        getattr(args, "question", None) or "").strip()


def _objective_source(args, case_dir: Path) -> str:
    """Where the run's objective came from, as core.run_state records it:
    "question" for -q, "default" for the standard objective, "tasks" for
    the case's own requests."""
    if (getattr(args, "question", None) or "").strip():
        return "question"
    if question_was_defaulted(args, case_dir):
        return "default"
    return "tasks"


def _run_investigation(args, case_dir: Path, command: str = "run",
                       lock_fd: int | None = None):
    """Shared body of `run` and `train`: build the agent, run the full
    investigation, and return the finished Agent (stats populated)."""
    from agent.prompts import build_system_prompt, initial_user_message

    if getattr(args, "json", False):
        args.quiet = True

    # Answer-key protection is anchored to the REAL case dir, resolved before
    # the mirror swap below. An --output-dir run works in a mirror
    # that already omits the key; a plain `atlas train` works in the case dir
    # where the key sits, so it also gets the filesystem stash.
    real_case = case_dir
    using_mirror = bool(getattr(args, "output_dir", None))

    # The command that passed a lock holds and releases it; a caller that
    # passed none gets one here, released when the session settles.
    from core import run_lock
    _run_lock_fd = None
    if lock_fd is None:
        try:
            _run_lock_fd = run_lock.acquire(real_case)
        except run_lock.RunLockedError as e:
            sys.exit(f"atlas: {e}")
    _install_stack_dump_signal(real_case)

    if getattr(args, "output_dir", None):
        case_dir = _prepare_output_dir(case_dir, args.output_dir)
    _ensure_case_layout(case_dir)
    try:
        from tools.tool_capabilities import missing_binaries
        _missing = missing_binaries()
        if _missing:
            print("atlas: programs not found on PATH — their tools will fail when called: "
                  + ", ".join(f"{b} ({ns})" for ns, b in _missing), file=sys.stderr)
        from tools.tool_capabilities import missing_modules
        _mods = missing_modules()
        if _mods:
            print("atlas: Python modules not installed — their tools will fail when called: "
                  + ", ".join(f"{m} ({ns})" for ns, m in _mods), file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass

    # Plane A first: evidence catalog, CASE.md→tasks, investigation plan.
    # Continuity entry point for every atlas run / train analyst phase.
    # Its disk-image auto-mount goes through the same run() every tool
    # uses, and run() records each call in the trace or refuses to go on,
    # so the trace is opened here, at the path the analyst is told to use;
    # the analyst's start_execution_log then resumes this file.
    _trace_path = _open_trace_before_plane_a(case_dir)
    from core.incremental import plane_a_scan
    plane = plane_a_scan(
        case_dir,
        persist=True,
        trigger=f"cli-{command}",
        write_journal=True,
        no_agent=True,
    )
    if not plane.get("success"):
        sys.exit(f"atlas: Plane A failed: {plane.get('error')}")

    # What the analyst already knows earns the first precautions before the
    # first tool runs — recorded as prior knowledge, never as findings.
    try:
        from core.ir_playbook import seed_from_intake
        seeded = seed_from_intake(case_dir)
        if seeded.get("seeded"):
            print(f"atlas: {len(seeded['seeded'])} precaution(s) from the case intake "
                  f"({', '.join(seeded['classes']) or 'general'}) recorded for the "
                  f"Response view", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — a precaution must not stop a run
        print(f"atlas: intake precautions not seeded: {exc!r}", file=sys.stderr)

    # Every agent session must re-inventory evidence before parsers
    # (hard gate in middleware). Plane A may leave a prior stamp if
    # evidence did not change — clear so the latch fires again.
    try:
        from core.evidence_inventory_gate import clear_inventory_stamp
        clear_inventory_stamp(case_dir)
    except Exception:
        pass

    question = _resolve_case_question(args, case_dir)
    if question_was_defaulted(args, case_dir):
        print(f"atlas: no objective in CASE.md and no --question — "
              f"investigating the standard objective: {question!r}",
              file=sys.stderr)
    # The report gate reads this record to know which question the run was
    # given instead of finding it in the model's own words.
    try:
        from core.run_state import record_objective
        record_objective(case_dir, text=question, source=_objective_source(args, case_dir),
                         trace_path=_trace_path or "")
    except Exception as exc:  # noqa: BLE001 - the gate falls back to the marker
        print(f"atlas: run objective not recorded: {exc!r}", file=sys.stderr)

    remote_cfg = _configure_remote(args, case_dir)
    agent = _make_agent(args, case_dir, command=command)
    system = build_system_prompt(case_dir, interactive=agent.interactive)
    user = initial_user_message(
        question,
        agent.toolbox.namespace_summary(),
        case_id=getattr(args, "case_id", "") or plane.get("case_id") or "",
        case_dir=case_dir,
    )

    # Positive-identifier gate: block the case's real grading file(s) by
    # realpath however they are later referenced (symlink, relative, mount).
    # Runs in the analyst's own process, so the in-process MCP server, executor
    # and jobs runner all consult the same registry.
    from core import paths as _paths
    from core.brain.answer_key import has_ground_truth
    _paths.register_answer_keys(real_case)
    if using_mirror:
        _paths.register_answer_keys(case_dir)  # key reachable via evidence link
    # Filesystem belt for the graded `train` context specifically: move the
    # key out of the analyst's tree for the analyst phase, restore it in the
    # finally below (before the reviewer/grader read it in cmd_train). Scoped
    # to train — an --output-dir run already works in a mirror that
    # omits the key, and interactive run/chat sessions leave the file in place
    # (the realpath gate still guards it). Self-heal a prior crash-interrupted
    # stash for this case first.
    stashed: list[dict] = []
    if command == "train" and not using_mirror and has_ground_truth(real_case):
        _paths.recover_stashed_answer_keys(real_case)
        stashed = _paths.stash_answer_keys(real_case)
        if stashed:
            agent.ui.info(f"answer-key guard: {len(stashed)} grading file(s) "
                          "moved out of the analyst tree for this run")

    if remote_cfg is not None:
        _remote_sync_up(remote_cfg, agent.ui)

    def _settle() -> None:
        run_lock.release(_run_lock_fd)
        if remote_cfg is not None:
            _remote_sync_down(remote_cfg, agent.ui)
        else:
            # Local runs only: remote mounts live on the VM, not under this
            # case dir. Unmount anything the run left mounted so it neither
            # leaks across runs nor trips a later clear_case_run.
            _teardown_local_mounts(case_dir, agent.ui)
        # Restore the answer key so the reviewer/grader (and the next run) see
        # it. Guaranteed on the normal path, on LLMError (sys.exit runs the
        # finally), and on any other exception.
        _paths.restore_answer_keys(stashed)

    return _run_agent_session(args, case_dir, agent, system, user, cleanup=_settle)


def _run_agent_session(args, case_dir: Path, agent, system: str, user: str, *,
                       cleanup=None):
    """Run one investigator session and settle its ending the same way for
    every command that starts one: the dashboard's SIGTERM is routed through
    the interrupt path, a provider failure or a crash is recorded rather
    than lost, the report the findings support is written when the analyst
    did not write one, the final status is persisted and the finished
    notification sent. ``cleanup`` runs first in the finally, whatever the
    ending: lock release, mounts, remote sync.

    Returns the agent on a clean ending; re-raises KeyboardInterrupt after
    settling; exits 1 after a provider failure.
    """
    from agent.llm import LLMError
    interrupted = False
    # The dashboard's Stop sends SIGTERM (then SIGKILL after 10 s). Python
    # has no default handler for it, so the run died mid-turn with no exit
    # record and no report. Route it through the
    # interrupt path, which persists the status and writes the report.
    try:
        import signal as _signal

        def _on_sigterm(_signum, _frame):
            _stop_tool_children()
            raise KeyboardInterrupt
        _signal.signal(_signal.SIGTERM, _on_sigterm)
    except (ValueError, OSError):
        pass    # not the main thread / unsupported platform: keep the default
    llm_error: Exception | None = None
    try:
        agent.run(system, user)
    except LLMError as e:
        # Persisted below, in finally — previously this branch went
        # straight to sys.exit(1) without ever writing run_status.json, so
        # a run that died here (a token/context-limit rejection from the
        # LLM API is the common real-world case — LLMError covers any
        # provider failure) left the file frozen on its last
        # _persist_live_status() snapshot, "stopped_reason": "running",
        # forever. A dashboard operator with no SSH access saw nothing at
        # all: not "finished", not an error, just a run that silently
        # stopped updating.
        llm_error = e
    except KeyboardInterrupt:
        # Persist interrupted status in finally — previously
        # _persist_run_status ran only after a normal return, so Ctrl+C
        # left .atlas/run_status.json as "starting" or missing.
        interrupted = True
    finally:
        # Anything else propagating out of agent.run() (an unexpected bug,
        # not LLMError/KeyboardInterrupt) hits this finally too — same
        # silent-run_status.json-staleness problem, and the fix is the same
        # write, keyed off whichever exception is actually in flight rather
        # than a broad `except Exception` that would swallow the traceback.
        _exc_type, _exc_val, _ = sys.exc_info()
        _arm_exit_signals()
        _stop_tool_children()
        if cleanup is not None:
            cleanup()
        if interrupted or llm_error is not None or _exc_val is not None:
            stats = dict(getattr(agent, "stats", None) or {})
            if interrupted:
                stats["finish_status"] = "interrupted"
                stats["stopped_reason"] = "keyboard_interrupt"
            elif llm_error is not None:
                stats["finish_status"] = "error"
                stats["stopped_reason"] = "llm_error"
                stats["error"] = str(llm_error)
            else:
                stats["finish_status"] = "error"
                stats["stopped_reason"] = "crashed"
                stats["error"] = f"{_exc_type.__name__}: {_exc_val}"
            # A stop is still an end: every abnormal branch owes the report
            # the findings support (the dashboard Stop button lands here too,
            # and a provider failure or a crash used to exit with none at
            # all). No model call on this path: whatever ended the run may be
            # the provider itself, and an exit path must not wait on it.
            try:
                agent.stats = stats
            except Exception:  # noqa: BLE001 - a half-dead agent still reports
                pass
            _ensure_report_on_exit(case_dir, agent, allow_llm=False)
            stats = dict(getattr(agent, "stats", None) or stats)
            # I8: live snapshot from Agent.run should already carry turns /
            # duration_seconds; keep non-null fallbacks for early interrupts.
            if stats.get("turns") is None:
                stats["turns"] = 0
            if stats.get("duration_seconds") is None:
                stats["duration_seconds"] = 0.0
            agent.stats = stats
            _persist_run_status(case_dir, stats)
            _notify_run_finished(case_dir, stats)
    if interrupted:
        raise KeyboardInterrupt
    if llm_error is not None:
        if getattr(args, "json", False):
            print(json.dumps({"stopped_reason": "llm_error",
                              "error": str(llm_error)}))
        sys.exit(1)
    # Clean return: the run ended on its own terms, so the narrative upgrade
    # over the deterministic report is worth its model calls.
    _ensure_report_on_exit(case_dir, agent, allow_llm=True)
    _persist_run_status(case_dir, agent.stats)
    _notify_run_finished(case_dir, agent.stats)
    return agent


def _ensure_report_on_exit(case_dir: Path, agent, *,
                           allow_llm: bool = True) -> None:
    """A run that stops before the analyst writes the report — turn cap,
    wall clock, stall, provider failure, crash — still owes one.

    The work itself lives in ``core.report_exit``: the deterministic report
    from the claim graph is written first and registered as the deliverable,
    marked as written on exit so nobody mistakes it for the reviewed report.
    ``allow_llm`` decides whether the narrative projection is then attempted
    over it — off on the abnormal branches, where the exit path must not make
    a network call it cannot cancel.
    """
    try:
        from core.report_exit import write_exit_report
        stats = getattr(agent, "stats", None) or {}
        reason = str(stats.get("stopped_reason") or "ended")
        _persist_run_status(case_dir, dict(stats,
                                           activity="writing the final report"))
        res = write_exit_report(case_dir, reason, allow_llm=allow_llm,
                                agent=agent)
        if not res.get("written"):
            return
        try:
            agent.stats["auto_report"] = res["path"]
        except Exception:  # noqa: BLE001 - a half-dead agent still gets the file
            pass
        print(f"atlas: no final report was written ({reason}) — wrote "
              f"{res['path']} from {res['findings']} finding(s) "
              f"({res['source']})", file=sys.stderr)
    except Exception as e:  # noqa: BLE001 - never mask the run's own exit
        print(f"atlas: could not auto-assemble a report: {e}", file=sys.stderr)


def _notify_run_finished(case_dir: Path, stats: dict) -> None:
    """Mail the run's outcome when ATLAS_RUN_NOTIFY_EMAIL names a recipient.

    This is how a run started from the terminal reports its own ending. A run
    the dashboard started is announced by the dashboard instead — it watches
    the process and therefore also sees the endings this process cannot
    report, a crash or a kill — so it sets ATLAS_RUN_NOTIFY_HANDLED in the
    child environment and this stays quiet. Best-effort throughout: a
    notification must never affect the run that earned it.
    """
    to_addr = (os.environ.get("ATLAS_RUN_NOTIFY_EMAIL") or "").strip()
    handled = (os.environ.get("ATLAS_RUN_NOTIFY_HANDLED") or "").strip()
    if not to_addr or handled:
        return
    try:
        from core import mail
        if not mail.is_configured():
            return
        mail.send_run_finished_email(to_addr, case_dir.name, dict(stats or {}))
    except Exception as exc:  # noqa: BLE001 — the run already succeeded
        print(f"atlas: could not send the run notification: {exc!r}",
              file=sys.stderr)


def _persist_run_status(case_dir: Path, stats: dict) -> None:
    """Persist the run's completion classification to .atlas/run_status.json.

    finish_status (complete / incomplete_coverage / exited_degraded_incomplete)
    previously reached only the TUI banner; status, dashboard and rerun
    consumers had no durable record of whether the last run was truthful-
    complete. Best-effort — never fails the run.
    """
    try:
        import json as _json
        from datetime import datetime, timezone
        p = Path(case_dir) / ".atlas" / "run_status.json"
        # Merge onto whatever the in-run live snapshot last wrote
        # (agent/loop.py's _persist_live_status: pid, input/output tokens,
        # tool_calls, recent_errors, activity, ...) instead of replacing the
        # whole file — a plain overwrite here wiped all of that the instant
        # a run finished, so the dashboard's completed-run view showed none
        # of it.
        existing: dict = {}
        if p.is_file():
            try:
                loaded = _json.loads(p.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    existing = loaded
            except (OSError, ValueError):
                pass
        existing.update({
            "finish_status": str(stats.get("finish_status") or ""),
            "stopped_reason": str(stats.get("stopped_reason") or ""),
            "turns": stats.get("turns"),
            "duration_seconds": stats.get("duration_seconds"),
            # Non-empty only for an abnormal stop (llm_error / crashed) —
            # see cmd_run's finally block. The dashboard shows this instead
            # of silently falling back to "No active run" with no
            # explanation of why a run actually ended.
            "error": str(stats.get("error") or ""),
            "updated_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
        })
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(
            _json.dumps(existing, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        os.replace(tmp, p)
    except Exception:
        pass


def _teardown_local_mounts(case_dir: Path, ui) -> None:
    """Unmount forensic mounts a run left under the case dir (ewfmount/ntfs/
    loop at <case>/mnt/...). Best-effort: failures are warned, never raised."""
    from core import mounts
    try:
        result = mounts.unmount_all_under(str(case_dir))
    except Exception as e:  # teardown must never mask the run's own outcome
        ui.warn(f"teardown: mount cleanup failed: {e}")
        return
    for mp in result["unmounted"]:
        ui.info(f"teardown: unmounted {mp}")
    for f in result["failed"]:
        ui.warn(f"teardown: could not unmount {f['mount']}: {f['error']}")


def _configure_remote(args, case_dir: Path):
    """Translate --remote flags into the env vars core.remote reads, and return
    the active remote config (or None when not requested). Case dir becomes the
    local root that maps to the VM workspace in copy mode."""
    host = getattr(args, "remote", None)
    if not host:
        return None
    os.environ["ATLAS_REMOTE_SIFT"] = host
    os.environ["ATLAS_REMOTE_MODE"] = getattr(args, "remote_mode", None) \
        or "resident"
    if getattr(args, "remote_workspace", None):
        os.environ["ATLAS_REMOTE_WORKSPACE"] = args.remote_workspace
    os.environ["ATLAS_REMOTE_LOCAL_ROOT"] = str(case_dir)
    from core import remote
    return remote.remote_config()


def _remote_sync_up(cfg: dict, ui) -> None:
    from core import remote
    if cfg["mode"] != "copy":
        ui.info(f"remote-SIFT: tools run on {cfg['host']} (resident evidence)")
        return
    ui.info(f"remote-SIFT: copying evidence up to {cfg['host']}:{cfg['workspace']}…")
    r = remote.sync_evidence_up(cfg)
    if not r.get("success"):
        ui.warn(f"remote evidence sync failed: {r.get('error') or r.get('stderr')}")


def _remote_sync_down(cfg: dict, ui) -> None:
    from core import remote
    if cfg["mode"] != "copy":
        return
    ui.info("remote-SIFT: syncing analysis/exports/reports back from the VM…")
    r = remote.sync_outputs_back(cfg)
    if not r.get("success"):
        ui.warn(f"remote output sync failed: {r}")


def _apply_report_language(args, case_dir) -> None:
    """Persist ``--language`` / ``-L`` into ``.atlas/case_config.json`` when set."""
    lang = getattr(args, "language", None)
    if not lang:
        return
    from core.case_config import set_report_language
    try:
        set_report_language(case_dir, lang)
    except ValueError as e:
        sys.exit(f"atlas: {e}")


def _prepare_run_isolation(args, case_dir: Path) -> None:
    """Enforce fresh vs resume for process (transient) run state.

    Persistent CIS under .atlas/ (claims, tasks, plan, ledger unit list) is
    kept by clear_case_run. Transient process state (analysis/exports/reports
    traces, ledger statuses, session beacon) is wiped on --fresh, or
    automatically when a prior run already finished / left process artifacts
    and --resume was not requested — preventing silent Scan@depth=7 append.
    """
    resume = bool(getattr(args, "resume", False))
    fresh = bool(getattr(args, "fresh", False))
    if resume and fresh:
        sys.exit("atlas: pass only one of --fresh / --resume")
    if resume:
        print("atlas: resuming prior execution trace (--resume)",
              file=sys.stderr)
        return
    terminal = _prior_run_is_terminal(case_dir)
    leftover = _prior_process_artifacts_present(case_dir)
    should_clear = fresh or terminal or leftover
    if not should_clear:
        return
    from tools.misc import clear_case_run
    try:
        from core.handling_stop import refuse_fresh_start as _refuse_fresh_start
        _refuse = _refuse_fresh_start(str(case_dir))
    except Exception:  # noqa: BLE001
        _refuse = None
    if _refuse:
        sys.exit(f"atlas: {_refuse}")
    result = clear_case_run(str(case_dir), clear_memory=False)
    if result.get("success") is False:
        sys.exit(f"atlas: {result.get('error')}")
    # Whatever the clear could not remove, the run would start on top of;
    # say so now rather than report a run as fresh that is not.
    if result.get("errors"):
        sys.exit("atlas: case clear failed: " + "; ".join(result["errors"]))
    # Drop the prior finish classification so a crash mid-run does not keep
    # looking "terminal" — isolation is process-scoped until the next finish.
    isolation = (
        "fresh" if fresh
        else ("auto_fresh_after_terminal" if terminal
              else "auto_fresh_after_leftover_trace")
    )
    try:
        import json as _json
        from datetime import datetime, timezone
        status_path = case_dir / ".atlas" / "run_status.json"
        status_path.parent.mkdir(parents=True, exist_ok=True)
        status_path.write_text(_json.dumps({
            "stopped_reason": "starting",
            "finish_status": "",
            "cleared_at": datetime.now(timezone.utc).isoformat(),
            "isolation": isolation,
        }, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass
    if fresh:
        reason = "--fresh"
    elif terminal:
        reason = ("prior run finished — starting a new process run "
                  "(pass --resume to continue the old trace)")
    else:
        reason = ("prior process artifacts found — starting a new process "
                  "run (pass --resume to continue the old trace)")
    print(f"atlas: cleared process state for a fresh run ({reason}; "
          f"{result.get('cleared_count', 0)} items removed). "
          "Claims/tasks under .atlas/ are retained.",
          file=sys.stderr)


def _needs_root(case_dir) -> bool:
    """Whether this case can need root at all: only mounting disk images
    and loop devices does. A case of exports and logs alone never uses
    passwordless sudo, so refusing it for lacking one would answer a
    question the evidence already answers."""
    if not case_dir:
        return True
    try:
        from core.evidence_profile import build_evidence_profile
        present = set(build_evidence_profile(case_dir).get("present_classes") or [])
    except Exception:  # noqa: BLE001
        return True
    return bool(present & {"disk", "memory"})


def _require_sudo_preflight(args, case_dir=None) -> None:
    """Abort before Plane A / clear when passwordless sudo is unavailable."""
    from core.sudo_preflight import require_passwordless_sudo
    if (not getattr(args, "all_tools", False) and case_dir is not None
            and not _needs_root(case_dir)):
        print("atlas: no disk or memory evidence in this case — passwordless "
              "sudo not required, preflight skipped", file=sys.stderr)
        return
    require_passwordless_sudo(
        skip=bool(getattr(args, "skip_sudo_check", False)),
    )


_STACK_DUMP_HANDLE = None


def _install_stack_dump_signal(case_dir) -> None:
    """``kill -USR1 <pid>`` writes every thread's stack to
    ``analysis/run_stacks.log`` of the case.

    A run that stops moving with no error and no heartbeat leaves nothing to
    read: the process sleeps in a system call, and attaching a debugger is
    not permitted on most hosts. The dump comes from the standard library's
    fault handler, which works from inside a blocking call, costs nothing
    until asked for, and names the frame the run is waiting in.
    """
    global _STACK_DUMP_HANDLE
    import faulthandler
    import signal
    try:
        path = Path(case_dir) / "analysis" / "run_stacks.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(path, "a", encoding="utf-8")  # noqa: SIM115 - kept open for the handler
        faulthandler.register(signal.SIGUSR1, file=handle, all_threads=True,
                              chain=False)
        _STACK_DUMP_HANDLE = handle
    except Exception:  # noqa: BLE001 - a diagnostic must never stop a run
        _STACK_DUMP_HANDLE = None


@contextlib.contextmanager
def _held_run_lock(case_dir: Path):
    """The case's run lock for the whole command. A second start of a live
    case fails here, before it changes the report language or clears the
    case under the running investigation, and the lock stays until the
    run's last write (exit report, status, notification, learn spawn,
    review) is done."""
    from core import run_lock
    try:
        fd = run_lock.acquire(case_dir)
    except run_lock.RunLockedError as e:
        sys.exit(f"atlas: {e}")
    try:
        yield fd
    finally:
        run_lock.release(fd)


def _stamp_run_start() -> None:
    """When this run started, for everything that reports its elapsed time:
    set once, here, before isolation and the evidence stage. A run the
    dashboard started carries the moment Start was pressed instead."""
    os.environ.setdefault("ATLAS_RUN_STARTED_AT",
                          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def cmd_run(args) -> None:
    _stamp_run_start()
    # Legacy capture (review-bullet mining) remains opt-in via --capture-brain
    # or ATLAS_CAPTURE_BRAIN. Background investigation *learning* now runs by
    # default after a finished run — that is the primary Brain growth path.
    if getattr(args, "no_capture_brain", False):
        args.capture_brain = False
    elif (os.environ.get("ATLAS_CAPTURE_BRAIN") or "").strip().lower() in (
            "1", "true", "yes", "on"):
        args.capture_brain = True
    # Apply brain flags for run as well (injection kill switch).
    _apply_brain_flags(args)
    case_dir = _resolve_case(args.case)
    if case_dir is None:
        sys.exit("atlas: not inside a case directory — pass --case DIR "
                 "(see case-template/).")
    with _held_run_lock(case_dir) as lock_fd:
        _run_locked(args, case_dir, lock_fd)


def _run_locked(args, case_dir: Path, lock_fd: int) -> None:
    _require_sudo_preflight(args, case_dir)
    _apply_report_language(args, case_dir)
    # With --output-dir the isolation clears the mirror, never the real case;
    # _run_investigation resolves the same mirror again (the call is idempotent).
    effective_dir = case_dir
    if getattr(args, "output_dir", None):
        effective_dir = _prepare_output_dir(case_dir, args.output_dir)
    _prepare_run_isolation(args, effective_dir)
    agent = _run_investigation(args, case_dir, lock_fd=lock_fd)

    from core.investigation_exit import ended_through_a_completion_path
    finish_status = str(agent.stats.get("finish_status") or "")
    # Truthful completion: finish_status says whether coverage + beliefs
    # actually support calling the investigation complete, and is the only
    # owner of that verdict. Reading stopped_reason for it instead counted
    # a run the loop closed out itself as unfinished, although its reports
    # were written and its gate had passed. Empty finish_status must NOT
    # count as complete or as an ending (fail-closed).
    finished = ended_through_a_completion_path(finish_status)
    complete = finish_status == "complete"
    captured = None
    # Optional legacy staging (review bullets / self-corrections). Same
    # complete-gate as primary learn — hollow runs must not seed the brain.
    if getattr(args, "capture_brain", False):
        if not complete:
            agent.ui.warn(
                f"brain: legacy capture skipped — finish status "
                f"'{finish_status or 'unset'}' (only complete runs feed "
                f"the brain)")
        else:
            try:
                from core.brain.capture import capture_case
                captured = capture_case(case_dir, command="run")
                agent.ui.info(
                    f"brain: staged {captured['candidates']} legacy "
                    f"candidate(s); run summary: {captured['run_summary']}")
            except Exception as e:
                agent.ui.warn(f"brain capture skipped: {e}")

    # Primary learning: only after a truthfully COMPLETE investigation
    # (unless disabled). Degraded / incomplete-coverage runs must not feed
    # the brain — it would learn from exactly the runs that failed.
    if finished and not getattr(args, "no_brain", False):
        if not complete:
            agent.ui.warn(
                f"brain: learning skipped — finish status "
                f"'{finish_status}' (only complete runs feed the brain)")
        else:
            try:
                from core.brain.background import spawn_investigation_learn
                spawned = spawn_investigation_learn(
                    case_dir, case_id=case_dir.name,
                    question=getattr(args, "question", "") or "",
                    command="run", source_dir=effective_dir)
                if spawned.get("spawned"):
                    agent.ui.info(
                        f"brain: background learn started "
                        f"(pid {spawned.get('pid')}); "
                        f"review later at Dashboard → Brain Review")
                elif spawned.get("reason") and spawned.get("reason") != "disabled":
                    agent.ui.warn(
                        f"brain learn not spawned: {spawned.get('reason')}")
            except Exception as e:
                agent.ui.warn(f"brain learn spawn skipped: {e}")

    if getattr(args, "json", False):
        import json
        out = dict(agent.stats)
        out["brain"] = {
            "legacy_capture": bool(getattr(args, "capture_brain", False)),
            "candidates": (captured or {}).get("candidates"),
            "learn_queued": complete and not getattr(args, "no_brain", False),
        }
        print(json.dumps(out, ensure_ascii=False))
    if not finished:
        sys.exit(2)
    if not complete:
        # The loop ended via atlas_finish but coverage/beliefs do not support
        # "complete" — exit distinctly so scripts and CI see the difference.
        sys.exit(4)


def _build_reviewer_client(args, analyst_model: str = "", ui=None):
    """Construct the independent reviewer's LLM client (distinct model where
    configured). Warns when it shares the analyst's model."""
    from agent.llm import LLMHubClient, LLMError
    from agent.review import reviewer_model, reviewer_provider
    from core import providers
    model = getattr(args, "review_model", "") or reviewer_model()
    client = LLMHubClient(provider=reviewer_provider(), model=model)
    try:
        provider = client.provider
        resolved_model = client.model
    except (providers.UnknownProvider, LLMError) as e:
        sys.exit(f"atlas: {e}")
    if not client.api_key:
        key_var = ("LLMHUB_API_KEY" if provider.name == providers.DEFAULT_NAME
                   else providers.var(provider.name, "API_KEY"))
        sys.exit(f"atlas: no API key for provider {provider.name!r}. Set "
                 f"{key_var} (env, .env, or `bin/atlas-secret set {key_var}`).")
    if ui is not None and analyst_model and resolved_model == analyst_model:
        ui.warn(f"reviewer shares the analyst model ({resolved_model}) — set "
                "ATLAS_REVIEW_MODEL for a distinct reviewer; the review still "
                "runs with a fresh, independent context")
    return client


def cmd_review(args) -> None:
    """Independent review of an investigation. With --live, review an in-flight
    run from its on-disk trace and emit unstick recommendations; otherwise a
    stall pre-check + review of the trace as it stands. Read-only, never
    mutates the trace. Exit: 0 healthy, 3 stalled."""
    from agent.llm import LLMError
    from agent.review import Reviewer, resolve_review_trace
    from agent.tui import UI

    case_dir = _resolve_case(args.case) or Path.cwd()
    ui = UI(quiet=getattr(args, "json", False))
    if args.trace:
        trace = Path(args.trace).expanduser()
    else:
        trace, warn = resolve_review_trace(case_dir,
                                           case_explicit=bool(args.case))
        if warn:
            ui.warn(warn)
    if trace is None:
        sys.exit("atlas: no active investigation trace found — pass --trace "
                 "PATH (or start one so ~/.cache/atlas/session.json points at "
                 "it).")
    # Name the trace up front — a review of the wrong case must be obvious
    # before the reviewer spends minutes on it, not after.
    print(f"atlas: reviewing trace: {trace}", file=sys.stderr)
    _configure_usage(case_dir, "review")
    client = _build_reviewer_client(args, ui=ui)
    try:
        review = Reviewer(client, case_dir, ui).review_live(
            trace_path=trace, question=getattr(args, "question", "") or "")
    except LLMError as e:
        sys.exit(f"atlas: live reviewer failed: {e}")
    if review.get("error"):
        sys.exit(f"atlas: {review['error']}")

    ui.info(f"live review ({review['status']}, stall={review['severity']}): "
            f"{review['path']}")
    ui.markdown(review["review"])
    if getattr(args, "json", False):
        import json
        print(json.dumps({k: review[k] for k in
                          ("status", "stalled", "severity", "hits", "path",
                           "reviewer_model", "trace_path")},
                         ensure_ascii=False))
    if review["stalled"]:
        sys.exit(3)


def _apply_brain_flags(args) -> None:
    """--no-brain means no brain at all. The injection kill switch is the
    ATLAS_NO_BRAIN env var agent.prompts._brain_context reads at prompt-build
    time, so it must be set before _run_investigation builds the system
    prompt (post-run candidate staging is gated separately in cmd_train)."""
    if getattr(args, "no_brain", False):
        os.environ["ATLAS_NO_BRAIN"] = "1"


def cmd_train(args) -> None:
    """A fresh, complete run, then an independent reviewer grades it and
    writes reports/<CASE_ID>_run_review.md (recommendations only if the run
    needs them). Exit: 0 ok, 2 run didn't finish, 3 review says NEEDS WORK,
    4 incomplete finish_status / cross-case review refused. Brain capture
    and learn run only when finish_status == complete."""
    _stamp_run_start()
    _apply_brain_flags(args)
    case_dir = _resolve_case(args.case)
    if case_dir is None:
        sys.exit("atlas: not inside a case directory — pass --case DIR "
                 "(see case-template/).")
    with _held_run_lock(case_dir) as lock_fd:
        _train_locked(args, case_dir, lock_fd)


def _train_locked(args, case_dir: Path, lock_fd: int) -> None:
    # Before clear — do not wipe the case if sudoers is missing.
    _require_sudo_preflight(args, case_dir)
    _apply_report_language(args, case_dir)

    # An objective always resolves now (the standard one when the case names
    # none), so there is nothing to fail fast on here — the notice is printed
    # once, where the run actually starts.

    # With --output-dir the whole run — clear, outputs, review — happens in a
    # mirror case (--output-dir isolation); the real case is never touched.
    effective_dir = case_dir
    if getattr(args, "output_dir", None):
        effective_dir = _prepare_output_dir(case_dir, args.output_dir)

    if not args.no_clear:
        from tools.misc import clear_case_run
        # A mirror has no case memory of its own, so leave memory alone.
        try:
            from core.handling_stop import refuse_fresh_start as _refuse_fresh_start
            _refuse = _refuse_fresh_start(str(effective_dir))
        except Exception:  # noqa: BLE001
            _refuse = None
        if _refuse:
            sys.exit(f"atlas: {_refuse}")
        result = clear_case_run(str(effective_dir),
                                clear_memory=effective_dir == case_dir)
        cleared = result.get("cleared_count", 0)
        print(f"atlas: cleared case for a fresh run "
              f"({cleared} items removed; --no-clear to keep prior state)",
              file=sys.stderr)
        if result.get("memory_skipped_reason"):
            print(f"atlas: assistant memory preserved "
                  f"({result['memory_skipped_reason']})", file=sys.stderr)
        if result.get("success") is False:
            sys.exit(f"atlas: {result.get('error')}")
        if result.get("errors"):
            sys.exit("atlas: case clear failed: "
                     + "; ".join(result["errors"]))

    agent = _run_investigation(args, case_dir, command="train", lock_fd=lock_fd)

    from agent.llm import LLMError
    from agent.review import CrossCaseTraceError, Reviewer
    client = _build_reviewer_client(args, analyst_model=agent.client.model,
                                    ui=agent.ui)
    try:
        review = Reviewer(client, effective_dir, agent.ui,
                          gt_dir=case_dir).review(
            agent.stats, question=args.question)
    except CrossCaseTraceError as e:
        # The execution-log singleton drifted to another case mid-run — the
        # review would grade the wrong trace. Refuse loudly rather than emit a
        # report naming the foreign case.
        agent.ui.error(f"review refused (cross-case bleed): {e}")
        sys.exit(4)
    except LLMError as e:
        if getattr(args, "json", False):
            import json
            print(json.dumps({"run": agent.stats,
                              "review": {"error": str(e)}},
                             ensure_ascii=False))
        else:
            agent.ui.error(f"reviewer failed: {e}")
        sys.exit(1)

    agent.ui.info(f"run review ({review['verdict']}): {review['path']}")
    agent.ui.markdown(review["review"])

    from core.investigation_exit import ended_through_a_completion_path
    finish_status = str(agent.stats.get("finish_status") or "")
    # Same truthful-completion gate as cmd_run: finish_status owns the
    # verdict and an empty one is fail-closed. Train must not feed the
    # brain from hollow runs.
    finished = ended_through_a_completion_path(finish_status)
    complete = finish_status == "complete"
    brain_skipped = bool(
        getattr(args, "no_brain", False)
        or getattr(args, "no_brain_capture", False)
    )

    # Second brain: write the run summary (+ legacy candidate staging), then
    # spawn non-blocking investigation learning so reports are never delayed.
    if not brain_skipped:
        if not complete:
            agent.ui.warn(
                f"brain: capture/learn skipped — finish status "
                f"'{finish_status or 'unset'}' (only complete runs feed "
                f"the brain)")
        else:
            try:
                from core.brain.capture import capture_run
                summary = capture_run(
                    effective_dir, _trace_case_id(effective_dir),
                    question=args.question,
                    review_text=review["review"],
                    verdict=review["verdict"], command="train")
                agent.ui.info(
                    f"brain: staged {summary['candidates']} memory "
                    f"candidate(s) ({summary['sensitive_flagged']} flagged "
                    f"sensitive, "
                    f"{summary.get('dropped_case_residue', 0)} case-residue "
                    f"dropped); run summary: {summary['run_summary']}")
            except Exception as e:
                agent.ui.warn(f"brain capture skipped: {e}")
            try:
                from core.brain.background import spawn_investigation_learn
                spawned = spawn_investigation_learn(
                    case_dir,
                    case_id=_trace_case_id(effective_dir),
                    question=args.question,
                    review_text=review["review"],
                    verdict=review["verdict"],
                    command="train", source_dir=effective_dir)
                if spawned.get("spawned"):
                    agent.ui.info(
                        f"brain: background learn started "
                        f"(pid {spawned.get('pid')}); "
                        f"status → {spawned.get('status_file')}")
                elif (spawned.get("reason")
                      and spawned.get("reason") != "disabled"):
                    agent.ui.warn(
                        f"brain learn not spawned: {spawned.get('reason')}")
            except Exception as e:
                agent.ui.warn(f"brain learn spawn skipped: {e}")

    if getattr(args, "json", False):
        import json
        print(json.dumps({
            "run": agent.stats,
            "review": {k: review[k] for k in
                       ("verdict", "needs_work", "path", "reviewer_model")},
            "metrics": review.get("metrics"),
            "models": {
                "analyst": agent.client.model,
                "reviewer": review["reviewer_model"],
                # what the child's tool modules imported at startup
                "reason": os.environ.get("REASON_MODEL") or "(default)",
                "dair": os.environ.get("DAIR_MODEL") or "(default)",
            },
            "brain": {
                "injection_disabled":
                    bool(os.environ.get("ATLAS_NO_BRAIN")),
                "capture_skipped": brain_skipped or not complete,
                "learn_queued": complete and not brain_skipped,
                "finish_status": finish_status,
            },
        }, ensure_ascii=False))
    if not finished:
        sys.exit(2)
    if review["needs_work"]:
        sys.exit(3)
    # Finished + review OK but coverage/beliefs incomplete — distinguish from
    # truthful train success (aligned with cmd_run exit 4).
    if not complete:
        sys.exit(4)


def _open_trace_before_plane_a(case_dir: Path, *, save_session: bool = True) -> str | None:
    """Configure the execution log at analysis/<case_id>_trace.json so the
    pre-run stage can record its tool calls (the mounts it makes). Returns
    the path, or None when the log could not be opened — the run goes on
    and Plane A then reports the calls it could not record."""
    from core.execution_log import log
    from core.paths import detect_case_id
    case_dir = Path(case_dir)
    case_id = detect_case_id(case_dir) or case_dir.name
    analysis = case_dir / "analysis"
    path = analysis / f"{case_id}_trace.json"
    try:
        analysis.mkdir(parents=True, exist_ok=True)
        log.configure(case_id, str(path), save_session=save_session)
    except Exception as e:  # noqa: BLE001
        print(f"atlas: could not open the trace before Plane A: {e}",
              file=sys.stderr)
        return None
    return str(path)


def _trace_case_id(case_dir: Path) -> str:
    """The case ID as the execution log knows it, falling back to the
    newest trace filename, then the directory name."""
    try:
        from core.execution_log import log
        if log._case_id:
            return log._case_id
    except Exception:
        pass
    traces = sorted(case_dir.glob("analysis/*_trace.json"))
    if traces:
        return traces[-1].name[:-len("_trace.json")]
    return case_dir.name


def cmd_chat(args) -> None:
    from agent.prompts import build_system_prompt

    case_dir = _resolve_case(args.case)
    agent = _make_agent(args, case_dir, command="chat")
    agent.chat(build_system_prompt(case_dir, interactive=agent.interactive,
                                   chat=True))


def cmd_interactive(args) -> None:
    """A full autonomous investigation, but supervised: the agent may consult
    you via atlas_ask_analyst at decision points."""
    args.interactive = True
    cmd_run(args)


def cmd_models(args) -> None:
    from agent.llm import LLMHubClient, LLMError
    from core import providers
    name = getattr(args, "provider", "") or ""
    try:
        client = LLMHubClient(provider=name)
        provider = client.provider
    except providers.UnknownProvider as e:
        sys.exit(f"atlas: {e}")
    if not client.api_key:
        key_var = ("LLMHUB_API_KEY" if provider.name == providers.DEFAULT_NAME
                   else providers.var(provider.name, "API_KEY"))
        sys.exit(f"atlas: no API key configured for provider "
                 f"{provider.name!r} ({key_var}).")
    try:
        model_ids = client.list_models()
    except LLMError as e:
        # A rejected key, a retired endpoint or an unreachable host are all
        # operator-facing conditions. A provider answers a rejected key with a
        # plain 401 and its own explanation — print that, not a stack trace.
        sys.exit(f"atlas: {e}")
    for model_id in model_ids:
        print(model_id)


def _print_journal_diff(result: dict, *, a: str, b: str) -> None:
    print(f"Diff {a} → {b}")
    print("Why in B:")
    for w in result.get("why_b") or []:
        print(f"  - {w}")
    print("Reasons only in B:",
          ", ".join(result.get("reasons_only_in_b") or []) or "(none)")
    print("Milestones in B:",
          ", ".join(result.get("milestones_in_b") or []) or "(none)")


def _print_journal_runs(case) -> None:
    from core.run_journal import list_runs, load_milestones

    runs = list_runs(case)
    if not runs:
        print("No journal runs yet.")
        return
    for r in runs:
        print(f"{r['run_id']}  {r.get('finished_at', '')}  "
              f"({r.get('journal_entry_count', 0)} journal entries)")
        for w in (r.get("why_summary") or [])[:3]:
            print(f"    · {w}")
    ms = load_milestones(case).get("milestones") or []
    if ms:
        print("\nMilestones:")
        for m in ms:
            print(f"  - [{m.get('kind')}] {m.get('summary', '')[:120]}")


def _finalize_report_snapshots(
    case,
    plane_a: dict,
    *,
    regen_result: dict | None = None,
    trigger: str = "",
    fp_before: dict | None = None,
) -> dict:
    """Promote immutable report snapshot + append cumulative diff_report.md."""
    from core.report_snapshots import finalize_rerun_reports

    snap = finalize_rerun_reports(
        case,
        plane_a=plane_a,
        regen_result=regen_result,
        trigger=trigger,
        migrate=True,
        fp_before=fp_before,
    )
    if snap.get("snapshot_created"):
        print(
            f"Report snapshot: {snap.get('rerun_dir')} "
            f"(latest → {snap.get('latest')})"
        )
    elif snap.get("material"):
        print(
            "Investigation state changed; no new report files to snapshot "
            f"(see {snap.get('diff_report')})"
        )
    else:
        print(
            "No material investigation-state changes — "
            f"report snapshot skipped (see {snap.get('diff_report')})"
        )
    return snap


def cmd_rerun(args) -> None:
    """Incremental investigation: Plane A always; Plane B regenerates stale sections unless --no-agent."""
    _stamp_run_start()
    case = _resolve_case(args.case)
    if case is None:
        sys.exit("atlas rerun: pass --case DIR or run from a case directory")

    # Same cross-process guard as `atlas run` (core.run_lock) — Plane A below
    # persists to .atlas/ (journal, tasks) and Plane B can run a full agent
    # session, so a concurrent `atlas run`/`rerun` on the same case must be
    # refused here too, not just on the `run` path. Held for this whole
    # command (cmd_rerun is the top-level handler — the process exits
    # shortly after it returns either way, which releases the flock).
    from core import run_lock
    try:
        run_lock.acquire(case)
    except run_lock.RunLockedError as e:
        sys.exit(f"atlas: {e}")
    # Report sections regenerated here call the model before any agent
    # starts; they belong to this rerun in the usage ledger.
    _configure_usage(case, "rerun")

    _apply_report_language(args, case)

    if getattr(args, "diff", None):
        from core.run_journal import diff_runs
        spec = args.diff.strip()
        if ".." not in spec:
            sys.exit("atlas rerun --diff expects RUN_A..RUN_B (e.g. run-0001..run-0002)")
        a, b = [x.strip() for x in spec.split("..", 1)]
        result = diff_runs(case, a, b)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if not result.get("success"):
                sys.exit(f"atlas rerun --diff failed: {result.get('error')}")
            _print_journal_diff(result, a=a, b=b)
        sys.exit(0 if result.get("success") else 2)

    if getattr(args, "list_runs", False):
        from core.run_journal import list_runs, load_milestones
        if args.json:
            print(json.dumps(
                {"runs": list_runs(case), "milestones": load_milestones(case)},
                indent=2))
        else:
            _print_journal_runs(case)
        return

    from core.incremental import format_plane_a_report, plane_a_scan

    analyst_q = (getattr(args, "question", None) or "").strip() or None
    withdraw_id = getattr(args, "withdraw_context", None) or None
    correct_id = getattr(args, "correct_context", None) or None
    if correct_id and not analyst_q:
        sys.exit("atlas rerun: --correct-context requires -q / --question "
                 "with the replacement context text")

    persist = not args.dry_run
    if persist:
        # The pre-run pass may open disk images; those calls are recorded in
        # the trace the analyst then continues, the same as for `atlas run`.
        _open_trace_before_plane_a(Path(case))

    # First persist rerun: migrate flat reports → initial_report/ before Plane A
    # so the baseline fingerprint reflects pre-rerun investigation state.
    fp_before = None
    if persist:
        from core.report_snapshots import (
            ensure_initial_report_layout,
            initial_report_dir,
            investigation_fingerprint,
            prior_fingerprint,
        )
        if not initial_report_dir(case).is_dir():
            fp_before = investigation_fingerprint(case)
            mig = ensure_initial_report_layout(case, fingerprint=fp_before)
            if mig.get("migrated"):
                moved = mig.get("moved") or []
                print(
                    f"Migrated {len(moved)} report file(s) → "
                    f"{mig.get('initial_report')}",
                    file=sys.stderr,
                )
        else:
            fp_before = prior_fingerprint(case)

    result = plane_a_scan(
        case,
        persist=persist,
        force_full_hash=bool(getattr(args, "full_hash", False)),
        trigger="cli",
        write_journal=persist,
        no_agent=True,
        analyst_feedback=analyst_q,
        withdraw_context_id=withdraw_id,
        correct_context_id=correct_id,
    )
    text = format_plane_a_report(result)
    print(text)
    if args.json:
        print(json.dumps(result, indent=2, default=str))

    if not result.get("success"):
        sys.exit(2)

    if args.dry_run:
        print("\n(dry-run: catalog/journal not updated)", file=sys.stderr)
        return

    report_fmt = getattr(args, "report_format", None) or "markdown"

    if getattr(args, "regenerate_sections", False):
        from core.report_projection import assemble_report, regenerate_sections
        gen = regenerate_sections(case, only_stale=True)
        print(json.dumps({"regenerate": gen}, indent=2) if args.json else (
            f"Regenerated sections: {', '.join(gen.get('regenerated') or []) or '(none)'}"
        ))
        if gen.get("errors"):
            for e in gen["errors"]:
                print(f"  error {e.get('section_id')}: {e.get('error')}", file=sys.stderr)
        asm = assemble_report(case, fmt=report_fmt)
        print(f"Assembled ({asm.get('format')}): {asm.get('output_path')} "
              f"(stale left: {', '.join(asm.get('stale_sections') or []) or 'none'})")
        _finalize_report_snapshots(
            case, result, regen_result=gen,
            trigger="regenerate-sections", fp_before=fp_before,
        )
        return

    if getattr(args, "assemble_report", False):
        from core.report_projection import assemble_report
        asm = assemble_report(case, fmt=report_fmt)
        if args.json:
            print(json.dumps(asm, indent=2))
        else:
            if not asm.get("success"):
                sys.exit(f"atlas rerun --assemble-report failed: {asm.get('error')}")
            print(f"Assembled ({asm.get('format')}): {asm.get('output_path')} "
                  f"(stale: {', '.join(asm.get('stale_sections') or []) or 'none'})")
        _finalize_report_snapshots(
            case, result, trigger="assemble-report", fp_before=fp_before,
        )
        return

    if args.no_agent:
        _finalize_report_snapshots(
            case, result, trigger="no-agent", fp_before=fp_before,
        )
        return

    # Plane B: the investigator starts whenever the pre-run pass found work
    # for it — evidence added, changed or removed, a question still open, a
    # finding under review, a fact added to or taken out of the brief.
    work = result.get("work") or {}
    if work.get("pending"):
        _require_sudo_preflight(args, Path(case))
        gen = _run_plane_b(args, Path(case), result, report_fmt)
        _finalize_report_snapshots(
            case, result, regen_result=gen,
            trigger="investigate", fp_before=fp_before,
        )
        return

    # Nothing for the investigator: say so, and keep the report current.
    print(
        "\nNothing new since the previous run: no evidence added or changed, "
        "no open question, no finding under review, no change to the brief. "
        "Add a question or a fact to CASE.md, or place evidence under "
        "evidence/, and run again."
    )
    from core.report_projection import (
        load_manifest,
        regenerate_sections,
        assemble_report,
    )
    brief = Path(case) / ".atlas" / "rerun_brief.md"
    if brief.is_file():
        print(f"Rerun brief: {brief}")
    man = load_manifest(case)
    sections = (man.get("sections") or {}) if isinstance(man, dict) else {}
    stale_or_missing = [
        sid for sid, meta in sections.items()
        if (meta or {}).get("status") in ("stale", "missing")
    ]
    gen: dict = {}
    if stale_or_missing or not sections:
        gen = regenerate_sections(case, only_stale=True)
        print(
            f"Regenerated report sections: "
            f"{', '.join(gen.get('regenerated') or []) or '(none)'}"
        )
        if gen.get("errors"):
            for e in gen["errors"]:
                print(f"  error {e.get('section_id')}: {e.get('error')}",
                      file=sys.stderr)
        asm = assemble_report(case, fmt=report_fmt)
        print(
            f"Assembled ({asm.get('format')}): {asm.get('output_path')} "
            f"(stale left: {', '.join(asm.get('stale_sections') or []) or 'none'})"
        )
    else:
        print("The report is current; use --assemble-report to stitch it anyway.")

    _finalize_report_snapshots(
        case, result, regen_result=gen or None,
        trigger="section-regen", fp_before=fp_before,
    )


def _run_plane_b(
    args, case_dir: Path, plane_a: dict, report_fmt: str,
) -> dict:
    """Start the investigator on what the pre-run pass found: the rerun
    brief, the open questions as the objective, what changed as the reason.
    The session ends the way a run's does (``_run_agent_session``).

    Returns the ``regenerate_sections`` result dict (empty on failure paths).
    """
    from agent.prompts import (
        build_system_prompt,
        initial_rerun_message,
        rerun_objective,
    )
    from core.report_projection import assemble_report, regenerate_sections

    brief_text = plane_a.get("rerun_brief_text") or ""
    if not brief_text:
        bp = case_dir / ".atlas" / "rerun_brief.md"
        if bp.is_file():
            brief_text = bp.read_text(encoding="utf-8")
    work = plane_a.get("work") or {}
    reasons = [str(r) for r in (work.get("reasons") or [])]
    reconcile = plane_a.get("context_reconcile") or {}
    context_added = [str(e.get("text") or "") for e in
                     list(reconcile.get("added") or [])
                     + list(reconcile.get("reactivated") or [])]
    context_withdrawn = [str(e.get("text") or "")
                         for e in (reconcile.get("withdrawn") or [])]

    for name, default in (("model", None), ("quiet", False),
                          ("all_tools", False), ("interactive", False),
                          ("output_dir", None), ("remote", None)):
        if not hasattr(args, name):
            setattr(args, name, default)

    # Every agent session re-inventories the evidence before parsers (hard
    # gate in middleware), a rerun included.
    try:
        from core.evidence_inventory_gate import clear_inventory_stamp
        clear_inventory_stamp(case_dir)
    except Exception:  # noqa: BLE001 - the gate itself still holds
        pass

    print("\nPlane B: starting the investigator"
          + (f" ({'; '.join(reasons)})" if reasons else "") + "…", flush=True)
    agent = _make_agent(args, case_dir, command="rerun")
    system = build_system_prompt(case_dir, interactive=False)
    _rerun_question = rerun_objective(case_dir, work)
    try:
        from core.execution_log import log as _log
        from core.run_state import record_objective
        record_objective(case_dir, text=_rerun_question, source="rerun",
                         trace_path=_log.trace_path() or "")
    except Exception as exc:  # noqa: BLE001 - the gate falls back to the marker
        print(f"atlas: rerun objective not recorded: {exc!r}", file=sys.stderr)
    user = initial_rerun_message(
        brief_text=brief_text,
        namespace_summary=agent.toolbox.namespace_summary(),
        case_id=plane_a.get("case_id") or case_dir.name,
        question=_rerun_question,
        changes=reasons,
        context_added=context_added,
        context_withdrawn=context_withdrawn,
    )
    from core import paths as _paths
    _paths.register_answer_keys(case_dir)
    _run_agent_session(
        args, case_dir, agent, system, user,
        cleanup=lambda: _teardown_local_mounts(case_dir, agent.ui),
    )

    gen = regenerate_sections(case_dir, only_stale=True)
    print(
        f"Plane B: regenerated sections: "
        f"{', '.join(gen.get('regenerated') or []) or '(none)'}"
    )
    asm = assemble_report(case_dir, fmt=report_fmt)
    print(
        f"Assembled ({asm.get('format')}): {asm.get('output_path')} "
        f"(stale left: {', '.join(asm.get('stale_sections') or []) or 'none'})"
    )
    return gen


def cmd_explain(args) -> None:
    from core.investigation_cli import explain, format_explain

    case = _resolve_case(args.case)
    if case is None:
        sys.exit("atlas explain: pass --case DIR or run from a case directory")
    result = explain(
        case,
        node_id=getattr(args, "node_id", None),
        section_id=getattr(args, "section", None),
        conflict_id=getattr(args, "conflict", None),
    )
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(format_explain(result))
    if not result.get("success"):
        sys.exit(2)


def cmd_timeline(args) -> None:
    from core.investigation_cli import build_timeline, format_timeline

    case = _resolve_case(args.case)
    if case is None:
        sys.exit("atlas timeline: pass --case DIR or run from a case directory")
    source = "master" if getattr(args, "from_master", False) else "claims"
    result = build_timeline(case, source=source)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(format_timeline(result, limit=int(getattr(args, "limit", 200) or 200)))
    if not result.get("success"):
        sys.exit(2)


def cmd_journal(args) -> None:
    from core.run_journal import diff_runs, list_runs, load_milestones, load_run

    case = _resolve_case(args.case)
    if case is None:
        sys.exit("atlas journal: pass --case DIR or run from a case directory")
    action = getattr(args, "journal_action", None) or "list"

    if action == "diff":
        spec = (getattr(args, "diff_spec", None) or "").strip()
        if ".." not in spec:
            sys.exit("atlas journal diff expects RUN_A..RUN_B")
        a, b = [x.strip() for x in spec.split("..", 1)]
        result = diff_runs(case, a, b)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if not result.get("success"):
                sys.exit(f"atlas journal diff failed: {result.get('error')}")
            _print_journal_diff(result, a=a, b=b)
        sys.exit(0 if result.get("success") else 2)

    if action == "show":
        run_id = getattr(args, "run_id", None)
        if not run_id:
            sys.exit("atlas journal show requires a run id (e.g. run-0003)")
        run = load_run(case, run_id)
        if run is None:
            sys.exit(f"atlas journal: unknown run {run_id!r}")
        if args.json:
            print(json.dumps(run, indent=2, default=str))
        else:
            print(f"{run.get('run_id') or run_id}  finished={run.get('finished_at')}")
            for w in run.get("why_summary") or []:
                print(f"  · {w}")
            entries = run.get("journal") or run.get("entries") or []
            print(f"Journal entries: {len(entries)}")
            for e in entries:
                reason = e.get("reason") or ""
                summary = (e.get("summary") or e.get("what") or e.get("why") or "")[:160]
                print(f"  [{reason}] {summary}")
        return

    if args.json:
        print(json.dumps(
            {"runs": list_runs(case), "milestones": load_milestones(case)},
            indent=2))
        return
    _print_journal_runs(case)


def cmd_case_autofill(args) -> None:
    """Interactive AI autofill for CASE.md's Evidence Links table.

    Deterministic classification (core.case_autofill.build_proposal) covers
    most evidence files for free; only genuinely ambiguous ones go to the
    connected analyst-role LLM, which itself asks the operator rather than
    guessing when unsure. Investigation Requests are never touched beyond
    the standard question when the section is empty.
    """
    from core import case_autofill, providers
    from core.evidence_links import read_case_md

    case = _resolve_case(args.case)
    if case is None:
        sys.exit("atlas autofill: pass --case DIR or run from a case directory")
    _configure_usage(case, "autofill")

    proposal = case_autofill.build_proposal(case)
    rows = list(proposal["rows"])
    unsure = proposal["unsure"]
    add_request = proposal["investigation_requests_empty"]
    prior = proposal["prior_knowledge"]

    if not rows and not unsure and not add_request and not prior:
        print("atlas autofill: CASE.md is already up to date — nothing to add.")
        return

    resolved: list[dict] = []
    rewrite: dict | None = None
    client = None
    if unsure or prior:
        from agent.llm import LLMError, LLMHubClient
        client = LLMHubClient(provider=providers.role_name("ATLAS_AGENT_PROVIDER"))
        try:
            _ = client.provider
        except Exception as e:
            sys.exit(f"atlas autofill: {e}")
        if not client.api_key:
            sys.exit("atlas autofill: no API key for the configured analyst "
                     "provider — needed to classify unrecognized evidence "
                     "files and to shape 'What you already know'.")
    if unsure:
        print(f"Asking the connected LLM about {len(unsure)} unrecognized "
              "evidence file(s)...")
        try:
            resolved = case_autofill.ask_llm_about_unsure(unsure, client)
        except LLMError as e:
            sys.exit(f"atlas autofill: LLM call failed: {e}")

        for item in resolved:
            if item["question"] and not args.yes:
                print(f"\n{item['path']}")
                print(f"  AI: {item['question']}")
                print(f"  (suggested: label={item['label']!r} "
                      f"kind={item['kind']!r})")
                answer = _ask("Your answer (blank = accept suggestion, "
                              "'skip' = don't add this row)", "")
                if answer.strip().lower() == "skip":
                    continue
                if answer.strip():
                    item["notes"] = (f"{item['notes']} — {answer.strip()}"
                                     if item["notes"] else answer.strip())
            rows.append({"path": item["path"], "label": item["label"],
                        "kind": item["kind"], "notes": item["notes"]})

    if prior:
        print("Asking the connected LLM to shape 'What you already know'...")
        try:
            rewrite = case_autofill.ask_llm_to_reformat_prior_knowledge(prior, client)
        except LLMError as e:
            sys.exit(f"atlas autofill: LLM call failed: {e}")
        if rewrite is None:
            print("  (no usable rewrite came back — the section stays as written)")
        else:
            print("\nWhat you already know, one bullet per fact:")
            for b in rewrite["knowledge"]:
                print(f"  - {b}")
            for r in rewrite["requests"]:
                print(f"  -> Investigation Request: {r}")
            if rewrite["dropped"]:
                print("  WARNING: the rewrite no longer names "
                      + ", ".join(rewrite["dropped"]) + " — put them back by hand.")
            if not args.yes and not _ask_yn(
                    "Rewrite the section as shown?", not rewrite["dropped"]):
                rewrite = None

    print(f"\n{len(rows)} Evidence Links row(s) to add:")
    for r in rows:
        print(f"  {r['label']:20} {r['kind']:10} {r['path']}")
    if add_request:
        print(f"  + standard Investigation Request: {case_autofill.STANDARD_REQUEST!r}")

    if not args.yes and not _ask_yn("Apply these changes to CASE.md?", True):
        print("atlas autofill: aborted — nothing was written.")
        return

    current_md = read_case_md(case)
    try:
        new_md = case_autofill.splice_case_md(
            current_md, rows, add_standard_request=add_request)
        if rewrite:
            new_md = case_autofill.splice_prior_knowledge(
                new_md, rewrite["knowledge"], requests=rewrite["requests"])
    except ValueError as e:
        sys.exit(f"atlas autofill: {e}")

    case_md_path = case / "CASE.md"
    tmp = case_md_path.with_suffix(".md.tmp")
    tmp.write_text(new_md, encoding="utf-8")
    os.replace(tmp, case_md_path)
    print(f"atlas autofill: updated {case_md_path}")


def cmd_status(args) -> None:
    from core.investigation_cli import format_status, investigation_status

    case = _resolve_case(args.case)
    if case is None:
        sys.exit("atlas status: pass --case DIR or run from a case directory")
    result = investigation_status(case)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(format_status(result))
    if not result.get("success"):
        sys.exit(2)


def _doctor_probe(providers) -> None:
    """GET /models on every registered provider and report what came back.

    This is the only network call `doctor` makes, hence --probe rather than
    always-on. It exists because the alternative is discovering a dead pin or an
    unreachable endpoint mid-run: a retired model answers HTTP 410 and aborts
    the run on its first call, and a name that resolves to the wrong host looks
    like a working config until something asks it for a completion.

    It reports status codes, not health. HTTP 200 means the endpoint answered
    and the key was accepted; 401/403 means reachable but not authorised; a
    transport error means it was never reached. The URL is printed so a
    wrong-host DNS answer is visible rather than inferred.
    """
    import httpx
    print("Probe (network, GET /models):")
    probe_names = providers.assigned()
    if not probe_names:
        print("  (no provider configured — nothing to probe)")
        return
    for name in probe_names:
        try:
            provider = providers.resolve(name)
        except providers.UnknownProvider as e:
            print(f"  {name:15}: skipped — {e}")
            continue
        url = provider.models_url()
        try:
            resp = httpx.get(url, headers=provider.headers(), timeout=20.0)
        except Exception as e:
            # DNS, TLS, connect timeout, proxy — never reached the service.
            print(f"  {name:15}: UNREACHABLE — {type(e).__name__}: {e}  {url}")
            continue
        detail = ""
        if resp.status_code < 400:
            try:
                body = resp.json()
                entries = body.get("data") if isinstance(body, dict) else body
                n = len(entries) if isinstance(entries, list) else 0
                detail = f"  models={n}"
                # Surface context_length for the configured model when present.
                try:
                    from core.model_context import (
                        extract_context_tokens,
                        match_model_entry,
                    )
                    want = provider.model or ""
                    if want and isinstance(entries, list):
                        hit = match_model_entry(
                            [e for e in entries if isinstance(e, dict)], want)
                        if hit:
                            tok, field = extract_context_tokens(hit)
                            if tok:
                                detail += f"  {want} context={tok} ({field})"
                except Exception:
                    pass
            except ValueError:
                detail = "  (2xx but body is not JSON)"
        print(f"  {name:15}: HTTP {resp.status_code}{detail}  {url}")


def cmd_doctor(args) -> None:
    from core import llmhub, providers

    def flag(v):  # never print secrets
        return "set" if v else "NOT SET"

    print(f"LLM Hub base URL : {llmhub.base_url()}")
    print(f"LLM Hub API key  : {flag(llmhub.api_key())}")
    print(f"LLM Hub model    : {llmhub.model()}")
    analyst = providers.role_name("ATLAS_AGENT_PROVIDER")
    print(f"Analyst provider : {analyst or '(not configured)'}")
    print(f"Analyst model    : "
          f"{os.environ.get('ATLAS_AGENT_MODEL') or '(provider default)'}")
    for role in ("REASON", "DAIR"):
        backend = os.environ.get(f"{role}_BACKEND") or "(not configured)"
        url = os.environ.get(f"{role}_URL") or ""
        model = os.environ.get(f"{role}_MODEL") or ""
        print(f"{role:6} backend   : {backend}"
              + (f"  url={url}" if url else "")
              + (f"  model={model}" if model else ""))

    # Registered providers, and which role resolves to which. Printed only when
    # something beyond the built-in default is declared, so an installation
    # that registers nothing sees exactly the output it always saw.
    if providers.declared() or providers.assigned():
        print(f"Providers        : {', '.join(providers.names())}")
        for name in providers.names():
            try:
                provider = providers.resolve(name)
            except providers.UnknownProvider as e:
                print(f"  {name:15}: UNUSABLE — {e}")
                continue
            # Only shown when it deviates, so a blank AUTH_PREFIX (bare token
            # instead of "Bearer ") cannot hide in the config.
            auth = ""
            if (provider.auth_header != providers.DEFAULT_AUTH_HEADER
                    or provider.auth_prefix != providers.DEFAULT_AUTH_PREFIX):
                auth = (f"  auth={provider.auth_header}: "
                        f"{provider.auth_prefix!r}+key")
            print(f"  {name:15}: {provider.base_url}  "
                  f"key={flag(provider.api_key)}  "
                  f"model={provider.model or '(NOT SET)'}{auth}")
        for label, env_vars in (("analyst", ("ATLAS_AGENT_PROVIDER",)),
                                ("reviewer", ("ATLAS_REVIEW_PROVIDER",)),
                                ("report", ("ATLAS_REPORT_PROVIDER",
                                            "ATLAS_AGENT_PROVIDER"))):
            print(f"  role {label:10}: {providers.role_name(*env_vars) or '(not configured)'}")
    for entry in providers.malformed():
        print(f"NOTE: ATLAS_PROVIDERS entry {entry!r} is not a usable provider "
              f"name and was ignored.")

    if getattr(args, "probe", False):
        _doctor_probe(providers)

    if os.environ.get("ANTHROPIC_API_KEY"):
        print("NOTE: ANTHROPIC_API_KEY is set but unused — Anthropic backends "
              "were removed. Configure a provider with `atlas provider setup` "
              "(see docs/llm.md).")
    if (os.environ.get("REASON_BACKEND") or "").strip() == "claude" or (
            os.environ.get("DAIR_BACKEND") or "").strip() == "claude":
        print("NOTE: REASON_BACKEND/DAIR_BACKEND=claude is no longer supported. "
              "Use llmhub or openai-compat.")

    from agent.tui import resolve_live_skin
    print(f"LIVE skin        : {resolve_live_skin()}  "
          f"(atlas skin | --skin | ATLAS_LIVE_SKIN)")


def cmd_addon_list(args) -> None:
    from core.plugins import list_addons
    addons = list_addons()
    if not addons:
        print("No addons discovered under plugins/.")
        return
    for a in addons:
        state = "enabled" if a["enabled"] else "disabled"
        compat = "" if a["compatible"] else "  INCOMPATIBLE (min_atlas_version not met)"
        version = f" v{a['version']}" if a["version"] else ""
        print(f"{a['name']:20} {state:9}{version}{compat}")
        if a["description"]:
            print(f"{'':20} {a['description'].strip()}")
    if getattr(args, "json", False):
        import json
        print(json.dumps(addons, indent=2))


def cmd_intel(args) -> None:
    """Supply indicators and threat reports to a case (core.threat_context)."""
    from core import threat_context as tc
    sub = args.intel_cmd
    if sub == "sources":
        from core.intel_readers import readers
        print("Readers: " + ", ".join(sorted(readers())))
        sources = tc.configured_sources()
        if not sources:
            print("No command sources configured (ATLAS_INTEL_SOURCES in .env).")
        for name, s in sources.items():
            print(f"{name:20} format={s['format'] or 'detected'} timeout={s['timeout']}s"
                  + ("" if s["command"] else "  (no command set)"))
        return
    case = _resolve_case(args.case)
    if case is None:
        sys.exit(f"atlas intel {sub}: pass --case DIR or run from a case directory")
    try:
        if sub == "add":
            mapping = dict(kv.split("=", 1) for kv in (args.map or "").split(",") if "=" in kv)
            if args.doc:
                res = tc.add_document(case, args.doc, name=args.name or "", tlp=args.tlp)
            else:
                res = tc.add_file(case, args.file, name=args.name or "", fmt=args.format,
                                  tlp=args.tlp, mapping=mapping or None)
        elif sub == "pull":
            res = tc.pull(case, args.source)
        elif sub == "withdraw":
            if not (args.id or args.source):
                sys.exit("atlas intel withdraw: name rows with --id or a whole source with --source")
            n = tc.withdraw(case, ids=args.id or [], source=args.source or "", reason=args.reason)
            print(f"{n} row(s) withdrawn")
            return
        else:  # list
            data = tc.load(case)
            if args.json:
                print(json.dumps(data, indent=2, ensure_ascii=False))
                return
            shown = [r for r in data["rows"] if args.all or r.get("status") == "active"]
            for r in shown:
                note = r.get("unfit_reason") or r.get("withdrawn_reason") or ""
                print(f"{r['id']}  {r.get('status', ''):9} {r['type']:10} {r['value']}  "
                      f"[{r['source']['name']}]" + (f"  ({note})" if note else ""))
            if not shown:
                print("No active rows." + ("" if args.all else " (--all shows unfit and withdrawn ones)"))
            return
    except tc.IntelError as exc:
        sys.exit(f"atlas intel {sub}: {exc}")
    print(f"{res['source']}: {res['added']} added, {res['updated']} updated, "
          f"{res['unfit']} unfit (format {res['format']})")


_ADDON_INIT_TEMPLATE = '''"""{name} — one-line description of what this addon does."""

from plugins.{name}.plugin import register

__all__ = ["register"]
'''

_ADDON_PLUGIN_TEMPLATE = '''"""{name} — describe what this addon does and why.

See docs/addons.md for the full authoring guide.
"""
from __future__ import annotations

from core.addons import Addon, tool


class {class_name}(Addon):
    name = "{name}"

    @tool()
    def hello(self, name: str) -> dict:
        """Replace with a real tool. Callable as {name}.hello."""
        return {{"greeting": f"Hello {{name}}"}}


def register(mcp) -> None:
    """Entry point for core.plugins.register_plugins()."""
    {class_name}().register(mcp)
'''

_ADDON_MANIFEST_TEMPLATE = """name: {name}
version: "0.1.0"
description: One line describing what this addon does.
author: {author}
min_atlas_version: "1.0.0"
"""


def cmd_addon_create(args) -> None:
    import re
    from agent.prompts import REPO_ROOT

    name = args.name.strip()
    if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
        sys.exit(f"atlas: addon name {name!r} must be lowercase "
                 f"letters/digits/underscore, starting with a letter "
                 f"(matches a Python package name).")

    addon_dir = REPO_ROOT / "plugins" / name
    if addon_dir.exists():
        sys.exit(f"atlas: plugins/{name}/ already exists.")

    class_name = "".join(part.capitalize() for part in name.split("_")) + "Addon"
    addon_dir.mkdir(parents=True)
    (addon_dir / "__init__.py").write_text(
        _ADDON_INIT_TEMPLATE.format(name=name), encoding="utf-8")
    (addon_dir / "plugin.py").write_text(
        _ADDON_PLUGIN_TEMPLATE.format(name=name, class_name=class_name),
        encoding="utf-8")
    (addon_dir / "addon.yaml").write_text(
        _ADDON_MANIFEST_TEMPLATE.format(name=name, author=os.environ.get("USER", "")),
        encoding="utf-8")
    print(f"Created plugins/{name}/ (__init__.py, plugin.py, addon.yaml).")
    print(f"Edit plugins/{name}/plugin.py to add real @tool()/@hook() methods, "
          f"then restart the MCP server — discovery is automatic.")
    print("See docs/addons.md for the full guide.")


# Which env var carries the provider choice for each model surface. reason/dair
# reuse their existing *_BACKEND vars, which already accept a provider name.
# Single source of truth lives in core/llm_setup.py (also used by the
# `provider setup` wizard); imported here under the name this module has
# always used it by.
from core.llm_setup import PROVIDER_ROLE_VARS


def cmd_provider_list(args) -> None:
    from core import providers
    active = {role: providers.role_name(var)
              for role, var in PROVIDER_ROLE_VARS.items()}
    for name in providers.names():
        try:
            provider = providers.resolve(name)
        except providers.UnknownProvider as e:
            print(f"{name:15} UNUSABLE — {e}")
            continue
        roles = [r for r, n in active.items() if n == name]
        print(f"{name:15} {provider.base_url}")
        print(f"{'':15} key={'set' if provider.api_key else 'NOT SET'}  "
              f"model={provider.model or '(NOT SET)'}  "
              f"roles={','.join(roles) if roles else '-'}")
        from agent.llm import resolve_api_compat
        profile = resolve_api_compat(name, provider.model)
        print(f"{'':15} thinking={providers.thinking_level(name) or 'auto'}  "
              f"observed={'yes' if profile.reasoning_observed else 'not yet'}")
    for entry in providers.malformed():
        print(f"NOTE: ATLAS_PROVIDERS entry {entry!r} is unusable and was ignored.")


def cmd_provider_test(args) -> None:
    """Three short calls against a registered provider: reachability, tool
    calling, thinking. The same check the dashboard's Test connection runs."""
    from core import llm_setup as ls, providers
    try:
        provider = providers.resolve(args.name)
    except providers.UnknownProvider as e:
        sys.exit(f"atlas: {e}")
    model = getattr(args, "model", "") or provider.model
    caps = ls.probe_capabilities(
        provider.base_url, provider.api_key, model,
        auth_header=provider.auth_header, auth_prefix=provider.auth_prefix,
        provider_name=provider.name)
    yes_no = lambda v: "unknown" if v is None else ("yes" if v else "no")  # noqa: E731
    print(f"{provider.name}: {provider.base_url}  model={model or '(NOT SET)'}")
    print(f"  models listed : {yes_no(caps.reachable)}"
          + (f" ({len(caps.models)})" if caps.models else ""))
    print(f"  answered      : {yes_no(caps.answered)}")
    print(f"  tool calling  : {yes_no(caps.tool_calling)}")
    try:
        from agent.llm import resolve_api_compat
        _learned_tools = resolve_api_compat(provider.name, model).max_tools
    except Exception:  # noqa: BLE001 - informational only
        _learned_tools = None
    if _learned_tools:
        print(f"  tool schemas  : runs pack under {_learned_tools}, learned from a run "
              f"(delete the entry in ~/.atlas/llm_api_compat.json or set "
              f"ATLAS_AGENT_MAX_OPENAI_TOOLS to change it)")
    print(f"  thinking      : {'observed in ' + caps.thinking_field if caps.thinking_field else ('observed' if caps.thinking_observed else 'not observed')}")
    if caps.thinking_observed:
        print(f"  level control : {yes_no(caps.control_accepted)}"
              + (f" (accepts {', '.join(caps.accepted_values)})" if caps.accepted_values else ""))
    print(f"  limit param   : {caps.limit_param}" + ("  (explicit cap needed)" if caps.cap_needed else ""))
    print(f"  roles allowed : {', '.join(caps.roles_allowed()) or '-'}")
    if caps.error:
        print(f"  error         : {caps.error}")
    if not caps.ok:
        sys.exit(1)


def cmd_provider_use(args) -> None:
    """Point one or all model surfaces at a registered provider, by editing .env.

    Refuses rather than writing a configuration that cannot work. Switching the
    provider is the one change that breaks *every* subsequent call at once, so
    the checks that would otherwise fail on the first model request happen here,
    before the config is touched.
    """
    from agent.prompts import REPO_ROOT
    from core import envfile, providers
    name = args.name
    try:
        provider = providers.resolve(name)
    except providers.UnknownProvider as e:
        sys.exit(f"atlas: {e}")

    is_default = provider.name == providers.DEFAULT_NAME
    model_var = ("LLMHUB_MODEL" if is_default
                 else providers.var(provider.name, "MODEL"))
    key_var = ("LLMHUB_API_KEY" if is_default
               else providers.var(provider.name, "API_KEY"))

    updates: dict[str, str] = {}
    model = (args.model or "").strip()
    if model:
        updates[model_var] = model
    else:
        model = provider.model
        if not model:
            sys.exit(f"atlas: provider {name!r} has no model configured. Pass "
                     f"--model ID, or set {model_var}. A named provider never "
                     f"inherits LLMHUB_MODEL — see core/providers.py.")
    if not provider.api_key:
        sys.exit(f"atlas: provider {name!r} has no API key. Set {key_var} — "
                 f"`bin/atlas-secret set {key_var}`, or `--env` on hosts with "
                 f"no keyring.")

    roles = (list(PROVIDER_ROLE_VARS) if args.role == "all" else [args.role])
    for role in roles:
        updates[PROVIDER_ROLE_VARS[role]] = name

    if not args.no_probe:
        import httpx
        url = provider.models_url()  # the model id plays no part in this URL
        try:
            resp = httpx.get(url, headers=provider.headers(), timeout=20.0)
        except Exception as e:
            sys.exit(f"atlas: {name!r} is not reachable from this host — "
                     f"{type(e).__name__}: {e}\n  {url}\n"
                     f"Nothing was changed. Re-run with --no-probe to configure "
                     f"it anyway (every model call will fail until the path "
                     f"opens).")
        if resp.status_code >= 400:
            sys.exit(f"atlas: {name!r} answered HTTP {resp.status_code} at {url}\n"
                     f"  {resp.text[:300]}\n"
                     f"Nothing was changed. A 401/403 means the key is not "
                     f"accepted; --no-probe skips this check.")
        available = []
        try:
            available = [m.get("id") for m in (resp.json().get("data") or [])]
        except ValueError:
            pass
        if available and model not in available:
            sys.exit(f"atlas: {model!r} is not in {name!r}'s catalogue "
                     f"({len(available)} models). Nothing was changed.\n"
                     f"  Pick one with: atlas models --provider {name}")

    env_path = envfile.resolve(REPO_ROOT)
    print(f"{'Would write' if args.dry_run else 'Writing'} to {env_path}:")
    for key, value in updates.items():
        print(f"  {key}={value}")
    if args.dry_run:
        print("--dry-run: nothing written.")
        return
    if not env_path.is_file():
        sys.exit(f"atlas: no .env at {env_path} — create it first "
                 f"(cp .env.example .env).")
    envfile.set_values(env_path, updates)
    print(f"Done. Verify with: bin/atlas doctor")
    print(f"Roll back with:   bin/atlas provider use "
          f"{providers.DEFAULT_NAME}"
          + ("" if args.role == "all" else f" --role {args.role}"))


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        raw = input(f"  {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        sys.exit("\natlas: aborted — nothing was written.")
    return raw or default


def _ask_secret(prompt: str) -> str:
    import getpass
    try:
        return getpass.getpass(f"  {prompt} (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        sys.exit("\natlas: aborted — nothing was written.")


def _ask_yn(prompt: str, default_yes: bool = True) -> bool:
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        raw = input(f"  {prompt} {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        sys.exit("\natlas: aborted — nothing was written.")
    if not raw:
        return default_yes
    return raw in ("y", "yes")


def cmd_provider_setup(args) -> None:
    """Interactive wizard: register an LLM provider and point roles at it.

    A thin interactive shell around core.llm_setup — every actual decision
    (presets, registration, probing, role assignment) lives there so a
    future browser dashboard can drive the identical logic from HTTP
    handlers instead of terminal prompts. This function only collects input
    and prints; it computes nothing itself beyond argv parsing.
    """
    from agent.prompts import REPO_ROOT
    from core import envfile, providers
    from core import llm_setup as ls

    print("Atlas LLM provider setup")
    print("=========================")
    print()
    print("Which backend are you connecting to?")
    for i, p in enumerate(ls.PRESETS, 1):
        star = "  (default)" if p.default_choice else ""
        print(f"  {i}. {p.label}{star}")
        print(f"     {p.description}")
    print()
    chosen = None
    while chosen is None:
        raw = _ask(f"Choice [1-{len(ls.PRESETS)}]", "")
        if raw.isdigit() and 1 <= int(raw) <= len(ls.PRESETS):
            chosen = ls.PRESETS[int(raw) - 1]
        else:
            print("  Please enter a number from the list (no default).")
    print()
    if chosen.notes:
        print(f"  {chosen.notes}")
        print()

    if chosen.id == "llmhub":
        name = providers.DEFAULT_NAME
    else:
        name = ""
        while True:
            name = _ask("Provider name (used in ATLAS_PROVIDERS and env "
                        "var names)", chosen.id)
            err = ls.validate_name(name)
            if err is None:
                break
            print(f"  {err}")

    base_url = _ask("Base URL", chosen.base_url)
    model_prompt = "Model id"
    if chosen.default_model:
        model_prompt += f" (blank = {chosen.default_model!r})"
    model = _ask(model_prompt, chosen.default_model)
    if ls.is_identity_model_id(model):
        sys.exit(
            f"atlas: model {model!r} looks like a dashboard role or username, "
            f"not a catalogue id. Nothing was written.")

    api_key = ""
    if chosen.needs_api_key:
        api_key = _ask_secret("API key")
    elif _ask_yn("This preset usually needs no API key — set one anyway?",
                default_yes=False):
        api_key = _ask_secret("API key")

    if _ask_yn("Test this connection now (GET /models)?", default_yes=True):
        result = ls.probe(base_url, api_key)
        if result.ok:
            print(f"  OK — HTTP {result.status}, {len(result.models)} "
                  f"models at {result.url}")
            if model and result.models and model not in result.models:
                print(f"  NOTE: {model!r} is not in that catalogue — "
                      f"double check the model id.")
        else:
            print(f"  FAILED — {result.error}  ({result.url})")
            if not _ask_yn("Save this configuration anyway?",
                           default_yes=False):
                sys.exit("atlas: aborted — nothing was written.")

    print()
    print("Which roles should use this provider? (analyst = investigation "
          "driver, reviewer = adversarial review, report = final synthesis, "
          "reason = reason.* tools, dair = phase director)")
    if _ask_yn("All of them (recommended for a single-backend setup)?",
              default_yes=True):
        roles = tuple(ls.PROVIDER_ROLE_VARS)
    else:
        roles = tuple(r for r in ls.PROVIDER_ROLE_VARS
                      if _ask_yn(f"  {r}?", default_yes=False))

    thinking = _ask("Thinking level for this provider (auto/low/medium/high; "
                    "auto lets Atlas learn one from a starved reply)", "auto")
    if thinking.strip().lower() not in providers.THINKING_VALUES:
        sys.exit(f"atlas: {thinking!r} is not a thinking level. Nothing was written.")

    key_var = ls.key_env_var(name)
    store_in_keyring = False
    if api_key:
        import shutil as _shutil
        if _shutil.which("secret-tool"):
            store_in_keyring = _ask_yn(
                f"Store {key_var} in the OS keyring (recommended over "
                f"plaintext .env)?", default_yes=True)

    try:
        choice = ls.SetupChoice(preset_id=chosen.id, name=name,
                                base_url=base_url, model=model, roles=roles,
                                thinking=thinking.strip().lower())
        updates = ls.register_provider_updates(choice)
    except ValueError as e:
        sys.exit(f"atlas: {e}")
    updates.update(ls.declared_providers_update(providers.declared(), name))
    updates.update(ls.role_updates(name, roles))

    env_path = envfile.resolve(REPO_ROOT)
    if not env_path.is_file():
        sys.exit(f"atlas: no .env at {env_path} — create it first "
                 f"(cp .env.example .env).")

    print()
    print(f"Writing to {env_path}:")
    for k, v in updates.items():
        print(f"  {k}={v}")
    if api_key:
        dest = "the OS keyring" if store_in_keyring else str(env_path)
        print(f"  {key_var}=<hidden> → {dest}")

    envfile.set_values(env_path, updates)

    if api_key:
        wrote_to_keyring = False
        if store_in_keyring:
            import subprocess
            secret_script = str(Path(REPO_ROOT) / "bin" / "atlas-secret")
            proc = subprocess.run(
                [secret_script, "set", key_var],
                input=api_key + "\n", text=True, capture_output=True)
            if proc.returncode == 0:
                wrote_to_keyring = True
            else:
                print(f"  Keyring write failed ({proc.stderr.strip() or 'no Secret Service'})"
                      f" — writing {key_var} to .env instead")
        if not wrote_to_keyring:
            envfile.set_values(env_path, {key_var: api_key})

    print()
    print("Done. Verify with: bin/atlas doctor")
    print(f"Change roles later with: bin/atlas provider use {name} --role <role>")


def cmd_share_status(args) -> None:
    from core import smb_share
    st = smb_share.status()
    if not st["installed"]:
        print("SMB share: samba not installed"
              + (f" ({st['error']})" if st.get("error") else ""))
        print("  Install it via install.sh's network-share option, or:"
              " sudo apt-get install samba && bin/atlas-sudoers")
        return
    print(f"SMB share: {'enabled' if st['enabled'] else 'disabled'}"
          f"  (smbd {'running' if st['service_active'] else 'not running'})")
    if st["enabled"]:
        print(f"  share:    \\\\<this host>\\{st['share_name']}")
        print(f"  path:     {st['share_path']}")
        print(f"  user:     {st['share_user']}"
              f"  (Samba password {'set' if st['password_set'] else 'NOT SET — run: bin/atlas share passwd'})")


def cmd_share_enable(args) -> None:
    from core import smb_share
    try:
        st = smb_share.enable()
    except smb_share.ShareError as e:
        sys.exit(f"atlas: {e}")
    print(f"Share enabled: \\\\<this host>\\{st['share_name']} -> {st['share_path']}")
    if not st["password_set"]:
        print("No Samba password set yet for this share — run: bin/atlas share passwd")


def cmd_share_disable(args) -> None:
    from core import smb_share
    try:
        smb_share.disable()
    except smb_share.ShareError as e:
        sys.exit(f"atlas: {e}")
    print("Share disabled.")


def cmd_share_passwd(args) -> None:
    from core import smb_share
    password = _ask_secret("New Samba share password")
    if not password:
        sys.exit("atlas: aborted — nothing was written.")
    confirm = _ask_secret("Confirm")
    if password != confirm:
        sys.exit("atlas: passwords did not match — nothing was written.")
    try:
        smb_share.set_password(password)
    except smb_share.ShareError as e:
        sys.exit(f"atlas: {e}")
    print("Samba share password set.")


def cmd_report(args) -> None:
    case_dir = _resolve_case(args.case)
    if case_dir is None:
        sys.exit("atlas: not inside a case directory — pass --case DIR.")
    if args.format in ("navigator", "stix"):
        # Machine-readable exports derive from the trace, not the report md.
        from tools.export_tools import write_iocs, write_navigator
        traces = sorted((case_dir / "analysis").glob("*_trace.json"),
                        key=lambda p: p.stat().st_mtime)
        if not traces:
            sys.exit(f"atlas: no *_trace.json under {case_dir}/analysis/ — "
                     "run an investigation first.")
        with open(traces[-1], encoding="utf-8") as f:
            data = json.load(f)
        case_id = data.get("case_id") or case_dir.name
        from core.claim_graph import asserted_finding_entries
        findings = asserted_finding_entries(
            [e for e in data.get("entries", []) if e.get("type") == "finding"],
            str(case_dir))
        out_dir = str(Path(args.output).expanduser()) if args.output \
            else str(case_dir / "exports")
        if args.format == "navigator":
            r = write_navigator(case_id, findings, out_dir)
            if not r.get("success"):
                sys.exit(f"atlas: {r.get('error')}")
            print(f"atlas: wrote {r['path']} ({r['techniques']} techniques)")
        else:
            r = write_iocs(case_id, findings, out_dir, fmt="all")
            print(f"atlas: wrote {r['stix_path']} and {r['csv_path']} "
                  f"({r['ioc_count']} IOCs)")
        return
    candidates = []
    # Prefer immutable snapshot layout (reports/latest → rerun_* / initial_report)
    try:
        from core.report_snapshots import resolve_latest_report_dir
        latest_dir = resolve_latest_report_dir(case_dir)
        if latest_dir.is_dir():
            candidates += [
                p for p in latest_dir.rglob("*.md")
                if p.is_file() and p.name != "diff_report.md"
            ]
    except Exception:
        pass
    for sub in ("reports", "analysis"):
        d = case_dir / sub
        if d.is_dir():
            # Flat layout + nested snapshots (skip diff_report at root)
            for p in d.rglob("*.md"):
                if not p.is_file():
                    continue
                if p.name == "diff_report.md":
                    continue
                if p not in candidates:
                    candidates.append(p)
    report = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if report is None:
        sys.exit(f"atlas: no report (*.md) found under {case_dir}/reports/ "
                 "or analysis/ — run an investigation first.")
    text = report.read_text(encoding="utf-8")
    if args.format == "term":
        from agent.tui import UI
        ui = UI()
        ui.info(f"report: {report}")
        ui.markdown(text)
        return
    if args.format == "pdf":
        from core.report_pdf import render_pdf
        try:
            data = render_pdf(text, title=report.stem,
                              case_id=os.path.basename(case_dir))
        except RuntimeError as exc:
            sys.exit(f"atlas: {exc}")
        out = (Path(args.output).expanduser() if args.output
               else report.with_suffix(".pdf"))
        out.write_bytes(data)
        print(f"atlas: wrote {out}")
        return
    if args.format == "md":
        rendered, suffix = text, ".md"
    else:  # html
        from agent.report import render_html
        rendered, suffix = render_html(text, title=report.stem), ".html"
    if args.output:
        out = Path(args.output).expanduser()
    else:
        out = report.with_suffix(suffix)
        if out == report:
            print(text, end="")
            return
    out.write_text(rendered, encoding="utf-8")
    print(f"atlas: wrote {out}")


def cmd_write_report(args) -> None:
    """Write the report a stopped run owes, from the case directory alone.

    cmd_report only finds and renders a report that exists; this one produces
    it. It needs nothing from the run's process, which is what makes it the
    way back after a run was killed outright.
    """
    case_dir = _resolve_case(args.case)
    if case_dir is None:
        sys.exit("atlas: not inside a case directory — pass --case DIR.")
    from core.report_exit import write_exit_report
    res = write_exit_report(case_dir, "manual", allow_llm=not args.no_llm,
                            force=args.force)
    if not res.get("written"):
        sys.exit("atlas: this case already has an official report — "
                 "pass --force to write the assembled one anyway.")
    print(f"atlas: wrote {res['path']} from {res['findings']} finding(s) "
          f"({res['source']})")
    if res.get("upgrade_error"):
        print(f"atlas: the narrative sections were not written: "
              f"{res['upgrade_error']}", file=sys.stderr)


def cmd_verify_trace(args) -> None:
    """Recompute the hash chain of a case's trace.jsonl mirror."""
    from core.execution_log import verify_trace_chain
    target = Path(args.path).expanduser() if args.path else None
    if target is None or target.is_dir():
        case_dir = (target if target and target.is_dir()
                    else _resolve_case(args.case))
        if case_dir is None:
            sys.exit("atlas: not inside a case directory — pass a "
                     "trace.jsonl path or --case DIR.")
        candidates = sorted((case_dir / "analysis").glob("*_trace.jsonl"))
        if not candidates:
            sys.exit(f"atlas: no *_trace.jsonl mirror under "
                     f"{case_dir}/analysis/ — mirrors are written from the "
                     "first flush of a run on this Atlas version.")
        target = candidates[-1]
    result = verify_trace_chain(str(target))
    if result.get("ok"):
        print(f"atlas: chain OK — {result['entries']} journaled entries "
              f"verified ({target})")
        return
    sys.exit(f"atlas: CHAIN BROKEN at line {result.get('line')}: "
             f"{result.get('error')} ({target})")


def cmd_serve(args) -> None:
    import server
    server.mcp.run(transport="stdio")


def cmd_publish(args) -> None:
    from core.brain.publish import main as publish_main
    argv = ["--remote", args.remote, "--branch", args.branch]
    if args.push:
        argv.append("--push")
    raise SystemExit(publish_main(argv))


def cmd_brain_new(args) -> None:
    from core.brain.notes import NoteError, new_note
    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
    try:
        path = new_note(args.type, args.title, tags=tags, force=args.force,
                        client=getattr(args, "client", ""))
    except NoteError as e:
        sys.exit(f"atlas: {e}")
    print(path)


def cmd_brain_search(args) -> None:
    from core.brain.search import main as search_main
    argv = [args.query, "--limit", str(args.limit)]
    for t in args.types or []:
        argv += ["--type", t]
    if args.include_confidential:
        argv.append("--include-confidential")
    raise SystemExit(search_main(argv))


def cmd_brain_reindex(args) -> None:
    from core.brain.indexes import main as reindex_main
    argv = ["--verbose"] if args.verbose else []
    if args.include_confidential:
        argv.append("--include-confidential")
    raise SystemExit(reindex_main(argv))


def cmd_brain_stats(args) -> None:
    from core.brain.stats import main as stats_main
    raise SystemExit(stats_main([]))


def cmd_brain_report(args) -> None:
    from core.brain.report import main as report_main
    argv = []
    if args.period:
        argv += ["--period", args.period]
    if args.since:
        argv += ["--since", args.since]
    raise SystemExit(report_main(argv))


def cmd_brain_review(args) -> None:
    from core.brain.review_candidates import main as review_main
    argv = []
    if args.type:
        argv += ["--type", args.type]
    if args.risk:
        argv.append("--risk")
    raise SystemExit(review_main(argv))


def cmd_brain_approve(args) -> None:
    from core.brain.approve import main as approve_main
    argv = [args.candidate]
    if args.yes:
        argv.append("--yes")
    if getattr(args, "show_redacted", False):
        argv.append("--show-redacted")
    raise SystemExit(approve_main(argv))


def cmd_brain_reject(args) -> None:
    from core.brain.reject import main as reject_main
    argv = [args.candidate, "--reason", args.reason]
    if args.yes:
        argv.append("--yes")
    raise SystemExit(reject_main(argv))


def cmd_brain_sync(args) -> None:
    """Fast-forward this clone to receive brain growth merged into the canonical
    branch. Explicit by design — never runs mid-investigation."""
    import subprocess
    from core.brain import store
    repo = store.REPO_ROOT
    print(f"atlas: syncing brain from {args.remote}/{args.branch} "
          "(git pull --ff-only)…")
    try:
        r = subprocess.run(
            ["git", "pull", "--ff-only", args.remote, args.branch],
            cwd=str(repo), text=True, capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        sys.exit(f"atlas: brain sync failed: {e}")
    if r.stdout.strip():
        print(r.stdout.strip())
    if r.returncode != 0:
        if r.stderr.strip():
            sys.stderr.write(r.stderr)
        sys.exit(
            "atlas: brain sync could not fast-forward — you likely have local "
            "commits or a dirty tree. Commit/stash your work or resolve with git.")
    print("atlas: brain up to date.")


def cmd_brain_capture(args) -> None:
    """Manual staged memory capture from an already-finished case run."""
    from core.brain.capture import capture_case, CaptureError
    case_dir = _resolve_case(args.case)
    if case_dir is None:
        sys.exit("atlas: not inside a case directory — pass --case DIR.")
    try:
        summary = capture_case(case_dir, command="capture")
    except CaptureError as e:
        sys.exit(f"atlas: {e}")
    print(f"atlas: staged {summary['candidates']} memory candidate(s); "
          f"run summary: {summary['run_summary']}")


def cmd_brain_learn(args) -> None:
    """Synchronous investigation-wide Brain learning (quality-first)."""
    from core.brain.learn import LearnError, learn_from_investigation
    case_dir = _resolve_case(args.case)
    if case_dir is None:
        sys.exit("atlas: not inside a case directory — pass --case DIR.")
    try:
        result = learn_from_investigation(
            case_dir,
            case_id=getattr(args, "case_id", "") or "",
            question=getattr(args, "question", "") or "",
            command="learn",
            skip_llm=bool(getattr(args, "digest_only", False)))
    except LearnError as e:
        sys.exit(f"atlas: {e}")
    except Exception as e:
        sys.exit(f"atlas brain learn failed: {e}")
    dropped = result.get("dropped") or {}
    drop_s = f"; dropped={dropped}" if dropped else ""
    print(f"atlas: brain learn {result.get('status')} — "
          f"{result.get('candidates', 0)} candidate(s) staged{drop_s}")
    print(f"atlas: status → {case_dir / '.atlas' / 'brain_learn.json'}")


def cmd_brain_globe(args) -> None:
    from core.brain.globe import main as globe_main
    argv = []
    if args.case_id:
        argv += ["--case", args.case_id]
    if args.topic:
        argv += ["--topic", args.topic]
    if args.mode:
        argv += ["--mode", args.mode]
    raise SystemExit(globe_main(argv))


# ── `atlas guide` — in-terminal orientation ────────────────────────────────
# Ordered topics. `atlas guide` prints them all; `atlas guide <topic>` prints one.
_GUIDE: dict[str, tuple[str, str]] = {
    "overview": ("What Atlas is", """
Atlas is an autonomous DFIR analyst. You point it at a case (a directory holding
evidence), ask a question, and it drives real forensic tools — Volatility, The
Sleuth Kit, plaso, EZ Tools, YARA and many more — to investigate. It records
tiered findings that cite the exact tool call behind each claim, then writes a
final report.

Two things make it more than a tool-runner:
  - A critic loop: an adversarial `reason.*` role hypothesis-tests and
    confidence-scores findings, and a `dair.*` role directs the phases.
  - A second brain: durable, cross-case knowledge injected into new runs and
    grown over time (see `atlas guide brain`).

Mental model:  evidence -> traced tool calls -> tiered findings -> report,
with the brain feeding prior lessons in and capturing new ones out."""),

    "workflow": ("How a run works", """
Lifecycle of `atlas run` / `atlas train`:
  1. Setup      resolve the case dir (auto-detected inside a case), load the
                brief (CASE.md), inject relevant brain knowledge.
  2. Investigate  plan, call forensic tools; every call is written to an
                append-only execution trace you can replay in the dashboard.
  3. Findings   each is tiered by confidence (CONFIRMED / LIKELY / SUSPECTED)
                and must cite the tool output behind it; the `reason.*` reviewer
                tries to refute weak ones and flags over-claims.
  4. Coverage   a gate checks evidence/tool coverage before the report, so the
                run doesn't stop with obvious stones unturned.
  5. Report     the final report lands in the case's reports/ directory.

`run` is the workhorse. `train` adds an INDEPENDENT reviewer that grades a clean
run (a graded practice run). `interactive` consults you at decision points;
`chat` lets you drive tools by hand. `review --live` tells you whether an
in-flight run is stuck."""),

    "commands": ("The commands", """
  run             full autonomous investigation (the workhorse)
  interactive     same, but asks for approval at decision points
  chat            conversational session — you drive the tools
  train           clean run + independent graded review
  review --live   is my running investigation stuck?
  report          render the newest final report (terminal, --format html/pdf)
  status          one-screen investigation health (conflicts, stale, dirty)
  explain         explain a claim / conflict / report section
  timeline        case timeline from claims+journal (or master_timeline.tsv)
  journal         list / show / diff investigation journal runs
  verify-trace    check an execution trace's hash chain
  models          list models your LLM Hub key can use
  doctor          show which backend/model each role resolved to
  rerun           continue the investigation from what changed
  serve           run the MCP server on stdio (for MCP clients)
  brain ...       manage the durable second brain (see `atlas guide brain`)

Every command has worked examples:  atlas <command> --help
Inside a case directory, --case is optional (auto-detected from cwd).
Add --remote HOST to run/train/interactive to run the forensic tools on an
external SIFT VM."""),

    "brain": ("The second brain", """
Durable, cross-case knowledge stored under brain/ (git-tracked). Three touch-
points:
  - Inject (read)   at run start, relevant memory/concepts/tool notes are added
                    to the analyst's context. Notes about the ACTIVE case are
                    excluded, so a run never "remembers" its own prior solve.
  - Propose (capture)  after a run, a few candidate lessons are staged to
                    brain/inbox/ for review. Happens for everyone; changes
                    nothing durable on its own.
  - Grow (approve + merge)  a candidate becomes durable only when a CONTRIBUTOR
                    promotes it with `atlas brain approve` and the change is
                    merged to the canonical `main`.

Growth is gated three ways, so the shared brain grows only from people who
commit/merge:
  1. `atlas brain approve` refuses unless your git email is in brain/CONTRIBUTORS.
  2. A pre-commit hook blocks durable-brain commits (brain/memory, wiki, logs,
     indexes) from non-listed identities; brain/inbox proposals are exempt.
  3. Protected `main` on the remotes restricts who can merge.
The gate is inert while brain/CONTRIBUTORS is absent — single-user setups are
unaffected.

Everyday commands:
  atlas brain review           list staged candidates
  atlas brain approve <file>   promote a candidate (contributors only)
  atlas brain reject <file> --reason '...'
  atlas brain sync             fast-forward your clone to pull merged growth
  atlas brain search '...'     search the brain
More: brain/AGENTS.md and docs/multi-user.md."""),

    "multiuser": ("Multi-user on a shared VM", """
Running Atlas for a team on one Ubuntu VM over SSH:
  - One Linux account per analyst. A separate $HOME isolates each user's caches
    (~/.cache/atlas), cases (~/cases) and run state automatically.
  - One Atlas clone per account (git clone + ./install.sh). Work your OWN cases;
    do not share a single case directory between users at the same time.
  - The brain is shared through git: the canonical copy is brain/ on the
    protected `main`. You read it locally, propose candidates freely, and pull
    others' merged growth with `atlas brain sync`. Growing the durable brain is
    limited to contributors (see `atlas guide brain`).

Provisioning steps + maintainer runbook: docs/multi-user.md."""),

    "setup": ("First-run setup", """
Atlas drives five model roles — the analyst, the adversarial `reason.*`
reviewer, the `dair.*` phase director, the run reviewer and the report
writer — and each is pointed at a provider: any OpenAI-compatible endpoint
(the Telekom LLM Hub, OpenAI, a local vLLM/Ollama server, another gateway).
Nothing is pre-selected; an unset role is off, not silently the hub.

First run:
  1. atlas provider setup      register a provider, test it, assign the roles
                               (or: dashboard → Settings → Providers)
  2. atlas doctor              show which provider/model each role resolved to
  3. atlas models              list the models your key can use
  4. atlas run --case ~/cases/<case>
                               -q "..." overrides the case's requests for one run;
                               with neither, Atlas asks "What happened on the Host(s)?"

Keys go in the repo .env (install.sh scaffolds it from .env.example) or the
keyring via atlas-secret set <KEY>; over SSH the keyring is usually locked,
so prefer .env there. An explicit ATLAS_AGENT_MODEL / REASON_MODEL /
DAIR_MODEL / ATLAS_REVIEW_MODEL outranks the provider's model — the
Settings page warns while one is set.
Cases live under ~/cases; run from there so outputs stay out of the git tree."""),
}


def cmd_guide(args) -> None:
    topic = getattr(args, "topic", "all") or "all"
    keys = list(_GUIDE) if topic == "all" else [topic]
    blocks = []
    for k in keys:
        title, body = _GUIDE[k]
        blocks.append(f"{title}\n{'─' * len(title)}\n{body.strip(chr(10))}")
    print("\n\n".join(blocks))
    if topic == "all":
        print("\nFocus on one topic:  atlas guide <" + "|".join(_GUIDE) + ">")
        print("Per-command detail:  atlas <command> --help")
        print("Written guides:      docs/cli.md · docs/multi-user.md · "
              "docs/try-it-out.md · docs/llm.md")


def _wrap(text: str) -> str:
    """Pre-wrap a subcommand description — RawDescriptionHelpFormatter (needed
    to keep the examples epilog verbatim) does not wrap it for us."""
    import textwrap
    return textwrap.fill(text, width=78)


def _examples(*lines: str) -> str:
    """Format an examples block for a subcommand epilog (rendered verbatim)."""
    return "examples:\n" + "\n".join(f"  {ln}" for ln in lines)


def build_parser() -> argparse.ArgumentParser:
    from agent.tui import LORE, TAGLINE
    from core.plugins import ATLAS_VERSION
    parser = argparse.ArgumentParser(
        prog="atlas",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap(f"Atlas — {TAGLINE}, running on any "
                    f"OpenAI-compatible model backend."),
        epilog=(
            "new here?  run `atlas guide`  — how Atlas works, start to finish\n"
            "\n"
            "quick orientation:\n"
            "  atlas run -q '...'          full autonomous investigation "
            "(the workhorse)\n"
            "  atlas train -q '...'        clean run + independent review, "
            "graded\n"
            "  atlas review --live         is my running investigation "
            "stuck?\n"
            "  atlas chat                  interactive session, you drive\n"
            "  atlas doctor                what backend/model did each role "
            "resolve to?\n"
            "  atlas provider setup        wizard: configure an LLM backend "
            "(Hub, OpenAI, local, …)\n"
            "  atlas skin                  LIVE panel look (matrix, radar, …)\n"
            "\n"
            "Inside a case directory, --case is optional (auto-detected "
            "from cwd).\n"
            "Add --remote HOST to run/train/interactive to execute the "
            "forensic tools\non an external SIFT VM (host from "
            "~/cases/.common/live_hosts.json).\n"
            "\n"
            "Full command guide: docs/cli.md · multi-user setup: "
            "docs/multi-user.md\n"
            "\n" + LORE))
    parser.add_argument("--version", action="version",
                        version=f"Atlas {ATLAS_VERSION} — {TAGLINE}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_guide = sub.add_parser(
        "guide",
        help="how Atlas works — an in-terminal orientation (start here)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Explain how Atlas works end to end: the investigation "
                    "lifecycle, the commands, the second brain and its "
                    "contributor gate, multi-user setup, and where to read more."),
        epilog=_examples(
            "atlas guide                 # the full orientation",
            "atlas guide brain           # just the second-brain model",
            "atlas guide multiuser       # shared-VM / SSH setup",
            "atlas guide setup           # first run: keys, .env, doctor"))
    p_guide.add_argument(
        "topic", nargs="?", default="all", choices=["all", *_GUIDE],
        help="focus on one topic (default: all)")
    p_guide.set_defaults(func=cmd_guide)

    p_run = sub.add_parser(
        "run", help="run a full autonomous investigation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Run one complete autonomous investigation: execution "
                    "log, evidence hash verification, competing hypotheses, "
                    "the DAIR phase loop, and a gated final report. No "
                    "confirmation prompts between steps. Output lands in the "
                    "case's reports/, analysis/, and exports/ directories."),
        epilog=_examples(
            "atlas run --case ~/Atlas/demo-cases/nitroba",
            "atlas run --case ~/cases/mycase -q 'optional one-shot override'",
            "cd ~/Atlas/demo-cases/nitroba && atlas run        "
            "# --case auto-detected; objectives from CASE.md",
            "atlas run --remote sift-lab            "
            "# tools execute on a SIFT VM",
            "atlas run --json > result.json         "
            "# scripting: stats on stdout",
        ) + "\nexit codes: 0 finished, 1 LLM/config error, 2 stopped "
            "unfinished")
    p_run.add_argument("--case", help="case directory (default: cwd if it "
                                      "looks like a case)")
    p_run.add_argument("--question", "-q",
                       help="optional override of CASE.md investigation "
                            "requests for this run")
    p_run.add_argument("--model", help="override LLMHUB_MODEL for the analyst")
    p_run.add_argument("--case-id", help="override the case ID (from CASE.md) "
                                         "used for the trace filename + anchor")
    p_run.add_argument("--output-dir", help="write analysis/exports/reports to "
                                           "this dir instead of inside the case "
                                           "(evidence stays read-only in place)")
    p_run.add_argument("--remote", metavar="HOST",
                       help="run all forensic tools on an external SIFT VM "
                            "(host key in ~/cases/.common/live_hosts.json); "
                            "the CLI/agent/LLM stay local — see docs/cli.md")
    p_run.add_argument("--remote-mode", choices=["resident", "copy"],
                       default="resident",
                       help="evidence on the VM already (resident) or rsynced "
                            "up from the client, outputs synced back after "
                            "the run (copy); default resident")
    p_run.add_argument("--remote-workspace", metavar="DIR",
                       help="remote workspace base dir for --remote-mode copy "
                            "(default ~/atlas-workspace on the VM)")
    p_run.add_argument("--all-tools", action="store_true",
                       help="expose every namespace up front (large context)")
    p_run.add_argument(
        "--fresh", action="store_true",
        help="wipe analysis/exports/reports + ledger statuses + session "
             "before starting (claims/tasks under .atlas/ kept). Implied when "
             "the prior run already finished unless --resume is set.",
    )
    p_run.add_argument(
        "--resume", action="store_true",
        help="continue appending to the existing execution trace and DAIR "
             "phase stack (default only when no finished prior run exists).",
    )
    p_run.add_argument(
        "--skip-sudo-check", action="store_true",
        help="skip passwordless-sudo preflight (tests/CI only; privileged "
             "tools will still fail with sudo_auth at runtime). "
             "Also: ATLAS_SKIP_SUDO_CHECK=1.",
    )
    p_run.add_argument("--quiet", action="store_true",
                       help="suppress per-turn narration")
    p_run.add_argument("--interactive", action="store_true",
                       help="supervise the run — the agent may consult you via "
                            "atlas_ask_analyst at decision points")
    _add_skin_arg(p_run)
    p_run.add_argument("--json", action="store_true",
                       help="print a machine-readable result to stdout "
                            "(implies --quiet)")
    p_run.add_argument("--no-brain", action="store_true",
                       help="disable Brain injection and post-run learning "
                            "for this investigation")
    p_run.add_argument("--no-capture-brain", action="store_true",
                       help="skip legacy review-bullet capture even when "
                            "ATLAS_CAPTURE_BRAIN is set (background learn "
                            "still runs unless --no-brain)")
    p_run.add_argument("--capture-brain", action="store_true",
                       help="also stage legacy review/self-correction "
                            "candidates (background investigation learn "
                            "already runs by default after a finished run)")
    p_run.add_argument(
        "--language", "-L", choices=("en", "de"), default=None,
        help="report language (en|de); persisted in .atlas/case_config.json",
    )
    p_run.set_defaults(func=cmd_run)

    p_interactive = sub.add_parser(
        "interactive",
        help="a supervised run — the agent asks you for guidance when it hits "
             "a decision point",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Exactly `atlas run`, but the agent may pause and consult "
                    "you (via atlas_ask_analyst) at genuine decision points — "
                    "scope questions, competing pivots, business context the "
                    "evidence can't answer. Between questions it works "
                    "autonomously."),
        epilog=_examples(
            "atlas interactive --case ~/cases/mycase -q 'How did they "
            "get in?'"))
    p_interactive.add_argument("--case", help="case directory (default: cwd if "
                                             "it looks like a case)")
    p_interactive.add_argument("--question", "-q",
                               help="optional override of CASE.md investigation "
                                    "requests for this run")
    p_interactive.add_argument("--model",
                               help="override LLMHUB_MODEL for the analyst")
    p_interactive.add_argument("--case-id",
                               help="override the case ID used for the trace "
                                    "filename + anchor")
    p_interactive.add_argument("--output-dir",
                               help="write outputs to this dir instead of "
                                    "inside the case")
    p_interactive.add_argument("--remote", metavar="HOST",
                               help="run forensic tools on an external SIFT "
                                    "VM (host key in ~/cases/.common/"
                                    "live_hosts.json) — see docs/cli.md")
    p_interactive.add_argument("--remote-mode", choices=["resident", "copy"],
                               default="resident",
                               help="resident (default): evidence already on "
                                    "the VM; copy: rsync evidence up, sync "
                                    "outputs back")
    p_interactive.add_argument("--remote-workspace", metavar="DIR",
                               help="remote workspace base dir for copy mode")
    p_interactive.add_argument("--all-tools", action="store_true",
                               help="expose every namespace up front")
    p_interactive.add_argument(
        "--fresh", action="store_true",
        help="wipe analysis/exports/reports + ledger statuses + session "
             "before starting (same as atlas run --fresh)",
    )
    p_interactive.add_argument(
        "--resume", action="store_true",
        help="continue the existing execution trace (same as atlas run --resume)",
    )
    p_interactive.add_argument(
        "--skip-sudo-check", action="store_true",
        help="skip passwordless-sudo preflight (same as atlas run --skip-sudo-check)",
    )
    _add_skin_arg(p_interactive)
    p_interactive.set_defaults(func=cmd_interactive)

    p_train = sub.add_parser(
        "train",
        help="fresh full run, then an independent agent reviews it",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Clean-slate run plus an independent review: the case's "
                    "analysis/exports/reports are cleared (evidence is never "
                    "touched; --no-clear keeps prior state), the "
                    "investigation runs to completion, then a separate "
                    "reviewer model grades it from the trace, report, and "
                    "ground_truth.json when the case ships one. The review "
                    "lands in reports/<CASE_ID>_run_review.md; memory "
                    "candidates are staged for `atlas brain review`."),
        epilog=_examples(
            "atlas train --case ~/Atlas/demo-cases/nitroba -q 'Who sent the posts?'",
            "atlas train -q '...' --no-clear                 "
            "# keep prior run output",
            "atlas train -q '...' --output-dir /tmp/run1     "
            "# isolated mirror; real case untouched",
            "atlas train -q '...' --review-model <model-id>",
        ) + "\nexit codes: 0 ok, 1 reviewer error, 2 run didn't finish, "
            "3 review says NEEDS WORK")
    p_train.add_argument("--case", help="case directory (default: cwd if it "
                                        "looks like a case)")
    p_train.add_argument("--question", "-q",
                         help="optional override of CASE.md investigation "
                              "requests (required only if CASE.md has none)")
    p_train.add_argument("--model", help="override LLMHUB_MODEL for the "
                                         "analyst")
    p_train.add_argument("--case-id", help="override the case ID used for the "
                                           "trace filename + anchor")
    p_train.add_argument("--output-dir", help="write analysis/exports/reports "
                                              "to this dir instead of inside "
                                              "the case (evidence stays "
                                              "read-only in place); the clear "
                                              "step then clears only this dir")
    p_train.add_argument("--remote", metavar="HOST",
                         help="run all forensic tools on an external SIFT VM "
                              "(host key in ~/cases/.common/live_hosts.json); "
                              "the CLI/agent/LLM stay local — see docs/cli.md")
    p_train.add_argument("--remote-mode", choices=["resident", "copy"],
                         default="resident",
                         help="evidence on the VM already (resident) or "
                              "rsynced up from the client, outputs synced "
                              "back after the run (copy); default resident")
    p_train.add_argument("--remote-workspace", metavar="DIR",
                         help="remote workspace base dir for --remote-mode "
                              "copy (default ~/atlas-workspace on the VM)")
    p_train.add_argument("--review-model",
                         help="reviewer model id (default: ATLAS_REVIEW_MODEL, "
                              "the reviewer provider's model, then "
                              "REASON_MODEL)")
    p_train.add_argument("--no-clear", action="store_true",
                         help="keep existing analysis/exports/reports instead "
                              "of starting from a clean case")
    p_train.add_argument(
        "--skip-sudo-check", action="store_true",
        help="skip passwordless-sudo preflight (tests/CI only)",
    )
    p_train.add_argument("--all-tools", action="store_true",
                         help="expose every namespace up front (large context)")
    p_train.add_argument("--quiet", action="store_true",
                         help="suppress per-turn narration")
    _add_skin_arg(p_train)
    p_train.add_argument("--json", action="store_true",
                         help="print a machine-readable result to stdout "
                              "(implies --quiet)")
    p_train.add_argument(
        "--language", "-L", choices=("en", "de"), default=None,
        help="report language (en|de); persisted in .atlas/case_config.json",
    )
    p_train.add_argument("--no-brain", action="store_true",
                         help="disable the second brain entirely for this "
                              "run: no memory/concept injection into the "
                              "prompt, no post-run candidate staging")
    p_train.add_argument("--no-brain-capture", action="store_true",
                         help="keep brain injection but skip staging memory "
                              "candidates after the review")
    p_train.set_defaults(func=cmd_train)

    p_review = sub.add_parser(
        "review",
        help="independent review of a run; --live for an in-flight, "
             "possibly-stalled investigation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Read-only review of an investigation from its on-disk "
                    "trace — safe to point at a live run. A deterministic "
                    "stall detector (no LLM) scores it first; a healthy, "
                    "progressing run is never flagged. If it looks stuck, "
                    "the reviewer writes concrete unstick steps to "
                    "reports/<CASE_ID>_live_review.md."),
        epilog=_examples(
            "atlas review --live                    # the active run "
            "(session beacon)",
            "atlas review --live --trace analysis/CASE_trace.json",
            "atlas review --live --json             # babysitter loops: "
            "exit 3 = stalled",
        ) + "\nexit codes: 0 healthy, 3 stalled")
    p_review.add_argument("--live", action="store_true",
                          help="review an in-flight run from its on-disk trace "
                               "and emit unstick recommendations")
    p_review.add_argument("--case", help="case directory (for the output "
                                         "reports/ dir; default: cwd)")
    p_review.add_argument("--trace", help="path to the trace JSON (default: "
                                          "the active session's trace)")
    p_review.add_argument("--question", "-q", help="the case question, for "
                                                   "context")
    p_review.add_argument("--review-model",
                          help="reviewer model id (default: ATLAS_REVIEW_MODEL, "
                               "the reviewer provider's model, then "
                               "REASON_MODEL)")
    p_review.add_argument("--json", action="store_true",
                          help="print a machine-readable result to stdout")
    p_review.set_defaults(func=cmd_review)

    p_chat = sub.add_parser(
        "chat", help="interactive analyst session",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("An open-ended analyst session: no autonomous phase "
                    "loop, you drive. Ask questions, run specific tools, "
                    "explore evidence — same tool access and safety rails "
                    "as `atlas run`. Good for post-run follow-ups or poking "
                    "at a single artifact."),
        epilog=_examples(
            "atlas chat --case ~/cases/mycase       # case-aware",
            "atlas chat                             # no case: toolbox Q&A"))
    p_chat.add_argument("--case", help="case directory")
    p_chat.add_argument("--model", help="override LLMHUB_MODEL")
    p_chat.add_argument("--all-tools", action="store_true")
    _add_skin_arg(p_chat)
    p_chat.set_defaults(func=cmd_chat)

    p_report = sub.add_parser(
        "report", help="render the case's newest final report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Find the newest report under the case's reports/ (or "
                    "analysis/) and render it — pretty-printed in the "
                    "terminal by default, or as Markdown/HTML for sharing."),
        epilog=_examples(
            "atlas report                           # terminal",
            "atlas report --format html             # writes <report>.html",
            "atlas report --format pdf              # writes <report>.pdf",
            "atlas report --format html --output /tmp/report.html"))
    p_report.add_argument("--case", help="case directory")
    p_report.add_argument("--format",
                          choices=["term", "md", "html", "pdf", "navigator",
                                   "stix"],
                          default="term",
                          help="render in the terminal (default), emit "
                               "Markdown/HTML/PDF, or export machine-readable "
                               "artifacts from the trace: an ATT&CK "
                               "Navigator layer or a STIX 2.1 bundle + "
                               "IOC CSV")
    p_report.add_argument("--output", help="write to this file (md/html) "
                                           "or directory (navigator/stix) "
                                           "instead of the default")
    p_report.set_defaults(func=cmd_report)

    p_write_report = sub.add_parser(
        "write-report", help="write the report a stopped run still owes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Assemble the report from the findings already in "
                    "the case's claim graph, and then — unless --no-llm — "
                    "upgrade it with the narrative sections. Nothing from "
                    "the run's own process is needed, so this is the way "
                    "back to a report after a run was killed outright. An "
                    "official analyst report already in the case is left "
                    "alone unless --force says otherwise."),
        epilog=_examples(
            "atlas write-report --case ~/cases/mycase",
            "atlas write-report --no-llm            # findings only, no model",
            "atlas write-report --force             # overwrite what is there"))
    p_write_report.add_argument("--case", help="case directory")
    p_write_report.add_argument("--force", action="store_true",
                                help="write even when a report already exists")
    p_write_report.add_argument("--no-llm", action="store_true",
                                help="skip the narrative sections (no model "
                                     "call, no network)")
    p_write_report.set_defaults(func=cmd_write_report)

    p_verify = sub.add_parser(
        "verify-trace",
        help="verify the hash-chained trace.jsonl mirror of a case",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Recompute the append-only trace mirror's hash "
                    "chain. Any edit, reorder, or deletion of a journaled "
                    "entry breaks the chain from that line onward — proof "
                    "the quoted trace was not altered after the fact."),
        epilog=_examples(
            "atlas verify-trace                     # newest mirror in cwd case",
            "atlas verify-trace analysis/CASE-1_trace.jsonl"))
    p_verify.add_argument("path", nargs="?",
                          help="trace.jsonl file or case directory "
                               "(default: the current case)")
    p_verify.add_argument("--case", help="case directory")
    p_verify.set_defaults(func=cmd_verify_trace)

    p_brain = sub.add_parser(
        "brain",
        help="second brain: durable cross-case knowledge (see brain/AGENTS.md)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Durable cross-case memory. Runs inject relevant "
                    "knowledge in and stage candidate lessons to brain/inbox/ "
                    "after — but a candidate becomes durable only when a "
                    "contributor approves it and it is merged to the canonical "
                    "branch. Growth is gated by brain/CONTRIBUTORS; anyone may "
                    "propose. `atlas brain sync` pulls merged growth. Full model: "
                    "`atlas guide brain`."),
        epilog=_examples(
            "atlas brain review                     # list staged candidates",
            "atlas brain approve <candidate>        # promote (contributors only)",
            "atlas brain reject <candidate> --reason 'too case-specific'",
            "atlas brain sync                       # pull merged brain growth",
            "atlas brain search 'prefetch'"))
    brain_sub = p_brain.add_subparsers(dest="brain_command", required=True)

    b_new = brain_sub.add_parser("new", help="create a note from a template")
    b_new.add_argument("--type", required=True,
                       choices=["note", "case", "tool", "technique", "actor",
                                "concept", "environment", "decision",
                                "research", "run", "memory_candidate"])
    b_new.add_argument("--title", required=True)
    b_new.add_argument("--tags", default="", help="comma-separated tags")
    b_new.add_argument("--client", default="",
                       help="client slug (required for --type environment)")
    b_new.add_argument("--force", action="store_true")
    b_new.set_defaults(func=cmd_brain_new)

    b_search = brain_sub.add_parser("search", help="search brain notes")
    b_search.add_argument("query")
    b_search.add_argument("--type", action="append", dest="types")
    b_search.add_argument("--limit", type=int, default=10)
    b_search.add_argument("--include-confidential", action="store_true")
    b_search.set_defaults(func=cmd_brain_search)

    b_reindex = brain_sub.add_parser("reindex", help="rebuild brain indexes")
    b_reindex.add_argument("--verbose", action="store_true")
    b_reindex.add_argument("--include-confidential", action="store_true")
    b_reindex.set_defaults(func=cmd_brain_reindex)

    brain_sub.add_parser(
        "stats", help="brain stats + JSON snapshot").set_defaults(
        func=cmd_brain_stats)

    b_report = brain_sub.add_parser("report", help="Markdown learning report")
    b_report.add_argument("--period", choices=["week", "month"])
    b_report.add_argument("--since", help="YYYY-MM-DD")
    b_report.set_defaults(func=cmd_brain_report)

    b_review = brain_sub.add_parser("review",
                                    help="list staged memory candidates")
    b_review.add_argument("--type", help="filter by candidate_type")
    b_review.add_argument("--risk", action="store_true",
                          help="only candidates flagged sensitive")
    b_review.set_defaults(func=cmd_brain_review)

    b_approve = brain_sub.add_parser(
        "approve", help="promote a memory candidate into durable memory")
    b_approve.add_argument("candidate", help="path to the candidate file")
    b_approve.add_argument("--yes", action="store_true",
                           help="skip the confirmation prompt")
    b_approve.add_argument(
        "--show-redacted", action="store_true",
        help="preview the candidate with case-specific identifiers redacted, "
             "then exit without promoting")
    b_approve.set_defaults(func=cmd_brain_approve)

    b_reject = brain_sub.add_parser(
        "reject", help="reject a memory candidate, archiving it with a reason")
    b_reject.add_argument("candidate", help="path to the candidate file")
    b_reject.add_argument("--reason", required=True,
                          help="why it was rejected (kept as the audit record)")
    b_reject.add_argument("--yes", action="store_true",
                          help="skip the confirmation prompt")
    b_reject.set_defaults(func=cmd_brain_reject)

    b_sync = brain_sub.add_parser(
        "sync",
        help="fast-forward this clone to receive merged brain growth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Fast-forward this clone from the canonical branch so "
                    "you receive brain knowledge other contributors have merged. "
                    "Runs `git pull --ff-only`; it never rewrites local commits. "
                    "Run it periodically — not mid-investigation, since it can "
                    "also update code."),
        epilog=_examples(
            "atlas brain sync                       # pull from origin/main",
            "atlas brain sync --remote upstream     # pull from another remote"))
    b_sync.add_argument("--remote", default="origin",
                        help="git remote to pull from (default: origin)")
    b_sync.add_argument("--branch", default="main",
                        help="branch to fast-forward from (default: main)")
    b_sync.set_defaults(func=cmd_brain_sync)

    b_capture = brain_sub.add_parser(
        "capture",
        help="stage memory candidates from a finished case run "
             "(run review + trace)")
    b_capture.add_argument("--case", help="case directory (default: cwd)")
    b_capture.set_defaults(func=cmd_brain_capture)

    b_learn = brain_sub.add_parser(
        "learn",
        help="extract high-quality reusable lessons from a finished "
             "investigation (synchronous; train spawns this in background)")
    b_learn.add_argument("--case", help="case directory (default: cwd)")
    b_learn.add_argument("--case-id", default="", dest="case_id")
    b_learn.add_argument("--question", default="")
    b_learn.add_argument("--digest-only", action="store_true",
                         help="build digest without calling an LLM")
    b_learn.set_defaults(func=cmd_brain_learn)

    b_globe = brain_sub.add_parser(
        "globe", help="generate the Brain Earth knowledge-graph data")
    b_globe.add_argument("--case", dest="case_id",
                         help="focus on one case and its neighborhood")
    b_globe.add_argument("--topic", help="focus on one tag/topic")
    b_globe.add_argument("--mode",
                         choices=["full", "growth", "quality", "security"])
    b_globe.set_defaults(func=cmd_brain_globe)

    p_publish = sub.add_parser(
        "publish",
        help="build a scrubbed public snapshot and push it to GitHub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap("Build a scrubbed snapshot for the PUBLIC GitHub "
                    "remote: HEAD minus every INTERNAL path in "
                    ".gitignore-public (raw captures, internal cases, "
                    "contributor PII), with the brain/wiki + brain/indexes "
                    "trees scanned for case-specific identifiers. Nothing is "
                    "pushed unless --push is given AND the snapshot is clean. "
                    "Internal work stays on a private remote; this is the "
                    "only sanctioned path to GitHub."),
        epilog=_examples(
            "atlas publish                 # dry run: build + scan, no push",
            "atlas publish --push          # publish the scrubbed 'public' branch",
            "atlas publish --push --remote origin --branch public"))
    p_publish.add_argument("--push", action="store_true",
                           help="push the scrubbed snapshot (default: dry run)")
    p_publish.add_argument("--remote", default="origin",
                           help="public remote (default: origin = GitHub)")
    p_publish.add_argument("--branch", default="public",
                           help="branch to publish (default: public)")
    p_publish.set_defaults(func=cmd_publish)

    p_models = sub.add_parser("models", help="list models on a provider")
    p_models.add_argument("--provider", default="",
                          help="registered provider name (required; no implicit default)")
    p_models.set_defaults(func=cmd_models)
    p_doctor = sub.add_parser("doctor", help="show resolved configuration")
    p_doctor.add_argument("--probe", action="store_true",
                          help="also GET /models on every provider "
                               "(the only network call doctor makes)")
    p_doctor.set_defaults(func=cmd_doctor)

    from agent.tui import LIVE_SKINS as _LIVE_SKINS
    p_skin = sub.add_parser(
        "skin",
        help="choose the animated LIVE dashboard skin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_wrap(
            "Pick how the LIVE panel looks during atlas run / train / chat. "
            "Colour themes stay on ATLAS_THEME (neon/atlas/mono); skins change "
            "the animation layout. Preference is saved in ~/.atlas/ui.json."
        ),
        epilog=_examples(
            "atlas skin                         # list skins (* = active)",
            "atlas skin matrix                  # set default + persist",
            "atlas skin radar --preview         # set + show a few frames",
            "atlas run --skin wave -q '…'       # one-shot, no persist",
        ),
    )
    p_skin.add_argument(
        "name", nargs="?", default=None, metavar="NAME",
        help="skin to activate: " + " | ".join(sorted(_LIVE_SKINS))
             + " (omit to list)",
    )
    p_skin.add_argument(
        "--preview", action="store_true",
        help="print a few static frames of the (new) skin",
    )
    p_skin.set_defaults(func=cmd_skin)

    p_provider = sub.add_parser("provider", help="inspect or switch model providers")
    p_provider_sub = p_provider.add_subparsers(dest="provider_cmd")
    p_provider_sub.required = True
    p_provider_sub.add_parser(
        "list", help="registered providers and which role uses which"
    ).set_defaults(func=cmd_provider_list)
    p_provider_use = p_provider_sub.add_parser(
        "use", help="point model surfaces at a provider (edits .env)")
    p_provider_use.add_argument("name", help="registered provider name")
    p_provider_use.add_argument(
        "--role", default="all",
        choices=["all", "analyst", "reviewer", "report", "reason", "dair"],
        help="which model surface to switch (default: all)")
    p_provider_use.add_argument(
        "--model", default="",
        help="model id to pin for this provider (required if it has none yet)")
    p_provider_use.add_argument(
        "--dry-run", action="store_true",
        help="print the .env changes without writing them")
    p_provider_use.add_argument(
        "--no-probe", action="store_true",
        help="skip the reachability and catalogue check (configures a provider "
             "that may not answer)")
    p_provider_use.set_defaults(func=cmd_provider_use)
    p_provider_test = p_provider_sub.add_parser(
        "test", help="three short calls: reachability, tool calling, thinking")
    p_provider_test.add_argument("name", help="registered provider name")
    p_provider_test.add_argument("--model", default="",
                                 help="model id to test (default: the provider's)")
    p_provider_test.set_defaults(func=cmd_provider_test)
    p_provider_sub.add_parser(
        "setup",
        help="interactive wizard: register a new LLM provider and point "
             "roles at it (OpenAI, local/self-hosted, Telekom LLM Hub, or "
             "any other OpenAI-compatible endpoint)",
    ).set_defaults(func=cmd_provider_setup)

    p_share = sub.add_parser(
        "share", help="SMB network share for case evidence (mount from Windows)")
    p_share_sub = p_share.add_subparsers(dest="share_cmd")
    p_share_sub.required = True
    p_share_sub.add_parser(
        "status", help="whether the share is installed/enabled/running"
    ).set_defaults(func=cmd_share_status)
    p_share_sub.add_parser(
        "enable", help="enable the share for this user's cases root (samba "
                       "must already be installed)"
    ).set_defaults(func=cmd_share_enable)
    p_share_sub.add_parser(
        "disable", help="remove the share config (leaves samba itself installed)"
    ).set_defaults(func=cmd_share_disable)
    p_share_sub.add_parser(
        "passwd", help="set/change the Samba password for this share (prompts, hidden input)"
    ).set_defaults(func=cmd_share_passwd)

    p_addon = sub.add_parser("addon", help="list or scaffold Atlas addons (see docs/addons.md)")
    p_addon_sub = p_addon.add_subparsers(dest="addon_cmd")
    p_addon_sub.required = True
    p_addon_list = p_addon_sub.add_parser(
        "list", help="discovered addons and their enabled/compatible state")
    p_addon_list.add_argument("--json", action="store_true",
                              help="also print machine-readable JSON")
    p_addon_list.set_defaults(func=cmd_addon_list)
    p_addon_create = p_addon_sub.add_parser(
        "create", help="scaffold a new addon under plugins/<name>/")
    p_addon_create.add_argument("name", help="addon name (valid Python package name)")
    p_addon_create.set_defaults(func=cmd_addon_create)

    p_intel = sub.add_parser(
        "intel", help="supply indicators and threat reports to a case (see docs/intel.md)")
    p_intel_sub = p_intel.add_subparsers(dest="intel_cmd")
    p_intel_sub.required = True
    _case_help = "case directory (default: cwd if it holds a case)"
    p_intel_add = p_intel_sub.add_parser(
        "add", help="read an indicator file or a threat report into the case's threat context")
    p_intel_add.add_argument("--case", help=_case_help)
    _intel_src = p_intel_add.add_mutually_exclusive_group(required=True)
    _intel_src.add_argument("--file", help="indicator file: one value per line, CSV, STIX 2.1, "
                                           "MISP event JSON, native JSONL, or an addon's format")
    _intel_src.add_argument("--doc", help="a threat report (text, HTML or PDF): kept as text; the "
                                          "indicators it names become rows nobody rated")
    p_intel_add.add_argument("--format", help="reader name (default: detected; see atlas intel sources)")
    p_intel_add.add_argument("--name", help="source label (default: the file name)")
    p_intel_add.add_argument("--tlp", help="TLP for rows that carry none: clear, green, amber, amber+strict, red")
    p_intel_add.add_argument("--map", help="CSV columns by field, e.g. value=Indicator,type=Kind")
    p_intel_add.set_defaults(func=cmd_intel)
    p_intel_pull = p_intel_sub.add_parser(
        "pull", help="run a command source configured in .env and record what it printed")
    p_intel_pull.add_argument("--case", help=_case_help)
    p_intel_pull.add_argument("--source", required=True, help="source name from ATLAS_INTEL_SOURCES")
    p_intel_pull.set_defaults(func=cmd_intel)
    p_intel_list = p_intel_sub.add_parser("list", help="the case's threat-context rows")
    p_intel_list.add_argument("--case", help=_case_help)
    p_intel_list.add_argument("--all", action="store_true", help="include unfit and withdrawn rows")
    p_intel_list.add_argument("--json", action="store_true", help="print the whole record as JSON")
    p_intel_list.set_defaults(func=cmd_intel)
    p_intel_withdraw = p_intel_sub.add_parser(
        "withdraw", help="retire rows by id or by source, keeping them with the reason")
    p_intel_withdraw.add_argument("--case", help=_case_help)
    p_intel_withdraw.add_argument("--id", action="append", help="row id, e.g. intel-0003 (repeatable)")
    p_intel_withdraw.add_argument("--source", help="withdraw every row of this source")
    p_intel_withdraw.add_argument("--reason", required=True, help="why the rows no longer apply")
    p_intel_withdraw.set_defaults(func=cmd_intel)
    p_intel_sub.add_parser(
        "sources", help="the readers available and the command sources .env configures"
    ).set_defaults(func=cmd_intel)

    p_rerun = sub.add_parser(
        "rerun",
        help="continue the investigation from what changed (evidence, questions, facts)",
        description=(
            "Continue the investigation from what changed: evidence added, "
            "changed or removed under evidence/, questions added to CASE.md, "
            "facts added to its 'What you already know' section, findings "
            "marked for review. The pre-run pass (Plane A) records the delta, "
            "re-validates only the findings it touches and writes the Rerun "
            "Brief; when it found work, the investigator starts from the brief "
            "(Plane B) unless --no-agent. When nothing changed, only stale "
            "report sections are regenerated. The dirty set is a starting "
            "point, not a hard boundary. Evidence is never modified."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  atlas rerun --case ~/cases/CASE-001 --no-agent\n"
            "  atlas rerun --case ~/cases/CASE-001 -q "
            "'IP 10.0.0.5 is a legitimate admin jump host'\n"
            "  atlas rerun --case ~/cases/CASE-001 -q '...' --no-agent\n"
            "  atlas rerun --withdraw-context ac-0001 --no-agent\n"
            "  atlas rerun --correct-context ac-0001 -q 'updated context' --no-agent\n"
            "  atlas rerun --dry-run --json\n"
            "  atlas rerun --assemble-report --format html\n"
        ),
    )
    p_rerun.add_argument("--case", "-c", default=None,
                         help="case directory (default: cwd if it looks like a case)")
    p_rerun.add_argument(
        "--question", "-q", default=None,
        help=(
            "a fact for the brief (not evidence): appended to the 'What you "
            "already know' section of CASE.md and kept as analyst context; "
            "the findings that mention what it names are re-validated by the "
            "investigator this rerun starts"
        ),
    )
    p_rerun.add_argument(
        "--withdraw-context", default=None, metavar="AC_ID",
        help="withdraw a previously recorded analyst_context id (e.g. ac-0001)",
    )
    p_rerun.add_argument(
        "--correct-context", default=None, metavar="AC_ID",
        help="withdraw AC_ID and replace with -q text (supersedes link recorded)",
    )
    p_rerun.add_argument("--no-agent", action="store_true",
                         help="Plane A only: catalog/diff/context; do not run AI or regenerate sections")
    p_rerun.add_argument("--dry-run", action="store_true",
                         help="scan and diff without writing catalog updates")
    p_rerun.add_argument("--json", action="store_true",
                         help="also print machine-readable JSON result")
    p_rerun.add_argument("--full-hash", action="store_true",
                         help="force full-file hashes even for large images")
    p_rerun.add_argument("--diff", default=None, metavar="RUN_A..RUN_B",
                         help="compare two journal runs (what/why)")
    p_rerun.add_argument("--list-runs", action="store_true",
                         help="list investigation journal runs and milestones")
    p_rerun.add_argument(
        "--regenerate-sections", action="store_true",
        help=(
            "AI-regenerate stale report projection sections then assemble "
            "(requires LLMHUB_API_KEY unless deterministic fallback applies)"
        ),
    )
    p_rerun.add_argument(
        "--assemble-report", action="store_true",
        help="assemble deliverable from current projection (no LLM)",
    )
    p_rerun.add_argument(
        "--format", dest="report_format", default="markdown",
        choices=("markdown", "md", "html", "pdf", "json"),
        help="assemble format when regenerating/assembling (default: markdown)",
    )
    p_rerun.add_argument("--model", default=None,
                         help="override LLMHUB_MODEL for analyst-context Plane B")
    p_rerun.add_argument(
        "--language", "-L", choices=("en", "de"), default=None,
        help="report language (en|de); persisted in .atlas/case_config.json "
             "(reruns inherit when omitted)",
    )
    p_rerun.set_defaults(func=cmd_rerun)

    p_explain = sub.add_parser(
        "explain",
        help="explain a claim, conflict, or report section",
        description=(
            "Explain a belief from Current Investigation State: statement, "
            "confidence, evidence, reasoning, gaps, related edges, journal events."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  atlas explain C0004\n"
            "  atlas explain --section lateral_movement\n"
            "  atlas explain --conflict X0001\n"
        ),
    )
    p_explain.add_argument("node_id", nargs="?", default=None,
                           help="claim/conclusion/hypothesis/conflict id")
    p_explain.add_argument("--case", "-c", default=None)
    p_explain.add_argument("--section", default=None,
                           help="report projection section id")
    p_explain.add_argument("--conflict", default=None,
                           help="conflict node id (alias for node_id)")
    p_explain.add_argument("--json", action="store_true")
    p_explain.set_defaults(func=cmd_explain)

    p_timeline = sub.add_parser(
        "timeline",
        help="case attack/investigation timeline",
        description=(
            "Build a case-level timeline without requiring Timeline Builder. "
            "Default: claim graph + journal milestones. "
            "Optional: analysis/master_timeline.tsv via --from-master."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  atlas timeline\n"
            "  atlas timeline --from-claims\n"
            "  atlas timeline --from-master\n"
        ),
    )
    p_timeline.add_argument("--case", "-c", default=None)
    src = p_timeline.add_mutually_exclusive_group()
    src.add_argument("--from-claims", action="store_true", default=True,
                     help="derive from claim graph + journal (default)")
    src.add_argument("--from-master", action="store_true",
                     help="use analysis/master_timeline.tsv if present")
    p_timeline.add_argument("--limit", type=int, default=200,
                            help="max events to print (default 200)")
    p_timeline.add_argument("--json", action="store_true")
    p_timeline.set_defaults(func=cmd_timeline)

    p_journal = sub.add_parser(
        "journal",
        help="inspect investigation journal runs",
        description="Ergonomic alias for atlas rerun --list-runs / --diff.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  atlas journal\n"
            "  atlas journal show run-0003\n"
            "  atlas journal diff run-0001..run-0003\n"
        ),
    )
    p_journal.add_argument("--case", "-c", default=None)
    p_journal.add_argument("--json", action="store_true")
    jsub = p_journal.add_subparsers(dest="journal_action")
    jsub.add_parser("list", help="list runs (default)").set_defaults(
        journal_action="list")
    p_jshow = jsub.add_parser("show", help="show one run")
    p_jshow.add_argument("run_id")
    p_jshow.set_defaults(journal_action="show")
    p_jdiff = jsub.add_parser("diff", help="diff two runs")
    p_jdiff.add_argument("diff_spec", metavar="RUN_A..RUN_B")
    p_jdiff.set_defaults(journal_action="diff")
    p_journal.set_defaults(func=cmd_journal, journal_action="list")

    p_status = sub.add_parser(
        "status",
        help="one-screen investigation health",
        description=(
            "Open conflicts, needs_review, dirty evidence, stale report "
            "sections, last journal run."
        ),
    )
    p_status.add_argument("--case", "-c", default=None)
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    p_autofill = sub.add_parser(
        "autofill",
        help="AI autofill for CASE.md's Evidence Links table",
        description=(
            "Scans evidence/, proposes Evidence Links rows for the connected "
            "analyst LLM's classification, and asks about anything it can't "
            "place. Investigation Requests are left alone except for adding "
            "the standard question when that section is empty."
        ),
    )
    p_autofill.add_argument("--case", "-c", default=None,
                            help="case directory (default: cwd if it looks "
                                 "like a case)")
    p_autofill.add_argument("--yes", "-y", action="store_true",
                            help="skip confirmation and accept every AI "
                                 "suggestion without asking")
    p_autofill.set_defaults(func=cmd_case_autofill)

    sub.add_parser("serve", help="run the MCP server (stdio)").set_defaults(
        func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    _bootstrap_env()
    args.func(args)


if __name__ == "__main__":
    main()
