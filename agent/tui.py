"""Terminal UI for the Atlas CLI.

A welcome panel, a spinner while the model thinks,
a marked `tool(args)` line and an indented result line for tool activity, Markdown-rendered
answers, and a slash-command REPL. Everything degrades to plain prints when
stdout is not a TTY, `--quiet` is set, or rich isn't installed — the agent
loop only ever talks to the `UI` class.
"""
from __future__ import annotations

import math
import os
import random
import re
import sys
import time
from pathlib import Path

try:
    from rich import box
    from rich.console import Console, Group
    from rich.live import Live
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:  # pragma: no cover - rich is in requirements
    HAS_RICH = False

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import FileHistory
    HAS_PTK = True
except ImportError:  # pragma: no cover
    HAS_PTK = False

NAME = "Atlas"
TAGLINE = "Autonomous DFIR agent for malware analysis and rogue-actor attribution"
LORE = ("Atlas was the Titan tasked with bearing the weight of the sky "
        "so it would not fall. This one bears the weight of the "
        "investigation.")

# The Atlas figure the tool is named after: a globe borne on two pillars.
# Variants by terminal width, widest first.
ATLAS_LARGE = (
    "  ◠─────◠\n"
    " ( ─ ⊕ ─ )\n"
    "  |     |\n"
    " ┴┴────┴┴"
)
ATLAS_SMALL = (
    " ◠───◠\n"
    "( ─ ⊕ ─ )"
)
ATLAS_TINY = "( ─ ⊕ ─ )"

# Block-letter wordmark, one string per letter per row, coloured with a neon
# gradient in the banner. Shown only when the terminal is wide enough.
WORDMARK = (
    ("█▀▄▀█", "▄▀█", "█▀█", "▄▀█"),
    ("█ ▀ █", "█▀█", "█▀▄", "█▀█"),
)

# ── Command-keyed animations ─────────────────────────────────────────────────
# `atlas run` → Atlas strides along (a walk cycle: legs + a bobbing gait).
# Frames are cycled by the dashboard's frame counter. Each set keeps a constant
# line count and near-constant width so the panel doesn't jitter. The globe
# (⊕) stays visible in every frame, borne aloft whatever the figure is doing.

ATLAS_WALK_LARGE = (
    # a steady stride: the globe bobs, legs swing, dust kicks up behind
    "  ◠─────◠   \n"
    " ( ─ ⊕ ─ )  \n"
    "  |     |   \n"
    " ┴┴────┴┴ ˙˙",
    "   ◠─────◠  \n"
    "  ( ─ ⊕ ─ ) \n"
    "   |     |  \n"
    "  ┴┴────┴┴ ˙",
    "  ◠─────◠   \n"
    " ( ─ ⊕ ─ )  \n"
    "  |     |   \n"
    " ┴ ┴──┴ ┴ ˙ ",
    "   ◠─────◠  \n"
    "  ( ─ ⊕ ─ ) \n"
    "   |     |  \n"
    "   ┴┴──┴┴  ˙",
)

ATLAS_WALK_SMALL = (
    " ◠───◠   \n"
    "( ─ ⊕ ─ )\n"
    " ┴ ── ┴ ˙",
    "  ◠───◠  \n"
    " ( ─ ⊕ ─ )\n"
    "  ┴──┴  ˙",
)

# `atlas review` → Atlas reads the run report line by line: a lens
# blinks (an open, then a filled circle) while the highlight sweeps across
# the page.
REVIEW_LARGE = (
    "  ◠─────◠   \n"
    " ( ─ ⊕ ─ )  \n"
    "  |     |(○)\n"
    " ▓≡≡≡≡≡≡≡≡≡ ",
    "  ◠─────◠   \n"
    " ( ─ ⊕ ─ )  \n"
    "  |     |(◉)\n"
    " ≡≡≡▓≡≡≡≡≡≡ ",
    "  ◠─────◠   \n"
    " ( ─ ⊕ ─ )  \n"
    "  |     |(○)\n"
    " ≡≡≡≡≡≡▓≡≡≡ ",
    "  ◠─────◠   \n"
    " ( ─ ⊕ ─ )  \n"
    "  |     |(◉)\n"
    " ≡≡≡≡≡≡≡≡≡▓ ",
)

REVIEW_SMALL = (
    " ◠───◠   \n"
    "( ─ ⊕ ─ )\n"
    "▓≡≡≡≡≡≡≡≡",
    " ◠───◠   \n"
    "( ─ ⊕ ─ )\n"
    "≡≡≡≡▓≡≡≡≡",
)

# Command → (large, small) avatar frame sets; anything not listed falls back
# to the standing figure with the classic periodic blink.
COMMAND_FRAMES = {
    "run": (ATLAS_WALK_LARGE, ATLAS_WALK_SMALL),
    "review": (REVIEW_LARGE, REVIEW_SMALL),
}

# Centralised theme: every rich style string used by the UI lives here.
# `neon` is the default cyber look; ATLAS_THEME=atlas restores the classic
# theme, ATLAS_THEME=mono gives style-free output on odd terminals.
THEMES = {
    "neon": {"accent": "bold bright_cyan", "avatar": "bold bright_magenta",
             "tool": "bold bright_green", "dim": "bright_black",
             "warn": "bold bright_yellow", "error": "bold bright_red",
             "info": "bold bright_blue",
             "border": "bright_cyan", "finish_border": "bright_green",
             "slow": "bright_yellow",
             "wordmark": ("bold bright_cyan", "bold bright_magenta",
                          "bold bright_green", "bold bright_cyan"),
             "tool_palette": ("bright_green", "bright_cyan", "bright_magenta",
                              "bright_yellow", "bright_blue")},
    "atlas": {"accent": "bold red", "avatar": "tan", "tool": "green",
             "dim": "dim", "warn": "yellow", "error": "bold red",
             "info": "cyan",
             "border": "dim", "finish_border": "green",
             "slow": "yellow",
             "wordmark": ("bold red",) * 4,
             "tool_palette": ("green",)},
    "mono": {"accent": "bold", "avatar": "default", "tool": "default",
             "dim": "dim", "warn": "bold", "error": "bold",
             "info": "dim",
             "border": "dim", "finish_border": "dim",
             "slow": "dim",
             "wordmark": ("bold",) * 4,
             "tool_palette": ("default",)},
}
THEME = THEMES.get(os.environ.get("ATLAS_THEME", "neon"), THEMES["neon"])

# ── LIVE dashboard skins ─────────────────────────────────────────────────────
# Colour palettes stay in ATLAS_THEME (neon/atlas/mono). Skins reshape the
# animated LIVE panel itself — Atlas, Matrix rain, radar sweep, waveform.
# Resolve: --skin / UI(skin=…) > ATLAS_LIVE_SKIN > ~/.atlas/ui.json > atlas.
LIVE_SKINS = {
    "atlas": "Classic animated Atlas figure + neon LIVE panel (default)",
    "matrix": "Digital rain with Atlas run data centred in the cascade",
    "radar": "Sonar sweep — blips for tools, findings, and alerts",
    "wave": "Oscilloscope heartbeat of the investigation signal",
    "aquarium": "Underwater fish tank — seaweed, bubbles, and fish",
}
DEFAULT_LIVE_SKIN = "atlas"
_MATRIX_GLYPHS = (
    "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ"
    "0123456789"
)
# Aquarium fish sprites (right-facing / left-facing).
_AQUA_FISH_R = ("><(((º>", "><>", ">°>", "·><(((('>")
_AQUA_FISH_L = ("<º)))><", "<><", "<°<", "<')))><·")


def ui_prefs_path() -> Path:
    return Path.home() / ".atlas" / "ui.json"


def load_ui_prefs() -> dict:
    path = ui_prefs_path()
    if not path.is_file():
        return {}
    try:
        import json
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_ui_prefs(prefs: dict) -> Path:
    path = ui_prefs_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    import json
    current = load_ui_prefs()
    current.update(prefs)
    path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def resolve_live_skin(cli_value: str | None = None) -> str:
    """Pick the LIVE dashboard skin. Unknown names fall back to the default."""
    for candidate in (
        (cli_value or "").strip().lower() or None,
        (os.environ.get("ATLAS_LIVE_SKIN") or "").strip().lower() or None,
        (load_ui_prefs().get("live_skin") or "").strip().lower() or None,
        DEFAULT_LIVE_SKIN,
    ):
        if candidate and candidate in LIVE_SKINS:
            return candidate
    return DEFAULT_LIVE_SKIN


# One animation frame per this many seconds. Frames are derived from the
# wall clock, not from Live refresh counts, so animation speed stays constant
# no matter how often the live region repaints (scrolling prints trigger
# extra refreshes). 0.1s matches the dashboard's refresh_per_second=10.
FRAME_SECONDS = 0.1

# Spinner verbs — DFIR work with nightmare-demon flavor.
VERBS = (
    "Haunting the registry",
    "Carving unallocated space",
    "Chasing ghosts through the shellbags",
    "Exorcising rootkits",
    "Interrogating hives",
    "Following the USN trail",
    "Summoning volatile memory",
    "Cross-examining timestamps",
    "Stalking lateral movement",
    "Reading the MFT's entrails",
    "Sniffing packets",
    "Digging up deleted files",
    "Following the scent",
    "Fetching artifacts",
    "Chewing on the evidence",
    "Auditing the nightmare",
    "Triaging",
    "Hypothesizing",
    "Correlating",
)

SLASH_COMMANDS = {
    "/help": "show this help",
    "/tools": "list tools in the loaded namespaces",
    "/namespaces": "list all namespaces (loaded and available)",
    "/model": "show the active model and hub",
    "/tokens": "show token usage for this session",
    "/case": "show the case dir, or /case DIR to switch",
    "/report": "render the newest report from reports/",
    "/history": "show recent turns and the transcript path",
    "/save": "save this session to analysis/ (/save NAME)",
    "/resume": "restore a saved session (/resume latest|PATH)",
    "/clear": "reset the conversation (keeps the system prompt)",
    "/quit": "exit",
}


class UI:
    """All CLI output goes through here; `plain` mode keeps it script-safe."""

    def __init__(self, quiet: bool = False, console=None,
                 skin: str | None = None):
        self.quiet = quiet
        self.live_skin = resolve_live_skin(skin)
        if console is not None:  # injected (tests) — trust it as a terminal
            self.plain = quiet or not HAS_RICH
            self.console = console
            self._honor_injected_terminal(console)
        else:
            self.plain = quiet or not HAS_RICH or not sys.stdout.isatty()
            self.console = Console(highlight=False) if HAS_RICH else None
        self._status = None
        # Persistent live dashboard (rich Live) shown for the whole command.
        # Animation frames derive from the wall clock (see _frame_now); the
        # clock is injectable so tests can drive animations deterministically.
        self._live = None
        self._clock = time.monotonic
        self._anim_t0: float | None = None
        # Recent one-shot events (kind → clock timestamp) that briefly change
        # how the dashboard renders: "finding" and "error" drive the avatar's
        # mood and the stats sparkle. Written from the main thread only; the
        # Live refresh thread just reads.
        self._events: dict[str, float] = {}
        # Live stats about the command currently running, rendered next to the
        # avatar in the status banner / live dashboard. Updated by the loop.
        self.run_state: dict = {}
        # Progress graph: a ring of recent tool short-names (the flow) and the
        # set of distinct evidence artifacts touched, rendered live.
        self._graph: list[str] = []
        self._artifacts: set[str] = set()
        self._graph_total = 0

    @staticmethod
    def _honor_injected_terminal(console) -> None:
        """Make an injected console behave as the real terminal it claims to be.

        A caller-injected console is built to be rendered against — it sets
        ``force_terminal=True`` and an explicit ``width`` and expects both to
        hold whatever the surrounding process looks like. Two pieces of rich's
        ambient auto-detection defeat that in a headless environment (CI, or
        ssh without a pty — e.g. the ``atlas setup`` install-time ``pytest``
        gate run under ``runuser -l ... -c``):

        1. When the ambient ``TERM`` is ``dumb`` or ``unknown``, rich flags the
           console as a *dumb terminal* — it then clamps the size to 80×25
           (silently discarding the injected ``width``) and skips its
           ``Live``/``status`` output. Shadow just ``TERM``, on a private copy
           of the environ (never the process-wide ``os.environ``), so
           ``is_dumb_terminal`` is false and the injected width is honoured.
        2. With no controlling tty, rich records ``is_interactive=False`` at
           construction, and a *transient* ``Live`` only paints its renderable
           to an interactive console — so ``thinking()``'s status banner would
           render to an empty string. Force it back on.

        No-op for the normal (non-injected) console: production never passes
        one in, so this only ever hardens the consoles built by the tests.
        """
        if not HAS_RICH or not getattr(console, "is_terminal", False):
            return
        try:  # best-effort: these touch rich internals — never break the UI
            env = getattr(console, "_environ", None)
            if env is not None and str(env.get("TERM", "")).lower() in (
                    "dumb", "unknown"):
                patched = dict(env)  # copy — don't mutate the shared os.environ
                patched["TERM"] = "xterm-256color"
                console._environ = patched
            console.is_interactive = True
        except Exception:  # noqa: BLE001 — cosmetic hardening, never fatal
            pass

    def set_run_state(self, **kw) -> None:
        """Merge live counters (command, turn, elapsed, tools, errors,
        infos, findings, tokens) shown in the status banner while a command runs."""
        self.run_state.update(kw)

    # ── animation clock & events ─────────────────────────────────────────

    def _frame_now(self) -> int:
        """The current animation frame, derived from elapsed wall-clock time
        since the live session started (0 outside a live session)."""
        if self._anim_t0 is None:
            return 0
        return int((self._clock() - self._anim_t0) / FRAME_SECONDS)

    def pulse_event(self, kind: str) -> None:
        """Stamp a one-shot event ("finding", "error") that briefly restyles
        the live dashboard — the avatar's mood, the stats sparkle."""
        self._events[kind] = self._clock()

    def _event_age(self, kind: str) -> float | None:
        """Seconds since `kind` last pulsed, or None if it never did."""
        ts = self._events.get(kind)
        return None if ts is None else self._clock() - ts

    # ── progress graph ───────────────────────────────────────────────────

    # A path-ish token with an extension — used to spot evidence artifacts a
    # tool touched (from its argument preview).
    _ARTIFACT_RE = re.compile(r"[\w./\\-]*[/\\][\w.\-]+\.[A-Za-z0-9]{1,6}\b")

    @staticmethod
    def _short_tool(name: str) -> str:
        """Compact node label for a tool: the last dotted/underscored segment
        (e.g. vol_vol_pslist → pslist, misc.record_finding → finding)."""
        token = name.replace(".", "_").rstrip("_")
        return token.rsplit("_", 1)[-1] if "_" in token else token

    def note_tool(self, name: str, args_preview: str = "") -> None:
        """Record a tool call for the live progress graph: append its node and
        harvest any evidence artifacts named in its arguments. Cheap and
        side-effect-free on output — only the live dashboard reads this."""
        self._graph_total += 1
        self._graph.append(self._short_tool(name))
        if len(self._graph) > 8:
            self._graph = self._graph[-8:]
        for m in self._ARTIFACT_RE.findall(args_preview or ""):
            base = m.replace("\\", "/").rsplit("/", 1)[-1]
            if base:
                self._artifacts.add(base)

    def _graph_text(self) -> "Text":
        """The recent tool flow as an arrow chain, newest node highlighted,
        plus the count of distinct artifacts touched."""
        t = Text()
        chain = self._graph[-6:]
        for i, node in enumerate(chain):
            if i:
                t.append(" → ", style=THEME["dim"])
            newest = i == len(chain) - 1
            t.append(node, style=THEME["tool"] if newest else THEME["dim"])
        if self._artifacts:
            t.append(f"   ◇ {len(self._artifacts)} artifacts",
                     style=THEME["dim"])
        return t

    # ── banner ───────────────────────────────────────────────────────────

    def _avatar_art(self) -> str | None:
        """Pick an avatar variant for the current terminal width, or None
        when the terminal is too narrow for multi-line art."""
        width = self.console.width
        if width >= 76:
            return ATLAS_LARGE
        if width >= 56:
            return ATLAS_SMALL
        return None

    def banner(self, model: str, hub: str, case_dir: Path | None,
               tools: int, namespaces: int, loaded: int) -> None:
        if self.quiet:
            return
        if self.plain:
            print(f"{NAME} — {TAGLINE}")
            print(f"  model: {model}  hub: {hub}")
            print(f"  case:  {case_dir or '(none)'}")
            print(f"  tools: {tools} in {namespaces} namespaces "
                  f"({loaded} loaded)")
            return
        avatar = self._avatar_art()
        body = Text()
        if avatar is None:
            body.append(f"{ATLAS_TINY} ", style=THEME["avatar"])
        if avatar is ATLAS_LARGE:  # wide terminal: the neon block wordmark
            for row in WORDMARK:
                for letter, style in zip(row, THEME["wordmark"]):
                    body.append(letter + " ", style=style)
                body.append("\n")
        body.append(f"{NAME}", style=THEME["accent"])
        body.append(f" — {TAGLINE}\n", style="dim")
        body.append(f"{LORE}\n\n", style="italic dim")
        info = (("model", model), ("hub", hub),
                ("case", str(case_dir) if case_dir
                 else "(none — pass --case DIR)"),
                ("tools", f"{tools} in {namespaces} namespaces "
                          f"({loaded} loaded)"))
        for key, value in info:
            body.append(f"{key:>6} ", style=THEME["accent"])
            body.append(f"{value}\n" if key != "tools" else value)
        if avatar is not None:
            grid = Table.grid(padding=(0, 2))
            grid.add_column()
            grid.add_column()
            grid.add_row(Text(avatar, style=THEME["avatar"]), body)
            content = grid
        else:
            content = body
        self.console.print(Panel(content, border_style=THEME["border"],
                                 box=box.ROUNDED, expand=False,
                                 padding=(0, 2)))

    # ── live stats / cyber dashboard ─────────────────────────────────────

    @staticmethod
    def _fmt_elapsed(seconds: float) -> str:
        minutes, secs = divmod(int(seconds), 60)
        return f"{minutes}m{secs:02d}s" if minutes else f"{secs}s"

    def _stats_text(self, frame: int = 0) -> "Text":
        """Live counters as an iconed strip: elapsed time, calls, errors,
        infos, findings and tokens. Values that signal something (errors,
        infos, findings) get colour; the rest stays dim. Elapsed ticks from
        `run_start` at render time, so the clock never freezes during a slow
        model call."""
        st = self.run_state
        text = Text()

        def part(icon: str, value: str, style: str) -> None:
            if text.plain:
                text.append("  ·  ", style=THEME["dim"])
            text.append(f"{icon} ", style=THEME["dim"])
            text.append(value, style=style)

        if st.get("run_start") is not None:
            part("⏱", self._fmt_elapsed(self._clock() - st["run_start"]),
                 THEME["dim"])
        elif st.get("elapsed") is not None:
            part("⏱", self._fmt_elapsed(st["elapsed"]), THEME["dim"])
        part("⚙", f"{st.get('tools', 0)} calls", THEME["dim"])
        # Always show err/info (even at 0) so the strip stays stable and the
        # operator can tell soft gate refusals (info) from real breakage (err).
        errors = int(st.get("errors") or 0)
        infos = int(st.get("infos") or 0)
        part("⚠", f"{errors} err",
             THEME["warn"] if errors else THEME["dim"])
        part("ℹ", f"{infos} info",
             THEME.get("info", THEME["dim"]) if infos else THEME["dim"])
        findings = st.get("findings", 0)
        # A fresh finding sparkles for a moment. Both branches occupy the
        # same two trailing cells so the row width never jitters.
        spark_age = self._event_age("finding")
        if spark_age is not None and spark_age < 2.0:
            part("◆", f"{findings} findings ✦", f"bold {self._neon(frame)}")
        else:
            part("◆", f"{findings} findings  ",
                 THEME["tool"] if findings else THEME["dim"])
        if st.get("tokens"):
            part("⌁", f"{st['tokens']:,} tok", THEME["dim"])
        # Investigation orchestrator stewardship strip (Phase 3).
        policy = st.get("ctx_policy")
        if policy:
            room = st.get("ctx_tool_tok")
            label = f"ctx {policy}"
            if room is not None:
                try:
                    label += f"/{int(room)}t"
                except (TypeError, ValueError):
                    pass
            part("▣", label, THEME["dim"])
        orch_top = st.get("orch_top")
        if orch_top:
            score = st.get("orch_score")
            tool = st.get("orch_tool") or ""
            rank = st.get("orch_rank") or "det"
            bit = f"next {orch_top}"
            if tool:
                bit += f"→{tool}"
            if score is not None:
                bit += f" ({score})"
            if rank == "llm":
                bit += "⋆"
            part("▸", bit, THEME.get("tool", THEME["dim"]))
        return text

    def _neon(self, frame: int) -> str:
        """Cycle through the neon palette for a pulsing effect."""
        palette = ("bright_cyan", "bright_magenta", "bright_green")
        return palette[(frame // 3) % len(palette)]

    def _alert_level(self, now: float) -> str | None:
        """"warn" while something deserves attention — the current tool has
        run for over a minute, or an error pulsed in the last 30s. The
        dashboard shifts from the neon cycle to the theme's warn colours."""
        ts = self.run_state.get("tool_started")
        if ts is not None and now - ts > 60:
            return "warn"
        err = self._events.get("error")
        if err is not None and now - err < 30:
            return "warn"
        return None

    def _avatar_frame(self, frame: int) -> str | None:
        """Atlas's avatar for the current frame, keyed on the running command
        (see COMMAND_FRAMES); anything else blinks. A recent finding or error
        overlays a mood on top. Returns None only when the terminal is too
        narrow for multi-line art (the caller falls back to ATLAS_TINY)."""
        avatar = self._avatar_art()
        if avatar is None:
            return None
        command = (self.run_state or {}).get("command", "run")
        sets = COMMAND_FRAMES.get(command)
        if sets is not None:
            frames = sets[0] if avatar is ATLAS_LARGE else sets[1]
            art = frames[(frame // 4) % len(frames)]
        else:
            # The classic periodic blink for everything else (e.g. chat).
            art = (avatar.replace("─ ⊕ ─", "· ⊕ ·")
                   if frame % 14 in (0, 1) else avatar)
        return self._mood_overlay(art, frame)

    def _mood_overlay(self, art: str, frame: int) -> str:
        """React to recent run events by swapping single-width glyphs in the
        avatar — never adding or removing cells, so the panel can't jitter.
        A fresh finding wins over a fresh error."""
        age = self._event_age("finding")
        if age is not None and age < 2.5:
            # bright: the globe glows, dust sparkles
            for face in ("─ ⊕ ─", "· ⊕ ·"):
                art = art.replace(face, "✦ ⊕ ✦")
            return art.replace("˙", "✦" if frame % 2 else "·")
        age = self._event_age("error")
        if age is not None and age < 4.0:
            # alert: a caution mark flanks the globe, alternating sides
            mark = "! ⊕ !" if frame % 2 == 0 else "─ ⊕ !"
            for face in ("─ ⊕ ─", "· ⊕ ·"):
                art = art.replace(face, mark)
        return art

    # Braille spinner + a ping-pong "scanline" that sweeps a neon pulse.
    _SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def _scanline(self, frame: int, width: int | None = None) -> str:
        """A comet that ping-pongs across a faint track: bright head, a
        gradient tail streaming behind its direction of travel. The track
        adapts to the terminal: what's left after the avatar column, the
        panel chrome, and a fixed reservation for the activity label (fixed
        so the panel width never jitters as labels change), clamped to
        [14, 40]."""
        if width is None:
            avatar = self._avatar_art()
            avatar_cols = (14 if avatar is ATLAS_LARGE
                           else 10 if avatar is ATLAS_SMALL else 0)
            width = max(14, min(self.console.width - avatar_cols - 40, 40))
        span = width * 2 - 2
        pos = frame % span
        head = pos if pos < width else span - pos
        direction = 1 if pos < width else -1
        cells = []
        for i in range(width):
            d = (head - i) * direction  # >0 → behind the head (the tail)
            if d == 0:
                cells.append("█")
            elif d == 1:
                cells.append("▓")
            elif d == 2:
                cells.append("▒")
            elif 2 < d <= 5:
                cells.append("░")
            else:
                cells.append("╌")
        return "".join(cells)

    def _status_banner(self, verb: str):
        """The avatar beside the running command and its counters — used
        for the one-shot thinking spinner (no live loop)."""
        st = self.run_state
        head = Text()
        head.append(f"atlas {st.get('command', 'run')}", style=THEME["accent"])
        if st.get("turn"):
            head.append(f"  ·  turn {st['turn']}", style=THEME["dim"])
        head.append(f"\n{verb}… ", style=THEME["tool"])
        head.append("(ctrl+c to interrupt)", style=THEME["dim"])
        body = Table.grid()
        body.add_row(head)
        body.add_row(self._stats_text())
        avatar = self._avatar_art()
        if avatar is None:
            grid = Table.grid()
            grid.add_row(Text(ATLAS_TINY, style=THEME["avatar"]))
            grid.add_row(body)
            return grid
        grid = Table.grid(padding=(0, 2))
        grid.add_column()
        grid.add_column()
        grid.add_row(Text(avatar, style=THEME["avatar"]), body)
        return grid

    def _live_inner_width(self) -> int:
        """Usable columns inside the LIVE panel (terminal width minus chrome)."""
        try:
            w = int(self.console.size.width) if self.console else 80
        except Exception:
            w = 80
        return max(48, w - 6)

    def _dashboard_alert_styles(self, frame: int) -> tuple[str, str, str]:
        """Return (border/neon colour, accent style, pulse glyph) for the
        current alert state."""
        if self._alert_level(self._clock()):
            neon = THEME["slow"]
            accent = THEME["warn"]
            pulse = ("⚠", "✳", "⚠", "·")[(frame // 3) % 4]
        else:
            neon = self._neon(frame)
            accent = f"bold {neon}"
            pulse = ("✳", "✷", "✳", "·")[(frame // 3) % 4]
        return neon, accent, pulse

    def _activity_label(self, frame: int) -> str:
        st = self.run_state
        verb = VERBS[(frame // 18) % len(VERBS)]
        return st.get("activity") or verb

    def _hud_lines(self, frame: int, *, inner_width: int = 40) -> list[str]:
        """Roomy plain-text run HUD for matrix / radar / aquarium plaques.

        `inner_width` is the text area inside the box (box width − borders /
        padding). Lines are left-aligned and padded so the plaque reads as a
        wide data panel, not a cramped caption.
        """
        st = self.run_state
        text_w = max(24, inner_width)

        def fit(s: str) -> str:
            s = s.replace("\n", " ")
            if len(s) > text_w:
                return s[: text_w - 1] + "…"
            return s.ljust(text_w)

        cmd = st.get("command", "run")
        turn = st.get("turn")
        head = f"atlas {cmd}"
        if turn:
            head += f" · turn {turn}"
        activity = self._activity_label(frame) + "…"
        if st.get("run_start") is not None:
            elapsed = self._fmt_elapsed(self._clock() - st["run_start"])
        elif st.get("elapsed") is not None:
            elapsed = self._fmt_elapsed(st["elapsed"])
        else:
            elapsed = "—"
        tools = int(st.get("tools") or 0)
        findings = int(st.get("findings") or 0)
        errors = int(st.get("errors") or 0)
        infos = int(st.get("infos") or 0)
        tokens = st.get("tokens")
        stats_a = (f"⏱ {elapsed}    ⚙ {tools} calls    "
                   f"◆ {findings} findings")
        stats_b = f"⚠ {errors} err    ℹ {infos} info"
        if tokens:
            try:
                stats_b += f"    ⌁ {int(tokens):,} tok"
            except (TypeError, ValueError):
                pass
        lines = [fit(head), fit(activity), fit(stats_a), fit(stats_b)]
        policy = st.get("ctx_policy")
        if policy:
            room = st.get("ctx_tool_tok")
            label = f"▣ ctx {policy}"
            if room is not None:
                try:
                    label += f" / {int(room)}t"
                except (TypeError, ValueError):
                    pass
            lines.append(fit(label))
        orch_top = st.get("orch_top")
        if orch_top:
            tool = st.get("orch_tool") or ""
            score = st.get("orch_score")
            bit = f"▸ next {orch_top}"
            if tool:
                bit += f" → {tool}"
            if score is not None:
                bit += f"  ({score})"
            lines.append(fit(bit))
        if self._graph:
            recent = " → ".join(self._graph[-6:])
            lines.append(fit(f"⟳ {recent}"))
        return lines

    def _render_dashboard(self, frame: int | None = None):
        """The persistent, animated LIVE dashboard. Skin selects the layout
        (atlas / matrix / radar / wave / aquarium); colours still follow
        ATLAS_THEME."""
        if frame is None:
            frame = self._frame_now()
        skin = self.live_skin
        if skin == "matrix":
            return self._render_matrix_dashboard(frame)
        if skin == "radar":
            return self._render_radar_dashboard(frame)
        if skin == "wave":
            return self._render_wave_dashboard(frame)
        if skin == "aquarium":
            return self._render_aquarium_dashboard(frame)
        return self._render_atlas_dashboard(frame)

    def _render_atlas_dashboard(self, frame: int):
        """Classic cyber panel: animated Atlas figure + neon LIVE chrome."""
        st = self.run_state
        neon, accent, pulse = self._dashboard_alert_styles(frame)
        spin = self._SPINNER[frame % len(self._SPINNER)]
        activity = self._activity_label(frame)

        head = Text()
        head.append(f"{spin} ", style=accent)
        head.append(f"atlas {st.get('command', 'run')}", style=THEME["accent"])
        if st.get("turn"):
            head.append("  ·  ", style=THEME["dim"])
            head.append(f"turn {st['turn']}", style=THEME["dim"])

        act = Text()
        act.append(self._scanline(frame), style=neon)
        act.append(f"  {activity}…", style=THEME["tool"])

        right = Table.grid(padding=(0, 0))
        right.add_row(head)
        right.add_row(self._stats_text(frame))
        right.add_row(act)
        if self._graph:
            right.add_row(self._graph_text())

        avatar = self._avatar_frame(frame)
        if avatar is None:
            body = Table.grid()
            body.add_row(Text(ATLAS_TINY, style=THEME["avatar"]))
            body.add_row(right)
        else:
            body = Table.grid(padding=(0, 2))
            body.add_column()
            body.add_column()
            body.add_row(Text(avatar, style=THEME["avatar"]), right)
        title = Text(f"◤ {NAME} LIVE {pulse} ◢", style=accent)
        return Panel(body, border_style=neon, expand=True, box=box.ROUNDED,
                     padding=(0, 2), title=title, title_align="left",
                     subtitle=Text("ctrl+c interrupts · skin atlas",
                                   style=THEME["dim"]),
                     subtitle_align="right")

    def _paint_hud_box(self, grid, styles, box_x, box_y, box_w, box_h,
                       hud, accent, *, head_style="bold bright_green",
                       body_style="bright_green"):
        """Carve a bordered HUD plaque into a char grid and paint `hud` lines."""
        height = len(grid)
        width = len(grid[0]) if grid else 0
        for y in range(box_y, box_y + box_h):
            for x in range(box_x, box_x + box_w):
                if 0 <= y < height and 0 <= x < width:
                    grid[y][x] = " "
                    styles[y][x] = None
        for x in range(box_x, box_x + box_w):
            if 0 <= box_y < height and 0 <= x < width:
                grid[box_y][x] = "─"
                styles[box_y][x] = accent
            bot = box_y + box_h - 1
            if 0 <= bot < height and 0 <= x < width:
                grid[bot][x] = "─"
                styles[bot][x] = accent
        for y in range(box_y, box_y + box_h):
            if 0 <= y < height:
                if 0 <= box_x < width:
                    grid[y][box_x] = "│"
                    styles[y][box_x] = accent
                right = box_x + box_w - 1
                if 0 <= right < width:
                    grid[y][right] = "│"
                    styles[y][right] = accent
        corners = (
            (box_y, box_x, "┌"),
            (box_y, box_x + box_w - 1, "┐"),
            (box_y + box_h - 1, box_x, "└"),
            (box_y + box_h - 1, box_x + box_w - 1, "┘"),
        )
        for y, x, ch in corners:
            if 0 <= y < height and 0 <= x < width:
                grid[y][x] = ch
                styles[y][x] = accent
        for i, line in enumerate(hud):
            y = box_y + 1 + i
            if not (0 <= y < height):
                continue
            start = box_x + 2
            style = head_style if i == 0 else (
                THEME["tool"] if i == 1 else body_style)
            for j, ch in enumerate(line[: max(0, box_w - 4)]):
                x = start + j
                if 0 <= x < width:
                    grid[y][x] = ch
                    styles[y][x] = style

    def _render_matrix_dashboard(self, frame: int):
        """Full-width digital-rain cascade with a wide centred run HUD."""
        neon, accent, pulse = self._dashboard_alert_styles(frame)
        width = self._live_inner_width()
        height = 14
        # Wide plaque: ~82% of the cascade so run stats have room to breathe.
        box_w = max(56, min(width - 4, int(width * 0.82)))
        hud = self._hud_lines(frame, inner_width=box_w - 4)
        box_h = len(hud) + 2
        box_x = (width - box_w) // 2
        box_y = max(1, (height - box_h) // 2)

        grid = [[" " for _ in range(width)] for _ in range(height)]
        styles = [[None for _ in range(width)] for _ in range(height)]
        rain = ("green", "bright_green", "bold bright_green", "bright_white")
        for col in range(width):
            head = (frame + col * 5) % (height + 8)
            trail = 4 + (col % 5)
            for t in range(trail):
                row = head - t
                if 0 <= row < height:
                    g = _MATRIX_GLYPHS[(frame + col * 13 + t * 3)
                                       % len(_MATRIX_GLYPHS)]
                    grid[row][col] = g
                    styles[row][col] = rain[
                        0 if t > 2 else (1 if t > 1 else (2 if t else 3))]

        self._paint_hud_box(grid, styles, box_x, box_y, box_w, box_h, hud,
                            accent)

        body = Text()
        for y in range(height):
            if y:
                body.append("\n")
            for x in range(width):
                body.append(grid[y][x], style=styles[y][x] or THEME["dim"])

        title = Text(f"▓ {NAME} MATRIX {pulse} ▓", style=accent)
        return Panel(body, border_style="bright_green", expand=True,
                     box=box.SQUARE, padding=(0, 1), title=title,
                     title_align="center",
                     subtitle=Text("ctrl+c interrupts · skin matrix",
                                   style=THEME["dim"]),
                     subtitle_align="right")

    def _render_radar_dashboard(self, frame: int):
        """Sonar sweep + wide run HUD in one fixed-height canvas.

        Earlier layout stacked a 15-row dish *above* the plaque (~26 lines
        total). rich Live clips from the bottom, so the run data (errors,
        info, activity…) vanished and only the spinning dish remained.
        Mirror matrix/aquarium: paint everything into a ~14-row grid so the
        plaque always stays on screen.
        """
        neon, accent, pulse = self._dashboard_alert_styles(frame)
        st = self.run_state
        width = self._live_inner_width()
        height = 14
        grid = [[" " for _ in range(width)] for _ in range(height)]
        styles = [[None for _ in range(width)] for _ in range(height)]

        # Compact dish in the upper band; leave the lower rows for the HUD.
        size = 9
        cx = cy = size // 2
        dish_x = (width - size) // 2
        dish_y = 0
        for r in (1, 2, 3, 4):
            for y in range(size):
                for x in range(size):
                    d2 = (x - cx) ** 2 + (y - cy) ** 2
                    if abs(d2 - r * r) <= max(1, r // 2 + 1):
                        gx, gy = dish_x + x, dish_y + y
                        if 0 <= gx < width and 0 <= gy < height:
                            grid[gy][gx] = "·"
                            styles[gy][gx] = THEME["dim"]
        arms = (
            [(0, -1), (0, -2), (0, -3), (0, -4)],
            [(1, -1), (2, -2), (3, -3)],
            [(1, 0), (2, 0), (3, 0), (4, 0)],
            [(1, 1), (2, 2), (3, 3)],
            [(0, 1), (0, 2), (0, 3), (0, 4)],
            [(-1, 1), (-2, 2), (-3, 3)],
            [(-1, 0), (-2, 0), (-3, 0), (-4, 0)],
            [(-1, -1), (-2, -2), (-3, -3)],
        )
        arm_i = (frame // 2) % len(arms)
        for dx, dy in arms[arm_i]:
            x, y = dish_x + cx + dx, dish_y + cy + dy
            if 0 <= x < width and 0 <= y < height:
                grid[y][x] = "/" if dx and dy else ("|" if dx == 0 else "─")
                styles[y][x] = neon
        tools = int(st.get("tools") or 0)
        findings = int(st.get("findings") or 0)
        errors = int(st.get("errors") or 0)
        blips = []
        for i in range(min(tools, 6)):
            ang = (i * 5 + frame // 3) % 8
            dx, dy = arms[ang][min(2, len(arms[ang]) - 1)]
            blips.append((dish_x + cx + dx, dish_y + cy + dy, "✦",
                          THEME["tool"]))
        for i in range(min(findings, 4)):
            ang = (i * 3 + 2) % 8
            dx, dy = arms[ang][min(1, len(arms[ang]) - 1)]
            blips.append((dish_x + cx + dx, dish_y + cy + dy, "◆",
                          THEME["tool"]))
        if errors and frame % 4 < 2:
            blips.append((dish_x + cx + 1, dish_y + cy - 1, "⚠",
                          THEME["warn"]))
        for x, y, ch, style in blips:
            if 0 <= x < width and 0 <= y < height:
                grid[y][x] = ch
                styles[y][x] = style
        # Hub last so blips never overwrite the centre.
        hx, hy = dish_x + cx, dish_y + cy
        if 0 <= hx < width and 0 <= hy < height:
            grid[hy][hx] = "●"
            styles[hy][hx] = accent

        # Wide HUD plaque under the dish — full panel width, always in-frame.
        box_w = max(56, min(width - 2, int(width * 0.92)))
        hud = self._hud_lines(frame, inner_width=box_w - 4)
        if hud:
            # Prefix sweep status onto the activity line.
            hud[1] = (f"sweep {arm_i + 1}/8  ·  "
                      + hud[1].strip()).ljust(box_w - 4)[: box_w - 4]
        box_h = len(hud) + 2
        box_x = (width - box_w) // 2
        # Sit the plaque just under the dish; clamp so it never falls off
        # the bottom of the fixed canvas (the Live-clipping bug we fixed).
        box_y = min(size, height - box_h)
        box_y = max(0, box_y)
        self._paint_hud_box(
            grid, styles, box_x, box_y, box_w, box_h, hud, accent,
            head_style=accent, body_style="bright_cyan")

        body = Text()
        for y in range(height):
            if y:
                body.append("\n")
            for x in range(width):
                body.append(grid[y][x], style=styles[y][x] or THEME["dim"])

        title = Text(f"◎ {NAME} RADAR {pulse}", style=accent)
        return Panel(body, border_style=neon, expand=True, box=box.ROUNDED,
                     padding=(0, 1), title=title, title_align="left",
                     subtitle=Text("ctrl+c interrupts · skin radar",
                                   style=THEME["dim"]),
                     subtitle_align="right")

    def _render_wave_dashboard(self, frame: int):
        """Oscilloscope skin — waveform spans the full LIVE panel width."""
        neon, accent, pulse = self._dashboard_alert_styles(frame)
        st = self.run_state
        width = self._live_inner_width()
        tools = int(st.get("tools") or 0)
        findings = int(st.get("findings") or 0)
        errors = int(st.get("errors") or 0)
        base = 2 + min(3, findings) + min(2, errors)
        blocks = " ▁▂▃▄▅▆▇█"
        wave = []
        for i in range(width):
            phase = (frame + i) * 0.45
            beat = abs(((frame * 2 + i) % 20) - 10) / 10.0
            amp = base + int(3 * (0.5 + 0.5 * math.sin(phase)))
            if beat < 0.25:
                amp = min(8, amp + 3 + min(2, tools % 5))
            wave.append(blocks[max(0, min(8, amp))])
        signal = Text("".join(wave), style=neon)

        ghost = []
        for i in range(width):
            phase = (frame + i + 7) * 0.35
            amp = 1 + int(2 * (0.5 + 0.5 * math.sin(phase)))
            ghost.append(blocks[max(0, min(8, amp))])
        ghost_line = Text("".join(ghost), style=THEME["dim"])

        head = Text()
        head.append(f"∿ SIG  atlas {st.get('command', 'run')}", style=accent)
        if st.get("turn"):
            head.append(f"  ·  turn {st['turn']}", style=THEME["dim"])

        act = Text()
        act.append(f"{self._activity_label(frame)}…", style=THEME["tool"])

        body = Table.grid(padding=(0, 0), expand=True)
        body.add_row(head)
        body.add_row(signal)
        body.add_row(ghost_line)
        body.add_row(self._stats_text(frame))
        body.add_row(act)
        if self._graph:
            body.add_row(self._graph_text())

        title = Text(f"⌁ {NAME} WAVE {pulse}", style=accent)
        return Panel(body, border_style=neon, expand=True, box=box.HEAVY,
                     padding=(0, 1), title=title, title_align="left",
                     subtitle=Text("ctrl+c interrupts · skin wave",
                                   style=THEME["dim"]),
                     subtitle_align="right")

    def _render_aquarium_dashboard(self, frame: int):
        """Underwater fish-tank skin — intentionally unlike the cyber skins.

        Seaweed sways, bubbles rise, fish cruise past a wide glass plaque
        that holds the run HUD.
        """
        neon, accent, pulse = self._dashboard_alert_styles(frame)
        width = self._live_inner_width()
        height = 14
        grid = [[" " for _ in range(width)] for _ in range(height)]
        styles = [[None for _ in range(width)] for _ in range(height)]

        # Surface shimmer + sandy floor.
        shimmer = "~≈~≈~≈" 
        for x in range(width):
            grid[0][x] = shimmer[(x + frame // 2) % len(shimmer)]
            styles[0][x] = "bold bright_cyan"
            floor = "▁▂▁▃▁▂"[x % 6]
            grid[height - 1][x] = floor
            styles[height - 1][x] = "yellow"

        # Swaying seaweed columns.
        for sx in range(3, width - 3, 11):
            sway = ((frame // 3) + sx) % 3 - 1
            for h in range(1, 5):
                y = height - 1 - h
                x = sx + (sway if h % 2 else -sway)
                if 0 <= x < width and 1 <= y < height - 1:
                    grid[y][x] = ("⎝" if sway >= 0 else "⎠") if h % 2 else "│"
                    styles[y][x] = "green"

        # Rising bubbles.
        for i in range(width // 6):
            bx = (i * 7 + 2) % width
            by = height - 2 - ((frame + i * 3) % (height - 2))
            if 1 <= by < height - 1 and grid[by][bx] == " ":
                grid[by][bx] = "o" if (frame + i) % 3 else "°"
                styles[by][bx] = "bright_white"

        # Wide glass plaque with run data first, then fauna that swims around it.
        box_w = max(56, min(width - 4, int(width * 0.82)))
        hud = self._hud_lines(frame, inner_width=box_w - 4)
        box_h = len(hud) + 2
        box_x = (width - box_w) // 2
        box_y = max(2, height - box_h - 2)
        self._paint_hud_box(
            grid, styles, box_x, box_y, box_w, box_h, hud, "bold bright_cyan",
            head_style="bold bright_cyan", body_style="cyan")

        def _blit(y: int, x: int, sprite: str, style: str) -> None:
            for j, ch in enumerate(sprite):
                xx = x + j
                if 0 <= xx < width and 1 <= y < height - 1 and grid[y][xx] == " ":
                    grid[y][xx] = ch
                    styles[y][xx] = style

        # Regular fish cruising in the open water above the plaque.
        water_h = max(2, box_y - 1)
        for i, sprite_pair in enumerate(zip(_AQUA_FISH_R, _AQUA_FISH_L)):
            period = width + 14
            pos = (frame + i * 17) % (period * 2)
            going_right = pos < period
            x = (pos if going_right else (period * 2 - 1 - pos)) - 7
            y = 1 + (i * 2 + (frame // 8 + i) % 2) % water_h
            spr = sprite_pair[0] if going_right else sprite_pair[1]
            _blit(y, x, spr,
                  "bright_magenta" if i % 2 else "bright_yellow")

        body = Text()
        for y in range(height):
            if y:
                body.append("\n")
            for x in range(width):
                body.append(grid[y][x], style=styles[y][x] or "blue")

        title = Text(f"≋ {NAME} AQUARIUM {pulse}", style=accent)
        return Panel(body, border_style="bright_blue", expand=True,
                     box=box.DOUBLE, padding=(0, 1), title=title,
                     title_align="center",
                     subtitle=Text("ctrl+c interrupts · skin aquarium",
                                   style=THEME["dim"]),
                     subtitle_align="right")

    def live_session(self):
        """Persistent animated dashboard for the whole command. Tool lines and
        assistant text print above it (rich Live prints scroll above the live
        region). No-op in plain/quiet mode. Use as a context manager."""
        if self.plain or self.quiet:
            return _NullStatus()
        self._anim_t0 = self._clock()
        self._live = _LiveHandle(self, Live(
            _Dashboard(self), console=self.console, refresh_per_second=10,
            transient=True))
        return self._live

    def thinking(self):
        """Spinner while an LLM call is in flight. No-op in plain mode, and
        also when the persistent live dashboard is active (a single console
        can host only one live display — the dashboard already shows activity;
        we just update the activity label)."""
        if self.plain or self._live is not None:
            self.set_run_state(activity="consulting model")
            return _NullStatus()
        verb = random.choice(VERBS)
        self._status = self.console.status(self._status_banner(verb),
                                           spinner="dots")
        return self._status

    # ── agent activity ───────────────────────────────────────────────────

    def turn(self, n: int) -> None:
        if self.quiet:
            return
        if self.plain:
            print(f"\n── turn {n} ────────────────────────────────")
        # rich mode: turns flow naturally, no separator needed

    def assistant(self, text: str) -> None:
        if self.quiet or not text:
            return
        if self.plain:
            print(f"\n{text}")
            return
        self.console.print()
        self.console.print(Markdown(text))

    @staticmethod
    def _tool_color(name: str) -> str:
        """A stable colour per tool namespace (the prefix before the first
        underscore), so e.g. all vol_* calls share one hue in the transcript."""
        palette = THEME["tool_palette"]
        prefix = name.split("_", 1)[0]
        return palette[sum(prefix.encode()) % len(palette)]

    def tool_call(self, name: str, args_preview: str) -> None:
        if self.quiet:
            return
        if self.plain:
            print(f"  → {name}({args_preview})")
            return
        line = Text()
        line.append("⏺ ", style=f"bold {self._tool_color(name)}")
        line.append(name, style="bold")
        line.append(f"({args_preview})", style="dim")
        self.console.print(line, no_wrap=True, overflow="ellipsis")

    def tool_result(self, preview: str, seconds: float,
                    is_error: bool = False, is_info: bool = False) -> None:
        if is_error:
            self.pulse_event("error")
        elif is_info:
            self.pulse_event("info")
        if self.quiet:
            return
        preview = (preview or "").splitlines()[0] if preview else ""
        if self.plain:
            print(f"    {seconds:6.1f}s  {preview[:160]}")
            return
        line = Text()
        line.append("  ⎿  ", style="dim")
        if is_error:
            line.append("✗ ", style=THEME["error"])
        elif is_info:
            line.append("ℹ ", style=THEME.get("info", THEME["dim"]))
        style = (THEME["error"] if is_error
                 else THEME.get("info", THEME["dim"]) if is_info
                 else THEME["dim"])
        line.append(preview[:200], style=style)
        # slow calls get a visible duration so hotspots stand out in the scroll
        duration_style = (THEME["dim"] if seconds < 10
                          else THEME["slow"] if seconds < 60
                          else THEME["error"])
        line.append(f"  ({seconds:.1f}s)", style=duration_style)
        self.console.print(line, no_wrap=True, overflow="ellipsis")

    # ── messages ─────────────────────────────────────────────────────────

    def info(self, text: str) -> None:
        if self.quiet:
            return
        if self.plain:
            print(text, file=sys.stderr)
        else:
            self.console.print(f"[dim]{text}[/dim]")

    def warn(self, text: str) -> None:
        if self.plain:
            print(f"[!] {text}", file=sys.stderr)
        else:
            self.console.print(f"[{THEME['warn']}]⚠ {text}[/]")

    def error(self, text: str) -> None:
        if self.plain:
            print(f"[ERROR] {text}", file=sys.stderr)
        else:
            self.console.print(f"[{THEME['error']}]✗ {text}[/]")

    def tokens(self, input_tokens: int, output_tokens: int) -> None:
        if self.quiet:
            return
        msg = f"tokens: {input_tokens:,} in / {output_tokens:,} out"
        if self.plain:
            print(f"[{msg}]")
        else:
            self.console.print(f"[dim]{msg}[/dim]")

    def markdown(self, text: str) -> None:
        """Render Markdown (raw text in plain mode)."""
        if self.quiet or not text:
            return
        if self.plain:
            print(text)
        else:
            self.console.print(Markdown(text))

    def finish(self, summary: str, stats: dict | None = None) -> None:
        if self.quiet or not summary:
            return
        status = (stats or {}).get("finish_status") or "incomplete_coverage"
        if status in ("incomplete_coverage", "exited_degraded_incomplete"):
            banner = "investigation exited (incomplete coverage)"
            plain_banner = "INVESTIGATION EXITED (INCOMPLETE COVERAGE)"
        elif status not in ("complete", "finished"):
            banner = f"investigation stopped ({status})"
            plain_banner = f"INVESTIGATION STOPPED ({status})"
        else:
            banner = "investigation complete"
            plain_banner = "INVESTIGATION COMPLETE"
        if self.plain:
            print(f"\n=== {plain_banner} ===\n{summary}")
            if stats:
                for key, value in self._stat_rows(stats):
                    print(f"  {key}: {value}")
            return
        self.console.print()
        parts: list = [Markdown(summary)]
        if stats:
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style=THEME["dim"], justify="right")
            grid.add_column()
            for key, value in self._stat_rows(stats):
                grid.add_row(key, str(value))
            parts += [Rule(style=THEME["dim"]), grid]
        self.console.print(Panel(
            Group(*parts), box=box.ROUNDED, padding=(1, 2),
            title=Text(f"✳ {banner}",
                       style=f"bold {THEME['finish_border']}"),
            title_align="left", border_style=THEME["finish_border"],
            subtitle=Text(f"{ATLAS_TINY}  investigation complete",
                          style=THEME["dim"]),
            subtitle_align="right"))

    @staticmethod
    def _stat_rows(stats: dict) -> list[tuple[str, str]]:
        rows = []
        if stats.get("finish_status"):
            rows.append(("finish status", str(stats["finish_status"])))
        if stats.get("duration_seconds") is not None:
            minutes, seconds = divmod(int(stats["duration_seconds"]), 60)
            rows.append(("duration", f"{minutes}m {seconds:02d}s"))
        if stats.get("turns"):
            rows.append(("turns", str(stats["turns"])))
        calls = stats.get("tool_calls") or []
        if calls:
            counts: dict[str, int] = {}
            for tc in calls:
                counts[tc["name"]] = counts.get(tc["name"], 0) + 1
            top = sorted(counts.items(), key=lambda kv: -kv[1])[:5]
            rows.append(("tool calls",
                         f"{len(calls)} — top: "
                         + ", ".join(f"{n} ×{c}" for n, c in top)))
            errors = sum(1 for tc in calls if tc.get("error"))
            if errors:
                rows.append(("tool errors", str(errors)))
            infos = sum(1 for tc in calls if tc.get("info"))
            if infos:
                rows.append(("protocol info", str(infos)))
        findings = stats.get("findings_recorded")
        if findings:
            rows.append(("findings recorded", str(findings)))
        return rows

    # ── REPL input ───────────────────────────────────────────────────────

    def make_prompt(self):
        """Returns a callable that reads one line of user input.
        Raises EOFError on ctrl+d and KeyboardInterrupt on ctrl+c,
        exactly like input()."""
        if self.plain or not HAS_PTK:
            return lambda: input("\n❯ ")
        from prompt_toolkit.formatted_text import ANSI
        session = PromptSession(
            history=FileHistory(str(Path.home() / ".atlas_history")),
            completer=WordCompleter(list(SLASH_COMMANDS), sentence=True),
            complete_while_typing=True,
        )
        return lambda: session.prompt(ANSI("\n\x1b[1;96m❯\x1b[0m "))

    def ask_analyst(self, question: str, context: str = "",
                    options: list | None = None) -> str:
        """Prompt the human analyst for guidance mid-investigation and return
        their reply (empty string if they decline / no TTY). Pauses the live
        dashboard while reading input so the prompt isn't clobbered by the
        animated panel."""
        if not sys.stdin.isatty():
            return ""
        live = self._live.live if self._live is not None else None
        if live is not None:
            try:
                live.stop()
            except Exception:  # noqa: BLE001 — never let a UI hiccup abort a run
                live = None
        try:
            if self.plain:
                print(f"\n[Atlas] {question}", file=sys.stderr)
                if context:
                    print(f"  context: {context}", file=sys.stderr)
                if options:
                    print("  options: " + " | ".join(str(o) for o in options),
                          file=sys.stderr)
                try:
                    return input("  your guidance ❯ ").strip()
                except (EOFError, KeyboardInterrupt):
                    return ""
            body = Text()
            body.append(question + "\n", style="bold")
            if context:
                body.append(f"\n{context}\n", style="dim")
            if options:
                body.append("\noptions: ", style="dim")
                body.append(" · ".join(str(o) for o in options),
                            style=THEME["tool"])
            self.console.print(Panel(
                body, border_style=THEME["warn"], expand=False,
                box=box.ROUNDED, padding=(0, 2),
                title=Text("Atlas needs your guidance",
                           style=THEME["warn"]),
                title_align="left"))
            try:
                return self.console.input(
                    f"[{THEME['warn']}]  your guidance ❯ [/] ").strip()
            except (EOFError, KeyboardInterrupt):
                return ""
        finally:
            if live is not None:
                try:
                    live.start()
                except Exception:  # noqa: BLE001
                    pass

    def help(self) -> None:
        if self.plain:
            rows = "\n".join(f"  {cmd:<12} {desc}"
                             for cmd, desc in SLASH_COMMANDS.items())
            print(f"{NAME} interactive session — ask anything about the case; "
                  f"the agent runs forensic tools as needed.\n\n{rows}\n\n"
                  "  ctrl+c interrupts a running turn, ctrl+d exits.")
            return
        grid = Table.grid(padding=(0, 3))
        grid.add_column(style=THEME["accent"])
        grid.add_column()
        for cmd, desc in SLASH_COMMANDS.items():
            grid.add_row(cmd, desc)
        intro = Text(
            "Ask anything about the case; the agent runs forensic tools "
            "as needed.\n", style=THEME["dim"])
        outro = Text("\nctrl+c interrupts a running turn · ctrl+d exits",
                     style=THEME["dim"])
        self.console.print(Panel(
            Group(intro, grid, outro), box=box.ROUNDED, expand=False,
            padding=(0, 2), border_style=THEME["border"],
            title=Text(f"{NAME} — interactive session",
                       style=THEME["accent"]),
            title_align="left"))


class _Dashboard:
    """A live renderable: rich calls __rich__ on every Live refresh from its
    own refresh thread. Rendering is read-only — the frame comes from the
    wall clock, so extra refreshes never speed the animation up."""

    def __init__(self, ui: "UI"):
        self.ui = ui

    def __rich__(self):
        return self.ui._render_dashboard()


class _LiveHandle:
    """Context manager wrapping a rich Live; clears the UI's `_live` pointer on
    exit so `thinking()` returns to its standalone spinner afterwards."""

    def __init__(self, ui: "UI", live):
        self.ui = ui
        self.live = live

    def __enter__(self):
        self.live.__enter__()
        return self

    def __exit__(self, *exc):
        try:
            self.live.__exit__(*exc)
        finally:
            self.ui._live = None
        return False


class _NullStatus:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
