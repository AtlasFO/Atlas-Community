"""Tests for the agent TUI — the Atlas banner across terminal widths."""
import pytest

rich = pytest.importorskip("rich")
from rich.console import Console  # noqa: E402
from agent.tui import UI  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_live_skin(monkeypatch, tmp_path):
    """Don't let the developer's ~/.atlas/ui.json or ATLAS_LIVE_SKIN leak into
    avatar/dashboard tests — default skin must stay `atlas` unless a test
    asks for another."""
    import agent.tui as tui
    monkeypatch.delenv("ATLAS_LIVE_SKIN", raising=False)
    monkeypatch.setattr(tui, "ui_prefs_path", lambda: tmp_path / "ui.json")


def _render(width: int) -> str:
    c = Console(record=True, width=width, force_terminal=True)
    ui = UI(console=c)
    ui.banner("model-x", "https://hub", None, tools=298, namespaces=26,
              loaded=6)
    return c.export_text()


def test_large_banner_has_avatar():
    out = _render(100)
    assert "\u2295" in out          # the globe
    assert "\u25e0─────\u25e0" in out    # the large variant's top arch
    assert "Atlas" in out


def test_small_banner_has_avatar():
    out = _render(66)
    assert "\u2295" in out
    assert "\u25e0───\u25e0" in out


def test_narrow_banner_uses_inline_tiny_avatar():
    out = _render(50)
    assert "( ─ \u2295 ─ )" in out
    assert "\u25e0─────\u25e0" not in out  # no multi-line art when narrow


def test_quiet_banner_is_plain_no_avatar(capsys):
    ui = UI(quiet=True)
    ui.banner("model-x", "https://hub", None, 298, 26, 6)
    assert ui.banner("model-x", "https://hub", None, 298, 26, 6) is None
    out = capsys.readouterr().out
    assert "\u2295" not in out


def test_neon_is_the_default_theme():
    from agent.tui import THEME, THEMES
    import os
    if "ATLAS_THEME" not in os.environ:
        assert THEME is THEMES["neon"]
    assert "bright_cyan" in THEMES["neon"]["accent"]


def test_status_banner_shows_avatar_and_live_stats():
    c = Console(record=True, width=100, force_terminal=True)
    ui = UI(console=c)
    ui.set_run_state(command="train", turn=7, elapsed=125.0, tools=42,
                     errors=2, infos=3, findings=5, tokens=123456)
    c.print(ui._status_banner("Sniffing packets"))
    out = c.export_text()
    assert "\u2295" in out
    assert "atlas train" in out
    assert "turn 7" in out
    assert "2m05s" in out
    assert "42 calls" in out
    assert "2 err" in out
    assert "3 info" in out
    assert "5 findings" in out
    assert "123,456 tok" in out


def test_status_banner_with_empty_state_renders():
    c = Console(record=True, width=100, force_terminal=True)
    ui = UI(console=c)
    c.print(ui._status_banner("Triaging"))
    out = c.export_text()
    assert "atlas run" in out  # default command label
    assert "0 findings" in out


def test_thinking_uses_status_banner_on_tty():
    c = Console(record=True, width=100, force_terminal=True)
    ui = UI(console=c)
    ui.set_run_state(command="run", turn=3, tools=1, findings=0)
    status = ui.thinking()
    with status:
        pass
    assert "turn 3" in c.export_text()


def test_dashboard_renders_avatar_stats_and_animation():
    c = Console(record=True, width=100, force_terminal=True)
    ui = UI(console=c)
    ui.set_run_state(command="train", turn=4, elapsed=65.0, tools=12,
                     errors=1, findings=2, tokens=9000, activity="vol_pslist")
    c.print(ui._render_dashboard())
    out = c.export_text()
    assert "\u2295" in out                 # Atlas avatar
    assert "LIVE" in out              # live badge
    assert "atlas train" in out
    assert "12 calls" in out
    assert "vol_pslist" in out


def _fake_clock_ui(width=100):
    """A UI wired to a settable fake clock; returns (ui, time_cell, console)."""
    c = Console(record=True, width=width, force_terminal=True)
    ui = UI(console=c)
    t = [0.0]
    ui._clock = lambda: t[0]
    return ui, t, c


def test_frames_derive_from_wall_clock():
    ui, t, _ = _fake_clock_ui()
    assert ui._frame_now() == 0          # no live session yet
    ui._anim_t0 = 0.0
    assert ui._frame_now() == 0
    t[0] = 0.55
    assert ui._frame_now() == 5          # 0.1s per frame


def test_dashboard_animation_advances_frames():
    ui, t, _ = _fake_clock_ui()
    ui._anim_t0 = 0.0
    ui.set_run_state(command="run")
    outs = []
    for now in (0.0, 0.55):
        t[0] = now
        c = Console(record=True, width=100, force_terminal=True)
        ui.console = c
        c.print(ui._render_dashboard())
        outs.append(c.export_text())
    assert outs[0] != outs[1]            # time moves the animation


def test_extra_refreshes_do_not_advance_animation():
    # The original bug: prints scrolling above the live region trigger extra
    # refreshes, which used to speed the animation up. With a frozen clock,
    # any number of refreshes must render the identical frame.
    from agent.tui import _Dashboard
    ui, t, _ = _fake_clock_ui()
    ui._anim_t0 = 0.0
    ui.set_run_state(command="run")
    dash = _Dashboard(ui)
    outs = []
    for _ in range(5):
        c = Console(record=True, width=100, force_terminal=True)
        ui.console = c
        c.print(dash.__rich__())
        outs.append(c.export_text())
    assert len(set(outs)) == 1


def test_live_session_sets_animation_clock():
    ui, t, _ = _fake_clock_ui()
    t[0] = 42.0
    ui.live_session()                    # not entered — just constructed
    assert ui._anim_t0 == 42.0
    ui._live = None


def test_scanline_and_neon_cycle_are_stable():
    ui = UI(console=Console(record=True, width=100, force_terminal=True))
    # scanline stays within the track width and ping-pongs (no index error)
    for f in range(0, 100):
        line = ui._scanline(f, width=20)
        assert len(line) == 20 and "\u2588" in line
    # neon cycles through the three-colour palette
    seen = {ui._neon(f) for f in range(0, 30)}
    assert seen == {"bright_cyan", "bright_magenta", "bright_green"}


def test_live_session_noop_when_quiet():
    ui = UI(quiet=True)
    with ui.live_session():
        pass
    assert ui._live is None


def test_thinking_is_noop_while_live_active():
    # a single console can host only one live display — thinking must yield
    ui = UI(console=Console(record=True, width=100, force_terminal=True))
    ui._live = object()  # pretend the dashboard is active
    status = ui.thinking()
    from agent.tui import _NullStatus
    assert isinstance(status, _NullStatus)
    assert ui.run_state.get("activity") == "consulting model"


# ── Command-keyed avatar animations ──────────────────────────────────────────

def _dash_frames(command, width=100, n=8):
    """Render n successive dashboard frames' text for a command."""
    outs = []
    for i in range(n):
        c = Console(record=True, width=width, force_terminal=True)
        ui = UI(console=c)
        ui.set_run_state(command=command, turn=1, tools=1, findings=0)
        c.print(ui._render_dashboard(frame=i))
        outs.append(c.export_text())
    return outs


def test_run_shows_walk_cycle_and_animates_legs():
    frames = _dash_frames("run", n=8)
    joined = "\n".join(frames)
    assert "\u2295" in joined                       # still Atlas
    assert "\u25e0─────\u25e0" in joined                  # the atlas body (large)
    # The leg line changes across the cycle → the legs actually move.
    leg_lines = {next(l for l in f.splitlines() if "┴" in l) for f in frames}
    assert len(leg_lines) >= 2


def test_chat_command_keeps_classic_blink_not_walk():
    frames = _dash_frames("chat", n=16)
    joined = "\n".join(frames)
    # No walk dust / no command-specific overlay — the classic standing
    # figure with a blink.
    assert "˙˙" not in joined
    assert "· \u2295 ·" in joined                    # blink frame appears


def test_narrow_terminal_falls_back_to_tiny_avatar_even_when_running():
    frames = _dash_frames("review", width=50, n=4)
    joined = "\n".join(frames)
    assert "( ─ \u2295 ─ )" in joined
    assert "(\u25cb)" not in joined and "(\u25c9)" not in joined  # no multi-line lens when narrow


def test_review_shows_lens_scan():
    frames = _dash_frames("review", n=8)
    joined = "\n".join(frames)
    assert "\u2295" in joined                        # still Atlas
    assert "(\u25cb)" in joined or "(\u25c9)" in joined   # the lens sweeping the report
    # The highlight sweeps across the report line → the scan actually moves.
    scan_lines = {next(l for l in f.splitlines() if "\u2261" in l) for f in frames}
    assert len(scan_lines) >= 2


@pytest.mark.parametrize("name", ["ATLAS_WALK_LARGE", "ATLAS_WALK_SMALL",
                                  "REVIEW_LARGE", "REVIEW_SMALL",])
def test_command_frames_are_jitter_free(name):
    # Constant line count and near-constant width across a frame set — the
    # structural property that keeps the live panel from jittering.
    import agent.tui as tui
    frames = getattr(tui, name)
    line_counts = {len(f.splitlines()) for f in frames}
    assert len(line_counts) == 1
    widths = {max(len(line) for line in f.splitlines()) for f in frames}
    assert max(widths) - min(widths) <= 1


# ── Reactive moods, alerts, and sparkles ─────────────────────────────────────

def test_finding_event_makes_avatar_bright():
    ui, t, _ = _fake_clock_ui()
    ui.set_run_state(command="run")
    ui.pulse_event("finding")
    assert "\u2726 \u2295 \u2726" in ui._avatar_frame(0)


def test_error_event_makes_avatar_alert():
    ui, t, _ = _fake_clock_ui()
    ui.set_run_state(command="chat")
    ui.pulse_event("error")
    assert "! \u2295 !" in ui._avatar_frame(0)


def test_mood_overlay_expires():
    ui, t, _ = _fake_clock_ui()
    ui.set_run_state(command="run")
    ui.pulse_event("finding")
    t[0] = 3.0
    assert "\u2726 \u2295 \u2726" not in ui._avatar_frame(0)


def test_finding_mood_beats_worried():
    ui, t, _ = _fake_clock_ui()
    ui.set_run_state(command="run")
    ui.pulse_event("error")
    ui.pulse_event("finding")
    frame = ui._avatar_frame(0)
    assert "\u2726 \u2295 \u2726" in frame and "!" not in frame


def test_mood_overlay_keeps_line_count():
    ui, t, _ = _fake_clock_ui()
    ui.set_run_state(command="run")
    base = ui._avatar_frame(0)
    ui.pulse_event("finding")
    happy = ui._avatar_frame(0)
    assert len(happy.splitlines()) == len(base.splitlines())


def test_tool_result_error_pulses_event():
    ui, t, c = _fake_clock_ui()
    ui.tool_result("TOOL ERROR: boom", 1.0, is_error=True)
    assert ui._event_age("error") == 0.0


def test_alert_level_warns_on_long_tool():
    ui, t, _ = _fake_clock_ui()
    ui.set_run_state(tool_started=0.0)
    assert ui._alert_level(61.0) == "warn"
    assert ui._alert_level(30.0) is None
    ui.set_run_state(tool_started=None)
    assert ui._alert_level(61.0) is None


def test_alert_level_warns_after_recent_error_then_clears():
    ui, t, _ = _fake_clock_ui()
    ui.pulse_event("error")                     # at t=0
    assert ui._alert_level(10.0) == "warn"
    assert ui._alert_level(31.0) is None


def test_dashboard_uses_warn_style_on_alert():
    ui, t, c = _fake_clock_ui()
    ui.set_run_state(command="run", tool_started=0.0)
    t[0] = 61.0
    c.print(ui._render_dashboard(frame=0))
    assert "\u26a0" in c.export_text()               # warning pulse in the title


def test_finding_sparkle_appears_and_expires():
    ui, t, _ = _fake_clock_ui()
    ui.set_run_state(findings=3)
    ui.pulse_event("finding")
    sparkling = ui._stats_text().plain
    assert "\u2726" in sparkling
    t[0] = 3.0
    calm = ui._stats_text().plain
    assert "\u2726" not in calm
    assert len(sparkling) == len(calm)          # reserved cells → no jitter


def test_stats_elapsed_ticks_from_run_start():
    ui, t, _ = _fake_clock_ui()
    ui.set_run_state(run_start=35.0, tools=1)
    t[0] = 100.0
    assert "1m05s" in ui._stats_text().plain
    t[0] = 130.0                                # no set_run_state in between
    assert "1m35s" in ui._stats_text().plain


def test_scanline_adapts_to_console_width():
    narrow = UI(console=Console(record=True, width=80, force_terminal=True))
    wide = UI(console=Console(record=True, width=160, force_terminal=True))
    n_line = narrow._scanline(0)
    w_line = wide._scanline(0)
    assert len(w_line) > len(n_line)
    assert 14 <= len(n_line) <= 40 and 14 <= len(w_line) <= 40


# ── ask_analyst (the surviving, panel-styled variant) ────────────────────────

def test_ask_analyst_returns_empty_without_tty(monkeypatch):
    import sys
    from types import SimpleNamespace
    ui, _, _ = _fake_clock_ui()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    assert ui.ask_analyst("Continue?") == ""


def test_ask_analyst_renders_guidance_panel(monkeypatch):
    import sys
    from types import SimpleNamespace
    ui, _, c = _fake_clock_ui()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(c, "input", lambda *a, **k: "  dig deeper  ")
    answer = ui.ask_analyst("Which host first?", context="two candidates",
                            options=["web01", "db02"])
    assert answer == "dig deeper"
    out = c.export_text()
    assert "Atlas needs your guidance" in out
    assert "Which host first?" in out
    assert "web01" in out and "db02" in out


# ── LIVE skins (matrix / radar / wave) ───────────────────────────────────────

def test_resolve_live_skin_priority(monkeypatch, tmp_path):
    import agent.tui as tui
    monkeypatch.delenv("ATLAS_LIVE_SKIN", raising=False)
    monkeypatch.setattr(tui, "ui_prefs_path", lambda: tmp_path / "ui.json")
    assert tui.resolve_live_skin() == "atlas"
    (tmp_path / "ui.json").write_text('{"live_skin": "radar"}\n')
    assert tui.resolve_live_skin() == "radar"
    monkeypatch.setenv("ATLAS_LIVE_SKIN", "wave")
    assert tui.resolve_live_skin() == "wave"
    assert tui.resolve_live_skin("matrix") == "matrix"
    # Unknown CLI value is ignored; env still wins.
    assert tui.resolve_live_skin("nope") == "wave"


def test_matrix_skin_shows_rain_and_centred_hud():
    c = Console(record=True, width=100, force_terminal=True)
    ui = UI(console=c, skin="matrix")
    ui.set_run_state(command="run", turn=4, tools=9, findings=2,
                     run_start=0.0, activity="Haunting the registry")
    t = [100.0]
    ui._clock = lambda: t[0]
    c.print(ui._render_dashboard(frame=5))
    out = c.export_text()
    assert "MATRIX" in out
    assert "atlas run" in out
    assert "turn 4" in out
    assert "│" in out and "┌" in out
    assert "calls" in out and "findings" in out  # roomy HUD, not tiny caption
    # Full-width cascade: rain spans far beyond the old 58-col layout.
    lines = [ln for ln in out.splitlines() if any(ch in ln for ch in "ｱｲｳｴｵ")]
    assert lines
    assert max(len(ln) for ln in lines) >= 70
    assert any(ch in out for ch in "ｱｲｳｴｵｶｷｸｹｺ")


def test_radar_skin_sweeps_and_shows_blips():
    outs = []
    for i in range(8):
        c = Console(record=True, width=100, force_terminal=True)
        ui = UI(console=c, skin="radar")
        ui.set_run_state(command="run", tools=5, findings=2, errors=1,
                         infos=3, turn=1, run_start=0.0,
                         activity="Haunting the registry")
        ui._clock = lambda: 90.0
        c.print(ui._render_dashboard(frame=i * 2))
        outs.append(c.export_text())
    joined = "\n".join(outs)
    assert "RADAR" in joined
    assert "\u25cf" in joined
    assert "sweep" in joined
    assert "calls" in joined and "findings" in joined
    # Run data must stay visible — the old stacked layout was ~26 lines and
    # rich Live clipped the plaque (errors/info/activity) off the bottom.
    assert "atlas run" in joined
    assert "err" in joined and "info" in joined
    assert "Haunting the registry" in joined
    # Fixed-height canvas (~matrix/aquarium): must fit a typical Live viewport.
    assert max(len(o.splitlines()) for o in outs) <= 18
    # Wide plaque under the dish.
    assert "┌" in joined and joined.count("─") > 40
    assert len({o for o in outs}) >= 2


def test_wave_skin_shows_oscilloscope_trace():
    c = Console(record=True, width=100, force_terminal=True)
    ui = UI(console=c, skin="wave")
    ui.set_run_state(command="run", tools=3, findings=1, turn=2)
    c.print(ui._render_dashboard(frame=10))
    out = c.export_text()
    assert "WAVE" in out
    assert any(ch in out for ch in "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588")
    assert "atlas run" in out
    # Waveform fills the LIVE panel (~ console width − chrome).
    wave_lines = [ln for ln in out.splitlines()
                  if sum(1 for ch in ln if ch in "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588") > 20]
    assert wave_lines
    assert max(len(ln.strip()) for ln in wave_lines) >= 80


def test_aquarium_skin_is_underwater_not_cyber():
    c = Console(record=True, width=100, force_terminal=True)
    ui = UI(console=c, skin="aquarium")
    ui.set_run_state(command="run", turn=2, tools=4, findings=1,
                     run_start=0.0, activity="Fetching artifacts")
    ui._clock = lambda: 50.0
    frames = []
    for i in (0, 5, 12, 20):
        c = Console(record=True, width=100, force_terminal=True)
        ui.console = c
        c.print(ui._render_dashboard(frame=i))
        frames.append(c.export_text())
    joined = "\n".join(frames)
    assert "AQUARIUM" in joined
    assert any(ch in joined for ch in "~≈")        # surface
    assert any(ch in joined for ch in "o°")        # bubbles
    assert "atlas run" in joined and "calls" in joined
    # Fish actually move across frames.
    assert len(set(frames)) >= 2


def test_default_skin_still_shows_avatar():
    c = Console(record=True, width=100, force_terminal=True)
    ui = UI(console=c, skin="atlas")
    ui.set_run_state(command="run", turn=1)
    c.print(ui._render_dashboard(frame=0))
    assert "\u2295" in c.export_text()
