"""Every CLI command answers --help, the read-only ones run on a scratch
case, the trace verifier tells a good chain from a tampered one, and the
helper scripts start from the repository's own venv. Enumerated from the
parser's own help so a new command is covered the day it is added."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from agent import cli
from tests._edition import DEVTOOLS_SHIPPED, NO_DEVTOOLS

_ROOT = Path(__file__).resolve().parents[2]

# install.sh runs this module after every install (pytest -m install_smoke).
pytestmark = pytest.mark.install_smoke


def _run(capsys, argv) -> tuple[int, str]:
    """main() in-process; argparse and sys.exit both surface as SystemExit."""
    with patch.object(cli, "_bootstrap_env", lambda *a, **k: None):
        try:
            cli.main(argv)
            code = 0
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
            # sys.exit("message") prints through the interpreter's exit
            # handler, which capsys never sees — take it from the exception.
            exit_text = exc.code if isinstance(exc.code, str) else ""
        else:
            exit_text = ""
    out = capsys.readouterr()
    return code, out.out + out.err + exit_text


def _subcommands(capsys, prefix: list[str]) -> list[str]:
    _, text = _run(capsys, prefix + ["--help"])
    m = re.search(r"\{([a-z0-9,-]+)\}", text)
    return m.group(1).split(",") if m else []


@pytest.fixture(scope="module")
def commands():
    """Top-level commands and their sub-commands, from the parser itself."""
    class _Cap:
        def readouterr(self):
            import io
            return type("R", (), {"out": self._o.getvalue(), "err": self._e.getvalue()})()
    # capsys is function-scoped; enumerate with a private capture instead
    import contextlib, io
    def run(argv):
        o, e = io.StringIO(), io.StringIO()
        with patch.object(cli, "_bootstrap_env", lambda *a, **k: None), \
             contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            try:
                cli.main(argv)
            except SystemExit:
                pass
        return o.getvalue() + e.getvalue()
    def subs(prefix):
        m = re.search(r"\{([a-z0-9,-]+)\}", run(prefix + ["--help"]))
        return m.group(1).split(",") if m else []
    top = subs([])
    assert len(top) >= 20, top
    return {c: subs([c]) for c in top}


class TestEveryCommandAnswersHelp:
    def test_top_level(self, commands, capsys):
        failed = [c for c in commands if _run(capsys, [c, "--help"])[0] != 0]
        assert not failed, failed

    def test_sub_commands(self, commands, capsys):
        failed = [f"{c} {s}" for c, subs in commands.items() for s in subs
                  if _run(capsys, [c, s, "--help"])[0] != 0]
        assert not failed, failed


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "SMOKE"
    (d / ".atlas").mkdir(parents=True)
    (d / "evidence").mkdir()
    (d / "CASE.md").write_text(
        "# Case: SMOKE\n\n**Case ID:** SMOKE\n\n## Investigation Requests\n- What happened?\n",
        encoding="utf-8")
    return d


class TestReadOnlyCommandsRun:
    @pytest.mark.parametrize("argv", [
        ["guide", "overview"], ["guide", "setup"], ["skin"], ["addon", "list"],
        ["provider", "list"], ["doctor"],
        ["brain", "search", "no-such-term-anywhere"],   # no matches is not a failure
    ])
    def test_without_a_case(self, capsys, argv, monkeypatch):
        monkeypatch.setenv("ATLAS_PROVIDERS", "")
        code, text = _run(capsys, argv)
        assert code == 0, text[-400:]

    @pytest.mark.parametrize("argv", [
        ["status"], ["status", "--json"], ["explain", "--section", "exec_summary"],
        ["timeline"], ["journal", "{case}", "list"],
    ])
    def test_on_a_case(self, capsys, case, argv):
        # `journal` takes --case before its sub-command; the others after.
        argv = [a for a in argv]
        if "{case}" in argv:
            argv[argv.index("{case}"):argv.index("{case}") + 1] = ["--case", str(case)]
        else:
            argv += ["--case", str(case)]
        code, text = _run(capsys, argv)
        assert code == 0, text[-400:]

    def test_guide_setup_describes_todays_setup(self, capsys):
        _, text = _run(capsys, ["guide", "setup"])
        assert "provider setup" in text and "five model roles" in text
        assert "Claude/Opus" not in text


class TestVerifyTrace:
    def _mirror(self, case, entries, tamper=False):
        from core.execution_log import _canonical_entry_json, _chain_hash
        (case / "analysis").mkdir(exist_ok=True)
        prev, lines = "", []
        for seq, entry in enumerate(entries, 1):
            h = _chain_hash(prev, _canonical_entry_json(entry))
            lines.append({"seq": seq, "prev_hash": prev, "entry_hash": h, "entry": entry})
            prev = h
        if tamper:
            lines[-1]["entry"]["type"] += " TAMPERED"
        (case / "analysis" / "SMOKE_trace.jsonl").write_text(
            "\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")

    def test_a_good_chain_verifies(self, capsys, case):
        self._mirror(case, [{"call_id": 1, "type": "system_error", "ts": "t"},
                            {"call_id": 2, "type": "narration", "ts": "t"}])
        code, text = _run(capsys, ["verify-trace", "--case", str(case)])
        assert code == 0 and "chain OK" in text

    def test_a_tampered_entry_breaks_it(self, capsys, case):
        self._mirror(case, [{"call_id": 1, "type": "system_error", "ts": "t"},
                            {"call_id": 2, "type": "narration", "ts": "t"}], tamper=True)
        code, text = _run(capsys, ["verify-trace", "--case", str(case)])
        assert code != 0 and "CHAIN BROKEN" in text


class TestHelperScripts:
    """The launchers are bash; they are tested as the operator runs them."""

    def test_dashboard_launcher_prefers_the_repository_venv(self, tmp_path):
        """A home without ~/.venv must not make the dashboard fall back to a
        system python that lacks the dependencies."""
        env = {k: v for k, v in os.environ.items() if k != "VENV_PY"}
        env["HOME"] = str(tmp_path)
        r = subprocess.run([str(_ROOT / "bin" / "atlas-dashboard"), "--help"],
                           cwd=_ROOT, env=env, capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, (r.stdout + r.stderr)[-600:]
        assert "usage: atlas-dashboard" in r.stdout + r.stderr

    @pytest.mark.skipif(not DEVTOOLS_SHIPPED, reason=NO_DEVTOOLS)
    def test_atlas_dev_is_a_command(self):
        path = _ROOT / "bin" / "atlas-dev"
        assert os.access(path, os.X_OK), "bin/atlas-dev must be executable — its docs say run it"
        r = subprocess.run([str(path), "--help"], cwd=_ROOT, capture_output=True,
                           text=True, timeout=120)
        assert r.returncode == 0 and "usage: atlas-dev" in r.stdout + r.stderr

    def test_atlas_launcher_help_exits_zero(self, tmp_path):
        """bin/atlas is the command every guide starts from; like the
        dashboard launcher it must run from the repository's own venv."""
        env = {k: v for k, v in os.environ.items() if k != "VENV_PY"}
        env["HOME"] = str(tmp_path)
        r = subprocess.run([str(_ROOT / "bin" / "atlas"), "--help"],
                           cwd=_ROOT, env=env, capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, (r.stdout + r.stderr)[-600:]
        assert "usage: atlas [" in r.stdout

    def test_atlas_secret_help_exits_zero(self):
        r = subprocess.run([str(_ROOT / "bin" / "atlas-secret"), "--help"],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0 and "Usage: atlas-secret" in r.stdout
