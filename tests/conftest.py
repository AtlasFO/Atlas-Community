"""Shared fixtures for Atlas test suite."""
import contextlib
import os

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def _environment_is_restored_after_every_test():
    """Code under test may set os.environ for its own process (the CLI's
    brain switch, a chat worker's beacon switch); in a test process that
    would reach every later test. The environment each test found is put
    back after it. Defined first, so it is set up first and torn down last,
    after every monkeypatch-based fixture has undone its own changes."""
    saved = dict(os.environ)
    yield
    if dict(os.environ) != saved:
        os.environ.clear()
        os.environ.update(saved)


@pytest.fixture(autouse=True)
def _learned_profiles_stay_out_of_the_users_file(monkeypatch, tmp_path):
    """The API-compat cache is one file shared by every Atlas process on
    the host. A test that resolves or stores a profile without pointing the
    cache elsewhere would write the test process's memory over what real
    runs learned; every test gets its own file and an empty memory."""
    import agent.llm as llm
    monkeypatch.setenv("ATLAS_LLM_COMPAT_CACHE", str(tmp_path / "llm_api_compat.json"))
    monkeypatch.setenv("ATLAS_MODEL_CONTEXT_CACHE", str(tmp_path / "model_context_cache.json"))
    llm._compat_mem.clear()
    llm._compat_dirty.clear()
    llm._compat_loaded = False
    yield
    llm._compat_mem.clear()
    llm._compat_dirty.clear()
    llm._compat_loaded = False


@pytest.fixture(autouse=True)
def _usage_ledger_stays_out_of_the_users_file(monkeypatch, tmp_path):
    """The usage ledger is one file per host and its context is exported to
    the environment; every test writes to its own file and starts without a
    context, so an in-process CLI run leaks nothing into the next test."""
    from core import usage_ledger
    monkeypatch.setenv("ATLAS_USAGE_DB", str(tmp_path / "usage.db"))
    monkeypatch.delenv("ATLAS_USAGE_CONTEXT", raising=False)
    usage_ledger.reset()
    yield
    usage_ledger.reset()


@pytest.fixture(autouse=True)
def _stream_requests_answer_like_posts(monkeypatch):
    """The transport tests fake ``httpx.post``; the client streams a chat
    completion through ``httpx.stream``. Route a stream request to whatever
    ``httpx.post`` is when it is made, as a plain reply, so those fakes keep
    answering. Streaming tests patch ``httpx.stream`` themselves."""
    import httpx

    @contextlib.contextmanager
    def _stream(method, url, **kwargs):
        yield httpx.post(url, **kwargs)

    monkeypatch.setattr(httpx, "stream", _stream)


def make_proc(returncode=0, stdout=b"output", stderr=b""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


@pytest.fixture
def ok_proc():
    return make_proc(0, b"tool output", b"")


@pytest.fixture
def fail_proc():
    return make_proc(1, b"", b"error detail")


@pytest.fixture
def run_ok():
    return {
        "success": True,
        "stdout": "tool output",
        "stderr": "",
        "exit_code": 0,
        "truncated": False,
        "cmd": "tool arg",
    }


@pytest.fixture
def run_fail():
    return {
        "success": False,
        "stdout": "",
        "stderr": "error detail",
        "exit_code": 1,
        "truncated": False,
        "cmd": "tool arg",
    }


@pytest.fixture(autouse=True)
def isolate_session_file(tmp_path):
    """Redirect _SESSION_FILE so tests never overwrite the real Atlas session.
    Also configure a per-test trace log so tests that hit core.executor.run()
    don't trip the new `_require_configured` raise (the global error-surfacing
    refactor turned silent drops into RuntimeErrors).

    The session + trace files live under a hidden subdir so they don't bleed
    into filesystem-walking tests that use tmp_path directly (e.g. hash_directory).
    """
    try:
        from core.llm_check import reset_session
        reset_session()
    except Exception:
        pass
    import core.execution_log as elog
    internal = tmp_path / ".pytest-atlas"
    internal.mkdir(exist_ok=True)
    fake_session = str(internal / "session.json")
    fake_trace = str(internal / "trace.json")
    fake_counter = str(internal / "call_id.counter")
    fake_marker_dir = str(internal / "clear_markers")
    fake_beacon_dir = str(internal / "beacons")
    # Isolate the shared call_id counter too — otherwise tests that assert
    # call_id == 1 race against the real ~/.cache/atlas/call_id.counter (shared
    # with any live Atlas session AND any concurrently-running pytest process).
    # The clear-marker and beacon dirs are isolated for the same reason: keep
    # the resurrection-guard state per-test so configure()/reset_for_clear()
    # never touch the real ~/.cache/atlas and tests can't cross-contaminate.
    with patch.object(elog, "_SESSION_FILE", fake_session), \
         patch.object(elog, "_CALL_ID_COUNTER_FILE", fake_counter), \
         patch.object(elog, "_CLEAR_MARKER_DIR", fake_marker_dir), \
         patch.object(elog, "_BEACON_DIR", fake_beacon_dir):
        # save_session=False is belt-and-suspenders alongside the
        # _SESSION_FILE patch: ensures even if the patch is bypassed (or
        # a test re-imports the module), the global session file stays
        # untouched. A configure() outside any fixture that overwrites
        # ~/.cache/atlas/session.json silently reroutes the active
        # investigation's writes.
        elog.log.configure("PYTEST", fake_trace, save_session=False)
        yield


@pytest.fixture
def tmp_evidence(tmp_path):
    """A fake evidence file (not in a protected path)."""
    f = tmp_path / "image.raw"
    f.write_bytes(b"\x00" * 1024)
    return str(f)


@pytest.fixture
def tmp_output(tmp_path):
    """A writable output directory (not in evidence paths)."""
    d = tmp_path / "exports"
    d.mkdir()
    return str(d)


# ── Helpers for the middleware gate chain ────────────────────────────────────
# core/middleware.py runs several gates before a tool body is reached, and two
# of them are newer than most of the tests below them:
#
#   1. the input-path gate — refuses a tool whose path arguments do not exist
#   2. the evidence-compat gate — refuses a tool whose required evidence class
#      is absent from the case's evidence profile
#
# Both run BEFORE the DAIR gate, the solution-material gate and the case-path
# rewrite. A unit test that targets one of those later layers must therefore
# hand it a case that satisfies the earlier ones, or it never gets there and
# fails with an unrelated refusal. These helpers exist so that setup is stated
# once instead of copied per test.

# One extension per class, from core/evidence_profile.py::_EXT_CLASS.
_EVIDENCE_CLASS_FILE = {
    "disk": "disk.E01",
    "memory": "memory.vmem",
    "tabular": "export.csv",
    "pcap": "capture.pcap",
}


def seed_evidence(case_dir, *classes, size: int = 64) -> dict[str, str]:
    """Create one real file per evidence class under ``<case_dir>/evidence/``.

    Satisfies the evidence-compat gate for tools that require those classes.
    Returns {class: absolute path} so a test can also point a path argument at
    a file that genuinely exists, which the input-path gate requires.
    """
    import pathlib

    ev = pathlib.Path(case_dir) / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    made = {}
    for cls in classes:
        name = _EVIDENCE_CLASS_FILE[cls]
        path = ev / name
        path.write_bytes(b"\x00" * size)
        made[cls] = str(path)
    return made


def shape_log_mock(mock_log):
    """Make a MagicMock a faithful stand-in for ``core.execution_log.log``.

    An unshaped MagicMock answers every attribute with a truthy MagicMock.
    ``core/middleware.py::_gate_decision`` reads
    ``log.deferred_backlog_status()`` and treats ``st.get("latched")`` as a
    boolean, so an unshaped mock latches the DAIR backlog and *every* tool call
    is refused before the middleware under test runs. Same for ``log._entries``,
    which the gate iterates.

    This shapes only what the gates read. Assertions on recording calls
    (record_agent_message and friends) keep working as before.
    """
    from core.deferred_intents import (
        DEFERRED_BACKLOG_CAP,
        DEFERRED_BACKLOG_HYSTERESIS,
    )

    mock_log._entries = []
    mock_log.deferred_backlog_status.return_value = {
        "open": 0,
        "prescribed": 0,
        "cap": DEFERRED_BACKLOG_CAP,
        "hysteresis": DEFERRED_BACKLOG_HYSTERESIS,
        "latched": False,
    }
    # No active case: the case-path gate only rewrites relative paths, and
    # these tests pass absolute ones or none at all.
    mock_log.case_dir.return_value = None
    return mock_log


# Raw-input magic that the input-kind gates check before any parser runs
# (core/input_kind.py::_evtx_magic_ok / _hive_magic_ok). Those gates refuse an
# invented path with failure_class="missing_input" and a non-raw file with
# "wrong_input_kind" — both BEFORE the tool is reached. A unit test for the tool
# itself therefore has to hand it a file that satisfies the gate, or it asserts
# on a call that never happened. Kept here so the magic bytes live in one place.
_EVTX_MAGIC = b"ElfFile\x00"
_HIVE_MAGIC = b"regf"


def make_evtx(path, size: int = 128) -> str:
    """Create a file the EVTX input-kind gate accepts. Returns its path."""
    import pathlib
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(_EVTX_MAGIC + b"\x00" * max(0, size - len(_EVTX_MAGIC)))
    return str(p)


def make_hive(path, size: int = 128) -> str:
    """Create a file the registry-hive input-kind gate accepts."""
    import pathlib
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(_HIVE_MAGIC + b"\x00" * max(0, size - len(_HIVE_MAGIC)))
    return str(p)


@pytest.fixture(autouse=True)
def no_privileged_kill(monkeypatch):
    """No test runs sudo kill for real: on a host with the Atlas grant (the
    test VM) it would SIGKILL, as root, whatever process group holds a
    number a test made up. The stub reports a refused sudo; a test that
    wants the call made reads the recorded commands or replaces the stub."""
    import subprocess as _sp
    import core.privileged_kill as _pk
    calls: list = []

    def _refused(cmd, **kw):
        calls.append(list(cmd))
        return _sp.CompletedProcess(cmd, 1)

    monkeypatch.setattr(_pk, "_run", _refused)
    return calls
