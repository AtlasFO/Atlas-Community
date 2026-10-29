"""A cancel of the memory batch (SIGTERM to the runner's process
group, as the job supervisor's _terminate sends at a run's normal end) also
stops the plugin in flight, which runs in a process group of its own.
Invented files; the plugin is a sleeping script."""
import json, os, signal, subprocess, sys, time
from core import memory_batch as MB
from tests.tools.test_memory_batch import _manifest, env  # noqa: F401
from tests.tools.test_memory_batch_owner import _slow_vol, _alive, _REPO


def test_cancel_of_runner_group_stops_plugin(env, tmp_path):  # noqa: F811
    case, image, _c, _v, syms = env
    marks = tmp_path / "m.jsonl"
    _manifest(case, image, _slow_vol(tmp_path, marks), syms)
    MB.add_owner(case)
    r = subprocess.Popen([sys.executable, os.path.join(_REPO, "tools", "memory_batch_runner.py"),
                          str(MB.manifest_path(case))], cwd=_REPO, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env={**os.environ, "PYTHONPATH": _REPO},
                         start_new_session=True)
    t = time.monotonic() + 60
    while not marks.exists() and time.monotonic() < t:
        time.sleep(0.2)
    plugin = json.loads(marks.read_text().splitlines()[0])
    os.killpg(r.pid, signal.SIGTERM)
    r.wait(timeout=30)
    time.sleep(1)
    alive = _alive(plugin["pid"])
    if alive:
        os.killpg(plugin["pid"], signal.SIGKILL)
    assert not alive, "plugin outlived the cancel of its runner"
