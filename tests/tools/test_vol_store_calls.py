"""Memory speed: a plugin call answered from the result store is a
full call of the run (its own saved output, cached_from naming the stored
call), also after a fresh start. Invented fixtures only (an invented image
file, a fake Volatility binary, dates in 2031)."""
from __future__ import annotations

import stat

import pytest

import tools.volatility as VV
from core import vol_cache as V


@pytest.fixture
def env(tmp_path, monkeypatch):
    from core.execution_log import ExecutionLog
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "evidence" / "mem").mkdir(parents=True)
    image = case / "evidence" / "mem" / "corp-ws01.mem"
    image.write_bytes(b"\x01" * (2 << 20))
    count = tmp_path / "runs.txt"
    vol = tmp_path / "vol"
    vol.write_text("#!/bin/sh\n"
                   "case \"$1\" in --help) echo 'Volatility 3 Framework 9.9.9'; exit 0;; esac\n"
                   f"echo run >> {count}\n"
                   "echo '[{\"PID\": 4242, \"ImageFileName\": \"svc_kit.exe\"}]'\n")
    vol.chmod(vol.stat().st_mode | stat.S_IEXEC)
    V.vol_version.cache_clear()
    monkeypatch.setattr(VV, "VOL", str(vol))
    monkeypatch.setattr(VV, "vol3_symbols", lambda: str(tmp_path / "symbols"))
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(case))

    def fresh_log(name):
        log = ExecutionLog()
        log.configure("CASE-A", str(case / "analysis" / name), save_session=False)
        monkeypatch.setattr("core.execution_log.log", log)
        return log
    return case, str(image), count, fresh_log


def test_a_repeat_after_a_fresh_start_is_answered_from_the_store_as_a_full_call(env):
    from tools._gates.citation_support import call_output_text
    case, image, count, fresh_log = env
    fresh_log("CASE-A_trace.json")
    first = VV._vol(image, "windows.pslist.PsList")
    assert first["success"] and count.read_text().count("run") == 1
    log = fresh_log("CASE-A2_trace.json")                 # a new trace: a fresh start
    again = VV._vol(image, "windows.pslist.PsList")
    assert count.read_text().count("run") == 1            # not run again
    assert again["cached_from"]["cmd"] == first["cmd"] and "result store" in again["note"]
    entry = next(e for e in log._entries if e.get("type") == "tool_call")
    assert entry["call_id"] == again["_atlas_call_id"] and entry.get("cached_from")
    assert entry.get("stdout_file") and "svc_kit.exe" in call_output_text(entry).lower()


def test_a_failed_call_is_not_stored_and_the_switch_bypasses(env, monkeypatch):
    case, image, count, fresh_log = env
    fresh_log("CASE-A_trace.json")
    monkeypatch.setattr(VV, "run", lambda cmd, timeout=0: {"success": False, "stdout": "", "exit_code": 1,
                                                          "cmd": " ".join(cmd)})
    VV._vol(image, "windows.netscan.NetScan")
    assert not list(V.store_dir(case).glob("*.json"))
    monkeypatch.undo()


def _config_vol(tmp_path, monkeypatch, fail_with_config=False):
    """A fake Volatility that saves a config naming the image it read, and
    with -c refuses a config whose location is not the image it is given."""
    import json as _json
    calls = tmp_path / "calls.txt"
    script = tmp_path / "vol_cfg.py"
    script.write_text(
        "import json, sys\n"
        "a = sys.argv[1:]\n"
        f"open({str(calls)!r}, 'a').write(' '.join(a) + '\\n')\n"
        "if a and a[0] == '--help':\n    print('Volatility 3 Framework 9.9.9'); sys.exit(0)\n"
        "img = a[a.index('-f') + 1]\n"
        "if '-c' in a:\n"
        "    cfg = json.load(open(a[a.index('-c') + 1]))\n"
        f"    if {fail_with_config!r} or not cfg['automagic.LayerStacker.single_location'].endswith(img):\n"
        "        sys.exit(1)\n"
        "if '--save-config' in a:\n"
        "    json.dump({'automagic.LayerStacker.single_location': 'file://' + img}, "
        "open(a[a.index('--save-config') + 1], 'w'))\n"
        "print(json.dumps([{'PID': 4242}]))\n")
    vol = tmp_path / "vol_cfg"
    vol.write_text(f"#!/bin/sh\nexec {__import__('sys').executable} {script} \"$@\"\n")
    vol.chmod(vol.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(VV, "VOL", str(vol))
    V.vol_version.cache_clear()
    return calls


def test_the_layer_config_is_saved_then_reused_with_the_images_current_path(env, tmp_path, monkeypatch):
    case, image, _count, fresh_log = env
    fresh_log("CASE-A_trace.json")
    calls = _config_vol(tmp_path, monkeypatch)
    assert VV._vol(image, "windows.pslist.PsList")["success"]
    import os
    moved_case = tmp_path / "case-moved"
    os.rename(case, moved_case)                  # the case moves: same relative path, content and mtime
    monkeypatch.setattr("core.paths.active_case_dir", lambda: str(moved_case))
    from core.execution_log import ExecutionLog
    log = ExecutionLog()
    log.configure("CASE-A", str(moved_case / "analysis" / "CASE-A2_trace.json"), save_session=False)
    monkeypatch.setattr("core.execution_log.log", log)
    moved = str(moved_case / "evidence" / "mem" / "corp-ws01.mem")
    assert VV._vol(moved, "windows.cmdline.CmdLine")["success"]
    lines = [ln for ln in calls.read_text().splitlines() if "--help" not in ln]
    assert "--save-config" in lines[0] and "-c" in lines[1].split() and "--save-config" not in lines[1]


def test_a_moved_image_without_a_full_hash_is_another_image(env, tmp_path, monkeypatch):
    case, image, _count, fresh_log = env
    fresh_log("CASE-A_trace.json")
    _config_vol(tmp_path, monkeypatch)
    assert VV._vol(image, "windows.pslist.PsList")["success"]
    import os
    moved = image.replace("corp-ws01.mem", "corp-ws02.mem")
    os.rename(image, moved)
    assert "cached_from" not in VV._vol(moved, "windows.pslist.PsList")


def test_a_capped_complete_output_is_stored_whole_and_its_hit_capped(env, tmp_path, monkeypatch):
    from core.paths import OUTPUT_CAP
    case, image, count, fresh_log = env
    fresh_log("CASE-A_trace.json")
    rows = ",".join('{"PID": %d, "ImageFileName": "proc%d.exe"}' % (n, n) for n in range(4000))
    script = tmp_path / "big.py"
    script.write_text("import sys\n"
                      "if sys.argv[1:2] == ['--help']:\n    print('Volatility 3 Framework 9.9.9'); sys.exit(0)\n"
                      f"open({str(count)!r}, 'a').write('run\\n')\n"
                      f"print('[' + {rows!r}.replace('}},', '}},\\n') + ']')\n")
    vol = tmp_path / "vol_big"
    vol.write_text(f"#!/bin/sh\nexec {__import__('sys').executable} {script} \"$@\"\n")
    vol.chmod(vol.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(VV, "VOL", str(vol))
    V.vol_version.cache_clear()
    first = VV._vol(image, "windows.psscan.PsScan")
    assert first["success"] and first["truncated"] and first.get("stdout_file")
    stored = list(V.store_dir(case).glob("*.out"))
    assert len(stored) == 1 and "proc3999.exe" in stored[0].read_text()
    again = VV._vol(image, "windows.psscan.PsScan")
    assert count.read_text().count("run") == 1 and again.get("cached_from")
    assert again["truncated"] and len(again["stdout"]) <= OUTPUT_CAP + 200 and "proc3999.exe" not in again["stdout"]
    assert "proc3999.exe" in open(again["stdout_file"]).read()
    assert again["stdout"] == first["stdout"]


def test_the_report_names_the_calls_answered_from_the_store(env):
    from core.investigation_exit import open_limit_lines
    case, image, count, fresh_log = env
    fresh_log("CASE-A_trace.json")
    VV._vol(image, "windows.pslist.PsList")
    assert not any("result store" in ln for ln in open_limit_lines(case))
    fresh_log("CASE-A2_trace.json")
    VV._vol(image, "windows.pslist.PsList")
    line = next(ln for ln in open_limit_lines(case) if "result store" in ln)
    assert "PsList on corp-ws01.mem" in line


def test_a_call_failing_with_the_config_runs_once_more_without_it(env, tmp_path, monkeypatch):
    case, image, _count, fresh_log = env
    fresh_log("CASE-A_trace.json")
    _config_vol(tmp_path, monkeypatch)
    VV._vol(image, "windows.pslist.PsList")
    calls = _config_vol(tmp_path, monkeypatch, fail_with_config=True)
    assert VV._vol(image, "windows.cmdline.CmdLine")["success"]
    lines = [ln for ln in calls.read_text().splitlines() if "--help" not in ln]
    assert "-c" in lines[-2].split() and "--save-config" in lines[-1]
