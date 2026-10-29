"""Memory speed: the memory plugin result store's key and its
write rule. Invented fixtures only (an invented image file, a fake
Volatility binary, dates in 2031)."""
from __future__ import annotations

import json
import os
import stat

import pytest

from core import vol_cache as V


@pytest.fixture
def env(tmp_path):
    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    (case / "evidence" / "mem").mkdir(parents=True)
    image = case / "evidence" / "mem" / "corp-ws01.mem"
    image.write_bytes(b"\x01" * (3 * (1 << 20)))
    syms = tmp_path / "symbols" / "windows"
    syms.mkdir(parents=True)
    (syms / "ntkrnlmp.pdb" ).mkdir()
    (syms / "ntkrnlmp.pdb" / "A1B2.json.xz").write_bytes(b"isf")
    vol = tmp_path / "vol"
    vol.write_text("#!/bin/sh\necho 'Volatility 3 Framework 9.9.9'\n")
    vol.chmod(vol.stat().st_mode | stat.S_IEXEC)
    V.vol_version.cache_clear()
    return case, str(image), str(tmp_path / "symbols"), str(vol)


def _key(env, plugin="windows.pslist.PsList", extra=None):
    case, image, syms, vol = env
    return V.key_for(case, image, plugin, extra, vol_bin=vol, symbol_dir=syms)


def test_the_key_follows_image_symbols_version_plugin_and_arguments(env):
    case, image, syms, vol = env
    k = _key(env)
    assert k and k == _key(env) and V.vol_version(vol) == "9.9.9"
    assert _key(env, extra=["--pid", "4,2"]) == _key(env, extra=["--pid", "2,4"]) != k
    assert _key(env, plugin="windows.netstat.NetStat") != k
    isf = os.path.join(syms, "windows", "ntkrnlmp.pdb", "A1B2.json.xz")
    os.utime(isf, ns=(1924560000 * 10**9, 1924560000 * 10**9))            # a pack updated in place
    k2 = _key(env)
    assert k2 != k
    with open(image, "r+b") as fh:                                          # the image changes
        fh.write(b"\x02")
    assert _key(env) != k2


def test_the_catalogs_full_hash_names_the_image_while_it_still_matches(env):
    case, image, syms, vol = env
    st = os.stat(image)
    (case / ".atlas" / "evidence_catalog.json").write_text(json.dumps({"units": {"ev1": {
        "path": "evidence/mem/corp-ws01.mem", "content_sha256": "ab" * 32, "size": st.st_size,
        "mtime_ns": st.st_mtime_ns}}}), encoding="utf-8")
    assert V.image_id(case, image) == "sha256:" + "ab" * 32
    os.utime(image, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    assert V.image_id(case, image).startswith("fp:")


def test_only_complete_successes_are_stored_and_file_writers_never(env):
    case = env[0]
    k = _key(env)
    ok = {"success": True, "stdout": "[{\"PID\": 4}]", "exit_code": 0, "truncated": False}
    assert not V.store(case, k, {**ok, "timed_out": True}, {})
    assert not V.store(case, k, {**ok, "truncated": True}, {})
    assert not V.store(case, k, {**ok, "success": False}, {})
    assert V.lookup(case, k) is None
    assert V.store(case, k, ok, {"cmd": "vol pslist", "time": "2031-03-10T14:00:00Z"})
    assert V.stored_text(V.lookup(case, k)) == "[{\"PID\": 4}]"
    assert V.writes_files("windows.dumpfiles.DumpFiles", None) and V.writes_files("windows.malfind.Malfind",
                                                                                   ["--dump"])
    assert V.writes_files("windows.pslist.PsList", None, output_dir="/tmp/x") and not V.writes_files(
        "windows.pslist.PsList", ["--pid", "4"])


def test_the_switch_turns_the_store_off(env, monkeypatch):
    case = env[0]
    k = _key(env)
    V.store(case, k, {"success": True, "stdout": "x", "exit_code": 0}, {})
    monkeypatch.setenv("ATLAS_VOL_RESULT_STORE", "0")
    assert V.lookup(case, k) is None


def test_two_images_alike_at_both_ends_never_share_the_fallback_key(env):
    case, image, syms, vol = env
    other = case / "evidence" / "mem" / "corp-ws02.mem"
    data = bytearray(b"\x01" * (3 * (1 << 20)))
    data[(1 << 20) + 5] = 7                                  # differs only in the middle
    other.write_bytes(bytes(data))
    st = os.stat(image)
    os.utime(other, ns=(st.st_atime_ns, st.st_mtime_ns))     # same size and mtime, same first and last MiB
    a, b = V.image_id(case, image), V.image_id(case, str(other))
    assert a.startswith("fp:") and b.startswith("fp:") and a != b


def test_the_warm_reads_full_hash_names_the_image_and_a_sampled_hash_does_not(env):
    case, image, syms, vol = env
    st = os.stat(image)
    (case / ".atlas" / "evidence_catalog.json").write_text(json.dumps({"units": {"ev1": {
        "path": "evidence/mem/corp-ws01.mem", "content_sha256": "cd" * 32, "size": st.st_size,
        "mtime_ns": st.st_mtime_ns, "fingerprint_mode": "sampled"}}}), encoding="utf-8")
    assert V.image_id(case, image).startswith("fp:")
    from tools.memory_batch_runner import warm
    warm(image, str(case))
    import hashlib
    full = hashlib.sha256(open(image, "rb").read()).hexdigest()
    assert V.image_id(case, image) == "sha256:" + full
    os.utime(image, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    assert V.image_id(case, image).startswith("fp:")


def test_the_volatility_packages_own_symbols_are_keyed(env, tmp_path):
    case, image, syms, vol = env
    venv = tmp_path / "venv"
    pkg = venv / "lib" / "python3.13" / "site-packages" / "volatility3" / "symbols"
    pkg.mkdir(parents=True)
    (pkg / "windows.zip").write_bytes(b"pack")
    (venv / "bin").mkdir()
    vbin = venv / "bin" / "vol"
    vbin.write_text(f"#!{venv}/bin/python3\necho 'Volatility 3 Framework 9.9.9'\n")
    V.package_symbols_dir.cache_clear()
    assert V.package_symbols_dir(str(vbin)) == str(pkg)
    k = V.key_for(case, image, "windows.pslist.PsList", None, vol_bin=str(vbin), symbol_dir=syms)
    os.utime(pkg / "windows.zip", ns=(1924560000 * 10**9, 1924560000 * 10**9))    # the pack updated in place
    assert V.key_for(case, image, "windows.pslist.PsList", None, vol_bin=str(vbin), symbol_dir=syms) != k
