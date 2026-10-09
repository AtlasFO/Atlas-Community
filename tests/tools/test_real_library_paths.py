"""The real libraries behind three tools, not stand-ins: libscca's Python
API as the prefetch fallback reads it, py-tlsh on files it can hash, and
odl.py on a OneDrive log built here from the format. Each check is skipped
where its library or program is not installed."""
from __future__ import annotations

import csv
import random
import struct
import sys
import types
from datetime import datetime, timezone

import pytest


def test_libscca_still_offers_what_the_prefetch_fallback_reads():
    pyscca = pytest.importorskip("pyscca")
    assert callable(pyscca.open)
    for name in ("get_last_run_time", "get_filename", "number_of_filenames",
                 "executable_filename", "prefetch_hash", "format_version", "run_count"):
        assert hasattr(pyscca.file, name), name


def test_one_unreadable_prefetch_file_does_not_end_the_batch(tmp_path, monkeypatch):
    import tools.eztools as ez

    class Readable:
        executable_filename = "TOOLX.EXE"
        prefetch_hash = 0x1A2B3C4D
        format_version = 30
        run_count = 1
        number_of_filenames = 0

        def get_last_run_time(self, i):
            if i:
                raise IndexError
            return datetime(2031, 2, 4, 12, 0, 0)

    class Corrupt(Readable):
        @property
        def executable_filename(self):
            raise OSError("unable to read executable filename")

    fake = types.ModuleType("pyscca")
    fake.open = lambda path: Corrupt() if "BROKEN" in path else Readable()
    monkeypatch.setitem(sys.modules, "pyscca", fake)
    for name in ("BROKEN.EXE-00000001.pf", "TOOLX.EXE-1A2B3C4D.pf"):
        (tmp_path / name).write_bytes(b"MAM\x04" + b"\x00" * 16)
    out = ez._prefetch_fallback(str(tmp_path), str(tmp_path), "prefetch.csv")
    assert out["success"] and out["records"] == 1
    assert "BROKEN.EXE-00000001.pf: unable to read executable filename" in out["stdout"]


def _noise(seed: int, tmp_path):
    p = tmp_path / f"sample-{seed}.bin"
    p.write_bytes(random.Random(seed).randbytes(4096))
    return str(p)


def test_tlsh_hashes_and_compares_real_files(tmp_path):
    pytest.importorskip("tlsh")
    from tools.bintriage import tlsh_compare, tlsh_hash
    a, b = _noise(2031, tmp_path), _noise(2032, tmp_path)
    digest = tlsh_hash(a)
    assert digest["success"] and digest["tlsh"].startswith("T1")
    same = tlsh_compare(a, a)
    assert same["distance"] == 0 and same["interpretation"] == "identical/near-identical"
    assert tlsh_compare(a, b)["distance"] > same["distance"]


def _odl_v3(code_file: bytes, function: bytes, param: bytes, when: datetime) -> bytes:
    """A version-3 OneDrive log holding one call, laid out as odl.py reads
    it: a 0x100-byte file header, then a 32-byte record header whose data
    follows 24 skipped bytes."""
    def lp(b: bytes) -> bytes:
        return struct.pack("<I", len(b)) + b
    header = (b"EBFGONED" + struct.pack("<IIQI", 3, 0, 0, 0)
              + b"26.000.0000.0001".ljust(0x40, b"\0") + b"10.0.26100".ljust(0x40, b"\0")
              + b"\0" * 0x64)
    assert len(header) == 0x100
    data = lp(code_file) + struct.pack("<I", 0) + lp(function) + lp(param)
    ms = int(when.timestamp() * 1000)
    record = (b"\xCC\xDD\xEE\xFF" + struct.pack("<HHQIIII", 0, 0, ms, 0, 0, 24 + len(data), 0)
              + b"\0" * 24 + data)
    return header + record


@pytest.mark.install_smoke
def test_odl_py_decodes_a_log_built_from_the_format(tmp_path, monkeypatch):
    import os
    from core.executor import run as real_run
    from tools.misc import _odl_script, onedrive_odl
    if not os.path.isfile(_odl_script()):
        pytest.skip("odl.py is not installed (install.sh puts it in /opt/onedrive-odl)")
    pytest.importorskip("construct")
    pytest.importorskip("Crypto")
    monkeypatch.setattr("tools.misc.run", real_run)
    logs = tmp_path / "evidence" / "logs" / "Business1"
    logs.mkdir(parents=True)
    (logs / "SyncEngine-2031-03-04.odl").write_bytes(_odl_v3(
        b"SyncEngine.cpp", b"UploadFile",
        b"report-2031.docx uploaded for jane.doe@example.com",
        datetime(2031, 3, 4, 5, 6, 7, tzinfo=timezone.utc)))
    monkeypatch.chdir(tmp_path)
    res = onedrive_odl(str(logs))
    assert res["success"], res
    with open(res["output_path"], encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert [(r["Code_File"], r["Function"]) for r in rows] == [("SyncEngine.cpp", "UploadFile")]
    assert "jane.doe@example.com" in rows[0]["Params_Decoded"]
    assert rows[0]["Timestamp"].startswith("2031-03-04 05:06:07")
