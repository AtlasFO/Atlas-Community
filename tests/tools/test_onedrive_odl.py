"""misc.onedrive_odl runs odl.py as a subprocess on a folder of links that
holds the sync logs and the account's key file together, writes its CSV
under the case, never beside the evidence, and says when no key file was
found."""
import os
import sys

import pytest

STUB = '''
import os, sys
stage, out = sys.argv[1], sys.argv[sys.argv.index("-o") + 1]
with open(out, "w") as fh:
    fh.write("entry,is_link\\n")
    for name in sorted(os.listdir(stage)):
        fh.write(f"{name},{os.path.islink(os.path.join(stage, name))}\\n")
'''


@pytest.fixture
def odl(tmp_path, monkeypatch):
    from core.executor import run as real_run
    monkeypatch.setattr("tools.misc.run", real_run)
    script = tmp_path / "odl_stub.py"
    script.write_text(STUB, encoding="utf-8")
    monkeypatch.setenv("ATLAS_ODL_PY", str(script))
    logs = tmp_path / "evidence" / "logs" / "Personal"
    logs.mkdir(parents=True)
    for name in ("SyncEngine-2024-01-01.odl", "SyncEngine-2024-01-02.odlgz", "readme.txt"):
        (logs / name).write_bytes(b"x")
    settings = tmp_path / "evidence" / "settings" / "Personal"
    settings.mkdir(parents=True)
    (settings / "general.keystore").write_text('[{"Key": "x"}]', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path, logs, settings


def test_logs_and_key_are_read_together_and_nothing_lands_beside_the_evidence(odl):
    from tools.misc import onedrive_odl
    root, logs, settings = odl
    before = sorted(os.listdir(logs)), sorted(os.listdir(settings))
    r = onedrive_odl(str(logs), settings_dir=str(settings))
    assert r["success"] is True, r
    rows = (root / r["output_path"]).read_text().splitlines()
    assert rows[1:] == ["SyncEngine-2024-01-01.odl,True", "SyncEngine-2024-01-02.odlgz,True",
                        "general.keystore,True"]
    assert r["logs_read"] == 2 and "stay encoded" not in r["note"]
    assert (sorted(os.listdir(logs)), sorted(os.listdir(settings))) == before
    assert not any(n.startswith(".odl_stage_") for n in os.listdir(root / "analysis"))


def test_without_a_key_file_the_note_says_so(odl):
    from tools.misc import onedrive_odl
    _root, logs, _settings = odl
    r = onedrive_odl(str(logs))
    assert r["success"] is True and "stay encoded" in r["note"]


def test_missing_script_folder_and_logs_are_reported(odl, monkeypatch, tmp_path):
    from tools.misc import onedrive_odl
    _root, logs, settings = odl
    assert "no OneDrive log files" in onedrive_odl(str(settings))["error"]
    assert onedrive_odl(str(tmp_path / "nope"))["gate"] == "missing_input"
    monkeypatch.setenv("ATLAS_ODL_PY", str(tmp_path / "absent.py"))
    assert "not installed" in onedrive_odl(str(logs))["error"]
