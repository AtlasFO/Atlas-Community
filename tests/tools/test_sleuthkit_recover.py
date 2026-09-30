import pytest
"""tsk.recover extracts one directory tree unless a whole-volume
extraction is asked for explicitly."""
from unittest.mock import patch

from tools import sleuthkit


@pytest.fixture(autouse=True)
def _images_need_not_exist(monkeypatch):
    """These tests build commands for images that are not on disk; the
    missing-image refusal is covered in test_sleuthkit_images.py."""
    monkeypatch.setattr("tools.sleuthkit._image_missing", lambda image: None)


def test_recover_without_a_directory_is_refused():
    with patch.object(sleuthkit, "run") as run:
        out = sleuthkit.tsk_recover("img.dd", "out", offset_sectors=2048)
    assert out["success"] is False and out["gate"] == "recover_scope"
    assert "dir_inode" in out["error"] and not run.called


def test_directory_inode_maps_to_the_tsk_flag():
    with patch.object(sleuthkit, "run", return_value={"success": True}) as run:
        sleuthkit.tsk_recover("img.dd", "out", offset_sectors=2048, dir_inode=106241)
    cmd = run.call_args.args[0]
    assert cmd[:1] == ["tsk_recover"] and "-d" in cmd and cmd[cmd.index("-d") + 1] == "106241"
    assert cmd[-2:] == ["img.dd", "out"]


def test_whole_volume_must_be_explicit():
    with patch.object(sleuthkit, "run", return_value={"success": True}) as run:
        sleuthkit.tsk_recover("img.dd", "out", whole_volume=True)
    assert "-d" not in run.call_args.args[0]
