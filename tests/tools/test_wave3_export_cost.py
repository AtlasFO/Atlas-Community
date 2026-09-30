"""Wave 3: refuse re-export when raw already satisfied; mount_plan lookup."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_find_export_for_source(tmp_path: Path):
    from core.mount_plan import register_exported_image, find_export_for_source

    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    (case / ".atlas").mkdir()
    raw = case / "analysis" / "host.raw"
    raw.write_bytes(b"\x00" * 2048)
    src = str(case / "evidence" / "host.vmdk")
    register_exported_image(case, raw, source=src)
    hit = find_export_for_source(case, src)
    assert hit is not None
    assert Path(hit["path"]).name == "host.raw"


def test_vmdk_export_refuses_when_raw_exists(tmp_path: Path):
    from tools.imaging import vmdk_export_raw

    case = tmp_path / "case"
    (case / "analysis").mkdir(parents=True)
    out = case / "analysis" / "host.raw"
    out.write_bytes(b"\x00" * 2_000_000)
    desc = str(tmp_path / "host.vmdk")
    Path(desc).write_bytes(b"vmdk")

    elog = MagicMock()
    elog.case_dir.return_value = str(case)
    with patch("core.vmdk.snapshot_warning", return_value=None), \
         patch("core.execution_log.log", elog), \
         patch("tools.imaging.run") as mock_run:
        r = getattr(vmdk_export_raw, "fn", vmdk_export_raw)(
            desc, str(out), force_reexport=False,
        )
        mock_run.assert_not_called()
    assert r["success"] is False
    assert r.get("gate") == "export_already_satisfied"
    assert r.get("recommended_next_tool") == "tsk.mmls"


def test_vmdk_export_derives_its_output_under_the_open_case(tmp_path: Path):
    """A caller that names the descriptor and nothing else gets the image
    written as analysis/exports/<stem>.raw under the case; outside a case
    the path has to be given."""
    from tools.imaging import vmdk_export_raw

    case = tmp_path / "case"
    (case / ".atlas").mkdir(parents=True)
    desc = case / "evidence" / "host.vmdk"
    desc.parent.mkdir()
    desc.write_bytes(b"vmdk")
    ok = {
        "success": True, "stdout": "", "stderr": "", "exit_code": 0,
        "elapsed_seconds": 0.1, "truncated": False, "cmd": "qemu-img",
        "retries": 0, "progress_lines": [],
    }
    commands = []

    def _run(cmd, **kwargs):
        commands.append(list(cmd))
        return dict(ok)

    elog = MagicMock()
    elog.case_dir.return_value = str(case)
    fn = getattr(vmdk_export_raw, "fn", vmdk_export_raw)
    with patch("core.vmdk.snapshot_warning", return_value=None), \
         patch("core.execution_log.log", elog), \
         patch("tools.imaging.run", side_effect=_run):
        r = fn(str(desc))
    expected = str(case / "analysis" / "exports" / "host.raw")
    assert r["success"] is True and r["output_path"] == expected
    assert commands[-1][-1] == expected and (case / "analysis" / "exports").is_dir()

    elog.case_dir.return_value = None
    with patch("core.vmdk.snapshot_warning", return_value=None), \
         patch("core.execution_log.log", elog), \
         patch("tools.imaging.run", side_effect=_run):
        r = fn(str(desc))
    assert r["success"] is False and "output_path is required" in r["error"]


def test_the_space_guard_budgets_the_sources_data_where_holes_are_kept(tmp_path: Path):
    """A sparse image converts to a raw file that holds only the data the
    source has; the guard asks for that much where the filesystem keeps
    holes, and for the full virtual size where it does not."""
    from tools import imaging
    from tools.imaging import vmdk_export_raw

    out = tmp_path / "analysis" / "host.raw"
    desc = str(tmp_path / "host.vmdk")
    Path(desc).write_bytes(b"vmdk")
    gib = 1024 ** 3
    ok = {
        "success": True, "stdout": "", "stderr": "", "exit_code": 0,
        "elapsed_seconds": 0.1, "truncated": False, "cmd": "qemu-img",
        "retries": 0, "progress_lines": [],
    }
    chain = [{"virtual-size": 150 * gib, "actual-size": 60 * gib},
             {"virtual-size": 150 * gib, "actual-size": 6 * gib}]

    def _run(cmd, **kwargs):
        if "info" in cmd:
            assert "--backing-chain" in cmd
            return {**ok, "stdout": __import__("json").dumps(chain)}
        return dict(ok)

    elog = MagicMock()
    elog.case_dir.return_value = None
    fn = getattr(vmdk_export_raw, "fn", vmdk_export_raw)
    common = [patch("core.vmdk.snapshot_warning", return_value=None),
              patch("core.execution_log.log", elog),
              patch("tools.imaging.run", side_effect=_run),
              patch("tools.imaging.shutil.disk_usage",
                    return_value=MagicMock(free=100 * gib))]
    with common[0], common[1], common[2], common[3], \
         patch.object(imaging, "_sparse_files_supported", return_value=True):
        r = fn(desc, str(out))
    assert r.get("success") is True          # 66 GB allocated + margin < 100 GB
    with common[0], common[1], common[2], common[3], \
         patch.object(imaging, "_sparse_files_supported", return_value=False):
        r = fn(desc, str(out))
    assert r.get("success") is False and "150.0 GB virtual" in r["error"]
    assert "66.0 GB allocated" in r["error"]


def test_a_directory_that_keeps_holes_is_recognised(tmp_path: Path):
    from tools.imaging import _sparse_files_supported
    # tmpfs and every common Linux filesystem keep holes; the probe must
    # not leave its file behind either way.
    _sparse_files_supported(str(tmp_path))
    assert not list(tmp_path.glob(".sparse-probe-*"))


def test_a_convert_that_stops_short_leaves_no_image_behind(tmp_path: Path):
    """A raw image cut off by a failure or a timeout reads as complete and
    would be found as a finished export by the next call; it is removed."""
    from tools.imaging import vmdk_export_raw

    out = tmp_path / "analysis" / "host.raw"
    out.parent.mkdir(parents=True)
    desc = str(tmp_path / "host.vmdk")
    Path(desc).write_bytes(b"vmdk")
    failed = {
        "success": False, "stdout": "", "stderr": "killed", "exit_code": -9,
        "elapsed_seconds": 0.1, "truncated": False, "cmd": "qemu-img",
        "retries": 0, "progress_lines": [], "error": "timeout",
    }

    def _run(cmd, **kwargs):
        if "info" in cmd:
            return {**failed, "success": True}
        out.write_bytes(b"\x00" * 4096)     # what a cut-off convert leaves
        return dict(failed)

    elog = MagicMock()
    elog.case_dir.return_value = None
    with patch("core.vmdk.snapshot_warning", return_value=None), \
         patch("core.execution_log.log", elog), \
         patch("tools.imaging.run", side_effect=_run):
        r = getattr(vmdk_export_raw, "fn", vmdk_export_raw)(desc, str(out))
    assert r["success"] is False and not out.exists()
    assert r["partial_output_removed"] == str(out)


def test_vmdk_export_force_reexport_allows(tmp_path: Path):
    from tools.imaging import vmdk_export_raw

    out = tmp_path / "analysis" / "host.raw"
    out.parent.mkdir(parents=True)
    out.write_bytes(b"\x00" * 2_000_000)
    desc = str(tmp_path / "host.vmdk")
    Path(desc).write_bytes(b"vmdk")

    ok = {
        "success": True, "stdout": "", "stderr": "", "exit_code": 0,
        "elapsed_seconds": 0.1, "truncated": False, "cmd": "qemu-img",
        "retries": 0, "progress_lines": [],
    }
    info = {
        **ok,
        "stdout": '{"virtual-size": 1000}',
    }
    elog = MagicMock()
    elog.case_dir.return_value = None

    def _run(cmd, **kwargs):
        if "info" in cmd:
            return dict(info)
        return dict(ok)

    with patch("core.vmdk.snapshot_warning", return_value=None), \
         patch("core.execution_log.log", elog), \
         patch("tools.imaging.run", side_effect=_run), \
         patch("tools.imaging.shutil.disk_usage",
               return_value=MagicMock(free=10**12)):
        r = getattr(vmdk_export_raw, "fn", vmdk_export_raw)(
            desc, str(out), force_reexport=True,
        )
    assert r.get("success") is True
