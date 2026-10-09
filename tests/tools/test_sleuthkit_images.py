"""A disk tool called on an image that is not on disk names the images the case has."""


class TestAMissingImageNamesTheImagesTheCaseHas:
    """A model that writes an export's name from memory gets the case's
    real image names back, not the library's stat error."""

    def test_the_refusal_lists_the_registered_images(self, tmp_path):
        import json
        from unittest.mock import MagicMock, patch
        from tools.sleuthkit import tsk_mmls
        (tmp_path / ".atlas").mkdir()
        (tmp_path / ".atlas" / "mount_plan.json").write_text(json.dumps({"images": [
            {"basename": "host.vmdk"},
            {"origin": "export_raw", "path": str(tmp_path / "analysis" / "exports" / "host.raw")},
        ]}))
        elog = MagicMock()
        elog.case_dir.return_value = str(tmp_path)
        with patch("core.execution_log.log", elog):
            out = getattr(tsk_mmls, "fn", tsk_mmls)("analysis/exports/host_raw.img")
        assert out["success"] is False and out["gate"] == "image_not_found"
        assert "analysis/exports/host.raw" in out["error"] and "host.vmdk" in out["error"]

    def test_an_existing_image_is_not_refused(self, tmp_path):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_mmls
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00" * 512)
        with patch("tools.sleuthkit.run", return_value={"success": True, "stdout": "", "stderr": ""}) as run:
            getattr(tsk_mmls, "fn", tsk_mmls)(str(img))
        run.assert_called_once()


def test_an_absent_component_answers_with_the_path_not_found_gate(tmp_path):
    """The resolver walked to the parent and the component is not there: the
    reply carries what was there instead, under a gate the failure latch
    reads as an answer."""
    from unittest.mock import patch
    from tools.sleuthkit import tsk_resolve_path
    img = tmp_path / "disk.raw"
    img.write_bytes(b"\x00" * 512)
    listing = {"success": True, "stdout": "d/d 39-144-1:\tWindows\nd/d 40-144-1:\tSystem32\n",
               "stderr": "", "truncated": False}
    with patch("tools.sleuthkit.run", return_value=listing):
        out = getattr(tsk_resolve_path, "fn", tsk_resolve_path)(str(img), "Windows/sru")
    assert out["success"] is False and out["gate"] == "path_not_found"
    assert out["missing"] == "sru" and "System32" in out["siblings"]


def test_a_second_walk_reuses_the_listings_already_read(tmp_path):
    """Resolving a sibling path lists only the directory not read before:
    an image does not change while a run reads it, and re-running fls for
    the root at every walk logged the same listing to the trace each time."""
    from unittest.mock import patch
    from tools import sleuthkit
    from tools.sleuthkit import tsk_resolve_path
    sleuthkit._LISTINGS.clear()
    img = tmp_path / "disk.raw"
    img.write_bytes(b"\x00" * 512)
    listings = {
        None: "d/d 134-144-4:\tProgram Files\nd/d 3671-144-7:\tDocuments and Settings\n",
        134: "d/d 11737-144-5:\tLook@LAN\nd/d 9947-144-5:\tCain\n",
        11737: "r/r 11776-128-3:\tirunin.ini\n",
        9947: "r/r 9958-128-3:\tAbel.dll\n",
    }

    def run(cmd, **kw):
        inode = int(cmd[-1]) if cmd[-1].isdigit() else None
        return {"success": True, "stdout": listings[inode], "stderr": "", "truncated": False}

    fn = getattr(tsk_resolve_path, "fn", tsk_resolve_path)
    with patch("tools.sleuthkit.run", side_effect=run) as mocked:
        first = fn(str(img), "Program Files/Look@LAN/irunin.ini")
        second = fn(str(img), "Program Files/Cain/Abel.dll")
    assert first["success"] and first["inode"] == "11776-128-3"
    assert second["success"] and second["inode"] == "9958-128-3"
    walked = [int(c.args[0][-1]) if c.args[0][-1].isdigit() else None for c in mocked.call_args_list]
    assert walked == [None, 134, 11737, 9947]
    sleuthkit._LISTINGS.clear()


class TestAnEwfImageIsReadThroughItsDevice:
    """The Sleuth Kit reads raw images. Given an Expert Witness container it
    reads the raw device ewfmount exposes when one is mounted, and names
    what to mount when none is - instead of reporting the compressed
    container as an encrypted volume."""

    @staticmethod
    def _case(tmp_path, monkeypatch, *, mounted):
        import core.paths
        case = tmp_path / "case"
        (case / "evidence").mkdir(parents=True)
        image = case / "evidence" / "notebook.E01"
        image.write_bytes(b"EVF" * 64)
        if mounted:
            dev = case / "mnt" / "notebook" / "ewf" / "ewf1"
            dev.parent.mkdir(parents=True)
            dev.write_bytes(b"\x00" * 512)
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(case))
        return case, str(image)

    def test_a_mounted_image_is_read_through_ewf1(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_fls
        case, image = self._case(tmp_path, monkeypatch, mounted=True)
        listing = {"success": True, "stdout": "d/d 5-144-1:\tWindows\n", "stderr": "", "truncated": False}
        with patch("tools.sleuthkit.run", return_value=listing) as run:
            out = getattr(tsk_fls, "fn", tsk_fls)(image, offset_sectors=63)
        assert out["success"]
        assert run.call_args.args[0][-1] == str(case / "mnt" / "notebook" / "ewf" / "ewf1")
        assert out["image_resolved"] == {"from": image, "to": str(case / "mnt" / "notebook" / "ewf" / "ewf1")}

    def test_an_unmounted_image_gets_the_mount_recipe_not_an_entropy_message(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_fls
        _case, image = self._case(tmp_path, monkeypatch, mounted=False)
        with patch("tools.sleuthkit.run") as run:
            out = getattr(tsk_fls, "fn", tsk_fls)(image)
        run.assert_not_called()
        assert out["success"] is False and out["gate"] == "image_format"
        assert "ewf.ewf_mount" in out["error"] and "ewf1" in out["error"]
        assert "compressed" in out["error"]

    def test_a_raw_image_is_read_as_given(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_fls
        import core.paths
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(tmp_path))
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00" * 512)
        with patch("tools.sleuthkit.run", return_value={"success": True, "stdout": "", "stderr": ""}) as run:
            out = getattr(tsk_fls, "fn", tsk_fls)(str(img), offset_sectors=2048)
        assert out["success"] and "image_resolved" not in out
        assert run.call_args.args[0][-1] == str(img)


class TestAFilesystemToolFindsTheLoneVolume:
    """A filesystem tool given a whole-disk image and no offset reads the
    partition table and, when it names exactly one volume, reads that
    volume; with several it lists them and asks."""

    MMLS_ONE = ("DOS Partition Table\nUnits are in 512-byte sectors\n\n"
                "      Slot      Start        End          Length       Description\n"
                "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
                "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
                "002:  000:000   0000002048   0000204799   0000202752   NTFS / exFAT (0x07)\n")
    MMLS_TWO = MMLS_ONE + "003:  000:001   0000204800   0000409599   0000204800   Linux (0x83)\n"

    @staticmethod
    def _run(mmls_text):
        def run(cmd, **kw):
            if cmd[0] == "mmls":
                return {"success": True, "stdout": mmls_text, "stderr": ""}
            if "-o" in cmd:
                return {"success": True, "stdout": "r/r 5-144-1:\t$MFT\n", "stderr": "",
                        "offset": cmd[cmd.index("-o") + 1]}
            return {"success": False, "stdout": "", "stderr": "Cannot determine file system type"}
        return run

    def test_one_volume_is_read_at_its_offset(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_fls
        import core.paths
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(tmp_path))
        img = tmp_path / "stick.raw"; img.write_bytes(b"\x00" * 512)
        with patch("tools.sleuthkit.run", side_effect=self._run(self.MMLS_ONE)) as run:
            out = getattr(tsk_fls, "fn", tsk_fls)(str(img))
        assert out["success"] and out["offset_sectors_used"] == 2048 and out["offset"] == "2048"
        assert [c.args[0][0] for c in run.call_args_list] == ["fls", "mmls", "fls"]

    def test_several_volumes_are_listed_not_guessed(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_fsstat
        import core.paths
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(tmp_path))
        img = tmp_path / "disk.raw"; img.write_bytes(b"\x00" * 512)
        with patch("tools.sleuthkit.run", side_effect=self._run(self.MMLS_TWO)) as run:
            out = getattr(tsk_fsstat, "fn", tsk_fsstat)(str(img))
        assert out["success"] is False
        assert "offset_sectors=2048" in out["hint"] and "offset_sectors=204800" in out["hint"]
        assert [c.args[0][0] for c in run.call_args_list] == ["fsstat", "mmls"]

    def test_an_offset_the_caller_gave_is_never_second_guessed(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_fls
        import core.paths
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(tmp_path))
        img = tmp_path / "disk.raw"; img.write_bytes(b"\x00" * 512)
        failing = {"success": False, "stdout": "", "stderr": "Cannot determine file system type"}
        with patch("tools.sleuthkit.run", return_value=failing) as run:
            out = getattr(tsk_fls, "fn", tsk_fls)(str(img), 63)
        assert out["success"] is False and run.call_count == 1

    def test_a_path_walk_finds_the_lone_volume_and_remembers_it(self, tmp_path, monkeypatch):
        """A path walk reports the listing's failure as its own error; it
        still reads the lone volume, and later calls default to its offset."""
        from unittest.mock import patch
        from core.mount_plan import volume_offset
        from tools import sleuthkit
        from tools.sleuthkit import tsk_resolve_path
        import core.paths
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(tmp_path))
        sleuthkit._LISTINGS.clear()
        img = tmp_path / "CORP-WS02.raw"; img.write_bytes(b"\x00" * 512)

        def run(cmd, **kw):
            if cmd[0] == "mmls":
                return {"success": True, "stdout": self.MMLS_ONE, "stderr": ""}
            if "-o" in cmd:
                return {"success": True, "stderr": "",
                        "stdout": "d/d 29-144-1:\tC\nr/r 64-128-1:\tnotes.txt\n"}
            return {"success": False, "stdout": "", "stderr": "Cannot determine file system type"}

        with patch("tools.sleuthkit.run", side_effect=run):
            out = getattr(tsk_resolve_path, "fn", tsk_resolve_path)(str(img), "C")
        assert out["success"] and out["offset_sectors_used"] == 2048
        assert volume_offset(tmp_path, img) == 2048


class TestAMountedFilesystemDirectoryIsReadThroughItsDevice:
    """A mounted filesystem directory is not an image; the Sleuth Kit gets
    the device the filesystem was mounted from, or a refusal that says what
    the directory is, instead of a raw-open error about a directory."""

    def test_the_convention_sibling_device_is_used(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_fls
        import core.paths
        case = tmp_path / "case"
        fs = case / "mnt" / "host" / "fs"; fs.mkdir(parents=True)
        dev = case / "mnt" / "host" / "ewf" / "ewf1"; dev.parent.mkdir(parents=True); dev.write_bytes(b"\x00" * 512)
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(case))
        with patch("tools.sleuthkit.run", return_value={"success": True, "stdout": "d/d 5-144-1:\tWindows\n", "stderr": ""}) as run:
            out = getattr(tsk_fls, "fn", tsk_fls)(str(fs), offset_sectors=2048)
        assert out["success"] and run.call_args.args[0][-1] == str(dev)
        assert out["image_resolved"] == {"from": str(fs), "to": str(dev)}

    def test_the_plans_recorded_device_wins(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from core.mount_plan import save_mount_plan
        from tools.sleuthkit import tsk_fls
        import core.paths
        case = tmp_path / "case"; (case / ".atlas").mkdir(parents=True)
        fs = case / "mnt" / "manual" / "root"; fs.mkdir(parents=True)
        dev = case / "mnt" / "manual" / "ewf1"; dev.write_bytes(b"\x00" * 512)
        save_mount_plan(case, {"images": [{"path": str(case / "evidence" / "d.E01"),
                                            "mount_result": {"mount_point": str(fs), "ewf_device": str(dev)}}]})
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(case))
        with patch("tools.sleuthkit.run", return_value={"success": True, "stdout": "", "stderr": ""}) as run:
            out = getattr(tsk_fls, "fn", tsk_fls)(str(fs), offset_sectors=63)
        assert out["success"] and run.call_args.args[0][-1] == str(dev)

    def test_a_directory_with_no_device_is_refused_with_what_it_is(self, tmp_path, monkeypatch):
        from unittest.mock import patch
        from tools.sleuthkit import tsk_fls
        import core.paths
        monkeypatch.setattr(core.paths, "active_case_dir", lambda: str(tmp_path))
        d = tmp_path / "somedir"; d.mkdir()
        with patch("tools.sleuthkit.run") as run:
            out = getattr(tsk_fls, "fn", tsk_fls)(str(d))
        run.assert_not_called()
        assert out["success"] is False and out["gate"] == "image_format"
        assert "mounted filesystem" in out["error"] and "raw device" in out["error"]
