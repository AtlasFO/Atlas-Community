"""Tests for tools/hashing.py."""
import os
import csv
import hashlib
import pytest
from unittest.mock import patch
from tools.hashing import (
    hash_file,
    hash_directory,
    verify_evidence_hash,
    ssdeep_hash,
    ssdeep_compare,
    ssdeep_scan_directory,
    hashdeep_compute,
    hashdeep_audit,
    md5deep_scan,
)


KNOWN_CONTENT = b"Atlas test content 12345"
KNOWN_MD5 = hashlib.md5(KNOWN_CONTENT).hexdigest()
KNOWN_SHA1 = hashlib.sha1(KNOWN_CONTENT).hexdigest()
KNOWN_SHA256 = hashlib.sha256(KNOWN_CONTENT).hexdigest()


@pytest.fixture
def test_file(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(KNOWN_CONTENT)
    return str(f)


class TestHashFile:
    def test_correct_md5(self, test_file):
        r = hash_file(test_file)
        assert r["success"] is True
        assert r["md5"] == KNOWN_MD5

    def test_correct_sha1(self, test_file):
        r = hash_file(test_file)
        assert r["sha1"] == KNOWN_SHA1

    def test_correct_sha256(self, test_file):
        r = hash_file(test_file)
        assert r["sha256"] == KNOWN_SHA256

    def test_correct_size(self, test_file):
        r = hash_file(test_file)
        assert r["size_bytes"] == len(KNOWN_CONTENT)

    def test_file_not_found(self):
        r = hash_file("/nonexistent/file.bin")
        assert r["success"] is False
        assert "error" in r

    def test_returns_file_path(self, test_file):
        r = hash_file(test_file)
        assert r["file"] == test_file


class TestHashFileCache:
    @pytest.fixture(autouse=True)
    def isolate_cache(self, tmp_path, monkeypatch):
        """Redirect the hash cache to a per-test tmp path and reset module state."""
        import tools.hashing as h
        cache_path = str(tmp_path / "hash_cache.json")
        monkeypatch.setattr(h, "_HASH_CACHE_PATH", cache_path)
        monkeypatch.setattr(h, "_HASH_CACHE", None)
        yield
        monkeypatch.setattr(h, "_HASH_CACHE", None)

    def test_first_call_is_cache_miss(self, test_file):
        r = hash_file(test_file)
        assert r["success"] is True
        assert r.get("cache_hit") is False

    def test_second_call_is_cache_hit(self, test_file):
        r1 = hash_file(test_file)
        r2 = hash_file(test_file)
        assert r1["cache_hit"] is False
        assert r2["cache_hit"] is True
        assert r1["sha256"] == r2["sha256"]

    def test_cache_invalidated_when_mtime_changes(self, test_file):
        import os, time
        r1 = hash_file(test_file)
        time.sleep(1.1)
        with open(test_file, "wb") as f:
            f.write(KNOWN_CONTENT + b"-modified")
        # Touch mtime so it definitely changes
        os.utime(test_file, None)
        r2 = hash_file(test_file)
        assert r2["cache_hit"] is False
        assert r2["sha256"] != r1["sha256"]


class TestHashDirectory:
    def test_hashes_all_files(self, tmp_path):
        for i in range(3):
            (tmp_path / f"file{i}.bin").write_bytes(f"content{i}".encode())
        r = hash_directory(str(tmp_path))
        assert r["success"] is True
        assert r["file_count"] == 3

    def test_sha256_algorithm(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"data")
        r = hash_directory(str(tmp_path), algorithm="sha256")
        assert r["algorithm"] == "sha256"
        assert "sha256" in r["hashes"][0]

    def test_unknown_algorithm_fails(self, tmp_path):
        r = hash_directory(str(tmp_path), algorithm="blake3")
        assert r["success"] is False

    def test_output_manifest_written(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"data")
        manifest = str(tmp_path / "manifest.csv")
        r = hash_directory(str(tmp_path), output_manifest=manifest)
        assert os.path.exists(manifest)
        with open(manifest) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 2  # header + 1 file

    def test_output_manifest_evidence_path_blocked(self, tmp_path):
        with pytest.raises(ValueError, match="protected evidence"):
            hash_directory(str(tmp_path), output_manifest="/cases/example/manifest.csv")

    def test_non_recursive(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "top.bin").write_bytes(b"top")
        (sub / "nested.bin").write_bytes(b"nested")
        r = hash_directory(str(tmp_path), recursive=False)
        assert r["file_count"] == 1


class TestVerifyEvidenceHash:
    def test_no_expected_hashes(self, test_file):
        r = verify_evidence_hash(test_file)
        assert r["success"] is True
        assert r["md5_match"] is None
        assert r["sha1_match"] is None

    def test_correct_md5_match(self, test_file):
        r = verify_evidence_hash(test_file, expected_md5=KNOWN_MD5)
        assert r["md5_match"] is True
        assert r["integrity_verified"] is True

    def test_wrong_md5_mismatch(self, test_file):
        r = verify_evidence_hash(test_file, expected_md5="deadbeef" * 4)
        assert r["md5_match"] is False
        assert r["integrity_verified"] is False

    def test_correct_sha1_match(self, test_file):
        r = verify_evidence_hash(test_file, expected_sha1=KNOWN_SHA1)
        assert r["sha1_match"] is True

    def test_case_insensitive_comparison(self, test_file):
        r = verify_evidence_hash(test_file, expected_md5=KNOWN_MD5.upper())
        assert r["md5_match"] is True

    def test_file_not_found(self):
        r = verify_evidence_hash("/nonexistent.img")
        assert r["success"] is False


class TestVerifyEvidenceHashState:
    """Hash verification: successful verify_evidence_hash records state in the execution log."""

    def test_state_recorded_on_success(self, test_file, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("HV-001", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            verify_evidence_hash(test_file)
        entries = [e for e in l._entries if e.get("tool") == "hash_verify_evidence_hash"]
        assert len(entries) == 1
        assert entries[0]["conclusion"].startswith("VERIFIED:")
        assert test_file in entries[0]["conclusion"]

    def test_has_evidence_been_verified_returns_true(self, test_file, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("HV-002", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            verify_evidence_hash(test_file)
        assert l.has_evidence_been_verified(test_file) is True

    def test_has_evidence_been_verified_returns_false_for_unverified(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("HV-003", str(tmp_path / "trace.json"))
        assert l.has_evidence_been_verified("/never/seen.img") is False

    def test_state_not_recorded_on_failure(self, tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("HV-004", str(tmp_path / "trace.json"))
        with patch("core.execution_log.log", l):
            verify_evidence_hash("/nonexistent.img")
        entries = [e for e in l._entries if e.get("tool") == "hash_verify_evidence_hash"]
        assert entries == []


class TestSsdeepTools:
    @patch("tools.hashing.run")
    def test_ssdeep_hash(self, mock_run, run_ok, test_file):
        mock_run.return_value = run_ok
        r = ssdeep_hash(test_file)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "ssdeep" in cmd

    @patch("tools.hashing.run")
    def test_ssdeep_compare(self, mock_run, run_ok, test_file):
        mock_run.return_value = run_ok
        ssdeep_compare(test_file, test_file)
        cmd = mock_run.call_args[0][0]
        assert "-d" in cmd

    @patch("tools.hashing.run")
    def test_ssdeep_scan_directory(self, mock_run, run_ok, tmp_path):
        mock_run.return_value = run_ok
        ssdeep_scan_directory(str(tmp_path), threshold=70)
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd
        assert "70" in cmd


class TestHashdeepTools:
    @patch("tools.hashing.run")
    def test_hashdeep_compute_basic(self, mock_run, run_ok, tmp_path):
        mock_run.return_value = run_ok
        hashdeep_compute(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "hashdeep" in cmd

    @patch("tools.hashing.run")
    def test_hashdeep_compute_recursive(self, mock_run, run_ok, tmp_path):
        (tmp_path / "sub").mkdir()
        mock_run.return_value = run_ok
        hashdeep_compute(str(tmp_path), recursive=True)
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd

    @patch("tools.hashing.run")
    def test_hashdeep_compute_writes_output(self, mock_run, run_ok, tmp_path):
        output = str(tmp_path / "manifest.txt")
        mock_run.return_value = {**run_ok, "stdout": "hashdeep output"}
        r = hashdeep_compute(str(tmp_path), output_path=output)
        assert os.path.exists(output)
        assert r["manifest_path"] == output

    @patch("tools.hashing.run")
    def test_hashdeep_audit(self, mock_run, run_ok, tmp_path):
        mock_run.return_value = run_ok
        hashdeep_audit("manifest.txt", str(tmp_path), mode="audit")
        cmd = mock_run.call_args[0][0]
        assert "-a" in cmd
        assert "-k" in cmd

    @patch("tools.hashing.run")
    def test_md5deep_scan(self, mock_run, run_ok, tmp_path):
        mock_run.return_value = run_ok
        md5deep_scan(str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert "md5deep" in cmd
        assert "-r" in cmd


class TestVerifyEvidenceHashPolicy:
    """Size-capped custody hashing: large evidence defers to a sampled
    fingerprint instead of reading every byte (a flat VMDK of hundreds of GB
    on a network mount takes hours to hash before any analysis starts)."""

    @pytest.fixture(autouse=True)
    def isolate_cache(self, tmp_path, monkeypatch):
        import tools.hashing as h
        monkeypatch.setattr(h, "_HASH_CACHE_PATH",
                            str(tmp_path / "hash_cache.json"))
        monkeypatch.setattr(h, "_HASH_CACHE", None)
        yield
        monkeypatch.setattr(h, "_HASH_CACHE", None)

    @pytest.fixture
    def big_file(self, tmp_path, monkeypatch):
        """A sparse file just over a monkeypatched 1 GB cap."""
        import core.paths
        monkeypatch.setattr(core.paths, "FULL_HASH_MAX_GB", 1)
        p = tmp_path / "big-flat.vmdk"
        with open(p, "wb") as f:
            f.truncate(1024 ** 3 + 4096)
        return str(p)

    def test_large_file_defers_to_sampled_fingerprint(self, big_file):
        r = verify_evidence_hash(big_file)
        assert r["success"] is True
        assert r["full_hash"] is False
        assert r["deferred"] is True
        assert len(r["sampled_sha256"]) == 64
        assert "md5" not in r
        assert "ATLAS_FULL_HASH_MAX_GB" in r["note"]

    def test_force_full_overrides_cap(self, big_file):
        r = verify_evidence_hash(big_file, force_full=True)
        assert r["success"] is True
        assert r["full_hash"] is True
        assert len(r["md5"]) == 32

    def test_expected_hash_forces_full_hash(self, big_file):
        r = verify_evidence_hash(big_file, expected_md5="0" * 32)
        assert r["full_hash"] is True
        assert r["md5_match"] is False

    def test_small_file_still_fully_hashed(self, test_file):
        r = verify_evidence_hash(test_file)
        assert r["full_hash"] is True
        assert r["md5"] == KNOWN_MD5

    def test_cap_disabled_means_always_full(self, test_file, monkeypatch):
        import core.paths
        monkeypatch.setattr(core.paths, "FULL_HASH_MAX_GB", 0)
        r = verify_evidence_hash(test_file)
        assert r["full_hash"] is True

    def test_deferred_recorded_as_deferred_not_verified(self, big_file,
                                                        tmp_path):
        from core.execution_log import ExecutionLog
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"), save_session=False)
        with patch("core.execution_log.log", l):
            verify_evidence_hash(big_file)
        entries = [e for e in l._entries
                   if e.get("tool") == "hash_verify_evidence_hash"]
        assert len(entries) == 1
        assert entries[0]["conclusion"].startswith("DEFERRED:")
        assert l.has_evidence_been_verified(big_file) is False

    def test_sampled_fingerprint_is_cached(self, big_file):
        r1 = verify_evidence_hash(big_file)
        r2 = verify_evidence_hash(big_file)
        assert r1["cache_hit"] is False
        assert r2["cache_hit"] is True
        assert r1["sampled_sha256"] == r2["sampled_sha256"]

    def test_sampled_fingerprint_sensitive_to_tail(self, tmp_path,
                                                   monkeypatch):
        import core.paths
        monkeypatch.setattr(core.paths, "FULL_HASH_MAX_GB", 1)
        a = tmp_path / "a.img"
        b = tmp_path / "b.img"
        size = 1024 ** 3 + 4096
        for p, tail in ((a, b"A"), (b, b"B")):
            with open(p, "wb") as f:
                f.truncate(size - 1)
                f.seek(size - 1)
                f.write(tail)
        ra = verify_evidence_hash(str(a))
        rb = verify_evidence_hash(str(b))
        assert ra["sampled_sha256"] != rb["sampled_sha256"]

    def test_missing_file_fails(self, monkeypatch):
        import core.paths
        monkeypatch.setattr(core.paths, "FULL_HASH_MAX_GB", 1)
        r = verify_evidence_hash("/nonexistent/huge.vmdk")
        assert r["success"] is False


class TestNetworkPathDetection:
    def test_network_fstype_detected(self, tmp_path):
        from core.paths import is_network_path, path_fstype
        target = tmp_path / "share" / "evidence.vmdk"
        target.parent.mkdir()
        target.write_bytes(b"x")
        fake_mounts = tmp_path / "mounts"
        fake_mounts.write_text(
            "sysfs /sys sysfs rw 0 0\n"
            f"//nas/ir {tmp_path}/share cifs rw 0 0\n"
            f"/dev/sda1 / ext4 rw 0 0\n")
        assert path_fstype(str(target),
                           proc_mounts=str(fake_mounts)) == "cifs"
        assert is_network_path(str(target),
                               proc_mounts=str(fake_mounts)) is True

    def test_local_fstype_not_network(self, tmp_path):
        from core.paths import is_network_path
        target = tmp_path / "evidence.img"
        target.write_bytes(b"x")
        fake_mounts = tmp_path / "mounts"
        fake_mounts.write_text("/dev/sda1 / ext4 rw 0 0\n")
        assert is_network_path(str(target),
                               proc_mounts=str(fake_mounts)) is False

    def test_wsl2_9p_share_is_network(self, tmp_path):
        from core.paths import is_network_path
        target = tmp_path / "evd" / "img.vmdk"
        target.parent.mkdir()
        target.write_bytes(b"x")
        fake_mounts = tmp_path / "mounts"
        fake_mounts.write_text(
            f"drvfs {tmp_path}/evd 9p rw,dirsync 0 0\n"
            "/dev/sdb / ext4 rw 0 0\n")
        assert is_network_path(str(target),
                               proc_mounts=str(fake_mounts)) is True

    def test_escaped_mountpoint_with_space(self, tmp_path):
        from core.paths import path_fstype
        share = tmp_path / "my share"
        share.mkdir()
        target = share / "x.bin"
        target.write_bytes(b"x")
        esc = str(share).replace(" ", "\\040")
        fake_mounts = tmp_path / "mounts"
        fake_mounts.write_text(f"//nas/a {esc} nfs4 rw 0 0\n")
        assert path_fstype(str(target),
                           proc_mounts=str(fake_mounts)) == "nfs4"


EWFINFO = """ewfinfo 20140816

Acquiry information
\tCase number:\t\t1
Media information
\tMedia type:\t\tfixed disk
\tNumber of sectors:\t9514260
\tMedia size:\t\t4.5 GiB (4871301120 bytes)

Digest hash information
\tMD5:\t\t\taee4fcd9301c03b3b054623ca261959a
"""
EWFVERIFY_OK = """MD5 hash stored in file:\t\taee4fcd9301c03b3b054623ca261959a
MD5 hash calculated over data:\t\taee4fcd9301c03b3b054623ca261959a

ewfverify: SUCCESS
"""


class TestEwfAcquisition:
    """An Expert Witness image stores the digest computed over the imaged
    media. The custody hash attests the segment files; the stored digest,
    re-computed by ewfverify, attests the media - the image integrity a
    report states first."""

    @pytest.fixture(autouse=True)
    def isolate_cache(self, tmp_path, monkeypatch):
        import tools.hashing as h
        monkeypatch.setattr(h, "_HASH_CACHE_PATH", str(tmp_path / "hash_cache.json"))
        monkeypatch.setattr(h, "_HASH_CACHE", None)
        yield
        monkeypatch.setattr(h, "_HASH_CACHE", None)

    @staticmethod
    def _run(verify_text=EWFVERIFY_OK, verify_ok=True, info_ok=True):
        def run(cmd, **kw):
            if cmd[0] == "ewfinfo":
                return ({"success": True, "stdout": EWFINFO, "stderr": ""} if info_ok
                        else {"success": False, "stdout": "", "stderr": "ewfinfo: not an EWF file"})
            if cmd[0] == "ewfverify":
                return {"success": verify_ok, "stdout": verify_text, "stderr": ""}
            raise AssertionError(cmd)
        return run

    def test_the_stored_digest_is_read_and_verified(self, tmp_path):
        img = tmp_path / "notebook.E01"; img.write_bytes(b"EVF" * 100)
        with patch("tools.hashing.run", side_effect=self._run()) as run:
            r = verify_evidence_hash(str(img))
        assert r["success"] and r["full_hash"] is True
        assert r["acquisition_hashes"] == {"md5": "aee4fcd9301c03b3b054623ca261959a"}
        assert r["acquisition_verified"] is True
        assert r["media_size_bytes"] == 4871301120
        assert [c.args[0][0] for c in run.call_args_list] == ["ewfinfo", "ewfverify"]

    def test_a_mismatch_is_reported_as_false(self, tmp_path):
        img = tmp_path / "notebook.E01"; img.write_bytes(b"EVF" * 100)
        text = EWFVERIFY_OK.replace("SUCCESS", "FAILURE")
        with patch("tools.hashing.run", side_effect=self._run(text, verify_ok=False)):
            r = verify_evidence_hash(str(img))
        assert r["success"] and r["acquisition_verified"] is False

    def test_a_raw_image_is_left_alone(self, tmp_path):
        img = tmp_path / "disk.raw"; img.write_bytes(b"\x00" * 512)
        with patch("tools.hashing.run", side_effect=self._run()) as run:
            r = verify_evidence_hash(str(img))
        assert r["success"] and "acquisition_hashes" not in r
        run.assert_not_called()

    def test_media_above_the_policy_is_read_but_not_rehashed(self, tmp_path, monkeypatch):
        import core.paths
        monkeypatch.setattr(core.paths, "FULL_HASH_MAX_GB", 1)   # the segment file is tiny, the media 4.5 GB
        img = tmp_path / "notebook.E01"; img.write_bytes(b"EVF" * 100)
        with patch("tools.hashing.run", side_effect=self._run()) as run:
            r = verify_evidence_hash(str(img))
        assert r["acquisition_hashes"]["md5"].startswith("aee4")
        assert r["acquisition_verified"] is None and "ATLAS_FULL_HASH_MAX_GB" in r["acquisition_note"]
        assert [c.args[0][0] for c in run.call_args_list] == ["ewfinfo"]
        with patch("tools.hashing.run", side_effect=self._run()) as run:
            r = verify_evidence_hash(str(img), force_full=True)
        assert r["acquisition_verified"] is True

    def test_a_missing_tool_never_fails_the_custody_hash(self, tmp_path):
        img = tmp_path / "notebook.E01"; img.write_bytes(b"EVF" * 100)
        with patch("tools.hashing.run", side_effect=self._run(info_ok=False)):
            r = verify_evidence_hash(str(img))
        assert r["success"] and len(r["md5"]) == 32
        assert "not an EWF file" in r["acquisition_error"] and "acquisition_hashes" not in r

    def test_the_trace_conclusion_names_the_digest_and_its_verdict(self, tmp_path):
        from core.execution_log import ExecutionLog
        img = tmp_path / "notebook.E01"; img.write_bytes(b"EVF" * 100)
        l = ExecutionLog()
        l.configure("TEST", str(tmp_path / "trace.json"), save_session=False)
        with patch("core.execution_log.log", l), \
                patch("tools.hashing.run", side_effect=self._run()):
            verify_evidence_hash(str(img))
        entry = [e for e in l._entries if e.get("tool") == "hash_verify_evidence_hash"][-1]
        assert "acquisition_md5=aee4fcd9301c03b3b054623ca261959a (verified by ewfverify)" in entry["conclusion"]
