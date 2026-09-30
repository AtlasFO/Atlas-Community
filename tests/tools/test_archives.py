"""Tests for tools/archives.py — Zip Slip / zip-bomb guards and format handling.

Evidence archives are untrusted input, so these tests care most about the
refusal paths: a crafted member name that would land outside output_dir, a
symlink member, and an archive that decompresses past the size cap.
"""
import gzip
import tarfile
import zipfile

import pytest

from tools import archives


# ── zip_extract ────────────────────────────────────────────────────────────

class TestZipExtract:
    def test_round_trip(self, tmp_path):
        archive = tmp_path / "evidence.zip"
        out = tmp_path / "out"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("notes.txt", "hello evidence")
            zf.writestr("sub/nested.txt", "nested content")

        r = archives.zip_extract(str(archive), str(out))

        assert r["success"] is True
        assert r["member_count"] == 2
        assert (out / "notes.txt").read_text() == "hello evidence"
        assert (out / "sub" / "nested.txt").read_text() == "nested content"

    def test_password_arg_does_not_break_unencrypted_extraction(self, tmp_path):
        # stdlib zipfile can only *read* encrypted zips, not write them, so a
        # real wrong-password rejection can't be exercised here without a
        # pre-built encrypted fixture. This just confirms passing `password`
        # doesn't interfere with a normal (unencrypted) extraction.
        archive = tmp_path / "plain.zip"
        out = tmp_path / "out"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("notes.txt", "hidden")

        r = archives.zip_extract(str(archive), str(out), password="unused")

        assert r["success"] is True
        assert (out / "notes.txt").read_text() == "hidden"

    def test_refuses_zip_slip(self, tmp_path):
        archive = tmp_path / "evil.zip"
        out = tmp_path / "out"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../../../tmp/evil.txt", "escaped")

        r = archives.zip_extract(str(archive), str(out))

        assert r["success"] is False
        assert "Zip Slip" in r["error"] or "outside output_dir" in r["error"]
        assert not (tmp_path / "tmp" / "evil.txt").exists()

    def test_refuses_zip_bomb(self, tmp_path, monkeypatch):
        monkeypatch.setattr(archives, "MAX_UNCOMPRESSED_BYTES", 10)
        archive = tmp_path / "bomb.zip"
        out = tmp_path / "out"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("big.txt", "x" * 1000)

        r = archives.zip_extract(str(archive), str(out))

        assert r["success"] is False
        assert "zip bomb" in r["error"]
        assert not (out / "big.txt").exists()

    def test_rejects_non_zip(self, tmp_path):
        not_a_zip = tmp_path / "fake.zip"
        not_a_zip.write_text("this is plain text, not a zip")

        r = archives.zip_extract(str(not_a_zip), str(tmp_path / "out"))

        assert r["success"] is False
        assert "not a zip" in r["error"]


# ── tar_extract ────────────────────────────────────────────────────────────

class TestTarExtract:
    def test_round_trip(self, tmp_path):
        src = tmp_path / "notes.txt"
        src.write_text("hello tar")
        archive = tmp_path / "evidence.tar.gz"
        out = tmp_path / "out"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(src, arcname="notes.txt")

        r = archives.tar_extract(str(archive), str(out))

        assert r["success"] is True
        assert (out / "notes.txt").read_text() == "hello tar"

    def test_refuses_path_traversal_member(self, tmp_path):
        archive = tmp_path / "evil.tar"
        out = tmp_path / "out"
        src = tmp_path / "payload.txt"
        src.write_text("escaped")
        with tarfile.open(archive, "w") as tf:
            tf.add(src, arcname="../../../tmp/evil.txt")

        r = archives.tar_extract(str(archive), str(out))

        assert r["success"] is False
        assert "outside output_dir" in r["error"]

    def test_refuses_symlink_member(self, tmp_path):
        archive = tmp_path / "evil_symlink.tar"
        out = tmp_path / "out"
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        with tarfile.open(archive, "w") as tf:
            tf.addfile(info)

        r = archives.tar_extract(str(archive), str(out))

        assert r["success"] is False
        assert "symlink" in r["error"]

    def test_refuses_tar_bomb(self, tmp_path, monkeypatch):
        monkeypatch.setattr(archives, "MAX_UNCOMPRESSED_BYTES", 10)
        archive = tmp_path / "bomb.tar"
        out = tmp_path / "out"
        src = tmp_path / "big.txt"
        src.write_text("x" * 1000)
        with tarfile.open(archive, "w") as tf:
            tf.add(src, arcname="big.txt")

        r = archives.tar_extract(str(archive), str(out))

        assert r["success"] is False
        assert "zip bomb" in r["error"]

    def test_rejects_non_tar(self, tmp_path):
        not_a_tar = tmp_path / "fake.tar"
        not_a_tar.write_text("this is plain text, not a tar")

        r = archives.tar_extract(str(not_a_tar), str(tmp_path / "out"))

        assert r["success"] is False
        assert "not a tar-family archive" in r["error"]


# ── gzip_extract ───────────────────────────────────────────────────────────

class TestGzipExtract:
    def test_round_trip(self, tmp_path):
        archive = tmp_path / "evidence.txt.gz"
        with gzip.open(archive, "wb") as f:
            f.write(b"hello gzip")
        out = tmp_path / "evidence.txt"

        r = archives.gzip_extract(str(archive), str(out))

        assert r["success"] is True
        assert out.read_bytes() == b"hello gzip"

    def test_rejects_bad_magic(self, tmp_path):
        not_gz = tmp_path / "fake.gz"
        not_gz.write_text("not actually gzipped")

        r = archives.gzip_extract(str(not_gz), str(tmp_path / "out.txt"))

        assert r["success"] is False
        assert "not gzip-compressed" in r["error"]

    def test_refuses_gzip_bomb(self, tmp_path, monkeypatch):
        monkeypatch.setattr(archives, "MAX_UNCOMPRESSED_BYTES", 10)
        archive = tmp_path / "bomb.gz"
        with gzip.open(archive, "wb") as f:
            f.write(b"x" * 1000)

        r = archives.gzip_extract(str(archive), str(tmp_path / "out.txt"))

        assert r["success"] is False
        assert "gzip bomb" in r["error"]
        assert not (tmp_path / "out.txt").exists()


# ── external-binary tools: graceful absence ────────────────────────────────

class TestExternalBinaryGracefulAbsence:
    def test_7z_not_installed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(archives.shutil, "which", lambda name: None)
        r = archives.archive_extract_7z(str(tmp_path / "x.7z"), str(tmp_path / "out"))
        assert r["success"] is False
        assert "p7zip-full" in r["error"]

    def test_rar_not_installed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(archives.shutil, "which", lambda name: None)
        r = archives.archive_extract_rar(str(tmp_path / "x.rar"), str(tmp_path / "out"))
        assert r["success"] is False
        assert "unrar" in r["error"]


class TestCandidatePasswords:
    def test_the_password_that_opens_the_archive_is_reported(self, tmp_path, monkeypatch):
        """Candidates are tried in turn; the first that extracts wins and is
        named. The stdlib cannot write encrypted zips, so the extractor is
        stood in for by the outcome each password would have had."""
        outcomes = {"wrong": {"success": False, "error": "Bad password"},
                    "right": {"success": True, "member_count": 1}}
        r = archives._with_candidates(lambda pw: dict(outcomes[pw]), ["wrong", "right"])
        assert r["success"] is True and r["password_used"] == "right"

    def test_when_none_opens_it_the_count_is_reported(self):
        r = archives._with_candidates(
            lambda pw: {"success": False, "error": f"Bad password ({pw})"}, ["a", "b", "c"])
        assert r["success"] is False and r["passwords_tried"] == 3
        assert "(c)" in r["error"] and "3 candidate passwords" in r["hint"]

    def test_no_candidate_means_one_attempt_without_a_password(self):
        seen = []

        def extract(pw):
            seen.append(pw)
            return {"success": True}
        r = archives._with_candidates(extract, None)
        assert seen == [None] and "password_used" not in r

    def test_a_list_reaches_the_zip_extractor(self, tmp_path):
        archive = tmp_path / "plain.zip"
        out = tmp_path / "out"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("a.txt", "x")
        r = archives.zip_extract(str(archive), str(out), password=["guess1", "guess2"])
        assert r["success"] is True and r["password_used"] == "guess1"
