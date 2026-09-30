"""Hidden data is extracted with whichever installed extractor can read it,
the passphrase reaches each tool the way it expects, and a missing tool is
named rather than mistaken for a miss."""
import json
import os
from unittest.mock import patch

import pytest

from tools import steg


@pytest.fixture
def image(tmp_path):
    img = tmp_path / "carrier.jpg"
    img.write_bytes(b"\xff\xd8\xff\xe0 not really a jpeg")
    return str(img)


def _installed(*names):
    return lambda name: f"/usr/bin/{name}" if name in names else None


def _runner(produces, seen):
    """A fake executor: extractors in ``produces`` write output, others fail."""
    def run(cmd, **kw):
        seen.append((cmd, kw))
        program = os.path.basename(cmd[0])
        out = cmd[-1] if program != "steghide" else cmd[cmd.index("-xf") + 1]
        if program in produces:
            with open(out, "wb") as f:
                f.write(b"secret")
            return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}
        return {"success": False, "exit_code": 1, "stdout": "",
                "stderr": "could not extract any data with that passphrase!"}
    return run


def test_status_names_installed_and_missing_extractors():
    with patch.object(steg, "tool_program", _installed("steghide")):
        status = steg.steg_status()
    assert [a["program"] for a in status["available"]] == ["steghide"]
    assert [m["program"] for m in status["missing"]] == ["outguess", "jpseek"]
    assert "apt outguess" in status["missing"][0]["install"]


def test_nothing_installed_is_a_missing_program_not_a_miss(image, tmp_path):
    with patch.object(steg, "tool_program", _installed()):
        result = steg.steg_extract(image, str(tmp_path / "out"))
    assert result["success"] is False and result["gate"] == "program_missing"
    assert len(result["missing"]) == 3


def test_the_first_extractor_that_produces_data_wins(image, tmp_path):
    seen = []
    with patch.object(steg, "tool_program", _installed("steghide", "outguess", "jpseek")), \
            patch.object(steg, "run", _runner({"outguess"}, seen)):
        result = steg.steg_extract(image, str(tmp_path / "out"), passphrase="pw")
    assert result["success"] and result["method"] == "outguess"
    assert result["output_path"].endswith("carrier.jpg.outguess.out")
    assert result["artifact_paths"] == [result["output_path"]]
    assert [a["method"] for a in result["attempts"]] == ["steghide", "outguess"]
    steghide_cmd = seen[0][0]
    assert steghide_cmd[steghide_cmd.index("-p") + 1] == "pw"
    assert seen[1][0][1:3] == ["-k", "pw"]
    assert not (tmp_path / "out" / "carrier.jpg.steghide.out").exists()


def test_jpseek_gets_the_passphrase_on_stdin(image, tmp_path):
    seen = []
    contents = {}

    def run(cmd, **kw):
        with open(kw["stdin_path"]) as f:
            contents["pass"] = f.read()
        return _runner({"jpseek"}, seen)(cmd, **kw)

    with patch.object(steg, "tool_program", _installed("jpseek")), patch.object(steg, "run", run):
        result = steg.steg_extract(image, str(tmp_path / "out"), passphrase="pw", method="jpseek")
    assert result["success"] and contents["pass"] == "pw\n"
    assert not [p for p in os.listdir(tmp_path / "out") if p.startswith(".steg-pass-")]


def test_a_miss_by_every_extractor_says_what_to_try(image, tmp_path):
    with patch.object(steg, "tool_program", _installed("steghide")), \
            patch.object(steg, "run", _runner(set(), [])):
        result = steg.steg_extract(image, str(tmp_path / "out"))
    # A miss is a completed examination of the carrier, not a failed call:
    # the coverage ledger and the citation gates read the envelope's
    # success, and a negative must count as contact and be citable.
    assert result["success"] is True and result["recovered"] == []
    assert "without a passphrase" in result["negative"]
    assert result["attempts"][0]["exit_code"] == 1
    assert [m["program"] for m in result["missing"]] == ["outguess", "jpseek"]
    from core.evidence_access import parse_tool_result_success
    assert parse_tool_result_success(json.dumps(result))[0] is True


def test_an_unknown_method_and_an_uninstalled_one_are_refused(image, tmp_path):
    with patch.object(steg, "tool_program", _installed("steghide")):
        assert "unknown method" in steg.steg_extract(image, str(tmp_path / "o"), method="lsb")["error"]
        result = steg.steg_extract(image, str(tmp_path / "o"), method="outguess")
    assert result["gate"] == "program_missing" and result["program"] == "outguess"


def test_structureless_output_is_not_a_success_and_the_loop_keeps_going(image, tmp_path):
    """outguess and jpseek write bytes and exit 0 with a wrong passphrase.
    A file that is not a recognizable payload is not a success, and the next
    extractor is still tried."""
    def run(cmd, **kw):
        program = os.path.basename(cmd[0])
        out = cmd[-1] if program != "steghide" else cmd[cmd.index("-xf") + 1]
        with open(out, "wb") as f:
            f.write(bytes(range(256)) * 8 if program != "jpseek"
                    else b"\xff\xd8\xff\xe0" + b"\x00" * 512)  # noise, then a jpeg
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    with patch.object(steg, "tool_program", _installed("steghide", "outguess", "jpseek")), \
            patch.object(steg, "run", run):
        result = steg.steg_extract(image, str(tmp_path / "out"), passphrase="pw")
    assert result["success"] and result["method"] == "jpseek" and result["payload_kind"] == "jpeg"
    kinds = {a["method"]: a["payload_kind"] for a in result["attempts"]}
    assert kinds["outguess"] == "no recognizable structure"
    assert not (tmp_path / "out" / "carrier.jpg.outguess.out").exists()  # noise removed


def test_only_noise_is_reported_as_no_recognizable_payload(image, tmp_path):
    def run(cmd, **kw):
        out = cmd[-1] if os.path.basename(cmd[0]) != "steghide" else cmd[cmd.index("-xf") + 1]
        with open(out, "wb") as f:
            f.write(bytes(range(256)) * 8)
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    with patch.object(steg, "tool_program", _installed("outguess")), patch.object(steg, "run", run):
        result = steg.steg_extract(image, str(tmp_path / "out"), passphrase="pw")
    assert result["success"] is True and result["recovered"] == []
    assert "recognizable payload" in result["negative"]
    assert "wrong passphrase" in result["next_step"]


def test_classify_payload_tells_a_file_from_noise(tmp_path):
    jpeg = tmp_path / "a"; jpeg.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
    text = tmp_path / "b"; text.write_text("username=jane.doe\npassword=example\n")
    noise = tmp_path / "c"; noise.write_bytes(bytes(range(256)) * 4)
    empty = tmp_path / "d"; empty.write_bytes(b"")
    assert steg._classify_payload(str(jpeg)) == (True, "jpeg")
    assert steg._classify_payload(str(text)) == (True, "text")
    assert steg._classify_payload(str(noise)) == (False, "no recognizable structure")
    assert steg._classify_payload(str(empty)) == (False, "empty")



def test_noise_never_passes_for_a_payload(tmp_path):
    """A wrong passphrase yields random bytes. Any short byte pair turns up
    somewhere in them, so a signature is read only where its format puts it,
    and a two-byte one only with the header structure that confirms it."""
    import random
    rng = random.Random(20260929)
    out = tmp_path / "noise.out"
    for _ in range(10_000):
        out.write_bytes(rng.randbytes(4096))
        assert steg._classify_payload(str(out))[0] is False


def test_a_signature_counts_only_at_its_offset_and_with_its_structure(tmp_path):
    def kind(data):
        p = tmp_path / "x.out"
        p.write_bytes(data)
        return steg._classify_payload(str(p))

    body = bytes(range(256)) * 4
    assert kind(b"\x89PNG\r\n\x1a\n" + body) == (True, "png")
    assert kind(body[:10] + b"PK\x03\x04" + body) == (False, "no recognizable structure")
    bmp = bytearray(b"BM" + body)
    assert kind(bytes(bmp))[0] is False                       # size field does not match
    bmp[2:6] = len(bmp).to_bytes(4, "little")
    assert kind(bytes(bmp)) == (True, "bmp")
    tar = bytearray(body[:257] + b"ustar" + body)
    assert kind(bytes(tar)) == (True, "tar")
    pe = bytearray(b"MZ" + bytes(62) + body)
    pe[0x3C:0x40] = (128).to_bytes(4, "little")
    assert kind(bytes(pe))[0] is False                        # no PE header at e_lfanew
    pe[128:132] = b"PE\x00\x00"
    assert kind(bytes(pe)) == (True, "pe")


def test_a_failed_run_leaves_no_file_even_when_its_bytes_look_like_a_payload(image, tmp_path):
    def run(cmd, **kw):
        with open(cmd[-1], "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + bytes(64))
        return {"success": False, "exit_code": 1, "stdout": "", "stderr": "wrong passphrase"}

    with patch.object(steg, "tool_program", _installed("jpseek")), patch.object(steg, "run", run):
        result = steg.steg_extract(image, str(tmp_path / "out"), passphrase="pw")
    assert result["success"] is True and result["recovered"] == []
    assert list((tmp_path / "out").iterdir()) == []


def test_a_negative_says_what_it_does_not_cover(image, tmp_path):
    with patch.object(steg, "tool_program", _installed("steghide", "jpseek")):
        status = steg.steg_status()
        assert "0.3" in next(a["covers"] for a in status["available"] if a["program"] == "jpseek")
        with patch.object(steg, "run", _runner(set(), [])):
            single = steg.steg_extract(image, str(tmp_path / "a"), passphrase="pw")
            grid = steg.steg_extract([image, image], str(tmp_path / "b"), passphrase=["pw", "px"])
    assert "JPHS for Windows 0.5x" in single["next_step"]
    assert "JPHS for Windows 0.5x" in grid["next_step"]
    assert "definitive" not in grid["next_step"]

class TestCandidateGrid:
    """Several carriers and several passphrases are one call: the search
    ends in the payloads found or in a negative that names every cell."""

    @staticmethod
    def _images(tmp_path, n):
        out = []
        for i in range(n):
            p = tmp_path / f"carrier{i}.jpg"
            p.write_bytes(b"\xff\xd8\xff\xe0 carrier %d" % i)
            out.append(str(p))
        return out

    @staticmethod
    def _grid_runner(hits, seen):
        """A fake executor that writes a payload only for the (carrier,
        passphrase) cells in ``hits``; outguess writes noise everywhere."""
        def run(cmd, **kw):
            seen.append(cmd)
            program = os.path.basename(cmd[0])
            if program == "steghide":
                image, out, pw = cmd[3], cmd[5], cmd[7]
            else:
                image, out = cmd[-2], cmd[-1]
                pw = cmd[cmd.index("-k") + 1] if "-k" in cmd else ""
            if (os.path.basename(image), pw) in hits and program == "steghide":
                with open(out, "wb") as f:
                    f.write(b"the hidden note says hello")
                return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}
            if program == "outguess":
                with open(out, "wb") as f:
                    f.write(bytes(range(256)) * 4)
                return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}
            return {"success": False, "exit_code": 1, "stdout": "", "stderr": "no"}
        return run

    def test_every_cell_is_tried_and_the_negative_counts_them(self, tmp_path):
        images = self._images(tmp_path, 3)
        seen = []
        with patch.object(steg, "tool_program", _installed("steghide", "outguess")), \
                patch.object(steg, "run", self._grid_runner(set(), seen)):
            result = steg.steg_extract(images, str(tmp_path / "out"),
                                       passphrase=["", "otter", "heron"])
        assert result["success"] is True
        assert result["carriers"] == 3 and result["passphrases"] == 3
        assert result["cells_tried"] == 9 and result["recovered"] == []
        assert result["noise"] == {"outguess": 9}
        assert "3 carrier(s) x 3 passphrase(s)" in result["negative"]
        assert "disposition" in result["next_step"]
        assert len(seen) == 18   # two extractors per cell
        assert not list((tmp_path / "out").glob("*.out"))   # noise is not kept

    def test_a_hit_stops_that_carriers_column_and_the_rest_continue(self, tmp_path):
        images = self._images(tmp_path, 2)
        seen = []
        hits = {("carrier0.jpg", "otter")}
        with patch.object(steg, "tool_program", _installed("steghide")), \
                patch.object(steg, "run", self._grid_runner(hits, seen)):
            result = steg.steg_extract(images, str(tmp_path / "out"),
                                       passphrase=["", "otter", "heron"])
        assert result["success"] is True
        assert [r["passphrase"] for r in result["recovered"]] == ["otter"]
        assert result["recovered"][0]["image_path"] == images[0]
        assert result["recovered"][0]["payload_kind"] == "text"
        # carrier0: "", otter (hit); carrier1: all three
        assert result["cells_tried"] == 5
        assert result["artifact_paths"] == [result["recovered"][0]["output_path"]]

    def test_one_carrier_one_passphrase_keeps_the_single_result_shape(self, image, tmp_path):
        seen = []
        with patch.object(steg, "tool_program", _installed("steghide")), \
                patch.object(steg, "run", _runner({"steghide"}, seen)):
            result = steg.steg_extract([image], str(tmp_path / "out"), passphrase=["pw"])
        assert result["success"] and result["method"] == "steghide"
        assert "attempts" in result and "cells_tried" not in result

    def test_a_missing_carrier_is_named_before_anything_runs(self, image, tmp_path):
        seen = []
        with patch.object(steg, "tool_program", _installed("steghide")), \
                patch.object(steg, "run", _runner({"steghide"}, seen)):
            result = steg.steg_extract([image, str(tmp_path / "gone.jpg")],
                                       str(tmp_path / "out"))
        assert result["success"] is False and "gone.jpg" in result["error"]
        assert seen == []
