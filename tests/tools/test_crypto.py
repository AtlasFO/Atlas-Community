"""Tests for tools/crypto.py — real AES/RC4 round trips with test-generated keys.

No case-specific key or flag material appears here: keys/IVs are either
generated inside the test with os.urandom or fixed synthetic byte patterns,
and plaintexts are synthetic.
"""
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as _sym_padding


def _aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = _sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


class TestAesCbcRoundTrip:
    def test_recovers_plaintext_with_correct_key(self, tmp_path):
        from tools.crypto import decrypt
        plain = b"the quick brown fox jumps over the lazy dog\n" * 3
        key, iv = os.urandom(32), os.urandom(16)
        blob = tmp_path / "confidential.enc"
        blob.write_bytes(_aes_cbc_encrypt(plain, key, iv))
        out = tmp_path / "recovered.bin"

        r = decrypt(
            str(blob), algo="aes", key=key.hex(), iv=iv.hex(),
            mode="cbc", key_encoding="hex", iv_encoding="hex",
            output_path=str(out),
        )
        assert r["success"] is True
        assert r["likely_wrong_key"] is False
        assert r["padding"] == "pkcs7-stripped"
        assert out.read_bytes() == plain
        assert "quick brown fox" in r["preview"]

    def test_wrong_key_yields_graceful_failure_signal(self, tmp_path):
        from tools.crypto import decrypt
        plain = b"the quick brown fox jumps over the lazy dog\n" * 3
        # Fixed synthetic key material: a random wrong key produces
        # PKCS7-valid garbage ~1/256 of the time, which made this test flaky.
        # This key/iv/wrong_key triple is known to yield invalid padding.
        key = bytes(range(32))
        iv = bytes(range(16))
        wrong_key = bytes(range(1, 33))
        blob = tmp_path / "confidential.enc"
        blob.write_bytes(_aes_cbc_encrypt(plain, key, iv))
        out = tmp_path / "garbage.bin"

        r = decrypt(
            str(blob), algo="aes", key=wrong_key.hex(), iv=iv.hex(),
            mode="cbc", key_encoding="hex", iv_encoding="hex",
            output_path=str(out),
        )
        # The tool ran (no traceback) but flagged the result as wrong.
        assert r["success"] is True
        assert r["padding"] == "pkcs7-invalid"
        assert r["likely_wrong_key"] is True
        assert "hint" in r
        assert out.read_bytes() != plain


class TestCandidateKeys:
    def test_the_key_that_yields_plaintext_is_found_among_candidates(self, tmp_path):
        """Several candidate keys are one call: the first whose plaintext is
        not flagged wins and is named, and the count of keys tried is
        reported."""
        from tools.crypto import decrypt
        plain = b"the quick brown fox jumps over the lazy dog\n" * 3
        key, iv = bytes(range(32)), bytes(range(16))
        wrong = bytes(range(1, 33))
        blob = tmp_path / "confidential.enc"
        blob.write_bytes(_aes_cbc_encrypt(plain, key, iv))
        out = tmp_path / "recovered.bin"
        r = decrypt(str(blob), algo="aes", key=[wrong.hex(), key.hex()], iv=iv.hex(),
                    mode="cbc", key_encoding="hex", iv_encoding="hex",
                    output_path=str(out))
        assert r["success"] is True and r["likely_wrong_key"] is False
        assert r["key_used"] == key.hex() and r["keys_tried"] == 2
        assert out.read_bytes() == plain

    def test_when_no_candidate_fits_the_last_attempt_is_reported_with_the_count(self, tmp_path):
        from tools.crypto import decrypt
        plain = b"the quick brown fox jumps over the lazy dog\n" * 3
        key, iv = bytes(range(32)), bytes(range(16))
        blob = tmp_path / "confidential.enc"
        blob.write_bytes(_aes_cbc_encrypt(plain, key, iv))
        r = decrypt(str(blob), algo="aes",
                    key=[bytes(range(1, 33)).hex(), bytes(range(2, 34)).hex()],
                    iv=iv.hex(), mode="cbc", key_encoding="hex", iv_encoding="hex",
                    output_path=str(tmp_path / "g.bin"))
        assert r["keys_tried"] == 2 and "key_used" not in r
        assert "2 candidate keys" in r["hint"]


class TestOtherModes:
    def test_rc4_round_trip(self, tmp_path):
        from tools.crypto import decrypt
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import ARC4
        plain = b"RC4 stream cipher plaintext payload"
        key = os.urandom(16)
        enc = Cipher(ARC4(key), None).encryptor()
        ct = enc.update(plain) + enc.finalize()
        blob = tmp_path / "rc4.enc"
        blob.write_bytes(ct)
        out = tmp_path / "rc4.dec"

        r = decrypt(str(blob), algo="rc4", key=key.hex(),
                    key_encoding="hex", output_path=str(out))
        assert r["success"] is True
        assert out.read_bytes() == plain

    def test_aes_gcm_round_trip_and_auth_failure(self, tmp_path):
        from tools.crypto import decrypt
        plain = b"authenticated GCM secret"
        key, nonce = os.urandom(32), os.urandom(12)
        enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        ct = enc.update(plain) + enc.finalize()
        # Tool convention: tag appended to ciphertext.
        blob = tmp_path / "gcm.enc"
        blob.write_bytes(ct + enc.tag)
        out = tmp_path / "gcm.dec"

        r = decrypt(str(blob), algo="aes", key=key.hex(), iv=nonce.hex(),
                    mode="gcm", key_encoding="hex", iv_encoding="hex",
                    output_path=str(out))
        assert r["success"] is True
        assert out.read_bytes() == plain

        # A wrong key must fail authentication loudly, not emit garbage.
        r2 = decrypt(str(blob), algo="aes", key=os.urandom(32).hex(),
                     iv=nonce.hex(), mode="gcm", key_encoding="hex",
                     iv_encoding="hex", output_path=str(tmp_path / "x.dec"))
        assert r2["success"] is False
        assert "authentication failed" in r2["error"].lower()


class TestGracefulErrors:
    def test_bad_key_length(self, tmp_path):
        from tools.crypto import decrypt
        blob = tmp_path / "x.enc"
        blob.write_bytes(os.urandom(64))
        r = decrypt(str(blob), algo="aes", key="tooshort", iv="0" * 32,
                    mode="cbc", key_encoding="utf8", iv_encoding="hex")
        assert r["success"] is False
        assert "16/24/32" in r["error"]

    def test_wrong_iv_length(self, tmp_path):
        from tools.crypto import decrypt
        blob = tmp_path / "x.enc"
        blob.write_bytes(os.urandom(64))
        r = decrypt(str(blob), algo="aes", key=os.urandom(32).hex(),
                    iv="00", mode="cbc", key_encoding="hex", iv_encoding="hex")
        assert r["success"] is False
        assert "16-byte IV" in r["error"]

    def test_missing_input(self):
        from tools.crypto import decrypt
        r = decrypt("/no/such/file", algo="rc4", key="0011", key_encoding="hex")
        assert r["success"] is False
        assert "not found" in r["error"]

    def test_output_into_evidence_blocked(self, tmp_path):
        from tools.crypto import decrypt
        blob = tmp_path / "x.enc"
        blob.write_bytes(os.urandom(32))
        import pytest
        with pytest.raises(Exception):
            decrypt(str(blob), algo="rc4", key="0011", key_encoding="hex",
                    output_path="/cases/x/evidence/out.dec")


class TestManifest:
    def test_registered_in_capability_manifest(self):
        from tools.tool_capabilities import allowed_tool_names, capability_for_tool
        allowed = allowed_tool_names()
        assert "crypto.decrypt" in allowed
        assert capability_for_tool("crypto.decrypt") == "decryption"

    def test_algorithms_lister(self):
        from tools.crypto import algorithms_supported
        r = algorithms_supported()
        assert r["success"] is True
        assert "aes" in r["algorithms"] and "rc4" in r["algorithms"]
        assert "gcm" in r["aes_modes"]
