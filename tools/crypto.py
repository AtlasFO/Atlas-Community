"""Symmetric decryption — first-class AES/RC4 decrypt for ransomware/CTF/crypto cases.

Atlas could *identify* an encrypted artifact and a key candidate but had no way to
actually decrypt it (only base64/hex/XOR-brute deob existed), so crypto cases
stalled at `strings`. This module closes that gap: given a file, an algorithm, a
key, and (where relevant) an IV/mode, it decrypts in-process using the
`cryptography` library and returns the plaintext path plus a hexdump/printable
preview, a detected file type, and — critically — a heuristic verdict so a wrong
key surfaces as "high-entropy/non-printable output, key or mode likely wrong"
rather than a traceback.

Read-only toward evidence; output is written only under analysis/ (or an
explicit output_path validated by @output_safe). Everything runs in-process.
"""
from __future__ import annotations

import base64
import math
import os
import re
from collections import Counter
from typing import Optional

from fastmcp import FastMCP
from core import DEFAULT_TIMEOUT, output_safe, run
from core.paths import assert_output_safe
from core.timeout import with_tool_timeout

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as _sym_padding

# RC4/ARC4 moved to the `decrepit` module in modern cryptography; fall back to
# the legacy location for older installs.
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
except ImportError:  # pragma: no cover - depends on cryptography version
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

mcp = FastMCP("crypto")

# Cap on returned preview text so decrypting a large blob can't blow the context.
_PREVIEW_CAP = 8000
_HEXDUMP_BYTES = 256

_AES_MODES = ("cbc", "ecb", "ctr", "gcm")
_KEY_ENCODINGS = ("utf8", "hex", "base64")
# GCM auth tags are 16 bytes and, by convention here, appended to the ciphertext
# when not supplied separately.
_GCM_TAG_LEN = 16


def _record_marker(tool_name: str, success: bool, summary: dict) -> None:
    """Log an in-process tool call to the execution trace, mirroring
    tools/deobfuscation.py so the audit story stays complete."""
    try:
        import json
        from core.execution_log import log
        log.record_tool_call(
            cmd=f"<py>:{tool_name}",
            success=success, truncated=False, retries=0,
            exit_code=0 if success else 1, stderr="", elapsed_seconds=0.0,
            stdout_excerpt=json.dumps(summary, sort_keys=True)[:600],
        )
    except Exception:
        pass


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(data)


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. ~8.0 = random/encrypted/compressed."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def _preview(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    if len(text) > _PREVIEW_CAP:
        return text[:_PREVIEW_CAP] + f"\n… [{len(text) - _PREVIEW_CAP} more chars]"
    return text


def _hexdump(data: bytes, limit: int = _HEXDUMP_BYTES) -> str:
    """A small `hexdump -C`-style dump of the first `limit` bytes."""
    chunk = data[:limit]
    lines = []
    for off in range(0, len(chunk), 16):
        row = chunk[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        hex_part = f"{hex_part:<47}"
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"{off:08x}  {hex_part}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(f"… [{len(data) - limit} more bytes]")
    return "\n".join(lines)


def _detect_type(path: str) -> str:
    """Reuse libmagic via `file`, the same identification strings.file_identify
    relies on. Returns "" if `file` is unavailable so callers degrade cleanly."""
    try:
        r = run(["file", "-b", path])
        if r.get("success"):
            return (r.get("stdout") or "").strip()[:200]
    except Exception:
        pass
    return ""


def _decode_material(material: str, encoding: str, label: str) -> bytes:
    enc = (encoding or "utf8").lower()
    if enc in ("utf8", "utf-8", "ascii", "raw", "str", "utf"):
        return material.encode("utf-8")
    if enc == "hex":
        cleaned = re.sub(r"(0x|\\x|[\s:,])", "", material)
        return bytes.fromhex(cleaned)
    if enc in ("base64", "b64"):
        return base64.b64decode(material + "=" * (-len(material) % 4))
    raise ValueError(
        f"unknown {label} encoding '{encoding}' — use one of {', '.join(_KEY_ENCODINGS)}")


def _err(msg: str, hint: str = "") -> dict:
    out = {"success": False, "error": msg}
    if hint:
        out["hint"] = hint
    return out


@mcp.tool()
@output_safe
@with_tool_timeout(DEFAULT_TIMEOUT, label="crypto_decrypt")
def decrypt(
    input_path: str,
    algo: str,
    key: str | list[str],
    iv: str = "",
    mode: str = "cbc",
    key_encoding: str = "utf8",
    output_path: str = "",
    iv_encoding: str = "",
    aad: str = "",
    tag: str = "",
    strip_padding: bool = True,
) -> dict:
    """
    Decrypt a symmetrically-encrypted file (AES or RC4) and write the plaintext.

    This is the decrypt step Atlas was missing for ransomware/CTF/crypto cases:
    once you have identified an encrypted artifact and a key candidate, call this
    to actually recover the plaintext instead of broad-searching with `strings`.

    Parameters
      input_path   : file to decrypt (evidence is read-only; only read here).
      algo         : "aes" or "rc4" (aka "arc4").
      key          : key material, interpreted per key_encoding; one key or a
                     list of candidate keys tried in turn (the first whose
                     plaintext is not flagged likely_wrong_key is the result,
                     and every key tried is reported).
      iv           : IV / nonce / initial counter, per iv_encoding (unused for
                     AES-ECB and RC4). For AES-GCM this is the nonce.
      mode         : AES mode — cbc | ecb | ctr | gcm (ignored for RC4).
      key_encoding : how `key` is encoded — utf8 | hex | base64.
      output_path  : where to write plaintext (must be outside evidence; defaults
                     to ./analysis/decrypted/<name>.dec).
      iv_encoding  : encoding for iv/tag; defaults to key_encoding.
      aad          : additional authenticated data (AES-GCM only), utf8.
      tag          : AES-GCM auth tag (per iv_encoding). If omitted, the last 16
                     bytes of the ciphertext are used as the tag.
      strip_padding: strip PKCS7 padding for CBC/ECB (default True).

    Returns the plaintext path, a hexdump + printable preview, the detected file
    type, entropy/printable stats, and `likely_wrong_key` — set True with a hint
    when the output looks high-entropy or non-printable (wrong key/mode/IV).
    """
    from core.candidates import candidates
    keys = candidates(key)
    if not keys:
        return _err("key is empty", "Pass the key material, or a list of candidate keys.")
    result: dict = {}
    for candidate in keys:
        result = _decrypt_one(input_path, algo, candidate, iv, mode, key_encoding,
                              output_path, iv_encoding, aad, tag, strip_padding)
        if result.get("success") and not result.get("likely_wrong_key"):
            break
    if len(keys) > 1:
        result["keys_tried"] = len(keys)
        if result.get("success") and not result.get("likely_wrong_key"):
            result["key_used"] = candidate
        else:
            result["hint"] = (
                f"none of the {len(keys)} candidate keys produced plausible plaintext "
                "(the last attempt is reported); the key material, IV, mode or "
                "encoding is wrong for all of them.")
    return result


def _decrypt_one(
    input_path: str,
    algo: str,
    key: str,
    iv: str,
    mode: str,
    key_encoding: str,
    output_path: str,
    iv_encoding: str,
    aad: str,
    tag: str,
    strip_padding: bool,
) -> dict:
    """One key against the ciphertext; the body of ``decrypt``."""
    algo_l = (algo or "").lower().strip()
    if algo_l in ("arc4", "rc4-drop", "rc-4"):
        algo_l = "rc4"
    mode_l = (mode or "cbc").lower().strip()
    iv_enc = iv_encoding or key_encoding

    if algo_l not in ("aes", "rc4"):
        return _err(f"unsupported algorithm '{algo}'",
                    "Supported: aes (cbc/ecb/ctr/gcm), rc4.")

    if not os.path.isfile(input_path):
        return _err(f"input file not found: {input_path}")

    # Decode key material.
    try:
        key_bytes = _decode_material(key, key_encoding, "key")
    except Exception as e:
        return _err(f"could not decode key: {e}",
                    "Check key_encoding (utf8 | hex | base64) matches the key.")

    try:
        with open(input_path, "rb") as fh:
            ciphertext = fh.read()
    except OSError as e:
        return _err(f"could not read input: {e}")
    if not ciphertext:
        return _err("input file is empty")

    # Build the algorithm/mode and validate lengths up front so bad inputs
    # produce a clear message instead of a library traceback.
    try:
        if algo_l == "rc4":
            if not 1 <= len(key_bytes) <= 256:
                return _err(f"RC4 key must be 1–256 bytes, got {len(key_bytes)}")
            algorithm = ARC4(key_bytes)
            cipher_mode = None
        else:  # aes
            if len(key_bytes) not in (16, 24, 32):
                return _err(
                    f"AES key must be 16/24/32 bytes, got {len(key_bytes)}",
                    "A hex key looks twice as long as its bytes; try "
                    "key_encoding=hex or base64 if the key is encoded.")
            if mode_l not in _AES_MODES:
                return _err(f"unsupported AES mode '{mode}'",
                            f"Supported modes: {', '.join(_AES_MODES)}.")
            algorithm = algorithms.AES(key_bytes)

            iv_bytes = _decode_material(iv, iv_enc, "iv") if iv else b""
            if mode_l == "ecb":
                cipher_mode = modes.ECB()
            elif mode_l == "cbc":
                if len(iv_bytes) != 16:
                    return _err(
                        f"AES-CBC needs a 16-byte IV, got {len(iv_bytes)}",
                        "Provide iv= (and iv_encoding= if it is hex/base64).")
                cipher_mode = modes.CBC(iv_bytes)
            elif mode_l == "ctr":
                if len(iv_bytes) != 16:
                    return _err(
                        f"AES-CTR needs a 16-byte counter/nonce, got {len(iv_bytes)}",
                        "Provide iv= (the 16-byte initial counter block).")
                cipher_mode = modes.CTR(iv_bytes)
            else:  # gcm
                if not iv_bytes:
                    return _err("AES-GCM needs a nonce (iv=)",
                                "GCM nonces are typically 12 bytes.")
                if tag:
                    tag_bytes = _decode_material(tag, iv_enc, "tag")
                    gcm_ct = ciphertext
                else:
                    # Convention: tag is appended to the ciphertext.
                    if len(ciphertext) < _GCM_TAG_LEN:
                        return _err(
                            "ciphertext shorter than a 16-byte GCM tag",
                            "Pass the tag explicitly via tag= if it is stored "
                            "separately from the ciphertext.")
                    gcm_ct = ciphertext[:-_GCM_TAG_LEN]
                    tag_bytes = ciphertext[-_GCM_TAG_LEN:]
                cipher_mode = modes.GCM(iv_bytes, tag_bytes)
    except Exception as e:
        return _err(f"could not decode iv/tag: {e}",
                    "Check iv_encoding matches the iv/tag encoding.")

    # Decrypt.
    padding_status = "not-applicable"
    try:
        decryptor = Cipher(algorithm, cipher_mode).decryptor()
        if algo_l == "aes" and mode_l == "gcm":
            if aad:
                decryptor.authenticate_additional_data(aad.encode("utf-8"))
            try:
                plaintext = decryptor.update(gcm_ct) + decryptor.finalize()
            except Exception:
                # InvalidTag — authentication failed; this is a hard, unambiguous
                # "wrong key/nonce/tag/AAD" signal, so fail loudly (no garbage).
                _record_marker("crypto_decrypt", False,
                               {"algo": "aes", "mode": "gcm", "auth": "failed"})
                return _err(
                    "AES-GCM authentication failed — the ciphertext is not "
                    "authentic under this key/nonce/tag/AAD.",
                    "Wrong key, nonce (iv), tag, or AAD. GCM verifies "
                    "integrity, so no plaintext is produced on mismatch.")
        else:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        return _err(f"decryption failed: {e}")

    # Strip PKCS7 padding for block modes when asked. Invalid padding is a strong
    # (though not certain) wrong-key signal for CBC/ECB — keep the raw bytes and
    # flag it rather than raising.
    padding_bad = False
    if strip_padding and algo_l == "aes" and mode_l in ("cbc", "ecb"):
        try:
            unpadder = _sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
            padding_status = "pkcs7-stripped"
        except Exception:
            padding_status = "pkcs7-invalid"
            padding_bad = True

    # Resolve + write the plaintext. Default under ./analysis/decrypted/.
    if output_path:
        out = output_path
    else:
        base = os.path.join(os.getcwd(), "analysis", "decrypted")
        out = os.path.join(base, os.path.basename(input_path) + ".dec")
    assert_output_safe(out)
    try:
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(plaintext)
    except OSError as e:
        return _err(f"could not write output: {e}")

    # Quality heuristic — is this plausibly real plaintext, or still garbage?
    entropy = _entropy(plaintext)
    pratio = _printable_ratio(plaintext)
    detected = _detect_type(out)
    recognized = bool(detected) and not detected.lower().startswith(
        ("data", "empty", "very short"))

    if recognized:
        likely_wrong = False
    elif padding_bad:
        likely_wrong = True
    elif pratio >= 0.85:
        likely_wrong = False
    elif entropy >= 7.5:
        likely_wrong = True
    else:
        likely_wrong = entropy >= 7.0 and pratio < 0.75

    result = {
        "success": True,
        "input_path": input_path,
        "output_path": out,
        "algo": algo_l,
        "mode": None if algo_l == "rc4" else mode_l,
        "key_encoding": key_encoding.lower(),
        "decrypted_bytes": len(plaintext),
        "printable_ratio": round(pratio, 3),
        "entropy": round(entropy, 3),
        "padding": padding_status,
        "detected_type": detected,
        "likely_wrong_key": likely_wrong,
        "hexdump": _hexdump(plaintext),
        "preview": _preview(plaintext[:_PREVIEW_CAP]),
    }
    if likely_wrong:
        result["hint"] = (
            "Decryption produced high-entropy / non-printable output — the key, "
            "IV, or mode is probably wrong. Verify the key material and "
            "key_encoding, and try a different mode "
            f"({', '.join(m for m in _AES_MODES if m != mode_l)}).")
    _record_marker("crypto_decrypt", True, {
        "algo": algo_l, "mode": result["mode"], "bytes": len(plaintext),
        "likely_wrong_key": likely_wrong, "detected_type": detected})
    return result


@mcp.tool()
@with_tool_timeout(DEFAULT_TIMEOUT, label="crypto_algorithms")
def algorithms_supported() -> dict:
    """List the algorithms, AES modes, and key encodings crypto.decrypt supports."""
    return {
        "success": True,
        "algorithms": ["aes", "rc4"],
        "aes_modes": list(_AES_MODES),
        "key_encodings": list(_KEY_ENCODINGS),
    }
