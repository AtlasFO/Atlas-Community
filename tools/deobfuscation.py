"""Deobfuscation helpers — pure-Python decoders for maldoc / script triage.

CyberChef-style decode chains, XOR brute force, base64 hunting, and a
PowerShell -EncodedCommand unwrapper. Everything runs in-process (no external
binaries except the optional JS beautifier), and nothing writes to evidence.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import zlib
from typing import Optional

from fastmcp import FastMCP
from core import DEFAULT_TIMEOUT, output_safe
from core.paths import assert_output_safe
from core.timeout import with_tool_timeout

mcp = FastMCP("deob")

# Cap on returned text so a decode of a large blob can never blow the context.
_PREVIEW_CAP = 8000


def _record_marker(tool_name: str, success: bool, summary: dict) -> None:
    """Log an in-process tool call to the execution trace, mirroring the
    convention in tools/network.py so the audit story stays complete."""
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


def _preview(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    if len(text) > _PREVIEW_CAP:
        return text[:_PREVIEW_CAP] + f"\n… [{len(text) - _PREVIEW_CAP} more chars]"
    return text


def _apply_op(data: bytes, op: str) -> bytes:
    op = op.lower().strip()
    if op == "base64":
        return base64.b64decode(data + b"=" * (-len(data) % 4))
    if op == "base32":
        pad = data.upper() + b"=" * (-len(data) % 8)
        return base64.b32decode(pad)
    if op == "hex":
        cleaned = re.sub(rb"(0x|\\x|[\s:,])", b"", data)
        return binascii.unhexlify(cleaned)
    if op == "url":
        from urllib.parse import unquote_to_bytes
        return unquote_to_bytes(data.decode("latin-1"))
    if op == "rot13":
        return codecs.encode(data.decode("latin-1"), "rot_13").encode("latin-1")
    if op == "gzip":
        return gzip.decompress(data)
    if op == "zlib":
        return zlib.decompress(data)
    if op == "utf16le":
        return data.decode("utf-16-le", errors="replace").encode("utf-8")
    if op == "reverse":
        return data[::-1]
    raise ValueError(f"unknown operation: {op}")


_SUPPORTED_OPS = ("base64", "base32", "hex", "url", "rot13", "gzip", "zlib",
                  "utf16le", "reverse")


@mcp.tool()
@with_tool_timeout(DEFAULT_TIMEOUT, label="deob_decode_chain")
def decode_chain(data: str, operations: list[str]) -> dict:
    """
    Apply a CyberChef-style chain of decode operations to a string, in order.

    Supported operations: base64, base32, hex, url, rot13, gzip, zlib,
    utf16le, reverse. Returns each intermediate stage so you can see where a
    layer fails.
    """
    current = data.encode("latin-1", errors="replace")
    stages = []
    for op in operations:
        try:
            current = _apply_op(current, op)
        except Exception as e:
            stages.append({"op": op, "success": False, "error": str(e)})
            _record_marker("deob_decode_chain", False,
                           {"failed_op": op, "stages": len(stages)})
            return {"success": False, "stages": stages,
                    "error": f"operation '{op}' failed: {e}"}
        stages.append({"op": op, "success": True,
                       "printable_ratio": round(_printable_ratio(current), 3),
                       "preview": _preview(current)})
    _record_marker("deob_decode_chain", True, {"ops": operations})
    return {"success": True, "operations": operations, "stages": stages,
            "result": _preview(current)}


@mcp.tool()
@with_tool_timeout(DEFAULT_TIMEOUT, label="deob_hex_decode")
def hex_decode(data: str) -> dict:
    """Decode a hex string, tolerating 0x / \\x prefixes, spaces, and colons."""
    try:
        raw = _apply_op(data.encode("latin-1"), "hex")
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "printable_ratio": round(_printable_ratio(raw), 3),
            "result": _preview(raw)}


@mcp.tool()
@with_tool_timeout(DEFAULT_TIMEOUT, label="deob_xor_bruteforce")
def xor_bruteforce(
    file_path: str,
    key_max_len: int = 1,
    plaintext_hints: Optional[list[str]] = None,
    max_bytes: int = 65536,
) -> dict:
    """
    Brute-force XOR keys against the start of a file and rank candidates.

    Tries every single-byte key (and, when key_max_len >= 2, repeating
    two-byte keys). Candidates are scored by printable ratio and by hits on
    plaintext_hints (defaults include 'http', 'This program', 'MZ', 'powershell').
    Returns the top 10 keys with decoded previews.
    """
    try:
        with open(file_path, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError as e:
        return {"success": False, "error": str(e), "file": file_path}

    hints = [h.lower().encode() for h in
             (plaintext_hints or ["http", "This program", "MZ", "powershell",
                                  "cmd", "\\x4d\\x5a"])]

    def score(dec: bytes) -> tuple[float, int]:
        low = dec.lower()
        hits = sum(1 for h in hints if h in low)
        return (_printable_ratio(dec) + hits, hits)

    keys: list[bytes] = [bytes([k]) for k in range(256)]
    if key_max_len >= 2:
        # A tractable slice of 2-byte space: printable-ASCII key bytes only.
        printable = range(32, 127)
        keys += [bytes([a, b]) for a in printable for b in printable]

    scored = []
    for key in keys:
        dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        s, hits = score(dec)
        scored.append((s, hits, key, dec))
    scored.sort(key=lambda t: t[0], reverse=True)

    top = [{
        "key_hex": key.hex(),
        "key_len": len(key),
        "score": round(s, 3),
        "hint_hits": hits,
        "printable_ratio": round(_printable_ratio(dec), 3),
        "preview": _preview(dec[:512]),
    } for s, hits, key, dec in scored[:10]]
    _record_marker("deob_xor_bruteforce", True,
                   {"file": file_path, "best_key": top[0]["key_hex"] if top else None})
    return {"success": True, "file": file_path, "bytes_scanned": len(data),
            "candidates": top}


@mcp.tool()
@with_tool_timeout(DEFAULT_TIMEOUT, label="deob_base64_hunt")
def base64_hunt(file_path: str, min_len: int = 16) -> dict:
    """
    Find base64 blobs in a file, decode them, and keep the ones that look real.

    Scans for [A-Za-z0-9+/=] runs of at least min_len, attempts a decode, and
    keeps results that are mostly printable or start with a known magic (MZ,
    PK, %PDF). Also reports a UTF-16LE reading of each decode (PowerShell).
    """
    try:
        with open(file_path, "rb") as fh:
            text = fh.read().decode("latin-1", errors="replace")
    except OSError as e:
        return {"success": False, "error": str(e), "file": file_path}

    magics = (b"MZ", b"PK\x03\x04", b"%PDF", b"\x7fELF")
    found = []
    for m in re.finditer(rf"[A-Za-z0-9+/]{{{max(min_len, 4)},}}={{0,2}}", text):
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception:
            continue
        if len(dec) < 4:
            continue
        interesting = (_printable_ratio(dec) > 0.85
                       or any(dec.startswith(mg) for mg in magics))
        if not interesting:
            continue
        utf16 = dec.decode("utf-16-le", errors="replace") if len(dec) % 2 == 0 else ""
        found.append({
            "offset": m.start(),
            "encoded_len": len(blob),
            "decoded_len": len(dec),
            "magic": next((mg.decode("latin-1", "replace")
                           for mg in magics if dec.startswith(mg)), None),
            "preview": _preview(dec[:400]),
            "utf16le_preview": utf16[:400] if utf16.isprintable() else "",
        })
        if len(found) >= 50:
            break
    _record_marker("deob_base64_hunt", True,
                   {"file": file_path, "count": len(found)})
    return {"success": True, "file": file_path, "count": len(found),
            "blobs": found}


@mcp.tool()
@with_tool_timeout(DEFAULT_TIMEOUT, label="deob_powershell_decode")
def powershell_decode(command_line: str) -> dict:
    """
    Unwrap an obfuscated PowerShell command line.

    Detects -EncodedCommand / -enc (base64 + UTF-16LE), then applies
    normalization passes: strips backticks, resolves simple string concat,
    joins [char]NN sequences, and collapses -join/format tricks. Returns each
    layer so you can follow the deobfuscation.
    """
    layers = []
    text = command_line

    # Layer 1: -EncodedCommand
    enc = re.search(r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})",
                    text, re.IGNORECASE)
    if enc:
        try:
            raw = base64.b64decode(enc.group(1) + "=" * (-len(enc.group(1)) % 4))
            decoded = raw.decode("utf-16-le", errors="replace")
            layers.append({"pass": "encodedcommand", "result": _preview(decoded.encode())})
            text = decoded
        except Exception as e:
            layers.append({"pass": "encodedcommand", "error": str(e)})

    # Layer 2: iterative normalization to a fixpoint.
    for _ in range(10):
        before = text
        text = text.replace("`", "")                       # escape backticks
        text = re.sub(r"['\"]\s*\+\s*['\"]", "", text)     # 'a'+'b' -> ab
        # [char]65 / [char]0x41 -> 'A'
        text = re.sub(r"\[char\]\s*(0x[0-9a-fA-F]+|\d+)",
                      lambda m: chr(int(m.group(1), 0)), text, flags=re.IGNORECASE)
        text = text.replace("\x00", "")
        if text == before:
            break
    layers.append({"pass": "normalized", "result": _preview(text.encode())})

    _record_marker("deob_powershell_decode", True,
                   {"had_encodedcommand": bool(enc), "layers": len(layers)})
    return {"success": True, "encoded_command_found": bool(enc),
            "layers": layers, "result": _preview(text.encode())}


@mcp.tool()
@output_safe
@with_tool_timeout(DEFAULT_TIMEOUT, label="deob_js_beautify")
def js_beautify(file_path: str, output_path: Optional[str] = None) -> dict:
    """
    Beautify minified/obfuscated JavaScript using jsbeautifier (pure-Python).

    Returns the beautified source, or writes it to output_path (must be under
    analysis/ or exports/). Requires `pip install jsbeautifier`.
    """
    try:
        import jsbeautifier
    except ImportError:
        return {"success": False,
                "error": "jsbeautifier not installed — pip install jsbeautifier"}
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as e:
        return {"success": False, "error": str(e), "file": file_path}
    pretty = jsbeautifier.beautify(src)
    if output_path:
        assert_output_safe(output_path)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(pretty)
        _record_marker("deob_js_beautify", True, {"output_path": output_path})
        return {"success": True, "file": file_path, "output_path": output_path,
                "lines": pretty.count("\n") + 1}
    _record_marker("deob_js_beautify", True, {"file": file_path})
    return {"success": True, "file": file_path, "result": _preview(pretty.encode())}


@mcp.tool()
@with_tool_timeout(DEFAULT_TIMEOUT, label="deob_supported_ops")
def supported_ops() -> dict:
    """List the operations available for decode_chain."""
    return {"success": True, "operations": list(_SUPPORTED_OPS)}
