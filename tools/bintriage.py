"""Binary triage — binwalk, Detect It Easy, TLSH, radare2/rizin, UPX.

Complements the existing capa/floss/densityscout tools with
structure-level triage of a suspect binary. Every tool degrades gracefully
when its underlying binary (or the optional py-tlsh wheel) is absent, and
nothing writes into evidence directories.
"""
from __future__ import annotations

import json
import shutil
from typing import Optional

from fastmcp import FastMCP
from core import run, output_safe
from core.paths import assert_output_safe

mcp = FastMCP("bintriage")


def _missing(binary: str) -> dict:
    return {"success": False,
            "error": f"'{binary}' not found on PATH — install it to use this tool."}


@mcp.tool()
@output_safe
def binwalk_scan(file_path: str, entropy: bool = False,
                 opcodes: bool = False) -> dict:
    """
    Signature-scan a file with binwalk to find embedded files and data.

    entropy: include an entropy analysis pass. opcodes: scan for common
    executable opcode signatures. Read-only — no extraction.
    """
    if not shutil.which("binwalk"):
        return _missing("binwalk")
    cmd = ["binwalk"]
    if entropy:
        cmd.append("-E")
    if opcodes:
        cmd.append("-A")
    cmd.append(file_path)
    return run(cmd, timeout=180)


@mcp.tool()
@output_safe
def binwalk_extract(file_path: str, output_dir: str) -> dict:
    """
    Extract embedded files identified by binwalk into output_dir.

    output_dir must be under analysis/ or exports/. Carves recognised
    embedded archives/filesystems out of the target; does not modify evidence.
    """
    if not shutil.which("binwalk"):
        return _missing("binwalk")
    assert_output_safe(output_dir)
    return run(["binwalk", "-e", "--run-as=root",
                "--directory", output_dir, file_path],
               timeout=300, output_dir=output_dir)


@mcp.tool()
@output_safe
def diec_scan(file_path: str, deep: bool = False) -> dict:
    """
    Identify packers, compilers, and protectors with Detect It Easy (diec).

    deep: enable heuristic deep scan. Returns parsed detections when the JSON
    output is available.
    """
    binary = shutil.which("diec") or shutil.which("die")
    if not binary:
        return _missing("diec")
    cmd = [binary, "-j"] + (["-d"] if deep else []) + [file_path]
    result = run(cmd, timeout=120)
    if result.get("success"):
        try:
            parsed = json.loads(result.get("stdout", ""))
            result["detections"] = parsed.get("detects", parsed)
        except (ValueError, AttributeError):
            pass
    return result


@mcp.tool()
def tlsh_hash(file_path: str) -> dict:
    """
    Compute a TLSH locality-sensitive hash of a file for fuzzy similarity.

    Requires the py-tlsh wheel (`pip install py-tlsh`). Files under ~50 bytes
    or with too little variance cannot be hashed by design.
    """
    try:
        import tlsh
    except ImportError:
        return {"success": False,
                "error": "py-tlsh not installed — pip install py-tlsh"}
    try:
        with open(file_path, "rb") as fh:
            digest = tlsh.hash(fh.read())
    except OSError as e:
        return {"success": False, "error": str(e), "file": file_path}
    if not digest or digest == "TNULL":
        return {"success": False, "file": file_path,
                "error": "file too small or too uniform for a TLSH hash"}
    return {"success": True, "file": file_path, "tlsh": digest}


@mcp.tool()
def tlsh_compare(file_a: str, file_b: str) -> dict:
    """
    Compare two files by TLSH distance (0 = identical, higher = more different;
    < 100 typically indicates strong similarity). Requires py-tlsh.
    """
    try:
        import tlsh
    except ImportError:
        return {"success": False,
                "error": "py-tlsh not installed — pip install py-tlsh"}
    try:
        with open(file_a, "rb") as fa, open(file_b, "rb") as fb:
            ha, hb = tlsh.hash(fa.read()), tlsh.hash(fb.read())
    except OSError as e:
        return {"success": False, "error": str(e)}
    if "TNULL" in (ha, hb) or not ha or not hb:
        return {"success": False,
                "error": "one or both files could not be TLSH-hashed"}
    distance = tlsh.diff(ha, hb)
    band = ("identical/near-identical" if distance < 30
            else "similar" if distance < 100
            else "weakly related" if distance < 200 else "unrelated")
    return {"success": True, "tlsh_a": ha, "tlsh_b": hb,
            "distance": distance, "interpretation": band}


@mcp.tool()
def r2_summary(file_path: str) -> dict:
    """
    Headless radare2/rizin structural summary: file info, sections with
    entropy, and imports. Prefers rizin (rz-bin) when present, else radare2.
    """
    if shutil.which("rz-bin"):
        base = "rz-bin"
    elif shutil.which("r2"):
        base = "r2"
    else:
        return _missing("radare2 or rizin")

    out: dict = {"success": True, "file": file_path, "tool": base}
    if base == "rz-bin":
        for key, flag in (("info", "-Ij"), ("sections", "-Sj"),
                          ("imports", "-ij")):
            r = run(["rz-bin", flag, file_path], timeout=120)
            if r.get("success"):
                try:
                    out[key] = json.loads(r.get("stdout", ""))
                except ValueError:
                    out[key] = r.get("stdout", "")[:4000]
    else:  # r2 -qc with JSON commands
        r = run(["r2", "-2", "-q", "-c", "ij;iSj;iij", file_path], timeout=120)
        out["raw"] = r.get("stdout", "")[:8000] if r.get("success") else ""
        out["success"] = bool(r.get("success"))
        if not r.get("success"):
            out["error"] = r.get("stderr", "")
    return out


@mcp.tool()
def upx_detect(file_path: str) -> dict:
    """
    Test whether a binary is UPX-packed (non-destructive `upx -t`).
    """
    if not shutil.which("upx"):
        return _missing("upx")
    result = run(["upx", "-t", file_path], timeout=60)
    blob = (result.get("stdout", "") + result.get("stderr", "")).lower()
    if "[ok]" in blob or "tested 1 file" in blob:
        status = "upx-packed"
    elif "not packed" in blob or "notpackedexception" in blob:
        status = "not-upx-packed"
    else:
        status = "unknown"
    result["upx_status"] = status
    return result


@mcp.tool()
@output_safe
def upx_unpack(file_path: str, output_path: str) -> dict:
    """
    Unpack a UPX-packed binary to output_path (under analysis/ or exports/).

    The evidence file is never modified: it is copied to output_path first and
    UPX decompresses the copy in place. Note the unpacked artifact's hash will
    differ from the original packed sample.
    """
    if not shutil.which("upx"):
        return _missing("upx")
    assert_output_safe(output_path)
    try:
        shutil.copyfile(file_path, output_path)
    except OSError as e:
        return {"success": False, "error": f"copy failed: {e}"}
    result = run(["upx", "-d", output_path], timeout=120)
    result["output_path"] = output_path
    result["note"] = ("unpacked artifact differs from the original packed "
                      "sample — hash it separately")
    return result
