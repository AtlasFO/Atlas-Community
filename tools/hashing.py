"""File hashing and fuzzy hash tools."""
import os
import re
import json
import hashlib
import glob
import threading
from typing import Optional
from fastmcp import FastMCP
from core import (run, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT, HASH_TIMEOUT,
                  output_safe, with_tool_timeout, scale_timeout)

mcp = FastMCP("hashing")


# ── Hash cache (keyed by absolute path + size + mtime) ──────────────────────

_HASH_CACHE_PATH = os.path.expanduser(
    os.environ.get("ATLAS_HASH_CACHE", "~/.cache/atlas/hash_cache.json")
)
_HASH_CACHE_LOCK = threading.Lock()
_HASH_CACHE: Optional[dict] = None


def _load_hash_cache() -> dict:
    global _HASH_CACHE
    if _HASH_CACHE is not None:
        return _HASH_CACHE
    try:
        with open(_HASH_CACHE_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            _HASH_CACHE = data
            return _HASH_CACHE
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    _HASH_CACHE = {}
    return _HASH_CACHE


def _save_hash_cache(cache: dict) -> None:
    os.makedirs(os.path.dirname(_HASH_CACHE_PATH), exist_ok=True)
    try:
        with open(_HASH_CACHE_PATH, "w") as f:
            json.dump(cache, f)
    except OSError:
        pass  # cache is opportunistic; tolerate filesystem errors


def _cache_key(stat_result, abs_path: str) -> str:
    return f"{abs_path}|{stat_result.st_size}|{int(stat_result.st_mtime)}"


def _case_dir() -> str:
    try:
        from core.execution_log import log
        return log.case_dir() or ""
    except Exception:  # noqa: BLE001 - no active case, no cross-match
        return ""


def _note_identical(result: dict, path: str) -> dict:
    """Add the other paths in the case that carry the same content, so a
    hash computed on a copy is at once a hash of the original."""
    sha = result.get("sha256")
    case_dir = _case_dir() if sha else ""
    if not case_dir:
        return result
    try:
        from core import hash_index
        others = hash_index.record(case_dir, [(path, sha)]).get(
            hash_index.rel_path(case_dir, path))
    except Exception:  # noqa: BLE001 - a hash is still a hash without the index
        return result
    if others:
        result["identical_to"] = others[:8]
        names = ", ".join(o["path"] for o in others[:3])
        result["note"] = (f"same content as {names}: one file under several paths; "
                          "what is established about one holds for the other")
    return result


@mcp.tool()
@output_safe
@with_tool_timeout(lambda file_path, **_: scale_timeout(HASH_TIMEOUT, file_path),
                   label="hash_file")
def hash_file(file_path: str) -> dict:
    """Compute MD5, SHA1, and SHA256 hashes of a file in one pass.

    Results are cached at ATLAS_HASH_CACHE (default ~/.cache/atlas/hash_cache.json)
    keyed by absolute path + size + mtime. Cache hits are returned instantly
    with `cache_hit: True` for the audit trail.
    """
    try:
        abs_path = os.path.abspath(file_path)
        stat = os.stat(abs_path)
    except OSError as e:
        return {"success": False, "error": str(e), "file": file_path}

    key = _cache_key(stat, abs_path)
    with _HASH_CACHE_LOCK:
        cache = _load_hash_cache()
        hit = cache.get(key)
        if hit:
            return _note_identical({**hit, "cache_hit": True, "file": file_path}, abs_path)

    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        size = 0
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                size += len(chunk)
        result = {
            "success": True,
            "file": file_path,
            "size_bytes": size,
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "file": file_path}

    with _HASH_CACHE_LOCK:
        cache = _load_hash_cache()
        cache[key] = {
            "success": True,
            "size_bytes": result["size_bytes"],
            "md5": result["md5"],
            "sha1": result["sha1"],
            "sha256": result["sha256"],
        }
        _save_hash_cache(cache)

    result["cache_hit"] = False
    return _note_identical(result, abs_path)


@mcp.tool()
@output_safe
@with_tool_timeout(HASH_TIMEOUT, label="hash_directory")
def hash_directory(
    directory: str,
    recursive: bool = True,
    algorithm: str = "sha256",
    output_manifest: Optional[str] = None,
) -> dict:
    """
    Hash all files in a directory.
    algorithm: md5, sha1, sha256, sha512.
    output_manifest: optional path to write hash manifest CSV.
    """
    from core.paths import assert_output_safe
    if output_manifest:
        assert_output_safe(output_manifest)

    algo_map = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    if algorithm not in algo_map:
        return {"success": False, "error": f"Unknown algorithm: {algorithm}"}

    hasher_cls = algo_map[algorithm]
    results = []
    errors = []
    pattern = "**/*" if recursive else "*"
    files = glob.glob(os.path.join(directory, pattern), recursive=recursive)

    for fpath in files:
        if not os.path.isfile(fpath):
            continue
        try:
            h = hasher_cls()
            with open(fpath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            results.append({"file": fpath, algorithm: h.hexdigest()})
        except Exception as e:
            errors.append({"file": fpath, "error": str(e)})

    if output_manifest:
        import csv
        with open(output_manifest, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["file", algorithm])
            writer.writeheader()
            writer.writerows(results)

    identical = 0
    case_dir = _case_dir() if algorithm == "sha256" and results else ""
    if case_dir:
        try:
            from core import hash_index
            matches = hash_index.record(case_dir, [(r["file"], r["sha256"]) for r in results])
            for r in results:
                others = matches.get(hash_index.rel_path(case_dir, r["file"]))
                if others:
                    r["identical_to"] = [o["path"] for o in others[:4]]
                    identical += 1
        except Exception:  # noqa: BLE001 - the listing stands without the index
            pass
    return {
        "success": True,
        "directory": directory,
        "algorithm": algorithm,
        "file_count": len(results),
        "identical_files": identical,
        "hashes": results,
        "errors": errors,
        "manifest": output_manifest,
    }


@mcp.tool()
@output_safe
def ssdeep_hash(file_path: str) -> dict:
    """Compute ssdeep fuzzy hash for similarity comparison."""
    return run(["ssdeep", file_path], line_cap=None,
               timeout=scale_timeout(DEFAULT_TIMEOUT, file_path))


@mcp.tool()
@output_safe
def ssdeep_compare(file1: str, file2: str) -> dict:
    """Compare two files using ssdeep fuzzy hashing — returns similarity score 0-100."""
    return run(["ssdeep", "-d", file1, file2], line_cap=None)


@mcp.tool()
@output_safe
def ssdeep_scan_directory(directory: str, threshold: int = 50) -> dict:
    """
    Find similar files in a directory using ssdeep.
    threshold: minimum similarity score (0-100) to report.
    """
    return run(["ssdeep", "-r", "-t", str(threshold), directory], timeout=DEFAULT_TIMEOUT, line_cap=None)


_SAMPLE_CHUNK = 64 * 1024 * 1024  # sampled fingerprint reads 64 MiB per end
_SAMPLE_SCHEME = "sha256(first64MiB+last64MiB+size)"


def _sampled_fingerprint(evidence_path: str) -> dict:
    """Fast integrity fingerprint for evidence too large to full-hash.

    Reads only the first and last 64 MiB (with the byte size mixed into the
    digest) — seconds instead of hours on a network-mounted multi-100-GB
    image. NOT a substitute for a full hash: it anchors the file identity
    in the trace; the full hash can still be computed later (hash_file)
    when custody requires it.
    """
    try:
        abs_path = os.path.abspath(evidence_path)
        stat = os.stat(abs_path)
    except OSError as e:
        return {"success": False, "error": str(e), "file": evidence_path}

    key = f"sampled|{_cache_key(stat, abs_path)}"
    with _HASH_CACHE_LOCK:
        cache = _load_hash_cache()
        hit = cache.get(key)
        if hit:
            return {**hit, "cache_hit": True, "file": evidence_path}

    try:
        h = hashlib.sha256()
        h.update(str(stat.st_size).encode())
        with open(abs_path, "rb") as f:
            remaining = _SAMPLE_CHUNK
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
            if stat.st_size > 2 * _SAMPLE_CHUNK:
                f.seek(stat.st_size - _SAMPLE_CHUNK)
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        result = {
            "success": True,
            "size_bytes": stat.st_size,
            "sampled_sha256": h.hexdigest(),
            "sample_scheme": _SAMPLE_SCHEME,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "file": evidence_path}

    with _HASH_CACHE_LOCK:
        cache = _load_hash_cache()
        cache[key] = dict(result)
        _save_hash_cache(cache)
    return {**result, "cache_hit": False, "file": evidence_path}


# An Expert Witness image carries the digest its acquisition tool computed
# over the imaged media. Hashing the segment files attests custody of the
# files as received; only that stored digest, re-computed over the data,
# attests the media, which is the question an examiner asks first.
_EWF_FIRST_SEGMENT_RE = re.compile(r"\.(?:e01|ex01|l01|lx01|s01)$", re.IGNORECASE)
_EWF_DIGEST_RE = re.compile(r"^\s*(MD5|SHA1|SHA256):\s*([0-9a-fA-F]{32,64})\s*$", re.MULTILINE)
_EWF_MEDIA_SIZE_RE = re.compile(r"Media size:.*?\((\d+) bytes\)")


def is_ewf_image(path: str) -> bool:
    return bool(_EWF_FIRST_SEGMENT_RE.search(str(path or "")))


def _ewf_acquisition(evidence_path: str, *, force: bool, cap_bytes: int) -> dict:
    """The digest stored in an Expert Witness image and, when the media is
    within the full-hash policy (or the caller insists), whether the data
    still hashes to it. Never fails the caller: a missing tool or a broken
    header is reported as ``acquisition_error``."""
    info = run(["ewfinfo", evidence_path], line_cap=None)
    if not info.get("success"):
        return {"acquisition_error": str(info.get("stderr") or info.get("error")
                                         or "ewfinfo failed")[:300]}
    text = info.get("stdout") or ""
    digests = {k.lower(): v.lower() for k, v in _EWF_DIGEST_RE.findall(text)}
    out: dict = {}
    m = _EWF_MEDIA_SIZE_RE.search(text)
    media = int(m.group(1)) if m else 0
    if media:
        out["media_size_bytes"] = media
    if not digests:
        out["acquisition_error"] = "the image stores no acquisition digest"
        return out
    out["acquisition_hashes"] = digests
    if not (force or cap_bytes <= 0 or media <= cap_bytes):
        out["acquisition_verified"] = None
        out["acquisition_note"] = (
            f"stored digest read; the media ({media / 1024**3:.1f} GB) is above "
            "ATLAS_FULL_HASH_MAX_GB, so it was not re-hashed. ewf.ewf_verify or "
            "force_full=True does that when the engagement requires it.")
        return out
    ver = run(["ewfverify", "-q", evidence_path],
              timeout=scale_timeout(VOL_TIMEOUT * 6, evidence_path), line_cap=None)
    said = (ver.get("stdout") or "") + "\n" + (ver.get("stderr") or "")
    if ver.get("success") and "SUCCESS" in said:
        out["acquisition_verified"] = True
    elif "FAILURE" in said or "MISMATCH" in said.upper():
        out["acquisition_verified"] = False
    else:
        out["acquisition_verified"] = None
        out["acquisition_error"] = str(ver.get("stderr") or ver.get("error")
                                       or "ewfverify gave no verdict")[:300]
    return out


def _acquisition_summary(result: dict) -> str:
    """One clause for the trace: the stored digest and its verdict."""
    hashes = result.get("acquisition_hashes") or {}
    if not hashes:
        return ""
    algo, digest = next(iter(sorted(hashes.items())))
    verdict = {True: "verified by ewfverify", False: "MISMATCH on ewfverify",
               None: "stored, not re-verified"}[result.get("acquisition_verified")]
    return f" acquisition_{algo}={digest} ({verdict})"


@mcp.tool()
@output_safe
@with_tool_timeout(lambda evidence_path, **_: scale_timeout(
    HASH_TIMEOUT, evidence_path), label="verify_evidence_hash")
def verify_evidence_hash(evidence_path: str,
                         expected_md5: Optional[str] = None,
                         expected_sha1: Optional[str] = None,
                         force_full: bool = False) -> dict:
    """
    Compute hashes of an evidence file and optionally compare to known values.
    Use to verify chain of custody integrity before analysis.

    For an Expert Witness image (E01 and kin) the result also carries
    `acquisition_hashes`, the digest the acquisition tool stored over the
    imaged media, and `acquisition_verified`: True when ewfverify re-hashed
    the data to that digest, False on a mismatch, None when the media is
    above the full-hash policy and was not re-hashed. That is the image
    integrity statement a report needs; the file hashes above attest the
    segment files as received.

    Evidence larger than ATLAS_FULL_HASH_MAX_GB (default 16) is NOT read in
    full: a sampled fingerprint (first+last 64 MiB) is recorded instead and
    the result carries `full_hash: false` — proceed with analysis, and hash
    the individual artifacts you extract or flag (hash_file) instead of the
    whole image. Passing an expected hash or force_full=True always computes
    the full hash regardless of size.

    On success, also records a `reason_call` entry tagged
    "hash_verify_evidence_hash" in the execution trace so downstream tools can
    look up whether a given evidence path has been verified in this session.
    """
    from core.paths import FULL_HASH_MAX_GB, is_network_path

    on_network = is_network_path(evidence_path)
    try:
        size_bytes = os.stat(evidence_path).st_size
    except OSError as e:
        return {"success": False, "error": str(e), "file": evidence_path}

    cap_bytes = FULL_HASH_MAX_GB * (1024 ** 3)
    want_full = bool(force_full or expected_md5 or expected_sha1
                     or cap_bytes <= 0 or size_bytes <= cap_bytes)

    if not want_full:
        result = _sampled_fingerprint(evidence_path)
        if not result["success"]:
            return result
        result["full_hash"] = False
        result["deferred"] = True
        result["network_storage"] = on_network
        if is_ewf_image(evidence_path):
            result.update(_ewf_acquisition(evidence_path, force=False, cap_bytes=cap_bytes))
        result["note"] = (
            f"Full hash skipped by policy: {size_bytes / 1024**3:.1f} GB > "
            f"ATLAS_FULL_HASH_MAX_GB={FULL_HASH_MAX_GB}"
            + (" and evidence is on NETWORK storage" if on_network else "")
            + ". Sampled fingerprint recorded for the trace. Do NOT re-try "
            "the full hash — proceed with analysis and hash_file every "
            "artifact you extract, carve, or flag as malicious. Use "
            "force_full=True only if the engagement requires a full "
            "custody hash.")
        try:
            from core.execution_log import log
            log.record_reason_call(
                tool="hash_verify_evidence_hash",
                success=True,
                conclusion=(f"DEFERRED: {evidence_path} "
                            f"sampled_sha256={result['sampled_sha256']} "
                            f"scheme={_SAMPLE_SCHEME}" + _acquisition_summary(result)),
                directives={},
            )
        except Exception as _e:
            import sys
            print(f"[Atlas WARN] verify_evidence_hash log failed: {_e}",
                  file=sys.stderr)
        return result

    result = hash_file(evidence_path)
    if not result["success"]:
        return result
    result["full_hash"] = True
    result["network_storage"] = on_network
    if is_ewf_image(evidence_path):
        result.update(_ewf_acquisition(
            evidence_path, force=bool(force_full or expected_md5 or expected_sha1),
            cap_bytes=cap_bytes))
    if on_network and size_bytes > 1024 ** 3:
        result["note"] = ("Evidence resolves to NETWORK storage — full-image "
                          "operations (hashing, mounting, fls/fsstat, "
                          "carving) are 10-50x slower than local disk. "
                          "Prefer targeted extraction or stage a local copy.")

    result["md5_match"] = None
    result["sha1_match"] = None

    if expected_md5:
        result["md5_match"] = result["md5"].lower() == expected_md5.lower()
    if expected_sha1:
        result["sha1_match"] = result["sha1"].lower() == expected_sha1.lower()

    if expected_md5 or expected_sha1:
        result["integrity_verified"] = (
            (result["md5_match"] is None or result["md5_match"]) and
            (result["sha1_match"] is None or result["sha1_match"])
        )

    # Record hash-verification state in the execution log so downstream tools
    # (and the trace report) can confirm chain of custody.
    try:
        from core.execution_log import log
        sha256 = result.get("sha256", "")
        log.record_reason_call(
            tool="hash_verify_evidence_hash",
            success=True,
            conclusion=f"VERIFIED: {evidence_path} sha256={sha256}" + _acquisition_summary(result),
            directives={},
        )
    except Exception as _e:
        import sys
        print(f"[Atlas WARN] verify_evidence_hash log failed: {_e}", file=sys.stderr)

    return result


@mcp.tool()
@output_safe
def hashdeep_compute(
    target: str,
    recursive: bool = True,
    algorithm: str = "md5,sha256",
    output_path: Optional[str] = None,
) -> dict:
    """
    Compute multiple hashes for files using hashdeep (supports md5, sha1, sha256, tiger, whirlpool).
    target: file or directory path.
    algorithm: comma-separated algorithms e.g. 'md5,sha1,sha256'.
    Produces a hash manifest that can be used with hashdeep_audit.
    """
    from core.paths import assert_output_safe
    if output_path:
        assert_output_safe(output_path)
    cmd = ["hashdeep", f"-c{algorithm}"]
    if recursive and os.path.isdir(target):
        cmd.append("-r")
    cmd.append(target)
    result = run(cmd, timeout=scale_timeout(VOL_TIMEOUT, target), line_cap=None)
    if output_path and result["success"]:
        with open(output_path, "w") as f:
            f.write(result["stdout"])
        result["manifest_path"] = output_path
    return result


@mcp.tool()
@output_safe
def hashdeep_audit(
    manifest_file: str,
    target_directory: str,
    mode: str = "audit",
) -> dict:
    """
    Audit a directory against a hashdeep manifest to detect modified, missing, or unknown files.
    manifest_file: path to a hashdeep manifest file (from hashdeep_compute).
    mode: 'audit' (report all discrepancies), 'match' (only matching), 'negative' (only mismatches).
    """
    flag_map = {"audit": "-a", "match": "-m", "negative": "-X"}
    flag = flag_map.get(mode, "-a")
    cmd = ["hashdeep", flag, "-k", manifest_file, "-r", target_directory]
    return run(cmd, timeout=VOL_TIMEOUT, line_cap=None)


@mcp.tool()
@output_safe
def md5deep_scan(directory: str, recursive: bool = True, output_path: Optional[str] = None) -> dict:
    """
    Compute MD5 hashes for all files in a directory using md5deep.
    Faster than hashdeep for MD5-only workflows.
    """
    from core.paths import assert_output_safe
    if output_path:
        assert_output_safe(output_path)
    cmd = ["md5deep"]
    if recursive:
        cmd.append("-r")
    cmd.append(directory)
    result = run(cmd, timeout=VOL_TIMEOUT, line_cap=None)
    if output_path and result["success"]:
        with open(output_path, "w") as f:
            f.write(result["stdout"])
    return result
