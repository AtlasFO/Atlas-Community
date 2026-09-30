"""File carving tools — bulk_extractor, foremost, scalpel."""
import os
from pathlib import Path
from typing import Optional
from fastmcp import FastMCP
from core import run, output_safe, DEFAULT_TIMEOUT, VOL_TIMEOUT, PLASO_TIMEOUT, scale_timeout
from core.paths import assert_output_safe
from tools._autodispatch import maybe_defer

mcp = FastMCP("carving")


# Pure command builders — shared by the sync tools below and the background
# job wrappers in tools/jobs.py (which must run the exact same argv).

def _bulk_extractor_cmd(image_path: str, output_dir: str, threads: int = 4,
                        scanners: Optional[str] = None) -> list[str]:
    cmd = ["bulk_extractor", "-j", str(threads), "-o", output_dir]
    if scanners:
        for s in scanners.split(","):
            cmd += ["-e", s.strip()]
    cmd.append(image_path)
    return cmd


def _bulk_extractor_unalloc_cmd(unallocated_raw: str, output_dir: str,
                                threads: int = 4) -> list[str]:
    return ["bulk_extractor", "-j", str(threads), "-o", output_dir, unallocated_raw]


def _foremost_cmd(image_path: str, output_dir: str,
                  file_types: Optional[str] = None,
                  config_file: Optional[str] = None) -> list[str]:
    cmd = ["foremost", "-o", output_dir]
    if file_types:
        cmd += ["-t", file_types]
    if config_file:
        cmd += ["-c", config_file]
    cmd.append(image_path)
    return cmd


# The configuration scalpel installs enables no file type, so a call with
# it fails at once ("The configuration file didn't specify any file types
# to carve"). Atlas ships its own, with the families foremost carves by
# default enabled, and uses it unless the caller names another.
SCALPEL_CONF = str(Path(__file__).resolve().parents[1] / "share" / "scalpel.conf")


def _scalpel_cmd(image_path: str, output_dir: str,
                 config_file: str = SCALPEL_CONF) -> list[str]:
    return ["scalpel", "-c", config_file or SCALPEL_CONF, "-o", output_dir, image_path]


def _scalpel_conf_types(config_file: str) -> list[str]:
    """The file types a scalpel configuration enables: the first word of
    each line that is neither blank nor a comment."""
    types: list[str] = []
    try:
        with open(config_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    types.append(s.split()[0])
    except OSError:
        return []
    return types


def _scalpel_conf_refusal(config_file: str) -> Optional[dict]:
    """Why scalpel would refuse ``config_file``, or None when it would not.
    Checked before the carve starts — a detached job that fails on its
    configuration reports nothing until someone reads it."""
    types = _scalpel_conf_types(config_file)
    if types:
        return None
    ours = ", ".join(sorted(set(_scalpel_conf_types(SCALPEL_CONF)))) or "none"
    return {
        "success": False,
        "gate": "scalpel_conf_no_types",
        "error": (f"{config_file} enables no file type"
                  + ("" if os.path.isfile(config_file) else " (not found)")
                  + "; scalpel refuses such a configuration before reading "
                  "the image"),
        "next_step": (f"omit config_file to carve with Atlas's own "
                      f"configuration ({SCALPEL_CONF}: {ours}), or pass one "
                      "whose type lines are uncommented"),
    }


@mcp.tool()
@output_safe
def bulk_extractor_scan(
    image_path: str,
    output_dir: str,
    threads: int = 4,
    scanners: Optional[str] = None,
) -> dict:
    """
    Carve features from a disk image or raw file using bulk_extractor.
    Extracts: email addresses, URLs, domains, credit cards, Bitcoin addresses,
              phone numbers, GPS coordinates, Base64 strings, and more.
    output_dir: directory to write feature files (one per feature type).
    threads: parallel scanner threads (default 4).
    scanners: comma-separated scanner names to limit scope
              e.g. 'email,url,domain,ip' — omit for all scanners.
    Large images are auto-dispatched as a background job (returns a job_id
    immediately — poll job.job_status, collect with job.job_collect).
    """
    deferred = maybe_defer("bulk_extractor", image_path, {
        "image_path": image_path, "output_dir": output_dir,
        "threads": threads, "scanners": scanners})
    if deferred:
        return deferred
    cmd = _bulk_extractor_cmd(image_path, output_dir, threads, scanners)
    return run(cmd, needs_sudo=True,
               timeout=scale_timeout(VOL_TIMEOUT*12, image_path),
               output_dir=output_dir)


@mcp.tool()
@output_safe
def bulk_extractor_unallocated(
    unallocated_raw: str,
    output_dir: str,
    threads: int = 4,
) -> dict:
    """
    Run bulk_extractor on a raw unallocated blocks file (from tsk_blkls).
    Faster than scanning a full image when you only care about deleted/unallocated data.
    """
    cmd = _bulk_extractor_unalloc_cmd(unallocated_raw, output_dir, threads)
    return run(cmd, needs_sudo=True,
               timeout=scale_timeout(VOL_TIMEOUT*6, unallocated_raw),
               output_dir=output_dir)


@mcp.tool()
@output_safe
def foremost_carve(
    image_path: str,
    output_dir: str,
    file_types: Optional[str] = None,
    config_file: Optional[str] = None,
) -> dict:
    """
    Carve files by header/footer signatures using foremost.
    file_types: comma-separated types e.g. 'jpg,pdf,doc,zip,exe' — omit for all.
    output_file: uses foremost default config if not specified.
    Large images are auto-dispatched as a background job.
    """
    deferred = maybe_defer("foremost", image_path, {
        "image_path": image_path, "output_dir": output_dir,
        "file_types": file_types, "config_file": config_file})
    if deferred:
        return deferred
    cmd = _foremost_cmd(image_path, output_dir, file_types, config_file)
    return run(cmd, needs_sudo=True,
               timeout=scale_timeout(VOL_TIMEOUT*12, image_path),
               output_dir=output_dir)


@mcp.tool()
@output_safe
def scalpel_carve(
    image_path: str,
    output_dir: str,
    config_file: str = "",
) -> dict:
    """
    Carve files by signature using scalpel (faster than foremost for large images).
    config_file: a scalpel.conf whose type lines are uncommented; omit it to
    use Atlas's own, which enables jpg, gif, png, bmp, avi, mpg, mov, wav,
    pdf, doc, zip and htm. The file scalpel installs enables nothing and
    is refused.
    Large images are auto-dispatched as a background job.
    """
    config_file = config_file or SCALPEL_CONF
    refused = _scalpel_conf_refusal(config_file)
    if refused:
        return refused
    deferred = maybe_defer("scalpel", image_path, {
        "image_path": image_path, "output_dir": output_dir,
        "config_file": config_file})
    if deferred:
        return deferred
    cmd = _scalpel_cmd(image_path, output_dir, config_file)
    return run(cmd, needs_sudo=True,
               timeout=scale_timeout(VOL_TIMEOUT*12, image_path),
               output_dir=output_dir)


@mcp.tool()
@output_safe
def bulk_extractor_report(output_dir: str) -> dict:
    """
    Read and summarize bulk_extractor output feature files from a completed scan.
    Returns line counts per feature file and first 100 entries from each.
    """
    import os
    summary = {}
    try:
        for fname in os.listdir(output_dir):
            if fname.endswith(".txt") and not fname.endswith("_histogram.txt") and not fname.startswith("report"):
                fpath = os.path.join(output_dir, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        lines = [l.strip() for l in f if not l.startswith("#") and l.strip()]
                    summary[fname] = {
                        "count": len(lines),
                        "sample": lines[:100],
                    }
                except Exception as e:
                    summary[fname] = {"error": str(e)}
        return {"success": True, "output_dir": output_dir, "features": summary}
    except Exception as e:
        return {"success": False, "error": str(e)}
