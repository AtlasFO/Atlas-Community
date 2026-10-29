"""The memory plugin result store (memory-speed design 3.3): a Volatility
plugin's complete answer, kept on the case disk under
``.atlas/vol_results/`` across runs and fresh starts (like the contents
index), so a repeat on the same image, symbols and Volatility is not run
again. ``ATLAS_VOL_RESULT_STORE`` (on by default) switches lookups and
writes; deleting the directory clears it.

The key is strict, so a stored answer is only ever the answer this call
would give:
- the image: a full content hash while the file's size and mtime still
  match the ones it was taken at (the intake's full hash in the evidence
  catalog, or the one the memory batch's warm read took), else its
  case-relative path, size, mtime and a hash of its first and last MiB (two
  images of the same size and template never share a key; a moved image
  only misses);
- the symbols: name, size and mtime of every symbol file under the symbol
  cache directory and under the Volatility package's own symbols directory
  (a pack updated in place misses);
- the Volatility version;
- the plugin and its arguments, normalised (flag-value pairs in order,
  comma lists sorted).

Only complete successes are stored: never a timed-out or failed output,
nor one cut at the output cap whose full copy was not kept, and never a
plugin call that writes files (its value is the files, not the output).
The full output is kept beside the key (``<key>.out``); a hit gets the
same cut a run would get (core.executor.capped_output).
"""
from __future__ import annotations

import functools
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

STORE_DIR = "vol_results"
# Plugins whose answer is the files they write, and the arguments that make
# any plugin write files: never stored. Volatility's public vocabulary.
_WRITING_PLUGINS = re.compile(r"(?i)(?:^|\.)(?:dumpfiles|memmap|procdump|moddump|dlldump|pslist\.dump)$")
_WRITING_ARGS = frozenset({"--dump", "--dump-dir", "--output-dir", "-o"})
# Symbol material in Volatility's public layout: ISF files and the zip packs.
_SYMBOL_SUFFIXES = (".json", ".json.xz", ".json.gz", ".json.bz2", ".isf", ".zip")
_MIB = 1 << 20


def store_on() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_VOL_RESULT_STORE", True)


def store_dir(case_dir: str | os.PathLike) -> Path:
    return Path(case_dir) / ".atlas" / STORE_DIR


def _rel(case_dir: str | os.PathLike, p: Path) -> str:
    """The image's case-relative path (its absolute path outside the case)."""
    try:
        return p.resolve().relative_to(Path(case_dir).resolve()).as_posix()
    except (ValueError, OSError):
        return str(p.resolve())


def _hash_record(case_dir: str | os.PathLike, rel: str) -> Path:
    return store_dir(case_dir) / "images" / (hashlib.sha256(rel.encode()).hexdigest()[:32] + ".json")


def record_full_hash(case_dir: str | os.PathLike, image: str | os.PathLike, sha256: str,
                     size: int, mtime_ns: int) -> None:
    """Keep the full content hash a sequential read of the whole image took
    (the memory batch's warm read), with the size and mtime it was taken
    at. Kept beside the store, not in the evidence catalog: the batch is a
    separate process and the catalog's writers lock in-process only."""
    rel = _rel(case_dir, Path(image))
    p = _hash_record(case_dir, rel)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"path": rel, "sha256": sha256, "size": int(size),
                                   "mtime_ns": int(mtime_ns)}), encoding="utf-8")
        os.replace(tmp, p)
    except OSError:
        pass


def image_id(case_dir: str | os.PathLike, image: str | os.PathLike) -> str:
    """The image's identity: a full content hash while the file still
    matches the size and mtime it was taken at, else a partial fingerprint
    that includes the image's case-relative path."""
    p = Path(image)
    try:
        st = p.stat()
    except OSError:
        return ""
    rel = _rel(case_dir, p)

    def same(rec: dict) -> bool:
        return int(rec.get("size") or -1) == st.st_size and int(rec.get("mtime_ns") or -1) == st.st_mtime_ns
    try:
        from core.evidence_catalog import load_catalog
        for unit in (load_catalog(case_dir).get("units") or {}).values():
            # A sampled catalog hash reads parts of the file only: not an identity.
            if (isinstance(unit, dict) and unit.get("path") == rel and unit.get("content_sha256")
                    and unit.get("fingerprint_mode", "full") == "full" and same(unit)):
                return "sha256:" + str(unit["content_sha256"])
    except (ValueError, OSError):
        pass
    try:
        rec = json.loads(_hash_record(case_dir, rel).read_text(encoding="utf-8"))
        if rec.get("path") == rel and rec.get("sha256") and same(rec):
            return "sha256:" + str(rec["sha256"])
    except (OSError, ValueError, AttributeError):
        pass
    h = hashlib.sha256(f"{rel}:{st.st_size}:{st.st_mtime_ns}".encode())
    try:
        with open(p, "rb") as fh:
            h.update(fh.read(_MIB))
            if st.st_size > _MIB:
                fh.seek(max(_MIB, st.st_size - _MIB))
                h.update(fh.read(_MIB))
    except OSError:
        return ""
    return "fp:" + h.hexdigest()


def symbols_id(symbol_dir: str | os.PathLike | None) -> str:
    """Name, size and mtime of every symbol file under the directory."""
    if not symbol_dir or not os.path.isdir(symbol_dir):
        return "none"
    rows = []
    for base, _dirs, files in os.walk(symbol_dir):
        for name in files:
            if name.lower().endswith(_SYMBOL_SUFFIXES):
                full = os.path.join(base, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                rows.append(f"{os.path.relpath(full, symbol_dir)}:{st.st_size}:{st.st_mtime_ns}")
    return hashlib.sha256("\n".join(sorted(rows)).encode()).hexdigest()


@functools.lru_cache(maxsize=8)
def package_symbols_dir(vol_bin: str) -> str:
    """The symbols directory inside the Volatility package the binary runs
    (packs installed there are read too); "" when it cannot be located.
    Looked for beside a source checkout's script and under the prefix of
    the binary and of its interpreter (a venv or the system's)."""
    real = os.path.realpath(shutil.which(vol_bin) or vol_bin)
    roots = [os.path.dirname(os.path.dirname(real))]
    try:
        with open(real, "rb") as fh:
            first = fh.readline(512).decode("utf-8", "ignore")
        words = first[2:].split() if first.startswith("#!") else []
        if words:
            interp = words[-1] if os.path.basename(words[0]) == "env" and len(words) > 1 else words[0]
            interp = shutil.which(interp) or interp
            roots.append(os.path.dirname(os.path.dirname(interp)))
    except OSError:
        pass
    found = [os.path.join(os.path.dirname(real), "volatility3", "symbols")]
    for root in roots:
        found += sorted(glob.glob(os.path.join(root, "lib", "python3*", "*-packages", "volatility3", "symbols")))
    return next((d for d in found if os.path.isdir(d)), "")


@functools.lru_cache(maxsize=8)
def vol_version(vol_bin: str) -> str:
    """The Volatility framework version the binary reports ("" when it does
    not say), asked once per process."""
    try:
        out = subprocess.run([vol_bin, "--help"], capture_output=True, text=True, timeout=60)
        m = re.search(r"Framework\s+(\S+)", (out.stdout or "") + (out.stderr or ""))
        return m.group(1) if m else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def norm_args(extra: list[str] | None) -> list[str]:
    """The plugin's arguments in one form: comma lists sorted (--pid 4,2
    and --pid 2,4 are one call)."""
    out = []
    for a in extra or []:
        s = str(a)
        if "," in s and not s.startswith("-"):
            s = ",".join(sorted(x.strip() for x in s.split(",") if x.strip()))
        out.append(s)
    return out


def writes_files(plugin: str, extra: list[str] | None, output_dir: str | None = None) -> bool:
    return bool(output_dir) or bool(_WRITING_PLUGINS.search(plugin)) or any(
        str(a) in _WRITING_ARGS for a in extra or [])


def key_for(case_dir: str | os.PathLike, image: str, plugin: str, extra: list[str] | None, *,
            vol_bin: str, symbol_dir: str | None) -> str:
    """The store key, "" when the image cannot be identified."""
    img = image_id(case_dir, image)
    if not img:
        return ""
    parts = {"image": img, "symbols": symbols_id(symbol_dir), "package_symbols": symbols_id(
                 package_symbols_dir(vol_bin)), "volatility": vol_version(vol_bin),
             "plugin": plugin, "args": norm_args(extra)}
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


def _spilled(result: dict[str, Any]) -> str:
    """The full copy of an output cut at the output cap, "" when none."""
    f = str(result.get("stdout_file") or "")
    return f if f and os.path.isfile(f) else ""


def complete(result: dict[str, Any]) -> bool:
    """A complete success: ran clean to its end with output, and when the
    output was cut at the cap, its full copy is on disk."""
    if (result.get("success") is not True or result.get("timed_out") or result.get("interrupted")
            or int(result.get("exit_code") or 0) != 0):
        return False
    if result.get("truncated"):
        return bool(_spilled(result))
    return bool(str(result.get("stdout") or "").strip())


def output_path(case_dir: str | os.PathLike, key: str) -> Path:
    return store_dir(case_dir) / f"{key}.out"


def lookup(case_dir: str | os.PathLike, key: str) -> Optional[dict[str, Any]]:
    """{"result", "meta", "output"} of a stored answer (``output`` the path
    of its full output), None on a miss or when off."""
    if not key or not store_on():
        return None
    try:
        hit = json.loads((store_dir(case_dir) / f"{key}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    out = output_path(case_dir, key)
    if not out.is_file():
        text = (hit.get("result") or {}).get("stdout")
        if text is None:
            return None
        try:                                    # an entry kept before outputs lived beside it
            out.write_text(str(text), encoding="utf-8")
        except OSError:
            return None
    hit["output"] = str(out)
    return hit


def stored_text(hit: dict[str, Any]) -> str:
    """The full output of a stored answer ("" when unreadable)."""
    try:
        return Path(hit["output"]).read_text(encoding="utf-8", errors="replace")
    except (OSError, KeyError, TypeError):
        return ""


def store(case_dir: str | os.PathLike, key: str, result: dict[str, Any], meta: dict[str, Any]) -> bool:
    """Keep a complete success under ``key``; True when stored. A cut
    output is kept whole from its full copy."""
    if not key or not store_on() or not complete(result):
        return False
    d = store_dir(case_dir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        out_tmp = d / f"{key}.out.tmp"
        if result.get("truncated"):
            shutil.copyfile(_spilled(result), out_tmp)
        else:
            out_tmp.write_text(str(result.get("stdout") or ""), encoding="utf-8")
        os.replace(out_tmp, output_path(case_dir, key))
        keep = {k: result.get(k) for k in ("success", "stderr", "exit_code", "cmd", "elapsed_seconds")}
        tmp = d / f"{key}.json.tmp"
        tmp.write_text(json.dumps({"result": keep, "meta": meta}, default=str), encoding="utf-8")
        os.replace(tmp, d / f"{key}.json")
        return True
    except OSError:
        return False


def store_answer_lines(case_dir: str | os.PathLike) -> list[str]:
    """The report's line naming the memory plugin calls of this run that
    were answered from the store, not run, with where each was kept."""
    try:
        from core.execution_log import trace_entries
        entries = trace_entries(case_dir) or []
    except Exception:  # noqa: BLE001
        return []
    said = []
    for e in entries:
        meta = e.get("cached_from") if e.get("type") == "tool_call" else None
        if not isinstance(meta, dict):
            continue
        words = str(e.get("cmd") or "").split()
        image = Path(words[words.index("-f") + 1]).name if "-f" in words[:-1] else "?"
        plugin = words[words.index("json") + 1] if "json" in words[:-1] else "?"
        said.append(f"{plugin.rsplit('.', 1)[-1]} on {image} (kept by {meta.get('trace') or '?'}, "
                    f"{meta.get('time') or '?'})")
    if not said:
        return []
    said = list(dict.fromkeys(said))
    return ["Memory plugin calls answered from the result store, not run again (the same image, symbols and "
            f"Volatility): {'; '.join(said)}"]


# ── the layer config (memory-speed design 3.3, (a)) ──────────────────────
#
# Volatility's --save-config writes the layer stack its automagic found for
# an image; -c loads it, so a later call skips the search. The config names
# the image's location, so it is kept per image identity and its locations
# are rewritten to the image's current path before each use.

def config_path(case_dir: str | os.PathLike, image: str) -> Optional[Path]:
    """Where the image's saved config lives (None without an identity)."""
    img = image_id(case_dir, image)
    if not img or not store_on():
        return None
    return store_dir(case_dir) / "configs" / (img.replace(":", "_") + ".json")


def config_for_use(case_dir: str | os.PathLike, image: str) -> Optional[str]:
    """A copy of the image's saved config with every location pointing at
    the image's current path, ready for -c; None when none is saved."""
    p = config_path(case_dir, image)
    if p is None or not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    uri = Path(image).resolve().as_uri()

    def fix(node: Any) -> Any:
        if isinstance(node, dict):
            return {k: (uri if isinstance(v, str) and k.endswith("location") and v.startswith("file:")
                        else fix(v)) for k, v in node.items()}
        if isinstance(node, list):
            return [fix(x) for x in node]
        return node
    use = p.with_suffix(".use.json")
    try:
        use.write_text(json.dumps(fix(data)), encoding="utf-8")
    except OSError:
        return None
    return str(use)


def forget_config(case_dir: str | os.PathLike, image: str) -> None:
    p = config_path(case_dir, image)
    if p is not None:
        for f in (p, p.with_suffix(".use.json")):
            try:
                f.unlink()
            except OSError:
                pass
