"""Worker of the batch image extract job (tools/jobs.py
job_start_image_extract).

Run by tools/jobs_runner.py as `python tools/image_extract_runner.py
<manifest>`. The manifest lists one item per file or folder to copy out of a
disk image: the image (or the raw device it is read through), the volume
offset in sectors, the inode, the destination and whether it is a folder.
Each file is copied with `icat`, each folder with `tsk_recover -d`, each
under its own per-call deadline. The result file the manifest names records
per item its size and SHA-256 (a file) or its file count and bytes (a
folder), or the error; job_collect reads it and ties the copies to the
index entries they came from.

Stdlib-only and import-light like tools/jobs_runner.py: it never imports
the server's modules, so it starts instantly and writes no trace.
Standard output carries the failures and one summary line, not the
copies' paths: the job's log goes into the trace and the search index, where
a copy's path could be taken for a read of the copy.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _offset(item: dict) -> list[str]:
    return ["-o", str(item["offset"])] if int(item.get("offset") or 0) else []


def _copy_file(item: dict) -> dict:
    dest = item["dest"]
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    reuse = item.get("reuse") or ""
    if reuse and os.path.isfile(reuse) and os.path.abspath(reuse) != os.path.abspath(dest):
        try:
            shutil.copyfile(reuse, part)
            os.replace(part, dest)
            return {"ok": True, "size": os.path.getsize(dest), "sha256": _sha256(dest), "reused": reuse}
        except OSError:
            _remove(part)          # the image is read instead
    elif reuse and os.path.abspath(reuse) == os.path.abspath(dest) and os.path.isfile(dest):
        return {"ok": True, "size": os.path.getsize(dest), "sha256": _sha256(dest), "reused": reuse}
    cmd = ["icat", *_offset(item), item["device"], str(item["inode"])]
    try:
        with open(part, "wb") as out:
            proc = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                  timeout=item.get("timeout") or None)
    except subprocess.TimeoutExpired:
        _remove(part)
        return {"ok": False, "error": f"icat did not finish within {item.get('timeout')} s"}
    except OSError as e:
        _remove(part)
        return {"ok": False, "error": f"icat could not run: {e}"}
    if proc.returncode != 0:
        _remove(part)
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        return {"ok": False, "error": f"icat exit {proc.returncode}: {err[:300]}"}
    os.replace(part, dest)
    return {"ok": True, "size": os.path.getsize(dest), "sha256": _sha256(dest)}


def _copy_folder(item: dict) -> dict:
    dest = item["dest"]
    os.makedirs(dest, exist_ok=True)
    cmd = ["tsk_recover", "-a", *_offset(item), "-d", str(item["inode"]).split("-")[0], item["device"], dest]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                              timeout=item.get("timeout") or None)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"tsk_recover did not finish within {item.get('timeout')} s"}
    except OSError as e:
        return {"ok": False, "error": f"tsk_recover could not run: {e}"}
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        return {"ok": False, "error": f"tsk_recover exit {proc.returncode}: {err[:300]}"}
    files = size = 0
    for root, _dirs, names in os.walk(dest):
        for n in names:
            files += 1
            size += os.path.getsize(os.path.join(root, n))
    return {"ok": True, "files": files, "size": size, "sha256": ""}


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def main(manifest_path: str) -> int:
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    results = []
    for item in manifest["items"]:
        res = _copy_folder(item) if item.get("is_dir") else _copy_file(item)
        results.append({"entry_id": item["entry_id"], "dest": item["dest"], **res})
        if not res["ok"]:
            print(f"failed: {item['image']}::{item['path']}: {res['error']}", flush=True)
    ok = [r for r in results if r["ok"]]
    print(f"{len(ok)} of {len(results)} item(s) copied, {sum(r.get('size') or 0 for r in ok)} bytes, "
          f"{len(results) - len(ok)} failed", flush=True)
    tmp = manifest["result"] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"items": results}, f, indent=1)
    os.replace(tmp, manifest["result"])
    return 0 if len(ok) == len(results) else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python tools/image_extract_runner.py <manifest>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
