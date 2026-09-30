"""Build a scrubbed public snapshot of the repo and (optionally) push it.

A private remote carries the full history: raw brain captures, run logs,
deliverables and internal cases. The PUBLIC GitHub remote must only ever
receive a scrubbed snapshot. This command produces that snapshot:

  1. Check out HEAD into a throwaway worktree.
  2. Remove every INTERNAL path listed in ``.gitignore-public``.
  3. Assert no internal path remains, then scan the remaining brain/wiki and
     brain/indexes trees for case-specific identifiers (``identifiers.py``).
  4. Only if clean AND ``--push`` is given: commit the scrubbed tree and push
     the ``public`` branch to the public remote (default ``origin``).

Nothing is pushed on a dry run (the default).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from core.brain import identifiers, store

# Trees on the public snapshot that must be generalized (no raw IOCs). Public
# case evidence legitimately contains IOCs and is NOT scanned here.
_SCAN_TREES = ("brain/wiki", "brain/indexes")


class PublishError(Exception):
    pass


def _run(args: list[str], cwd: Path) -> str:
    r = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True)
    if r.returncode != 0:
        raise PublishError(f"`{' '.join(args)}` failed: {r.stderr.strip()}")
    return r.stdout


def load_internal_paths(repo: Path) -> list[str]:
    """Parse ``.gitignore-public`` into a list of internal path prefixes."""
    spec = repo / ".gitignore-public"
    if not spec.is_file():
        raise PublishError(".gitignore-public not found — cannot define the "
                           "public boundary")
    paths = []
    for line in spec.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            paths.append(line.rstrip("/"))
    return paths


def _scan_snapshot(root: Path) -> list[tuple[str, list[str]]]:
    """Scan the generalized trees for case-specific identifiers."""
    problems: list[tuple[str, list[str]]] = []
    for tree in _SCAN_TREES:
        base = root / tree
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            hits = identifiers.scan_text(
                path.read_text(encoding="utf-8", errors="replace"))
            if hits:
                problems.append((str(path.relative_to(root)),
                                 sorted({h.kind for h in hits})))
    return problems


def publish(push: bool = False, remote: str = "origin",
            branch: str = "public") -> dict:
    repo = store.REPO_ROOT
    internal = load_internal_paths(repo)
    with tempfile.TemporaryDirectory(prefix="atlas-publish-") as tmp:
        wt = Path(tmp) / "public"
        _run(["git", "worktree", "add", "--detach", "--quiet",
              str(wt), "HEAD"], cwd=repo)
        try:
            removed = []
            for rel in internal:
                if (wt / rel).exists():
                    _run(["git", "rm", "-r", "--quiet", "--ignore-unmatch",
                          "--", rel], cwd=wt)
                    removed.append(rel)
            remaining = [rel for rel in internal if (wt / rel).exists()]
            if remaining:
                raise PublishError(
                    "internal paths survived the scrub: "
                    + ", ".join(remaining))
            # Regenerate indexes from the scrubbed subset so they never re-list
            # internal case names / IOCs (stale committed indexes would).
            if (wt / "brain" / "indexes").is_dir():
                env = {**os.environ, "ATLAS_BRAIN_ROOT": str(wt / "brain"),
                       "PYTHONPATH": str(repo)}
                r = subprocess.run(
                    [sys.executable, "-m", "core.brain.indexes"],
                    cwd=str(repo), env=env, text=True, capture_output=True)
                if r.returncode != 0:
                    raise PublishError(
                        f"reindex of the scrubbed snapshot failed: "
                        f"{r.stderr.strip()}")
                _run(["git", "add", "-A", "brain/indexes"], cwd=wt)
            leaks = _scan_snapshot(wt)
            if leaks:
                detail = "; ".join(f"{p} ({', '.join(k)})" for p, k in leaks)
                raise PublishError(
                    "case-specific identifiers found in the public snapshot — "
                    f"refusing to publish: {detail}")
            result = {"removed": removed, "clean": True, "pushed": False,
                      "remote": remote, "branch": branch}
            if push:
                _run(["git", "commit", "--quiet", "-m",
                      "chore(publish): scrubbed public snapshot"], cwd=wt)
                _run(["git", "push", "--force", remote,
                      f"HEAD:refs/heads/{branch}"], cwd=wt)
                result["pushed"] = True
            return result
        finally:
            _run(["git", "worktree", "remove", "--force", str(wt)], cwd=repo)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a scrubbed public snapshot; push it only with "
                    "--push and only if clean.")
    parser.add_argument("--push", action="store_true",
                        help="push the scrubbed 'public' branch to the remote "
                             "(default: dry run, no push)")
    parser.add_argument("--remote", default="origin",
                        help="public remote to push to (default: origin)")
    parser.add_argument("--branch", default="public",
                        help="branch to publish (default: public)")
    args = parser.parse_args(argv)
    try:
        res = publish(push=args.push, remote=args.remote, branch=args.branch)
    except PublishError as e:
        print(f"error: {e}")
        return 1
    print(f"scrubbed {len(res['removed'])} internal path(s); snapshot is clean.")
    if res["pushed"]:
        print(f"pushed '{res['branch']}' to {res['remote']}.")
    else:
        print("dry run — nothing pushed. Re-run with --push to publish.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
