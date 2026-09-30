"""sudoers inventory must cover every needs_sudo=True binary basename."""
from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BINS_FILE = REPO / "share" / "atlas-sudoers.bins"
SUDOERS_IN = REPO / "share" / "atlas-sudoers.in"
SCAN_ROOTS = (REPO / "tools", REPO / "core")


def _allowed_basenames() -> set[str]:
    names: set[str] = set()
    for line in BINS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        names.add(line)
    return names


def _literal_cmd_head(node: ast.AST) -> str | None:
    """First string element of a list literal passed as cmd to run(...)."""
    if not isinstance(node, ast.List) or not node.elts:
        return None
    first = node.elts[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _needs_sudo_binaries() -> set[str]:
    """Static scan: run([...], needs_sudo=True) / run_with_output_file(...)."""
    found: set[str] = set()
    for root in SCAN_ROOTS:
        for path in root.rglob("*.py"):
            src = path.read_text(encoding="utf-8")
            try:
                tree = ast.parse(src, filename=str(path))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                kw = {
                    k.arg: k.value
                    for k in node.keywords
                    if k.arg
                }
                ns = kw.get("needs_sudo")
                if not isinstance(ns, ast.Constant) or ns.value is not True:
                    continue
                # Positional cmd is first arg for run()/run_with_output_file()
                if node.args:
                    head = _literal_cmd_head(node.args[0])
                    if head:
                        found.add(Path(head).name)
                # Or cmd= keyword
                if "cmd" in kw:
                    head = _literal_cmd_head(kw["cmd"])
                    if head:
                        found.add(Path(head).name)
    # Infra helpers that use sudo outside needs_sudo=True kwargs
    found.update({"true", "chown", "kill"})
    return found


def test_bins_file_and_sudoers_template_exist():
    assert BINS_FILE.is_file()
    assert SUDOERS_IN.is_file()
    text = SUDOERS_IN.read_text(encoding="utf-8")
    assert "@USER@" in text
    assert "ATLAS_FORENSICS" in text
    # Grant line must be the Cmnd_Alias, not NOPASSWD: ALL
    grant_lines = [
        ln for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#") and "NOPASSWD" in ln
    ]
    assert grant_lines
    assert all("NOPASSWD: ATLAS_FORENSICS" in ln for ln in grant_lines)
    assert not any(re.search(r"NOPASSWD:\s*ALL\b", ln) for ln in grant_lines)


def test_every_needs_sudo_binary_is_in_inventory():
    allowed = _allowed_basenames()
    used = _needs_sudo_binaries()
    # cmd built in a variable (network/carving) — still listed in .bins
    missing = sorted(used - allowed)
    assert not missing, (
        f"needs_sudo binaries missing from share/atlas-sudoers.bins: {missing}. "
        f"Add them to atlas-sudoers.bins and atlas-sudoers.in."
    )


def test_sudoers_template_mentions_every_inventory_basename():
    text = SUDOERS_IN.read_text(encoding="utf-8")
    allowed = _allowed_basenames()
    # fusermount3 may only appear as /usr/bin/fusermount3
    missing = sorted(
        b for b in allowed
        if not re.search(rf"[/\s]{re.escape(b)}([,\s]|$)", text)
    )
    assert not missing, f"basenames not in atlas-sudoers.in paths: {missing}"


def test_tcpdump_z_is_forbidden_and_unused():
    """`tcpdump -z <cmd>` runs an arbitrary program as root after each rotated
    file. The grant forbids it, and the codebase must not need it — if a call
    site ever passes -z, this test says so before the grant silently blocks it.
    """
    text = SUDOERS_IN.read_text(encoding="utf-8")
    assert "ATLAS_FORBIDDEN" in text
    assert "-z" in text
    # sudoers takes the LAST match, so the negation has to come after the alias.
    assert text.index("ATLAS_FORBIDDEN =") < text.index("!ATLAS_FORBIDDEN")

    used = []
    for py in (REPO / "tools").rglob("*.py"):
        src = py.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r'"tcpdump"(.{0,200})', src, re.S):
            if '"-z"' in m.group(1) or "'-z'" in m.group(1):
                used.append(str(py.relative_to(REPO)))
    assert not used, (
        f"tcpdump -z is forbidden by the sudoers grant but used in: {used}")


def test_whitelist_is_read_from_the_template_not_duplicated():
    """The preflight audit must derive its list from the grant itself.

    A second hardcoded list would drift from the file that actually decides,
    and the drift would be invisible until someone audited the wrong thing.
    """
    from core.sudo_preflight import whitelisted_binaries
    paths = whitelisted_binaries()
    assert paths, "no binaries parsed out of share/atlas-sudoers.in"
    assert all(p.startswith("/") for p in paths), paths
    # Argument patterns must not leak into the path list.
    assert not [p for p in paths if "*" in p], paths
    basenames = {Path(p).name for p in paths}
    for expected in ("ewfmount", "losetup", "mount", "tcpdump"):
        assert expected in basenames, expected


def test_permission_audit_flags_a_hijackable_binary_and_fails_open():
    """A group-writable whitelisted binary is a root shell for whoever can
    write it — sudo matches the absolute path, so PATH order does not save you.
    The audit is advisory: it must report, never raise, and stay silent rather
    than guess when it cannot stat.
    """
    from core.sudo_preflight import audit_sudoers_binaries

    class _St:
        def __init__(self, uid, mode):
            self.st_uid, self.st_mode = uid, mode

    def hostile(path):
        if path == "/usr/local/bin":
            return _St(0, 0o40775)              # group-writable directory
        if path == "/usr/bin/chown":
            return _St(1000, 0o100755)          # not owned by root
        return _St(0, 0o100755) if "." not in path else _St(0, 0o100755)

    findings = audit_sudoers_binaries(stat_fn=hostile)
    assert any("not owned by root" in f for f in findings), findings
    assert any("writable by group or other" in f for f in findings), findings

    def exploding(path):
        raise OSError("no such host")

    assert audit_sudoers_binaries(stat_fn=exploding) == []
