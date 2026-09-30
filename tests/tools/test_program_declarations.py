"""Every program a tool can execute must be declared.

Twice now a tool has been advertised in the manifest while the program it
runs was never installed — RegRipper's hardcoded ``/usr/local/bin/rip.pl``,
then six more in ``misc``. The model finds out by spending a call on
"No such file or directory". An undeclared program is that bug in waiting,
so this test enumerates what the tool layer actually executes and requires
each one to be either a base-system utility or declared in the registry.
"""
from __future__ import annotations

import pathlib
import re

from tools.tool_capabilities import EXTERNAL_BINARIES

# Present on any Linux host Atlas supports (coreutils, mount, the shell).
BASE_SYSTEM = {
    "sh", "bash", "ls", "cp", "mv", "rm", "mkdir", "stat", "file", "strings",
    "kill", "sudo", "mount", "umount", "losetup", "partprobe", "fusermount",
    "git", "curl", "python3", "dd", "cat", "grep", "find", "tar", "unzip",
    "gzip", "df", "ps", "chmod", "chown", "ln", "echo", "true", "printf",
    "sort", "head", "tail", "wc", "date", "hostname", "uname", "which",
    "dotnet", "pip", "openssl", "hexdump", "xxd", "secret-tool", "query",
    "disable", "enable", "set-password", "status", "log",
}

# A program shipped by the same package as one already declared: if the
# declared one is installed, so is this. Value = the declared sibling.
PACKAGE_SIBLINGS = {
    "blkcalc": "fls", "blkcat": "fls", "blkls": "fls", "blkstat": "fls",
    "ffind": "fls", "fsstat": "fls", "hfind": "fls", "ils": "fls",
    "jcat": "fls", "jls": "fls", "mactime": "fls", "mmcat": "fls",
    "mmstat": "fls", "sigfind": "fls", "sorter": "fls", "tsk_recover": "fls",
    "pinfo.py": "log2timeline.py", "psort.py": "log2timeline.py",
    "ewfverify": "ewfmount", "bdeinfo": "bdemount",
    "olevba3": "olevba", "mraptor3": "mraptor", "usnparser": "usn.py",
    "pdfid": "pdfid.py", "pdf-parser": "pdf-parser.py",
    "hindsight.py": "hindsight",
    "7za": "7z", "diec": "die", "md5deep": "hashdeep", "r2": "rz-bin",
    "whois": "whois", "xmount": "xmount", "hayabusa": "hayabusa",
}

_INVOCATION = (
    re.compile(r'run\(\s*\[\s*["\']([A-Za-z0-9_.\-]+)["\']'),
    re.compile(r'cmd\s*=\s*\[\s*["\']([A-Za-z0-9_.\-]+)["\']'),
    re.compile(r'_bin_or_warn\(\s*["\']([^"\']+)["\']'),
    re.compile(r'tool_program\(\s*["\']([^"\']+)["\']'),
)


def _invoked_programs() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in pathlib.Path("tools").rglob("*.py"):
        if path.name.startswith("test_"):
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        for rx in _INVOCATION:
            for match in rx.finditer(src):
                name = match.group(1).rsplit("/", 1)[-1]
                found.setdefault(name, set()).add(path.name)
    return found


def test_every_invoked_program_is_declared_or_base_system():
    # A declaration may name alternatives ("rz-bin|r2"): both count.
    declared = {alt for bins in EXTERNAL_BINARIES.values()
                for spec in bins for alt in str(spec).split("|")}
    undeclared = {
        name: sorted(files)
        for name, files in _invoked_programs().items()
        if name not in declared
        and name not in BASE_SYSTEM
        and PACKAGE_SIBLINGS.get(name) not in declared
        and name not in PACKAGE_SIBLINGS
    }
    assert not undeclared, (
        "these programs are executed by a tool but declared nowhere, so the "
        "manifest will advertise the tool on a machine that lacks them:\n"
        + "\n".join(f"  {n}: {f}" for n, f in sorted(undeclared.items()))
        + "\nAdd them to EXTERNAL_BINARIES (or PACKAGE_SIBLINGS if another "
          "declared program ships in the same package)."
    )


def test_no_tool_hardcodes_an_absolute_program_path():
    """A hardcoded /usr/local/bin path ignores PATH, so the program can be
    installed and still be invisible — and the manifest, which asks PATH,
    then disagrees with the wrapper."""
    offenders: list[str] = []
    literal = re.compile(r'["\'](/(?:usr/local/bin|usr/bin|usr/sbin|sbin)/[A-Za-z0-9_.\-]+)["\']')
    for path in pathlib.Path("tools").rglob("*.py"):
        src = path.read_text(encoding="utf-8", errors="replace")
        for match in literal.finditer(src):
            line = src[:match.start()].count("\n") + 1
            context = src.splitlines()[line - 1]
            # A fallback after a real lookup is fine: which(...) or "/usr/..."
            if "tool_program" in context or "which(" in context or "_bin_or_warn" in context:
                continue
            offenders.append(f"{path.name}:{line}: {context.strip()[:90]}")
    assert not offenders, (
        "resolve the program with core.paths.tool_program instead:\n"
        + "\n".join(offenders))


def test_a_tool_with_alternative_programs_is_available_when_either_exists():
    """Several wrappers prefer one program and fall back to another —
    rizin then radare2, pdfid.py then pdfid. Declaring only the preferred
    name marks a working tool unavailable and steers the model away from it."""
    from unittest.mock import patch

    import tools.tool_capabilities as tc

    with patch.dict(tc.EXTERNAL_BINARIES, {"bin.demo": ("rz-bin|r2",)}, clear=True):
        with patch("core.paths.tool_program",
                   side_effect=lambda n, *a: "/usr/bin/r2" if n == "r2" else None):
            assert tc.missing_binaries() == [], "the fallback counts as installed"
        with patch("core.paths.tool_program", return_value=None):
            missing = tc.missing_binaries()
            assert missing and "rz-bin or r2" in missing[0][1]
