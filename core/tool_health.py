"""What every tool needs, and whether this machine has it.

Two tools were advertised for months while the program behind them was never
installed — the model found out by spending a call on "No such file or
directory". Availability was also answered in two places that could disagree:
the manifest asked PATH, a wrapper hardcoded an absolute path.

This module is the one answer. The installer writes what it did into
``install_report.json``; the live probe resolves each declared program the way
the wrappers resolve it; the dashboard and the CLI both read the result, so a
tool that cannot run is visible instead of silent.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Where the installer records what it installed, skipped or failed.
INSTALL_REPORT = Path(
    os.environ.get("ATLAS_INSTALL_REPORT",
                   os.path.expanduser("~/.cache/atlas/install_report.json")))

# Tools whose upstream program is gone or unusable, with what to use instead.
# Retired ≠ missing: nothing is coming to install, so the board says so once
# rather than reporting a failure the operator cannot act on.
RETIRED: dict[str, str] = {}

# Programs the installer deliberately does not fetch. Reporting these as
# "missing" hands the operator a fault they cannot clear: either nothing
# packages the program, or it is behind an opt-in flag they chose not to
# pass. They belong on the board — just not as errors.
OPTIONAL: dict[str, str] = {
    "die": ("names packers, protectors and compilers. No distribution packages "
     "it, so install.sh fetches the .deb upstream builds for this "
     "release — re-run ./install.sh to retry, or install it by hand "
     "from github.com/horsicq/DIE-engine/releases. Without it, "
     "misc.pe_scanner still reports section entropy and packer hints"),
    "diec": ("names packers, protectors and compilers. No distribution packages "
     "it, so install.sh fetches the .deb upstream builds for this "
     "release — re-run ./install.sh to retry, or install it by hand "
     "from github.com/horsicq/DIE-engine/releases. Without it, "
     "misc.pe_scanner still reports section entropy and packer hints"),
    "rz-bin": "optional; bin.r2_summary falls back to radare2",
    "zeek": "opt-in: install.sh --with-network-tools",
    "suricata": "opt-in: install.sh --with-network-tools",
    "tcpxtract": "opt-in: install.sh --with-network-tools",
}

STATUS_OK = "ok"
STATUS_MISSING = "missing"
STATUS_RETIRED = "retired"
STATUS_ALTERNATIVE = "alternative"
STATUS_OPTIONAL = "optional"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_install_report() -> dict[str, Any]:
    """What the installer recorded, or an empty report when it never ran."""
    try:
        return json.loads(INSTALL_REPORT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def probe() -> dict[str, Any]:
    """Live status of every program the tool layer declares.

    Each entry: the declared program (or alternatives), which tools need it,
    where it resolved, and what an operator should do about it.
    """
    from core.paths import tool_program
    from tools.tool_capabilities import (
        AVAILABILITY_PROBES, EXTERNAL_BINARIES, EXTERNAL_MODULES,
    )

    installed = load_install_report()
    by_program = installed.get("programs") or {}
    entries: list[dict[str, Any]] = []

    for owner, specs in sorted(EXTERNAL_BINARIES.items()):
        for spec in specs:
            alternatives = [a for a in str(spec).split("|") if a]
            resolved = next(
                ((a, tool_program(a)) for a in alternatives if tool_program(a)),
                (None, None))
            name, path = resolved
            if path:
                status = STATUS_OK if name == alternatives[0] else STATUS_ALTERNATIVE
                detail = f"{name} at {path}"
            elif any(a in RETIRED for a in alternatives):
                status = STATUS_RETIRED
                detail = RETIRED[next(a for a in alternatives if a in RETIRED)]
            elif any(a in OPTIONAL for a in alternatives):
                status = STATUS_OPTIONAL
                detail = OPTIONAL[next(a for a in alternatives if a in OPTIONAL)]
            else:
                status = STATUS_MISSING
                detail = (by_program.get(alternatives[0], {}) or {}).get(
                    "note", "not installed on this host")
            entries.append({
                "kind": "program",
                "needs": " or ".join(alternatives),
                "used_by": owner,
                "status": status,
                "detail": detail,
                # Where it comes from, even before any install report exists:
                # the board is most useful on a machine where the install did
                # not finish.
                "installed_by": ((by_program.get(alternatives[0], {}) or {}).get("source")
                                 or SOURCES.get(alternatives[0], "")),
            })

    for owner, modules in sorted(EXTERNAL_MODULES.items()):
        for module in modules:
            try:
                __import__(module)
                status, detail = STATUS_OK, f"{module} importable"
            except Exception as exc:  # noqa: BLE001
                status, detail = STATUS_MISSING, f"{module}: {exc}"
            entries.append({"kind": "module", "needs": module, "used_by": owner,
                            "status": status, "detail": detail,
                            "installed_by": "requirements.txt"})

    for owner, spec in sorted(AVAILABILITY_PROBES.items()):
        module, attr = spec[0], spec[1]
        hint = spec[2] if len(spec) > 2 else ""
        try:
            probe_fn = getattr(__import__(module, fromlist=[attr]), attr)
            found = probe_fn() if callable(probe_fn) else probe_fn
            status = STATUS_OK if found else STATUS_MISSING
            detail = str(found) if found else (hint or "not found")
        except Exception as exc:  # noqa: BLE001
            status, detail = STATUS_MISSING, f"{module}.{attr}: {exc}"
        entries.append({"kind": "probe", "needs": owner.split(".")[-1],
                        "used_by": owner, "status": status, "detail": detail,
                        "installed_by": "install.sh"})

    counts: dict[str, int] = {}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    return {
        "generated_at": _utcnow(),
        "install_report_at": installed.get("generated_at", ""),
        "counts": counts,
        "healthy": counts.get(STATUS_MISSING, 0) == 0,
        "entries": entries,
    }


def problems() -> list[dict[str, Any]]:
    """Only the entries an operator can act on.

    Retired and optional programs stay on the board with their reason, but
    they are not faults: nothing the operator does will clear them, and
    counting them made a healthy install report four problems it did not have.
    """
    return [e for e in probe()["entries"] if e["status"] == STATUS_MISSING]


# Which part of the install provides each program. A missing entry on the
# board is only actionable if the operator is told where it comes from.
SOURCES: dict[str, str] = {
    # apt packages
    "fls": "apt sleuthkit", "icat": "apt sleuthkit", "mmls": "apt sleuthkit",
    "istat": "apt sleuthkit", "ewfmount": "apt libewf-tools",
    "ewfinfo": "apt libewf-tools", "bdemount": "apt libbde-utils",
    "bdeinfo": "apt libbde-utils", "vshadowmount": "apt libvshadow-utils",
    "qemu-img": "apt qemu-utils", "tcpdump": "apt tcpdump",
    "tshark": "apt tshark", "ngrep": "apt ngrep", "clamscan": "apt clamav",
    "binwalk": "apt binwalk", "unrar": "apt unrar", "7z": "apt p7zip-full",
    "upx": "apt upx-ucl", "sqlite3": "apt sqlite3", "exiftool": "apt libimage-exiftool-perl",
    "ssdeep": "apt ssdeep", "hashdeep": "apt hashdeep", "whois": "apt whois",
    "foremost": "apt foremost", "scalpel": "apt scalpel",
    "steghide": "apt steghide", "outguess": "apt outguess",
    "jpseek": "install.sh (builds h3xx/jphs, pinned in install-versions.env)",
    "esedbexport": "apt libesedb-utils (libesedb-tools with the GIFT PPA)",
    "esedbinfo": "apt libesedb-utils (libesedb-tools with the GIFT PPA)",
    "evtexport": "apt libevt-utils (libevt-tools with the GIFT PPA)",
    "velociraptor": "install.sh (Velocidex release, pinned in install-versions.env)",
    "bulk_extractor": "apt bulk-extractor", "photorec": "apt testdisk",
    "suricata": "install.sh --with-network-tools", "zeek": "install.sh --with-network-tools (adds the Zeek OBS repo)",
    "tcpxtract": "install.sh --with-network-tools", "readpst": "apt pst-utils",
    "pffexport": "apt libpff-utils", "dotnet": "apt dotnet-runtime",
    "strings": "apt binutils", "rz-bin": "apt rizin (optional; radare2 is the fallback)",
    "r2": "apt radare2", "die": "install.sh (Detect It Easy .deb, pinned in install-versions.env)",
    "diec": "install.sh (Detect It Easy .deb, pinned in install-versions.env)",
    # python packages from requirements.txt
    "capa": "pip flare-capa", "floss": "pip flare-floss", "olevba": "pip oletools",
    "mraptor": "pip oletools", "usn.py": "pip usnparser", "vol": "pip volatility3",
    "log2timeline.py": "pip plaso", "hindsight": "pip pyhindsight",
    "pe-carver": "pip pe-carver", "machinae": "pip machinae",
    "analyzemft": "pip analyzeMFT",
    # fetched by an install.sh step
    "rip.pl": "install.sh (RegRipper)", "chainsaw": "install.sh (Chainsaw)",
    "densityscout": "install.sh (DensityScout)",
    "INDXParse.py": "install.sh (INDXParse: pip into the venv, pinned in install-versions.env)",
    "pdfid.py": "install.sh (Didier Stevens suite)",
    "pdf-parser.py": "install.sh (Didier Stevens suite)",
}


def write_install_report(path: Path | None = None) -> Path:
    """Record what exists after an install, and where each program comes from.

    Run by install.sh as its last step: the board can then distinguish
    "never installed" from "the installer tried and it did not take".
    """
    from core.paths import tool_program
    from tools.tool_capabilities import EXTERNAL_BINARIES

    target = Path(path or INSTALL_REPORT)
    programs: dict[str, dict[str, str]] = {}
    for specs in EXTERNAL_BINARIES.values():
        for spec in specs:
            for name in str(spec).split("|"):
                if name in programs:
                    continue
                resolved = tool_program(name)
                programs[name] = {
                    "resolved": resolved or "",
                    "source": SOURCES.get(name, "not provided by the installer"),
                    "note": ("installed" if resolved else
                             RETIRED.get(name, "install step did not produce it")),
                }
    payload = {
        "generated_at": _utcnow(),
        "programs": programs,
        "installed": sum(1 for p in programs.values() if p["resolved"]),
        "total": len(programs),
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


if __name__ == "__main__":  # `python -m core.tool_health` after an install
    import sys

    if "--write-install-report" in sys.argv:
        written = write_install_report()
        report = load_install_report()
        print(f"tool report → {written} "
              f"({report.get('installed')}/{report.get('total')} programs present)")
    else:
        result = probe()
        print(json.dumps(result["counts"], indent=2))
        for entry in result["entries"]:
            if entry["status"] != STATUS_OK:
                where = entry.get("installed_by") or ""
                print(f"  [{entry['status']:9}] {entry['needs']:24} "
                      f"{entry['used_by']:32} {entry['detail'][:52]}")
                if where:
                    print(f"  {'':11} provided by: {where}")
