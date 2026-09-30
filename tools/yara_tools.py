"""YARA scanning via yara-python (no binary required)."""
import os
import glob
from typing import Optional
from fastmcp import FastMCP
from core.paths import assert_output_safe
from core import output_safe

mcp = FastMCP("yara")


def _compile_rules_or_inline(rules_path: Optional[str], inline_rule: Optional[str]):
    """Compile from exactly one of rules_path / inline_rule."""
    import yara
    if rules_path and inline_rule:
        raise ValueError("Pass either rules_path or inline_rule, not both.")
    if inline_rule:
        return yara.compile(source=inline_rule)
    if not rules_path:
        rules_path = bundled_rules_dir()
        if not rules_path:
            raise ValueError(
                "Pass rules_path (a .yar file or directory of rules) or "
                "inline_rule (complete YARA rule text); no bundled rules found."
            )
    return _compile_rules(rules_path)


def bundled_rules_dir() -> Optional[str]:
    """The rule sets shipped with Atlas (rules/ in the install), or None."""
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
    return d if os.path.isdir(d) else None


def _compile_rules(rules_path: str):
    import yara
    if os.path.isdir(rules_path):
        # Keyed by the path relative to the rules directory, which yara uses
        # as the namespace. Keying by basename let two files with the same
        # name in different sub-folders silently shadow each other.
        rule_files = {
            os.path.relpath(f, rules_path): f
            for f in sorted(
                glob.glob(os.path.join(rules_path, "**/*.yar"), recursive=True)
                + glob.glob(os.path.join(rules_path, "**/*.yara"), recursive=True))
        }
        if not rule_files:
            raise ValueError(f"No .yar/.yara files found in {rules_path}")
        return yara.compile(filepaths=rule_files)
    else:
        return yara.compile(filepath=rules_path)


def _match_to_dict(match) -> dict:
    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "tags": list(match.tags),
        "meta": dict(match.meta),
        "strings": [
            {"offset": s.instances[0].offset if s.instances else 0, "identifier": s.identifier}
            for s in match.strings
        ],
    }


@mcp.tool()
@output_safe
def yara_scan_file(file_path: str, rules_path: Optional[str] = None,
                   timeout: int = 60, inline_rule: Optional[str] = None) -> dict:
    """
    Scan a single file with YARA rules.
    rules_path: a .yar file or a directory of .yar/.yara files. Omit it (and
        inline_rule) to scan with the rule sets bundled with Atlas.
    inline_rule: alternatively, complete YARA rule text.
    Returns all matching rules with offsets and string identifiers.
    """
    try:
        import yara
        rules = _compile_rules_or_inline(rules_path, inline_rule)
        matches = rules.match(file_path, timeout=timeout)
        return {
            "success": True,
            "file": file_path,
            "match_count": len(matches),
            "matches": [_match_to_dict(m) for m in matches],
        }
    except Exception as e:
        return {"success": False, "error": str(e), "file": file_path, "matches": []}


@mcp.tool()
@output_safe
def yara_scan_directory(
    directory: str,
    rules_path: Optional[str] = None,
    recursive: bool = True,
    timeout_per_file: int = 30,
    max_files: int = 10000,
    inline_rule: Optional[str] = None,
) -> dict:
    """
    Scan all files in a directory with YARA rules.
    rules_path: path to a .yar file or directory of rules; or pass
    inline_rule: complete YARA rule text (pass exactly one).
    Returns files with matches only (non-matching files omitted).
    """
    try:
        import yara
        rules = _compile_rules_or_inline(rules_path, inline_rule)
        results = []
        errors = []
        scanned = 0

        pattern = "**/*" if recursive else "*"
        files = glob.glob(os.path.join(directory, pattern), recursive=recursive)

        # A directory arg is a legal gate input, but enumeration must not
        # read answer keys sitting next to the evidence (matched-string
        # context would leak their content into the analyst's output).
        from core.paths import is_solution_path

        for fpath in files[:max_files]:
            if not os.path.isfile(fpath):
                continue
            if is_solution_path(fpath):
                continue
            try:
                matches = rules.match(fpath, timeout=timeout_per_file)
                scanned += 1
                if matches:
                    results.append({
                        "file": fpath,
                        "matches": [_match_to_dict(m) for m in matches],
                    })
            except yara.TimeoutError:
                errors.append({"file": fpath, "error": "timeout"})
            except Exception as e:
                errors.append({"file": fpath, "error": str(e)})

        return {
            "success": True,
            "directory": directory,
            "scanned": scanned,
            "hits": len(results),
            "results": results,
            "errors": errors[:50],
        }
    except Exception as e:
        return {"success": False, "error": str(e), "directory": directory}


@mcp.tool()
@output_safe
def yara_scan_process_memory(
    dump_file: str,
    rules_path: Optional[str] = None,
    timeout: int = 120,
    inline_rule: Optional[str] = None,
) -> dict:
    """
    Scan a process memory dump file with YARA rules.
    dump_file: path to a .dmp or .raw memory file (e.g. from vol_memmap with dump=True).
    rules_path: path to a .yar file or directory of rules; or pass
    inline_rule: complete YARA rule text (pass exactly one).
    """
    return yara_scan_file(dump_file, rules_path, timeout=timeout,
                          inline_rule=inline_rule)


@mcp.tool()
@output_safe
def yara_compile_check(rules_path: str) -> dict:
    """
    Compile and validate a YARA rule file without scanning anything.
    Returns success/error — use before a scan to catch syntax errors early.
    """
    try:
        rules = _compile_rules(rules_path)
        return {"success": True, "rules_path": rules_path, "message": "Rules compiled successfully."}
    except Exception as e:
        return {"success": False, "error": str(e), "rules_path": rules_path}


@mcp.tool()
@output_safe
def yara_scan_memory_image(
    image_path: str,
    rules_path: Optional[str] = None,
    timeout: int = 300,
    inline_rule: Optional[str] = None,
) -> dict:
    """
    Scan a full memory image (e.g. ws01-memory.img) with YARA rules.
    Suitable for raw memory captures — not just per-process dumps.
    rules_path: path to a .yar file or directory of .yar/.yara files.
    inline_rule: alternatively, complete YARA rule text (pass exactly one).
    Use ~/atlas/rules/ for the built-in TTP rule library.
    timeout: per-scan timeout in seconds (default 300 — full images are large).
    """
    try:
        import yara
        rules = _compile_rules_or_inline(rules_path, inline_rule)
        matches = rules.match(image_path, timeout=timeout)
        return {
            "success": True,
            "image": image_path,
            "rules": rules_path or "<inline_rule>",
            "match_count": len(matches),
            "matches": [_match_to_dict(m) for m in matches],
        }
    except Exception as e:
        return {"success": False, "error": str(e), "image": image_path, "matches": []}


@mcp.tool()
@output_safe
def yara_scan_strings(inline_rule: str, file_path: str) -> dict:
    """
    Scan a file using an inline YARA rule string.
    inline_rule: complete YARA rule text (e.g. 'rule test { strings: $a = "evil" condition: $a }').
    """
    try:
        import yara
        rules = yara.compile(source=inline_rule)
        matches = rules.match(file_path)
        return {
            "success": True,
            "file": file_path,
            "match_count": len(matches),
            "matches": [_match_to_dict(m) for m in matches],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
