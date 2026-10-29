"""Network analysis tools — tcpdump, ngrep, pcap inspection."""
import functools
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional
from fastmcp import FastMCP
from core import run, run_with_output_file, output_safe
from core.paths import assert_output_safe

mcp = FastMCP("network")

# Names tcpdump is allowed to open under the AppArmor profile Debian and
# Ubuntu ship for it. Any other path is readable only under ``owner
# @{HOME}/**`` — a rule that stops matching the moment the process runs as
# root, which is exactly how the wrappers run it. A capture exported as
# .log or .dat is therefore denied with a bare "Permission denied" under
# sudo while ngrep and tcpxtract read the same file without complaint.
_TCPDUMP_READABLE_SUFFIXES = frozenset({".pcap", ".pcapng", ".cap"})


def _capture_for_tcpdump(pcap_file: str) -> str:
    """The path tcpdump gets to read: the file itself when its name already
    satisfies the profile, else a hard link (copy as fallback) under the
    case's ``analysis/pcap_staging/`` carrying a .pcap name.

    Staging is by name only — the bytes are the evidence file's own, and a
    hard link neither duplicates nor alters them. When no case directory is
    known or the link cannot be made, the original path is returned and
    tcpdump reports the denial.

    The link lives in a directory named after the evidence file, so the
    recorded command still names the file the analyst asked for: lineage is
    judged on the names a call and a finding share, and a mangled stem is a
    name nothing else uses.
    """
    src = Path(os.path.expanduser(pcap_file))
    if src.suffix.lower() in _TCPDUMP_READABLE_SUFFIXES or not src.is_file():
        return pcap_file
    try:
        from core.execution_log import log as _log
        case = _log.case_dir()
    except Exception:  # noqa: BLE001
        case = None
    if not case:
        return pcap_file
    staging = Path(case) / "analysis" / "pcap_staging"
    tag = hashlib.sha1(str(src.resolve()).encode()).hexdigest()[:8]
    staged = staging / src.name / f"{tag}.pcap"
    try:
        if staged.is_file():
            return str(staged)
        staged.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(src, staged)
        except OSError:
            shutil.copy2(src, staged)
        return str(staged)
    except OSError:
        return pcap_file


def _tcpdump_read(pcap_file: str, *args: str) -> list[str]:
    """argv for reading a capture: ``tcpdump -r <readable path> ...``."""
    return ["tcpdump", "-r", _capture_for_tcpdump(pcap_file), *args]


def _run_tcpdump_ascii(cmd: list[str], timeout: int) -> dict:
    """Run a large tcpdump ASCII extraction without the normal stdout cap."""
    import os
    import tempfile

    fh = tempfile.NamedTemporaryFile(
        prefix="atlas-tcpdump-", suffix=".txt", dir="/tmp", delete=False
    )
    path = fh.name
    fh.close()
    raw = run_with_output_file(cmd, output_path=path, needs_sudo=True, timeout=timeout)
    if raw.get("success"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                raw["stdout"] = f.read()
        except OSError as e:
            raw["success"] = False
            raw["stderr"] = f"failed to read tcpdump output {path}: {e}"
    try:
        os.unlink(path)
    except OSError:
        pass
    return raw


def _record_structured_marker(tool_name: str, raw: dict, summary: dict | None = None) -> int | None:
    """Record the MCP wrapper name, not only the underlying tcpdump command."""
    try:
        import json
        from core.execution_log import log

        raw_id = raw.get("_atlas_call_id")
        return log.record_tool_call(
            cmd=f"<py>:{tool_name}",
            success=bool(raw.get("success")),
            truncated=False,
            retries=0,
            exit_code=0 if raw.get("success") else int(raw.get("exit_code", 1) or 1),
            stderr=raw.get("stderr", ""),
            elapsed_seconds=0.0,
            stdout_excerpt=json.dumps(summary or {}, sort_keys=True)[:600],
            input_call_ids=[raw_id] if raw_id else None,
        )
    except Exception as e:
        import sys
        print(f"[Atlas WARN] structured marker failed for {tool_name}: {e}",
              file=sys.stderr)
        return None


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tcpdump_read(
    pcap_file: str,
    filter_expr: Optional[str] = None,
    count: int = 100,
    output_path: Optional[str] = None,
) -> dict:
    """
    Read and display packets from a PCAP file.
    filter_expr: BPF filter expression e.g. 'tcp and host 192.0.2.10' or 'port 443'.
    count: maximum number of packets to display (default 100; 0 = all).
    """
    cmd = _tcpdump_read(pcap_file, "-nn", "-tttt")
    if count > 0:
        cmd += ["-c", str(count)]
    if filter_expr:
        cmd += filter_expr.split()
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tcpdump_extract_http(pcap_file: str, output_path: Optional[str] = None) -> dict:
    """Extract HTTP traffic (ports 80, 8080, 8000, 8443) from a PCAP file."""
    cmd = _tcpdump_read(pcap_file, "-nn", "-A",
                        "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8443")
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tcpdump_extract_dns(pcap_file: str) -> dict:
    """Extract DNS queries and responses from a PCAP file."""
    cmd = _tcpdump_read(pcap_file, "-nn", "port 53")
    return run(cmd, needs_sudo=True, timeout=60)


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tcpdump_list_connections(pcap_file: str) -> dict:
    """Extract unique source/destination IP pairs and ports from a PCAP."""
    cmd = _tcpdump_read(pcap_file, "-nn", "-q", "tcp or udp")
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def ngrep_search(
    pcap_file: str,
    pattern: str,
    protocol: Optional[str] = None,
    case_insensitive: bool = True,
) -> dict:
    """
    Search PCAP payload data for a string or regex pattern using ngrep.
    pattern: string or regex to match in packet payloads.
    protocol: 'tcp', 'udp', 'icmp' — omit for all.
    Useful for finding credentials, commands, or malware C2 beacons in traffic.
    """
    # -q suppresses the per-packet '#' progress dump. Without it, ngrep prints
    # one '#' per inspected packet, and on a large pcap that progress noise
    # fills the captured stdout buffer before any actual match line is emitted
    # — causing real matches to be invisible under `truncated: true` output.
    cmd = ["ngrep", "-q", "-I", pcap_file]
    if case_insensitive:
        cmd.append("-i")
    cmd.append(pattern)
    if protocol:
        cmd.append(protocol)
    return run(cmd, needs_sudo=True, timeout=120)


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tcpdump_extract_ips(pcap_file: str) -> dict:
    """
    Extract all unique IP addresses from a PCAP.
    Returns sorted unique source and destination addresses.
    """
    import re
    from collections import Counter
    result = run(_tcpdump_read(pcap_file, "-nn", "-q"), needs_sudo=True, timeout=120)
    if not result["success"]:
        return {
            "success": False,
            "pcap": pcap_file,
            "error": result.get("stderr", ""),
            "_atlas_call_id": result.get("_atlas_call_id"),
        }
    # The executor caps the stdout the model sees but keeps the whole text
    # on disk. The address set must come from the whole capture: a beacon
    # that starts late in a pcap is otherwise never in the list, and the
    # list then says "8 addresses" about a capture holding a C2.
    ip_re = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    counts: Counter = Counter()
    spill = result.get("stdout_file") or ""
    complete = True
    if spill and os.path.isfile(spill):
        with open(spill, "rb") as f:
            for line in f:
                counts.update(ip_re.findall(line))
    else:
        counts.update(ip_re.findall((result.get("stdout") or "").encode("utf-8", "replace")))
        complete = not result.get("truncated")
    ips = sorted(k.decode() for k in counts)
    out = {
        "success": True,
        "pcap": pcap_file,
        "unique_ips": ips[:500],
        "count": len(ips),
        "by_packets": [{"ip": k.decode(), "lines": n} for k, n in counts.most_common(50)],
        "complete": complete,
        "_atlas_call_id": result.get("_atlas_call_id"),
    }
    if len(ips) > 500:
        out["note"] = (f"{len(ips)} addresses: unique_ips holds the first 500 in "
                       "sort order, by_packets the 50 busiest.")
    if not complete:
        out["note"] = ("the capture summary was truncated and no retained copy "
                       "was available: the list covers only its first part.")
    return out


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tcpdump_write_filtered(
    pcap_file: str,
    output_pcap: str,
    filter_expr: str,
) -> dict:
    """
    Write a filtered subset of packets to a new PCAP file.
    filter_expr: BPF filter e.g. 'host 192.0.2.10 and tcp'.
    output_pcap: path for the new PCAP (must be in exports/ or analysis/).
    """
    # tcpdump drops root to its own service user before it opens the file
    # named by -w; a case directory owned by the operator is not writable
    # for that user. Keep root for the write; the executor hands the file
    # back to the operator afterwards.
    cmd = (_tcpdump_read(pcap_file, "-Z", "root", "-w", output_pcap)
           + filter_expr.split())
    # The executor makes output_dir exist: hand it the directory, not the
    # file, or the file's own name becomes a directory tcpdump cannot write.
    return run(cmd, needs_sudo=True, timeout=300,
               output_dir=os.path.dirname(os.path.abspath(output_pcap)))


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def http_session_inventory(
    pcap_file: str,
    output_path: Optional[str] = None,
) -> dict:
    """
    Structured extraction of every HTTP session identity artifact from a PCAP.
    Returns a deterministic table — prefer this over keyword `ngrep` searches
    when hunting identity, session, or attribution data in plaintext HTTP.

    Extracts and groups by (source_ip, host, user_agent):
        - All Cookie names and values (Yahoo Y/T/B, Gmail gmailchat/NID/SID,
          Hotmail MSPAuth, AOL a/b, Facebook c_user/login_x, etc.)
        - URL auth parameters from GET/POST request lines
          (login=, email=, user=, gausr=, account=, screenname=, sn=)
        - Authorization headers
        - Email-like strings in URL paths/queries

    Output is a structured dict rather than raw text — no keyword guessing,
    no missed fields. Use this as the first identity-extraction step on any
    PCAP investigation; only fall back to ngrep for ad-hoc keyword lookups.

    output_path: optional path under analysis/ or exports/ to persist the
    structured table as JSON.
    """
    import json
    import re as _re

    # Pull HTTP traffic in ASCII; the same flags as tcpdump_extract_http but
    # we parse the output rather than return it raw.
    raw = _run_tcpdump_ascii(
        _tcpdump_read(pcap_file, "-nn", "-A") + [
         "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8443"],
        timeout=180,
    )
    if not raw.get("success"):
        return {
            "success": False,
            "pcap": pcap_file,
            "error": raw.get("stderr", "tcpdump failed"),
            "_atlas_call_id": raw.get("_atlas_call_id"),
        }

    text = raw.get("stdout", "") or ""

    # Group requests by (src_ip, host, user_agent) — each (src, host, UA)
    # tuple is roughly one browser session.
    src_re = _re.compile(r"IP (\d{1,3}(?:\.\d{1,3}){3})\.\d+ > \d{1,3}(?:\.\d{1,3}){3}\.\d+")
    host_re = _re.compile(r"Host:\s*([^\r\n]+)", _re.IGNORECASE)
    ua_re = _re.compile(r"User-Agent:\s*([^\r\n]+)", _re.IGNORECASE)
    cookie_re = _re.compile(r"Cookie:\s*([^\r\n]+)", _re.IGNORECASE)
    set_cookie_re = _re.compile(r"Set-Cookie:\s*([^\r\n]+)", _re.IGNORECASE)
    auth_re = _re.compile(r"Authorization:\s*([^\r\n]+)", _re.IGNORECASE)
    reqline_re = _re.compile(r"(GET|POST|HEAD|PUT|DELETE)\s+(\S+)\s+HTTP/", _re.IGNORECASE)
    url_param_re = _re.compile(
        r"[?&](login|email|username|user|gausr|account|screenname|sn|usr|uname)=([^&\s]+)",
        _re.IGNORECASE,
    )
    email_re = _re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    # Block requests on blank-line boundaries (best-effort for tcpdump -A output)
    blocks = _re.split(r"\n(?=\d{2}:\d{2}:\d{2})", text)

    sessions: dict[tuple, dict] = {}

    for block in blocks:
        src_m = src_re.search(block)
        host_m = host_re.search(block)
        ua_m = ua_re.search(block)
        if not src_m:
            continue
        src = src_m.group(1)
        host = host_m.group(1).strip() if host_m else "(no_host)"
        ua = ua_m.group(1).strip() if ua_m else "(no_ua)"
        key = (src, host, ua)

        if key not in sessions:
            sessions[key] = {
                "source_ip": src,
                "host": host,
                "user_agent": ua,
                "cookies": {},          # cookie_name -> set of values
                "set_cookies": {},
                "url_params": {},       # param_name -> set of values
                "auth_headers": [],
                "request_paths": [],
                "emails": [],
            }
        sess = sessions[key]

        for m in cookie_re.finditer(block):
            for kv in m.group(1).split(";"):
                kv = kv.strip()
                if "=" in kv:
                    name, value = kv.split("=", 1)
                    sess["cookies"].setdefault(name.strip(), set()).add(value.strip())

        for m in set_cookie_re.finditer(block):
            cookie_str = m.group(1).split(";")[0].strip()
            if "=" in cookie_str:
                name, value = cookie_str.split("=", 1)
                sess["set_cookies"].setdefault(name.strip(), set()).add(value.strip())

        for m in auth_re.finditer(block):
            val = m.group(1).strip()
            if val not in sess["auth_headers"]:
                sess["auth_headers"].append(val)

        for m in reqline_re.finditer(block):
            path = m.group(2)
            if path not in sess["request_paths"]:
                sess["request_paths"].append(path)
            for pm in url_param_re.finditer(path):
                sess["url_params"].setdefault(pm.group(1).lower(), set()).add(pm.group(2))

        for em in email_re.findall(block):
            if em not in sess["emails"]:
                sess["emails"].append(em)

    # Serialise sets to sorted lists for JSON
    out_sessions = []
    for sess in sessions.values():
        out_sessions.append({
            "source_ip": sess["source_ip"],
            "host": sess["host"],
            "user_agent": sess["user_agent"],
            "cookies": {k: sorted(v) for k, v in sess["cookies"].items()},
            "set_cookies": {k: sorted(v) for k, v in sess["set_cookies"].items()},
            "url_params": {k: sorted(v) for k, v in sess["url_params"].items()},
            "auth_headers": sess["auth_headers"],
            "request_paths": sess["request_paths"][:50],
            "emails": sess["emails"],
        })

    # Identity-bearing summary: every distinct cookie/param/email value seen
    all_cookie_values: dict[str, set] = {}
    all_url_param_values: dict[str, set] = {}
    all_emails: set = set()
    for sess in sessions.values():
        for k, vs in sess["cookies"].items():
            all_cookie_values.setdefault(k, set()).update(vs)
        for k, vs in sess["url_params"].items():
            all_url_param_values.setdefault(k, set()).update(vs)
        all_emails.update(sess["emails"])

    summary = {
        "session_count": len(sessions),
        "unique_cookie_names": sorted(all_cookie_values.keys()),
        "unique_cookie_values_by_name": {k: sorted(v) for k, v in all_cookie_values.items()},
        "unique_url_param_names": sorted(all_url_param_values.keys()),
        "unique_url_param_values_by_name": {k: sorted(v) for k, v in all_url_param_values.items()},
        "unique_emails": sorted(all_emails),
    }

    result = {
        "success": True,
        "pcap": pcap_file,
        "summary": summary,
        "sessions": out_sessions,
        "raw_call_id": raw.get("_atlas_call_id"),
    }
    marker_id = _record_structured_marker(
        "net_http_session_inventory",
        raw,
        {"session_count": summary["session_count"],
         "unique_emails": summary["unique_emails"][:10]},
    )
    result["_atlas_call_id"] = marker_id or raw.get("_atlas_call_id")

    if output_path:
        assert_output_safe(output_path)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        result["output_path"] = output_path

    return result


def _packet_blocks(text: str) -> list[str]:
    """Split tcpdump -tttt -A output into packet-ish blocks."""
    import re as _re

    starts = [
        m.start()
        for m in _re.finditer(
            r"(?m)^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+IP\s+",
            text,
        )
    ]
    if not starts:
        return [b for b in _re.split(r"\n(?=\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+IP\s+)", text) if b.strip()]
    starts.append(len(text))
    return [text[starts[i]:starts[i + 1]] for i in range(len(starts) - 1)]


def _roster_index(roster_names: Optional[list[str]]) -> dict[str, list[str]]:
    if not roster_names:
        return {}
    try:
        from tools.misc import _derive_person_variants
    except Exception:
        _derive_person_variants = None

    out: dict[str, list[str]] = {}
    for name in roster_names:
        raw = (name or "").strip()
        if not raw:
            continue
        if _derive_person_variants:
            variants = _derive_person_variants(raw)
        else:
            parts = raw.lower().split()
            variants = parts[:]
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                variants += [first + last, first[0] + last, last + first[0]]
        out[raw] = sorted({v.lower() for v in variants if len(v) >= 3})
    return out


def _match_roster(value: str, roster: dict[str, list[str]]) -> list[str]:
    import re as _re

    value_l = value.lower()
    prefix = value_l.split("@", 1)[0]
    compact = _re.sub(r"[^a-z0-9]", "", value_l)
    prefix_compact = _re.sub(r"[^a-z0-9]", "", prefix)
    matches: list[str] = []
    for name, variants in roster.items():
        for variant in variants:
            v_compact = _re.sub(r"[^a-z0-9]", "", variant)
            if (
                variant == prefix
                or variant == value_l
                or v_compact == prefix_compact
                or (len(v_compact) >= 5 and v_compact in compact)
            ):
                matches.append(name)
                break
    return sorted(matches)


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def pcap_identity_timeline(
    pcap_file: str,
    source_ip: Optional[str] = None,
    roster_names: Optional[list[str]] = None,
    output_path: Optional[str] = None,
) -> dict:
    """
    Build a deterministic timeline of identity-bearing PCAP artifacts.

    This is the attribution-safe companion to ad-hoc ngrep searches: it extracts
    HTTP query identities, identity cookies, email addresses, and simple YMSG
    profile/login fields, then cross-references them against roster-derived
    username variants. Use it before attributing a person from plaintext PCAP
    traffic, especially when multiple accounts appear on the same source host.

    source_ip: optional source IP to focus on after extraction.
    roster_names: optional list such as ["Jane Doe", "John Roe"].
    output_path: optional JSON path under analysis/ or exports/.
    """
    import json
    import re as _re
    from urllib.parse import parse_qsl, unquote_plus, urlsplit

    raw = _run_tcpdump_ascii(
        _tcpdump_read(
            pcap_file, "-nn", "-tttt", "-A",
            "tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8443 or tcp port 5050",
        ),
        timeout=180,
    )
    if not raw.get("success"):
        return {
            "success": False,
            "pcap": pcap_file,
            "error": raw.get("stderr", "tcpdump failed"),
            "_atlas_call_id": raw.get("_atlas_call_id"),
        }

    roster = _roster_index(roster_names)
    host_re = _re.compile(r"Host:\s*([^\r\n]+)", _re.IGNORECASE)
    ua_re = _re.compile(r"User-Agent:\s*([^\r\n]+)", _re.IGNORECASE)
    req_re = _re.compile(r"(GET|POST|HEAD|PUT|DELETE)\s+(\S+)\s+HTTP/", _re.IGNORECASE)
    cookie_re = _re.compile(r"(?:Cookie|Set-Cookie):\s*([^\r\n]+)", _re.IGNORECASE)
    email_re = _re.compile(
        r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?"
        r"@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b"
    )
    ip_re = _re.compile(
        r"(?m)^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+IP\s+"
        r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})\.(?P<src_port>\d+)\s+>\s+"
        r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})\.(?P<dst_port>\d+):"
    )
    identity_params = {
        "login", "email", "username", "user", "gausr", "account",
        "screenname", "sn", "usr", "uname", "req0_value",
    }
    identity_cookies = {
        "gmailchat", "ol_session", "ys", "y", "t", "f", "mspauth",
        "c_user", "login_x",
    }

    rows: list[dict] = []

    def add_row(order: int, header: _re.Match, block: str, kind: str,
                field: str, value: str) -> None:
        decoded = unquote_plus(value.strip())
        if not decoded:
            return
        matches = _match_roster(decoded, roster)
        confidence = "high" if matches and (kind in {"url_param", "cookie", "email"}) else (
            "medium" if matches else "low"
        )
        excerpt = " ".join(block.split())[:240]
        rows.append({
            "order": order,
            "timestamp": header.group("ts"),
            "source_ip": header.group("src"),
            "source_port": int(header.group("src_port")),
            "destination_ip": header.group("dst"),
            "destination_port": int(header.group("dst_port")),
            "host": (host_re.search(block).group(1).strip()
                     if host_re.search(block) else ""),
            "user_agent": (ua_re.search(block).group(1).strip()
                           if ua_re.search(block) else ""),
            "identity_type": kind,
            "field": field,
            "value": decoded,
            "roster_matches": matches,
            "confidence": confidence,
            "evidence_excerpt": excerpt,
        })

    for order, block in enumerate(_packet_blocks(raw.get("stdout", "") or ""), start=1):
        header = ip_re.search(block)
        if not header:
            continue
        if source_ip and header.group("src") != source_ip:
            continue
        decoded_block = unquote_plus(block)

        for req_m in req_re.finditer(block):
            path = req_m.group(2)
            split = urlsplit(path)
            for key, value in parse_qsl(split.query, keep_blank_values=False):
                if key.lower() in identity_params:
                    add_row(order, header, block, "url_param", key.lower(), value)

        for key, value in _re.findall(
            r"(?:^|[?&;\s])"
            r"(login|email|username|user|gausr|account|screenname|sn|usr|uname|req0_value)"
            r"=([^&;\s]+)",
            decoded_block,
            flags=_re.IGNORECASE,
        ):
            add_row(order, header, block, "param", key.lower(), value)

        for cookie_m in cookie_re.finditer(block):
            cookie_blob = cookie_m.group(1)
            for part in cookie_blob.split(";"):
                if "=" not in part:
                    continue
                name, value = part.strip().split("=", 1)
                name_l = name.strip().lower()
                decoded_value = unquote_plus(value)
                if name_l in identity_cookies or email_re.search(decoded_value):
                    add_row(order, header, block, "cookie", name.strip(), value)

        for email in email_re.findall(decoded_block):
            add_row(order, header, block, "email", "payload", email)

        if "YMSG" in block:
            for field, value in _re.findall(r"(1|216|254)\.\.([A-Za-z][A-Za-z0-9._-]{2,})", block):
                add_row(order, header, block, "ymsg_field", field, value)

    seen: set[tuple] = set()
    deduped: list[dict] = []
    for row in rows:
        key = (
            row["timestamp"], row["source_ip"], row["host"], row["identity_type"],
            row["field"], row["value"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)

    matched_by_person: dict[str, list[str]] = {}
    identities_by_source: dict[str, list[str]] = {}
    for row in deduped:
        identities_by_source.setdefault(row["source_ip"], [])
        if row["value"] not in identities_by_source[row["source_ip"]]:
            identities_by_source[row["source_ip"]].append(row["value"])
        for name in row["roster_matches"]:
            matched_by_person.setdefault(name, [])
            if row["value"] not in matched_by_person[name]:
                matched_by_person[name].append(row["value"])

    result = {
        "success": True,
        "pcap": pcap_file,
        "source_ip": source_ip,
        "summary": {
            "identity_artifact_count": len(deduped),
            "roster_match_count": sum(1 for r in deduped if r["roster_matches"]),
            "matched_by_person": matched_by_person,
            "identities_by_source_ip": identities_by_source,
        },
        "identities": deduped,
        "raw_call_id": raw.get("_atlas_call_id"),
    }
    marker_id = _record_structured_marker(
        "net_pcap_identity_timeline",
        raw,
        {
            "identity_artifact_count": result["summary"]["identity_artifact_count"],
            "roster_match_count": result["summary"]["roster_match_count"],
            "matched_by_person": matched_by_person,
        },
    )
    result["_atlas_call_id"] = marker_id or raw.get("_atlas_call_id")

    if output_path:
        assert_output_safe(output_path)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        result["output_path"] = output_path

    return result


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def zeek_analyze(pcap_file: str, output_dir: str) -> dict:
    """
    Run Zeek over a PCAP offline, producing protocol logs (conn.log, dns.log,
    http.log, ssl.log, files.log, …) in output_dir (under analysis/ or
    exports/). Returns the list of generated log files.
    """
    from core.paths import missing_program_result, tool_program
    assert_output_safe(output_dir)
    program = tool_program("zeek")
    if not program:
        return missing_program_result("net.zeek_analyze", "zeek",
                                      "install.sh --with-network-tools")
    os.makedirs(output_dir, exist_ok=True)
    # zeek runs inside output_dir so its logs land there; the capture path
    # must therefore be absolute, or a case-relative name no longer resolves.
    capture = os.path.abspath(os.path.expanduser(pcap_file))
    result = run([program, "-C", "-r", capture, "local"],
                 timeout=600, cwd=output_dir)
    if result.get("success"):
        logs = sorted(f for f in os.listdir(output_dir) if f.endswith(".log"))
        result["logs"] = logs
        _record_structured_marker("net_zeek_analyze", result,
                                   {"log_count": len(logs), "logs": logs})
    return result


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def suricata_analyze(
    pcap_file: str,
    output_dir: str,
    rules_file: Optional[str] = None,
) -> dict:
    """
    Run Suricata IDS over a PCAP offline into output_dir (analysis/ or
    exports/). rules_file: optional custom ruleset. Summarizes the alert count
    from eve.json when present.
    """
    import os
    import shutil as _sh
    if not _sh.which("suricata"):
        return {"success": False, "error": "'suricata' not found on PATH"}
    assert_output_safe(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["suricata", "-r", pcap_file, "-l", output_dir]
    if rules_file:
        cmd += ["-S", rules_file]
    result = run(cmd, timeout=600)
    eve = os.path.join(output_dir, "eve.json")
    if result.get("success") and os.path.exists(eve):
        import json as _json
        alerts = 0
        signatures: dict[str, int] = {}
        try:
            with open(eve, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        ev = _json.loads(line)
                    except ValueError:
                        continue
                    if ev.get("event_type") == "alert":
                        alerts += 1
                        sig = ev.get("alert", {}).get("signature", "?")
                        signatures[sig] = signatures.get(sig, 0) + 1
        except OSError:
            pass
        result["alert_count"] = alerts
        result["top_signatures"] = sorted(
            signatures.items(), key=lambda kv: -kv[1])[:10]
        _record_structured_marker("net_suricata_analyze", result,
                                   {"alert_count": alerts})
    return result


def _tshark(args: list[str], timeout: int = 180) -> dict:
    import shutil as _sh
    if not _sh.which("tshark"):
        return {"success": False, "error": "'tshark' not found on PATH"}
    return run(["tshark"] + args, needs_sudo=True, timeout=timeout)


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tshark_protocol_hierarchy(pcap_file: str) -> dict:
    """Protocol hierarchy statistics (io,phs) for a PCAP, via tshark."""
    return _tshark(["-r", pcap_file, "-q", "-z", "io,phs"])


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tshark_conversations(pcap_file: str, proto: str = "tcp") -> dict:
    """
    Conversation statistics for a PCAP (endpoints, packets, bytes), via tshark.
    proto: one of tcp, udp, ip, eth.
    """
    if proto not in ("tcp", "udp", "ip", "eth"):
        return {"success": False,
                "error": "proto must be one of: tcp, udp, ip, eth"}
    return _tshark(["-r", pcap_file, "-q", "-z", f"conv,{proto}"])


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tshark_ja3(pcap_file: str) -> dict:
    """
    Extract JA3/JA3S TLS client/server fingerprints from a PCAP via tshark.

    Requires a tshark build with the tls.handshake.ja3 field; if unavailable,
    the underlying error is surfaced verbatim.
    """
    return _tshark([
        "-r", pcap_file, "-Y", "tls.handshake.type==1", "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "tls.handshake.ja3",
        "-e", "tls.handshake.ja3_full",
    ])


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tcpxtract_streams(
    pcap_file: str,
    output_dir: str,
) -> dict:
    """
    Carve files out of the packet payloads of a PCAP by content signature
    (tcpxtract). Each hit is written from its header to the footer or the
    size cap its type has in tcpxtract.conf, not to the end of the transfer:
    a large object, or one whose footer the configuration does not know,
    comes out cut short or not at all. net.tshark_export_objects writes the
    objects a protocol carried, whole and under their own names.
    output_dir: destination for the carved files.
    """
    import os
    os.makedirs(output_dir, exist_ok=True)
    cmd = ["tcpxtract", "-f", pcap_file, "-o", output_dir]
    return run(cmd, needs_sudo=True, timeout=300, output_dir=output_dir)


# tshark's own vocabulary for --export-objects: the dissectors that hand a
# complete object to its export tap. The installed build is asked once per
# process (``tshark --export-objects help``); this is the set of the builds
# known when the tool was written, used when the build cannot be asked. A
# fact of the program, not a rule of what to look for.
_EXPORT_OBJECT_PROTOCOLS = ("http", "ftp-data", "smb", "tftp", "imf", "dicom")
_PROTOCOL_TOKEN = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@functools.lru_cache(maxsize=1)
def _export_protocols() -> tuple[str, ...]:
    """The export object types the installed tshark lists, in its order; the
    written set when it cannot be asked (no tshark, a build without the
    help form, a timeout). A capability query, not a tool call: nothing of
    the case is read, so it is not a traced command."""
    try:
        proc = subprocess.run(["tshark", "--export-objects", "help"], capture_output=True,
                              text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return _EXPORT_OBJECT_PROTOCOLS
    lines = (proc.stderr + "\n" + proc.stdout).splitlines()
    listed = []
    seen_head = False
    for line in lines:
        if "export object types" in line.lower():
            seen_head = True
            continue
        token = line.strip()
        if seen_head and _PROTOCOL_TOKEN.match(token):
            listed.append(token)
    return tuple(listed) or _EXPORT_OBJECT_PROTOCOLS


@mcp.tool(meta={"input_names": ["*.pcap", "*.pcapng", "*.cap"]})
@output_safe
def tshark_export_objects(
    pcap_file: str,
    output_dir: str,
    protocol: str = "http",
) -> dict:
    """
    Write the objects a protocol carried in a PCAP as whole files,
    reassembled from the TCP stream by tshark's dissectors, each under the
    name the protocol gave it (an HTTP object: its URL path, with / and ?
    encoded). protocol: http, ftp-data, smb, tftp, imf or dicom (the
    installed tshark's own list; a name it does not list is refused with
    the list). Nothing is carved by signature; an object the dissector did
    not see complete (a transfer the capture cut) may not be written, so no
    object means no complete object of that protocol, not an empty capture.
    The result counts every object and lists up to 200, largest first; a
    name over 200 characters is shortened in the list, the directory holds
    the full name. output_dir: where the objects go.
    """
    import shutil as _sh
    protocols = _export_protocols()
    if protocol not in protocols:
        return {"success": False,
                "error": f"protocol must be one of: {', '.join(protocols)}"}
    if not _sh.which("tshark"):
        return {"success": False, "error": "'tshark' not found on PATH"}
    # No sudo: the Atlas user reads evidence already (the Python readers do),
    # and a dissector over an attacker-supplied capture runs unprivileged.
    # run() checks and creates output_dir itself.
    result = run(["tshark", "-r", pcap_file, "-q", "--export-objects", f"{protocol},{output_dir}"],
                 timeout=600, output_dir=output_dir)
    if result.get("success"):
        total, listed, shortened = _exported_objects(output_dir)
        result["output_dir"] = output_dir
        result["object_count"] = total
        result["objects"] = listed
        notes = []
        if total > len(listed):
            notes.append(f"{len(listed)} of {total} objects listed, largest first; the directory "
                         "holds them all")
        if shortened:
            notes.append("names over 200 characters are shortened in this list; the directory "
                         "holds the full names")
        if notes:
            result["note"] = "; ".join(notes)
    return result


def _exported_objects(output_dir: str, limit: int = 200) -> tuple[int, list[dict], bool]:
    """``(count, listed, shortened)``: how many regular files lie directly
    under output_dir, the largest ``limit`` of them as ``{"name",
    "size_bytes"}``, and whether a listed name was cut. The names are what
    the protocol carried, chosen by whoever sent the object: each is shown
    JSON-quoted and escaped, nothing under a subdirectory or behind a link
    is listed, and a file is listed only when it resolves under the
    directory."""
    from core.coverage_ledger import shown_name  # loaded after the tool modules
    root = os.path.realpath(output_dir)
    found: list[tuple[int, str]] = []
    try:
        with os.scandir(root) as it:
            for entry in it:
                if not entry.is_file(follow_symlinks=False):
                    continue
                if os.path.dirname(os.path.realpath(entry.path)) != root:
                    continue
                found.append((entry.stat(follow_symlinks=False).st_size, entry.name))
    except OSError:
        return 0, [], False
    found.sort(key=lambda t: (-t[0], t[1]))
    top = found[:limit]
    listed = [{"name": shown_name(name), "size_bytes": size} for size, name in top]
    return len(found), listed, any(len(name) > 200 for _size, name in top)
