"""Gate: external-world facts must be tool-checked — model memory is not evidence.

Principle (case-independent)
---------------------------
The analyst LLM has *parametric* knowledge: associations baked into its weights
from pre-training (web text, docs, blogs). That is **not** a Atlas tool result
and **not** case evidence. It is often stale or wrong.

CONFIRMED / LIKELY findings may only assert external-world identity facts when
the rows of a cited call show a **verifying tool** was run (or the claim
is a literal quote of case evidence — handled by not matching these patterns).

External-world fact classes covered here (extend ``_RULES`` as new lookup
tools appear):

  - MAC/OUI → organization          → enrich.oui_lookup
  - IP → geo / ASN / reputation     → enrich.vt_lookup_ip | abuseipdb | whois
  - Domain → ownership / reputation → enrich.vt_lookup_domain | whois | otx
  - File hash → malware family      → enrich.vt_lookup_hash
  - Malware family / tool name      → the name itself must appear in cited
                                      evidence (a scanner, rule or lookup
                                      that printed it)
  - CVE identity as confirmed cause → CVE string must appear in cited evidence
                                      *or* an enrich/advisory lookup marker
  - Explicit "from training / model memory / common knowledge" admissions

A literal evidence string (e.g. a USB product name) supports quoting that
string — it does **not** satisfy a different class (e.g. MAC-OUI→vendor).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ._match import lineage_evidence_text, printed_name


@dataclass(frozen=True)
class _ExternalFactRule:
    """One class of unchecked external claim → required verification marker.

    With ``name_group`` the claim names the external fact itself (a malware
    family), and the check is that this very name occurs in the cited
    evidence - some tool printed it - rather than that a lookup of any kind
    ran.
    """
    id: str
    claim: re.Pattern[str]
    evidence_ok: re.Pattern[str]
    remediation: str
    name_group: int = 0


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# ── Claim detectors + required evidence markers ──────────────────────────────

_RULES: tuple[_ExternalFactRule, ...] = (
    _ExternalFactRule(
        id="mac_oui_vendor",
        claim=_re(
            r"(?:"
            r"(?:OUI|organizationally\s+unique(?:\s+identifier)?|"
            r"MAC\s*(?:address\s*)?(?:prefix|vendor)|mac\s*vendor)"
            r".{0,100}?"
            r"(?:belongs\s+to|assigned\s+to|maps\s+to|is\s+(?:registered\s+to|a)|"
            r"→|->|vendor|manufacturer|organisation|organization)"
            r"|"
            r"(?:belongs\s+to|assigned\s+to|registered\s+to|manufactured\s+by|"
            r"vendor\s+is|manufacturer\s+is)"
            r".{0,80}?"
            r"(?:based\s+on|from|via|per|using)\s+(?:the\s+)?(?:MAC|OUI|prefix)"
            r"|"
            r"(?:based\s+on|from|via|per)\s+(?:the\s+)?(?:MAC|OUI|prefix|MAC\s*OUI)"
            r".{0,80}?"
            r"(?:belongs|vendor|manufacturer)"
            r"|"
            r"(?:prefix|OUI)\s+[0-9A-Fa-f][:\-.]?[0-9A-Fa-f]{2}"
            r"[:\-.]?[0-9A-Fa-f]{2}.{0,40}?(?:belongs\s+to|is\s+|→|->|maps\s+to)"
            r")"
        ),
        evidence_ok=_re(
            r"(?:oui_lookup|enrich\.oui_lookup|enrich_oui_lookup|"
            r"ieee\s+ma-l|ieee\s+oui|oui\.txt|prefix_dashed|"
            r"registry[\"']?\s*:\s*[\"']?IEEE)"
        ),
        remediation=(
            "Call enrich.oui_lookup(mac_or_oui=…) against local IEEE oui.txt, "
            "cite that call_id, or downgrade to SUSPECTED/HUNCH and label "
            "the vendor unverified. A USB product string does not ground a "
            "MAC-OUI vendor claim."
        ),
    ),
    _ExternalFactRule(
        id="ip_geo_asn_reputation",
        claim=_re(
            r"(?:"
            r"\b(?:IP|IPv4|IPv6|address)\b.{0,60}?"
            r"(?:located\s+in|geolocat\w*|geo\s*ip|ASN\b|as[_ ]?number|"
            r"autonomous\s+system|hosted\s+(?:by|in)|belongs\s+to\s+(?:AS|ISP)|"
            r"reputation\s+(?:score|is)|malicious\s+(?:IP|address))"
            r"|"
            r"(?:geolocat\w*|ASN\b|as[_ ]?owner|ISP\b).{0,40}?"
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            r")"
        ),
        evidence_ok=_re(
            r"(?:vt_lookup_ip|enrich\.vt_lookup_ip|abuseipdb|whois|"
            r"as_owner|\"asn\"\s*:|country[\"']?\s*:|geoloc)"
        ),
        remediation=(
            "Cite enrich.vt_lookup_ip / enrich.abuseipdb_check / whois output "
            "for that IP, or downgrade to HUNCH/SUSPECTED."
        ),
    ),
    _ExternalFactRule(
        id="domain_ownership_reputation",
        claim=_re(
            r"(?:"
            r"\b(?:domain|hostname|FQDN)\b.{0,80}?"
            r"(?:registered\s+(?:to|by)|owned\s+by|whois|registrar|"
            r"malicious\s+domain|typosquat|phishing\s+domain|"
            r"reputation\s+(?:score|is))"
            r"|"
            r"(?:registered\s+(?:to|by)|owned\s+by|whois\s+shows).{0,60}?"
            r"\b(?:domain|hostname)\b"
            r")"
        ),
        evidence_ok=_re(
            r"(?:vt_lookup_domain|enrich\.vt_lookup_domain|whois|"
            r"otx_.*domain|registrar|passive_dns|\"domain\"\s*:)"
        ),
        remediation=(
            "Cite enrich.vt_lookup_domain / whois / OTX domain lookup output, "
            "or downgrade to HUNCH/SUSPECTED."
        ),
    ),
    _ExternalFactRule(
        id="hash_malware_family",
        claim=_re(
            r"(?:"
            r"\b(?:MD5|SHA-?1|SHA-?256|hash)\b.{0,100}?"
            r"(?:is\s+(?:known\s+)?(?:malware|ransomware|trojan|backdoor|"
            r"stealer|family|detected\s+as)|identified\s+as|classified\s+as|"
            r"matches\s+(?:family|malware))"
            r"|"
            r"(?:malware\s+family|known\s+(?:malware|ransomware|trojan)|"
            r"detected\s+as\s+\w+).{0,80}?"
            r"\b(?:MD5|SHA-?1|SHA-?256|hash|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b"
            r")"
        ),
        evidence_ok=_re(
            r"(?:vt_lookup_hash|enrich\.vt_lookup_hash|virustotal|"
            r"last_analysis_stats|malicious[\"']?\s*:\s*\d|"
            r"yara\.scan|yara_scan)"
        ),
        remediation=(
            "Cite enrich.vt_lookup_hash (or a yara.scan_* hit that names the "
            "family) before asserting malware identity at CONFIRMED/LIKELY."
        ),
    ),
    # A family or tool name bound to a malware-class noun: "the implant is
    # Cobalt Strike", "malware identified as Emotet", "a RedCurtain implant".
    # The name is the analyst's unless a scanner, a rule hit or a lookup in
    # the cited evidence printed it. Grammar only - no list of families.
    _ExternalFactRule(
        id="malware_family_attribution",
        claim=re.compile(
            r"(?:\b(?:malware|implant|beacon|trojan|backdoor|loader|stealer|"
            r"ransomware|rootkit|rat|toolkit|framework)\b(?:\s+family)?\s+"
            r"(?:(?:was|is|were|are)\s+)?(?:(?:identified|classified|attributed|"
            r"recogni[sz]ed|known|named|confirmed|assessed)\s+(?:as|to\s+be|to)|"
            r"consistent\s+with|matches|is|was|named|called)\s+(?:the\s+|a\s+|an\s+)?"
            r"([A-Z][\w-]{2,}(?:\s+[A-Z][\w-]{2,})?)"
            r"|\b([A-Z][\w-]{2,}(?:\s+[A-Z][\w-]{2,})?)\s+"
            r"(?:malware|implant|beacon|trojan|backdoor|loader|stealer|ransomware|"
            r"rootkit|rat)\b)",
            re.DOTALL),
        evidence_ok=_re(r"(?!x)x"),   # the name itself must occur; see check()
        remediation=(
            "Name the family only when a cited scanner, rule hit or lookup "
            "(yara, capa, clamscan, enrich.vt_lookup_hash) printed that name, "
            "and cite that call - or downgrade to SUSPECTED and state the "
            "attribution as a hypothesis."
        ),
        name_group=1,
    ),
    _ExternalFactRule(
        id="cve_identity",
        claim=_re(
            r"(?:"
            r"\bCVE-\d{4}-\d{4,}\b.{0,80}?"
            r"(?:exploited|used\s+to|caused|is\s+the\s+(?:root\s+)?cause|"
            r"confirmed|responsible\s+for|vulnerability\s+was)"
            r"|"
            r"(?:exploited|root\s+cause|vulnerability\s+was|patched\s+via)"
            r".{0,60}?\bCVE-\d{4}-\d{4,}\b"
            r")"
        ),
        # Either the CVE ID appears in cited tool output, or an advisory lookup.
        evidence_ok=_re(
            r"(?:CVE-\d{4}-\d{4,}|nvd\.nist|cve\.mitre|advisory|"
            r"enrich\.|vuln)"
        ),
        remediation=(
            "The CVE ID must appear in cited tool/evidence output (advisory, "
            "patch note, scanner hit), or downgrade — do not assign a CVE from "
            "model memory alone."
        ),
    ),
)

# Names of network protocols, transport and application layers, Windows
# management interfaces and runtimes a DFIR reader uses as adjectives
# ("an SMB beacon", "the PowerShell loader"): universal knowledge, not a
# list of families. They are plain words, never a name.
_PROTOCOL_WORDS = frozenset({
    "smb", "http", "https", "dns", "tcp", "udp", "rdp", "ssh", "ftp", "smtp", "imap", "ldap",
    "kerberos", "ntlm", "wmi", "winrm", "powershell", ".net", "net", "tls", "ssl", "socks",
    "icmp", "webdav", "vpn", "api",
})
_PROTO = r"(?i:\.NET|" + "|".join(sorted((w for w in _PROTOCOL_WORDS if w != ".net"), key=len,
                                          reverse=True)) + r")\b"
_CLASS_NOUN = r"(?:malware|implant|beacon|trojan|backdoor|loader|stealer|ransomware|rootkit|rat)\b"
_NAME_WORD = r"[A-Z][\w-]{2,}"
_NAME_V2 = rf"({_NAME_WORD}(?:\s+(?!{_PROTO}){_NAME_WORD})?)"
# ATLAS_EXTERNAL_LOOKUP_FIRST: a run of protocol words may stand between the
# name and the class noun ("<Name> SMB beacon" binds "<Name>"), and a
# protocol word is never the name's second word.
_FAMILY_CLAIM_V2 = re.compile(
    r"(?:\b(?:malware|implant|beacon|trojan|backdoor|loader|stealer|"
    r"ransomware|rootkit|rat|toolkit|framework)\b(?:\s+family)?\s+"
    r"(?:(?:was|is|were|are)\s+)?(?:(?:identified|classified|attributed|"
    r"recogni[sz]ed|known|named|confirmed|assessed)\s+(?:as|to\s+be|to)|"
    r"consistent\s+with|matches|is|was|named|called)\s+(?:the\s+|a\s+|an\s+)?"
    + _NAME_V2 + r"|\b" + _NAME_V2 + rf"\s+(?:{_PROTO}\s+)*" + _CLASS_NOUN + ")",
    re.DOTALL)


def _lookup_first() -> bool:
    from core.envfile import env_flag
    return env_flag("ATLAS_EXTERNAL_LOOKUP_FIRST")


# Explicit admissions that the source is model memory / "common knowledge".
_PARAMETRIC_SOURCE_RE = _re(
    r"\b(?:from\s+(?:my\s+)?(?:training|prior)\s+knowledge"
    r"|from\s+model\s+memory"
    r"|based\s+on\s+(?:common|general|public|internal)\s+knowledge"
    r"|known\s+(?:manufacturer|vendor|family|CVE)\s+of"
    r"|without\s+(?:an?\s+)?(?:tool|lookup|registry|database)\s+check"
    r"|I\s+(?:know|recall)\s+(?:that|from)\b)"
)


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None

    desc = ctx.description or ""
    # What the cited calls printed, and which tools they were: that a
    # verifying tool ran is the trace's record of the call, not the
    # analyst's words; its arguments are left out.
    evidence = f"{lineage_evidence_text(ctx)} \n {_cited_tool_names(ctx)}"

    if _PARAMETRIC_SOURCE_RE.search(desc):
        return {
            "gate": "external_knowledge_grounding",
            "success": False,
            "error": (
                "[external_knowledge_grounding] This finding treats model "
                "training memory / 'common knowledge' as a factual source. "
                "Atlas only accepts (1) literal case-evidence strings or "
                "(2) cited verifying-tool output. Re-run the appropriate "
                "enrich.* / whois / scanner tool and cite it, or downgrade "
                "to HUNCH/SUSPECTED and label the claim unverified."
            ),
            "detail_gate": "parametric_source",
        }

    for rule in _RULES:
        named = ""
        if rule.name_group:
            # Every binding in the description is read: the sentence opener
            # "The implant" is grammar, the later "implant is X" is the claim.
            # The name must come from a tool: the analyst's own
            # supporting_evidence repeating it is the same claim twice.
            if _lookup_first():
                cited = _cited_entries(ctx)
                run_start = _run_start(ctx)
                names = [_claimed_name(m) for m in _FAMILY_CLAIM_V2.finditer(desc)]
                names = [n for n in dict.fromkeys(names)
                         if n and not any(printed_name(e, n, run_start) for e in cited)]
                if not names:
                    continue
                return _lookup_first_refusal(rule, names[0], desc, cited)
            printed = _cited_tool_text(ctx).lower()
            names = [_claimed_name(m) for m in rule.claim.finditer(desc)]
            names = [n for n in names if n and n.lower() not in printed]
            if not names:
                continue
            named = names[0]
        else:
            if not rule.claim.search(desc):
                continue
            if rule.evidence_ok.search(evidence):
                continue
            if rule.id in _INTEL_RATEABLE and _intel_grounded(ctx, desc):
                continue
        return {
            "gate": "external_knowledge_grounding",
            "success": False,
            "error": (
                f"[external_knowledge_grounding:{rule.id}] CONFIRMED/LIKELY "
                f"external-world fact requires a verifying tool result in the rows of "
                f"a cited call (input_call_ids; text in supporting_evidence is not a row). "
                + (f"No cited output prints the name {named!r}. " if named else "")
                + rule.remediation
                + ("" if "SUSPECTED" in rule.remediation
                   else " Or record it at SUSPECTED, naming what would verify it.")
            ),
            "detail_gate": rule.id,
            **({"unverified_name": named} if named else {}),
        }

    return None


# Rules whose claim is a rating an operator's threat context may state:
# "per intel-0003" attributes it to the row's source (core.threat_context).
_INTEL_RATEABLE = frozenset({"ip_geo_asn_reputation", "domain_ownership_reputation",
                             "hash_malware_family"})


def _intel_grounded(ctx, desc: str) -> bool:
    """The finding cites an active threat-context row whose value it names,
    and a cited evidence call shows that value: the rating is the source's
    claim, the presence the evidence's."""
    try:
        from core.threat_context import grounds_rating
        from .negative_completeness import _case_dir
        return bool(grounds_rating(_case_dir(ctx), desc, _cited_tool_text(ctx),
                                   also=ctx.supporting_evidence or ""))
    except Exception:  # noqa: BLE001 - no record, no grounding
        return False


def _cited_tool_text(ctx) -> str:
    """What the cited forensic tools printed (command line, excerpt, spilled
    output), without the analyst's own words."""
    from .citation_support import call_output_text, evidence_calls
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    cids = list(ctx.input_call_ids or [])
    if ctx.linked_call_id:
        cids.append(ctx.linked_call_id)
    cited = [by_id.get(c) for c in dict.fromkeys(cids) if by_id.get(c)]
    return " \n ".join(call_output_text(e) for e in evidence_calls(cited))


def _cited_tool_names(ctx) -> str:
    """The names of the tools the cited calls ran (a typed tool's name, else
    the program a command line starts with), without their arguments."""
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    names = []
    for c in list(ctx.input_call_ids or []) + [ctx.linked_call_id]:
        e = by_id.get(c) if c else None
        if not isinstance(e, dict):
            continue
        cmd = str(e.get("mcp_tool") or e.get("cmd") or "").strip()
        cmd = cmd[len("<py>:"):] if cmd.startswith("<py>:") else cmd
        words = [w for w in cmd.split() if w not in ("sudo", "timeout", "env")]
        if words:
            names.append(words[0].rsplit("/", 1)[-1])
    return " ".join(names)


def _cited_entries(ctx) -> list[dict]:
    """The cited tool calls, read by id over the whole trace: a cited
    lookup is what grounds a name, so lookups are not filtered out here."""
    by_id = getattr(ctx.idx, "by_call_id", {}) or {}
    cids = []
    for c in list(ctx.input_call_ids or []) + [ctx.linked_call_id]:
        try:
            if c:
                cids.append(int(c))
        except (TypeError, ValueError):
            continue
    return [e for e in (by_id.get(c) for c in dict.fromkeys(cids))
            if isinstance(e, dict) and e.get("type") == "tool_call"]


def _run_start(ctx) -> Optional[float]:
    """When the trace's first entry was written (epoch seconds): a rule file
    older than that was not written by this run's analyst."""
    try:
        from datetime import datetime
        entries = list(getattr(ctx.log, "_entries", None) or [])
        stamp = next((str(e.get("ts")) for e in entries if isinstance(e, dict) and e.get("ts")), "")
        return datetime.fromisoformat(stamp).timestamp() if stamp else None
    except (TypeError, ValueError):
        return None


_HASH_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_FILE_ARG_KEYS = ("file_path", "path", "target", "input_path")


def _file_to_scan(desc: str, cited: list[dict]) -> str:
    """The file a scanner should read: a file a cited call read, preferring
    the one whose name the finding states, else a path the finding names."""
    import os
    from ._match import _call_args
    files = []
    for e in cited:
        args = _call_args(e)
        files += [str(args[k]) for k in _FILE_ARG_KEYS if isinstance(args.get(k), str) and args.get(k)]
    low = desc.lower()
    for f in files:
        base = os.path.basename(f.replace("\\", "/")).lower()
        if base and base in low:
            return f
    from core.entities import _UNIX_PATH_RE, _WIN_PATH_RE
    m = _UNIX_PATH_RE.search(desc) or _WIN_PATH_RE.search(desc)
    if m:
        return m.group(0).rstrip(".,;:)")
    return files[0] if files else ""


def _lookup_first_refusal(rule, name: str, desc: str, cited: list[dict]) -> dict:
    """The refusal leads with the check to run, ready to call; the
    downgrade comes last."""
    target = _file_to_scan(desc, cited)
    hashes = _HASH_RE.findall(desc)
    checks, ready = [], None
    if target:
        ready = {"tool": "yara.scan_file", "args": {"file_path": target}}
        checks.append(f"yara.scan_file(file_path={target!r}) with the installed rule set (leave "
                      "rules_path out), or misc.capa_analyze or misc.clamscan_file on it")
    if hashes:
        ready = ready or {"tool": "enrich.vt_lookup_hash", "args": {"file_hash": hashes[0]}}
        checks.append(f"enrich.vt_lookup_hash({hashes[0]!r})")
    if not checks:
        checks.append("yara.scan_file, misc.capa_analyze or misc.clamscan_file on the file that "
                      "carries it, or enrich.vt_lookup_hash on its hash")
    item_id = None
    try:
        from core.deferred_intents import work_order_on
        if work_order_on() and ready is not None:
            # The look-up survives the turn as a proposal for the director.
            from core.execution_log import log
            t = ({"path": ready["args"]["file_path"]} if "file_path" in ready["args"]
                 else {"source_hint": ready["args"].get("file_hash", "")})
            item_id = log.add_work_item("reason", [], ready["tool"], t, f"verify the name '{name}' the finding states",
                                        status="proposed")["call_id"]
    except Exception:  # noqa: BLE001 - the refusal stands without its item
        item_id = None
    return {
        "gate": "external_knowledge_grounding",
        "success": False,
        **({"work_item": item_id} if item_id else {}),
        "error": (
            f"[external_knowledge_grounding:{rule.id}] No cited output prints the name {name!r}. "
            f"Check it: {'; '.join(checks)}. Cite that call; the name is grounded by a match or "
            "a result that prints it, not by a rule you write. Without a scanner result, record "
            "what the output shows without the name at the tier it supports, and the attribution "
            "as a SUSPECTED hypothesis naming what would verify it."),
        "detail_gate": rule.id,
        "unverified_name": name,
        **({"ready_call": ready} if ready else {}),
    }


def _claimed_name(m: "re.Match[str]") -> str:
    """The family or tool name a match binds to a malware-class noun, or ''
    when the capitalised words are sentence grammar rather than a name."""
    from .named_actor_attribution_grounding import _NAME_STOPS
    name = next((g for g in m.groups() if g), "") or ""
    name = name.strip()
    words = name.split()
    if _lookup_first():
        def plain(w: str) -> bool:
            return w in _NAME_STOPS or w.lower() in _GENERIC_WORDS or w.lower() in _PROTOCOL_WORDS
        while words and plain(words[-1]):
            words.pop()
        while words and plain(words[0]):
            words.pop(0)
        return " ".join(words)
    if not words or all(w in _NAME_STOPS or w.lower() in _GENERIC_WORDS for w in words):
        return ""
    return name


# Capitalised words that describe a malware-class noun without naming a
# family: what kind of thing it is, where it sat, what it did.
_GENERIC_WORDS = frozenset({
    "windows", "unknown", "custom", "generic", "suspected", "possible", "likely",
    "known", "new", "second", "additional", "further", "malicious", "memory",
    "resident", "injected", "packed", "encrypted", "commodity", "remote",
    "access", "http", "https", "tcp", "dns", "powershell", "python", "java",
    "the", "this", "that", "an", "another", "its", "their", "our",
})
