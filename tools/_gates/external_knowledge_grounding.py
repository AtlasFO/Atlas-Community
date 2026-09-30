"""Gate: external-world facts must be tool-checked — model memory is not evidence.

Principle (case-independent)
---------------------------
The analyst LLM has *parametric* knowledge: associations baked into its weights
from pre-training (web text, docs, blogs). That is **not** a Atlas tool result
and **not** case evidence. It is often stale or wrong.

CONFIRMED / LIKELY findings may only assert external-world identity facts when
lineage / supporting_evidence shows a **verifying tool** was run (or the claim
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

from ._match import lineage_evidence_text


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
    evidence = lineage_evidence_text(ctx)

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
                f"external-world fact requires a cited verifying tool result "
                f"in supporting_evidence or input_call_ids. "
                + (f"No cited output prints the name {named!r}. " if named else "")
                + rule.remediation
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


def _claimed_name(m: "re.Match[str]") -> str:
    """The family or tool name a match binds to a malware-class noun, or ''
    when the capitalised words are sentence grammar rather than a name."""
    from .named_actor_attribution_grounding import _NAME_STOPS
    name = next((g for g in m.groups() if g), "") or ""
    name = name.strip()
    words = name.split()
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
