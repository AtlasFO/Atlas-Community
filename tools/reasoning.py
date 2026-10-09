"""Adversarial reasoning — T-Systems LLM Hub or any OpenAI-compatible endpoint."""
import os
import re
import json
from pathlib import Path

from fastmcp import FastMCP
from core.envfile import env_int
from core.paths import REASON_TIMEOUT
from core.timeout import with_tool_timeout
from tools.tool_capabilities import (
    annotate_directives_with_manifest,
    format_tool_manifest_for_prompt,
)

# Watchdog budget: the reasoning client's whole turn (REASON_TIMEOUT, 300 s by
# default, passed as its turn budget, so the reply cut and the lower rungs of
# its ladder fit inside) plus a 30 s buffer for parsing, trace-logging and
# directive extraction after the reply returns. Without this, a hang in the
# post-HTTP code path looks like a silent stall to the agent.
_REASON_WATCHDOG = REASON_TIMEOUT + 30

# Reaching the endpoint and waiting for it to finish writing are different
# waits and deserve different limits. A host that is down should be reported
# in seconds; a model still composing an answer should be allowed to finish.
# One number for both makes the choice between them impossible.
REASON_CONNECT_TIMEOUT = 15.0

mcp = FastMCP("reasoning")

# ── Backend configuration ────────────────────────────────────────────────────
# Supported: llmhub (when selected), openai-compat, and any provider
# registered in ATLAS_PROVIDERS (see core/providers.py). An unset
# REASON_BACKEND is "not configured", not a silent fall-through to the hub.
# Anthropic/Claude API backends were removed — REASON_BACKEND=claude
# returns a clear configuration error.
# FOUNDATION_SEC_URL / HF_TOKEN remain as openai-compat aliases.

REASON_BACKEND   = os.environ.get("REASON_BACKEND") or ""
# The provider the role names, for the usage ledger's label: REASON_BACKEND
# becomes the transport kind below once that provider is resolved.
REASON_PROVIDER  = "" if REASON_BACKEND in ("openai-compat", "claude") else REASON_BACKEND

# openai-compat vars — FOUNDATION_SEC_URL / HF_TOKEN are deprecated aliases
REASON_URL       = (os.environ.get("REASON_URL")
                    or os.environ.get("FOUNDATION_SEC_URL") or "")
REASON_API_KEY   = (os.environ.get("REASON_API_KEY")
                    or os.environ.get("HF_TOKEN") or "")
REASON_MODEL     = os.environ.get("REASON_MODEL") or ""

from core import llmhub as _llmhub
from core import providers as _providers

# Auth shape. Bearer for the hub and every OpenAI-compatible endpoint; a
# registered provider may override it.
REASON_AUTH_HEADER = _providers.DEFAULT_AUTH_HEADER
REASON_AUTH_PREFIX = _providers.DEFAULT_AUTH_PREFIX

# Set when the configured backend cannot be resolved. Resolution must never
# raise here: tools/ is imported while the MCP server starts, so a config typo
# has to surface as a tool error rather than a server that never comes up.
_BACKEND_CONFIG_ERROR = ""

# llmhub backend — only when REASON_BACKEND=llmhub is set explicitly.
if REASON_BACKEND == "llmhub":
    REASON_URL     = REASON_URL or _llmhub.base_url()
    REASON_API_KEY = REASON_API_KEY or _llmhub.api_key()
    REASON_MODEL   = REASON_MODEL or _llmhub.model()
    REASON_BACKEND = "openai-compat"
elif REASON_BACKEND and REASON_BACKEND not in ("openai-compat", "claude"):
    # A registered provider name works exactly like `llmhub` above: prefill the
    # generic vars from that provider, then continue down the openai-compat path.
    try:
        _reason_provider = _providers.resolve(REASON_BACKEND)
        REASON_URL         = REASON_URL or _reason_provider.base_url
        REASON_API_KEY     = REASON_API_KEY or _reason_provider.api_key
        REASON_MODEL       = REASON_MODEL or _reason_provider.model
        REASON_AUTH_HEADER = _reason_provider.auth_header
        REASON_AUTH_PREFIX = _reason_provider.auth_prefix
        REASON_BACKEND     = "openai-compat"
    except _providers.UnknownProvider as _provider_error:
        _BACKEND_CONFIG_ERROR = f"REASON_BACKEND is unusable: {_provider_error}"

_DEFAULT_COMPAT_MODEL = "fdtn-ai/Foundation-Sec-8B-Reasoning"
_CLAUDE_BACKEND_REMOVED = (
    "REASON_BACKEND=claude is no longer supported. "
    "Use REASON_BACKEND=llmhub or openai-compat. "
    "See docs/llm.md."
)

_SYNTHESIZE_INPUT_CHARS   = env_int("ATLAS_REASON_SYNTHESIZE_INPUT_CHARS", 24000)


def _active_backend() -> str:
    """Resolve which backend to use (llmhub → openai-compat, or explicit).

    An empty REASON_BACKEND is not the hub. A REASON_URL with no backend
    name still means the operator pointed at an OpenAI-compatible endpoint.
    """
    if REASON_BACKEND:
        return REASON_BACKEND
    if REASON_URL:
        return "openai-compat"
    return ""


# ── Shared constants ─────────────────────────────────────────────────────────

_EMPTY_DIRECTIVES: dict = {
    "priority_tools": [],
    "skip_tools": [],
    "focus_pids": [],
    "focus_paths": [],
    "max_depth": "",
    "next_hypothesis_triggers": [],
    # Exploratory allowance: the number of read-only "curiosity_probe" calls the
    # agent may run of its OWN choosing this batch, on top of priority_tools.
    # Granted by dair_assess, refreshed each call. 0 ⇒ today's strict
    # directive-only behavior. Enforced by tools/_gates/curiosity_budget.py.
    "curiosity_budget": 0,
    # Free-text imperatives DAIR can attach to a batch (e.g. "record findings
    # for confirmed IOCs before the next batch"). Surfaced to the analyst
    # verbatim in the dair_assess result. Empty by default.
    "required_actions": [],
}

_DIRECTIVES_INSTRUCTION = """\

Write your full analysis first, then end your response with the DIRECTIVES block. \
No markdown bold, no code fences, no // comments, plain text only:
DIRECTIVES:
{
  "priority_tools": ["vol.psscan", "ez.amcacheparser"],
  "skip_tools": [],
  "focus_pids": [],
  "focus_paths": [],
  "max_depth": "targeted",
  "next_hypothesis_triggers": []
}
Replace the example values with your actual recommendations. \
Tool names must use Atlas MCP format: namespace.tool and must come from the \
Tool Capability Manifest. \
Do not invent tool names outside this list.

""" + format_tool_manifest_for_prompt(max_tools_per_capability=6)


_EVIDENCE_AUDIT_INSTRUCTION = """\

Write your full analysis first. Then include the EVIDENCE_AUDIT block, \
followed by the DIRECTIVES block at the very end. \
List each major claim in the finding in EVIDENCE_AUDIT:
EVIDENCE_AUDIT:
[
  {
    "claim": "brief statement of the claim being audited",
    "tool": "vol.psscan / ez.evtxecmd / yara / etc.",
    "command": "exact MCP tool call or command used",
    "raw_output_excerpt": "verbatim snippet from tool output",
    "artifact_path": "file path or memory offset",
    "timestamp_source": "how the timestamp was established",
    "proof_rationale": "why this output proves the claim",
    "benign_alternatives": "alternate non-attacker explanations"
  }
]
Write NOT PROVIDED for any field not supplied in the supporting evidence.
Claims with 2+ NOT PROVIDED fields are hallucination candidates."""


# ── Text utilities ────────────────────────────────────────────────────────────

def _strip_block(text: str, marker: str) -> str:
    """Remove a named block marker and everything after it."""
    if not text:
        return text
    return re.sub(
        rf"\*{{0,2}}{re.escape(marker)}\*{{0,2}}\s*:?\*{{0,2}}.*",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    ).rstrip()


def _strip_directives(text: str) -> str:
    return _strip_block(text, "DIRECTIVES")


def _strip_evidence_audit(text: str) -> str:
    return _strip_block(text, "EVIDENCE_AUDIT")


def _parse_evidence_audit(text: str) -> list:
    """Extract the EVIDENCE_AUDIT JSON array from model output. Returns [] on failure."""
    if not text:
        return []
    match = re.search(
        r"EVIDENCE_AUDIT:\s*(\[.*?\])\s*(?:DIRECTIVES:|$)",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    raw = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        result = json.loads(raw)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def _parse_directives(text: str) -> dict:
    """Extract the DIRECTIVES JSON block from model output.

    Returns _EMPTY_DIRECTIVES template on any parse failure so callers always
    have the expected keys and can check priority_tools without KeyError.
    On successful parse, missing keys are filled from the template.
    """
    if not text:
        return annotate_directives_with_manifest(_EMPTY_DIRECTIVES.copy())
    match = re.search(
        r"\*{0,2}DIRECTIVES\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\{.*?\})\s*(?:```)?",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return annotate_directives_with_manifest(_EMPTY_DIRECTIVES.copy())
    raw = match.group(1)
    raw = re.sub(r"\s*//[^\n]*", "", raw)  # strip // comments
    try:
        return annotate_directives_with_manifest({**_EMPTY_DIRECTIVES, **json.loads(raw)})
    except (json.JSONDecodeError, ValueError):
        return annotate_directives_with_manifest(_EMPTY_DIRECTIVES.copy())


def _cap_lines(text: str, max_lines: int) -> str:
    """Trim text to max_lines, appending a note if trimmed."""
    lines = text.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return text
    omitted = len(lines) - max_lines
    return "".join(lines[:max_lines]) + f"\n[... {omitted} lines omitted for brevity]\n"


# ── Backend implementations ───────────────────────────────────────────────────

_COMPACT_INPUT_CHARS = 9000


def _compact_user_message(user: str) -> str:
    """The same request, bounded, with a request for terseness."""
    text = str(user or "")
    if len(text) > _COMPACT_INPUT_CHARS:
        head = text[: _COMPACT_INPUT_CHARS * 2 // 3]
        tail = text[-(_COMPACT_INPUT_CHARS // 3):]
        text = f"{head}\n[… {len(user) - len(head) - len(tail)} characters omitted for budget …]\n{tail}"
    return (text + "\n\nBUDGET NOTE: the previous two attempts produced no "
            "visible output. Answer tersely — at most 12 short lines per "
            "section, no restatement of the input — and keep the canonical "
            "final line(s) the format requires.")


def _ask_openai_compat(system: str, user: str, _tool_name: str,
                       hypothesis_id: str = "",
                       input_call_ids: list[int] | None = None) -> dict:
    """Call any OpenAI-compatible endpoint over the one transport.

    ``agent.llm.LLMHubClient`` owns the request: the learned request shape,
    the retries, the rate-limit waits, the role's thinking level and the
    starvation ladder. This function only turns the reply into the result
    dict the reasoning tools and the trace consume.
    """
    from agent.llm import LLMHubClient
    _inputs = {
        "user_message": user,
        "system_prompt_kind": _tool_name,
    }
    _empty = {"success": False, "conclusion": "", "directives": {},
              "input_tokens": 0, "output_tokens": 0, "inputs": _inputs}
    if hypothesis_id:
        _empty["hypothesis_id"] = hypothesis_id

    if not REASON_URL:
        result = {**_empty, "error": "REASON_URL not set for openai-compat backend"}
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result

    model = REASON_MODEL or _DEFAULT_COMPAT_MODEL
    try:
        from core.execution_log import log as _elog
        _elog.record_call_initiated(_tool_name, "openai-compat",
                                    {"model": model, "url": REASON_URL},
                                    input_call_ids=input_call_ids)
    except Exception as _e:
        import sys; print(f"[Atlas WARN] record_call_initiated failed: {_e}", file=sys.stderr)
    try:
        client = LLMHubClient(
            base_url=REASON_URL, api_key=REASON_API_KEY, model=model,
            timeout=REASON_TIMEOUT, turn_time_budget=REASON_TIMEOUT,
            # The resolved provider's name: REASON_BACKEND became the
            # transport kind above, and under it the role learned its
            # request shape apart from the analyst's.
            provider=REASON_PROVIDER if _providers.is_declared(REASON_PROVIDER) else "",
            auth_header=REASON_AUTH_HEADER, auth_prefix=REASON_AUTH_PREFIX,
            usage_provider=REASON_PROVIDER)
        _messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        # The ladder's last rung: when the input itself makes the thinking
        # too long, a bounded, terse request beats a dead turn.
        resp = client.chat(
            _messages, role=_tool_name, temperature=None,
            compact=lambda msgs: [msgs[0], {"role": "user",
                                            "content": _compact_user_message(user)}])
        parsed = {
            "content": resp.content,
            "finish_reason": resp.finish_reason,
            "input_tokens": resp.input_tokens,
            "output_tokens": resp.output_tokens,
            "reasoning_tokens": resp.reasoning_tokens,
        }
        raw = (parsed.get("content") or "").strip()
        if not raw:
            result = {
                **_empty,
                "error": resp.starved_reason(),
                "input_tokens": parsed.get("input_tokens", 0),
                "output_tokens": parsed.get("output_tokens", 0),
                "reasoning_tokens": parsed.get("reasoning_tokens", 0),
                "finish_reason": parsed.get("finish_reason") or "",
                "gate": "empty_reason_response",
            }
            _log_reason(_tool_name, result, input_call_ids=input_call_ids)
            return result
        evidence_audit = _parse_evidence_audit(raw)
        directives = _parse_directives(raw)
        conclusion = _strip_evidence_audit(_strip_directives(raw)).strip()
        # Fail closed after strip: DIRECTIVES:/EVIDENCE_AUDIT:-only payloads
        # used to return success=True with an empty conclusion, which the
        # agent treated as a usable reason call while pre_report correctly
        # rejected them — split brain.
        if not conclusion:
            result = {
                **_empty,
                "error": (
                    "Model returned no usable conclusion after stripping "
                    "DIRECTIVES/EVIDENCE_AUDIT blocks (directives-only or "
                    "whitespace). Retry the reason tool."
                ),
                "directives": directives,
                "evidence_audit": evidence_audit,
                "input_tokens": parsed.get("input_tokens", 0),
                "output_tokens": parsed.get("output_tokens", 0),
                "reasoning_tokens": parsed.get("reasoning_tokens", 0),
                "finish_reason": parsed.get("finish_reason") or "",
                "gate": "empty_reason_response",
            }
            _log_reason(_tool_name, result, input_call_ids=input_call_ids)
            return result
        result = {
            "success": True,
            "conclusion": conclusion,
            "directives": directives,
            "evidence_audit": evidence_audit,
            "input_tokens": parsed.get("input_tokens", 0),
            "output_tokens": parsed.get("output_tokens", 0),
            "reasoning_tokens": parsed.get("reasoning_tokens", 0),
            "finish_reason": parsed.get("finish_reason") or "",
            "inputs": _inputs,
        }
        if hypothesis_id:
            result["hypothesis_id"] = hypothesis_id
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result
    except Exception as e:
        try:
            from core.execution_log import log as _elog
            _elog.record_call_abandoned(_tool_name, str(e))
        except Exception as _log_err:
            # Best-effort — we're already in the failure path. Surface to
            # stderr so the double-fault isn't completely silent. Not
            # routed through record_system_error to avoid recursion if the
            # trace itself is the cause.
            import sys as _sys
            print(f"[Atlas WARN] reason record_call_abandoned failed during "
                  f"{_tool_name} error: {_log_err!r}", file=_sys.stderr)
        result = {**_empty, "error": str(e)}
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result


# Reviewer tools whose output is a pure function of their input text: an
# identical (finding + evidence) prompt gets an identical verdict, so the
# 15-20 s LLM round-trip is wasted on repeats, e.g. evaluate_finding or
# confidence_score called again on the same finding after a citation
# self-correction. Planning/synthesis tools are NOT
# memoized — they must reflect current investigation state.
_MEMOIZED_REASON_TOOLS = frozenset({
    "reason_evaluate_finding",
    "reason_confidence_score",
    "reason_cite_check",
})


def _reason_memo_lookup(tool_name: str, user: str) -> dict | None:
    """Prior successful identical reviewer call from this run's trace."""
    if tool_name not in _MEMOIZED_REASON_TOOLS or not user:
        return None
    try:
        from core.execution_log import log as _elog
        for e in reversed(_elog._entries):
            if (e.get("type") == "reason_call"
                    and e.get("tool") == tool_name
                    and e.get("success")
                    and (e.get("conclusion") or "").strip()
                    and (e.get("inputs") or {}).get("user_message") == user):
                return {
                    "success": True,
                    "conclusion": e.get("conclusion") or "",
                    "directives": dict(e.get("directives") or {}),
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cached_from_call_id": e.get("call_id"),
                    "cached": True,
                }
    except Exception:
        return None
    return None


def _ask(system: str, user: str, _tool_name: str = "",
         hypothesis_id: str = "",
         input_call_ids: list[int] | None = None) -> dict:
    """Dispatch to the active reasoning backend. `input_call_ids` is propagated
    through to the eventual record_reason_call so the reason entry carries its
    agent-declared upstream lineage as a foreign key, so it is bounded against
    the ids the run has issued before anything is asked."""
    from core.execution_log import log
    from tools._gates import lineage_required
    refusal = lineage_required.check_ids(log, input_call_ids)
    if refusal is not None:
        return {**refusal, "conclusion": "", "directives": {}}
    cached = _reason_memo_lookup(_tool_name, user)
    if cached is not None:
        # Re-record as a fresh reason_call (zero tokens) so recency-window
        # gates (evidence_strength) still see a preceding reviewer call.
        cached["inputs"] = {
            "user_message": user,
            "system_prompt_kind": _tool_name,
        }
        if hypothesis_id:
            cached["hypothesis_id"] = hypothesis_id
        _log_reason(_tool_name, cached, input_call_ids=input_call_ids)
        return cached
    backend = _active_backend()

    def _config_error(message: str) -> dict:
        _inputs = {
            "user_message": user,
            "system_prompt_kind": _tool_name,
        }
        result = {
            "success": False,
            "conclusion": "",
            "directives": {},
            "input_tokens": 0,
            "output_tokens": 0,
            "inputs": _inputs,
            "error": message,
        }
        if hypothesis_id:
            result["hypothesis_id"] = hypothesis_id
        _log_reason(_tool_name, result, input_call_ids=input_call_ids)
        return result

    if not backend:
        return _config_error(
            "REASON_BACKEND is not configured. Set it to a provider name "
            "(llmhub, or a name from ATLAS_PROVIDERS) or openai-compat with "
            "REASON_URL. Telekom LLM Hub is not used unless you select it.")
    if backend == "claude":
        return _config_error(_CLAUDE_BACKEND_REMOVED)
    if _BACKEND_CONFIG_ERROR:
        return _config_error(_BACKEND_CONFIG_ERROR)
    # Positive list. A recognised provider name was normalised to
    # openai-compat during configuration above, so anything left over is a
    # typo. Refusing beats the old silent fall-through: with more than one
    # endpoint registered, that would have run the reviewer against whichever
    # endpoint happened to be configured and recorded it as if intended.
    if backend != "openai-compat":
        return _config_error(
            f"REASON_BACKEND={backend!r} is not a known backend. Use "
            f"openai-compat, or one of these registered providers: "
            f"{', '.join(_providers.names())}.")
    return _ask_openai_compat(system, user, _tool_name, hypothesis_id,
                              input_call_ids=input_call_ids)


def _log_reason(tool_name: str, result: dict,
                input_call_ids: list[int] | None = None) -> None:
    try:
        from core.execution_log import log
        cid = log.record_reason_call(
            tool=tool_name,
            success=result.get("success", False),
            conclusion=result.get("conclusion", ""),
            directives=result.get("directives", {}),
            evidence_audit=result.get("evidence_audit"),
            input_tokens=result.get("input_tokens", 0),
            output_tokens=result.get("output_tokens", 0),
            hypothesis_id=result.get("hypothesis_id", ""),
            inputs=result.get("inputs"),
            input_call_ids=input_call_ids,
            error=result.get("error") or "",
            finish_reason=result.get("finish_reason") or "",
            reasoning_tokens=int(result.get("reasoning_tokens") or 0),
            gate=result.get("gate") or "",
        )
        if cid:
            result["_atlas_call_id"] = cid
    except Exception as e:
        import sys
        print(f"[Atlas WARN] _log_reason failed for {tool_name}: {e}", file=sys.stderr)


def _next_hypothesis_id() -> str:
    """Generate a stable, sequential hypothesis_id like H0001.
    Used to build the hypothesis→finding lineage rendered in trace.md."""
    try:
        from core.execution_log import log
        existing = sum(
            1 for e in log._entries
            if e.get("type") == "reason_call" and e.get("hypothesis_id")
        )
        return f"H{existing + 1:04d}"
    except Exception:
        return "H0001"


# ── System prompts ────────────────────────────────────────────────────────────

_PLAN_SYS = (
    "You are a senior DFIR analyst receiving a new case. Given the case description "
    "and available evidence, produce a prioritized investigation plan:\n"
    "1. Most likely threat scenarios based on the evidence profile\n"
    "2. Highest-yield artifacts to examine first and why\n"
    "3. Specific TTPs to hunt for given the scenario\n"
    "4. Recommended tool sequence (memory → disk → network → enrichment or adjusted)\n"
    "5. Red flags that would change the priority order mid-investigation\n\n"
    "Be specific and opinionated. The investigator will follow this plan.\n"
    "The DIRECTIVES block is the primary output — populate priority_tools with the "
    "first 3-5 concrete tool calls the investigator should run, in order.\n\n"
    "EXHAUSTIVE COLLECTION: for each artifact category in the plan, the tool sequence "
    "must collect ALL instances, not just the first. Explicitly name: all registry hive "
    "variants needed (SOFTWARE, SYSTEM, SAM, NTUSER.DAT per user profile), all event "
    "log channels relevant to the TTP, all HTTP session types (Cookie headers, URL auth "
    "params: login=, email=, user=, gausr=, Y=, T=), all browser profiles present. "
    "If the case description includes a suspect list (class roster, employee directory, "
    "user accounts), include a cross-reference step as a named plan item — it is "
    "mandatory, not optional. The plan is incomplete if it names an identity-bearing "
    "artifact category without specifying the full collection sequence for that category."
    + _DIRECTIVES_INSTRUCTION
)

_HYPOTHESIZE_SYS = (
    "You are a senior DFIR analyst reviewing a colleague's live investigation. "
    "Given a forensic observation, generate ranked alternative hypotheses — both "
    "malicious and benign. Be adversarial: challenge the obvious interpretation. "
    "For each hypothesis state: likelihood (high/medium/low), supporting artifacts, "
    "and what evidence would confirm or rule it out.\n"
    "Keep your response concise and structured.\n"
    "The DIRECTIVES block is the primary output — populate priority_tools with the "
    "discriminators that resolve the TOP TWO competing hypotheses: the artifacts "
    "that decide WHICH hypothesis is true (e.g. logon type/source, USB serials "
    "across profiles, registry account bindings like OneDrive), not just tools that "
    "support the leading one. Populate next_hypothesis_triggers with conditions "
    "that should prompt re-evaluation.\n"
    "IMPORTANT: priority_tools MUST be non-empty if your conclusion names specific "
    "search patterns, artifact types, or investigative steps. Convert every concrete "
    "recommendation in your conclusion text into a priority_tools entry. Examples: "
    "if you write 'search for the suspect username in webmail traffic', add "
    "net.ngrep_search(pattern='<username>'); if you write 'check webmail cookies', "
    "add net.ngrep_search(pattern='Cookie:') and net.tcpdump_extract_http. "
    "An empty priority_tools alongside a conclusion that contains investigative "
    "recommendations is invalid — the structured directive must reflect the text."
    + _DIRECTIVES_INSTRUCTION
)

# Absence-seeded mode. The presence-mode prompt above reasons over what was
# already surfaced; this one reasons over what is MISSING. It is the structural
# counterweight to single-actor lock-in and shallow coverage: it generates leads
# about evidence that has NOT yet been looked at, which is where less-obvious
# identity / attribution / exfil / second-principal evidence lives.
_HYPOTHESIZE_ABSENCE_SYS = (
    "You are a senior DFIR analyst doing a DIFFERENTIAL coverage review of a "
    "live investigation. You are given the case question, the part of it still "
    "UNRESOLVED, and the list of artifact categories ALREADY examined. Your job "
    "is NOT to re-explain what was found — it is to name the high-value artifact "
    "categories that have NOT yet been touched and could carry decisive evidence "
    "for the unresolved question, especially:\n"
    "  - IDENTITY / ATTRIBUTION (a second SID's profile, cookies, cert CNs, "
    "comms-store correspondents, USB serials across profiles)\n"
    "  - A SECOND PRINCIPAL (a newly-created or unseen account, a logon from an "
    "unexpected source/type, a controller binding not yet established)\n"
    "  - AN ALTERNATE EXFIL CHANNEL ranked weaker-evidenced but unchecked "
    "(removable-media LNK/MountedDevices, FTP/transfer logs, cloud-client DB, "
    "mail attachment, web upload) — a transfer artifact, not mere staging\n"
    "  - INGRESS / INITIAL ACCESS overlooked by an egress-only lens "
    "(setupapi.dev.log HID/composite / BadUSB when removable media is in evidence)\n"
    "For each gap, state the one finding it would most plausibly produce and rank "
    "by EXPECTED INFORMATION GAIN for the unresolved question — not by ease.\n"
    "Do not propose categories already in the examined list. If a category was "
    "examined but only sampled (first instance only), it IS a valid gap — say so.\n"
    "The DIRECTIVES block is the primary output — populate priority_tools with one "
    "concrete Atlas MCP call per gap, highest-information-gain first. These become "
    "the investigator's curiosity probes; keep the list to the top 3-5. Populate "
    "next_hypothesis_triggers with the result conditions that would open a new line."
    + _DIRECTIVES_INSTRUCTION
)

_EVALUATE_SYS = (
    "You are a DFIR peer reviewer with two roles: adversarial challenger AND "
    "technical fact-checker.\n\n"
    "For the finding presented, work through ALL of the following:\n"
    "1. EVIDENCE SUPPORT — what raw tool output directly supports it? "
    "Name the specific tool, output field, and value.\n"
    "2. CONTRADICTING EVIDENCE — what contradicts or weakens it?\n"
    "3. ALTERNATIVE EXPLANATIONS — benign or non-attacker interpretations "
    "of the same artifacts.\n"
    "4. HALLUCINATION CHECK — flag any claim stated as fact but not derivable "
    "from the cited evidence: invented specificity (precise numbers/offsets "
    "without a cited source), fabricated mechanism (e.g. 'VAD tag X proves "
    "API Y was used' without a reference), or conclusions that require "
    "evidence not mentioned in the supporting evidence field.\n"
    "5. FACT-CHECK — verify technical accuracy:\n"
    "   - YARA match alone is NEVER sufficient to confirm a tool, technique, "
    "or actor — it is a lead requiring corroboration.\n"
    "   - Null process cmdline has multiple benign explanations; never "
    "characterize as intentional wiping without supporting evidence.\n"
    "   - ATT&CK technique IDs must exist in the MITRE ATT&CK matrix and "
    "correctly describe the behaviour being claimed.\n"
    "   - Port numbers, VAD tags, and memory structure claims must match "
    "established forensic facts — flag if unverifiable.\n"
    "   - CAPABILITY VS ACT: evidence that a tool or client was installed, "
    "configured, or an account was bound proves capability, never the act. "
    "A finding claiming data was exfiltrated, transferred, or executed that "
    "cites only installation/configuration evidence is overclaimed — flag "
    "CHALLENGED and recommend LIKELY until an act artifact (transfer log, "
    "sync journal, execution trace with timestamps) is cited.\n"
    "   - NEGATIVE FINDING SCRUTINY: if the finding states that something was NOT "
    "found (no persistence, no injection, identity unknown, no C2 traffic), verify "
    "that the absence claim was reached by exhaustive collection — not by a single "
    "tool pass that returned empty. A single ngrep returning no results does not mean "
    "the artifact is absent; a single vol.malfind pass does not clear all processes. "
    "Flag CHALLENGED if the negative claim is based on incomplete collection coverage.\n"
    "   - OBSERVATION VS INFERENCE: separate what the cited tool output "
    "directly shows (file contents, log lines, decoded strings, command text "
    "in a history file — the observable core) from what the finding claims it "
    "means (attacker action, success, attribution — the inference). Never flag "
    "CHALLENGED because the inference is weak when the observable core is "
    "accurately quoted from cited output — say which component fails, and "
    "state explicitly that the observable core, narrowed to exactly what the "
    "output shows, is CONFIRMED-eligible on its own. Challenge the whole "
    "finding only when the observable core itself is misquoted, fabricated, "
    "or uncited.\n"
    "   - EXTERNAL / UNCHECKED FACTS: flag CHALLENGED any CONFIRMED/LIKELY "
    "claim whose factual payload (MAC/OUI vendor, IP geo/ASN, domain "
    "ownership, malware family from a hash, CVE as root cause, product "
    "manufacturer identity, etc.) comes from model training memory rather "
    "than (1) a literal quoted evidence string or (2) a cited verifying-tool "
    "result (enrich.oui_lookup, enrich.vt_lookup_*, whois, yara, …). "
    "Different artifact classes do not substitute for each other. "
    "Training-memory identity claims are often wrong.\n"
    "6. ADDITIONAL INVESTIGATION — what specific tool run would upgrade this "
    "finding from its current confidence tier?\n"
    "7. VERDICT: SUPPORTED / CHALLENGED / UNCERTAIN — one-line rationale.\n\n"
    "OUTPUT FORMAT — the VERY FIRST line of your response must be the verdict, "
    "exactly:\n"
    "  VERDICT: SUPPORTED   (or CHALLENGED / UNCERTAIN)\n"
    "in plain text, no markdown decoration. Then the sections above. The first "
    "line is machine-parsed; a verdict buried at the end can be cut off by the "
    "token limit and the whole evaluation is then discarded as unparseable.\n\n"
    "Be blunt. Overclaimed findings damage court cases. Flag any finding "
    "that upgrades an indicator to a confirmed fact without direct evidence."
    + _EVIDENCE_AUDIT_INSTRUCTION
    + _DIRECTIVES_INSTRUCTION
)

_SYNTHESIZE_SYS = (
    "You are a DFIR lead analyst doing a final logic and confidence check before "
    "a report is written. Apply this evidence tier standard to every finding:\n\n"
    "  CONFIRMED   → physical artifact (file/key/log) + corroborating context\n"
    "  LIKELY      → live memory structure, active connection, or registry key "
    "with supporting context\n"
    "  SUSPECTED   → YARA match, behavioral indicator, or single corroborating "
    "point — never write CONFIRMED for a SUSPECTED-tier finding\n"
    "  UNCONFIRMED → inference or pattern-match without a direct artifact\n\n"
    "Identify:\n"
    "1. LOGICAL GAPS — steps in the attack chain that aren't evidenced\n"
    "2. CONTRADICTIONS — findings that conflict with each other\n"
    "3. TIER VIOLATIONS — findings written as CONFIRMED/HIGH where the evidence "
    "is SUSPECTED or UNCONFIRMED tier; list each with the correct tier\n"
    "4. TIER CONTRADICTIONS — any two findings that make the same mechanistic "
    "claim (same attacker action, same host, same credential) at different "
    "confidence tiers; list each pair as TIER_CONTRADICTION with the correct tier\n"
    "5. OVERCLAIMED MECHANISMS — technical explanations that aren't supported "
    "by cited evidence (e.g. YARA hit stated as 'confirmed execution')\n"
    "6. MISSING INVESTIGATION — what should have been checked but wasn't, including:\n"
    "   - EVIDENCE EXHAUSTION: for each artifact category named in findings, was the "
    "full category collected (all hives, all log channels, all HTTP cookie types, all "
    "memory regions) or only sampled? Flag as BLOCKER if a conclusion of 'identity "
    "unknown' or 'no evidence found' was reached without exhausting an artifact "
    "category that IS PRESENT in the case evidence tree. Flag as BLOCKER if found "
    "identities were never cross-referenced against a suspect list that was "
    "available in the case context.\n"
    "   - COLLECTION GAPS (not BLOCKERS): if an artifact was never provided to the "
    "case (e.g. 'host disk image not in evidence', 'log channel not in the package', "
    "'EVTX window starts at date X — earlier logs unavailable'), that is an "
    "ADVISORY / report Limitations item — NOT a BLOCKER. Tools cannot conjure "
    "evidence that was never collected. Do not block the report on absent packages.\n\n"
    "Return a structured punch list. Mark BLOCKERS (must fix before report is "
    "written) separately from ADVISORIES (should note, not blocking).\n\n"
    "ALWAYS end your response with a single canonical line in EXACTLY this form, "
    "on its own line:\n"
    "  BLOCKERS: None        (when there are no blockers)\n"
    "  BLOCKERS: <1-line summary of each blocker>   (when there are)\n"
    "This line is machine-parsed. Do not use the word 'blocker' elsewhere to "
    "describe a gap you are NOT blocking on — call those ADVISORIES. If the only "
    "remaining issues are collection gaps (evidence never provided), you MUST "
    "emit: BLOCKERS: None"
    + _DIRECTIVES_INSTRUCTION
)


# ── MCP tools ─────────────────────────────────────────────────────────────────

def _default_evidence_available() -> tuple[str, list[int], str]:
    """Ground reason.plan from latest inventory (+ mount_plan) when omitted.

    Returns (text, call_ids, source_label). Empty text if nothing usable.
    """
    parts: list[str] = []
    cids: list[int] = []
    try:
        from core.execution_log import log as _elog
        for e in reversed(list(_elog._entries or [])):
            if e.get("type") != "tool_call" or not e.get("success"):
                continue
            blob = " ".join(
                str(e.get(k) or "") for k in ("cmd", "mcp_tool", "tool")
            ).casefold()
            if "inventory_evidence" not in blob:
                continue
            excerpt = (
                e.get("stdout_excerpt")
                or e.get("stdout")
                or e.get("result_excerpt")
                or ""
            )
            if not str(excerpt).strip():
                # Fall back to a short inventory stamp note
                excerpt = (
                    f"(inventory_evidence call_id={e.get('call_id')} "
                    f"succeeded — see trace for full listing)"
                )
            parts.append(str(excerpt)[:8000])
            cid = e.get("call_id")
            if isinstance(cid, int):
                cids.append(cid)
            break
        case = _elog.case_dir()
        if case:
            try:
                from core.mount_plan import load_mount_plan
                plan = load_mount_plan(case)
                images = plan.get("images") or []
                if images:
                    summary = []
                    for img in images[:12]:
                        summary.append(
                            f"- {img.get('basename') or img.get('path')}: "
                            f"type={img.get('image_type')} "
                            f"next={img.get('recommended_tool')} "
                            f"({img.get('reason') or ''})"
                        )
                    parts.append(
                        "mount_plan.json:\n" + "\n".join(summary)
                    )
            except Exception:
                pass
    except Exception:
        pass
    if not parts:
        return "", [], ""
    return "\n\n".join(parts), cids, "inventory_evidence+mount_plan"


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_plan")
def reason_plan(case_description: str,
                evidence_available: str | None = None,
                input_call_ids: list[int] | None = None) -> dict:
    """
    Generate a prioritized investigation plan before deep forensic tool runs.
    Call this after the fast pre-enumeration block (SYSTEM hive, SAM hive,
    SOFTWARE hive, memory stat) so the plan is grounded in real evidence data.

    case_description: incident description — host, timeframe, and the
        analyst's PRIOR KNOWLEDGE statements that bear on it, with their ids
    evidence_available: concatenated output from the pre-enumeration tools.
        Optional — when omitted/empty, Atlas defaults from the latest successful
        misc.inventory_evidence (+ mount_plan summary) so a missing arg does
        not burn Triage on analyst_error retries.
    input_call_ids: REQUIRED (after genesis grace) — list of _atlas_call_id
        values for the pre-enumeration tool calls that produced the evidence
        you're passing in. The `lineage_required` gate enforces this; when
        evidence_available is auto-grounded, inventory call_ids are attached.
    """
    grounded_from = None
    text = (evidence_available or "").strip()
    if not text:
        text, auto_cids, grounded_from = _default_evidence_available()
        if auto_cids:
            merged = list(input_call_ids or [])
            for c in auto_cids:
                if c not in merged:
                    merged.append(c)
            input_call_ids = merged
        if not text:
            return {
                "success": False,
                "gate": "evidence_available_required",
                "error": (
                    "evidence_available is empty and no successful "
                    "misc.inventory_evidence was found to auto-ground the "
                    "plan. Run misc.inventory_evidence first, then retry."
                ),
            }
    capped = _cap_lines(text, 300)
    user = f"CASE:\n{case_description}\n\nEVIDENCE AVAILABLE:\n{capped}"
    result = _ask(_PLAN_SYS, user, _tool_name="reason_plan",
                  input_call_ids=input_call_ids)
    if grounded_from and isinstance(result, dict):
        result["evidence_available_grounded_from"] = grounded_from
    return result


# ── Per-hypothesis split (sub-hypothesis tracking) ───────────────────────────
# reason_hypothesize returns N ranked alternatives in ONE call under ONE
# hypothesis_id. Parse them into individually-trackable records so the
# exhaustion gate can require EACH contested principal to be driven to a verdict
# (not just the leading one). Header form: "H1 — <title> (Likelihood: <level>)".
_SUB_HYP_HEADER_RE = re.compile(
    r"^\s*H(\d+)\s*[—–:\-]\s*(.+?)\s*\(\s*Likelihood\s*:\s*([A-Za-z/\- ]+?)\s*\)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_SUB_ENTITY_STOP = frozenset({
    "PC", "IT", "THE", "THIS", "THAT", "NEW", "ADMIN", "USER", "SERVICE",
    "DEFAULT", "SYSTEM", "NAME", "ACCOUNT", "PRINCIPAL",
})
_SUB_BUILTIN_ACCTS = ("guest", "administrator", "defaultaccount", "homegroupuser",
                      "wdagutilityaccount", "krbtgt")


def _sub_hyp_tier(level: str) -> str:
    """Normalise a likelihood string to HIGH/MEDIUM/LOW ('MEDIUM-HIGH'→HIGH,
    'LOW-MEDIUM'→MEDIUM, unknown→MEDIUM so it must still be resolved)."""
    l = (level or "").lower()
    if "high" in l:
        return "HIGH"
    if "med" in l:
        return "MEDIUM"
    if "low" in l:
        return "LOW"
    return "MEDIUM"


def _sub_hyp_entities(block: str) -> list[str]:
    """Principal/account tokens a sub-hypothesis contests: quoted account names
    and built-in account names. Quoting is how analysts mark a real account
    (e.g. 'svc_example'); built-ins (Guest/Administrator) are valid subjects.
    Deliberately does NOT scrape 'X account' — that is descriptive noise
    ('OneDrive account binding', 'malware-created account')."""
    ents: set[str] = set()
    for m in re.finditer(r"[`'\"]([A-Za-z][\w.$-]{2,40})[`'\"]", block):
        ents.add(m.group(1).upper())
    low = block.lower()
    for b in _SUB_BUILTIN_ACCTS:
        if re.search(r"\b" + re.escape(b) + r"\b", low):
            ents.add(b.upper())
    return sorted(e for e in ents if e not in _SUB_ENTITY_STOP)


def _parse_sub_hypotheses(conclusion: str, hid: str) -> list[dict]:
    """Split a hypothesize conclusion's ranked 'H1 — … (Likelihood: …)' blocks
    into per-hypothesis records {sub_id,label,title,likelihood_tier,entities}.
    Returns [] when fewer than 2 parse, so callers fall back to per-call-id
    tracking (non-breaking for differently-formatted output)."""
    if not conclusion:
        return []
    matches = list(_SUB_HYP_HEADER_RE.finditer(conclusion))
    if len(matches) < 2:
        return []
    subs: list[dict] = []
    for i, m in enumerate(matches):
        n = m.group(1)
        title = (m.group(2) or "").strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(conclusion)
        block = title + "\n" + conclusion[start:end]
        subs.append({
            "sub_id": f"{hid}.{n}",
            "label": f"H{n}",
            "title": title[:160],
            "likelihood_tier": _sub_hyp_tier(m.group(3)),
            "entities": _sub_hyp_entities(block),
        })
    return subs


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_hypothesize")
def reason_hypothesize(observation: str, evidence: str = "", context: str = "",
                       mode: str = "presence",
                       input_call_ids: list[int] | None = None) -> dict:
    """
    Generate ranked hypotheses to guide the investigation. Two modes:

    mode="presence" (default) — ranked alternative explanations (malicious and
    benign) for an artifact you HAVE surfaced. Call when a finding has multiple
    plausible interpretations.
      observation: the single behaviour/artifact being explained (one sentence,
                   e.g. "cmd.exe PID 5024 spawned from orphaned PPID 2748")
      evidence:    raw artifact list supporting it (tool output, EIDs, timestamps)

    mode="absence" — DIFFERENTIAL coverage review: what high-value artifact
    category has NOT been examined that could carry decisive identity /
    attribution / second-principal / alternate-exfil evidence for the unresolved
    question. Returns probe candidates in priority_tools. Fire this before any
    phase-out / Triage max-pass-cap transition, and whenever coverage feels thin.
      observation: the UNRESOLVED part of the case question (one sentence)
      evidence:    the artifact categories ALREADY examined (so it proposes gaps)

    context: broader case context (OS, known TTPs, incident timeline, roster,
             the analyst's PRIOR KNOWLEDGE statements that bear on it).
    input_call_ids: REQUIRED — _atlas_call_id values for the calls that informed this.

    The returned hypothesis_id should be passed as `seeded_by` to any
    misc.record_curiosity_probe spawned from an absence-mode gap.
    """
    if mode == "absence":
        user = f"UNRESOLVED QUESTION:\n{observation}"
        if evidence:
            user += f"\n\nARTIFACT CATEGORIES ALREADY EXAMINED:\n{evidence}"
        if context:
            user += f"\n\nCASE CONTEXT:\n{context}"
        system = _HYPOTHESIZE_ABSENCE_SYS
    else:
        user = f"OBSERVATION:\n{observation}"
        if evidence:
            user += f"\n\nSUPPORTING EVIDENCE:\n{evidence}"
        if context:
            user += f"\n\nCASE CONTEXT:\n{context}"
        system = _HYPOTHESIZE_SYS
    hid = _next_hypothesis_id()
    result = _ask(system, user, _tool_name="reason_hypothesize", hypothesis_id=hid,
                  input_call_ids=input_call_ids)

    # ── Server-side conclusion parser (Fix G) ───────────────────────────────
    # If the model's prose conclusion names specific search patterns or
    # investigative steps but the structured directives.priority_tools is
    # empty, extract the recommendations from the prose and synthesise
    # priority_tools entries. Defense in depth — keeps the agent moving
    # even when the model forgets to populate the directives block.
    try:
        import re as _re
        directives = result.get("directives") or {}
        existing_tools = list(directives.get("priority_tools") or [])
        if not existing_tools:
            conclusion = result.get("conclusion", "") or ""
            extracted: list[str] = []
            # Pattern A: explicit "search for X" / "grep for X" / "look for X"
            for m in _re.finditer(
                r"(?:search|grep|look|check|hunt|extract|filter)\s+(?:for\s+|the\s+)?[`\"']?([A-Za-z0-9_@:.\-=/]{3,40})[`\"']?",
                conclusion, _re.IGNORECASE,
            ):
                term = m.group(1).strip().rstrip(".,;:")
                if term and term.lower() not in {"the", "and", "for", "from"}:
                    extracted.append(f"net.ngrep_search(pattern={term!r})")
            # Pattern B: explicit tool names mentioned (net.X, vol.X, ez.X, ...)
            for m in _re.finditer(
                r"\b((?:net|vol|tsk|ez|strings|hash|carve|enrich|misc|yara|correlate|af|live)\.[a-z_]+)",
                conclusion,
            ):
                tool_name = m.group(1)
                if tool_name not in extracted:
                    extracted.append(tool_name)
            # Pattern C: HTTP cookie / webmail keywords trigger session inventory.
            # Bare "session" — meaning a *logon* session — must NOT pull an HTTP
            # PCAP tool; that misfire emitted net.http_session_inventory for a
            # logon-session (not web-session) hypothesis.
            if _re.search(
                r"\b(cookie|webmail|gmail|yahoo|hotmail|aol|http session|web session)\b",
                conclusion, _re.IGNORECASE,
            ):
                if "net.http_session_inventory" not in extracted:
                    extracted.append("net.http_session_inventory")
            # Pattern D: identity-discriminator phrases → the EZ/misc tool that
            # extracts them, so the top-two competing hypotheses' discriminators
            # become the actual work order (not a generic sweep). Closes the
            # breakpoint where the model's confirm/rule-out recipe was dropped.
            for _rx, _tool in (
                (r"onedrive|account binding|registry .*account|cloud account|liveid", "ez.recmd_hive"),
                (r"\busb\b|usbstor|device serial|removable .*serial|usb serial", "misc.regripper_hive"),
                (r"logon type|logon source|\b4624\b|\b4625\b|interactive logon|source address", "ez.evtxecmd"),
                (r"prefetch|run count", "ez.pecmd"),
                (r"shellbag", "ez.sbecmd"),
                (r"userassist", "misc.regripper_hive"),
                (r"amcache", "ez.amcacheparser"),
            ):
                if _re.search(_rx, conclusion, _re.IGNORECASE) and _tool not in extracted:
                    extracted.append(_tool)
            # Cap to avoid runaway
            extracted = extracted[:12]
            if extracted:
                directives["priority_tools"] = extracted
                directives.setdefault("_extracted_from_conclusion", True)
                result["directives"] = directives
                # Annotate the result so callers know these were auto-extracted
                result["_priority_tools_auto_extracted"] = True
    except Exception as _ge:
        import sys as _sys
        print(f"[Atlas WARN] hypothesize conclusion post-processor failed: {_ge}",
              file=_sys.stderr)

    # ── Per-hypothesis split (Part 1) ───────────────────────────────────────
    # Parse the ranked H1…Hn alternatives into individually-trackable records and
    # persist them on this reason_call entry so the exhaustion gate can require
    # each contested principal to reach a verdict (not just the leading one).
    try:
        subs = _parse_sub_hypotheses(result.get("conclusion", "") or "",
                                     result.get("hypothesis_id", "") or "")
        if subs:
            cid = result.get("_atlas_call_id")
            if cid:
                from core.execution_log import log as _elog
                _elog.update_reason_call(cid, sub_hypotheses=subs,
                                         directives=result.get("directives"))
            result["sub_hypotheses"] = subs
    except Exception as _se:
        import sys as _sys
        print(f"[Atlas WARN] hypothesize sub-split failed: {_se}", file=_sys.stderr)

    return result


def _finding_words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9][a-z0-9_.\-]{3,}", (text or "").lower())}


def _prior_challenges(finding: str) -> int:
    """How many earlier evaluate_finding calls on this finding (by word
    overlap, so a rewording still counts) came back CHALLENGED."""
    try:
        from core.execution_log import log
        entries = list(log._entries)
    except Exception:  # noqa: BLE001
        return 0
    words = _finding_words(finding)
    if len(words) < 4:
        return 0
    n = 0
    for e in entries:
        if e.get("type") != "reason_call" or e.get("tool") != "reason_evaluate_finding":
            continue
        if "CHALLENGED" not in str(e.get("conclusion") or "").upper():
            continue
        prompt = str((e.get("inputs") or {}).get("user_message") or "")
        m = re.search(r"FINDING:\s*(.+?)(?:\n\s*SUPPORTING_EVIDENCE|\n\s*CASE_CONTEXT|$)", prompt, re.S)
        prior_words = _finding_words(m.group(1) if m else prompt[:1500])
        if not prior_words:
            continue
        overlap = len(words & prior_words) / len(words | prior_words)
        if overlap >= 0.5:
            n += 1
    return n


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_evaluate_finding")
def reason_evaluate_finding(
    finding: str,
    supporting_evidence: str,
    case_context: str = "",
    input_call_ids: list[int] | None = None,
) -> dict:
    """
    Adversarially challenge a specific conclusion before it goes into the report.
    Returns verdict (SUPPORTED / CHALLENGED / UNCERTAIN), identified weaknesses,
    and what additional evidence would resolve uncertainty.

    finding: the specific conclusion being made
    supporting_evidence: the artifacts and tool output that support it
    case_context: broader investigation context
    input_call_ids: REQUIRED — list of _atlas_call_id values that produced
        the supporting_evidence you're passing in.

    When the model returns VERDICT: CHALLENGED, this function auto-emits a
    `self_correction` trace entry so the moment is captured as a first-class
    audit event even when the agent abandons the claim without ever calling
    record_finding (the only path that previously emitted self_correction).

    Reformulation depth gate: tracks how many times the same normalized finding
    description has been through evaluate_finding recently without intervening
    new tool calls. Refuses on the third consecutive reformulation so the agent
    stops defending a finding that isn't improving with new evidence.
    """
    import re
    # ── Reformulation depth gate ────────────────────────────────────────────
    # Normalize the finding for comparison: lowercase, collapse whitespace,
    # drop punctuation. Then walk recent trace entries to count prior
    # evaluate_finding calls on the same normalized description that occurred
    # without an intervening tool_call producing new evidence.
    def _normalize(s: str) -> str:
        return re.sub(r"[\s\W_]+", " ", (s or "").lower()).strip()
    try:
        from core.execution_log import log
        norm_now = _normalize(finding)[:200]
        if norm_now:
            recent = log._entries[-60:] if len(log._entries) > 60 else log._entries
            prior_evals = 0
            new_tool_calls_since_last_eval = 0
            saw_eval = False
            for entry in reversed(recent):
                t = entry.get("type")
                if t == "reason_call" and entry.get("tool") == "reason_evaluate_finding":
                    blob = entry.get("conclusion", "") + " " + str(entry.get("inputs", {}).get("user_message", ""))
                    if norm_now and norm_now in _normalize(blob)[:5000]:
                        prior_evals += 1
                        saw_eval = True
                elif t == "tool_call" and entry.get("success"):
                    if not saw_eval:
                        new_tool_calls_since_last_eval += 1
            # 2 prior reformulations + no new tool evidence between latest eval
            # and now = refuse the third attempt.
            if prior_evals >= 2 and new_tool_calls_since_last_eval == 0:
                refusal_msg = (
                    f"Reformulation depth gate refused this evaluate_finding call: "
                    f"the same finding description has been evaluated {prior_evals} "
                    f"time(s) recently with no new tool evidence collected between "
                    f"attempts. Reformulating a finding that isn't acquiring new "
                    f"supporting evidence is a rumination spiral. Run new tool "
                    f"calls to gather fresh evidence, OR park this finding "
                    f"(record as UNCONFIRMED with note about the reformulation "
                    f"loop) and explore a different finding direction relevant "
                    f"to the case question."
                )
                # Emit a self_correction so the loop break is auditable
                try:
                    log.record_self_correction(
                        trigger="reformulation_depth_gate",
                        prior_belief=f"Repeated evaluate on: {finding[:200]}",
                        new_belief=("Refused by reformulation depth gate — explore "
                                    "different finding directions or run new tools."),
                        evidence=refusal_msg[:300],
                        linked_call_id=0,
                    )
                except Exception:
                    pass
                return {
                    "success": False,
                    "error": refusal_msg,
                    "gate": "reformulation_depth_limit",
                    "prior_evaluations": prior_evals,
                    "new_tool_calls_since_last_eval": new_tool_calls_since_last_eval,
                }
    except Exception as _gate_e:
        # Gate must never break the underlying call — log and continue
        import sys as _sys
        print(f"[Atlas WARN] reformulation_depth_limit check failed: {_gate_e}",
              file=_sys.stderr)

    user = f"FINDING:\n{finding}\n\nSUPPORTING EVIDENCE:\n{supporting_evidence}"
    if case_context:
        user += f"\n\nCASE CONTEXT:\n{case_context}"
    result = _ask(_EVALUATE_SYS, user, _tool_name="reason_evaluate_finding",
                  input_call_ids=input_call_ids)
    conclusion = result.get("conclusion", "") or ""
    # Tolerate markdown decoration and separator variants around the verdict
    # ("**VERDICT: SUPPORTED**", "Verdict — CHALLENGED"); \W{0,12} spans any
    # short run of punctuation/whitespace between the keyword and the value.
    verdict_match = re.search(
        r"VERDICT\W{0,12}(SUPPORTED|CHALLENGED|UNCERTAIN)", conclusion,
        re.IGNORECASE,
    )
    if verdict_match and verdict_match.group(1).upper() == "CHALLENGED":
        # An evaluator that challenges the same finding again and again, each
        # time with a new demand, turns verification into a chase. After the
        # second challenge the finding belongs in the report at the tier its
        # cited evidence supports, with the remaining gap named.
        try:
            prior = _prior_challenges(finding)
            if prior >= 2:
                result["repeated_challenges"] = prior + 1
                result["guidance"] = (
                    f"This finding has now been CHALLENGED {prior + 1} times, each "
                    "time with a further demand. Do not evaluate it again: record "
                    "it at the tier its cited evidence supports (LIKELY when the "
                    "observable core is cited) and state the open point as a "
                    "limitation. CONFIRMED is not required for the report."
                )
                result["conclusion"] = conclusion + "\n\nREPEATED CHALLENGE: " + result["guidance"]
        except Exception:  # noqa: BLE001
            pass
        try:
            from core.execution_log import log
            # _log_reason has already written the reason_call entry. Find its
            # call_id so the self_correction can carry an explicit FK.
            eval_cid = 0
            for entry in reversed(log._entries):
                if (entry.get("type") == "reason_call"
                        and entry.get("tool") == "reason_evaluate_finding"):
                    eval_cid = int(entry.get("call_id") or 0)
                    break
            log.record_self_correction(
                trigger="evaluate_challenged",
                prior_belief=f"Attempted to assert: {finding[:200]}",
                new_belief=("reason.evaluate_finding returned CHALLENGED — do "
                            "not blanket-downgrade. Split the claim: re-record "
                            "the directly-observable core (exactly what the "
                            "cited output shows) as its own finding — it can "
                            "still earn CONFIRMED through the normal gate "
                            "chain — and record the challenged inference "
                            "separately at the tier its remaining evidence "
                            "supports."),
                evidence=conclusion[:300],
                linked_call_id=eval_cid,
            )
        except Exception as e:  # noqa: BLE001
            import sys
            print(f"[Atlas WARN] auto-self_correction emit failed: {e}", file=sys.stderr)
    return result


_CITE_CHECK_SYS = (
    "You are a citation auditor. Given a forensic FINDING and its SUPPORTING_EVIDENCE, "
    "verify that every concrete claim in the finding has a citation in the evidence.\n\n"
    "Concrete claims include: file paths, IP addresses, port numbers, timestamps, "
    "process names, account names, registry keys, hash values, event IDs, port numbers, "
    "service names, MITRE ATT&CK technique IDs, and specific numeric quantities.\n\n"
    "For each concrete claim, decide:\n"
    "  CITED — the same value appears in supporting_evidence with a tool name or "
    "field reference (e.g. 'vol.psscan: PID=5024', '/mnt/host01/Windows/Temp/X.exe').\n"
    "  UNCITED — the value appears in the finding but not in supporting_evidence, "
    "OR appears without a tool/field reference.\n\n"
    "Output format (strict, no markdown bolding, no code fences):\n"
    "CITE_CHECK:\n"
    "{\n"
    '  "verdict": "ALL_CITED" | "UNCITED_CLAIMS_PRESENT" | "INSUFFICIENT_EVIDENCE",\n'
    '  "cited_claims": ["claim text 1", "claim text 2", ...],\n'
    '  "uncited_claims": ["claim text X", "claim text Y", ...],\n'
    '  "rationale": "one-sentence summary"\n'
    "}\n\n"
    "Choose INSUFFICIENT_EVIDENCE only when supporting_evidence is empty or contains "
    "no actual artifact data. A finding with no concrete claims gets ALL_CITED with "
    "empty arrays."
)


def _parse_cite_check(raw: str) -> dict:
    """Extract CITE_CHECK JSON block from model output."""
    import re
    if not raw:
        return {"verdict": "INSUFFICIENT_EVIDENCE", "cited_claims": [],
                "uncited_claims": [], "rationale": "empty model output"}
    match = re.search(
        r"\*{0,2}CITE_CHECK\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\{.*\})\s*(?:```)?",
        raw, re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return {"verdict": "INSUFFICIENT_EVIDENCE", "cited_claims": [],
                "uncited_claims": [], "rationale": "no CITE_CHECK block found"}
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        parsed = json.loads(text)
        return {
            "verdict": parsed.get("verdict", "INSUFFICIENT_EVIDENCE"),
            "cited_claims": parsed.get("cited_claims", []) or [],
            "uncited_claims": parsed.get("uncited_claims", []) or [],
            "rationale": parsed.get("rationale", ""),
        }
    except (json.JSONDecodeError, ValueError):
        return {"verdict": "INSUFFICIENT_EVIDENCE", "cited_claims": [],
                "uncited_claims": [], "rationale": "malformed CITE_CHECK JSON"}


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_cite_check")
def reason_cite_check(finding: str, supporting_evidence: str,
                      input_call_ids: list[int] | None = None) -> dict:
    """
    Proactively verify every concrete claim in `finding` is backed by a citation
    in `supporting_evidence`. Call before record_finding to surface uncited
    claims while you can still gather evidence.

    finding: the conclusion text as you intend to record it.
    supporting_evidence: the tool output excerpts and citations that back it.
    input_call_ids: REQUIRED — list of _atlas_call_id values that produced
        the supporting_evidence.

    Returns: verdict (ALL_CITED / UNCITED_CLAIMS_PRESENT / INSUFFICIENT_EVIDENCE),
             cited_claims, uncited_claims, rationale.
    """
    user = f"FINDING:\n{finding}\n\nSUPPORTING_EVIDENCE:\n{supporting_evidence}"
    settled = _settled_cite_check(finding, supporting_evidence, input_call_ids)
    if settled is not None:
        # Recorded as a reason_call like a model verdict, so the
        # record_finding gate finds the check it requires and reads the
        # same verdict the analyst was shown.
        result = {
            "success": True,
            "conclusion": "CITE_CHECK:\n" + json.dumps(settled),
            "directives": {},
            "input_tokens": 0,
            "output_tokens": 0,
            "deterministic": True,
            "inputs": {
                "user_message": user,
                "system_prompt_kind": "reason_cite_check",
            },
        }
        _log_reason("reason_cite_check", result, input_call_ids=input_call_ids)
        result.update(settled)
        return result
    result = _ask(_CITE_CHECK_SYS, user, _tool_name="reason_cite_check",
                  input_call_ids=input_call_ids)
    if result.get("success"):
        parsed = _parse_cite_check(result.get("conclusion", ""))
        result.update(parsed)
    return result


def _settled_cite_check(finding: str, supporting_evidence: str,
                        input_call_ids: list[int] | None) -> dict | None:
    """The citation verdict when string matching alone settles it, else None.

    cite_check's job is a lookup — does each value the finding rests on
    appear in the evidence offered for it — and the record_finding gate
    already answers it deterministically for inline evidence. The model is
    consulted only where matching cannot decide: a finding with no citable
    value (prose claims), or values present in the offered evidence that the
    trace of the cited calls does not show. Two outcomes need no model:

    - a value missing from the evidence is uncited whatever a reader makes
      of the prose, and the gate would refuse the finding on it anyway;
    - every value is in the offered evidence and in what the cited calls
      actually printed, so there is nothing left to doubt.
    """
    from tools._gates._citation import deterministic_cite_check
    det = deterministic_cite_check(finding, supporting_evidence)
    if det["verdict"] != "ALL_CITED":
        missing = ", ".join(det["uncited_claims"][:5])
        det["rationale"] = (
            "supporting_evidence is empty" if det["verdict"] == "INSUFFICIENT_EVIDENCE"
            else f"values in the finding that supporting_evidence does not contain: {missing}")
        return det
    if not det["cited_claims"]:
        return None
    wanted = {int(c) for c in (input_call_ids or []) if c}
    if not wanted:
        return None
    try:
        from core.execution_log import log as _elog
        recorded = " ".join(
            _call_output_text(e) for e in list(_elog._entries)
            if e.get("type") == "tool_call" and e.get("call_id") in wanted
        ).lower()
    except Exception:  # noqa: BLE001
        return None
    if not all(v.lower() in recorded for v in det["cited_claims"]):
        return None
    det["rationale"] = "every cited value appears in the output of the cited calls"
    return det


_CONFIDENCE_SCORE_SYS = (
    "You are a forensic confidence-tier scorer. Given a finding and its "
    "supporting evidence, decide the appropriate confidence tier:\n\n"
    "  CONFIRMED — multiple independent forensic artifacts directly support "
    "the claim (e.g. MFT record + Prefetch + EVTX 7045 all agreeing); the "
    "claim is technically verified and the alternative explanations are ruled out.\n"
    "  LIKELY    — a single high-quality artifact supports the claim "
    "(e.g. a definitive EVTX entry, an authoritative VT detection ratio); "
    "alternative explanations are weak but not eliminated.\n"
    "  SUSPECTED — indirect or pattern-based evidence (e.g. anomalous timing, "
    "YARA hit alone, suspicious filename); plausible alternatives remain.\n"
    "  UNCONFIRMED — inference or expectation only; no direct artifact.\n\n"
    "Apply hard rules:\n"
    "  - YARA hit ALONE is NEVER above SUSPECTED.\n"
    "  - A claim that the supporting evidence does not literally contain is "
    "UNCONFIRMED.\n"
    "  - Mechanism claims (how something happened) need direct artifact "
    "support or drop to SUSPECTED.\n"
    "  - Negative findings (we didn't see X) are UNCONFIRMED unless an "
    "exhaustive search method is cited.\n\n"
    "Output format (strict, no markdown bolding, no code fences):\n"
    "CONFIDENCE_SCORE:\n"
    "{\n"
    '  "tier": "CONFIRMED" | "LIKELY" | "SUSPECTED" | "UNCONFIRMED",\n'
    '  "score": 0.0,\n'
    '  "rationale": "one-line justification citing the evidence",\n'
    '  "downgrade_reasons": ["reason 1", "reason 2"]\n'
    "}\n\n"
    "score is a 0.0–1.0 numeric confidence: ≥0.85 CONFIRMED, 0.60–0.84 LIKELY, "
    "0.30–0.59 SUSPECTED, <0.30 UNCONFIRMED. downgrade_reasons is non-empty "
    "only when the tier is below the agent's apparent intent."
)


def _parse_confidence_score(raw: str) -> dict:
    """Extract CONFIDENCE_SCORE JSON from model output."""
    if not raw:
        return {"tier": "UNCONFIRMED", "score": 0.0,
                "rationale": "empty model output", "downgrade_reasons": []}
    match = re.search(
        r"\*{0,2}CONFIDENCE_SCORE\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\{.*\})\s*(?:```)?",
        raw, re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return {"tier": "UNCONFIRMED", "score": 0.0,
                "rationale": "no CONFIDENCE_SCORE block found",
                "downgrade_reasons": []}
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        parsed = json.loads(text)
        tier = (parsed.get("tier") or "UNCONFIRMED").upper()
        if tier not in ("CONFIRMED", "LIKELY", "SUSPECTED", "UNCONFIRMED"):
            tier = "UNCONFIRMED"
        score_val = parsed.get("score", 0.0)
        try:
            score = float(score_val)
        except (TypeError, ValueError):
            score = 0.0
        return {
            "tier": tier,
            "score": max(0.0, min(1.0, score)),
            "rationale": parsed.get("rationale", ""),
            "downgrade_reasons": parsed.get("downgrade_reasons", []) or [],
        }
    except (json.JSONDecodeError, ValueError):
        return {"tier": "UNCONFIRMED", "score": 0.0,
                "rationale": "malformed CONFIDENCE_SCORE JSON",
                "downgrade_reasons": []}


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_confidence_score")
def reason_confidence_score(finding: str, supporting_evidence: str,
                            intended_tier: str = "",
                            input_call_ids: list[int] | None = None) -> dict:
    """
    Score a finding's confidence tier from its supporting evidence. Use BEFORE
    record_finding for any tier above SUSPECTED — this grounds the tier choice
    in evidence properties rather than agent assertion.

    finding: the claim text.
    supporting_evidence: tool output excerpts + citations that back the claim.
    intended_tier: optional — what tier the agent was about to use. The reviewer
                   compares its scoring to this and flags downgrades.
    input_call_ids: REQUIRED — list of _atlas_call_id values that produced
        the supporting_evidence.

    Returns: tier (CONFIRMED/LIKELY/SUSPECTED/UNCONFIRMED), score (0.0–1.0),
             rationale, downgrade_reasons.
    """
    user = (
        f"FINDING:\n{finding}\n\n"
        f"SUPPORTING_EVIDENCE:\n{supporting_evidence}"
    )
    if intended_tier:
        user += f"\n\nAGENT_INTENDED_TIER: {intended_tier.upper()}"
    result = _ask(_CONFIDENCE_SCORE_SYS, user, _tool_name="reason_confidence_score",
                  input_call_ids=input_call_ids)
    if result.get("success"):
        parsed = _parse_confidence_score(result.get("conclusion", ""))
        result.update(parsed)
    return result


_AUDIT_FINDINGS_SYS = (
    "You audit a forensic investigation's execution trace for unrecorded findings.\n\n"
    "You receive:\n"
    "  - A list of recent NARRATIONS (assistant analysis text written to the trace).\n"
    "  - A list of RECORDED_FINDINGS (structured finding entries currently in the trace).\n\n"
    "Identify factual claims in the narrations that should have been recorded as "
    "structured `finding` entries but weren't. Look for:\n"
    "  - Specific IOCs (file paths, IPs, hashes, process names, account names).\n"
    "  - Attribution claims (this is attacker tool X, this is technique Y).\n"
    "  - Mechanism claims (X happened because of Y).\n"
    "  - Confirmed compromise statements.\n"
    "  - Exfiltration / lateral-movement / persistence confirmations.\n\n"
    "Skip narrations that:\n"
    "  - Just restate a finding that's already in RECORDED_FINDINGS (same IOC + same claim).\n"
    "  - Describe planned next steps without stating facts.\n"
    "  - Express reasoning, hypotheses, or directives only.\n\n"
    "Output format (strict, no markdown bolding, no code fences):\n"
    "AUDIT_FINDINGS:\n"
    "[\n"
    "  {\n"
    "    \"narration_call_id\": 819,\n"
    "    \"narration_excerpt\": \"first ~200 chars of the narration\",\n"
    "    \"suggested_finding\": {\n"
    "      \"description\": \"…\",\n"
    "      \"suggested_confidence\": \"CONFIRMED|LIKELY|SUSPECTED|UNCONFIRMED\",\n"
    "      \"suggested_source\": \"tool that produced it, e.g. vol.netscan\"\n"
    "    },\n"
    "    \"suggested_linked_call_id\": 815,\n"
    "    \"rationale\": \"one-line why this should be a structured finding\"\n"
    "  }\n"
    "]\n\n"
    "Return an empty array [] if all factual claims are already represented in "
    "RECORDED_FINDINGS. Conservative is better than aggressive — if in doubt, skip."
)


def _parse_audit_findings(raw: str) -> list[dict]:
    """Extract AUDIT_FINDINGS JSON array from model output."""
    if not raw:
        return []
    match = re.search(
        r"\*{0,2}AUDIT_FINDINGS\*{0,2}\s*:?\*{0,2}\s*(?:```json\s*)?(\[.*\])\s*(?:```)?",
        raw, re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []
    text = re.sub(r"\s*//[^\n]*", "", match.group(1))
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, ValueError):
        return []


def _audit_cursor_path(case_dir: str | None) -> Path | None:
    if not case_dir:
        return None
    return Path(case_dir) / ".atlas" / "audit_findings_cursor.json"


def _load_audit_watermark(case_dir: str | None) -> int:
    path = _audit_cursor_path(case_dir)
    if path is None or not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return int(data.get("last_narration_call_id") or 0)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0


def _save_audit_watermark(case_dir: str | None, call_id: int) -> None:
    path = _audit_cursor_path(case_dir)
    if path is None or call_id <= 0:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"last_narration_call_id": int(call_id)}, indent=2),
            encoding="utf-8",
        )
        tmp.replace(path)
    except OSError:
        pass


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_audit_findings")
def reason_audit_findings(narration_window: int = 60,
                          input_call_ids: list[int] | None = None) -> dict:
    """
    Audit the live trace for unrecorded findings (delta-only).

    Reads investigation_narration entries newer than the last successful audit
    watermark (capped by `narration_window`), plus current `finding` entries,
    sends them to the reason backend, and returns model-judged candidates for
    factual claims that should be recorded as structured findings but aren't.

    Re-auditing with no new narrations is a no-op (no LLM call) — this stops
    the audit ritual from burning tokens on an unchanged window.

    narration_window: max number of new narrations to audit in one call.

    Returns:
      candidates: list of {
        narration_call_id, narration_excerpt,
        suggested_finding: {description, suggested_confidence, suggested_source},
        suggested_linked_call_id, rationale,
      }
      summary: {total_narrations, recorded_findings, candidate_count, ...}
    """
    from core.execution_log import is_disposition, log
    try:
        case_dir = log.case_dir()
    except Exception:
        case_dir = None
    watermark = _load_audit_watermark(case_dir)
    # A disposition records that a search found nothing; it holds no claim
    # to promote, and auditing it would ask for the finding it exists to
    # avoid.
    narrations = [
        e for e in log._entries
        if e.get("type") == "investigation_narration"
        and not is_disposition(e)
        and int(e.get("call_id") or 0) > watermark
    ]
    if narration_window and len(narrations) > narration_window:
        narrations = narrations[-narration_window:]
    findings_entries = [e for e in log._entries if e.get("type") == "finding"]

    if not narrations:
        return {
            "success": True,
            "candidates": [],
            "gate": "audit_delta_empty" if watermark else None,
            "summary": {
                "total_narrations": 0,
                "recorded_findings": len(findings_entries),
                "candidate_count": 0,
                "skipped_reason": (
                    "no_new_narrations" if watermark else "no_narrations"
                ),
                "watermark": watermark,
            },
        }

    # Trim narrations/findings for the prompt
    nars_payload = [
        {"call_id": e.get("call_id"),
         "content": (e.get("content") or "")[:1200],
         "input_call_ids": e.get("input_call_ids") or []}
        for e in narrations
    ]
    finds_payload = [
        {"call_id": e.get("call_id"),
         "description": (e.get("description") or "")[:300],
         "confidence": e.get("confidence", ""),
         "linked_call_id": e.get("linked_call_id", 0)}
        for e in findings_entries
    ]
    user = (
        f"NARRATIONS ({len(nars_payload)} new since call_id>{watermark}):\n"
        f"{json.dumps(nars_payload, indent=2)}\n\n"
        f"RECORDED_FINDINGS ({len(finds_payload)}):\n"
        f"{json.dumps(finds_payload, indent=2)}"
    )
    # If no explicit input_call_ids supplied, auto-derive from the call_ids
    # of every narration + finding we just consumed — keeps the lineage
    # complete without forcing the agent to list them all.
    derived_ids = input_call_ids or [
        e.get("call_id") for e in (narrations + findings_entries)
        if e.get("call_id")
    ]
    result = _ask(_AUDIT_FINDINGS_SYS, user, _tool_name="reason_audit_findings",
                  input_call_ids=derived_ids)
    candidates = []
    if result.get("success"):
        candidates = _parse_audit_findings(result.get("conclusion", ""))
        max_id = max(int(e.get("call_id") or 0) for e in narrations)
        _save_audit_watermark(case_dir, max_id)
    return {
        **result,
        "candidates": candidates,
        "summary": {
            "total_narrations": len(narrations),
            "recorded_findings": len(findings_entries),
            "candidate_count": len(candidates),
            "watermark_before": watermark,
        },
    }


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_synthesize")
def reason_synthesize(findings: str, investigation_summary: str = "",
                      input_call_ids: list[int] | None = None) -> dict:
    """
    Cross-finding consistency and completeness check. Call this before writing
    the final report. Identifies logical gaps, contradictions, overclaimed
    conclusions, and missing investigation steps.

    findings: newline-separated list of confirmed findings
    investigation_summary: brief summary of tools run and scope covered
    input_call_ids: REQUIRED — typically the call_ids of every CONFIRMED/LIKELY
        finding entry in the trace (the synthesis aggregates them all).

    Only callable in the Report phase. Requires that the most recent dair_assess
    call returned current_phase="Report"; otherwise refused.
    """
    from core.execution_log import log
    recent_dair = None
    for e in reversed(log._entries):
        if e.get("type") == "dair_call":
            recent_dair = e
            break
    if recent_dair is None:
        return {
            "success": False,
            "error": (
                "No dair_assess call found in execution trace. Call dair_assess "
                "to establish phase state before reason.synthesize."
            ),
        }
    phase = recent_dair.get("current_phase", "")
    # Synthesis is legitimate from Analyze onward. Report-exclusivity created
    # a structural deadlock: pre_report_check's
    # only blocker demanded a fresh reason.synthesize, synthesize refused
    # outside Report, and DAIR stayed in Collect — six wrong_phase refusals
    # per cycle until the refuse latch force-advanced the phase. Triage and
    # Collect still refuse (synthesizing before analysis is premature).
    if phase not in ("Analyze", "Scan", "Report"):
        from core.investigation_exit import (
            record_wrong_phase_refuse, refuse_latch_tripped,
        )
        # Escape hatch: after repeated wrong-phase refuses OR a wrap-up
        # marker that explicitly allows synthesize escape (ledger-ready
        # force-report / wall-clock / hard turn cap). Exploration stalls
        # with an open coverage ledger must NOT unlock synthesize.
        allow_escape = refuse_latch_tripped(required_phase="Analyze")
        if not allow_escape:
            try:
                # Same flag-aware predicate as the report gate — the two
                # close-out gates must agree about what a wrap-up permits.
                allow_escape = any(
                    _wrapup_entry_allows_escape(e)
                    for e in (log._entries or [])[-60:]
                )
            except Exception:
                allow_escape = False
        if not allow_escape:
            record_wrong_phase_refuse(
                "reason_synthesize", "Analyze", current_phase=phase or "")
            return {
                "success": False,
                "gate": "wrong_phase",
                "required_phase": "Analyze",
                "current_phase": phase or "unknown",
                "error": (
                    f"reason.synthesize needs DAIR phase Analyze or later "
                    f"(current: {phase or 'unknown'}). Finish Collect work "
                    f"first, then advance via dair_assess (stack_action="
                    f"'push', next_phase='Analyze')."
                ),
                "hint": (
                    "Advance the DAIR phase to Analyze with dair_assess, "
                    "then call reason.synthesize."
                ),
            }
        # Fall through — synthesize allowed under escape; record for audit.
        try:
            log.record_call_abandoned(
                "reason_synthesize",
                f"wrong_phase_escape:allowed_from={phase or 'unknown'}",
            )
        except Exception:
            pass
    # The punch list scales with its input; an unbounded findings block
    # produced an unbounded reasoning pass. Keep the head (the findings the
    # agent listed first are the ones it considers primary) and say so.
    if len(findings) > _SYNTHESIZE_INPUT_CHARS:
        findings = (findings[:_SYNTHESIZE_INPUT_CHARS]
                    + f"\n[… findings list truncated at {_SYNTHESIZE_INPUT_CHARS} "
                      "characters; remaining findings are in the trace …]")
    user = f"FINDINGS:\n{findings}"
    if investigation_summary:
        user += f"\n\nINVESTIGATION COVERAGE:\n{investigation_summary[:6000]}"
    # Auto-derive lineage from every finding cid if not supplied
    derived_ids = input_call_ids or [
        e.get("call_id") for e in log._entries
        if e.get("type") == "finding" and e.get("call_id")
    ]
    return _ask(_SYNTHESIZE_SYS, user, _tool_name="reason_synthesize",
                input_call_ids=derived_ids)


_BLOCKER_NEGATION_RE = re.compile(
    r"(?:no|zero|0|without|not|n/?a|none|never|free of|resolved|cleared|"
    r"are no|were no|there are no|there were no)[\s\w]{0,15}$",
    re.IGNORECASE,
)


# LLM synthesize prompts ask the model to "separate BLOCKERS from ADVISORIES"
# / "Mark BLOCKERS separately". Echoed instructional prose must not trip the
# fallback.
_BLOCKER_META_HINTS = (
    "separat",
    "from advisories",
    "mark blockers",
    "punch list",
    "canonical line",
    "blockers from",
    "label one or more gaps as blocker",
    "output a structured",
    "end with a single",
)


def _has_unnegated_blocker(text: str) -> bool:
    """True if `text` mentions a 'blocker'/'blockers' that is NOT negated.

    Used only as a fallback when no canonical 'BLOCKERS:' header is present.
    A negated mention ("no blockers", "free of blockers", "0 blockers",
    "no blocker conditions found") is not a real blocker and must pass — the
    previous bare-word `\\bBLOCKER\\b` check wrongly flagged those, and also
    only matched the singular. Here we scan every blocker(s) occurrence and
    require at least one whose preceding context carries no negation.
    Instructional/rubric echoes (separate BLOCKERS from ADVISORIES) are ignored.
    """
    for mt in re.finditer(r"blockers?\b", text, re.IGNORECASE):
        pre = text[max(0, mt.start() - 25):mt.start()]
        if _BLOCKER_NEGATION_RE.search(pre):
            continue
        window = text[max(0, mt.start() - 60):mt.end() + 40].lower()
        if any(h in window for h in _BLOCKER_META_HINTS):
            continue
        if _heading_with_empty_body(text, mt.start()):
            continue
        return True
    return False


# A heading or label line: decoration and capitals around the word, ending
# in a colon or in the same decoration ("=== BLOCKER ASSESSMENT ===",
# "EVIDENCE EXHAUSTION (potential BLOCKERS):"). It speaks about the lines
# under it, so its verdict is theirs.
_HEADING_LINE_RE = re.compile(
    r"^\s*[=#*\-\s]*(?:[A-Z][A-Za-z\s()/&,-]*?)?\bBLOCKERS?\b[A-Za-z\s()/&,-]*"
    r"[:=#*\-\s]*$")
_EMPTY_BODY_RE = re.compile(
    r"^\s*[-*\d.)\s]*(?:none|no\b|n/?a\b|nothing|zero|0\b|not applicable|"
    r"nil\b)", re.IGNORECASE)


def _heading_with_empty_body(text: str, pos: int) -> bool:
    """Whether the blocker mention at ``pos`` sits in a heading whose body -
    the next line with content - says there is none. "BLOCKER ASSESSMENT:
    No blocker conditions are met" declares no blocker; the heading alone
    used to be read as one."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    line_end = len(text) if line_end < 0 else line_end
    if not _HEADING_LINE_RE.match(text[line_start:line_end]):
        return False
    rest = text[line_end:]
    for body in rest.split("\n"):
        if body.strip():
            return bool(_EMPTY_BODY_RE.match(body))
    return True     # a heading with nothing under it announces nothing


# Synthesize sometimes labels "evidence never provided to the case" as BLOCKER.
# Tools cannot conjure missing packages — those are report Limitations, not
# pre-report hard stops.
_COLLECTION_GAP_BLOCKER_RE = re.compile(
    r"(?i)(?:"
    r"not (?:in|present in|available in) (?:the )?(?:case |provided )?evidence"
    r"|not (?:in|present in) (?:the )?case"
    r"|(?:disk|forensic)?\s*image (?:is |was )?(?:not |never )?(?:in evidence|provided|available|collected)"
    r"|never (?:provided|collected|acquired|supplied)(?: to the case)?"
    r"|collection gap"
    r"|not (?:in|part of) (?:the )?(?:kape )?collection"
    r"|earlier (?:logs?|evtx) (?:are |were )?(?:not |un)?available"
    r"|evtx window starts"
    r"|no (?:earlier|prior) (?:dc )?logs? (?:are |were )?available"
    r"|disk image not collected"
    r")",
)


def _blocker_sentences(text: str) -> str:
    """The sentences of a synthesis that carry an un-negated blocker mention,
    one per line: the prose form of a BLOCKERS section, so a blocker written
    in prose is compared across syntheses the same way."""
    found = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text or ""):
        sentence = sentence.strip()
        if len(sentence) >= 12 and _has_unnegated_blocker(sentence):
            found.append(sentence)
    return "\n".join(found)


def _task_disposition_for_report(case_dir) -> "tuple[str | None, str | None]":
    """The open-questions blocker with the way out in it, and the blocked
    questions as a warning.

    A question marked blocked on missing evidence is dispositioned: the
    report states it as a limitation. Only questions still open, in
    progress, partial or reopened block, and the blocker names them with
    the beliefs that could answer them, so closing them is one call each
    rather than another probe cycle.
    """
    if not case_dir:
        return None, None
    from core.investigation_tasks import actionable_tasks, answer_candidates
    rows = actionable_tasks(case_dir)
    blocked = [t for t in rows if t.get("status") == "blocked_missing_evidence"]
    pending = [t for t in rows if t.get("status") != "blocked_missing_evidence"]
    warning = None
    if blocked:
        warning = (
            f"{len(blocked)} question(s) blocked on missing evidence; state "
            "each in the report's Limitations section: "
            + "; ".join(f"{t.get('id')} {str(t.get('text') or '')[:70]}"
                        for t in blocked[:6])
        )
    if not pending:
        return None, warning
    from core.request_parts import open_parts

    def _line(t: dict) -> str:
        head = f"{t.get('id')} [{t.get('status')}] {str(t.get('text') or '')[:70]}"
        pending_parts = open_parts(t)
        if pending_parts:
            head += " (open parts: " + ", ".join(
                f"{p['id']} {p['text'][:40]} needs a {p['type']}" for p in pending_parts[:5]) + ")"
        return head
    listing = "; ".join(_line(t) for t in pending[:6])
    if len(pending) > 6:
        listing += f"; +{len(pending) - 6} more"
    candidates = answer_candidates(case_dir, limit=6)
    from core.investigation_tasks import PARTS_HOW
    issue = (
        f"{len(pending)} investigation task(s) still actionable: {listing}. "
        "Close each with one misc.update_investigation_task(task_id, status, "
        "related_claim_ids=[...], parts=...) call: 'answered' with the belief(s) that "
        "answer every part; link a belief to a part it answers, or limit a part the "
        f"evidence cannot answer ({PARTS_HOW}). "
        + ("Beliefs that can carry an answer: " + " | ".join(candidates)
           if candidates else
           "No current belief can carry an answer yet: record the finding first.")
    )
    return issue, warning


def _blocker_text_is_only_collection_gaps(blocker_text: str) -> bool:
    """True when every substantive clause is an unresolvable collection gap."""
    text = (blocker_text or "").strip()
    if not text:
        return False
    parts = [
        p.strip(" \t-•*;")
        for p in re.split(r"(?:;|\n|\|(?=\s))", text)
        if p.strip(" \t-•*;")
    ]
    if not parts:
        parts = [text]
    substantive = [
        p for p in parts
        if len(p) > 8 and not re.fullmatch(
            r"(?:none|n/a|not applicable|see (?:above|advisories?)|and|"
            r"\d+\.?|actually[, ].*)",
            p,
            re.IGNORECASE,
        )
    ]
    # Verbose LLM dumps into BLOCKERS: often mix real gaps with rambling —
    # treat as collection-only when every long clause hits the gap regex OR
    # the whole blob is dominated by collection-gap hits and has no "run tool".
    if not substantive:
        return False
    if all(_COLLECTION_GAP_BLOCKER_RE.search(p) for p in substantive):
        return True
    if (
        _COLLECTION_GAP_BLOCKER_RE.search(text)
        and not re.search(r"(?i)\b(?:run|re-?parse|exhaust|call)\b.+\b(?:tool|evtx|hive)", text)
        and len(_COLLECTION_GAP_BLOCKER_RE.findall(text)) >= 1
        and not re.search(r"(?i)tier (?:violation|contradiction)", text)
    ):
        # Single collection-gap blocker with prose — still unresolvable by tools.
        clauses_with_gap = sum(1 for p in substantive if _COLLECTION_GAP_BLOCKER_RE.search(p))
        if clauses_with_gap == len(substantive):
            return True
    return False


# ── Unresolvable-blocker escape hatch & budget-aware deadlock relief ──────────
# The BLOCKERS check in pre_report_check is the one hard report gate with no
# bounded escape. When a genuine dead-end exists (evidence no available tool can
# parse, an artifact that was destroyed, a third party who cannot be reached)
# the agent's synthesize keeps re-listing it, pre_report_check keeps returning
# READY_TO_REPORT: false, and the report write is refused until the turn budget
# is spent with NO deliverable — the recurring "P4 report-gate deadlock"
#.
#
# Two bounded relief valves, mirroring the TTP opt-out and the report-lint
# "warn once then write" pattern already in this file:
#
#   (a) Escape hatch — the agent may ACKNOWLEDGE a blocker as genuinely
#       unresolvable WITH a justification (a dedicated UNRESOLVABLE: /
#       ACKNOWLEDGED LIMITATIONS: section, or an inline "<blocker> —
#       unresolvable because <why>"). That downgrades the hard block to a
#       documented limitation surfaced in the report's Limitations section.
#
#   (b) Budget backstop — once the loop has forced budget wrap-up (a
#       system-written budget_wrapup trace marker), unresolved CONTENT-quality
#       blockers downgrade to documented limitations: an honest partial report
#       beats an unwritten one.
#
# Scope / anti-gaming: (a) relaxes only the agent's OWN synthesize-declared
# BLOCKERS; every independently-computed gate below (coverage, hostile-auth,
# TTP mapping, under-tier, case-question) still fires from the trace, so the
# hatch cannot skip objective evidence work. (b) is triggered by the SYSTEM,
# not the agent — there is no MCP tool that emits a budget_wrapup entry — and
# it never relaxes the structural prerequisites (non-empty trace, reason.plan,
# reason.synthesize), which stay hard blocks.
_UNRESOLVABLE_PHRASE_RE = re.compile(
    r"\b(?:unresolvable|not resolvable|cannot be resolved|can'?t be resolved|"
    r"un(?:able|resolvable) to (?:parse|resolve|recover|read|decode|open)|"
    r"no (?:available|known|working) (?:tool|parser|means|method|way)s? "
    r"(?:to|can|exist|available)|"
    r"genuine(?:ly)? dead[ -]end|"
    r"accepted (?:as )?(?:a )?(?:documented )?limitation|"
    r"documented (?:as (?:a )?)?limitation)\b",
    re.IGNORECASE,
)
_UNRESOLVABLE_SECTION_RE = re.compile(
    r"(?:^|\n)\s*(?:UNRESOLVABLE|ACKNOWLEDGED LIMITATIONS?|"
    r"DOCUMENTED LIMITATIONS?|ACCEPTED LIMITATIONS?)"
    r"(?:\s*\([^)]*\))?\s*:\s*(.*?)"
    r"(?=\n\s*[A-Z][A-Z _-]{2,}(?:\s*\([^)]*\))?\s*:|\Z)",
    re.IGNORECASE | re.DOTALL,
)
# A bare "unresolvable" is not enough — the justification must be substantive so
# the hatch documents a real dead-end instead of rubber-stamping the gate away.
_MIN_ACK_JUSTIFICATION = 40
# (c) Repeat backstop. A blocker the agent neither resolves nor acknowledges
# leaves the gate returning the same verdict indefinitely: with no wall clock
# and no turn cap, the budget backstop (b) cannot arm while the run still
# looks busy, so the run grinds. After this many consecutive gate verdicts
# that say exactly the same thing, the agent's OWN declared blockers become
# documented limitations — the same outcome as (a), reached without needing
# the agent to phrase it. Scope is unchanged: every independently-computed
# gate (citation integrity, coverage, tier) stays hard. The lowering of a
# mis-cited finding reads the same number per finding and as occurrences:
# the check that lowers is the Nth in a row to flag that finding.
_BLOCKER_VERDICT_MAX_REPEATS = int(
    os.environ.get("ATLAS_REPORT_BLOCKER_MAX_REPEATS") or "4")


def _blocker_verdicts_exhausted() -> bool:
    """True once the report gate has said the same thing too many times."""
    if _BLOCKER_VERDICT_MAX_REPEATS <= 0:
        return False
    try:
        from core.investigation_exit import unchanged_blocker_verdicts
        return unchanged_blocker_verdicts() >= _BLOCKER_VERDICT_MAX_REPEATS
    except Exception:  # noqa: BLE001
        return False


_REPEAT_BACKSTOP_NOTE = (
    "reason.synthesize blocker(s) unchanged across {n} consecutive report-gate "
    "verdicts are recorded as documented limitations rather than held open. "
    "State each in the report's Limitations section with why it caps the "
    "affected conclusion's tier: ")
_ACK_NONE_BODY_RE = re.compile(r"(?:none|n/?a|not applicable|0)[.\s-]*", re.IGNORECASE)


_BLOCKERS_SECTION_RE = re.compile(
    r"(?:^|\n)\s*BLOCKERS?(?:\s*\([^)]*\))?\s*:\s*(.*?)(?=\n\s*[A-Z][A-Z _-]{2,}(?:\s*\([^)]*\))?\s*:|\Z)",
    re.IGNORECASE | re.DOTALL,
)


def _blocker_items(text: str) -> list[str]:
    """Individual blockers from a BLOCKERS section: one per bullet or line."""
    items: list[str] = []
    for line in (text or "").splitlines():
        line = re.sub(r"^\s*(?:[-*\u2022]|\d+[.)]|BLOCKER[-_ ]?\d+\s*:)\s*", "", line).strip()
        if len(line) >= 12:
            items.append(line)
    return items


def _blocker_words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9][a-z0-9_.\-]{2,}", text.lower())}


def _split_persisted_blockers(entries, latest_blockers: str) -> tuple[list[str], list[str]]:
    """``(persisted, fresh)``: blockers of the latest synthesis that the
    previous synthesis already listed (by word overlap) although tool work
    happened in between, and the ones that are new."""
    latest = _blocker_items(latest_blockers)
    if not latest:
        return [], []
    prev_text = ""
    seen_latest = False
    work_between = 0
    for e in reversed(list(entries)):
        t = e.get("type")
        if t == "reason_call" and e.get("tool") == "reason_synthesize" and e.get("success"):
            if not seen_latest:
                seen_latest = True
                continue
            prev_conclusion = e.get("conclusion") or ""
            m = _BLOCKERS_SECTION_RE.search(prev_conclusion)
            prev_text = m.group(1) if m else _blocker_sentences(prev_conclusion)
            break
        if seen_latest and t == "tool_call" and e.get("success"):
            work_between += 1
    if not prev_text or work_between == 0:
        return [], latest
    previous = [_blocker_words(b) for b in _blocker_items(prev_text)]
    persisted, fresh = [], []
    for item in latest:
        words = _blocker_words(item)
        same = any(words and pw and len(words & pw) / len(words | pw) >= 0.5 for pw in previous)
        (persisted if same else fresh).append(item)
    return persisted, fresh


def _unresolvable_acknowledgments(text: str) -> list[str]:
    """Justifications by which the agent has acknowledged a blocker as a genuine
    dead-end. Non-empty ⇒ documented limitation, not a deadlock.

    Accepts a dedicated UNRESOLVABLE:/ACKNOWLEDGED LIMITATIONS: section or an
    inline unresolvable-with-justification phrasing. Requires the acknowledged
    text to carry >= _MIN_ACK_JUSTIFICATION characters — a bare "unresolvable"
    with no explanation does not clear the gate."""
    if not text:
        return []
    acks: list[str] = []
    for m in _UNRESOLVABLE_SECTION_RE.finditer(text):
        body = m.group(1).strip()
        if (len(body) >= _MIN_ACK_JUSTIFICATION
                and not _ACK_NONE_BODY_RE.fullmatch(body)):
            acks.append(body)
    if not acks and len(text.strip()) >= _MIN_ACK_JUSTIFICATION:
        mm = _UNRESOLVABLE_PHRASE_RE.search(text)
        if mm:
            # Carry the sentence bearing the acknowledgment into the report,
            # not the whole synthesis blob (which may be raw model analysis).
            lo = max(text.rfind(".", 0, mm.start()),
                     text.rfind("\n", 0, mm.start())) + 1
            hi = min((p for p in (text.find(". ", mm.end()),
                                  text.find("\n", mm.end())) if p != -1),
                     default=len(text))
            sentence = text[lo:hi].strip(" \t\n.-")
            acks.append(sentence if len(sentence) >= _MIN_ACK_JUSTIFICATION
                        else text.strip())
    return acks


def _wrapup_entry_allows_escape(e: dict) -> bool:
    """Does this ``budget_wrapup`` trace marker permit forced close-out
    (synthesize escape / report-gate blocker relaxation)?

    The loop stamps ``allow_synthesize_escape`` on every wrap-up marker:
    True only for wall-clock / hard-turn-cap / llm-deadline / llm-transport / ledger-ready
    force-report. Exploration or quiet stalls with an OPEN coverage ledger
    stamp False — those wrap-ups steer the agent, they must not unlock a
    hollow report.
    Legacy markers without the flag: only hard stops count.
    """
    if (e.get("type") != "budget_wrapup"
            and e.get("category") != "budget_wrapup"):
        return False
    if "allow_synthesize_escape" in e:
        return bool(e.get("allow_synthesize_escape"))
    return e.get("trigger") in ("wall_clock", "turn_budget", "llm_deadline", "llm_transport")


def _budget_wrapup_signaled(entries: list[dict]) -> bool:
    """True if the agent loop has forced budget wrap-up this run AND that
    wrap-up permits close-out (see ``_wrapup_entry_allows_escape``). The
    report gate keys off it to relax unresolved content-quality blockers to
    documented limitations so the deliverable is never lost to the turn
    budget — but never for stall wrap-ups with an open coverage ledger."""
    return any(_wrapup_entry_allows_escape(e) for e in entries)


def _analyst_accepted_limitations_note(case_dir: str | Path | None) -> str | None:
    """Optional analyst escape: analysis/REPORT_LIMITATIONS_ACCEPTED.md."""
    if not case_dir:
        return None
    path = Path(case_dir) / "analysis" / "REPORT_LIMITATIONS_ACCEPTED.md"
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not text:
        return None
    return text[:4000]


# ── TTP-mapping vocabulary & helpers ─────────────────────────────────────────
# Module-level (not closures in pre_report_check) so the DAIR nudge
# (tools/dair.py) and coverage_report (tools/coverage.py) apply the exact
# same attack-shape / carries-technique tests mid-run that the pre-report
# gate applies at the end — one definition, three consumers.

# When any finding names malware, a CVE, or attack-tool/sniffing/recon
# activity, it is "attack-shaped" and should carry a technique. A malware-only
# vocabulary misses whole case classes: hacking tools, packet sniffing and
# password cracking would never fire the gate.
ATTACK_VOCAB_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b|\b(?:malware|trojan|ransomware|backdoor|"
    r"implant|beacon|dropper|loader|rootkit|webshell|web shell|"
    r"keylogger|infostealer|stealer|botnet|exploit(?:ed|ation)?|"
    r"c2|command[- ]and[- ]control|lateral movement|privilege escalation|"
    r"exfiltrat\w+|persistence mechanism|"
    r"hacking (?:tools?|utilit\w+|software)|attack tools?|"
    r"password crack\w*|cracking tools?|"
    r"credential (?:dump\w*|theft|harvest\w*)|hash (?:dump\w*|crack\w*)|"
    r"sniff\w*|promiscuous mode|intercept(?:ion|ed|ing)?|"
    r"port scan\w*|network scan\w*|reconnaissance|"
    r"brute[- ]forc\w*|wardriv\w*)\b",
    re.IGNORECASE,
)

TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Per-run opt-out: genuinely TTP-less cases exist (harassment, network
# attribution). Stated in reason.synthesize, it passes the mapping gates.
TTP_OPTOUT_RE = re.compile(
    r"(?:TTPs?|techniques?)\s*[:\-—]\s*(?:none|n/?a|not applicable)|"
    r"no (?:applicable|relevant) (?:MITRE |ATT&CK )*(?:TTPs?|techniques?)|"
    r"not TTP[- ]mappable|TTP[- ]less",
    re.IGNORECASE,
)

# Case-blind mapping targets. Blocking bar: unmapped attack-shaped
# CONFIRMED/LIKELY findings tolerated before pre_report blocks. Breadth bar
# (advisory only — a case-blind gate must never demand techniques the
# evidence doesn't support): distinct techniques / tactics for runs with
# several attack findings.
TTP_UNMAPPED_BLOCK = env_int("ATLAS_TTP_UNMAPPED_BLOCK", 2)
TTP_MIN_TECHNIQUES = env_int("ATLAS_TTP_MIN_TECHNIQUES", 5)
TTP_MIN_TACTICS = env_int("ATLAS_TTP_MIN_TACTICS", 3)


def finding_carries_technique(f: dict) -> bool:
    """A finding "carries" a technique when a T-ID is in its description or
    stamped as a gate-validated technique (record_finding's mitre_techniques
    channel). Requiring that mitre_map merely *ran* proved toothless —
    several cases ran it yet shipped 0 mapped TTPs because
    the techniques never landed on a finding.

    Techniques annotated relevance=\"unsupported\" do not count — the
    record-time mitre gate stamps those when mitre_map finds no textual basis.
    Counting them as \"carried\" let anti-spam fire on immutable superseded
    findings that could never be remapped.
    """
    if TID_RE.search(f.get("description") or ""):
        return True
    for vt in (f.get("validated_techniques") or []):
        if isinstance(vt, dict):
            if (vt.get("relevance") or "").lower() == "unsupported":
                continue
            if vt.get("technique_id"):
                return True
        elif vt:
            return True
    return False


def active_finding_entries(finding_entries: list[dict],
                           case_dir: str | None = None) -> list[dict]:
    """The trace's findings as the run currently asserts them.

    Trace findings are immutable; supersession, withdrawal and a tier the
    report gate lowered live on the claim graph. Every report gate reasons
    over this view, so a withdrawn claim cannot keep blocking the report it
    is no longer part of (core.claim_graph.asserted_finding_entries).
    """
    from core.claim_graph import asserted_finding_entries
    return asserted_finding_entries(finding_entries, case_dir)


def is_attack_finding(f: dict) -> bool:
    """CONFIRMED/LIKELY finding that is attack-shaped — the population the
    mapping-completeness gates and coverage accounting apply to.

    A finding qualifies if its description matches the attack vocabulary OR it
    already carries a validated technique. The technique-carries clause closes
    a blind spot: the vocab regex is noun-heavy (malware/C2/exfil) and
    misses findings phrased as exploitation or credential access that
    carry a validated technique yet score 0/0 attack-shaped because no
    vocab noun matches, so the gate never engages
    and coverage stays 0. A finding the analyst already
    mapped to ATT&CK is attack-shaped by definition; keying solely off
    description vocab when the technique is on the entry was the bug. This can
    only add already-mapped findings to the population — it can never move a
    finding into the unmapped set — so it strictly improves accounting without
    making the block fire more aggressively.

    The technique clause is tier-INDEPENDENT: an honestly under-tiered run recorded 10 technique-carrying
    SUSPECTED/UNCONFIRMED findings and coverage read "1/1 attack-shaped" —
    cautious tiering erased the attack story from coverage. A finding the
    analyst mapped to ATT&CK is attack-shaped whatever its tier; since it is
    mapped by construction, admitting it cannot grow the unmapped set. The
    vocab-only clause keeps the CONFIRMED/LIKELY filter — expanding THAT would
    push unmapped SUSPECTED findings into the population and make the
    pre-report block fire more aggressively."""
    if finding_carries_technique(f):
        return True
    return ((f.get("confidence") or "").upper() in {"CONFIRMED", "LIKELY"}
            and bool(ATTACK_VOCAB_RE.search(f.get("description") or "")))


def finding_tactics(f: dict) -> set[str]:
    """Normalized tactic labels from a finding's validated techniques."""
    out: set[str] = set()
    for vt in (f.get("validated_techniques") or []):
        if isinstance(vt, dict):
            for part in str(vt.get("tactic") or "").split(","):
                part = part.strip().lower().replace("-", " ")
                if part:
                    out.add(part)
    return out


def finding_technique_ids(f: dict) -> set[str]:
    """All T-IDs a finding carries (description + validated channel).

    Skips validated_techniques marked relevance=unsupported (same rule as
    finding_carries_technique).
    """
    tids = {t.upper() for t in TID_RE.findall(f.get("description") or "")}
    for vt in (f.get("validated_techniques") or []):
        if isinstance(vt, dict):
            if (vt.get("relevance") or "").lower() == "unsupported":
                continue
            tid = vt.get("technique_id") or ""
        else:
            tid = vt or ""
        if tid:
            tids.add(str(tid).upper())
    return tids


_CASE_QUESTION_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "this", "that", "what", "who",
    "where", "when", "why", "how", "did", "does", "was", "were", "are",
    "is", "of", "to", "on", "in", "at", "by", "an", "a", "as", "be",
    "or", "if", "it", "any",
    # How a question is framed rather than what it asks about: a finding
    # states the fact, it does not repeat "happened" or "whether".
    "happened", "happen", "occurred", "occur", "has", "have", "had", "been",
    "there", "which", "whether", "into", "about",
})

_CQ_POLLUTION_SPLIT = re.compile(
    r"\b(?:Evidence|Case context|Known players|Comms channels|"
    r"Starting pre-plan reads|Plan|Approach|Steps)\s*:",
    re.IGNORECASE,
)

# Capture CASE_QUESTION including following bullet lines (multi-task objectives).
# Only the literal marker at the start of a line anchors the gate: prose that
# mentions "the case question: ..." is not the objective the run was given.
_CQ_BLOB_RE = re.compile(
    r"(?m)^[ \t]*CASE_QUESTION:[ \t]*(.*?)(?=\n\n|\n(?i:Evidence|Case context|Known players|"
    r"Comms channels|Starting pre-plan reads|Plan|Approach|Steps)\s*:|\Z)",
    re.DOTALL,
)


def _normalize_single_case_question(raw: str) -> str:
    """Trim one question: stop at first '?' or strip jammed plan/context text."""
    case_question = (raw or "").strip()
    if not case_question:
        return ""
    qmark = case_question.find("?")
    if qmark != -1:
        case_question = case_question[: qmark + 1]
    else:
        case_question = _CQ_POLLUTION_SPLIT.split(case_question, maxsplit=1)[0].strip()
        case_question = case_question.split(". ")[0][:200]
    return case_question.strip()


def _split_case_questions(blob: str) -> list[str]:
    """Expand a CASE_QUESTION blob into one-or-more gated questions.

    Multi-task objectives from ``objectives_from_tasks`` look like::

        Investigate the following open requests:
        - task-0001: What happened on HOST-A?
        - task-0002: Was there lateral movement?

    Those must not be truncated at the first ``?``.
    """
    text = (blob or "").strip()
    if not text:
        return []
    lines = text.splitlines()
    body = lines
    multi = False
    if re.match(
        r"(?i)^investigate the following open requests\s*:?\s*$",
        lines[0].strip(),
    ):
        multi = True
        body = lines[1:]

    bullets: list[str] = []
    for line in body:
        m = re.match(
            r"^\s*[-*+]\s+(?:task-\d{4}:\s*)?(.+\S)\s*$",
            line,
            re.IGNORECASE,
        )
        if m:
            bullets.append(m.group(1).strip())

    if multi or len(bullets) >= 2:
        out = []
        for b in bullets:
            q = _normalize_single_case_question(b)
            if q:
                out.append(q)
        if out:
            return out

    q = _normalize_single_case_question(text)
    return [q] if q else []


def _case_question_blobs_from_entries(entries: list) -> list[str]:
    blobs: list[str] = []
    for e in entries:
        for field in ("conclusion", "content", "case_context", "case_description"):
            blob = (e.get(field) or "") if isinstance(e.get(field), str) else ""
            m = _CQ_BLOB_RE.search(blob)
            if m:
                text = m.group(1).strip()
                if text:
                    blobs.append(text)
                    return blobs  # first marker wins (historical objective)
    return blobs


def _fold_question(text: str) -> str:
    return " ".join(_normalize_single_case_question(str(text or "")).casefold().split())


def _is_umbrella_question(question: str) -> bool:
    """A question about the case as a whole ("what happened on the hosts?"),
    which no single finding answers word for word."""
    try:
        from core.investigation_tasks import DEFAULT_OBJECTIVE
        if _fold_question(question) == _fold_question(DEFAULT_OBJECTIVE):
            return True
    except Exception:  # noqa: BLE001
        pass
    try:
        from core.answer_synthesis import is_general_question
        return bool(is_general_question(question))
    except Exception:  # noqa: BLE001
        return False


def _tracked_question_texts(case_dir: str | None) -> list[str]:
    """The folded texts of every request the case tracks as a task."""
    if not case_dir:
        return []
    try:
        from core.investigation_tasks import load_tasks
        tasks = (load_tasks(case_dir) or {}).get("tasks") or []
    except Exception:  # noqa: BLE001
        return []
    return [f for f in (_fold_question(t.get("text")) for t in tasks if isinstance(t, dict)) if f]


def _is_tracked_question(question: str, tracked: list[str]) -> bool:
    """Whether a marker question is one of the case's tracked requests.
    The marker text and the task store can word one request differently
    (a question cut at its first "?", a bullet prefix), so either may
    contain the other; the shorter must say enough to mean something."""
    q = _fold_question(question)
    for t in tracked:
        short, long_ = (q, t) if len(q) <= len(t) else (t, q)
        if len(short) >= 12 and short in long_:
            return True
    return False


def _case_questions_for_pre_report(entries: list, case_dir: str | None, *,
                                   trace_path: str | None = None) -> list[tuple[str, str]]:
    """The questions the word test gates, each with its kind.

    ``free``: a question the run was asked in words (``-q``); a finding must
    name its key words. ``umbrella``: a question about the case as a whole;
    no finding answers it word for word, so it never blocks.

    Requests the case tracks as tasks are not returned: the task gate
    (``_task_disposition_for_report``) already holds them until each is
    answered with linked beliefs or its parts are limited, which is the
    stricter test. Which question the run was given comes from the record
    the CLI writes (core.run_state.read_objective, for this trace only); a
    trace without one (written before the record existed, or checked from a
    session that wrote none) falls back to the literal CASE_QUESTION marker,
    and a marker question that matches no tracked request by its wording is
    then word-gated as a free question.
    """
    found: list[tuple[str, str]] = []
    record = None
    if case_dir:
        try:
            from core.run_state import read_objective
            record = read_objective(case_dir, trace_path=trace_path)
        except Exception:  # noqa: BLE001
            record = None
    if record is not None:
        source = record.get("source")
        text = str(record.get("text") or "")
        if source == "question":
            for q in _split_case_questions(text):
                found.append((q, "umbrella" if _is_umbrella_question(q) else "free"))
        elif source == "default":
            found.append((_normalize_single_case_question(text) or text, "umbrella"))
        # tasks / rerun: the questions are the case's tracked requests.
    else:
        tracked = _tracked_question_texts(case_dir)
        for blob in _case_question_blobs_from_entries(entries):
            for q in _split_case_questions(blob):
                if _is_tracked_question(q, tracked):
                    continue
                found.append((q, "umbrella" if _is_umbrella_question(q) else "free"))

    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for q, kind in found:
        key = q.casefold()
        if not q or key in seen:
            continue
        seen.add(key)
        out.append((q, kind))
    return out


def _question_words(case_question: str) -> list[str]:
    words: list[str] = []
    for t in re.findall(r"[A-Za-z0-9_]+", (case_question or "").lower()):
        if len(t) >= 3 and t not in _CASE_QUESTION_STOPWORDS and t not in words:
            words.append(t)
    return words


def _question_coverage(entries: list, case_question: str) -> tuple[str, list[str], int]:
    """``(verdict, missing, required)`` for one free question.

    ``addressed`` when one CONFIRMED or LIKELY finding names ``required`` of
    the question's key words, ``unaddressed`` when none does (``missing``:
    the key words the closest finding lacks), ``unjudgeable`` when the
    question has no key word to look for. ``required`` is half the key
    words, at least two and at most five, and never more than there are.
    """
    words = _question_words(case_question)
    if not words:
        return "unjudgeable", [], 0
    required = min(max(2, len(words) // 2), 5, len(words))
    best: list[str] = []
    for e in entries:
        if e.get("type") != "finding":
            continue
        if (e.get("confidence") or "").upper() not in {"CONFIRMED", "LIKELY"}:
            continue
        desc_l = (e.get("description") or "").lower()
        hits = [t for t in words if t in desc_l]
        if len(hits) >= required:
            return "addressed", [], required
        if len(hits) > len(best):
            best = hits
    return "unaddressed", [t for t in words if t not in best], required


def _finding_addresses_case_question(entries: list, case_question: str) -> bool:
    return _question_coverage(entries, case_question)[0] == "addressed"


def _call_output_text(entry: dict) -> str:
    """What a recorded tool call showed (tools._gates.citation_support)."""
    from tools._gates.citation_support import call_output_text
    return call_output_text(entry)


def _miscited_finding_entries(finding_entries, entries) -> list[dict]:
    """Findings whose cited evidence does not support them, judged as every
    citation reader judges it (tools._gates.citation_support.citation_supports):
    a positive claim needs a cited evidence call that shows one of its
    identifiers, an absence claim needs a cited complete search of what it
    says is missing. Only what a forensic tool produced counts as the cited
    evidence; the finding's own record call or a reasoning step would let
    it support itself. A positive claim whose cited calls left no output
    behind cannot be judged and is not flagged.
    """
    try:
        from tools._gates.citation_support import cited_ids, citation_supports
    except Exception:  # noqa: BLE001
        return []
    # Every cited entry is handed over, the run's own words included: the
    # judgement tells a finding that cites only a reasoning step (an absence
    # resting on itself) from one that cites nothing at all.
    by_id = {e.get("call_id"): e for e in entries if e.get("call_id") is not None}
    tool_calls = [e for e in entries if e.get("type") == "tool_call"]
    out: list[dict] = []
    for f in finding_entries:
        cited = [by_id[c] for c in cited_ids(f) if c in by_id]
        if citation_supports(str(f.get("description") or ""), cited,
                             tool_calls=tool_calls,
                             supporting_evidence=str(f.get("supporting_evidence") or "")
                             ) is False:
            out.append(f)
    return out


def _citation_blocker(miscited: list[dict]) -> str:
    """The blocker for findings whose citations do not support them, each
    named with its problem and the supersedes= that repairs it, so the repair
    is a re-record that replaces the finding rather than a variant beside it.

    The text depends only on which findings stand flagged (call-id order,
    three named), so the verdict repeats while they stand and the backstops
    that wait for a repeated verdict can see it. Which calls would support
    each finding changes with every call and goes to the warning from
    :func:`_citation_repair_hint` instead."""
    from tools._gates.citation_support import is_absence_claim
    flagged = sorted(miscited, key=lambda f: int(f.get("call_id") or 0))
    lines: list[str] = []
    for f in flagged[:3]:
        desc = str(f.get("description") or "")
        what = ("asserts an absence but cites no complete search that would have found what "
                "it says is missing" if is_absence_claim(desc)
                else "its cited calls show none of the identifiers it rests on")
        lines.append(f"{desc[:80]!r} (supersedes={f.get('call_id')}): {what}")
    if len(flagged) > 3:
        lines.append(f"and {len(flagged) - 3} more (supersedes= "
                     + ", ".join(str(f.get("call_id")) for f in flagged[3:]) + ")")
    return (
        "Finding(s) cite calls that do not contain the identifiers they rest on: "
        + "; ".join(lines)
        + ". Repair each by recording it again with the supersedes= named, which replaces "
        "it instead of adding a variant beside it: cite the calls that show it (for an "
        "absence, run the complete search first and cite that), or move the value they "
        "show into supporting_evidence. The same words with the right citations is a "
        "citation repair, not a duplicate, and it carries the hypothesis the finding "
        "resolved. Where nothing shows it, lower it: record it again at UNCONFIRMED with "
        "the same supersedes=, as a limitation. Withdraw it (claim.supersede with no "
        "new_id) only when no tool output anywhere supports it. A report must not rest "
        "on evidence that does not say what the finding claims."
    )


def _citation_repair_hint(miscited: list[dict], entries) -> str:
    """Which calls in the trace would support each finding the citation
    blocker names. A warning, not part of the blocker: the next call can
    change it while the finding stands unrepaired."""
    from tools._gates.citation_support import (calls_showing, cited_ids,
                                               is_absence_claim)
    tool_calls = [e for e in entries if e.get("type") == "tool_call"]
    leads: list[str] = []
    for f in sorted(miscited, key=lambda f: int(f.get("call_id") or 0))[:3]:
        desc = str(f.get("description") or "")
        absence = is_absence_claim(desc)
        shown = calls_showing(desc, tool_calls, exclude=cited_ids(f),
                              complete_only=absence,
                              supporting_evidence=str(f.get("supporting_evidence") or ""))
        if shown:
            lead = ("call(s) " + ", ".join(f"{s['call_id']} ({s['why']})" for s in shown)
                    + " would support it")
        elif absence:
            lead = "no complete search in the trace covers it yet; run one, or lower it"
        else:
            lead = "no evidence call in the trace shows it; lower or withdraw it"
        leads.append(f"supersedes={f.get('call_id')}: {lead}")
    return "Citation repair leads: " + "; ".join(leads) + "."


def _withdrawn_since_last_check(trace: list[dict], case_dir) -> list[str]:
    """Ids of the claims withdrawn since the previous report check recorded
    itself on the trace; empty before the first check or without a case."""
    last = None
    for e in reversed(trace or []):
        if (e.get("type") == "reason_call"
                and str(e.get("tool") or "").endswith("pre_report_check")):
            last = e.get("ts")
            break
    if not last or not case_dir:
        return []
    from datetime import datetime

    def _when(ts) -> "datetime | None":
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None

    since = _when(last)
    if since is None:
        return []
    try:
        from core.claim_graph import load_graph
        nodes = load_graph(case_dir).get("nodes") or {}
    except Exception:  # noqa: BLE001
        return []
    out: list[str] = []
    for nid, node in nodes.items():
        if not isinstance(node, dict) or node.get("kind") != "claim":
            continue
        if node.get("status") != "withdrawn":
            continue
        at = _when(node.get("updated_at"))
        if at is not None and at >= since:
            out.append(str(nid))
    return sorted(out)


def _findings_with_unsupported_citations(finding_entries, entries) -> list[str]:
    """Descriptions of the findings :func:`_miscited_finding_entries` flags."""
    return [str(f.get("description") or "")[:80]
            for f in _miscited_finding_entries(finding_entries, entries)]


# The stamps record_finding leaves on a finding recorded again: named with
# supersedes=, a citation repair, a sharper statement, an elaboration.
_REPRISE_KEYS = ("replaces_call_id", "repairs_call_id", "refines_call_id", "restates_call_id")


def _finding_lineage_root(finding: dict, findings_by_cid: dict) -> int:
    """The call id of the first record in a finding's chain of re-records,
    so a finding recorded again is still the same finding to the lowering
    below. A link to a finding the trace does not hold ends the chain."""
    cur, seen = finding, set()
    while True:
        cid = int(cur.get("call_id") or 0)
        seen.add(cid)
        prev = next((int(cur[k]) for k in _REPRISE_KEYS if cur.get(k)), 0)
        if not prev or prev in seen or prev not in findings_by_cid:
            return cid
        cur = findings_by_cid[prev]


def _miscited_streaks(trace: list[dict], roots: list[int]) -> dict[int, int]:
    """For each lineage root, how many of the newest report checks in a row
    flagged it. A check that stored no list (an older build) ends a streak."""
    checks = [e.get("miscited_lineage") for e in reversed(trace)
              if e.get("type") == "reason_call"
              and e.get("tool") == "reason_pre_report_check"]
    out: dict[int, int] = {}
    for root in roots:
        n = 0
        for flagged in checks:
            if not isinstance(flagged, list) or root not in flagged:
                break
            n += 1
        out[root] = n
    return out


def _lower_miscited_findings(miscited: list[dict], case_dir) -> list[str]:
    """Drop each mis-cited finding's claim to UNCONFIRMED; return what moved.

    The gate detects a finding whose cited call carries none of the
    identifiers the finding rests on. Its own message offers three remedies,
    and the third — lower the finding — is the one that can be applied
    without weakening anything: the report then claims only what the evidence
    shows. Taken only once the gate has flagged the same finding (followed
    through its re-records) in _BLOCKER_VERDICT_MAX_REPEATS report checks in
    a row, so a run whose repair works is never pre-empted.

    This is the gate's one write, and it is deliberate: the gate is the only
    thing that knows a citation is unsupported. Idempotent — a claim already
    at the floor moves nowhere.
    """
    if not case_dir:
        return []
    moved: list[str] = []
    try:
        from core.claim_graph import upsert_claim_from_finding
    except Exception:  # noqa: BLE001
        return []
    for f in miscited:
        statement = str(f.get("description") or "").strip()
        if not statement:
            continue
        try:
            res = upsert_claim_from_finding(
                case_dir,
                statement=statement,
                confidence="UNCONFIRMED",
                source="report_gate_unsupported_citation",
                host=str(f.get("host") or ""),
                finding_call_id=int(f.get("call_id") or 0),
                linked_call_id=int(f.get("linked_call_id") or 0),
                input_call_ids=list(f.get("input_call_ids") or []),
            )
        except Exception:  # noqa: BLE001
            continue
        if isinstance(res, dict) and res.get("success"):
            moved.append(statement[:80])
    return moved


def _pre_report_check(*, apply_remedies: bool = False) -> dict:
    """The readiness verdict. Read-only unless ``apply_remedies``.

    The gate is consulted by things other than the analyst — a readiness
    panel, a status probe, a review of a finished case — and one of its
    remedies writes: a finding whose citation does not support it is lowered
    once the gate has repeated itself. An inspector rendering that verdict
    must not move a claim, and a panel that refreshes would move one per
    refresh. So writing is opt-in and only the analyst's own tool below opts
    in; anything importing this gets the verdict and changes nothing.

    Readers wanting the last verdict without running the gate at all should
    prefer the recorded one — see core.progress_signature.
    """
    from core.execution_log import log
    # The trace records what happened; the gates judge what the run still
    # asserts. Findings the claim graph marks superseded or withdrawn are
    # dropped from the view every check below reads, and a finding whose
    # claim now carries another tier is seen at that tier - the trace itself
    # is untouched and keeps them for audit. Only the structural checks and
    # the verdict's own lineage read the whole trace.
    trace = log._entries
    try:
        _case_dir = log.case_dir()
    except Exception:
        _case_dir = None
    all_finding_entries = [e for e in trace if e.get("type") == "finding"]
    finding_entries = active_finding_entries(all_finding_entries, _case_dir)
    _asserted_by_cid = {f.get("call_id"): f for f in finding_entries}
    entries = [
        _asserted_by_cid[e.get("call_id")] if e.get("type") == "finding" else e
        for e in trace
        if e.get("type") != "finding" or e.get("call_id") in _asserted_by_cid
    ]

    def _successful_reason(tool: str) -> bool:
        """True only for a usable result — not a zero-token empty attempt.

        A failed, empty synthesize attempt must not count: presence alone
        would satisfy the structural spine and report READY_TO_REPORT:true.
        """
        from core.reason_outcome import any_usable_reason_call
        return any_usable_reason_call(entries, tool)

    has_plan = _successful_reason("reason_plan")
    has_synthesize = _successful_reason("reason_synthesize")
    has_hypothesize = _successful_reason("reason_hypothesize")
    from core.reason_outcome import is_usable_reason_call as _usable_reason
    evaluate_calls = sum(
        1 for e in entries
        if e.get("type") == "reason_call"
        and e.get("tool") == "reason_evaluate_finding"
        and _usable_reason(e)
    )
    confirmed_findings = sum(
        1 for e in entries
        if e["type"] == "finding" and e.get("confidence", "").upper() == "CONFIRMED"
    )
    tool_calls = sum(1 for e in entries if e["type"] == "tool_call")
    total_input_tokens = sum(e.get("input_tokens", 0) for e in entries if e["type"] == "reason_call")
    total_output_tokens = sum(e.get("output_tokens", 0) for e in entries if e["type"] == "reason_call")

    issues: list[str] = []
    # Structural prerequisites (non-empty trace, plan, synthesize) are the
    # report's spine — kept separate because the budget-aware backstop below
    # relaxes CONTENT-quality blockers but must never relax these.
    structural_issues: list[str] = []
    warnings: list[str] = []
    # Blockers downgraded to documented limitations by the escape hatch (a) or
    # the budget backstop (b); surfaced in the report's Limitations section.
    documented_limitations: list[str] = []

    if len(trace) == 0:
        structural_issues.append("Execution trace is empty — start_execution_log was not called before tool runs")
    if not has_plan:
        structural_issues.append(
            "reason.plan was not completed successfully — mandatory before "
            "tool selection (empty/failed reason calls do not count)")
    if not has_synthesize:
        structural_issues.append(
            "reason.synthesize was not completed successfully with a usable "
            "conclusion — mandatory before writing report (empty responses "
            "with finish_reason=length do not count)")

    # Open investigation tasks — work-queue integrity. An investigation that
    # never dispositions CASE.md requests is not report-ready; the agent must
    # misc.update_investigation_task to answered/partial/blocked as work lands.
    try:
        _task_issue, _task_warning = _task_disposition_for_report(log.case_dir())
        if _task_issue:
            issues.append(_task_issue)
        if _task_warning:
            warnings.append(_task_warning)
    except Exception:
        pass

    # Access stage — SoT only (mount_plan / evidence_access). Do not treat
    # prose "access_failed" findings as clearing this gate.
    try:
        from core.evidence_access import OPEN_STEPS, media_access_summary, media_entries
        _acc_case = log.case_dir()
        if _acc_case:
            _acc = media_access_summary(_acc_case)
            if _acc.get("blocks_exit") and _acc.get("pending_open"):
                _pend = _acc["pending_open"][:5]
                _bits = [
                    f"{p.get('path')} ({p.get('access_stage')}"
                    f"→{p.get('recommended_tool') or 'tsk.mmls'})"
                    for p in _pend
                ]
                structural_issues.append(
                    "Disk media access stage incomplete — "
                    + "; ".join(_bits)
                    + f". Open each: {OPEN_STEPS}; or record access_failed. Do this "
                    "before treating filesystem/EVTX sources as examined or absent. "
                    "Cite Access Stage / mount_plan — do not spawn repeated "
                    "UNCONFIRMED limitation findings as a substitute."
                )
            else:
                _failed = [
                    e for e in media_entries(_acc_case)
                    if e.get("access_stage") == "access_failed"
                ]
                if _failed and not _acc.get("pending_open"):
                    # Terminal failure already on SoT — one Limitations pointer,
                    # not a Collect re-entry demand.
                    _samp = _failed[0]
                    issues.append(
                        "LIMITATION (Access Stage): disk open recorded "
                        f"access_failed for {_samp.get('path')} "
                        f"({(_samp.get('error') or 'see mount_plan')[:120]}). "
                        "Document once in report Limitations — do not re-push "
                        "Collect or add duplicate UNCONFIRMED clones."
                    )
    except Exception:
        pass

    # Coverage ledger — probe floor for HV tabular/EVTX units (not accessibility).
    # Before this, pre_report_check talked about tool sweeps and citation
    # percentages while 63/73 evidence units sat unseen.
    # Reads the same verdict atlas_finish classifies on, so the two gates
    # cannot disagree. The earlier form appended a blocker only when it could
    # list unseen units — an empty ledger produced no list and therefore no
    # blocker, and a run went READY_TO_REPORT:true straight into
    # finish_status=incomplete_coverage.
    try:
        from core.coverage_ledger import exit_block_reason as _led_reason
        _led_case = log.case_dir()
        _led_why = _led_reason(_led_case) if _led_case else ""
        if _led_why:
            from core.coverage_ledger import open_units_read_hint as _led_how
            _how = _led_how(_led_case)
            issues.append(
                "Coverage ledger floor not met — " + _led_why + ". This is the "
                "primary open work: read each unseen unit"
                + (f" ({_how})" if _how else "") + "; "
                "coverage.mark_blocked(path, reason) records a read that failed. "
                "Do NOT run unrelated tools to clear other warnings while "
                "coverage is open."
            )
    except Exception:
        pass  # ledger unavailable → other checks still apply

    latest_synthesize = ""
    latest_synthesize_inputs = ""
    try:
        _pre_case_dir = log.case_dir()
    except Exception:
        _pre_case_dir = None
    _accepted_limits = _analyst_accepted_limitations_note(_pre_case_dir)
    for e in reversed(entries):
        if (e.get("type") == "reason_call"
                and e.get("tool") == "reason_synthesize"
                and e.get("success")
                and (e.get("conclusion") or "").strip()):
            latest_synthesize = e.get("conclusion") or ""
            # Agent often puts "TTPs: not applicable" in the findings payload;
            # the model may drop it from the conclusion.
            # Honor opt-out from either channel.
            raw_in = e.get("inputs")
            if isinstance(raw_in, dict):
                latest_synthesize_inputs = " ".join(
                    str(raw_in.get(k) or "")
                    for k in ("user_message", "findings", "investigation_summary")
                )
            elif isinstance(raw_in, str):
                latest_synthesize_inputs = raw_in
            break
    if latest_synthesize:
        # Escape hatch (a): a blocker the agent has acknowledged as GENUINELY
        # unresolvable WITH a justification is a documented limitation, not a
        # deadlock. Detected in a dedicated UNRESOLVABLE: section or inline.
        synth_acks = _unresolvable_acknowledgments(latest_synthesize)
        m = re.search(
            r"(?:^|\n)\s*BLOCKERS?(?:\s*\([^)]*\))?\s*:\s*(.*?)(?=\n\s*[A-Z][A-Z _-]{2,}(?:\s*\([^)]*\))?\s*:|\Z)",
            latest_synthesize,
            re.IGNORECASE | re.DOTALL,
        )
        synth_blocker_issue = None
        blocker_text = ""
        if m:
            blocker_text = m.group(1).strip()
            # A blocker the previous synthesis already named, still standing
            # after the work done since, is a limitation of the evidence, not
            # a task: it is recorded as such and no longer blocks the report.
            persisted, fresh = _split_persisted_blockers(entries, blocker_text)
            if persisted:
                documented_limitations.extend(persisted)
                warnings.append(
                    "reason.synthesize blocker(s) unchanged after a resolve "
                    "cycle are recorded as documented limitations; state each "
                    "in the report's Limitations section: "
                    + " | ".join(b[:160] for b in persisted)
                )
                blocker_text = "\n".join(fresh)
            # Placeholder / truncated rubric echo ("BLOCKERS: ...", "BLOCKERS:")
            # is not a real punch-list item.
            placeholder = bool(re.fullmatch(
                r"(?:\.{2,}|…|<\w[\w-]*>|-)?\s*",
                blocker_text,
            )) or bool(re.match(
                r"^(?:\.{2,}|…|as needed|from advisories)\b",
                blocker_text,
                re.IGNORECASE,
            ))
            if (blocker_text and not placeholder and not re.fullmatch(
                r"(?:none|no blockers?|n/a|not applicable|0)[.\s-]*",
                blocker_text,
                re.IGNORECASE,
            )):
                # Rung 1 (from main): a blocker the agent has ACKNOWLEDGED as a
                # genuine dead-end with a substantive justification is already a
                # documented limitation — it never reaches the ladder below.
                acks = _unresolvable_acknowledgments(blocker_text) or synth_acks
                if acks:
                    documented_limitations.extend(acks)
                    warnings.append(
                        "reason.synthesize BLOCKERS acknowledged as genuinely "
                        "unresolvable and recorded as documented limitations. "
                        "State each in the report's Limitations section with "
                        "why it caps the affected conclusion's tier: "
                        + " | ".join(a[:160] for a in acks)
                    )
                elif _blocker_verdicts_exhausted():
                    _items = _blocker_items(blocker_text) or [blocker_text]
                    documented_limitations.extend(_items)
                    warnings.append(
                        _REPEAT_BACKSTOP_NOTE.format(
                            n=_BLOCKER_VERDICT_MAX_REPEATS)
                        + " | ".join(b[:160] for b in _items))
                else:
                    synth_blocker_issue = (
                        "Latest reason.synthesize still lists BLOCKERS. Resolve "
                        "them — run the requested tools or record why they are "
                        "inapplicable — then re-run reason.synthesize before "
                        "Report. If a blocker is a GENUINE dead-end (no "
                        "available tool can parse the evidence, the artifact "
                        "was destroyed, a third party is unreachable), state "
                        "'UNRESOLVABLE: <what> — <why it cannot be "
                        "resolved>' in reason.synthesize and re-run it — that "
                        "records it as a documented limitation and clears this "
                        "gate. Do not use the hatch to skip resolvable work."
                    )
        elif _has_unnegated_blocker(latest_synthesize):
            # No canonical "BLOCKERS:" header, but a non-negated "blocker"
            # mention remains in the prose. A negated mention ("no blockers",
            # "free of blockers", "0 blockers") is NOT a blocker and must pass —
            # the old bare-word \bBLOCKER\b check false-positived on those.
            # The same hatch as the header form: a prose blocker the previous
            # synthesis already carried, still standing after tool work in
            # between, is a limitation of the evidence and no longer blocks.
            persisted, fresh = _split_persisted_blockers(
                entries, _blocker_sentences(latest_synthesize))
            if persisted:
                documented_limitations.extend(persisted)
                warnings.append(
                    "reason.synthesize blocker(s) unchanged after a resolve "
                    "cycle are recorded as documented limitations; state each "
                    "in the report's Limitations section: "
                    + " | ".join(b[:160] for b in persisted)
                )
            # Rung 1 (from main), prose variant: same acknowledgment hatch.
            if persisted and not fresh:
                pass
            elif synth_acks:
                documented_limitations.extend(synth_acks)
                warnings.append(
                    "reason.synthesize blocker(s) acknowledged as genuinely "
                    "unresolvable and recorded as documented limitations. "
                    "Carry each into the report's Limitations section: "
                    + " | ".join(a[:160] for a in synth_acks)
                )
            elif _blocker_verdicts_exhausted():
                _items = (_blocker_items(_blocker_sentences(latest_synthesize))
                          or [_blocker_sentences(latest_synthesize)])
                _items = [i for i in _items if i]
                documented_limitations.extend(_items)
                warnings.append(
                    _REPEAT_BACKSTOP_NOTE.format(
                        n=_BLOCKER_VERDICT_MAX_REPEATS)
                    + " | ".join(b[:160] for b in _items))
            else:
                synth_blocker_issue = (
                    "Latest reason.synthesize still labels one or more gaps as "
                    "BLOCKER. Return to Triage/Collect/Analyze as needed, run "
                    "the missing evidence work, then re-run reason.synthesize "
                    "before Report. Do not try to satisfy this by rewording "
                    "findings. If a gap is a GENUINE dead-end, state "
                    "'UNRESOLVABLE: <what> — <why>' in reason.synthesize "
                    "to record it as a documented limitation and clear the gate."
                )
                blocker_text = "\n".join(fresh) if persisted else latest_synthesize

        # Rungs 2 and 3: only reached when the acknowledgment hatch above
        # did NOT fire.
        if synth_blocker_issue:
            # Rung 2) Analyst escape hatch: explicit acceptance file in analysis/
            if _accepted_limits:
                warnings.append(
                    "reason.synthesize listed BLOCKERS, but the analyst accepted "
                    "report limitations via analysis/REPORT_LIMITATIONS_ACCEPTED.md. "
                    "Document those items under Limitations in the report — do not "
                    "hard-block. Accepted note (excerpt): "
                    + _accepted_limits.splitlines()[0][:240]
                )
            # Rung 3) Unresolvable collection gaps (evidence never in the case)
            elif blocker_text and _blocker_text_is_only_collection_gaps(blocker_text):
                warnings.append(
                    "reason.synthesize flagged collection gap(s) as BLOCKER, but "
                    "those artifacts were never provided to the case (tools cannot "
                    "collect them). Downgraded to warning — state as Limitations "
                    "in the report: "
                    + re.sub(r"\s+", " ", blocker_text)[:320]
                )
            else:
                issues.append(synth_blocker_issue)

    # Case-question gate: each question the run was asked in words must be
    # addressed by a CONFIRMED/LIKELY finding. Tracked requests are the task
    # gate's; a question about the case as a whole never blocks.
    _cq_case_dir = None
    _cq_trace = None
    try:
        _cq_case_dir = log.case_dir() or None
        _cq_trace = log.trace_path()
    except Exception:
        _cq_case_dir = None
    _cq_any_belief = any(
        e.get("type") == "finding"
        and (e.get("confidence") or "").upper() in {"CONFIRMED", "LIKELY"}
        for e in entries)
    for case_question, _cq_kind in _case_questions_for_pre_report(
            entries, _cq_case_dir, trace_path=_cq_trace):
        if _cq_kind == "umbrella":
            if not _cq_any_belief:
                warnings.append(
                    f"Nothing recorded at CONFIRMED or LIKELY answers "
                    f"\"{case_question}\". If the examination found nothing, "
                    f"state that negative result, and what was examined, in the report.")
            continue
        _cq_verdict, _cq_missing, _cq_required = _question_coverage(entries, case_question)
        if _cq_verdict == "unjudgeable":
            warnings.append(
                f"Case question \"{case_question}\" has no key word the gate can look "
                f"for in the findings; answer it explicitly in the report.")
        elif _cq_verdict == "unaddressed":
            issues.append(
                f"Case question \"{case_question}\" is not directly addressed by "
                f"any CONFIRMED or LIKELY finding: no finding names {_cq_required} of "
                f"its key words ({', '.join(_cq_missing[:6])}). Record a finding whose "
                f"description answers the question, naming what it asks about, "
                f"before transitioning to Report."
            )

    if evaluate_calls < confirmed_findings:
        warnings.append(
            f"{confirmed_findings} CONFIRMED finding(s) but only {evaluate_calls} "
            "reason.evaluate_finding call(s) — each CONFIRMED finding requires evaluation"
        )
    if not has_hypothesize:
        warnings.append(
            "reason.hypothesize was never called — required for any unusual artifact, "
            "orphaned process, or unexpected network connection"
        )

    # ── coverage & finding-tier gates ────────────────────────────────────────
    # Learned from cross-case run reviews (several cases): every
    # run left TTP coverage at 0/0 because coverage.coverage_report — though DAIR
    # recommends it every run — was never executed, and evidence-backed findings
    # were systematically left at LIKELY because they were never adversarially
    # evaluated. Both are cheap, mechanical steps; enforce them so the pattern
    # does not recur.
    ran_coverage = any(
        e["type"] == "tool_call" and "coverage_report" in str(e.get("cmd") or "")
        for e in entries
    )
    if not ran_coverage:
        # Advisory only: ATT&CK coverage is useful but must never block a
        # deliverable whose priority is timeline + analysis. Missing coverage_report used to hard-block Report.
        warnings.append(
            "coverage.coverage_report was never executed. Run it when useful "
            "so findings can map to MITRE ATT&CK — it returns cleanly even for "
            "cases with no TTPs. Do not delay the report solely for this."
        )

    # Report-readiness grounding gates. Both escalate a record-time advisory
    # the run may have ignored; both are bounded and satisfiable (record,
    # re-cite, or lower a finding), and both respect the accepted-limitations
    # hatch so a genuine dead-end never loops. One env flag disables the pair.
    _flagged_lineage: list[int] = []
    if not _accepted_limits and (os.environ.get("ATLAS_REPORT_READINESS_GATES")
                                 or "1").strip().lower() not in ("0", "false", "no", "off"):
        # (1) Indicators the evidence keeps showing that no finding names.
        # Blocking only while the demand is bounded: a population the
        # evidence shows in bulk is mentioned by count, because ruling on
        # its members one by one never empties it (core.ioc_pivots).
        try:
            from core.ioc_pivots import (describe_unrecorded_bulk,
                                         unrecorded_demand,
                                         unrecorded_evidence_indicators)
            _demand, _bulk = unrecorded_demand(
                unrecorded_evidence_indicators(entries, _case_dir))
        except Exception:  # noqa: BLE001
            _demand, _bulk = [], []
        if _demand:
            issues.append(
                "Indicators recur across the evidence but no finding names them: "
                # Named in a fixed order and without their call counts, which
                # grow with every read: the blocker's text changes only when
                # the indicators it names change.
                + "; ".join(f"{d['value']} ({d['kind']})" for d in sorted(
                    _demand, key=lambda d: (str(d['kind']), str(d['value']))))
                + ". Record a finding naming each — one finding may cover "
                "several, and a SUSPECTED finding that rules them benign counts "
                "— or accept them in analysis/REPORT_LIMITATIONS_ACCEPTED.md. "
                "Do not report while high-signal indicators are unrecorded."
            )
        if _bulk:
            warnings.append(
                "Indicators recur across the evidence in bulk and no finding "
                "names them; not demanded one by one because the population "
                "outruns any list of rulings: " + describe_unrecorded_bulk(_bulk)
                + ". Record any that bear on a conclusion; the report may "
                "proceed without a ruling on each."
            )
        # (2) Findings whose cited calls do not contain their own identifiers.
        # A finding already at the floor tier is what the gate's own remedy
        # produces ("or lower the finding"): the report says no more than the
        # citation shows, so it is a limitation to state, not a blocker. The
        # tier read here is the claim's current one, so a finding the gate
        # lowered on an earlier pass is seen lowered on this one.
        _miscited_all = _miscited_finding_entries(finding_entries, entries)
        _miscited_floor = [f for f in _miscited_all
                           if (f.get("confidence") or "").upper() == "UNCONFIRMED"]
        _miscited_entries = [f for f in _miscited_all if f not in _miscited_floor]
        if _miscited_floor:
            _floor_desc = [str(f.get("description") or "")[:80] for f in _miscited_floor]
            warnings.append(
                "UNCONFIRMED finding(s) whose cited calls carry none of the "
                "identifiers they rest on: " + " | ".join(_floor_desc)
                + ". Already at the floor tier; state in the report's "
                "Limitations section that the citation does not show the value, "
                "or withdraw the claim (claim.supersede with no new_id).")
            documented_limitations.extend(_floor_desc)
        # Each finding is followed back through its re-records to the first
        # one, and the check stores the roots it flagged on its own trace
        # entry. A root flagged by this check and the ones right before it,
        # _BLOCKER_VERDICT_MAX_REPEATS checks in all, is lowered: counted per
        # finding, so a repair loop that changes the rest of the verdict on
        # every pass still reaches the remedy.
        _by_cid = {int(e.get("call_id") or 0): e for e in all_finding_entries}
        _roots = [_finding_lineage_root(f, _by_cid) for f in _miscited_entries]
        _flagged_lineage = sorted(set(_roots))
        _streaks = _miscited_streaks(trace, _flagged_lineage)
        _due = [f for f, root in zip(_miscited_entries, _roots)
                if 0 < _BLOCKER_VERDICT_MAX_REPEATS <= _streaks[root] + 1]
        _moved = ([f for f in _due if _lower_miscited_findings([f], _case_dir)]
                  if apply_remedies else [])
        _still = [f for f in _miscited_entries if f not in _moved]
        if _moved:
            _lowered = [str(f.get("description") or "")[:80] for f in _moved]
            warnings.append(
                "Finding(s) whose cited calls carry none of the identifiers "
                "they rest on were lowered to UNCONFIRMED after the gate "
                f"flagged each in {_BLOCKER_VERDICT_MAX_REPEATS} report checks "
                "in a row: " + " | ".join(_lowered)
                + ". State in the report's Limitations section that the "
                "citation does not support the original tier.")
            documented_limitations.extend(_lowered)
        if _still:
            issues.append(_citation_blocker(_still))
            warnings.append(_citation_repair_hint(_still, entries))

    mitre_findings = finding_entries
    if len(finding_entries) < len(all_finding_entries):
        warnings.append(
            f"{len(all_finding_entries) - len(finding_entries)} finding(s) "
            "excluded from every report gate because their claim-graph status "
            "is superseded or withdrawn (immutable trace entries remain for "
            "audit)."
        )

    # tool_coverage / evidence_coverage are no longer auto-nagged here.
    # They competed with coverage_ledger + DAIR work-orders as a fourth
    # "what was missed" voice and pushed junk tool runs. MCP tools remain:
    # coverage.audit_tool_coverage / coverage.audit_evidence_coverage — use
    # on demand. Ledger units are the progress authority.

    # Midnight-placeholder lint (advisory only). Parsers emit T00:00:00 for
    # date-only fields; a finding quoting one as an event time is usually
    # citing a placeholder, not a real 00:00:00 UTC event. Mulder auto-nulls
    # these — Atlas only warns, because event times live in prose here and a
    # genuine midnight event must stay quotable.
    _midnight = [
        e for e in finding_entries
        if (e.get("confidence") or "").upper() in ("CONFIRMED", "LIKELY")
        and re.search(r"[T ]00:00:00", str(e.get("description") or ""))
    ]
    if _midnight:
        warnings.append(
            f"{len(_midnight)} CONFIRMED/LIKELY finding(s) quote a T00:00:00 "
            "timestamp — often a date-only parser placeholder, not a real "
            "midnight event. Verify each against the source artifact (MFT/"
            "registry timestamps carry full precision) or state the time as "
            "date-only."
        )

    # Multi-host estate-synthesis check (advisory). When substantiated findings
    # span several hosts, the deliverable is two-level: per-host reports plus
    # an estate report whose synthesis carries a per-host disposition and the
    # cross-host narrative. A single-host-flavoured report on an estate-wide
    # incident misses that picture.
    _mh_hosts = sorted({
        e.get("host") for e in finding_entries
        if e.get("host") and (e.get("confidence") or "").upper()
        in ("CONFIRMED", "LIKELY")
    })
    # Response plan check (advisory): the report's Recommendations section is
    # a projection of recorded recommendations, so a run that recorded none
    # would ship an empty plan.
    try:
        from core.recommendations import report_readiness_advisories
        warnings.extend(report_readiness_advisories(
            _case_dir, _mh_hosts,
            sum(1 for e in finding_entries
                if (e.get("confidence") or "").upper() in ("CONFIRMED", "LIKELY"))))
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Indicator completeness (advisory): a finding that describes initial
    # access, persistence, C2, exfiltration or credential access without a
    # typed indicator leaves the indicator list and the plan short.
    try:
        from core.indicators import report_warning
        _iw = report_warning(_case_dir, finding_entries)
        if _iw:
            warnings.append(_iw)
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Refused indicator rows (advisory, never a blocker): a typed value the
    # record refused is in no indicator list; the reader sees it under
    # "Not exported", the analyst may re-type it from the cited output.
    try:
        from core.indicators import dropped_warning
        _dw = dropped_warning(_case_dir)
        if _dw:
            warnings.append(_dw)
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Response coverage (advisory): a substantiated finding of those kinds
    # needs a recommendation resting on it.
    try:
        from core.recommendations import coverage_warning
        _cw = coverage_warning(_case_dir)
        if _cw:
            warnings.append(_cw)
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Steps whose basis was withdrawn (advisory): the report holds them back.
    try:
        from core.recommendations import basis_lost_warning
        _bl = basis_lost_warning(_case_dir)
        if _bl:
            warnings.append(_bl)
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Standing duplicates (advisory, never a blocker): a claim that restates
    # or refines an older one on the same host is one finding twice in the
    # report; name the pairs so one can be superseded, or both kept as
    # different facts.
    try:
        from core.claim_graph import load_graph
        from tools.misc import standing_duplicate_pairs
        _pairs = standing_duplicate_pairs(load_graph(_case_dir).get("nodes") or {})
        if _pairs:
            _lines = []
            for _p in _pairs:
                if _p["relation"] == "restates":
                    _lines.append(f"{_p['newer']} restates {_p['older']} in other words: "
                                  f"supersede one by the other")
                elif _p["relation"] == "elaborates":
                    _lines.append(f"{_p['newer']} restates {_p['older']} at more length: "
                                  f"supersede one by the other")
                else:
                    _adds = ", ".join(a.split(":", 1)[-1] for a in _p["adds"])
                    _lines.append(f"{_p['newer']} refines {_p['older']}"
                                  + (f" (adds {_adds})" if _adds else "")
                                  + f": supersede {_p['older']} by {_p['newer']} if it replaces it")
            warnings.append(
                "Standing duplicates, one finding twice in the report: " + "; ".join(_lines)
                + " (claim.supersede). Keep both where they are different facts.")
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Standing contradictions (advisory, never a blocker): two standing
    # claims that say opposite things about the same words both reach the
    # report unless the conflict is recorded or the wrong one superseded.
    try:
        from core.claim_graph import load_graph
        from tools.misc import standing_contradictions_warning
        _opp = standing_contradictions_warning(load_graph(_case_dir).get("nodes") or {})
        if _opp:
            warnings.append(_opp)
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Examination follow-ups (advisory): on a device examined after the
    # fact, the findings that name a third party's records need the
    # investigative step they open, ahead of hardening lessons.
    try:
        from core.recommendations import followup_warning
        _fw = followup_warning(_case_dir)
        if _fw:
            warnings.append(_fw)
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Threat context (advisory; a blocker with ATLAS_INTEL_ANCHOR_BLOCK=1):
    # when the operator supplied indicators, at least one substantiated
    # finding stands on evidence found without them.
    try:
        from core.threat_context import anchoring_note
        _an = anchoring_note(_case_dir)
        if _an:
            (issues if os.environ.get("ATLAS_INTEL_ANCHOR_BLOCK") == "1" else warnings).append(_an)
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # Delivered evidence (advisory): an item no call has read is named
    # before the report says what the evidence showed; the report lists
    # every item with its status either way.
    try:
        from core.evidence_items import unseen as _unseen_items
        _ui = _unseen_items(_case_dir, limit=9)
        if _ui:
            warnings.append(
                "Delivered evidence no call has read: " + ", ".join(_ui[:8])
                + (" and more" if len(_ui) > 8 else "")
                + ". Read each with an applicable tool, or record a failed attempt "
                "with coverage.mark_blocked (path, reason). The report's evidence "
                "coverage table lists it as not examined otherwise.")
    except Exception:  # noqa: BLE001 — advisory only
        pass
    # A brief that states an engagement Atlas does not know is read as an
    # incident; the operator is told rather than left to find out.
    try:
        from core.case_config import unrecognized_engagement, unrecognized_system_owner
        _eng = unrecognized_engagement(_case_dir)
        if _eng:
            warnings.append(_eng)
        _own = unrecognized_system_owner(_case_dir)
        if _own:
            warnings.append(_own)
    except Exception:  # noqa: BLE001 — advisory only
        pass
    if len(_mh_hosts) >= 2 and not re.search(
            r"per-host|disposition|estate|cross-host",
            latest_synthesize, re.IGNORECASE):
        warnings.append(
            f"Findings span {len(_mh_hosts)} hosts ({', '.join(_mh_hosts[:6])}) "
            "but the latest reason.synthesize has no estate-level structure. "
            "Synthesize a per-host disposition (host → status → basis) and the "
            "cross-host narrative (who moved where, when, with what "
            "privileges), then write one per-host report per system with "
            "findings plus the estate report as the primary deliverable."
        )

    # MITRE-mapping checks — advisory only (never block Report).
    # Timeline, analysis quality, and evidence-backed findings outrank ATT&CK
    # labelling. A blocking gate here would deadlock a case that has solid
    # findings but unsupported T-IDs, leaving no report. Keep the
    # nudges so mapping still improves when cheap; never refuse the write.
    ttp_opted_out = bool(
        TTP_OPTOUT_RE.search(latest_synthesize)
        or TTP_OPTOUT_RE.search(latest_synthesize_inputs)
    )
    attack_findings = [f for f in mitre_findings if is_attack_finding(f)]
    unmapped_attack = [f for f in attack_findings
                       if not finding_carries_technique(f)]
    mapped_attack = [f for f in attack_findings
                     if finding_carries_technique(f)]

    attack_gate_fired = False
    if unmapped_attack and not ttp_opted_out:
        cids = ", ".join(f"#{f.get('call_id')}" for f in unmapped_attack[:8])
        remedy = (
            "Optional: run correlate.mitre_map / mitre_validate, then record "
            "each finding again with mitre_techniques= and supersedes=<its "
            "call id>, which replaces it; without supersedes= the re-record "
            "stands beside it as a second finding. Or state 'TTPs: not "
            "applicable — <reason>' in reason.synthesize. Do not delay the "
            "report for ATT&CK labelling alone.")
        attack_gate_fired = len(unmapped_attack) > TTP_UNMAPPED_BLOCK
        warnings.append(
            f"{len(unmapped_attack)} of {len(attack_findings)} "
            f"CONFIRMED/LIKELY finding(s) describing attack activity "
            f"carry no MITRE technique (finding call_ids: {cids}). "
            + remedy)

    # Breadth check — advisory only, never blocks: a case-blind gate cannot
    # demand techniques the evidence doesn't support (same overclaim-
    # avoidance stance as the under-tier gate below). Fires when the run has
    # several mapped attack findings but they cluster on very few techniques
    # or tactics — the signature of minimum-compliance mapping.
    if len(attack_findings) >= 5 and mapped_attack:
        distinct_tids: set[str] = set()
        distinct_tactics: set[str] = set()
        for f in mapped_attack:
            distinct_tids |= finding_technique_ids(f)
            distinct_tactics |= finding_tactics(f)
        want_tids = min(TTP_MIN_TECHNIQUES, len(attack_findings))
        if (len(distinct_tids) < want_tids
                or len(distinct_tactics) < TTP_MIN_TACTICS):
            warnings.append(
                f"Findings map to only {len(distinct_tids)} distinct "
                f"technique(s) across {len(distinct_tactics)} tactic(s) "
                f"(breadth target for {len(attack_findings)} attack "
                f"findings: ≥{want_tids} techniques / ≥{TTP_MIN_TACTICS} "
                f"tactics). Sweep tactics that have evidence but no mapped "
                f"technique — coverage.coverage_report's finding_mapping/"
                f"targets fields show the live status."
            )

    # Anti-spam: valid-but-irrelevant techniques pasted on every finding.
    # Advisory only — never blocks the report write.
    vt_entries = [vt for f in mapped_attack
                  for vt in (f.get("validated_techniques") or [])
                  if isinstance(vt, dict)]
    if (vt_entries and not ttp_opted_out
            and all(vt.get("relevance") == "unsupported"
                    for vt in vt_entries)):
        warnings.append(
            f"All {len(vt_entries)} MITRE technique(s) attached to attack "
            "findings are unsupported by their finding's own description "
            "(correlate.mitre_map found no textual basis). Remap when cheap; "
            "do not hold the report for ATT&CK labelling."
        )
    if len(mapped_attack) >= 4:
        tid_counts: dict[str, int] = {}
        for f in mapped_attack:
            for tid in finding_technique_ids(f):
                tid_counts[tid] = tid_counts.get(tid, 0) + 1
        for tid, n in sorted(tid_counts.items(), key=lambda kv: -kv[1])[:1]:
            if n >= 0.8 * len(mapped_attack):
                warnings.append(
                    f"{tid} is stamped on {n} of {len(mapped_attack)} mapped "
                    "attack findings — copy-pasting one technique across the "
                    "run is not mapping. Re-check each finding's technique "
                    "against its own evidence with correlate.mitre_map."
                )

    # Structural TTP nudge (advisory). Missing ATT&CK labels must not block
    # a report whose value is timeline + analysis.
    confirmed_entries = [
        f for f in mitre_findings
        if (f.get("confidence") or "").upper() == "CONFIRMED"
    ]
    if (not attack_gate_fired
            and len(confirmed_entries) >= 3
            and not any(finding_carries_technique(f) for f in mitre_findings)
            and not ttp_opted_out):
        warnings.append(
            f"{len(confirmed_entries)} CONFIRMED finding(s) but none carries a "
            "MITRE technique — TTP coverage would report 0 mapped techniques. "
            "Optional: map with correlate.mitre_map or state 'TTPs: not "
            "applicable — <reason>' in reason.synthesize. Prefer shipping "
            "the timeline/analysis over delaying for ATT&CK labels."
        )

    def _has_lineage(f: dict) -> bool:
        return bool(f.get("input_call_ids")) or int(f.get("linked_call_id") or 0) > 0

    likely_cited = [
        f for f in finding_entries
        if (f.get("confidence") or "").upper() == "LIKELY" and _has_lineage(f)
    ]
    # Under-tier gate. Warning-only is toothless: a run can ship 0
    # CONFIRMED despite direct evidence and ignore the nudge. Blocking must not force overclaiming, so it only fires when the
    # LIKELY findings were never adversarially evaluated — evaluating ≥2 and
    # standing by LIKELY is a judgment call and passes with a warning.
    if confirmed_findings == 0 and len(likely_cited) >= 2 and evaluate_calls < 2:
        issues.append(
            f"0 CONFIRMED findings, {len(likely_cited)} LIKELY finding(s) with "
            f"direct evidence lineage, and only {evaluate_calls} "
            "reason.evaluate_finding call(s). Adversarially evaluate at least "
            "your two strongest LIKELY findings before Report: promote to "
            "CONFIRMED where evaluation returns SUPPORTED with a citation, or "
            "keep LIKELY where it does not — either resolves this gate."
        )
    elif finding_entries and evaluate_calls == 0:
        warnings.append(
            f"{len(finding_entries)} finding(s) recorded but reason.evaluate_finding "
            "was never called. Adversarially evaluate your strongest, evidence-backed "
            "findings before Report — an unevaluated run systematically under-tiers "
            "(findings stuck at LIKELY/SUSPECTED when direct evidence would support "
            "CONFIRMED)."
        )
    elif confirmed_findings == 0 and len(likely_cited) >= 2:
        warnings.append(
            f"0 CONFIRMED findings despite {len(likely_cited)} LIKELY finding(s) with "
            "direct evidence lineage. Evaluations exist, so this is advisory: "
            "confirm LIKELY is genuinely the right tier for each, or re-evaluate "
            "for CONFIRMED promotion (requires SUPPORTED with a citation)."
        )

    # Overclaim (capability-vs-act) check. The gates above only police
    # under-tiering: a finding that a cloud sync client was installed and
    # configured can go out as CONFIRMED with T1567.002 attached, although
    # only the installation is proven and not the exfiltration act.
    # Heuristic: a CONFIRMED finding whose description shows only
    # capability vocabulary (installed/configured/account bound), no act
    # vocabulary, yet carries an exfiltration-class technique, is tiering the
    # act on capability evidence.
    #
    # Whether this blocks or merely warns turns on ONE thing: did an
    # evidence-aware reviewer ever adversarially challenge THIS finding? The
    # heuristic itself is description-only and cannot see the cited evidence, so
    # it must not block on its own. But reason.evaluate_finding CAN see the
    # evidence, and its CAPABILITY VS ACT rule refuses overclaims — so if a
    # SUPPORTED evaluate_finding actually reviewed this finding, we defer to that
    # (warning only). The dangerous case is the overclaim that was NEVER
    # individually evaluated: at record time it passed confirmed_requires_
    # supported_evaluate on the *most-recent fallback* (borrowing a different
    # finding's SUPPORTED verdict), so nothing evidence-aware ever vetted it.
    # That combination — overclaim shape + no description-matched SUPPORTED
    # evaluation — blocks.
    from tools._gates._match import normalize_desc

    def _supported_eval_reviewed(desc: str) -> bool:
        """True when a reason_evaluate_finding entry that echoes THIS finding's
        description returned VERDICT: SUPPORTED. Mirrors the record-time
        confirmed_requires_supported_evaluate matcher (normalized 60-char prefix
        substring in the eval's inputs.user_message), so the report-boundary
        backstop agrees with what the record gate actually verified and fires
        exactly when that gate had to fall back to an unrelated verdict."""
        norm = normalize_desc(desc)
        if not norm:
            return False
        for e in entries:
            if (e.get("type") != "reason_call"
                    or e.get("tool") != "reason_evaluate_finding"):
                continue
            user_msg = ((e.get("inputs") or {}).get("user_message") or "").lower()
            if norm not in user_msg:
                continue
            vm = re.search(
                r"VERDICT\W{0,12}(SUPPORTED|CHALLENGED|UNCERTAIN)",
                e.get("conclusion", "") or "", re.IGNORECASE,
            )
            if vm and vm.group(1).upper() == "SUPPORTED":
                return True
        return False

    _capability_re = re.compile(
        r"\b(?:install(?:ed|ation)|configur(?:ed|ation)|"
        r"account (?:was )?(?:bound|configured|added|linked)|registered)\b",
        re.IGNORECASE,
    )
    _act_re = re.compile(
        r"\b(?:exfiltrat\w+|upload(?:ed|s)?|transferr\w+|synced|sync log|"
        r"sent|leaked|copied (?:to|out|onto)|burned|wrote|written to)\b",
        re.IGNORECASE,
    )
    _exfil_tid_re = re.compile(r"\bT1(?:020|029|030|041|048|052|537|567)(?:\.\d{3})?\b")
    for f in confirmed_entries:
        desc = f.get("description") or ""
        # validated_techniques entries are dicts ({technique_id, name,
        # tactic}) in the trace; joining them raw raises TypeError, which
        # would crash pre_report_check at wrap-up and cost the final report.
        tid_scope = desc + " " + " ".join(
            t.get("technique_id", "") if isinstance(t, dict) else str(t)
            for t in (f.get("validated_techniques") or [])
        )
        if (_capability_re.search(desc)
                and not _act_re.search(desc)
                and _exfil_tid_re.search(tid_scope)):
            if _supported_eval_reviewed(desc):
                # An evidence-aware reviewer explicitly challenged this finding
                # and returned SUPPORTED — defer to that judgment, warn only.
                warnings.append(
                    f"CONFIRMED finding '{desc[:90]}…' describes installation/"
                    "configuration but carries an exfiltration technique — "
                    "capability evidence proves the channel existed, not that "
                    "data moved through it. A SUPPORTED reason.evaluate_finding "
                    "reviewed it, so this is advisory: confirm the cited evidence "
                    "includes an act artifact (transfer log, sync journal, "
                    "written-file timestamps), or record the exfiltration act as "
                    "a separate LIKELY finding."
                )
            else:
                # Overclaim shape and no evidence-aware review of THIS finding:
                # it was tiered CONFIRMED on capability (installation) evidence
                # alone. Block.
                issues.append(
                    f"CONFIRMED finding '{desc[:90]}…' asserts an exfiltration "
                    "technique but its description shows only installation/"
                    "configuration — capability evidence alone, and no "
                    "reason.evaluate_finding adversarially reviewed THIS finding "
                    "and returned SUPPORTED. It rode the confirmed-requires-"
                    "evaluate gate's fallback on another finding's verdict. "
                    "Either downgrade this finding to LIKELY, or run "
                    "reason.evaluate_finding on it and cite an act artifact "
                    "(transfer log, sync journal, uploaded-file timestamps) that "
                    "proves data moved through the channel, then record it "
                    f"again CONFIRMED with supersedes={f.get('call_id')}, which "
                    "replaces this record."
                )

    # Cross-host correlation gate (warning, not blocking). When findings span
    # multiple hosts but no correlate.process_to_file / correlate.network_to_process
    # call was made, per-host findings will land in synthesis as isolated slices
    # rather than a coherent cross-host timeline. Warning-level keeps single-host
    # cases unaffected and lets the agent recover by running the missing call.
    try:
        from tools.dair import _extract_host_tokens
        finding_hosts: set[str] = set()
        for e in entries:
            if e.get("type") == "finding":
                finding_hosts |= _extract_host_tokens(e.get("description") or "")
            elif e.get("type") == "dair_call":
                finding_hosts |= _extract_host_tokens(
                    e.get("investigation_focus") or "")
        if len(finding_hosts) >= 2:
            has_correlate = any(
                e.get("type") == "tool_call"
                and isinstance(e.get("cmd"), str)
                and (
                    "correlate_process_to_file" in e["cmd"]
                    or "correlate_network_to_process" in e["cmd"]
                )
                for e in entries
            )
            if not has_correlate:
                hosts_str = ", ".join(sorted(finding_hosts)[:5])
                warnings.append(
                    f"Findings span {len(finding_hosts)} hosts ({hosts_str}"
                    f"{'…' if len(finding_hosts) > 5 else ''}) but no "
                    f"correlate.process_to_file or correlate.network_to_process "
                    f"call was made. Call them (with no PID/IP/path filter) "
                    f"before reason.synthesize so the timeline reflects "
                    f"cross-host joins, not isolated per-host slices."
                )
    except Exception as _e:
        import sys as _sys
        print(f"[Atlas WARN] cross-host correlation check failed: {_e}",
              file=_sys.stderr)

    # Unrecorded-findings audit: model-based scan of narrations vs. structured
    # finding entries. Surfaces facts the agent wrote in chat but never
    # promoted via misc.record_finding.
    audit_summary: dict = {}
    try:
        audit = reason_audit_findings()
        audit_summary = audit.get("summary", {}) or {}
        n = int(audit_summary.get("candidate_count") or 0)
        if n > 0:
            cands = audit.get("candidates", [])[:5]
            cids = ", ".join(f"#{c.get('narration_call_id')}" for c in cands)
            warnings.append(
                f"{n} narration(s) appear to contain factual claims that aren't "
                f"recorded as structured `finding` entries (first 5: {cids}). "
                f"Record a finding ONLY where the narration states an "
                f"evidence-backed fact about the case (an event, account, "
                f"file, connection). Meta-statements about the process "
                f"('tool X produced no unique findings', 'parse completed') "
                f"are NOT findings — never record those; ignore this warning "
                f"for them."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[Atlas WARN] audit_findings failed: {_e}", file=_sys.stderr)

    # ── Structural-integrity checks (generic) ───────────────────────────────
    # Catch the loose ends that let a verdict ship structurally wrong even when
    # every individual finding passed its record-time gates:
    #   #1 (blocking) a created/covert account whose controller was never
    #       established and was never parked as controller-unknown;
    #   #2 (warning) multiple un-ranked exfil channels;
    #   #3 (warning) a named recipient with no evident roster cross-reference.
    # #2/#3 are warnings because finding entries retain only the description,
    # not the supporting_evidence the record-time gates inspect — so channel /
    # recipient grounding cannot be soundly re-derived at report scope. #1 is
    # blocking: a named account with no controller binding is detectable from
    # descriptions alone and is the structural gap most likely to invert a case.
    try:
        from tools.dair import _extract_principal_tokens
        from tools._gates.principal_attribution_grounding import _SESSION_RE
        from tools._gates.exfil_channel_grounding import _EGRESS_RE, _CHANNEL_RE

        s_findings = [e for e in entries if e.get("type") == "finding"]

        def _ftier(e):
            return (e.get("confidence") or "").upper()

        # #1 — created/covert accounts named in CONFIRMED/LIKELY findings.
        # RID/SID tokens are excluded: they don't match reliably across prose
        # ("RID 1006" vs token "RID1006"); named accounts are trackable.
        created_principals = {
            p
            for e in s_findings if _ftier(e) in {"CONFIRMED", "LIKELY"}
            for p in _extract_principal_tokens(e.get("description") or "",
                                               require_cue=True)
            if not p.startswith("RID") and not p.startswith("S-1-")
        }
        for p in sorted(created_principals):
            established = False
            parked = False
            for e in s_findings:
                desc = e.get("description") or ""
                if p.lower() not in desc.lower():
                    continue
                if _ftier(e) in {"CONFIRMED", "LIKELY"} and _SESSION_RE.search(desc):
                    established = True
                    break
                if re.search(
                    r"(?:controll?er|who controls)[^.\n]*"
                    r"\b(?:unknown|unidentified|not established|unestablished)\b"
                    r"|\bunattributed\b",
                    desc, re.IGNORECASE,
                ):
                    parked = True
            if not established and not parked:
                issues.append(
                    f"Created/covert account '{p}' is named in a CONFIRMED/LIKELY "
                    f"finding but no finding establishes who controls it (no "
                    f"logon/session/source binding) and none parks it as "
                    f"controller-unknown. Pull the authentication artifact "
                    f"(Security 4624/4625 logon type + source address) and "
                    f"attribute it, or record an UNCONFIRMED 'controller unknown' "
                    f"finding before Report."
                )

        # #2 — multiple distinct exfil channel *families* in CONFIRMED/LIKELY
        # findings. Synonyms collapse to a family so "cloud via Dropbox" counts
        # once, not twice.
        def _channel_family(token: str) -> str:
            t = token.lower()
            if t in {"dropbox", "onedrive", "gdrive", "google drive", "mega", "box.com", "cloud"}:
                return "cloud"
            if t in {"ftp", "sftp", "tftp"}:
                return "ftp"
            if t in {"usb", "removable", "thumb drive", "flash drive"}:
                return "usb/removable"
            if t in {"email", "e-mail", "webmail", "smtp", "attachment"}:
                return "email"
            if t in {"web upload", "http upload"}:
                return "web upload"
            if t in {"c2", "telegram"}:
                return "c2/messenger"
            return t

        channels: set[str] = set()
        for e in s_findings:
            if _ftier(e) not in {"CONFIRMED", "LIKELY"}:
                continue
            desc = e.get("description") or ""
            if _EGRESS_RE.search(desc):
                channels |= {_channel_family(m.group(0)) for m in _CHANNEL_RE.finditer(desc)}
        if len(channels) >= 2:
            warnings.append(
                f"{len(channels)} distinct exfiltration channels appear in "
                f"CONFIRMED/LIKELY findings ({', '.join(sorted(channels))}). "
                f"Enumerate ALL candidate channels and ensure the verdict "
                f"headlines the strongest-evidenced one — a transfer artifact "
                f"beats tool/folder presence; do not over-weight a channel that "
                f"lacks a transfer record."
            )

        # #3 — a recipient named in a CONFIRMED/LIKELY exfil finding with no
        # evident roster cross-reference anywhere in the trace.
        recipient_findings = [
            e for e in s_findings
            if _ftier(e) in {"CONFIRMED", "LIKELY"}
            and _EGRESS_RE.search(e.get("description") or "")
            and re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+|\brecipient\b|\bbuyer\b|\bsent to\b",
                          e.get("description") or "", re.IGNORECASE)
        ]
        if recipient_findings:
            xref_seen = any(
                isinstance(e.get(f), str) and re.search(
                    r"roster|cross-referenc|suspect list|not on (?:the )?roster"
                    r"|knowns_pattern_generate|user directory",
                    e.get(f), re.IGNORECASE,
                )
                for e in entries
                for f in ("description", "content", "cmd", "conclusion")
            )
            if not xref_seen:
                warnings.append(
                    f"{len(recipient_findings)} exfil/dissemination finding(s) name "
                    f"a recipient but no roster / suspect-list cross-reference is "
                    f"evident in the trace. Inventory all correspondents and "
                    f"cross-reference the named recipient against the case roster "
                    f"(or note explicitly it is not on the roster) before Report."
                )

        # #4 — per-hypothesis exhaustion. reason_hypothesize returns N ranked
        # alternatives under ONE id; Part 1 split them into sub_hypotheses with
        # the principal entities each contests. EVERY contested principal at
        # MEDIUM+ likelihood must be driven to a verdict before Report — its
        # controller established (a CONFIRMED/LIKELY finding naming it WITH a
        # session/identity binding) or the alternative refuted. "Controller
        # unknown"/parked does NOT count (the single-actor lock-in dodge: a
        # second-principal alternative and the prime-subject hypothesis both
        # left unresolved while shipping a sole-actor verdict). When no
        # sub_hypotheses were parsed, fall back to the per-call-id ledger.
        idx = log.index()
        _distinct_principal_re = re.compile(
            r"(?:second (?:actor|principal|operator|user)\b|distinct principal\b"
            r"|who controls\b|another (?:account|user|person)\b|separate principal\b"
            r"|controller (?:of|unknown|unestablished)\b|who authenticated\b"
            r"|different (?:actor|operator)\b|\brdp\b|logon type\s*(?:2|10)\b)",
            re.IGNORECASE,
        )
        _refute_re = re.compile(
            r"\b(?:refuted|ruled out|disproven|false positive|rejected|not supported"
            r"|excluded|cannot be (?:attributed|established|determined)|unproven"
            r"|indeterminate|no identif\w+ artifact)\b", re.IGNORECASE,
        )
        all_subs = [
            s for e in entries
            if e.get("type") == "reason_call" and e.get("tool") == "reason_hypothesize"
            for s in (e.get("sub_hypotheses") or [])
        ]
        if all_subs:
            _rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
            ent_tier: dict[str, str] = {}
            ent_labels: dict[str, set] = {}
            for s in all_subs:
                t = s.get("likelihood_tier", "MEDIUM")
                for ent in s.get("entities") or []:
                    if _rank.get(t, 1) >= _rank.get(ent_tier.get(ent, "LOW"), 0):
                        ent_tier[ent] = t
                    ent_labels.setdefault(ent, set()).add(s.get("label") or "?")

            def _entity_terminal(ent: str) -> bool:
                el = ent.lower()
                _park_re = re.compile(
                    r"controller\s+unknown|evidence\s+unavailable|"
                    r"cannot\s+determine\s+(?:who|the\s+controller)|"
                    r"controller\s+(?:unestablished|not\s+established)",
                    re.IGNORECASE,
                )
                for fe in s_findings:
                    d = fe.get("description") or ""
                    if el not in d.lower():
                        continue
                    if _ftier(fe) in {"CONFIRMED", "LIKELY"} and _SESSION_RE.search(d):
                        return True   # controller established
                    if _refute_re.search(d):
                        return True   # refuted / honestly exhausted
                    # Explicit park (aligned with fallback path + #1/#6):
                    # UNCONFIRMED + controller-unknown / evidence-unavailable.
                    if _ftier(fe) == "UNCONFIRMED" and _park_re.search(d):
                        return True
                return False

            for ent in sorted(ent_tier):
                if _entity_terminal(ent):
                    continue
                labels = ", ".join(sorted(ent_labels.get(ent, set())))
                tier = ent_tier[ent]
                msg = (
                    f"Contested principal '{ent}' (raised as hypothesis {labels}, "
                    f"likelihood {tier}) was never driven to a verdict: no "
                    f"CONFIRMED/LIKELY finding establishes its controller with a "
                    f"session/identity binding (logon 4624/4625 + type/source, "
                    f"OneDrive/registry account binding, USB serials), no "
                    f"finding refutes the alternative, and no UNCONFIRMED "
                    f"'controller unknown'/'evidence unavailable' disposition "
                    f"parks it. Resolve it (run the discriminators), refute it, "
                    f"or record an explicit park before Report."
                )
                if _rank.get(tier, 1) >= 1:   # MEDIUM / HIGH
                    issues.append(msg)
                else:                          # LOW
                    warnings.append(msg)
        else:
            # Fallback (no sub_hypotheses parsed): per-call-id resolution ledger.
            resolved_ids: set[str] = set()
            for e in s_findings:
                tid = (e.get("tested_hypothesis_id") or "").strip()
                if tid:
                    resolved_ids.add(tid)
                gh = e.get("gated_by_hypothesize_call_id")
                if gh:
                    ghe = idx.by_call_id.get(gh) or {}
                    ghid = (ghe.get("hypothesis_id") or "").strip()
                    if ghid:
                        resolved_ids.add(ghid)
            open_generic: list[str] = []
            for hid, hyp in sorted(idx.hypotheses_by_id.items()):
                if not hid or hid in resolved_ids:
                    continue
                obs = ((hyp.get("inputs") or {}).get("user_message") or "")
                is_distinct = bool(
                    _distinct_principal_re.search(obs)
                    or _distinct_principal_re.search(hyp.get("conclusion") or "")
                )
                if is_distinct:
                    issues.append(
                        f"Hypothesis {hid} frames a distinct/second principal or "
                        f"controller question but was never resolved: no finding "
                        f"carries it as tested_hypothesis_id and none parks it "
                        f"controller-unknown. A competing-principal hypothesis "
                        f"cannot be silently dropped — record a CONFIRMED/LIKELY "
                        f"finding that resolves it (with a logon/session binding), "
                        f"or an explicit UNCONFIRMED 'controller unknown' finding, "
                        f"before Report. If the finding that resolved it was "
                        f"withdrawn over its citation, re-record it citing the "
                        f"calls that support it: the repair carries "
                        f"tested_hypothesis_id."
                    )
                else:
                    open_generic.append(hid)
            if open_generic:
                warnings.append(
                    f"{len(open_generic)} hypothesis/es raised but never resolved "
                    f"({', '.join(open_generic[:5])}"
                    f"{'…' if len(open_generic) > 5 else ''}) — no finding cites "
                    f"them as tested_hypothesis_id. Resolve or park each before Report."
                )

        # #5 (blocking) — attribution closure (i): a human/account attribution
        # verdict cannot ship without a logon/RDP session inventory that could
        # rule out a second principal operating the host. Scoped to human/account
        # verdicts so a process/malware attribution in a memory-only case (no
        # event logs) is not blocked.
        from tools._gates.principal_attribution_grounding import _ACCOUNT_RE
        from tools._gates.named_actor_attribution_grounding import (
            _NAME_RE as _na_name_re, _NAME_STOPS as _na_stops,
        )
        _VERDICT_RE = re.compile(
            r"\b(?:exfiltrat\w+|copied|stole|stol\w+|disseminat\w+|uploaded"
            r"|transferred|transmit\w+|leaked|smuggled|operated by|controlled by"
            r"|attributed to|logged ?in as|sole actor|acted alone"
            r"|responsible for)\b", re.IGNORECASE,
        )

        def _is_human_or_account_verdict(desc: str) -> bool:
            if not _VERDICT_RE.search(desc):
                return False
            if _ACCOUNT_RE.search(desc):
                return True
            if re.search(r"\bsole actor\b|\bacted alone\b|\bby [A-Z][a-z]+\b", desc):
                return True
            return bool(set(_na_name_re.findall(desc)) - _na_stops)

        has_verdict = any(
            _ftier(e) in {"CONFIRMED", "LIKELY"}
            and _is_human_or_account_verdict(e.get("description") or "")
            for e in s_findings
        )
        has_pcap_activity = any(
            e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
            and re.search(
                r"\b(?:tcpdump|ngrep)\b|http_session_inventory|pcap_identity_timeline",
                e["cmd"], re.IGNORECASE,
            )
            for e in entries
        )
        has_pcap_identity_closure = any(
            (
                e.get("type") == "tool_call"
                and isinstance(e.get("cmd"), str)
                and re.search(
                    r"http_session_inventory|pcap_identity_timeline",
                    e["cmd"], re.IGNORECASE,
                )
            )
            or (
                e.get("type") == "finding"
                and re.search(
                    r"net\.http_session_inventory|net\.pcap_identity_timeline",
                    e.get("source") or "", re.IGNORECASE,
                )
            )
            for e in entries
        )
        has_knowns_sweep = any(
            isinstance(e.get(f), str)
            and re.search(r"knowns_pattern_generate|roster", e.get(f), re.IGNORECASE)
            for e in entries
            for f in ("cmd", "description", "content", "conclusion")
        )
        from core.auth_ontology import logon_inventory_cmd_regex
        _LOGON_TOOL_RE = logon_inventory_cmd_regex()
        has_logon_enum = any(
            e.get("type") == "tool_call" and isinstance(e.get("cmd"), str)
            and _LOGON_TOOL_RE.search(e["cmd"])
            for e in entries
        )
        if has_verdict and has_pcap_activity and not has_pcap_identity_closure:
            issues.append(
                "A human/account attribution verdict was recorded from PCAP "
                "evidence, but no structured PCAP identity inventory appears "
                "in the trace (net.http_session_inventory or "
                "net.pcap_identity_timeline). Run one of those tools, compare "
                "all identities on the sender host/session, and disposition "
                "competing accounts before Report."
            )
        if has_verdict and has_pcap_activity and not has_knowns_sweep:
            issues.append(
                "A human/account attribution verdict was recorded from PCAP "
                "evidence, but no roster/knowns sweep is evident. Generate "
                "person-username variants with misc.knowns_pattern_generate and "
                "sweep the PCAP or pass the roster to net.pcap_identity_timeline "
                "before Report."
            )
        if has_verdict and not has_pcap_activity and not has_logon_enum:
            issues.append(
                "A human/account attribution verdict was recorded but no "
                "logon/RDP session-enumeration appears anywhere in the trace "
                "(no ez.evtxecmd / misc.chainsaw_hunt on "
                "4624/4625/4778/4779, and no Linux last/wtmp). A sole-actor "
                "verdict cannot stand without a logon-session inventory that "
                "rules out a second principal operating the host — run it and "
                "disposition every session before Report."
            )

        # #6 (blocking) — attribution closure (ii): every previously-unseen
        # identity for which a controller question was opened, or which DAIR
        # surfaced as a forced principal candidate, must be dispositioned:
        # attributed-with-session, excluded-with-evidence, or parked
        # controller-unknown. Focus harvesting is restricted to controller
        # questions so an ordinary subject mention is not harvested.
        from_focus: set[str] = set()
        from_pivots: set[str] = set()
        from core.execution_log import as_text
        for e in entries:
            if e.get("type") != "dair_call":
                continue
            focus = as_text(e.get("investigation_focus"))
            if re.search(r"controls principal|who controls", focus, re.IGNORECASE):
                from_focus |= _extract_principal_tokens(focus, require_cue=False)
            for pivot in e.get("candidate_pivots") or []:
                if not isinstance(pivot, dict):
                    continue
                if str(pivot.get("kind") or "").lower() != "principal":
                    continue
                if str(pivot.get("cue") or "").lower() != "forced":
                    continue
                value = str(pivot.get("value") or "")
                from_pivots |= _extract_principal_tokens(
                    f"who controls principal {value}", require_cue=False)
        # Phantom-principal guard: DAIR prose is LLM-authored and its forced
        # principal candidates have included section-heading words rather
        # than accounts. Generic report
        # vocabulary never creates a blocker; a *forced pivot* candidate
        # must additionally appear somewhere in actual tool output. An
        # explicit controller QUESTION opened by the director keeps blocking
        # regardless — that is a deliberate investigative commitment.
        _GENERIC_NON_PRINCIPALS = {
            "PROCESSES", "PROCESS", "ANALYSIS", "FINDINGS", "FINDING",
            "EVENTS", "EVENT", "SESSIONS", "SESSION", "RESULTS", "SUMMARY",
            "UNKNOWN", "ACCOUNTS", "ACCOUNT", "USERS", "LOGONS", "LOGON",
            "TIMELINE", "EVIDENCE", "REPORT", "COLLECT", "TRIAGE",
        }
        if from_pivots:
            _corpus_parts: list[str] = []
            for e in entries:
                if e.get("type") == "tool_call":
                    for k in ("stdout_excerpt", "stdout", "cmd"):
                        v = e.get(k)
                        if v:
                            _corpus_parts.append(str(v))
            _corpus = " ".join(_corpus_parts).casefold()
            from_pivots = {p for p in from_pivots
                           if not _corpus or p.casefold() in _corpus}
        surfaced = {
            p for p in (from_focus | from_pivots)
            if not p.startswith("RID") and not p.startswith("S-1-")
            and p.upper() not in _GENERIC_NON_PRINCIPALS
        }
        for p in sorted(surfaced):
            dispositioned = False
            for e in s_findings:
                d = e.get("description") or ""
                if p.lower() not in d.lower():
                    continue
                if _ftier(e) in {"CONFIRMED", "LIKELY"} and _SESSION_RE.search(d):
                    dispositioned = True
                    break
                if (re.search(r"\b(?:excluded|ruled out|not the (?:actor|operator)"
                              r"|did not (?:log|authenticate))\b", d, re.IGNORECASE)
                        and _SESSION_RE.search(d)):
                    dispositioned = True
                    break
                if re.search(r"(?:controll?er|who controls)[^.\n]*\b(?:unknown"
                             r"|unidentified|not established|unestablished)\b"
                             r"|\bunattributed\b", d, re.IGNORECASE):
                    dispositioned = True
                    break
            if not dispositioned:
                issues.append(
                    f"Previously-unseen identity '{p}' surfaced during the "
                    f"investigation (a controller question was opened or DAIR "
                    f"surfaced a forced principal candidate) but no finding "
                    f"dispositions it: not attributed-with-session, not "
                    f"excluded-with-evidence, and not parked "
                    f"controller-unknown. Disposition '{p}' before Report: "
                    f"either record a CONFIRMED/LIKELY finding tying '{p}' to "
                    f"a logon session, or — if it cannot be attributed or is "
                    f"not actually an account — park it with a "
                    f"misc.record_finding (any tier) whose description "
                    f"contains '{p}' and the words 'controller unknown' (or "
                    f"'unattributed'), stating why."
                )
    except Exception as _e:
        import sys as _sys
        print(f"[Atlas WARN] structural-integrity check failed: {_e}",
              file=_sys.stderr)

    # Contested auth.success observations (failure+success for same endpoint)
    # with no covering finding/claim — Claim Graph auth coverage, advisory only.
    try:
        from tools.coverage_audit import hostile_auth_reconciliation
        _unrep = hostile_auth_reconciliation().get("unreported") or []
        for ev in _unrep[:8]:
            where = " ".join(p for p in (
                f"on {ev['date']}" if ev.get("date") else "",
                f"logon type {ev['logon_type']}" if ev.get("logon_type") else "",
            ) if p)
            warnings.append(
                "unreported_auth_success: a SUCCESSFUL authentication "
                f"from {ev['ip']} — an endpoint that also has auth.failure "
                f"observations — {(where + ' ') if where else ''}appears in "
                f"tool output (call_id {ev.get('call_id')}) but no "
                "finding/claim reports successful access for that "
                "endpoint/date. Record a finding or claim, or note why it is "
                "benign. A failure-only narrative does not account for a "
                "success."
            )
        if len(_unrep) > 8:
            warnings.append(
                f"unreported_auth_success: +{len(_unrep) - 8} more "
                "successful auth(s) on contested endpoints unreported — see "
                "coverage.audit_hostile_auth_coverage for the full list."
            )
    except Exception as _e:
        import sys as _sys
        print(f"[Atlas WARN] auth_success_coverage failed: {_e}",
              file=_sys.stderr)

    # Cross-source reconciliation: when SIEM + disk/timeline sources coexist
    # and findings make first-access claims, require reconciliation before report.
    # Complements hostile_auth_reconciliation (trace-based) with evidence-file
    # reconciliation (Wazuh JSON vs EVTX CSV vs timeline TSV).
    try:
        from core.cross_source_reconciliation import (
            case_needs_reconciliation,
            findings_trigger_reconciliation,
            load_reconciliation_result,
        )
        case_dir = log.case_dir()
        if case_dir and case_needs_reconciliation(case_dir):
            recon_ran = any(
                e.get("type") == "tool_call"
                and "cross_source_reconciliation" in (e.get("mcp_tool") or "")
                for e in entries
            )
            access_claims = findings_trigger_reconciliation(finding_entries)
            if access_claims and not recon_ran:
                issues.append(
                    "Cross-source reconciliation required: SIEM exports and "
                    "disk/timeline sources both exist, and CONFIRMED/LIKELY "
                    "findings assert initial/first-access timing. Run "
                    "correlate.cross_source_reconciliation before writing the "
                    "report — compare successful logons across Wazuh, EVTX CSV, "
                    "and timeline TSV so SIEM-only successes are not missed."
                )
            else:
                recon = load_reconciliation_result(case_dir)
                if recon and recon.get("blocking_issues"):
                    for bi in recon["blocking_issues"][:5]:
                        issues.append(
                            f"Cross-source reconciliation blocking issue: {bi}"
                        )
                elif access_claims and recon_ran and not recon:
                    warnings.append(
                        "correlate.cross_source_reconciliation ran but "
                        "analysis/cross_source_reconciliation.json is missing."
                    )
    except Exception as _e:
        import sys as _sys
        print(f"[Atlas WARN] cross-source reconciliation check failed: {_e}",
              file=_sys.stderr)

    # Critical auth/session scans that timed out must be retried — not skipped.
    # Timeline seeding does not clear this.
    #
    # Deliberately placed BEFORE the budget-aware backstop below: this gate
    # appends to `issues`, so at forced budget wrap-up it is downgraded to a
    # documented limitation like every other content gate instead of costing the
    # deliverable. In normal operation (no wrap-up marker) it still blocks.
    try:
        from tools._gates.critical_scan_timeout import (
            format_blocking_issue,
            unresolved_critical_scan_timeouts,
        )
        unresolved = unresolved_critical_scan_timeouts(entries)
        if unresolved:
            issues.append(format_blocking_issue(unresolved))
    except Exception as _e:
        import sys as _sys
        print(f"[Atlas WARN] critical-scan timeout check failed: {_e}",
              file=_sys.stderr)

    # ── Deadlock relief (b): budget-aware backstop ────────────────────────────
    # Even with the acknowledgment hatch (a), the agent may not use it, or an
    # independently-computed content gate may be genuinely unsatisfiable. Once
    # the loop has forced budget wrap-up, an honest partial report with a
    # documented-limitations section beats losing the deliverable entirely
    # (P4 report-gate deadlock). Structural prerequisites still block — a report
    # with no plan/synthesize/trace has no spine, and they cost only a few
    # close-out turns. This never fires from agent action alone: only the loop
    # writes the budget_wrapup marker.
    if issues and not structural_issues and _budget_wrapup_signaled(entries):
        documented_limitations.extend(issues)
        warnings.extend(
            "DOCUMENTED LIMITATION (budget wrap-up — was blocking): " + i
            for i in issues
        )
        warnings.append(
            "[budget wrap-up] Unresolved blocking issue(s) were downgraded to "
            "documented limitations so an honest partial report can be written "
            "before the turn budget is spent. State them in the report's "
            "Limitations section; do not present the case as fully resolved."
        )
        issues = []

    # Structural prerequisites are NEVER relaxed: `ready` is derived from both
    # lists, not from `issues` alone. Do not simplify this to
    # `len(issues) == 0` — that would let a report with no plan, no synthesize
    # and no trace pass the gate.
    # A run that withdraws claims between two checks while the blocker set
    # persists is dismantling its findings to pass a gate. Withdrawal stays
    # allowed; the pattern is named, with the repair that keeps the finding.
    _shed = _withdrawn_since_last_check(trace, _case_dir)
    if _shed and issues:
        warnings.append(
            f"{len(_shed)} claim(s) withdrawn since the previous report check "
            f"({', '.join(_shed[:6])}) while blocking issues remain. A withdrawal "
            "to clear a gate loses the finding and reopens the question, "
            "hypothesis or indicator it resolved. When the citation was the "
            "objection, record a standing finding again with supersedes=<its "
            "call id> citing the calls that support it instead of withdrawing it "
            "(a citation repair is not a duplicate and carries the hypothesis), "
            "or lower it the same way: recorded again at UNCONFIRMED with "
            "supersedes=<its call id>, as a limitation.")

    all_issues = structural_issues + issues
    ready = len(all_issues) == 0

    # Persist ready_to_report as a reason_call trace entry so downstream gates
    # (misc.export_execution_log) can read the verdict from the audit log
    # instead of relying on the agent re-narrating the result. The conclusion
    # leads with a parseable marker so the gate's regex is trivial.
    conclusion = (
        f"READY_TO_REPORT: {'true' if ready else 'false'}\n"
        f"BLOCKING_ISSUES ({len(all_issues)}): {'; '.join(all_issues) if all_issues else 'none'}\n"
        f"WARNINGS ({len(warnings)}): {'; '.join(warnings) if warnings else 'none'}"
    )
    if documented_limitations:
        conclusion += (
            f"\nDOCUMENTED_LIMITATIONS ({len(documented_limitations)}): "
            + "; ".join(d[:200] for d in documented_limitations)
        )
    try:
        # Auto-derive lineage: the pre-report check by nature reads the entire
        # trace, so its upstream lineage is "every finding + every synthesize".
        synthesized_cids = [
            e.get("call_id") for e in trace
            if e.get("call_id") and (
                e.get("type") == "finding"
                or (e.get("type") == "reason_call" and e.get("tool") == "reason_synthesize")
            )
        ]
        _check_cid = log.record_reason_call(
            tool="reason_pre_report_check",
            success=True,
            conclusion=conclusion,
            directives={},
            input_call_ids=synthesized_cids or None,
        )
        # What the next check counts a mis-cited finding's streak from.
        log.update_reason_call(_check_cid, miscited_lineage=_flagged_lineage)
    except Exception as _e:
        import sys as _sys
        print(f"[Atlas WARN] pre_report_check trace write failed: {_e}", file=_sys.stderr)

    return {
        "ready_to_report": ready,
        "blocking_issues": all_issues,
        "documented_limitations": documented_limitations,
        "warnings": warnings,
        "trace_entries": len(trace),
        "tool_calls": tool_calls,
        "confirmed_findings": confirmed_findings,
        "evaluate_finding_calls": evaluate_calls,
        "has_plan": has_plan,
        "has_synthesize": has_synthesize,
        "has_hypothesize": has_hypothesize,
        "audit_summary": audit_summary,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
    }


@mcp.tool()
@with_tool_timeout(_REASON_WATCHDOG, label="reason_pre_report_check")
def reason_pre_report_check() -> dict:
    """
    Verify all mandatory investigation checkpoints before writing the report.
    Reads the live execution trace and returns blocking_issues (must resolve)
    and warnings (should review). Do not write the report if ready_to_report
    is False.

    Call this after reason.synthesize and before writing any report section.
    """
    # The analyst's own call is the one that may act on what the gate found.
    return _pre_report_check(apply_remedies=True)
