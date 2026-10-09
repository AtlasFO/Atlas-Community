"""Gate: a CONFIRMED/LIKELY finding that binds an *account / identity* to a
*named principal* performing actions must be grounded in an authentication or
session artifact — not asserted from assumption.

Trigger (description prose):
  tier ∈ {CONFIRMED, LIKELY}
  AND the description references an account/identity (RID/SID/account/user/
      credential/logon account)
  AND it binds that account to an actor via an attribution copula
      (operated by, controlled by, belongs to, created by, logged in as,
       used by, attributed to, "= <Name>", "is <Name>").

Only CONFIRMED/LIKELY are gated — SUSPECTED/UNCONFIRMED account-actor
hypotheses in narrative findings are acceptable as open propositions.
"""
import re
from typing import Optional

from core.auth_ontology import session_evidence_regex, windows_auth_eids_prose

from ._match import lineage_evidence_text

# References an account / identity as the *subject* of the attribution.
_ACCOUNT_RE = re.compile(
    r"\b(?:RID\s*\d+|SID\b|S-1-5-\S+|account\b|user account\b|local admin(?:istrator)?\b"
    r"|logon account\b|service account\b|credential\b|identity\b)\b",
    re.IGNORECASE,
)

# Binds that account to an actor/principal.
_ATTRIB_RE = re.compile(
    r"(?:\boperated by\b|\bcontrolled by\b|\bbelongs to\b|\bcreated by\b"
    r"|\blogged ?in as\b|\bwas used by\b|\bused by\b|\battributed to\b"
    r"|\bacted as\b|\bis\s+[A-Z][a-z]+|=\s*[A-Z][a-z]+)",
)

# Authentication / session evidence that grounds the binding (ontology).
_SESSION_RE = session_evidence_regex()


def check(ctx) -> Optional[dict]:
    if ctx.tier not in {"CONFIRMED", "LIKELY"}:
        return None

    desc = ctx.description or ""
    if not (_ACCOUNT_RE.search(desc) and _ATTRIB_RE.search(desc)):
        return None

    # A binding is an attribution only when it binds to a person. One that
    # binds to a program the cited evidence names ("Abel is Cain's companion
    # tool"), to another account or artifact noun ("used by local Windows
    # account 'jcloudy'"), to a token the text spells as a file, domain or
    # path, a quoted name a thing-noun introduces (the job "Nightly Sync"),
    # or to nobody named at all ("used by the attacker") binds nothing to a
    # person. When no binding in the description does, there is no
    # attribution here.
    from ._match import labelled_quote_words, named_things_in_text, program_names_in_evidence
    from .named_actor_attribution_grounding import _NAME_STOPS
    programs = program_names_in_evidence(ctx)
    things = (named_things_in_text(desc) | named_things_in_text(lineage_evidence_text(ctx))
              | labelled_quote_words(desc))

    def _binds_a_person(bound: str) -> bool:
        if not bound or bound in _NAME_STOPS:
            return False
        if bound in programs or bound.rstrip("s") in programs:
            return False
        return bound.casefold() not in things

    bound_to = []
    for m in _ATTRIB_RE.finditer(desc):
        tail = re.search(r"([A-Z][\w'-]{1,30})", desc[m.start():m.end() + 40])
        # A possessive ("Alice's") is a suffix, not a character set: a
        # character strip turned "Windows" into "Window" and past the stops.
        bound_to.append(re.sub(r"'s?$", "", tail.group(1)) if tail else "")
    if bound_to and not any(_binds_a_person(b) for b in bound_to):
        return None

    evidence = lineage_evidence_text(ctx)
    if _SESSION_RE.search(evidence):
        return None

    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding binds an account/identity to a named principal "
            f"but no authentication/session artifact appears in its evidence "
            f"(supporting_evidence or the linked_call_id / input_call_ids "
            f"entries). Attributing an account's actions to a person requires a "
            f"logon-session binding — e.g. Security "
            f"{windows_auth_eids_prose()} with logon type and "
            f"source address (ez.evtxecmd / misc.chainsaw_hunt), an RDP/SMB/SSH "
            f"session, or an identity artifact (SAM InternetName, cert CN). Pull "
            f"that artifact and cite it (pass its _atlas_call_id in "
            f"input_call_ids), or downgrade this finding to SUSPECTED."
        ),
        "description": ctx.description,
        "confidence": ctx.confidence,
        "gate": "principal_attribution_grounding",
    }
