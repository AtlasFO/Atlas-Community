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
    if not binds_account_to_person(ctx):
        return None

    from core.attribution_identity import identity_rows_on
    if identity_rows_on():
        # The credited account (and the person it is bound to) stands in a
        # row of a cited call beside another term of the claim.
        from ._identity_rows import binding_rows, refusal
        ident, who = account_identity(ctx)
        ok, cited, others = binding_rows(ctx, ident)
        if ok:
            return None
        return refusal(ctx, "principal_attribution_grounding", who, "the account", cited, others)

    evidence = lineage_evidence_text(ctx)
    if _SESSION_RE.search(evidence):
        return None
    return _refusal(ctx)


def binds_account_to_person(ctx) -> bool:
    """Whether the finding binds an account or identity to a person: the
    account-plus-copula shape of an attribution verdict."""
    desc = ctx.description or ""
    if not (_ACCOUNT_RE.search(desc) and _ATTRIB_RE.search(desc)):
        return False

    # A binding is an attribution only when it binds to a person. One that
    # binds to a program the cited evidence names ("PsExec is the remote-execution
    # tool"), to another account or artifact noun ("used by local Windows
    # account 'jdoe'"), to a token the text spells as a file, domain or
    # path, a quoted name a thing-noun introduces (the job "Nightly Sync"),
    # or to nobody named at all ("used by the attacker") binds nothing to a
    # person. When no binding in the description does, there is no
    # attribution here.
    from ._match import labelled_quote_words, named_things_in_text, program_names_in_evidence
    from .named_actor_attribution_grounding import _NAME_STOPS
    programs = program_names_in_evidence(ctx)
    things = (named_things_in_text(desc) | named_things_in_text(lineage_evidence_text(ctx))
              | labelled_quote_words(desc))
    # The account's own name is not a thing: "account jane.doe was used by
    # Jane" binds the account to the person its name spells.
    things -= _account_name_parts(desc)

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
    return not (bound_to and not any(_binds_a_person(b) for b in bound_to))


def account_identity(ctx) -> tuple[set[str], str]:
    """The identity an account binding credits, and how to name it: the
    account's user name as written after its cue (the part after a domain
    and before a mail domain), a SID in the description, and the person the
    copula binds it to with that person's account spellings."""
    from core.attribution_identity import full_names, person_variants
    desc = ctx.description or ""
    ident: set[str] = set()
    shown = ""
    for m in _ACCOUNT_RE.finditer(desc):
        nxt = re.match(r"\s+['\"`]?([\w.@\\$-]+)", desc[m.end():])
        if nxt:
            token = nxt.group(1).rstrip(".")
            user = token.replace("/", "\\").rsplit("\\", 1)[-1].split("@", 1)[0]
            if len(user) >= 3:
                ident.add(user.casefold())
                shown = shown or token
    ident |= {s.casefold() for s in re.findall(r"S-1-5-[\d-]+", desc)}
    for m in _ATTRIB_RE.finditer(desc):
        tail = re.search(r"([A-Z][\w'-]{1,30})", desc[m.start():m.end() + 40])
        if not tail:
            continue
        person = re.sub(r"'s?$", "", tail.group(1))
        names = full_names(person, [desc]) or [person]
        for n in names:
            ident |= set(person_variants(n))
        shown = shown or person
    return ident, (shown or "the account")


def _account_name_parts(desc: str) -> set[str]:
    """The labels of the token right after an account cue ("account
    jane.doe", "user CORP\\jdoe"): the account's own name, casefolded."""
    out: set[str] = set()
    for m in _ACCOUNT_RE.finditer(desc):
        nxt = re.match(r"\s+['\"`]?([\w.@\\$-]+)", desc[m.end():])
        if nxt:
            out.update(p.casefold() for p in re.split(r"[.@\\$]+", nxt.group(1)) if p)
    return out


def _refusal(ctx) -> dict:
    return {
        "success": False,
        "error": (
            f"{ctx.tier} finding binds an account/identity to a named principal "
            f"but no authentication/session artifact appears in the rows of the "
            f"calls it cites (linked_call_id / input_call_ids; text in "
            f"supporting_evidence is not a row). Attributing an account's actions to a person requires a "
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
