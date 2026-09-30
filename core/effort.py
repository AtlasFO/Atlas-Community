"""The reasoning level each model role is asked for, in one place.

A reasoning model draws its thinking from the same completion budget as its
answer, in a field of its own that is paid for and never read as the answer.
So a role that thinks at length under a fixed budget can exhaust it before any
content arrives, and one that thinks too little answers a question it has not
considered. Neither failure is visible in a short probe, both cost a whole run,
and the workable value is not predictable from a model's name.

Atlas therefore asks for a level per role rather than detecting one. This
module owns the vocabulary (which levels exist, which roles can be set, what
each role does and what it defaults to) so the CLI, the dashboard and the
transport layer agree without each keeping a copy.

Where the parts live:

* ``core.llmhub.reasoning_effort_for`` resolves a role to the value to send,
  reading ``ATLAS_EFFORT_<ROLE>`` over the per-role default.
* ``core.llmhub.chat_payload`` puts it on a Chat Completions body, and drops
  it for the rest of the process once a 400 names it as unsupported.
* ``core.responses_api.build_responses_payload`` puts it on a Responses body,
  which spells the same idea ``reasoning: {effort: ...}``.
* ``agent.llm.LLMHubClient.chat`` applies the analyst's level, and yields to
  an endpoint that pins a value of its own alongside function tools.

Nothing here talks to a provider. Whether a given endpoint accepts the option
is answered by the endpoint, not by a table of model names kept here: such a
table is wrong the day a provider ships a model, and the request path already
recovers from a refusal without failing the call.
"""
from __future__ import annotations

from dataclasses import dataclass

# "default" is a value a user can choose on purpose: it means the endpoint's
# own, and sends nothing. Ordered endpoint-default first, then least thinking
# to most, which is the order the dashboard renders them in.
VALUES: tuple[str, ...] = ("default", "low", "medium", "high")


@dataclass(frozen=True)
class EffortRole:
    """One role whose reasoning level can be set.

    ``key`` is the role name the request path uses (``core.llmhub``'s roles);
    ``var`` is the environment variable that overrides it. ``label`` and
    ``blurb`` exist for the dashboard, so the setting is explained where it is
    changed rather than only in a document.
    """
    key: str
    var: str
    label: str
    blurb: str


# The analyst first, then the director, then the reasoning tools in the order
# an investigation meets them. Every entry's var is ATLAS_EFFORT_ plus the role
# name with any "reason_" prefix removed — the rule core.llmhub applies when
# resolving a role, restated here as data so the two cannot drift silently
# (tests/core/test_effort.py asserts they agree).
ROLES: tuple[EffortRole, ...] = (
    EffortRole(
        "agent", "ATLAS_EFFORT_AGENT", "Analyst",
        "The investigator itself, and the roles that run on its client: the "
        "run reviewer and the case chat. Too much thinking here spends a "
        "turn's whole budget before a tool call is issued; too little returns "
        "replies that carry no call at all. Left unset, the provider's own "
        "Thinking setting applies, and Atlas learns a level from a starved "
        "reply. The report writer has a level of its own, below.",
    ),
    EffortRole(
        "report", "ATLAS_EFFORT_REPORT", "Report writer",
        "Writes the narrative sections of the report from the findings already "
        "recorded. It invents nothing and cites what the claims say, so a high "
        "level buys little; a starved reply costs the section, which falls back "
        "to the deterministic text assembled from the claim graph.",
    ),
    EffortRole(
        "dair", "ATLAS_EFFORT_DAIR", "Director",
        "Rules on which phase the investigation is in and what to do next. "
        "Left at the endpoint's own: on one model a lowered level changed the "
        "ruling on every prompt whose unconstrained answer was stable, while "
        "on another it changed nothing. Lower it only against measurement.",
    ),
    EffortRole(
        "reason_plan", "ATLAS_EFFORT_PLAN", "Planning",
        "Turns a case description into an approach. Its answer changes with "
        "thought, so it keeps the endpoint's own level.",
    ),
    EffortRole(
        "reason_hypothesize", "ATLAS_EFFORT_HYPOTHESIZE", "Hypotheses",
        "Proposes explanations for an observation. Its answer changes with "
        "thought, so it keeps the endpoint's own level.",
    ),
    EffortRole(
        "reason_evaluate_finding", "ATLAS_EFFORT_EVALUATE_FINDING",
        "Finding evaluation",
        "Decides which confidence tier the offered evidence supports. A "
        "judgement about text already in hand, so it asks for a low level: "
        "thinking longer does not change what the text contains.",
    ),
    EffortRole(
        "reason_cite_check", "ATLAS_EFFORT_CITE_CHECK", "Citation check",
        "Decides whether the values a finding rests on appear in what the "
        "cited calls printed. A containment question, so it asks for a low "
        "level.",
    ),
    EffortRole(
        "reason_confidence_score", "ATLAS_EFFORT_CONFIDENCE_SCORE",
        "Confidence score",
        "Scores how well the evidence carries the claim. A judgement about "
        "text already in hand, so it asks for a low level.",
    ),
    EffortRole(
        "reason_audit_findings", "ATLAS_EFFORT_AUDIT_FINDINGS",
        "Finding audit",
        "Reviews the findings recorded so far against the narration around "
        "them. Its answer changes with thought, so it keeps the endpoint's "
        "own level.",
    ),
    EffortRole(
        "reason_synthesize", "ATLAS_EFFORT_SYNTHESIZE", "Synthesis",
        "Draws the findings into a conclusion, and is the report gate's one "
        "hard prerequisite. Its answer changes with thought, so it keeps the "
        "endpoint's own level; a starved reply is answered by the request "
        "path's own retry ladder rather than by lowering it here.",
    ),
)

_BY_KEY = {r.key: r for r in ROLES}


def role(key: str) -> EffortRole | None:
    """The role named ``key``, or None when nothing is registered under it."""
    return _BY_KEY.get(key)


def normalise(value: str) -> str:
    """``value`` as one of VALUES, or "" when it is none of them.

    Empty and "default" are the same answer — the endpoint's own — and both
    come back as "default" so a caller never has to spell that twice.
    """
    text = str(value or "").strip().lower()
    if not text:
        return "default"
    return text if text in VALUES else ""


def default_for(key: str) -> str:
    """The level ``key`` runs at with nothing set, as one of VALUES."""
    from core import llmhub
    return normalise(llmhub.default_effort_for(key)) or "default"


def settings(env: dict[str, str] | None = None) -> list[dict]:
    """Every settable role, what it is set to, and what it would run at.

    ``env`` is where the configured values are read from — pass the .env
    file's own values when they may differ from this process's environment,
    which they do whenever the file was edited after the process started.
    """
    import os
    source = os.environ if env is None else env
    out = []
    for entry in ROLES:
        raw = str(source.get(entry.var, "") or "").strip()
        configured = normalise(raw) if raw else ""
        out.append({
            "role": entry.key,
            "var": entry.var,
            "label": entry.label,
            "blurb": entry.blurb,
            # "" means nothing is set for this role; the default applies.
            "value": configured,
            "invalid": raw if (raw and not configured) else "",
            "default": default_for(entry.key),
            "effective": configured or default_for(entry.key),
        })
    return out


def updates(values: dict[str, str]) -> dict[str, str]:
    """.env updates for a ``{role: level}`` mapping.

    A role set to its own default is written as "default" rather than removed,
    because the two differ in intent: the endpoint's own level chosen on
    purpose is an answer, not an absence.
    Unknown roles and values are refused rather than written, so a malformed
    request cannot leave a run unable to start.
    """
    out: dict[str, str] = {}
    for key, value in (values or {}).items():
        entry = _BY_KEY.get(str(key))
        if entry is None:
            raise ValueError(f"{key!r} is not a model role Atlas asks a level of")
        level = normalise(value)
        if not level:
            raise ValueError(
                f"{value!r} is not a reasoning level. Use one of: "
                + ", ".join(VALUES)
            )
        out[entry.var] = level
    return out

